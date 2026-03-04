// ==============================
// c_server.c  (V2: Zero Privacy + TOFU Pinning & Key Confirmation)
// ==============================
//
// Goals:
//   1) Let clients learn/pin server identity during SETUP by sending server_static_pub.
//   2) Mutual auth: server proves possession of its static secret during AUTH.
//   3) Zero Privacy: Hide identity via ECDHE (X25519) + ChaCha20Poly1305 tunnel during AUTH.
//   4) Replay protection: persistent nonce tracking (dropped time-based TTL for DoS fix).
//   5) Key confirmation MACs: server sends tag_s, client replies tag_c over the secure tunnel.
//
// Build:
//   gcc -O2 -std=c11 -Wall -Wextra server.c -o c_server -lsodium
//
#define _POSIX_C_SOURCE 200112L
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MSG_SETUP 0x01
#define MSG_AUTH_V2 0x03

#define REGISTRY_BIN    "registry.bin"
#define REGISTRY_BAK    "registry.bak"
#define SERVER_SK_FILE  "server_sk.bin"

// Replay cache params
#define REPLAY_MAX 50000

// -----------------------------
// File helpers
// -----------------------------
static int file_exists(const char *path) { return access(path, F_OK) == 0; }

static int read_file_32(const char *path, uint8_t out[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, 32, f);
    fclose(f);
    return (n == 32) ? 0 : -1;
}

static int write_file_32(const char *path, const uint8_t in[32]) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(in, 1, 32, f);
    fclose(f);
    return (n == 32) ? 0 : -1;
}

// -----------------------------
// Timing helper
// -----------------------------
static double get_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// -----------------------------
// Registry persistence
// -----------------------------
typedef struct {
    uint8_t id[32];
    uint8_t pub[32];
} reg_entry_t;

static int load_registry(reg_entry_t **out, size_t *out_n) {
    *out = NULL;
    *out_n = 0;
    if (!file_exists(REGISTRY_BIN)) return 0;

    FILE *f = fopen(REGISTRY_BIN, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    if ((sz % 64) != 0) { fclose(f); return -1; }

    size_t n = (size_t)sz / 64;
    if (n == 0) { fclose(f); return 0; }

    reg_entry_t *arr = (reg_entry_t*)calloc(n, sizeof(reg_entry_t));
    if (!arr) { fclose(f); return -1; }

    for (size_t i = 0; i < n; i++) {
        if (fread(arr[i].id, 1, 32, f) != 32) { fclose(f); free(arr); return -1; }
        if (fread(arr[i].pub, 1, 32, f) != 32) { fclose(f); free(arr); return -1; }
    }
    fclose(f);

    *out = arr;
    *out_n = n;
    return 0;
}

static int save_registry(const reg_entry_t *arr, size_t n) {
    if (file_exists(REGISTRY_BIN)) {
        rename(REGISTRY_BIN, REGISTRY_BAK);
    }
    
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", REGISTRY_BIN);
    
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;

    for (size_t i = 0; i < n; i++) {
        if (fwrite(arr[i].id, 1, 32, f) != 32) { fclose(f); return -1; }
        if (fwrite(arr[i].pub, 1, 32, f) != 32) { fclose(f); return -1; }
    }
    
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    
    return rename(tmp, REGISTRY_BIN);
}

static int reg_lookup(const reg_entry_t *arr, size_t n, const uint8_t id[32], uint8_t pub_out[32]) {
    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            memcpy(pub_out, arr[i].pub, 32);
            return 0;
        }
    }
    return -1;
}

static int reg_upsert(reg_entry_t **arrp, size_t *np, const uint8_t id[32], const uint8_t pub[32]) {
    reg_entry_t *arr = *arrp;
    size_t n = *np;

    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            if (sodium_memcmp(arr[i].pub, pub, 32) != 0) return -1;
            return 0; 
        }
    }

    reg_entry_t *b = (reg_entry_t*)realloc(arr, (n + 1) * sizeof(reg_entry_t));
    if (!b) return -1;
    arr = b;

    memcpy(arr[n].id, id, 32);
    memcpy(arr[n].pub, pub, 32);
    n++;

    *arrp = arr;
    *np = n;

    return (save_registry(arr, n) == 0) ? 1 : -1;
}

// -----------------------------
// Replay cache (Fixed size, drops oldest conceptually by wiping)
// -----------------------------
typedef struct {
    uint8_t hash[64];
} replay_entry_t;

static replay_entry_t *replay_cache = NULL;
static size_t replay_count = 0;

static int check_and_insert_replay(const uint8_t device_id[32], const uint8_t nonce_c[32]) {
    uint8_t k[64];
    memcpy(k, device_id, 32);
    memcpy(k + 32, nonce_c, 32);

    for (size_t i = 0; i < replay_count; i++) {
        if (sodium_memcmp(replay_cache[i].hash, k, 64) == 0) {
            return -1; // Replay detected
        }
    }

    if (replay_count >= REPLAY_MAX) {
        replay_count = 0; // Prevent memory exhaustion
    }

    if (!replay_cache) {
        replay_cache = malloc(sizeof(replay_entry_t) * REPLAY_MAX);
    }

    memcpy(replay_cache[replay_count++].hash, k, 64);
    return 0;
}

// -----------------------------
// Network helpers
// -----------------------------
static int send_all(int fd, const uint8_t *buf, size_t len, size_t *sent) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    if (sent) *sent += len;
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len, size_t *recv_tracker) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    if (recv_tracker) *recv_tracker += len;
    return 0;
}

static int recv_u8(int fd, uint8_t *out, size_t *recv_tracker) { 
    return recv_all(fd, out, 1, recv_tracker); 
}

static void send_len(int fd, uint32_t val, size_t *sent_tracker) {
    uint8_t buf[4];
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    send_all(fd, buf, 4, sent_tracker);
}

static int recv_len(int fd, uint32_t *val, size_t *recv_tracker) {
    uint8_t buf[4];
    if (recv_all(fd, buf, 4, recv_tracker) != 0) return -1;
    *val = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 0;
}

// -----------------------------
// Transcript
// -----------------------------
typedef struct {
    uint8_t buf[4096];
    size_t len;
} transcript_t;

static void tr_init(transcript_t *tr, const char *domain) {
    tr->len = 0;
    size_t dlen = strlen(domain);
    if (dlen > 255) { fprintf(stderr, "domain too long\n"); exit(1); }
    tr->buf[tr->len++] = (uint8_t)dlen;
    memcpy(tr->buf + tr->len, domain, dlen);
    tr->len += dlen;
}

static void tr_append(transcript_t *tr, const char *label, const uint8_t *val, uint32_t vlen) {
    size_t llen = strlen(label);
    if (llen > 255) { fprintf(stderr, "label too long\n"); exit(1); }

    if (tr->len + 1 + llen + 4 + vlen > sizeof(tr->buf)) {
        fprintf(stderr, "transcript overflow\n");
        exit(1);
    }

    tr->buf[tr->len++] = (uint8_t)llen;
    memcpy(tr->buf + tr->len, label, llen);
    tr->len += llen;

    tr->buf[tr->len++] = (uint8_t)(vlen);
    tr->buf[tr->len++] = (uint8_t)(vlen >> 8);
    tr->buf[tr->len++] = (uint8_t)(vlen >> 16);
    tr->buf[tr->len++] = (uint8_t)(vlen >> 24);

    memcpy(tr->buf + tr->len, val, vlen);
    tr->len += vlen;
}

static void tr_challenge_scalar(uint8_t c_out[32], const transcript_t *tr) {
    uint8_t h[64];
    crypto_hash_sha512(h, tr->buf, (unsigned long long)tr->len);
    crypto_core_ristretto255_scalar_reduce(c_out, h);
}

// -----------------------------
// Schnorr verify/prove
// -----------------------------
static int schnorr_verify_setup(const uint8_t device_id[32], const uint8_t pubkey[32],
                                const uint8_t server_nonce[32], const uint8_t A[32], const uint8_t s[32]) {
    uint8_t c[32], left[32], cX[32], right[32];

    transcript_t tr;
    tr_init(&tr, "setup_schnorr_v1");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", pubkey, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "server_nonce", server_nonce, 32);

    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);

    if (crypto_scalarmult_ristretto255(cX, c, pubkey) != 0) return -1;

    crypto_core_ristretto255_add(right, A, cX);
    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

static int schnorr_verify_auth(const uint8_t device_id[32], const uint8_t expected_pub[32],
                               const uint8_t A[32], const uint8_t s[32],
                               const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t c[32], left[32], cX[32], right[32];

    transcript_t tr;
    tr_init(&tr, "client_schnorr_v1");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", expected_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);

    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);

    if (crypto_scalarmult_ristretto255(cX, c, expected_pub) != 0) return -1;

    crypto_core_ristretto255_add(right, A, cX);
    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

static void schnorr_prove_server(uint8_t A[32], uint8_t s[32],
                                 const uint8_t server_sk[32],
                                 const uint8_t server_pub[32],
                                 const uint8_t nonce_s[32],
                                 const uint8_t eph_s[32]) {
    uint8_t r[32], c[32], cx[32];
    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);

    transcript_t tr;
    tr_init(&tr, "server_schnorr_v1");
    tr_append(&tr, "pubkey", server_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_s", nonce_s, 32);
    tr_append(&tr, "eph_s", eph_s, 32);

    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cx, c, server_sk);
    crypto_core_ristretto255_scalar_add(s, r, cx);

    sodium_memzero(r, sizeof r);
    sodium_memzero(cx, sizeof cx);
    sodium_memzero(c, sizeof c);
}

// -----------------------------
// HKDF & Derivations
// -----------------------------
static void hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);
}

static void hkdf_expand(uint8_t *okm, size_t okm_len, const uint8_t prk[32],
                        const uint8_t *info, size_t info_len) {
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t ctr = 1;
    size_t out = 0;

    while (out < okm_len) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, 32);
        if (t_len) crypto_auth_hmacsha256_update(&st, t, t_len);
        crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &ctr, 1);
        crypto_auth_hmacsha256_final(&st, t);
        t_len = 32;

        size_t take = (okm_len - out < 32) ? (okm_len - out) : 32;
        memcpy(okm + out, t, take);
        out += take;
        ctr++;
    }
    sodium_memzero(t, sizeof t);
}

static int derive_session_key(uint8_t key[32],
                              const uint8_t eph_s_secret[32],
                              const uint8_t eph_c[32],
                              const uint8_t nonce_c[32],
                              const uint8_t nonce_s[32],
                              const uint8_t device_id[32],
                              const uint8_t eph_s[32]) {
    uint8_t shared[32];
    if (crypto_scalarmult_ristretto255(shared, eph_s_secret, eph_c) != 0) {
        sodium_memzero(shared, sizeof shared);
        return -1;
    }

    uint8_t salt[64];
    memcpy(salt, nonce_c, 32);
    memcpy(salt + 32, nonce_s, 32);

    uint8_t info[11 + 32 + 32 + 32];
    size_t off = 0;
    memcpy(info + off, "session key", 11); off += 11;
    memcpy(info + off, device_id, 32); off += 32;
    memcpy(info + off, eph_c, 32); off += 32;
    memcpy(info + off, eph_s, 32); off += 32;

    uint8_t prk[32];
    hkdf_extract(prk, salt, sizeof salt, shared, sizeof shared);
    hkdf_expand(key, 32, prk, info, sizeof info);

    sodium_memzero(shared, sizeof shared);
    sodium_memzero(prk, sizeof prk);
    return 0;
}

static void kc_transcript_hash(uint8_t th[32],
                               const uint8_t device_id[32],
                               const uint8_t a_c[32], const uint8_t s_c[32],
                               const uint8_t nonce_c[32],
                               const uint8_t eph_c[32],
                               const uint8_t server_pub[32],
                               const uint8_t a_s[32], const uint8_t s_s[32],
                               const uint8_t nonce_s[32],
                               const uint8_t eph_s[32]) {
    transcript_t tr;
    tr_init(&tr, "kc_v1");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "a_c", a_c, 32);
    tr_append(&tr, "s_c", s_c, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);
    tr_append(&tr, "server_pub", server_pub, 32);
    tr_append(&tr, "a_s", a_s, 32);
    tr_append(&tr, "s_s", s_s, 32);
    tr_append(&tr, "nonce_s", nonce_s, 32);
    tr_append(&tr, "eph_s", eph_s, 32);

    crypto_hash_sha256(th, tr.buf, (unsigned long long)tr.len);
}

static void derive_kc_keys(uint8_t k_s2c[32], uint8_t k_c2s[32],
                           const uint8_t session_key[32],
                           const uint8_t th[32]) {
    uint8_t prk[32];
    hkdf_extract(prk, th, 32, session_key, 32);
    hkdf_expand(k_s2c, 32, prk, (const uint8_t*)"kc s2c", 6);
    hkdf_expand(k_c2s, 32, prk, (const uint8_t*)"kc c2s", 6);
    sodium_memzero(prk, sizeof prk);
}

static void hmac_tag(uint8_t out[32], const uint8_t key[32], const char *label, const uint8_t th[32]) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, 32);
    crypto_auth_hmacsha256_update(&st, (const unsigned char*)label, (unsigned long long)strlen(label));
    crypto_auth_hmacsha256_update(&st, th, 32);
    crypto_auth_hmacsha256_final(&st, out);
}

// -----------------------------
// TCP listen
// -----------------------------
static int listen_tcp(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(fd, (struct sockaddr*)&addr, sizeof addr) != 0) { close(fd); return -1; }
    if (listen(fd, 32) != 0) { close(fd); return -1; }
    return fd;
}

static int parse_bind(const char *bind, char ip[64], uint16_t *port) {
    const char *colon = strchr(bind, ':');
    if (!colon) return -1;
    size_t il = (size_t)(colon - bind);
    if (il >= 64) return -1;
    memcpy(ip, bind, il);
    ip[il] = 0;

    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

// -----------------------------
// Client Handler
// -----------------------------
static void handle_client(int cfd, const char *peer,
                          reg_entry_t **reg, size_t *reg_n,
                          const uint8_t server_sk[32],
                          const uint8_t server_pub[32]) {
    double start_time = get_time_sec();
    size_t sent = 0, recv = 0;
    uint8_t msg_type;

    if (recv_u8(cfd, &msg_type, &recv) != 0) {
        goto cleanup;
    }

    if (msg_type == MSG_SETUP) {
        uint8_t tlen;
        if (recv_u8(cfd, &tlen, &recv) != 0) goto cleanup;

        if (tlen > 0) {
            uint8_t *tmp = (uint8_t*)malloc(tlen);
            if (!tmp) goto cleanup;
            if (recv_all(cfd, tmp, tlen, &recv) != 0) { free(tmp); goto cleanup; }
            free(tmp);
        }

        uint8_t device_id[32], device_pub[32];
        if (recv_all(cfd, device_id, 32, &recv) != 0) goto cleanup;
        if (recv_all(cfd, device_pub, 32, &recv) != 0) goto cleanup;

        uint8_t server_nonce[32];
        randombytes_buf(server_nonce, 32);

        if (send_all(cfd, server_pub, 32, &sent) != 0) goto cleanup;
        if (send_all(cfd, server_nonce, 32, &sent) != 0) goto cleanup;

        uint8_t A[32], s[32];
        if (recv_all(cfd, A, 32, &recv) != 0) goto cleanup;
        if (recv_all(cfd, s, 32, &recv) != 0) goto cleanup;

        if (schnorr_verify_setup(device_id, device_pub, server_nonce, A, s) != 0) {
            fprintf(stderr, "Server[SETUP]: PoP invalid\n");
            goto cleanup;
        }

        char hex_id[65];
        sodium_bin2hex(hex_id, sizeof(hex_id), device_id, 32);

        int upsert_res = reg_upsert(reg, reg_n, device_id, device_pub);
        if (upsert_res < 0) {
            fprintf(stderr, "Server[SETUP]: registry update failed (mismatch)\n");
            goto cleanup;
        } else if (upsert_res == 1) {
            printf("Server[SETUP]: enrolled NEW device_id=%s\n", hex_id);
        } else {
            printf("Server[SETUP]: validated existing device_id=%s\n", hex_id);
        }
    } 
    else if (msg_type == MSG_AUTH_V2) {
        // 1. ANONYMOUS EPHEMERAL KEY EXCHANGE (ECDHE)
        uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
        if (recv_all(cfd, client_pk, 32, &recv) != 0) goto cleanup;

        uint8_t srv_eph_sk[crypto_kx_SECRETKEYBYTES];
        uint8_t srv_eph_pk[crypto_kx_PUBLICKEYBYTES];
        crypto_kx_keypair(srv_eph_pk, srv_eph_sk);

        if (send_all(cfd, srv_eph_pk, 32, &sent) != 0) goto cleanup;

        uint8_t shared_secret[32];
        if (crypto_scalarmult(shared_secret, srv_eph_sk, client_pk) != 0) {
            fprintf(stderr, "Server[AUTH]: Invalid client X25519 key\n");
            goto cleanup;
        }

        uint8_t hash[64];
        crypto_generichash_state st;
        crypto_generichash_init(&st, NULL, 0, 64);
        crypto_generichash_update(&st, shared_secret, 32);
        crypto_generichash_update(&st, client_pk, 32);
        crypto_generichash_update(&st, srv_eph_pk, 32);
        crypto_generichash_final(&st, hash, 64);

        uint8_t rx_key[32], tx_key[32];
        memcpy(rx_key, hash + 32, 32); // Server rx is hash[32..64]
        memcpy(tx_key, hash, 32);      // Server tx is hash[0..32]

        // 2. READ ENCRYPTED CLIENT PAYLOAD
        uint32_t rx_len;
        if (recv_len(cfd, &rx_len, &recv) != 0) goto cleanup;

        uint8_t *rx_ct = malloc(rx_len);
        if (!rx_ct || recv_all(cfd, rx_ct, rx_len, &recv) != 0) {
            free(rx_ct); goto cleanup;
        }

        uint8_t pt1[160];
        unsigned long long pt1_len;
        uint8_t nonce_rx_1[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};

        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt1, &pt1_len, NULL, rx_ct, rx_len, 
                                                      NULL, 0, nonce_rx_1, rx_key) != 0) {
            fprintf(stderr, "Server[AUTH]: Client payload decryption failed\n");
            free(rx_ct); goto cleanup;
        }
        free(rx_ct);

        if (pt1_len != 160) {
            fprintf(stderr, "Server[AUTH]: Invalid payload size\n");
            goto cleanup;
        }

        uint8_t device_id[32], A_c[32], s_c[32], nonce_c[32], eph_c[32];
        memcpy(device_id, pt1, 32);
        memcpy(A_c, pt1 + 32, 32);
        memcpy(s_c, pt1 + 64, 32);
        memcpy(nonce_c, pt1 + 96, 32);
        memcpy(eph_c, pt1 + 128, 32);

        // 3. REPLAY & SCHNORR VERIFICATION
        if (check_and_insert_replay(device_id, nonce_c) != 0) {
            fprintf(stderr, "Server[AUTH]: Replay detected\n");
            goto cleanup;
        }

        uint8_t expected_pub[32];
        if (reg_lookup(*reg, *reg_n, device_id, expected_pub) != 0) {
            fprintf(stderr, "Server[AUTH]: Unknown device_id\n");
            goto cleanup;
        }

        if (schnorr_verify_auth(device_id, expected_pub, A_c, s_c, nonce_c, eph_c) != 0) {
            fprintf(stderr, "Server[AUTH]: Client proof invalid\n");
            goto cleanup;
        }

        // 4. GENERATE ENCRYPTED RESPONSE
        uint8_t nonce_s[32];
        randombytes_buf(nonce_s, 32);

        uint8_t eph_s_secret[32], eph_s[32];
        crypto_core_ristretto255_scalar_random(eph_s_secret);
        crypto_scalarmult_ristretto255_base(eph_s, eph_s_secret);

        uint8_t A_s[32], s_s[32];
        schnorr_prove_server(A_s, s_s, server_sk, server_pub, nonce_s, eph_s);

        uint8_t session_key[32];
        if (derive_session_key(session_key, eph_s_secret, eph_c, nonce_c, nonce_s, device_id, eph_s) != 0) {
            fprintf(stderr, "Server[AUTH]: invalid eph_c point\n");
            goto cleanup;
        }

        uint8_t th[32];
        kc_transcript_hash(th, device_id, A_c, s_c, nonce_c, eph_c, server_pub, A_s, s_s, nonce_s, eph_s);

        uint8_t k_s2c[32], k_c2s[32];
        derive_kc_keys(k_s2c, k_c2s, session_key, th);

        uint8_t tag_s[32];
        hmac_tag(tag_s, k_s2c, "server finished", th);

        uint8_t payload2[192];
        memcpy(payload2, server_pub, 32);
        memcpy(payload2 + 32, A_s, 32);
        memcpy(payload2 + 64, s_s, 32);
        memcpy(payload2 + 96, nonce_s, 32);
        memcpy(payload2 + 128, eph_s, 32);
        memcpy(payload2 + 160, tag_s, 32);

        uint8_t nonce_tx_1[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
        uint8_t ct2[192 + crypto_aead_chacha20poly1305_IETF_ABYTES];
        unsigned long long ct2_len;

        crypto_aead_chacha20poly1305_ietf_encrypt(ct2, &ct2_len, payload2, sizeof(payload2), 
                                                  NULL, 0, NULL, nonce_tx_1, tx_key);

        send_len(cfd, (uint32_t)ct2_len, &sent);
        if (send_all(cfd, ct2, (size_t)ct2_len, &sent) != 0) goto cleanup;

        // 5. DECRYPT CLIENT CONFIRMATION (tag_c)
        uint32_t rx_len2;
        if (recv_len(cfd, &rx_len2, &recv) != 0) goto cleanup;

        uint8_t *rx_ct2 = malloc(rx_len2);
        if (!rx_ct2 || recv_all(cfd, rx_ct2, rx_len2, &recv) != 0) {
            free(rx_ct2); goto cleanup;
        }

        uint8_t pt3[32];
        unsigned long long pt3_len;
        uint8_t nonce_rx_2[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
        nonce_rx_2[0] = 1; // Expected increment from client!

        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt3, &pt3_len, NULL, rx_ct2, rx_len2, 
                                                      NULL, 0, nonce_rx_2, rx_key) != 0) {
            fprintf(stderr, "Server[AUTH]: tag_c decryption failed\n");
            free(rx_ct2); goto cleanup;
        }
        free(rx_ct2);

        uint8_t expected_tag_c[32];
        hmac_tag(expected_tag_c, k_c2s, "client finished", th);
        if (sodium_memcmp(expected_tag_c, pt3, 32) != 0) {
            fprintf(stderr, "Server[AUTH]: key confirmation failed (tag_c mismatch)\n");
            goto cleanup;
        }

        char hex_id[65], hex_sk[65];
        sodium_bin2hex(hex_id, sizeof(hex_id), device_id, 32);
        sodium_bin2hex(hex_sk, sizeof(hex_sk), session_key, 32);
        
        printf("Server[AUTH]: device_id=%s session_key=%s KC=OK\n", hex_id, hex_sk);

        sodium_memzero(eph_s_secret, 32);
        sodium_memzero(session_key, 32);
        sodium_memzero(k_s2c, 32);
        sodium_memzero(k_c2s, 32);
        sodium_memzero(srv_eph_sk, 32);
        sodium_memzero(shared_secret, 32);
        sodium_memzero(tx_key, 32);
        sodium_memzero(rx_key, 32);
    } 
    else {
        fprintf(stderr, "Server: unknown msg_type\n");
    }

cleanup:
    close(cfd);
    double duration = get_time_sec() - start_time;
    printf("SERVER METRICS -> %s Duration: %.3fms, Sent: %zu bytes, Received: %zu bytes\n", 
           peer, duration * 1000.0, sent, recv);
}

// -----------------------------
// Main
// -----------------------------
int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;

    const char *bind_str = "0.0.0.0:4000";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bind") && i + 1 < argc) bind_str = argv[++i];
        else { fprintf(stderr, "Usage: %s --bind 0.0.0.0:4000\n", argv[0]); return 1; }
    }

    char ip[64];
    uint16_t port;
    if (parse_bind(bind_str, ip, &port) != 0) {
        fprintf(stderr, "bad --bind value\n");
        return 1;
    }

    uint8_t server_sk[32];
    if (file_exists(SERVER_SK_FILE)) {
        if (read_file_32(SERVER_SK_FILE, server_sk) != 0) {
            fprintf(stderr, "failed reading %s\n", SERVER_SK_FILE);
            return 1;
        }
    } else {
        crypto_core_ristretto255_scalar_random(server_sk);
        if (write_file_32(SERVER_SK_FILE, server_sk) != 0) {
            fprintf(stderr, "failed writing %s\n", SERVER_SK_FILE);
            return 1;
        }
    }

    uint8_t server_pub[32];
    crypto_scalarmult_ristretto255_base(server_pub, server_sk);

    reg_entry_t *reg = NULL;
    size_t reg_n = 0;
    if (load_registry(&reg, &reg_n) != 0) {
        fprintf(stderr, "Failed to load registry\n");
        return 1;
    }

    int lfd = listen_tcp(ip, port);
    if (lfd < 0) { fprintf(stderr, "listen failed\n"); return 1; }
    printf("C Server listening on %s\n", bind_str);

    for (;;) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int cfd = accept(lfd, (struct sockaddr*)&peer_addr, &peer_len);
        if (cfd < 0) continue;

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
        
        char peer_str[64];
        snprintf(peer_str, sizeof(peer_str), "%s:%d", peer_ip, ntohs(peer_addr.sin_port));

        handle_client(cfd, peer_str, &reg, &reg_n, server_sk, server_pub);
    }
}