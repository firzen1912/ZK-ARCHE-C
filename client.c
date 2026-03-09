#define _POSIX_C_SOURCE 200112L
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

// -----------------------------
// Protocol constants
// -----------------------------
#define MSG_SETUP 0x01
#define MSG_AUTH_V2 0x03

#define STATE_DIR        "."
#define DEVICE_ROOT_FILE "device_root.bin"
#define SERVER_PUB_FILE  "server_pub.bin"

// -----------------------------
// File + directory helpers
// -----------------------------
static int file_exists(const char *path) { return access(path, F_OK) == 0; }

static int ensure_state_dir(void) {
    struct stat st;
    if (stat(STATE_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            errno = ENOTDIR;
            return -1;
        }
        return 0;
    }

    if (mkdir(STATE_DIR, 0700) == 0) {
        return 0;
    }

    return -1;
}

static int read_file_32(const char *path, uint8_t out[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, 32, f);
    fclose(f);
    return (n == 32) ? 0 : -1;
}

static int write_file_32(const char *path, const uint8_t in[32]) {
    if (ensure_state_dir() != 0) return -1;

    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(in, 1, 32, f);
    fclose(f);
    if (n != 32) return -1;

    if (chmod(path, 0600) != 0) {
        return -1;
    }
    return 0;
}

// -----------------------------
// Root-secret model
// -----------------------------
static int load_or_create_device_root(uint8_t root[32], int *created) {
    if (file_exists(DEVICE_ROOT_FILE)) {
        if (read_file_32(DEVICE_ROOT_FILE, root) != 0) return -1;
        if (created) *created = 0;
        return 0;
    }

    randombytes_buf(root, 32);
    if (write_file_32(DEVICE_ROOT_FILE, root) != 0) return -1;
    if (created) *created = 1;
    return 0;
}

static void derive_device_id(const uint8_t root[32], uint8_t device_id[32]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const unsigned char *)"device-id", 9);
    crypto_generichash_update(&st, root, 32);
    crypto_generichash_final(&st, device_id, 32);
}

static void derive_device_scalar(const uint8_t root[32], uint8_t x[32]) {
    uint8_t wide[64];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 64);
    crypto_generichash_update(&st, (const unsigned char *)"device-auth-v1", 14);
    crypto_generichash_update(&st, root, 32);
    crypto_generichash_final(&st, wide, 64);
    crypto_core_ristretto255_scalar_reduce(x, wide);
    sodium_memzero(wide, sizeof wide);
}

static int load_device_creds_from_root(uint8_t device_id[32], uint8_t x[32], int *created_root) {
    uint8_t root[32];
    if (load_or_create_device_root(root, created_root) != 0) return -1;
    derive_device_id(root, device_id);
    derive_device_scalar(root, x);
    sodium_memzero(root, sizeof root);
    return 0;
}

static int creds_exist(void) {
    return file_exists(DEVICE_ROOT_FILE);
}

// -----------------------------
// Timing + TCP helpers
// -----------------------------
static double get_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int tcp_connect(const char *hostport) {
    char host[256] = {0};
    char port[32] = {0};

    const char *colon = strchr(hostport, ':');
    if (!colon) return -1;

    size_t hl = (size_t)(colon - hostport);
    if (hl >= sizeof(host)) return -1;
    memcpy(host, hostport, hl);
    strncpy(port, colon + 1, sizeof(port) - 1);

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int send_all(int fd, const uint8_t *buf, size_t len, size_t *sent_tracker) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    if (sent_tracker) *sent_tracker += len;
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
// Transcript (Merlin replacement)
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

    if (tr->len + 1 + llen + 4 + (size_t)vlen > sizeof(tr->buf)) {
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
// Schnorr proofs (client) + server verify
// -----------------------------
static void schnorr_prove_setup(uint8_t A[32], uint8_t s[32],
                                const uint8_t x[32],
                                const uint8_t device_id[32],
                                const uint8_t pubkey[32],
                                const uint8_t server_nonce[32]) {
    uint8_t r[32], c[32], cx[32];

    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);

    transcript_t tr;
    tr_init(&tr, "setup_schnorr_v1");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", pubkey, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "server_nonce", server_nonce, 32);

    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(s, r, cx);

    sodium_memzero(r, sizeof r);
    sodium_memzero(cx, sizeof cx);
    sodium_memzero(c, sizeof c);
}

static void schnorr_prove_auth(uint8_t A[32], uint8_t s[32],
                               const uint8_t x[32],
                               const uint8_t device_id[32],
                               const uint8_t pubkey[32],
                               const uint8_t nonce_c[32],
                               const uint8_t eph_c[32]) {
    uint8_t r[32], c[32], cx[32];

    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);

    transcript_t tr;
    tr_init(&tr, "client_schnorr_v1");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", pubkey, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);

    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(s, r, cx);

    sodium_memzero(r, sizeof r);
    sodium_memzero(cx, sizeof cx);
    sodium_memzero(c, sizeof c);
}

static int schnorr_verify_server(const uint8_t server_pub[32],
                                 const uint8_t A[32],
                                 const uint8_t s[32],
                                 const uint8_t nonce_s[32],
                                 const uint8_t eph_s[32]) {
    uint8_t c[32], left[32], cX[32], right[32];

    transcript_t tr;
    tr_init(&tr, "server_schnorr_v1");
    tr_append(&tr, "pubkey", server_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_s", nonce_s, 32);
    tr_append(&tr, "eph_s", eph_s, 32);

    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);

    if (crypto_scalarmult_ristretto255(cX, c, server_pub) != 0) {
        return -1;
    }

    crypto_core_ristretto255_add(right, A, cX);
    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

// -----------------------------
// HKDF-SHA256
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
                              const uint8_t eph_secret[32],
                              const uint8_t eph_s[32],
                              const uint8_t nonce_c[32],
                              const uint8_t nonce_s[32],
                              const uint8_t device_id[32],
                              const uint8_t eph_c[32]) {
    uint8_t shared[32];
    if (crypto_scalarmult_ristretto255(shared, eph_secret, eph_s) != 0) {
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

// -----------------------------
// KC transcript hash + tag helpers
// -----------------------------
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
// Setup Flow
// -----------------------------
static int do_setup(const char *server, const uint8_t device_id[32], const uint8_t x[32]) {
    double start_time = get_time_sec();
    size_t sent = 0, recv = 0;

    int fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return -1; }

    printf("Client[SETUP]: Connected to %s\n", server);

    uint8_t device_pub[32];
    crypto_scalarmult_ristretto255_base(device_pub, x);

    uint8_t msg = MSG_SETUP;
    uint8_t toklen = 0;
    if (send_all(fd, &msg, 1, &sent) != 0) { close(fd); return -1; }
    if (send_all(fd, &toklen, 1, &sent) != 0) { close(fd); return -1; }

    if (send_all(fd, device_id, 32, &sent) != 0) { close(fd); return -1; }
    if (send_all(fd, device_pub, 32, &sent) != 0) { close(fd); return -1; }

    uint8_t server_pub[32];
    uint8_t server_nonce[32];
    if (recv_all(fd, server_pub, 32, &recv) != 0) { close(fd); return -1; }
    if (recv_all(fd, server_nonce, 32, &recv) != 0) { close(fd); return -1; }

    if (!file_exists(SERVER_PUB_FILE)) {
        if (write_file_32(SERVER_PUB_FILE, server_pub) != 0) {
            fprintf(stderr, "failed to write %s\n", SERVER_PUB_FILE);
            close(fd);
            return -1;
        }
        printf("Client[SETUP]: Pinning server pubkey (TOFU) to %s\n", SERVER_PUB_FILE);
    } else {
        uint8_t pinned[32];
        if (read_file_32(SERVER_PUB_FILE, pinned) != 0) {
            fprintf(stderr, "failed to read %s\n", SERVER_PUB_FILE);
            close(fd);
            return -1;
        }
        if (sodium_memcmp(pinned, server_pub, 32) != 0) {
            fprintf(stderr, "MITM ALERT: Server offered a different public key than our pinned key!\n");
            close(fd);
            return -1;
        }
        printf("Client[SETUP]: Server pubkey matches pinned value.\n");
    }

    uint8_t A[32], s[32];
    schnorr_prove_setup(A, s, x, device_id, device_pub, server_nonce);
    if (send_all(fd, A, 32, &sent) != 0) { close(fd); return -1; }
    if (send_all(fd, s, 32, &sent) != 0) { close(fd); return -1; }
    close(fd);

    char hex_id[65];
    sodium_bin2hex(hex_id, sizeof(hex_id), device_id, 32);

    double duration = get_time_sec() - start_time;
    printf("Client[SETUP]: Sent=%zu bytes, Received=%zu bytes. Enrolled device_id=%s\n", sent, recv, hex_id);
    printf("CLIENT METRICS -> Duration: %.3fms\n", duration * 1000.0);

    return 0;
}

// -----------------------------
// Auth Flow V2 (Encrypted Zero-Privacy Tunnel)
// -----------------------------
static int do_auth_v2(const char *server, const uint8_t device_id[32], const uint8_t x[32]) {
    double start_time = get_time_sec();
    size_t sent = 0, recv = 0;

    uint8_t pinned_server_pub[32];
    if (read_file_32(SERVER_PUB_FILE, pinned_server_pub) != 0) {
        fprintf(stderr, "Missing %s; run with --setup first\n", SERVER_PUB_FILE);
        return -1;
    }

    int fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return -1; }

    printf("Client[AUTH]: Connected to %s\n", server);

    // 1. ANONYMOUS EPHEMERAL KEY EXCHANGE (ECDHE)
    uint8_t client_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    uint8_t msg = MSG_AUTH_V2;
    if (send_all(fd, &msg, 1, &sent) != 0) { close(fd); return -1; }
    if (send_all(fd, client_pk, 32, &sent) != 0) { close(fd); return -1; }

    uint8_t server_pk[32];
    if (recv_all(fd, server_pk, 32, &recv) != 0) { close(fd); return -1; }

    uint8_t shared_secret[32];
    if (crypto_scalarmult(shared_secret, client_sk, server_pk) != 0) {
        fprintf(stderr, "Client[AUTH]: Invalid server X25519 key\n");
        close(fd); return -1;
    }

    uint8_t hash[64];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 64);
    crypto_generichash_update(&st, shared_secret, 32);
    crypto_generichash_update(&st, client_pk, 32);
    crypto_generichash_update(&st, server_pk, 32);
    crypto_generichash_final(&st, hash, 64);

    uint8_t rx_key[32], tx_key[32];
    memcpy(rx_key, hash, 32);
    memcpy(tx_key, hash + 32, 32);

    // 2. ENCRYPT IDENTITY AND SCHNORR PROOF
    uint8_t device_pub[32];
    crypto_scalarmult_ristretto255_base(device_pub, x);

    uint8_t nonce_c[32];
    randombytes_buf(nonce_c, 32);

    uint8_t eph_secret[32], eph_c[32];
    crypto_core_ristretto255_scalar_random(eph_secret);
    crypto_scalarmult_ristretto255_base(eph_c, eph_secret);

    uint8_t A_c[32], s_c[32];
    schnorr_prove_auth(A_c, s_c, x, device_id, device_pub, nonce_c, eph_c);

    uint8_t payload1[160];
    memcpy(payload1, device_id, 32);
    memcpy(payload1 + 32, A_c, 32);
    memcpy(payload1 + 64, s_c, 32);
    memcpy(payload1 + 96, nonce_c, 32);
    memcpy(payload1 + 128, eph_c, 32);

    uint8_t nonce_tx_1[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
    uint8_t ct1[160 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ct1_len;

    crypto_aead_chacha20poly1305_ietf_encrypt(ct1, &ct1_len, payload1, sizeof(payload1),
                                              NULL, 0, NULL, nonce_tx_1, tx_key);

    send_len(fd, (uint32_t)ct1_len, &sent);
    if (send_all(fd, ct1, (size_t)ct1_len, &sent) != 0) { close(fd); return -1; }

    // 3. READ ENCRYPTED SERVER RESPONSE
    uint32_t rx_len;
    if (recv_len(fd, &rx_len, &recv) != 0) { close(fd); return -1; }

    uint8_t *rx_ct = malloc(rx_len);
    if (!rx_ct || recv_all(fd, rx_ct, rx_len, &recv) != 0) {
        free(rx_ct); close(fd); return -1;
    }

    uint8_t pt2[192];
    unsigned long long pt2_len;
    uint8_t nonce_rx_1[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};

    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt2, &pt2_len, NULL, rx_ct, rx_len,
                                                  NULL, 0, nonce_rx_1, rx_key) != 0) {
        fprintf(stderr, "Client[AUTH]: Server payload decryption failed\n");
        free(rx_ct); close(fd); return -1;
    }
    free(rx_ct);

    if (pt2_len != 192) {
        fprintf(stderr, "Client[AUTH]: Invalid server payload size\n");
        close(fd); return -1;
    }

    uint8_t server_pub[32], A_s[32], s_s[32], nonce_s[32], eph_s[32], tag_s[32];
    memcpy(server_pub, pt2, 32);
    memcpy(A_s, pt2 + 32, 32);
    memcpy(s_s, pt2 + 64, 32);
    memcpy(nonce_s, pt2 + 96, 32);
    memcpy(eph_s, pt2 + 128, 32);
    memcpy(tag_s, pt2 + 160, 32);

    if (sodium_memcmp(server_pub, pinned_server_pub, 32) != 0) {
        fprintf(stderr, "Client[AUTH]: Server pubkey mismatch vs pinned (refuse auth)\n");
        close(fd); return -1;
    }

    if (schnorr_verify_server(server_pub, A_s, s_s, nonce_s, eph_s) != 0) {
        fprintf(stderr, "Client[AUTH]: Authentication FAILED\n");
        close(fd); return -1;
    }
    printf("Client[AUTH]: Server Schnorr authentication = true\n");

    uint8_t session_key[32];
    if (derive_session_key(session_key, eph_secret, eph_s, nonce_c, nonce_s, device_id, eph_c) != 0) {
        fprintf(stderr, "Client[AUTH]: invalid eph_s point\n");
        close(fd); return -1;
    }

    uint8_t th[32];
    kc_transcript_hash(th, device_id, A_c, s_c, nonce_c, eph_c, server_pub, A_s, s_s, nonce_s, eph_s);

    uint8_t k_s2c[32], k_c2s[32];
    derive_kc_keys(k_s2c, k_c2s, session_key, th);

    uint8_t expected_s[32];
    hmac_tag(expected_s, k_s2c, "server finished", th);
    if (sodium_memcmp(expected_s, tag_s, 32) != 0) {
        fprintf(stderr, "Client[AUTH]: server key confirmation failed (tag_s mismatch)\n");
        close(fd); return -1;
    }
    printf("Client[AUTH]: Key confirmation (server finished) OK\n");

    // 4. SEND ENCRYPTED CLIENT CONFIRMATION (tag_c)
    uint8_t tag_c[32];
    hmac_tag(tag_c, k_c2s, "client finished", th);

    uint8_t nonce_tx_2[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
    nonce_tx_2[0] = 1;

    uint8_t ct3[32 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ct3_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(ct3, &ct3_len, tag_c, 32,
                                              NULL, 0, NULL, nonce_tx_2, tx_key);

    send_len(fd, (uint32_t)ct3_len, &sent);
    if (send_all(fd, ct3, (size_t)ct3_len, &sent) != 0) { close(fd); return -1; }
    printf("Client[AUTH]: Sent encrypted client finished tag\n");

    double duration = get_time_sec() - start_time;
    printf("CLIENT METRICS -> Duration: %.3fms, Sent: %zu bytes, Received: %zu bytes\n", duration * 1000.0, sent, recv);

    sodium_memzero(eph_secret, 32);
    sodium_memzero(session_key, 32);
    sodium_memzero(k_s2c, 32);
    sodium_memzero(k_c2s, 32);
    sodium_memzero(client_sk, 32);
    sodium_memzero(shared_secret, 32);
    sodium_memzero(tx_key, 32);
    sodium_memzero(rx_key, 32);

    close(fd);
    return 0;
}

// -----------------------------
// Main
// -----------------------------
static void usage(const char *p) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s --server 127.0.0.1:4000 --setup\n", p);
    fprintf(stderr, "  %s --server 127.0.0.1:4000\n", p);
    fprintf(stderr, "  %s --pin-server-pub <hex_string>\n", p);
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;

    const char *server = "127.0.0.1:4000";
    int setup = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server") && i + 1 < argc) {
            server = argv[++i];
        } else if (!strcmp(argv[i], "--setup")) {
            setup = 1;
        } else if (!strcmp(argv[i], "--pin-server-pub") && i + 1 < argc) {
            const char *hex_str = argv[++i];
            uint8_t pinned[32];
            size_t bin_len;
            if (sodium_hex2bin(pinned, sizeof(pinned), hex_str, strlen(hex_str), NULL, &bin_len, NULL) != 0 || bin_len != 32) {
                fprintf(stderr, "Client: invalid hex for pinned key\n");
                return 1;
            }
            if (write_file_32(SERVER_PUB_FILE, pinned) != 0) {
                fprintf(stderr, "Client: failed to write pinned key\n");
                return 1;
            }
            printf("Client: Successfully pinned server pubkey out-of-band.\n");
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    uint8_t device_id[32], x[32];
    int created_root = 0;

    if (!creds_exist() && !setup) {
        fprintf(stderr, "Client: device root missing (%s). Refusing AUTH. Run with --setup to enroll.\n", DEVICE_ROOT_FILE);
        return 0;
    }

    if (load_device_creds_from_root(device_id, x, &created_root) != 0) {
        fprintf(stderr, "Failed loading/creating device root\n");
        return 1;
    }

    if (setup) {
        if (created_root) {
            printf("Client[SETUP]: No device root found; generating NEW device root (re-enroll).\n");
        } else {
            printf("Client[SETUP]: Using existing device root for setup (idempotent).\n");
        }
    }

    int rc = setup ? do_setup(server, device_id, x) : do_auth_v2(server, device_id, x);
    sodium_memzero(x, 32);
    sodium_memzero(device_id, 32);
    return (rc == 0) ? 0 : 1;
}
