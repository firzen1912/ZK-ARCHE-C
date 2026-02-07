#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MSG_SETUP 0x01
#define MSG_AUTH  0x02

#define REGISTRY_BIN "registry.bin"
#define SERVER_SK_FILE "server_sk.bin"

// Demo constant server identity binding (same as Rust)
static const uint8_t SERVER_ID[32] = { [0 ... 31] = 0x53 };


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

// registry format: repeated (device_id 32 || pubkey 32)
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
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (sz % 64) != 0) { fclose(f); return -1; }

    size_t n = (size_t)sz / 64;
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
    FILE *f = fopen(REGISTRY_BIN, "wb");
    if (!f) return -1;
    for (size_t i = 0; i < n; i++) {
        if (fwrite(arr[i].id, 1, 32, f) != 32) { fclose(f); return -1; }
        if (fwrite(arr[i].pub, 1, 32, f) != 32) { fclose(f); return -1; }
    }
    fclose(f);
    return 0;
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
            // idempotent must match key
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
    return save_registry(arr, n);
}

// -----------------------------
// Network helpers
// -----------------------------
static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int recv_u8(int fd, uint8_t *out) { return recv_all(fd, out, 1); }

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
    tr->buf[tr->len++] = (uint8_t)dlen;
    memcpy(tr->buf + tr->len, domain, dlen);
    tr->len += dlen;
}

static void tr_append(transcript_t *tr, const char *label, const uint8_t *val, uint32_t vlen) {
    size_t llen = strlen(label);
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
// Schnorr verify + prove server
// -----------------------------
static int schnorr_verify_setup(const uint8_t device_id[32], const uint8_t pubkey[32],
                                const uint8_t server_nonce[32], const uint8_t A[32], const uint8_t s[32]) {
    uint8_t c[32], left[32], cX[32], right[32];

    transcript_t tr;
    tr_init(&tr, "setup_schnorr");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", pubkey, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "server_nonce", server_nonce, 32);

    tr_challenge_scalar(c, &tr);

    crypto_scalarmult_ristretto255_base(left, s);
    crypto_scalarmult_ristretto255(cX, c, pubkey);
    crypto_core_ristretto255_add(right, A, cX);

    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

static int schnorr_verify_auth(const uint8_t device_id[32], const uint8_t expected_pub[32],
                               const uint8_t A[32], const uint8_t s[32],
                               const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t c[32], left[32], cX[32], right[32];

    transcript_t tr;
    tr_init(&tr, "client_schnorr");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", expected_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);

    tr_challenge_scalar(c, &tr);

    crypto_scalarmult_ristretto255_base(left, s);
    crypto_scalarmult_ristretto255(cX, c, expected_pub);
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
    tr_init(&tr, "server_schnorr");
    tr_append(&tr, "server_id", SERVER_ID, 32);
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
// HKDF-SHA256 (same as client)
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

static void derive_session_key(uint8_t key[32],
                               const uint8_t eph_s_secret[32],
                               const uint8_t eph_c[32],
                               const uint8_t nonce_c[32],
                               const uint8_t nonce_s[32],
                               const uint8_t device_id[32],
                               const uint8_t eph_s[32]) {
    uint8_t shared[32];
    crypto_scalarmult_ristretto255(shared, eph_s_secret, eph_c);

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
}

// -----------------------------
// Server main loop
// -----------------------------
static int listen_tcp(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(fd, (struct sockaddr*)&addr, sizeof addr) != 0) { close(fd); return -1; }
    if (listen(fd, 32) != 0) { close(fd); return -1; }
    return fd;
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;

    const char *bind = "0.0.0.0:4000";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bind") && i + 1 < argc) bind = argv[++i];
        else { fprintf(stderr, "Usage: %s --bind 0.0.0.0:4000\n", argv[0]); return 1; }
    }

    // parse ip:port
    char ip[64] = {0};
    char port_s[16] = {0};
    const char *colon = strchr(bind, ':');
    if (!colon) return 1;
    size_t il = (size_t)(colon - bind);
    if (il >= sizeof ip) return 1;
    memcpy(ip, bind, il);
    strncpy(port_s, colon + 1, sizeof(port_s) - 1);
    int port = atoi(port_s);

    // server static key (persist if you want; for now load-or-create)
    uint8_t server_sk[32];
    if (file_exists(SERVER_SK_FILE)) {
        if (read_file_32(SERVER_SK_FILE, server_sk) != 0) return 1;
    } else {
        crypto_core_ristretto255_scalar_random(server_sk);
        if (write_file_32(SERVER_SK_FILE, server_sk) != 0) return 1;
    }
    uint8_t server_pub[32];
    crypto_scalarmult_ristretto255_base(server_pub, server_sk);

    // load registry
    reg_entry_t *reg = NULL;
    size_t reg_n = 0;
    if (load_registry(&reg, &reg_n) != 0) {
        fprintf(stderr, "Failed to load registry\n");
        return 1;
    }

    int lfd = listen_tcp(ip, (uint16_t)port);
    if (lfd < 0) { fprintf(stderr, "listen failed\n"); return 1; }
    printf("C Server listening on %s\n", bind);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;

        uint8_t msg_type;
        if (recv_u8(cfd, &msg_type) != 0) { close(cfd); continue; }

        if (msg_type == MSG_SETUP) {
            // token_len (ignored but must be consumed)
            uint8_t tlen;
            if (recv_u8(cfd, &tlen) != 0) { close(cfd); continue; }
            if (tlen) {
                uint8_t tmp[256];
                if (recv_all(cfd, tmp, tlen) != 0) { close(cfd); continue; }
            }

            uint8_t device_id[32], pubkey[32];
            if (recv_all(cfd, device_id, 32) != 0) { close(cfd); continue; }
            if (recv_all(cfd, pubkey, 32) != 0) { close(cfd); continue; }

            uint8_t server_nonce[32];
            randombytes_buf(server_nonce, 32);
            if (send_all(cfd, server_nonce, 32) != 0) { close(cfd); continue; }

            uint8_t A[32], s[32];
            if (recv_all(cfd, A, 32) != 0) { close(cfd); continue; }
            if (recv_all(cfd, s, 32) != 0) { close(cfd); continue; }

            if (schnorr_verify_setup(device_id, pubkey, server_nonce, A, s) != 0) {
                fprintf(stderr, "SETUP: PoP invalid\n");
                close(cfd);
                continue;
            }

            if (reg_upsert(&reg, &reg_n, device_id, pubkey) != 0) {
                fprintf(stderr, "SETUP: registry update failed\n");
                close(cfd);
                continue;
            }

            printf("SETUP: ok device enrolled/validated\n");
            close(cfd);
            continue;
        }

        if (msg_type == MSG_AUTH) {
            uint8_t device_id[32], A_c[32], s_c[32], nonce_c[32], eph_c[32];
            if (recv_all(cfd, device_id, 32) != 0) { close(cfd); continue; }
            if (recv_all(cfd, A_c, 32) != 0) { close(cfd); continue; }
            if (recv_all(cfd, s_c, 32) != 0) { close(cfd); continue; }
            if (recv_all(cfd, nonce_c, 32) != 0) { close(cfd); continue; }
            if (recv_all(cfd, eph_c, 32) != 0) { close(cfd); continue; }

            uint8_t expected_pub[32];
            if (reg_lookup(reg, reg_n, device_id, expected_pub) != 0) {
                fprintf(stderr, "AUTH: unknown device\n");
                close(cfd);
                continue;
            }

            if (schnorr_verify_auth(device_id, expected_pub, A_c, s_c, nonce_c, eph_c) != 0) {
                fprintf(stderr, "AUTH: client proof invalid\n");
                close(cfd);
                continue;
            }

            // server response
            uint8_t nonce_s[32];
            randombytes_buf(nonce_s, 32);

            uint8_t eph_s_secret[32], eph_s[32];
            crypto_core_ristretto255_scalar_random(eph_s_secret);
            crypto_scalarmult_ristretto255_base(eph_s, eph_s_secret);

            uint8_t A_s[32], s_s[32];
            schnorr_prove_server(A_s, s_s, server_sk, server_pub, nonce_s, eph_s);

            // send: server_pub | A_s | s_s | nonce_s | eph_s
            if (send_all(cfd, server_pub, 32) != 0) { close(cfd); continue; }
            if (send_all(cfd, A_s, 32) != 0) { close(cfd); continue; }
            if (send_all(cfd, s_s, 32) != 0) { close(cfd); continue; }
            if (send_all(cfd, nonce_s, 32) != 0) { close(cfd); continue; }
            if (send_all(cfd, eph_s, 32) != 0) { close(cfd); continue; }

            uint8_t key[32];
            derive_session_key(key, eph_s_secret, eph_c, nonce_c, nonce_s, device_id, eph_s);

            printf("AUTH: ok, session key = ");
            for (int i = 0; i < 32; i++) printf("%02x", key[i]);
            printf("\n");

            sodium_memzero(eph_s_secret, 32);
            sodium_memzero(key, 32);
            close(cfd);
            continue;
        }

        close(cfd);
    }
}
