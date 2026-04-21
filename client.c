#define _POSIX_C_SOURCE 200112L
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#define MSG_SETUP    0x01
#define MSG_AUTH_V2  0x03

#define STATE_DIR        "/var/lib/iot-auth"
#define CLIENT_STATE_DIR "/var/lib/iot-auth/client"
#define DEVICE_ROOT_FILE "/var/lib/iot-auth/client/device_root.bin"
#define SERVER_PUB_FILE  "/var/lib/iot-auth/client/server_pub.bin"
#define ROLE_CRED_FILE   "/var/lib/iot-auth/client/role_cred.bin"

#define NONCE_LEN 32
#define SETUP_CHALLENGE_LEN 16
#define MAX_ENCRYPTED_PAYLOAD 4096
#define IO_TIMEOUT_SEC 5

#define T_SETUP        "setup_client_schnorr_v1"
#define T_SETUP_SERVER "setup_server_schnorr_v1"
#define T_SERVER       "server_schnorr_v1"
#define T_PID          "iot-auth/pid/v1"
#define T_CLIENT_V2    "client_schnorr_v2"
#define T_KC_V2        "kc_v2"
#define T_ROLE_SET     "client_role_set_v1"
#define T_ROLE_RERAND  "client_role_rerand_v1"
#define T_ATTR_ROLE    "client_attr_role_v1"

static const uint64_t ALLOWED_ROLES[] = {1ULL, 2ULL};
#define ALLOWED_ROLE_COUNT (sizeof(ALLOWED_ROLES) / sizeof(ALLOWED_ROLES[0]))

typedef struct { uint64_t count; } nonce_ctr_t;
typedef struct { uint8_t buf[4096]; size_t len; } transcript_t;
typedef struct {
    uint64_t role_code;
    uint8_t role_scalar[32];
    uint8_t blind[32];
    uint8_t commitment[32];
} role_cred_t;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1000000.0;
}

static void print_client_metrics(double start_ms, size_t sent, size_t recv_bytes) {
    double duration_ms = now_ms() - start_ms;
    printf("CLIENT METRICS -> Duration: %.6fms, Sent: %zu bytes, Received: %zu bytes\n",
           duration_ms, sent, recv_bytes);
}

static void bin2hex_lower(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    sodium_bin2hex(out, out_len, in, in_len);
}

static void nonce_next(nonce_ctr_t *c, uint8_t out[12]) {
    uint64_t v = c->count++;
    memset(out, 0, 12);
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

static int file_exists(const char *path) { return access(path, F_OK) == 0; }

static int ensure_state_dir(void) {
    struct stat st;
    if (stat(STATE_DIR, &st) != 0) {
        if (mkdir(STATE_DIR, 0700) != 0 && errno != EEXIST) return -1;
    }
    if (stat(CLIENT_STATE_DIR, &st) != 0) {
        if (mkdir(CLIENT_STATE_DIR, 0700) != 0 && errno != EEXIST) return -1;
    }
    chmod(STATE_DIR, 0700);
    chmod(CLIENT_STATE_DIR, 0700);
    return 0;
}

static int write_exact_file(const char *path, const uint8_t *buf, size_t len, mode_t mode) {
    FILE *f;
    if (ensure_state_dir() != 0) return -1;
    f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return chmod(path, mode);
}

static int read_exact_file(const char *path, uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fread(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static void le64_store(uint8_t out[8], uint64_t v) {
    out[0] = (uint8_t)(v);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

static uint64_t le64_load(const uint8_t in[8]) {
    return ((uint64_t)in[0]) |
           ((uint64_t)in[1] << 8) |
           ((uint64_t)in[2] << 16) |
           ((uint64_t)in[3] << 24) |
           ((uint64_t)in[4] << 32) |
           ((uint64_t)in[5] << 40) |
           ((uint64_t)in[6] << 48) |
           ((uint64_t)in[7] << 56);
}

static int read_file_32(const char *path, uint8_t out[32]) { return read_exact_file(path, out, 32); }
static int write_file_32(const char *path, const uint8_t in[32]) { return write_exact_file(path, in, 32, 0600); }

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

static int recv_all(int fd, uint8_t *buf, size_t len, size_t *recv_bytes) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    if (recv_bytes) *recv_bytes += len;
    return 0;
}

static int send_u32_le(int fd, uint32_t v, size_t *sent) {
    uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    return send_all(fd, b, 4, sent);
}

static int recv_u32_le(int fd, uint32_t *v, size_t *recv_bytes) {
    uint8_t b[4];
    if (recv_all(fd, b, 4, recv_bytes) != 0) return -1;
    *v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return 0;
}

static uint8_t *recv_encrypted_blob(int fd, uint32_t *out_len, size_t *recv_bytes) {
    uint32_t n;
    uint8_t *buf;
    if (recv_u32_le(fd, &n, recv_bytes) != 0) return NULL;
    if (n > MAX_ENCRYPTED_PAYLOAD) return NULL;
    buf = malloc(n ? n : 1);
    if (!buf) return NULL;
    if (n && recv_all(fd, buf, n, recv_bytes) != 0) { free(buf); return NULL; }
    *out_len = n;
    return buf;
}

static void tr_init(transcript_t *tr, const char *domain) {
    size_t dlen = strlen(domain);
    tr->len = 0;
    tr->buf[tr->len++] = (uint8_t)dlen;
    memcpy(tr->buf + tr->len, domain, dlen);
    tr->len += dlen;
}

static void tr_append(transcript_t *tr, const char *label, const uint8_t *val, uint32_t vlen) {
    size_t llen = strlen(label);
    tr->buf[tr->len++] = (uint8_t)llen;
    memcpy(tr->buf + tr->len, label, llen); tr->len += llen;
    tr->buf[tr->len++] = (uint8_t)vlen;
    tr->buf[tr->len++] = (uint8_t)(vlen >> 8);
    tr->buf[tr->len++] = (uint8_t)(vlen >> 16);
    tr->buf[tr->len++] = (uint8_t)(vlen >> 24);
    memcpy(tr->buf + tr->len, val, vlen); tr->len += vlen;
}

static void tr_challenge_scalar(uint8_t out[32], const transcript_t *tr) {
    uint8_t h[64];
    crypto_hash_sha512(h, tr->buf, (unsigned long long)tr->len);
    crypto_core_ristretto255_scalar_reduce(out, h);
}

static int check_point(const uint8_t p[32], const char *what) {
    if (crypto_core_ristretto255_is_valid_point(p) != 1) {
        fprintf(stderr, "%s invalid\n", what);
        return -1;
    }
    return 0;
}

static void hash_to_point(const char *label, uint8_t out[32]) {
    uint8_t h[64];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const unsigned char *)"ristretto-hash-to-point-v1", 26);
    crypto_hash_sha512_update(&st, (const unsigned char *)label, strlen(label));
    crypto_hash_sha512_final(&st, h);
    crypto_core_ristretto255_from_hash(out, h);
}

static void attr_h(uint8_t out[32]) { hash_to_point("iot-auth/attr-h/v1", out); }

static void scalar_zero(uint8_t s[32]) { memset(s, 0, 32); }

static void scalar_from_u64(uint64_t v, uint8_t out[32]) {
    scalar_zero(out);
    le64_store(out, v);
}

static void compute_pid(uint8_t pid[32], const uint8_t device_pub[32], const uint8_t nonce_c[32],
                        const uint8_t eph_c[32], const uint8_t server_pub[32]) {
    crypto_hash_sha256_state st;
    uint8_t dlen[4];
    uint32_t n = (uint32_t)strlen(T_PID);
    dlen[0] = (uint8_t)n; dlen[1] = (uint8_t)(n >> 8); dlen[2] = (uint8_t)(n >> 16); dlen[3] = (uint8_t)(n >> 24);
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, dlen, 4);
    crypto_hash_sha256_update(&st, (const unsigned char *)T_PID, n);
    crypto_hash_sha256_update(&st, device_pub, 32);
    crypto_hash_sha256_update(&st, nonce_c, 32);
    crypto_hash_sha256_update(&st, eph_c, 32);
    crypto_hash_sha256_update(&st, server_pub, 32);
    crypto_hash_sha256_final(&st, pid);
}

static int rerandomize_role_commitment(uint8_t c_prime[32], uint8_t blind_prime[32], uint8_t delta[32],
                                       const role_cred_t *cred) {
    uint8_t h[32], h_delta[32];
    attr_h(h);
    crypto_core_ristretto255_scalar_random(delta);
    crypto_core_ristretto255_scalar_add(blind_prime, cred->blind, delta);
    if (crypto_scalarmult_ristretto255(h_delta, delta, h) != 0) return -1;
    crypto_core_ristretto255_add(c_prime, cred->commitment, h_delta);
    return 0;
}

static int prove_role_rerandomization(uint8_t A[32], uint8_t s[32], const uint8_t stored_c[32], const uint8_t c_prime[32],
                                      const uint8_t delta[32], const uint8_t pid[32], const uint8_t nonce_c[32],
                                      const uint8_t eph_c[32]) {
    uint8_t h[32], r[32], c[32], cd[32];
    transcript_t tr;
    attr_h(h);
    crypto_core_ristretto255_scalar_random(r);
    if (crypto_scalarmult_ristretto255(A, r, h) != 0) return -1;
    tr_init(&tr, T_ROLE_RERAND);
    tr_append(&tr, "pid", pid, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);
    tr_append(&tr, "stored_c", stored_c, 32);
    tr_append(&tr, "c_prime", c_prime, 32);
    tr_append(&tr, "a", A, 32);
    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cd, c, delta);
    crypto_core_ristretto255_scalar_add(s, r, cd);
    return 0;
}

static int prove_role_set_membership(uint8_t proof[][96], const uint8_t c_prime[32], uint64_t role_code,
                                     const uint8_t blind_prime[32], const uint8_t pid[32],
                                     const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t h[32], y_points[ALLOWED_ROLE_COUNT][32], a_points[ALLOWED_ROLE_COUNT][32];
    uint8_t c_vals[ALLOWED_ROLE_COUNT][32], s_vals[ALLOWED_ROLE_COUNT][32];
    uint8_t w_true[32], master_c[32], sum_sim[32], tmp_scalar[32], tmp_point[32], role_scalar[32];
    size_t i, true_index = (size_t)-1;
    transcript_t tr;
    attr_h(h);
    for (i = 0; i < ALLOWED_ROLE_COUNT; i++) {
        if (ALLOWED_ROLES[i] == role_code) true_index = i;
        scalar_from_u64(ALLOWED_ROLES[i], role_scalar);
        crypto_scalarmult_ristretto255_base(tmp_point, role_scalar);
        crypto_core_ristretto255_sub(y_points[i], c_prime, tmp_point);
        scalar_zero(c_vals[i]);
        scalar_zero(s_vals[i]);
    }
    if (true_index == (size_t)-1) return -1;
    for (i = 0; i < ALLOWED_ROLE_COUNT; i++) {
        if (i == true_index) {
            crypto_core_ristretto255_scalar_random(w_true);
            if (crypto_scalarmult_ristretto255(a_points[i], w_true, h) != 0) return -1;
        } else {
            crypto_core_ristretto255_scalar_random(c_vals[i]);
            crypto_core_ristretto255_scalar_random(s_vals[i]);
            if (crypto_scalarmult_ristretto255(tmp_point, s_vals[i], h) != 0) return -1;
            if (crypto_scalarmult_ristretto255(tmp_scalar, c_vals[i], y_points[i]) != 0) return -1;
            crypto_core_ristretto255_sub(a_points[i], tmp_point, tmp_scalar);
        }
    }
    tr_init(&tr, T_ROLE_SET);
    tr_append(&tr, "pid", pid, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);
    tr_append(&tr, "c_prime", c_prime, 32);
    for (i = 0; i < ALLOWED_ROLE_COUNT; i++) {
        char label[16]; uint8_t le[8];
        snprintf(label, sizeof label, "r_%zu", i);
        le64_store(le, ALLOWED_ROLES[i]);
        tr_append(&tr, label, le, 8);
    }
    for (i = 0; i < ALLOWED_ROLE_COUNT; i++) {
        char label[16];
        snprintf(label, sizeof label, "A_%zu", i);
        tr_append(&tr, label, a_points[i], 32);
    }
    tr_challenge_scalar(master_c, &tr);
    scalar_zero(sum_sim);
    for (i = 0; i < ALLOWED_ROLE_COUNT; i++) if (i != true_index) crypto_core_ristretto255_scalar_add(sum_sim, sum_sim, c_vals[i]);
    crypto_core_ristretto255_scalar_sub(c_vals[true_index], master_c, sum_sim);
    crypto_core_ristretto255_scalar_mul(tmp_scalar, c_vals[true_index], blind_prime);
    crypto_core_ristretto255_scalar_add(s_vals[true_index], w_true, tmp_scalar);
    for (i = 0; i < ALLOWED_ROLE_COUNT; i++) {
        memcpy(proof[i] + 0, a_points[i], 32);
        memcpy(proof[i] + 32, c_vals[i], 32);
        memcpy(proof[i] + 64, s_vals[i], 32);
    }
    return 0;
}

static void encode_role(uint64_t role_code, uint8_t out[32]) {
    uint8_t wide[64] = {0};
    le64_store(wide, role_code);
    crypto_core_ristretto255_scalar_reduce(out, wide);
}

static int make_role_commitment(uint8_t out[32], const uint8_t role_scalar[32], const uint8_t blind[32]) {
    uint8_t g_r[32], h[32], h_b[32];
    attr_h(h);
    crypto_scalarmult_ristretto255_base(g_r, role_scalar);
    if (crypto_scalarmult_ristretto255(h_b, blind, h) != 0) return -1;
    crypto_core_ristretto255_add(out, g_r, h_b);
    return 0;
}

static int load_or_create_device_root(uint8_t root[32]) {
    if (file_exists(DEVICE_ROOT_FILE)) return read_file_32(DEVICE_ROOT_FILE, root);
    randombytes_buf(root, 32);
    return write_file_32(DEVICE_ROOT_FILE, root);
}

static void derive_device_id(const uint8_t root[32], uint8_t out[32]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const unsigned char *)"device-id", 9);
    crypto_generichash_update(&st, root, 32);
    crypto_generichash_final(&st, out, 32);
}

static void derive_device_scalar(const uint8_t root[32], uint8_t out[32]) {
    uint8_t wide[64];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 64);
    crypto_generichash_update(&st, (const unsigned char *)"device-auth-v1", 14);
    crypto_generichash_update(&st, root, 32);
    crypto_generichash_final(&st, wide, 64);
    crypto_core_ristretto255_scalar_reduce(out, wide);
}

static int load_device_creds(uint8_t device_id[32], uint8_t x[32]) {
    uint8_t root[32];
    if (load_or_create_device_root(root) != 0) return -1;
    derive_device_id(root, device_id);
    derive_device_scalar(root, x);
    sodium_memzero(root, sizeof root);
    return 0;
}

static int save_role_credential(const role_cred_t *cred) {
    uint8_t buf[72];
    le64_store(buf, cred->role_code);
    memcpy(buf + 8, cred->blind, 32);
    memcpy(buf + 40, cred->commitment, 32);
    return write_exact_file(ROLE_CRED_FILE, buf, sizeof buf, 0600);
}

static int load_or_create_role_credential(role_cred_t *cred) {
    uint8_t buf[72], expected[32];
    if (file_exists(ROLE_CRED_FILE)) {
        if (read_exact_file(ROLE_CRED_FILE, buf, sizeof buf) != 0) return -1;
        cred->role_code = le64_load(buf);
        encode_role(cred->role_code, cred->role_scalar);
        memcpy(cred->blind, buf + 8, 32);
        memcpy(cred->commitment, buf + 40, 32);
        if (make_role_commitment(expected, cred->role_scalar, cred->blind) != 0) return -1;
        return sodium_memcmp(expected, cred->commitment, 32) == 0 ? 0 : -1;
    }
    cred->role_code = 1;
    encode_role(cred->role_code, cred->role_scalar);
    crypto_core_ristretto255_scalar_random(cred->blind);
    if (make_role_commitment(cred->commitment, cred->role_scalar, cred->blind) != 0) return -1;
    return save_role_credential(cred);
}

static void prove_role_commitment_opening(uint8_t A[32], uint8_t s_attr[32], uint8_t s_blind[32],
                                          const role_cred_t *cred, const uint8_t device_id[32],
                                          const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t u[32], v[32], c[32], cu[32], cv[32], h[32], gv[32], hv[32];
    transcript_t tr;
    crypto_core_ristretto255_scalar_random(u);
    crypto_core_ristretto255_scalar_random(v);
    attr_h(h);
    crypto_scalarmult_ristretto255_base(gv, u);
    if (crypto_scalarmult_ristretto255(hv, v, h) != 0) abort();
    crypto_core_ristretto255_add(A, gv, hv);
    tr_init(&tr, T_ATTR_ROLE);
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "commitment", cred->commitment, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);
    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cu, c, cred->role_scalar);
    crypto_core_ristretto255_scalar_add(s_attr, u, cu);
    crypto_core_ristretto255_scalar_mul(cv, c, cred->blind);
    crypto_core_ristretto255_scalar_add(s_blind, v, cv);
}

static void schnorr_prove_setup(uint8_t A[32], uint8_t s[32], const uint8_t x[32],
                                const uint8_t device_id[32], const uint8_t device_pub[32],
                                const uint8_t server_pub[32], const uint8_t client_nonce[32],
                                const uint8_t server_nonce[32], const uint8_t setup_challenge[SETUP_CHALLENGE_LEN]) {
    uint8_t r[32], c[32], cx[32];
    transcript_t tr;
    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);
    tr_init(&tr, T_SETUP);
    tr_append(&tr, "role", (const uint8_t *)"client", 6);
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "device_pub", device_pub, 32);
    tr_append(&tr, "server_pub", server_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "client_nonce", client_nonce, 32);
    tr_append(&tr, "server_nonce", server_nonce, 32);
    tr_append(&tr, "setup_challenge", setup_challenge, SETUP_CHALLENGE_LEN);
    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(s, r, cx);
}

static int schnorr_verify_setup_server(const uint8_t server_pub[32], const uint8_t device_id[32],
                                       const uint8_t device_pub[32], const uint8_t client_nonce[32],
                                       const uint8_t server_nonce[32], const uint8_t setup_challenge[SETUP_CHALLENGE_LEN],
                                       const uint8_t A[32], const uint8_t s[32]) {
    uint8_t c[32], left[32], cx[32], right[32];
    transcript_t tr;
    tr_init(&tr, T_SETUP_SERVER);
    tr_append(&tr, "role", (const uint8_t *)"server", 6);
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "device_pub", device_pub, 32);
    tr_append(&tr, "server_pub", server_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "client_nonce", client_nonce, 32);
    tr_append(&tr, "server_nonce", server_nonce, 32);
    tr_append(&tr, "setup_challenge", setup_challenge, SETUP_CHALLENGE_LEN);
    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cx, c, server_pub) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cx);
    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

static void schnorr_prove_auth(uint8_t A[32], uint8_t s[32], const uint8_t x[32],
                               const uint8_t pid[32], const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t pubkey[32], r[32], c[32], cx[32];
    transcript_t tr;
    crypto_scalarmult_ristretto255_base(pubkey, x);
    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);
    tr_init(&tr, T_CLIENT_V2);
    tr_append(&tr, "pid", pid, 32);
    tr_append(&tr, "pubkey", pubkey, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);
    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(s, r, cx);
}

static int schnorr_verify_server(const uint8_t server_pub[32], const uint8_t A[32], const uint8_t s[32],
                                 const uint8_t nonce_s[32], const uint8_t eph_s[32]) {
    uint8_t c[32], left[32], cx[32], right[32];
    transcript_t tr;
    tr_init(&tr, T_SERVER);
    tr_append(&tr, "pubkey", server_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_s", nonce_s, 32);
    tr_append(&tr, "eph_s", eph_s, 32);
    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cx, c, server_pub) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cx);
    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

static void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, msg, (unsigned long long)msg_len);
    crypto_auth_hmacsha256_final(&st, out);
}

static void hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len) {
    hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
}

static void hkdf_expand(uint8_t *out, size_t out_len, const uint8_t prk[32], const uint8_t *info, size_t info_len) {
    uint8_t t[32];
    uint8_t buf[32 + 256 + 1];
    size_t pos = 0, tlen = 0;
    uint8_t ctr = 1;
    while (pos < out_len) {
        size_t off = 0;
        if (tlen) { memcpy(buf + off, t, tlen); off += tlen; }
        memcpy(buf + off, info, info_len); off += info_len;
        buf[off++] = ctr++;
        hmac_sha256(t, prk, 32, buf, off);
        tlen = 32;
        size_t take = (out_len - pos < 32) ? (out_len - pos) : 32;
        memcpy(out + pos, t, take);
        pos += take;
    }
    sodium_memzero(t, sizeof t);
}

static int derive_session_key(uint8_t key[32], const uint8_t eph_secret[32], const uint8_t eph_peer[32],
                              const uint8_t nonce_c[32], const uint8_t nonce_s[32], const uint8_t pid[32],
                              const uint8_t eph_c[32], const uint8_t eph_s[32]) {
    uint8_t shared[32], salt[64], info[14 + 32 + 32 + 32], prk[32];
    size_t off = 0;
    if (crypto_scalarmult_ristretto255(shared, eph_secret, eph_peer) != 0) return -1;
    memcpy(salt, nonce_c, 32);
    memcpy(salt + 32, nonce_s, 32);
    memcpy(info + off, "session key v2", 14); off += 14;
    memcpy(info + off, pid, 32); off += 32;
    memcpy(info + off, eph_c, 32); off += 32;
    memcpy(info + off, eph_s, 32); off += 32;
    hkdf_extract(prk, salt, sizeof salt, shared, sizeof shared);
    hkdf_expand(key, 32, prk, info, off);
    sodium_memzero(shared, sizeof shared);
    sodium_memzero(prk, sizeof prk);
    return 0;
}

static void kc_transcript_hash(uint8_t th[32], const uint8_t pid[32], const uint8_t a_c[32],
                               const uint8_t s_c[32], const uint8_t nonce_c[32], const uint8_t eph_c[32],
                               const uint8_t server_pub[32], const uint8_t a_s[32], const uint8_t s_s[32],
                               const uint8_t nonce_s[32], const uint8_t eph_s[32]) {
    transcript_t tr;
    tr_init(&tr, T_KC_V2);
    tr_append(&tr, "pid", pid, 32);
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

static void derive_kc_keys(uint8_t k_s2c[32], uint8_t k_c2s[32], const uint8_t session_key[32], const uint8_t th[32]) {
    uint8_t prk[32];
    hkdf_extract(prk, th, 32, session_key, 32);
    hkdf_expand(k_s2c, 32, prk, (const uint8_t *)"kc s2c", 6);
    hkdf_expand(k_c2s, 32, prk, (const uint8_t *)"kc c2s", 6);
    sodium_memzero(prk, sizeof prk);
}

static void hmac_tag(uint8_t out[32], const uint8_t key[32], const char *label, const uint8_t th[32]) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, 32);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)label, strlen(label));
    crypto_auth_hmacsha256_update(&st, th, 32);
    crypto_auth_hmacsha256_final(&st, out);
}

static int tcp_connect(const char *hostport) {
    char host[256], port[32];
    const char *colon = strrchr(hostport, ':');
    struct addrinfo hints, *res = NULL, *rp;
    int fd = -1;

    if (!colon) return -1;
    if ((size_t)(colon - hostport) >= sizeof host) return -1;
    if (strlen(colon + 1) >= sizeof port) return -1;

    memset(host, 0, sizeof host);
    memset(port, 0, sizeof port);
    memcpy(host, hostport, (size_t)(colon - hostport));
    strcpy(port, colon + 1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd >= 0) {
        struct timeval tv = { IO_TIMEOUT_SEC, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }

    return fd;
}

static int load_server_pub(uint8_t out[32]) { return read_file_32(SERVER_PUB_FILE, out); }

static int do_setup(const char *server_addr, const char *pairing_token, int allow_tofu) {
    uint8_t device_id[32], x[32], device_pub[32], client_nonce[32], server_nonce[32], setup_chal[SETUP_CHALLENGE_LEN];
    uint8_t server_pub[32], A_s[32], s_s[32], A[32], s[32], pinned[32];
    role_cred_t cred;
    size_t sent = 0, recv_bytes = 0;
    int fd = -1;
    uint8_t msg_type;
    int had_root = file_exists(DEVICE_ROOT_FILE);
    int had_pinned_before = file_exists(SERVER_PUB_FILE);
    double start_ms = now_ms();

    if (load_device_creds(device_id, x) != 0) return -1;

    if (had_root) {
        printf("Client[SETUP]: Using existing device root for setup (idempotent).\n");
    } else {
        printf("Client[SETUP]: Created new device root for setup.\n");
    }

    crypto_scalarmult_ristretto255_base(device_pub, x);
    if (load_or_create_role_credential(&cred) != 0) return -1;
    randombytes_buf(client_nonce, 32);

    fd = tcp_connect(server_addr);
    if (fd < 0) return -1;

    printf("Client[SETUP]: Connected to %s\n", server_addr);

    msg_type = MSG_SETUP;
    if (send_all(fd, &msg_type, 1, &sent) != 0) goto fail;

    {
        uint8_t tlen = pairing_token ? (uint8_t)strlen(pairing_token) : 0;
        if (send_all(fd, &tlen, 1, &sent) != 0) goto fail;
        if (tlen && send_all(fd, (const uint8_t *)pairing_token, tlen, &sent) != 0) goto fail;
    }

    if (send_all(fd, device_id, 32, &sent) != 0) goto fail;
    if (send_all(fd, device_pub, 32, &sent) != 0) goto fail;
    if (send_all(fd, client_nonce, 32, &sent) != 0) goto fail;
    if (send_all(fd, cred.commitment, 32, &sent) != 0) goto fail;

    if (recv_all(fd, server_nonce, 32, &recv_bytes) != 0) goto fail;
    if (recv_all(fd, setup_chal, SETUP_CHALLENGE_LEN, &recv_bytes) != 0) goto fail;
    if (recv_all(fd, server_pub, 32, &recv_bytes) != 0) goto fail;
    if (recv_all(fd, A_s, 32, &recv_bytes) != 0) goto fail;
    if (recv_all(fd, s_s, 32, &recv_bytes) != 0) goto fail;

    if (check_point(server_pub, "server_pub") != 0 || check_point(A_s, "a_s") != 0) goto fail;

    if (had_pinned_before) {
        if (load_server_pub(pinned) != 0) goto fail;
        if (sodium_memcmp(pinned, server_pub, 32) != 0) {
            fprintf(stderr, "Client[SETUP]: pinned server key mismatch\n");
            goto fail;
        }
    } else if (!allow_tofu) {
        fprintf(stderr, "Client[SETUP]: no pinned server key; use --allow-tofu-setup\n");
        goto fail;
    }

    if (schnorr_verify_setup_server(server_pub, device_id, device_pub, client_nonce, server_nonce, setup_chal, A_s, s_s) != 0) {
        fprintf(stderr, "Client[SETUP]: server setup proof invalid\n");
        goto fail;
    }

    schnorr_prove_setup(A, s, x, device_id, device_pub, server_pub, client_nonce, server_nonce, setup_chal);
    if (send_all(fd, A, 32, &sent) != 0) goto fail;
    if (send_all(fd, s, 32, &sent) != 0) goto fail;
    if (recv_all(fd, &msg_type, 1, &recv_bytes) != 0) goto fail;
    if (msg_type != 1) goto fail;

    if (!had_pinned_before && allow_tofu) {
        if (write_file_32(SERVER_PUB_FILE, server_pub) != 0) goto fail;
    }

    printf("Client[SETUP]: Enrollment OK\n");
    print_client_metrics(start_ms, sent, recv_bytes);

    {
        char hex_pub[65];
        bin2hex_lower(server_pub, 32, hex_pub, sizeof hex_pub);
        printf("Client[SETUP]: Server public key pinned: %s\n", hex_pub);
    }

    close(fd);
    sodium_memzero(x, sizeof x);
    return 0;

fail:
    perror("setup");
    if (fd >= 0) close(fd);
    sodium_memzero(x, sizeof x);
    return -1;
}

static int do_auth(const char *server_addr) {
    uint8_t device_id[32], x[32], pinned_server_pub[32], device_pub[32];
    uint8_t nonce_c[32], eph_secret[32], eph_c[32], pid[32], A_c[32], s_c[32];
    uint8_t c_prime[32], blind_prime[32], delta[32], rerand_A[32], rerand_s[32];
    uint8_t or_proof[ALLOWED_ROLE_COUNT][96];
    uint8_t session_key[32], th[32], k_s2c[32], k_c2s[32], expected_s[32], tag_c[32];
    uint8_t payload1[256 + 96 * ALLOWED_ROLE_COUNT], payload2[192], server_pub2[32], A_s[32], s_s[32], nonce_s[32], eph_s[32], tag_s[32];
    size_t sent = 0, recv_bytes = 0;
    int fd = -1;
    role_cred_t cred;
    double start_ms = now_ms();
    size_t off = 0, i;

    if (load_device_creds(device_id, x) != 0) return -1;
    if (load_server_pub(pinned_server_pub) != 0) {
        fprintf(stderr, "Client[AUTH]: no pinned server_pub.bin — run --setup first\n");
        return -1;
    }
    if (load_or_create_role_credential(&cred) != 0) return -1;
    crypto_scalarmult_ristretto255_base(device_pub, x);
    if (check_point(device_pub, "device_static_pub") != 0) return -1;

    fd = tcp_connect(server_addr);
    if (fd < 0) return -1;
    printf("Client[AUTH]: Connected to %s\n", server_addr);
    { uint8_t m = MSG_AUTH_V2; if (send_all(fd, &m, 1, &sent) != 0) goto fail; }

    randombytes_buf(nonce_c, 32);
    crypto_core_ristretto255_scalar_random(eph_secret);
    crypto_scalarmult_ristretto255_base(eph_c, eph_secret);
    compute_pid(pid, device_pub, nonce_c, eph_c, pinned_server_pub);
    schnorr_prove_auth(A_c, s_c, x, pid, nonce_c, eph_c);
    if (rerandomize_role_commitment(c_prime, blind_prime, delta, &cred) != 0) goto fail;
    if (prove_role_rerandomization(rerand_A, rerand_s, cred.commitment, c_prime, delta, pid, nonce_c, eph_c) != 0) goto fail;
    if (prove_role_set_membership(or_proof, c_prime, cred.role_code, blind_prime, pid, nonce_c, eph_c) != 0) goto fail;

    memcpy(payload1 + off, pid, 32); off += 32;
    memcpy(payload1 + off, A_c, 32); off += 32;
    memcpy(payload1 + off, s_c, 32); off += 32;
    memcpy(payload1 + off, nonce_c, 32); off += 32;
    memcpy(payload1 + off, eph_c, 32); off += 32;
    memcpy(payload1 + off, c_prime, 32); off += 32;
    memcpy(payload1 + off, rerand_A, 32); off += 32;
    memcpy(payload1 + off, rerand_s, 32); off += 32;
    for (i = 0; i < ALLOWED_ROLE_COUNT; i++) { memcpy(payload1 + off, or_proof[i], 96); off += 96; }

    if (send_all(fd, payload1, off, &sent) != 0) goto fail;
    if (recv_all(fd, payload2, sizeof(payload2), &recv_bytes) != 0) goto fail;

    memcpy(server_pub2, payload2, 32);
    memcpy(A_s,         payload2 + 32, 32);
    memcpy(s_s,         payload2 + 64, 32);
    memcpy(nonce_s,     payload2 + 96, 32);
    memcpy(eph_s,       payload2 + 128, 32);
    memcpy(tag_s,       payload2 + 160, 32);

    if (check_point(server_pub2, "server_pub2") != 0 || check_point(A_s, "A_s") != 0 || check_point(eph_s, "eph_s") != 0) goto fail;
    if (sodium_memcmp(server_pub2, pinned_server_pub, 32) != 0) { fprintf(stderr, "Client[AUTH]: server pubkey mismatch\n"); goto fail; }
    if (schnorr_verify_server(server_pub2, A_s, s_s, nonce_s, eph_s) != 0) { fprintf(stderr, "Client[AUTH]: Server Schnorr proof FAILED\n"); goto fail; }
    printf("Client[AUTH]: Server Schnorr proof OK\n");

    if (derive_session_key(session_key, eph_secret, eph_s, nonce_c, nonce_s, pid, eph_c, eph_s) != 0) goto fail;
    kc_transcript_hash(th, pid, A_c, s_c, nonce_c, eph_c, server_pub2, A_s, s_s, nonce_s, eph_s);
    derive_kc_keys(k_s2c, k_c2s, session_key, th);
    hmac_tag(expected_s, k_s2c, "server finished", th);
    if (sodium_memcmp(expected_s, tag_s, 32) != 0) { fprintf(stderr, "Client[AUTH]: server finished mismatch\n"); goto fail; }
    printf("Client[AUTH]: Key confirmation (server finished) OK\n");

    hmac_tag(tag_c, k_c2s, "client finished", th);
    if (send_all(fd, tag_c, 32, &sent) != 0) goto fail;
    printf("Client[AUTH]: Sent encrypted client finished tag\n");
    print_client_metrics(start_ms, sent, recv_bytes);
    close(fd);
    sodium_memzero(x, sizeof x);
    sodium_memzero(eph_secret, sizeof eph_secret);
    sodium_memzero(session_key, sizeof session_key);
    return 0;
fail:
    perror("auth");
    if (fd >= 0) close(fd);
    sodium_memzero(x, sizeof x);
    sodium_memzero(eph_secret, sizeof eph_secret);
    sodium_memzero(session_key, sizeof session_key);
    return -1;
}

static int print_identity(void) {
    uint8_t id[32], x[32], pub[32];
    char id_hex[65], pub_hex[65];
    if (load_device_creds(id, x) != 0) return -1;
    crypto_scalarmult_ristretto255_base(pub, x);
    bin2hex_lower(id, 32, id_hex, sizeof id_hex);
    bin2hex_lower(pub, 32, pub_hex, sizeof pub_hex);
    printf("%s %s\n", id_hex, pub_hex);
    sodium_memzero(x, sizeof x);
    return 0;
}

static int parse_hex32(const char *hex, uint8_t out[32]) {
    size_t n = 0;
    return (sodium_hex2bin(out, 32, hex, strlen(hex), NULL, &n, NULL) == 0 && n == 32) ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *server = NULL, *pairing_token = NULL, *pin_hex = NULL;
    int do_setup_mode = 0, allow_tofu = 0, print_id = 0;
    int i;

    if (sodium_init() < 0) return 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server = argv[++i];
        } else if (strcmp(argv[i], "--setup") == 0) {
            do_setup_mode = 1;
        } else if (strcmp(argv[i], "--pairing-token") == 0 && i + 1 < argc) {
            pairing_token = argv[++i];
        } else if (strcmp(argv[i], "--allow-tofu-setup") == 0) {
            allow_tofu = 1;
        } else if (strcmp(argv[i], "--pin-server-pub") == 0 && i + 1 < argc) {
            pin_hex = argv[++i];
        } else if (strcmp(argv[i], "--print-identity") == 0) {
            print_id = 1;
        } else {
            fprintf(stderr,
                    "Usage: %s [--print-identity] [--pin-server-pub HEX] "
                    "[--server host:port [--setup] [--pairing-token TOKEN] [--allow-tofu-setup]]\n",
                    argv[0]);
            return 1;
        }
    }

    if (print_id) return print_identity() == 0 ? 0 : 1;

    if (pin_hex) {
        uint8_t pub[32];
        if (parse_hex32(pin_hex, pub) != 0) return 1;
        return write_file_32(SERVER_PUB_FILE, pub) == 0 ? 0 : 1;
    }

    if (!server) {
        fprintf(stderr, "--server is required unless using --print-identity or --pin-server-pub\n");
        return 1;
    }

    return do_setup_mode
        ? (do_setup(server, pairing_token, allow_tofu) == 0 ? 0 : 1)
        : (do_auth(server) == 0 ? 0 : 1);
}