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

#define BASE_STATE_DIR   "/var/lib/iot-auth"
#define SERVER_STATE_DIR "/var/lib/iot-auth/server"
#define REGISTRY_BIN     "/var/lib/iot-auth/server/registry.bin"
#define REGISTRY_BAK     "/var/lib/iot-auth/server/registry.bak"
#define SERVER_SK_FILE   "/var/lib/iot-auth/server/server_sk.bin"

#define SETUP_CHALLENGE_LEN 16
#define MAX_ENCRYPTED_PAYLOAD 4096
#define IO_TIMEOUT_SEC 5

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif

#define T_SETUP        "setup_client_schnorr_v1"
#define T_SETUP_SERVER "setup_server_schnorr_v1"
#define T_CLIENT       "client_schnorr_v1"
#define T_SERVER       "server_schnorr_v1"
#define T_KC           "kc_v1"
#define T_ATTR_ROLE    "client_attr_role_v1"

typedef struct { uint64_t count; } nonce_ctr_t;
typedef struct { uint8_t buf[4096]; size_t len; } transcript_t;
typedef struct {
    uint8_t id[32];
    uint8_t pub[32];
    uint8_t role_commitment[32];
    uint64_t role_code;
} reg_entry_t;
typedef struct {
    int enabled;
    const char *token;
    time_t deadline;
} pairing_policy_t;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void bin2hex_lower(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    sodium_bin2hex(out, out_len, in, in_len);
}

static void peer_to_string(int fd, char *out, size_t out_len) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    char host[NI_MAXHOST], serv[NI_MAXSERV];

    if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0) {
        snprintf(out, out_len, "unknown");
        return;
    }
    if (getnameinfo((struct sockaddr *)&ss, slen, host, sizeof host, serv, sizeof serv,
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        snprintf(out, out_len, "unknown");
        return;
    }
    snprintf(out, out_len, "%s:%s", host, serv);
}

static void print_server_metrics(const char *peer, double start_ms, size_t sent, size_t recv_bytes) {
    double duration_ms = now_ms() - start_ms;
    printf("SERVER METRICS -> Some(%s) Duration: %.6fms, Sent: %zu bytes, Received: %zu bytes\n",
           peer, duration_ms, sent, recv_bytes);
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

static int ensure_state_dir(void) {
    struct stat st;
    if (stat(BASE_STATE_DIR, &st) != 0) {
        if (mkdir(BASE_STATE_DIR, 0700) != 0 && errno != EEXIST) return -1;
    }
    if (stat(SERVER_STATE_DIR, &st) != 0) {
        if (mkdir(SERVER_STATE_DIR, 0700) != 0 && errno != EEXIST) return -1;
    }
    chmod(BASE_STATE_DIR, 0700);
    chmod(SERVER_STATE_DIR, 0700);
    return 0;
}

static int file_exists(const char *path) { return access(path, F_OK) == 0; }

static int write_exact_file(const char *path, const uint8_t *buf, size_t len, mode_t mode) {
    FILE *f;
    if (ensure_state_dir() != 0) return -1;
    f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fflush(f);
    fsync(fileno(f));
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

static int require_private_file_mode(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;
    return ((st.st_mode & 077) == 0) ? 0 : -1;
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
    memcpy(tr->buf + tr->len, label, llen);
    tr->len += llen;
    tr->buf[tr->len++] = (uint8_t)vlen;
    tr->buf[tr->len++] = (uint8_t)(vlen >> 8);
    tr->buf[tr->len++] = (uint8_t)(vlen >> 16);
    tr->buf[tr->len++] = (uint8_t)(vlen >> 24);
    memcpy(tr->buf + tr->len, val, vlen);
    tr->len += vlen;
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

static int load_or_create_server_sk(uint8_t out[32]) {
    if (file_exists(SERVER_SK_FILE)) return read_file_32(SERVER_SK_FILE, out);
    crypto_core_ristretto255_scalar_random(out);
    return write_file_32(SERVER_SK_FILE, out);
}

static int save_registry(const reg_entry_t *arr, size_t n) {
    FILE *f;
    char tmp[256];
    uint8_t le[8];

    if (file_exists(REGISTRY_BIN)) rename(REGISTRY_BIN, REGISTRY_BAK);
    snprintf(tmp, sizeof tmp, "%s.tmp", REGISTRY_BIN);
    f = fopen(tmp, "wb");
    if (!f) return -1;

    for (size_t i = 0; i < n; i++) {
        le64_store(le, arr[i].role_code);
        if (fwrite(arr[i].id, 1, 32, f) != 32 ||
            fwrite(arr[i].pub, 1, 32, f) != 32 ||
            fwrite(arr[i].role_commitment, 1, 32, f) != 32 ||
            fwrite(le, 1, 8, f) != 8) {
            fclose(f);
            return -1;
        }
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);
    chmod(tmp, 0600);
    return rename(tmp, REGISTRY_BIN);
}

static int load_registry(reg_entry_t **out, size_t *out_n) {
    FILE *f;
    long sz;
    size_t n;

    *out = NULL;
    *out_n = 0;
    if (!file_exists(REGISTRY_BIN)) return 0;

    f = fopen(REGISTRY_BIN, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    sz = ftell(f);
    if (sz < 0 || (sz % 104) != 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    n = (size_t)sz / 104;
    if (n == 0) { fclose(f); return 0; }

    *out = calloc(n, sizeof(reg_entry_t));
    if (!*out) { fclose(f); return -1; }

    for (size_t i = 0; i < n; i++) {
        uint8_t le[8];
        if (fread((*out)[i].id, 1, 32, f) != 32 ||
            fread((*out)[i].pub, 1, 32, f) != 32 ||
            fread((*out)[i].role_commitment, 1, 32, f) != 32 ||
            fread(le, 1, 8, f) != 8) {
            fclose(f);
            free(*out);
            *out = NULL;
            return -1;
        }
        (*out)[i].role_code = le64_load(le);
    }

    fclose(f);
    *out_n = n;
    return 0;
}

static int reg_lookup_record(const reg_entry_t *arr, size_t n, const uint8_t id[32], reg_entry_t *out) {
    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            if (out) *out = arr[i];
            return 0;
        }
    }
    return -1;
}

static int reg_upsert(reg_entry_t **arrp, size_t *np, const uint8_t id[32], const uint8_t pub[32],
                      const uint8_t role_commitment[32], uint64_t role_code) {
    reg_entry_t *arr = *arrp;
    size_t n = *np;

    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            if (sodium_memcmp(arr[i].pub, pub, 32) != 0) return -1;
            if (sodium_memcmp(arr[i].role_commitment, role_commitment, 32) != 0) return -1;
            if (arr[i].role_code != role_code) return -1;
            return 0;
        }
    }

    arr = realloc(arr, (n + 1) * sizeof(reg_entry_t));
    if (!arr) return -1;

    memcpy(arr[n].id, id, 32);
    memcpy(arr[n].pub, pub, 32);
    memcpy(arr[n].role_commitment, role_commitment, 32);
    arr[n].role_code = role_code;
    n++;

    *arrp = arr;
    *np = n;
    return save_registry(arr, n) == 0 ? 1 : -1;
}

static int allows_setup(const pairing_policy_t *pol, const char *provided, size_t provided_len) {
    if (!pol->enabled) return -1;
    if (pol->deadline && time(NULL) > pol->deadline) return -1;
    if (pol->token) {
        size_t exp = strlen(pol->token);
        if (provided_len != exp) return -1;
        if (sodium_memcmp(provided, pol->token, exp) != 0) return -1;
    }
    return 0;
}

static int schnorr_verify_setup(const uint8_t device_id[32], const uint8_t device_pub[32], const uint8_t server_pub[32],
                                const uint8_t client_nonce[32], const uint8_t server_nonce[32],
                                const uint8_t setup_challenge[SETUP_CHALLENGE_LEN], const uint8_t A[32], const uint8_t s[32]) {
    uint8_t c[32], left[32], cx[32], right[32];
    transcript_t tr;

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

    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cx, c, device_pub) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cx);
    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

static void schnorr_prove_setup_server(uint8_t A[32], uint8_t s[32], const uint8_t server_sk[32], const uint8_t server_pub[32],
                                       const uint8_t device_id[32], const uint8_t device_pub[32],
                                       const uint8_t client_nonce[32], const uint8_t server_nonce[32],
                                       const uint8_t setup_challenge[SETUP_CHALLENGE_LEN]) {
    uint8_t r[32], c[32], cx[32];
    transcript_t tr;

    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);

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

    crypto_core_ristretto255_scalar_mul(cx, c, server_sk);
    crypto_core_ristretto255_scalar_add(s, r, cx);
}

static int schnorr_verify_auth(const uint8_t device_id[32], const uint8_t expected_pub[32], const uint8_t A[32], const uint8_t s[32],
                               const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t c[32], left[32], cx[32], right[32];
    transcript_t tr;

    tr_init(&tr, T_CLIENT);
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", expected_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);
    tr_challenge_scalar(c, &tr);

    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cx, c, expected_pub) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cx);
    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

static void schnorr_prove_server(uint8_t A[32], uint8_t s[32], const uint8_t server_sk[32], const uint8_t server_pub[32],
                                 const uint8_t nonce_s[32], const uint8_t eph_s[32]) {
    uint8_t r[32], c[32], cx[32];
    transcript_t tr;

    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);

    tr_init(&tr, T_SERVER);
    tr_append(&tr, "pubkey", server_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_s", nonce_s, 32);
    tr_append(&tr, "eph_s", eph_s, 32);
    tr_challenge_scalar(c, &tr);

    crypto_core_ristretto255_scalar_mul(cx, c, server_sk);
    crypto_core_ristretto255_scalar_add(s, r, cx);
}

static int verify_role_commitment_opening(const uint8_t commitment[32], const uint8_t A[32], const uint8_t s_attr[32], const uint8_t s_blind[32],
                                          const uint8_t device_id[32], const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t c[32], h[32], left1[32], left2[32], left[32], cc[32], right[32];
    transcript_t tr;

    attr_h(h);
    tr_init(&tr, T_ATTR_ROLE);
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "commitment", commitment, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_c", nonce_c, 32);
    tr_append(&tr, "eph_c", eph_c, 32);
    tr_challenge_scalar(c, &tr);

    crypto_scalarmult_ristretto255_base(left1, s_attr);
    if (crypto_scalarmult_ristretto255(left2, s_blind, h) != 0) return -1;
    crypto_core_ristretto255_add(left, left1, left2);

    if (crypto_scalarmult_ristretto255(cc, c, commitment) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cc);
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
    uint8_t t[32], buf[32 + 256 + 1];
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
                              const uint8_t nonce_c[32], const uint8_t nonce_s[32], const uint8_t device_id[32],
                              const uint8_t eph_c[32], const uint8_t eph_s[32], const uint8_t x25519_shared[32]) {
    uint8_t shared[32], salt[64], info[11 + 32 + 32 + 32 + 32], prk[32];
    size_t off = 0;

    if (crypto_scalarmult_ristretto255(shared, eph_secret, eph_peer) != 0) return -1;

    memcpy(salt, nonce_c, 32);
    memcpy(salt + 32, nonce_s, 32);
    memcpy(info + off, "session key", 11); off += 11;
    memcpy(info + off, device_id, 32); off += 32;
    memcpy(info + off, eph_c, 32); off += 32;
    memcpy(info + off, eph_s, 32); off += 32;
    memcpy(info + off, x25519_shared, 32); off += 32;

    hkdf_extract(prk, salt, sizeof salt, shared, sizeof shared);
    hkdf_expand(key, 32, prk, info, off);

    sodium_memzero(shared, sizeof shared);
    sodium_memzero(prk, sizeof prk);
    return 0;
}

static void kc_transcript_hash(uint8_t th[32], const uint8_t device_id[32], const uint8_t a_c[32], const uint8_t s_c[32],
                               const uint8_t nonce_c[32], const uint8_t eph_c[32], const uint8_t server_pub[32],
                               const uint8_t a_s[32], const uint8_t s_s[32], const uint8_t nonce_s[32], const uint8_t eph_s[32]) {
    transcript_t tr;

    tr_init(&tr, T_KC);
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

static int bind_listener(const char *bind_addr) {
    char host[256], port[32];
    const char *colon = strrchr(bind_addr, ':');
    struct addrinfo hints, *res = NULL, *rp;
    int fd = -1, opt = 1;

    if (!colon) return -1;
    memset(host, 0, sizeof host);
    memset(port, 0, sizeof port);
    memcpy(host, bind_addr, (size_t)(colon - bind_addr));
    strcpy(port, colon + 1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, 32) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int handle_client(int cfd, const uint8_t server_sk[32], const uint8_t server_pub[32],
                         pairing_policy_t policy, reg_entry_t **reg, size_t *reg_n) {
    uint8_t msg;
    size_t sent = 0, recv_bytes = 0;
    char peer[NI_MAXHOST + NI_MAXSERV + 2];
    double start_ms = now_ms();

    peer_to_string(cfd, peer, sizeof peer);

    if (recv_all(cfd, &msg, 1, &recv_bytes) != 0) return -1;

    if (msg == MSG_SETUP) {
        uint8_t tlen, device_id[32], device_pub[32], client_nonce[32], role_commitment[32];
        uint8_t server_nonce[32], setup_chal[SETUP_CHALLENGE_LEN], A_s[32], s_s[32], A[32], s[32], ack = 1;
        char token[129] = {0};
        int upsert;
        char did_hex[65];

        if (recv_all(cfd, &tlen, 1, &recv_bytes) != 0) return -1;
        if (tlen > 128) return -1;
        if (tlen && recv_all(cfd, (uint8_t *)token, tlen, &recv_bytes) != 0) return -1;

        if (allows_setup(&policy, token, tlen) != 0) {
            fprintf(stderr, "Server[SETUP/RPK]: pairing denied\n");
            return -1;
        }

        if (recv_all(cfd, device_id, 32, &recv_bytes) != 0) return -1;
        if (recv_all(cfd, device_pub, 32, &recv_bytes) != 0) return -1;
        if (recv_all(cfd, client_nonce, 32, &recv_bytes) != 0) return -1;
        if (recv_all(cfd, role_commitment, 32, &recv_bytes) != 0) return -1;

        if (check_point(device_pub, "device_pub") != 0 ||
            check_point(role_commitment, "role_commitment") != 0) {
            return -1;
        }

        randombytes_buf(server_nonce, 32);
        randombytes_buf(setup_chal, SETUP_CHALLENGE_LEN);

        schnorr_prove_setup_server(A_s, s_s, server_sk, server_pub,
                                   device_id, device_pub,
                                   client_nonce, server_nonce, setup_chal);

        if (send_all(cfd, server_nonce, 32, &sent) != 0) return -1;
        if (send_all(cfd, setup_chal, SETUP_CHALLENGE_LEN, &sent) != 0) return -1;
        if (send_all(cfd, server_pub, 32, &sent) != 0) return -1;
        if (send_all(cfd, A_s, 32, &sent) != 0) return -1;
        if (send_all(cfd, s_s, 32, &sent) != 0) return -1;

        if (recv_all(cfd, A, 32, &recv_bytes) != 0) return -1;
        if (recv_all(cfd, s, 32, &recv_bytes) != 0) return -1;

        if (check_point(A, "setup_A") != 0) return -1;

        if (schnorr_verify_setup(device_id, device_pub, server_pub,
                                 client_nonce, server_nonce, setup_chal,
                                 A, s) != 0) {
            fprintf(stderr, "Server[SETUP/RPK]: client setup proof invalid\n");
            return -1;
        }

        upsert = reg_upsert(reg, reg_n, device_id, device_pub, role_commitment, 1);
        if (upsert < 0) return -1;

        if (send_all(cfd, &ack, 1, &sent) != 0) return -1;

        bin2hex_lower(device_id, 32, did_hex, sizeof did_hex);
        printf("Server[SETUP/RPK]: validated existing device_id=%s via raw-public-key onboarding\n", did_hex);
        print_server_metrics(peer, start_ms, sent, recv_bytes);
        return 0;
    }

    if (msg == MSG_AUTH_V2) {
        uint8_t client_pk[32], srv_pk[32], srv_sk_x[32], x25519_shared[32], hash[64], rx_key[32], tx_key[32];
        nonce_ctr_t nonce_rx = {0}, nonce_tx = {0};
        uint32_t rx_len;
        uint8_t *rx_ct = NULL;
        uint8_t pt1[288], nonce_buf[12];
        unsigned long long pt1_len;
        uint8_t device_id[32], A_c[32], s_c[32], nonce_c[32], eph_c[32], role_commitment[32], attr_A[32], attr_s_attr[32], attr_s_blind[32];
        reg_entry_t record;
        uint8_t nonce_s[32], eph_s_secret[32], eph_s[32], A_s[32], s_s[32], session_key[32], th[32], k_s2c[32], k_c2s[32], tag_s[32], expected_tag_c[32], payload2[192], pt3[32];
        unsigned long long pt3_len, ct2_len;
        uint8_t ct2[192 + crypto_aead_chacha20poly1305_IETF_ABYTES];
        char did_hex[65];

        if (recv_all(cfd, client_pk, 32, &recv_bytes) != 0) return -1;

        crypto_kx_keypair(srv_pk, srv_sk_x);
        if (send_all(cfd, srv_pk, 32, &sent) != 0) return -1;

        if (crypto_scalarmult(x25519_shared, srv_sk_x, client_pk) != 0) return -1;

        {
            crypto_generichash_state st;
            crypto_generichash_init(&st, NULL, 0, 64);
            crypto_generichash_update(&st, x25519_shared, 32);
            crypto_generichash_update(&st, client_pk, 32);
            crypto_generichash_update(&st, srv_pk, 32);
            crypto_generichash_final(&st, hash, 64);
            memcpy(tx_key, hash, 32);
            memcpy(rx_key, hash + 32, 32);
        }

        rx_ct = recv_encrypted_blob(cfd, &rx_len, &recv_bytes);
        if (!rx_ct) return -1;

        nonce_next(&nonce_rx, nonce_buf);
        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt1, &pt1_len, NULL, rx_ct, rx_len, NULL, 0, nonce_buf, rx_key) != 0) {
            free(rx_ct);
            return -1;
        }
        free(rx_ct);
        rx_ct = NULL;

        if (pt1_len != 288) return -1;

        memcpy(device_id,       pt1 + 0,   32);
        memcpy(A_c,             pt1 + 32,  32);
        memcpy(s_c,             pt1 + 64,  32);
        memcpy(nonce_c,         pt1 + 96,  32);
        memcpy(eph_c,           pt1 + 128, 32);
        memcpy(role_commitment, pt1 + 160, 32);
        memcpy(attr_A,          pt1 + 192, 32);
        memcpy(attr_s_attr,     pt1 + 224, 32);
        memcpy(attr_s_blind,    pt1 + 256, 32);

        if (check_point(A_c, "A_c") != 0 ||
            check_point(eph_c, "eph_c") != 0 ||
            check_point(role_commitment, "role_commitment") != 0 ||
            check_point(attr_A, "attr_A") != 0) {
            return -1;
        }

        if (reg_lookup_record(*reg, *reg_n, device_id, &record) != 0) {
            fprintf(stderr, "Server[AUTH]: unknown device\n");
            return -1;
        }

        if (sodium_memcmp(record.role_commitment, role_commitment, 32) != 0 || record.role_code != 1) return -1;
        if (schnorr_verify_auth(device_id, record.pub, A_c, s_c, nonce_c, eph_c) != 0) return -1;
        if (verify_role_commitment_opening(role_commitment, attr_A, attr_s_attr, attr_s_blind, device_id, nonce_c, eph_c) != 0) return -1;

        randombytes_buf(nonce_s, 32);
        crypto_core_ristretto255_scalar_random(eph_s_secret);
        crypto_scalarmult_ristretto255_base(eph_s, eph_s_secret);
        schnorr_prove_server(A_s, s_s, server_sk, server_pub, nonce_s, eph_s);

        if (derive_session_key(session_key, eph_s_secret, eph_c, nonce_c, nonce_s, device_id, eph_c, eph_s, x25519_shared) != 0) return -1;

        kc_transcript_hash(th, device_id, A_c, s_c, nonce_c, eph_c, server_pub, A_s, s_s, nonce_s, eph_s);
        derive_kc_keys(k_s2c, k_c2s, session_key, th);
        hmac_tag(tag_s, k_s2c, "server finished", th);

        memcpy(payload2 + 0,   server_pub, 32);
        memcpy(payload2 + 32,  A_s,        32);
        memcpy(payload2 + 64,  s_s,        32);
        memcpy(payload2 + 96,  nonce_s,    32);
        memcpy(payload2 + 128, eph_s,      32);
        memcpy(payload2 + 160, tag_s,      32);

        nonce_next(&nonce_tx, nonce_buf);
        crypto_aead_chacha20poly1305_ietf_encrypt(ct2, &ct2_len, payload2, sizeof payload2, NULL, 0, NULL, nonce_buf, tx_key);

        if (send_u32_le(cfd, (uint32_t)ct2_len, &sent) != 0) return -1;
        if (send_all(cfd, ct2, (size_t)ct2_len, &sent) != 0) return -1;

        rx_ct = recv_encrypted_blob(cfd, &rx_len, &recv_bytes);
        if (!rx_ct) return -1;

        nonce_next(&nonce_rx, nonce_buf);
        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt3, &pt3_len, NULL, rx_ct, rx_len, NULL, 0, nonce_buf, rx_key) != 0) {
            free(rx_ct);
            return -1;
        }
        free(rx_ct);

        if (pt3_len != 32) return -1;

        hmac_tag(expected_tag_c, k_c2s, "client finished", th);
        if (sodium_memcmp(expected_tag_c, pt3, 32) != 0) return -1;

        bin2hex_lower(device_id, 32, did_hex, sizeof did_hex);
        printf("Server[AUTH]: device_id=%s KC=OK\n", did_hex);
        printf("Server[ONLINE]: one-shot session completed for %s\n", did_hex);
        print_server_metrics(peer, start_ms, sent, recv_bytes);
        return 0;
    }

    return -1;
}

int main(int argc, char **argv) {
    const char *bind_addr = "0.0.0.0:4000";
    const char *pairing_token = NULL;
    int pairing = 0, print_pubkey = 0;
    uint64_t pairing_seconds = 0;
    uint8_t server_sk[32], server_pub[32];
    reg_entry_t *reg = NULL;
    size_t reg_n = 0;
    int lfd;
    pairing_policy_t policy;

    if (sodium_init() < 0) return 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) bind_addr = argv[++i];
        else if (strcmp(argv[i], "--pairing") == 0) pairing = 1;
        else if (strcmp(argv[i], "--pairing-token") == 0 && i + 1 < argc) pairing_token = argv[++i];
        else if (strcmp(argv[i], "--pairing-seconds") == 0 && i + 1 < argc) pairing_seconds = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--print-pubkey") == 0) print_pubkey = 1;
        else {
            fprintf(stderr, "Usage: %s [--bind 0.0.0.0:4000] [--pairing] [--pairing-token TOKEN] [--pairing-seconds N] [--print-pubkey]\n", argv[0]);
            return 1;
        }
    }

    if (load_or_create_server_sk(server_sk) != 0) return 1;
    if (require_private_file_mode(SERVER_SK_FILE) != 0) {
        fprintf(stderr, "Insecure server_sk.bin permissions\n");
        return 1;
    }

    crypto_scalarmult_ristretto255_base(server_pub, server_sk);

    if (print_pubkey) {
        char hex[65];
        sodium_bin2hex(hex, sizeof hex, server_pub, 32);
        printf("%s\n", hex);
        return 0;
    }

    if (load_registry(&reg, &reg_n) != 0) return 1;

    policy.enabled = pairing;
    policy.token = pairing_token;
    policy.deadline = pairing_seconds ? time(NULL) + (time_t)pairing_seconds : 0;

    lfd = bind_listener(bind_addr);
    if (lfd < 0) return 1;

    {
        char hex[65];
        char deadline_buf[64];

        if (policy.deadline) snprintf(deadline_buf, sizeof deadline_buf, "%lld", (long long)policy.deadline);
        else snprintf(deadline_buf, sizeof deadline_buf, "none");

        bin2hex_lower(server_pub, 32, hex, sizeof hex);

        printf("C-compatible Rust Server listening on %s\n", bind_addr);
        printf("Server public key (pin this on client): %s\n", hex);
        printf("Server: pairing_enabled=%s token_configured=%s deadline=%s raw_pubkey_onboarding=true\n",
               policy.enabled ? "true" : "false",
               policy.token ? "true" : "false",
               deadline_buf);
    }

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;

        {
            struct timeval tv = { IO_TIMEOUT_SEC, 0 };
            setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        }

        handle_client(cfd, server_sk, server_pub, policy, &reg, &reg_n);
        close(cfd);
    }

    return 0;
}