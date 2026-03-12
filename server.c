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

// ─── Protocol constants ───────────────────────────────────────────────────────
#define MSG_SETUP    0x01
#define MSG_AUTH_V2  0x03

#define REGISTRY_BIN      "registry.bin"
#define REGISTRY_BAK      "registry.bak"
#define SERVER_SK_FILE    "server_sk.bin"
#define BOOTSTRAP_DB_FILE "bootstrap_registry.bin"
#define BOOTSTRAP_DB_BAK  "bootstrap_registry.bak"
#define BOOTSTRAP_ID_LEN      32
#define BOOTSTRAP_SECRET_LEN  32

// [FIX-4] Hard cap on incoming encrypted payload
#define MAX_ENCRYPTED_PAYLOAD  4096

// [FIX-5] Each replay cache generation holds at most this many entries.
// When current fills up, it becomes previous and a fresh current starts.
#define REPLAY_GEN_MAX  25000

// ─── [FIX-9] Nonce counter ────────────────────────────────────────────────────
typedef struct { uint64_t count; } nonce_ctr_t;
#define NONCE_CTR_INIT { 0 }

static void nonce_next(nonce_ctr_t *c, uint8_t out[12]) {
    uint64_t v = c->count++;
    out[0]  = (uint8_t)(v);
    out[1]  = (uint8_t)(v >> 8);
    out[2]  = (uint8_t)(v >> 16);
    out[3]  = (uint8_t)(v >> 24);
    out[4]  = (uint8_t)(v >> 32);
    out[5]  = (uint8_t)(v >> 40);
    out[6]  = (uint8_t)(v >> 48);
    out[7]  = (uint8_t)(v >> 56);
    out[8]  = 0; out[9] = 0; out[10] = 0; out[11] = 0;
}

// ─── [FIX-1] Pairing policy ───────────────────────────────────────────────────
typedef struct {
    int    enabled;
    int    token_configured;
    char   token[128];
    double deadline_sec; // 0 = no deadline
} pairing_policy_t;

// Returns 0 if the setup is allowed, -1 if not.
// [FIX-1] provided_token (may be NULL) is compared constant-time against the
//          configured token when one is required.
static int allows_ztp_setup(const pairing_policy_t *pol,
                              const char *provided_token, size_t provided_len) {
    if (!pol->enabled) return -1;

    if (pol->deadline_sec > 0.0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        double now = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
        if (now > pol->deadline_sec) {
            fprintf(stderr, "Server[SETUP/ZTP]: pairing window expired\n");
            return -1;
        }
    }

    // [FIX-1] Token enforcement
    if (pol->token_configured) {
        size_t expected_len = strlen(pol->token);
        if (!provided_token || provided_len != expected_len) return -1;
        // sodium_memcmp is constant-time
        if (sodium_memcmp(provided_token, pol->token, expected_len) != 0) return -1;
    }

    return 0;
}

// ─── File helpers ─────────────────────────────────────────────────────────────
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

// ─── Timing helper ───────────────────────────────────────────────────────────
static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// ─── Registry persistence ─────────────────────────────────────────────────────
typedef struct { uint8_t id[32]; uint8_t pub[32]; } reg_entry_t;

static int load_registry(reg_entry_t **out, size_t *out_n) {
    *out = NULL; *out_n = 0;
    if (!file_exists(REGISTRY_BIN)) return 0;
    FILE *f = fopen(REGISTRY_BIN, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0 || (sz % 64) != 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    size_t n = (size_t)sz / 64;
    if (n == 0) { fclose(f); return 0; }
    reg_entry_t *arr = calloc(n, sizeof(reg_entry_t));
    if (!arr) { fclose(f); return -1; }
    for (size_t i = 0; i < n; i++) {
        if (fread(arr[i].id,  1, 32, f) != 32 ||
            fread(arr[i].pub, 1, 32, f) != 32) {
            fclose(f); free(arr); return -1;
        }
    }
    fclose(f);
    *out = arr; *out_n = n;
    return 0;
}

static int save_registry(const reg_entry_t *arr, size_t n) {
    if (file_exists(REGISTRY_BIN)) rename(REGISTRY_BIN, REGISTRY_BAK);
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", REGISTRY_BIN);
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    for (size_t i = 0; i < n; i++) {
        if (fwrite(arr[i].id,  1, 32, f) != 32 ||
            fwrite(arr[i].pub, 1, 32, f) != 32) {
            fclose(f); return -1;
        }
    }
    fflush(f); fsync(fileno(f)); fclose(f);
    return rename(tmp, REGISTRY_BIN);
}

static int reg_lookup(const reg_entry_t *arr, size_t n,
                       const uint8_t id[32], uint8_t pub_out[32]) {
    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            memcpy(pub_out, arr[i].pub, 32);
            return 0;
        }
    }
    return -1;
}

// Returns: 1=new entry saved, 0=existing matched (no change), -1=error/mismatch
static int reg_upsert(reg_entry_t **arrp, size_t *np,
                       const uint8_t id[32], const uint8_t pub[32]) {
    reg_entry_t *arr = *arrp;
    size_t n = *np;
    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            if (sodium_memcmp(arr[i].pub, pub, 32) != 0) return -1;
            return 0;
        }
    }
    reg_entry_t *b = realloc(arr, (n + 1) * sizeof(reg_entry_t));
    if (!b) return -1;
    arr = b;
    memcpy(arr[n].id,  id,  32);
    memcpy(arr[n].pub, pub, 32);
    n++;
    *arrp = arr; *np = n;
    return (save_registry(arr, n) == 0) ? 1 : -1;
}

// ─── Bootstrap DB ─────────────────────────────────────────────────────────────
typedef struct {
    uint8_t id[BOOTSTRAP_ID_LEN];
    uint8_t secret[BOOTSTRAP_SECRET_LEN];
} bootstrap_entry_t;

static int load_bootstrap_db(bootstrap_entry_t **out, size_t *out_n) {
    *out = NULL; *out_n = 0;
    if (!file_exists(BOOTSTRAP_DB_FILE)) return 0;
    FILE *f = fopen(BOOTSTRAP_DB_FILE, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0 || (sz % 64) != 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    size_t n = (size_t)sz / 64;
    if (n == 0) { fclose(f); return 0; }
    bootstrap_entry_t *arr = calloc(n, sizeof *arr);
    if (!arr) { fclose(f); return -1; }
    for (size_t i = 0; i < n; i++) {
        if (fread(arr[i].id,     1, 32, f) != 32 ||
            fread(arr[i].secret, 1, 32, f) != 32) {
            fclose(f); free(arr); return -1;
        }
    }
    fclose(f);
    *out = arr; *out_n = n;
    return 0;
}

static int save_bootstrap_db(const bootstrap_entry_t *arr, size_t n) {
    if (file_exists(BOOTSTRAP_DB_FILE)) rename(BOOTSTRAP_DB_FILE, BOOTSTRAP_DB_BAK);
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", BOOTSTRAP_DB_FILE);
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    for (size_t i = 0; i < n; i++) {
        if (fwrite(arr[i].id,     1, 32, f) != 32 ||
            fwrite(arr[i].secret, 1, 32, f) != 32) {
            fclose(f); return -1;
        }
    }
    fflush(f); fsync(fileno(f)); fclose(f);
    return rename(tmp, BOOTSTRAP_DB_FILE);
}

static int bootstrap_lookup(const bootstrap_entry_t *arr, size_t n,
                              const uint8_t id[32], uint8_t secret_out[32]) {
    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            memcpy(secret_out, arr[i].secret, 32);
            return 0;
        }
    }
    return -1;
}

static int bootstrap_upsert(bootstrap_entry_t **arrp, size_t *np,
                              const uint8_t id[32], const uint8_t secret[32]) {
    bootstrap_entry_t *arr = *arrp;
    size_t n = *np;
    for (size_t i = 0; i < n; i++) {
        if (sodium_memcmp(arr[i].id, id, 32) == 0) {
            memcpy(arr[i].secret, secret, 32);
            return save_bootstrap_db(arr, n);
        }
    }
    bootstrap_entry_t *b = realloc(arr, (n + 1) * sizeof *b);
    if (!b) return -1;
    arr = b;
    memcpy(arr[n].id,     id,     32);
    memcpy(arr[n].secret, secret, 32);
    n++;
    *arrp = arr; *np = n;
    return save_bootstrap_db(arr, n);
}

// ─── [FIX-5] Two-generation replay cache ─────────────────────────────────────
//
// Nonces are never forgotten within a window of 2*REPLAY_GEN_MAX entries.
// When the current generation fills, it becomes previous and a fresh current
// starts — using the swapped buffer to avoid realloc on the hot path.
//
// Because the C server is single-threaded no mutex is required.
typedef struct { uint8_t key[64]; } replay_key_t;

static replay_key_t *replay_curr  = NULL;
static replay_key_t *replay_prev  = NULL;
static size_t        replay_curr_n = 0;
static size_t        replay_prev_n = 0;

static int replay_init(void) {
    replay_curr = malloc(sizeof(replay_key_t) * REPLAY_GEN_MAX);
    replay_prev = malloc(sizeof(replay_key_t) * REPLAY_GEN_MAX);
    if (!replay_curr || !replay_prev) {
        free(replay_curr); free(replay_prev);
        replay_curr = replay_prev = NULL;
        return -1;
    }
    replay_curr_n = replay_prev_n = 0;
    return 0;
}

static int check_and_insert_replay(const uint8_t device_id[32],
                                     const uint8_t nonce_c[32]) {
    if (!replay_curr) return -1; // not initialised

    uint8_t k[64];
    memcpy(k,      device_id, 32);
    memcpy(k + 32, nonce_c,   32);

    // Check both generations (constant-time sodium_memcmp)
    for (size_t i = 0; i < replay_curr_n; i++) {
        if (sodium_memcmp(replay_curr[i].key, k, 64) == 0) return -1;
    }
    for (size_t i = 0; i < replay_prev_n; i++) {
        if (sodium_memcmp(replay_prev[i].key, k, 64) == 0) return -1;
    }

    // Rotate when current is full: swap buffers, reset current counter
    if (replay_curr_n >= REPLAY_GEN_MAX) {
        replay_key_t *tmp = replay_prev;
        replay_prev   = replay_curr;
        replay_prev_n = replay_curr_n;
        replay_curr   = tmp;          // reuse previous buffer
        replay_curr_n = 0;
    }

    memcpy(replay_curr[replay_curr_n++].key, k, 64);
    return 0;
}

// ─── Network helpers ──────────────────────────────────────────────────────────
static int send_all(int fd, const uint8_t *buf, size_t len,
                     size_t *sent_tracker) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    if (sent_tracker) *sent_tracker += len;
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len,
                     size_t *recv_tracker) {
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

// [FIX-C2] Returns int
static int send_u32_le(int fd, uint32_t val, size_t *sent_tracker) {
    uint8_t buf[4];
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    return send_all(fd, buf, 4, sent_tracker);
}

static int recv_u32_le(int fd, uint32_t *val, size_t *recv_tracker) {
    uint8_t buf[4];
    if (recv_all(fd, buf, 4, recv_tracker) != 0) return -1;
    *val = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 0;
}

// [FIX-4] Bounded ciphertext read
static uint8_t *recv_encrypted_blob(int fd, uint32_t *out_len,
                                     size_t *recv_tracker) {
    uint32_t rx_len;
    if (recv_u32_le(fd, &rx_len, recv_tracker) != 0) return NULL;
    if (rx_len > MAX_ENCRYPTED_PAYLOAD) {
        fprintf(stderr, "payload too large: %u (max %d)\n",
                rx_len, MAX_ENCRYPTED_PAYLOAD);
        return NULL;
    }
    uint8_t *buf = malloc(rx_len);
    if (!buf) return NULL;
    if (recv_all(fd, buf, rx_len, recv_tracker) != 0) { free(buf); return NULL; }
    *out_len = rx_len;
    return buf;
}

// [FIX-11] Receive the pairing token sent by the client during SETUP.
// Wire format: 1-byte length (0 = no token) followed by that many bytes.
// Writes token into caller-supplied buffer (max 128 bytes) and sets *out_len.
static int recv_pairing_token(int fd, char token_buf[128], size_t *out_len,
                                size_t *recv_tracker) {
    uint8_t tlen;
    if (recv_u8(fd, &tlen, recv_tracker) != 0) return -1;
    *out_len = tlen;
    if (tlen == 0) return 0; // no token
    if (tlen > 128) {
        fprintf(stderr, "pairing token too long\n");
        return -1;
    }
    if (recv_all(fd, (uint8_t *)token_buf, tlen, recv_tracker) != 0) return -1;
    token_buf[tlen] = '\0'; // safe: buffer is [128], max tlen=127
    return 0;
}

// ─── [FIX-7] Point validity helper ───────────────────────────────────────────
static int check_point(const uint8_t p[32], const char *what) {
    if (crypto_core_ristretto255_is_valid_point(p) != 1) {
        fprintf(stderr, "invalid or identity point: %s\n", what);
        return -1;
    }
    return 0;
}

// ─── Transcript ──────────────────────────────────────────────────────────────
typedef struct { uint8_t buf[4096]; size_t len; } transcript_t;

static void tr_init(transcript_t *tr, const char *domain) {
    tr->len = 0;
    size_t dlen = strlen(domain);
    if (dlen > 255) { fprintf(stderr, "domain too long\n"); exit(1); }
    tr->buf[tr->len++] = (uint8_t)dlen;
    memcpy(tr->buf + tr->len, domain, dlen);
    tr->len += dlen;
}

static void tr_append(transcript_t *tr, const char *label,
                       const uint8_t *val, uint32_t vlen) {
    size_t llen = strlen(label);
    if (llen > 255) { fprintf(stderr, "label too long\n"); exit(1); }
    if (tr->len + 1 + llen + 4 + (size_t)vlen > sizeof(tr->buf)) {
        fprintf(stderr, "transcript overflow\n"); exit(1);
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

// ─── Schnorr verify/prove ─────────────────────────────────────────────────────
static int schnorr_verify_setup(const uint8_t device_id[32],
                                  const uint8_t pubkey[32],
                                  const uint8_t server_nonce[32],
                                  const uint8_t A[32],
                                  const uint8_t s[32]) {
    uint8_t c[32], left[32], cX[32], right[32];
    transcript_t tr;
    tr_init(&tr, "setup_schnorr_v1");
    tr_append(&tr, "device_id",    device_id,    32);
    tr_append(&tr, "pubkey",       pubkey,        32);
    tr_append(&tr, "a",            A,             32);
    tr_append(&tr, "server_nonce", server_nonce,  32);
    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cX, c, pubkey) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cX);
    return (sodium_memcmp(left, right, 32) == 0) ? 0 : -1;
}

static int schnorr_verify_auth(const uint8_t device_id[32],
                                 const uint8_t expected_pub[32],
                                 const uint8_t A[32],
                                 const uint8_t s[32],
                                 const uint8_t nonce_c[32],
                                 const uint8_t eph_c[32]) {
    uint8_t c[32], left[32], cX[32], right[32];
    transcript_t tr;
    tr_init(&tr, "client_schnorr_v1");
    tr_append(&tr, "device_id", device_id,    32);
    tr_append(&tr, "pubkey",    expected_pub,  32);
    tr_append(&tr, "a",         A,             32);
    tr_append(&tr, "nonce_c",   nonce_c,       32);
    tr_append(&tr, "eph_c",     eph_c,         32);
    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cX, c, expected_pub) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cX);
    return (sodium_memcmp(left, right, 32) == 0) ? 0 : -1;
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
    tr_append(&tr, "a",      A,          32);
    tr_append(&tr, "nonce_s", nonce_s,   32);
    tr_append(&tr, "eph_s",  eph_s,      32);
    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cx, c, server_sk);
    crypto_core_ristretto255_scalar_add(s, r, cx);
    sodium_memzero(r, sizeof r);
    sodium_memzero(cx, sizeof cx);
    sodium_memzero(c, sizeof c);
}

// ─── HKDF-SHA256 ─────────────────────────────────────────────────────────────
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
    size_t  t_len = 0, out = 0;
    uint8_t ctr = 1;
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
        out += take; ctr++;
    }
    sodium_memzero(t, sizeof t);
}

// [FIX-8]  x25519_shared mixed into info (channel binding).
// [FIX-C1] eph_c_pub and eph_s_pub are explicit canonical-order parameters
//           (client eph first, server eph second) so both sides agree on info.
static int derive_session_key(uint8_t key[32],
                               const uint8_t ristretto_eph_scalar[32],
                               const uint8_t ristretto_peer_pub[32],
                               const uint8_t nonce_c[32],
                               const uint8_t nonce_s[32],
                               const uint8_t device_id[32],
                               const uint8_t eph_c_pub[32],    // [FIX-C1]
                               const uint8_t eph_s_pub[32],    // [FIX-C1]
                               const uint8_t x25519_shared[32]) { // [FIX-8]
    uint8_t shared[32];
    if (crypto_scalarmult_ristretto255(shared, ristretto_eph_scalar,
                                        ristretto_peer_pub) != 0) {
        sodium_memzero(shared, sizeof shared);
        return -1;
    }

    uint8_t salt[64];
    memcpy(salt,      nonce_c, 32);
    memcpy(salt + 32, nonce_s, 32);

    uint8_t info[11 + 32 + 32 + 32 + 32];
    size_t off = 0;
    memcpy(info + off, "session key",  11); off += 11;
    memcpy(info + off, device_id,      32); off += 32;
    memcpy(info + off, eph_c_pub,      32); off += 32;  // [FIX-C1]
    memcpy(info + off, eph_s_pub,      32); off += 32;  // [FIX-C1]
    memcpy(info + off, x25519_shared,  32); off += 32;  // [FIX-8]

    uint8_t prk[32];
    hkdf_extract(prk, salt, sizeof salt, shared, sizeof shared);
    hkdf_expand(key, 32, prk, info, off);

    sodium_memzero(shared, sizeof shared);
    sodium_memzero(prk,    sizeof prk);
    return 0;
}

// ─── KC helpers ───────────────────────────────────────────────────────────────
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
    tr_append(&tr, "device_id",  device_id,  32);
    tr_append(&tr, "a_c",        a_c,         32);
    tr_append(&tr, "s_c",        s_c,         32);
    tr_append(&tr, "nonce_c",    nonce_c,     32);
    tr_append(&tr, "eph_c",      eph_c,       32);
    tr_append(&tr, "server_pub", server_pub,  32);
    tr_append(&tr, "a_s",        a_s,         32);
    tr_append(&tr, "s_s",        s_s,         32);
    tr_append(&tr, "nonce_s",    nonce_s,     32);
    tr_append(&tr, "eph_s",      eph_s,       32);
    crypto_hash_sha256(th, tr.buf, (unsigned long long)tr.len);
}

static void derive_kc_keys(uint8_t k_s2c[32], uint8_t k_c2s[32],
                             const uint8_t session_key[32],
                             const uint8_t th[32]) {
    uint8_t prk[32];
    hkdf_extract(prk, th, 32, session_key, 32);
    hkdf_expand(k_s2c, 32, prk, (const uint8_t *)"kc s2c", 6);
    hkdf_expand(k_c2s, 32, prk, (const uint8_t *)"kc c2s", 6);
    sodium_memzero(prk, sizeof prk);
}

static void hmac_tag(uint8_t out[32], const uint8_t key[32],
                      const char *label, const uint8_t th[32]) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, 32);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)label,
                                   (unsigned long long)strlen(label));
    crypto_auth_hmacsha256_update(&st, th, 32);
    crypto_auth_hmacsha256_final(&st, out);
}

// ─── ZTP bootstrap MAC ───────────────────────────────────────────────────────
static void ztp_mac_transcript_hash(uint8_t out[32],
                                     const uint8_t bootstrap_id[BOOTSTRAP_ID_LEN],
                                     const uint8_t device_id[32],
                                     const uint8_t device_pub[32],
                                     const uint8_t server_pub[32],
                                     const uint8_t client_nonce[32],
                                     const uint8_t server_nonce[32]) {
    transcript_t tr;
    tr_init(&tr, "ztp-bootstrap-v1");
    tr_append(&tr, "bootstrap_id", bootstrap_id, BOOTSTRAP_ID_LEN);
    tr_append(&tr, "device_id",    device_id,    32);
    tr_append(&tr, "device_pub",   device_pub,   32);
    tr_append(&tr, "server_pub",   server_pub,   32);
    tr_append(&tr, "client_nonce", client_nonce, 32);
    tr_append(&tr, "server_nonce", server_nonce, 32);
    crypto_hash_sha256(out, tr.buf, (unsigned long long)tr.len);
}

static void compute_bootstrap_mac(uint8_t out[32],
                                   const uint8_t bootstrap_secret[BOOTSTRAP_SECRET_LEN],
                                   const uint8_t bootstrap_id[BOOTSTRAP_ID_LEN],
                                   const uint8_t device_id[32],
                                   const uint8_t device_pub[32],
                                   const uint8_t server_pub[32],
                                   const uint8_t client_nonce[32],
                                   const uint8_t server_nonce[32]) {
    uint8_t th[32];
    ztp_mac_transcript_hash(th, bootstrap_id, device_id, device_pub,
                             server_pub, client_nonce, server_nonce);
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, bootstrap_secret, BOOTSTRAP_SECRET_LEN);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)"ztp-bootstrap-mac", 17);
    crypto_auth_hmacsha256_update(&st, th, 32);
    crypto_auth_hmacsha256_final(&st, out);
    sodium_memzero(th, sizeof th);
}

// ─── TCP listen ───────────────────────────────────────────────────────────────
static int listen_tcp(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) { close(fd); return -1; }
    if (listen(fd, 32) != 0)                                   { close(fd); return -1; }
    return fd;
}

static int parse_bind(const char *bind_str, char ip[64], uint16_t *port) {
    const char *colon = strchr(bind_str, ':');
    if (!colon) return -1;
    size_t il = (size_t)(colon - bind_str);
    if (il >= 64) return -1;
    memcpy(ip, bind_str, il); ip[il] = 0;
    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

// ─── Client handler ───────────────────────────────────────────────────────────
static void handle_client(int cfd, const char *peer,
                           reg_entry_t **reg, size_t *reg_n,
                           bootstrap_entry_t **boot, size_t *boot_n,
                           const uint8_t server_sk[32],
                           const uint8_t server_pub[32],
                           const pairing_policy_t *policy) {
    double start_time = get_time_sec();
    size_t sent = 0, recv_bytes = 0;

    uint8_t msg_type;
    if (recv_u8(cfd, &msg_type, &recv_bytes) != 0) goto cleanup;

    // ── MSG_SETUP ──────────────────────────────────────────────────────────────
    if (msg_type == MSG_SETUP) {

        // [FIX-11] Receive pairing token FIRST (before any policy-sensitive data)
        char token_buf[129]; // 128 + NUL
        size_t token_len = 0;
        memset(token_buf, 0, sizeof token_buf);
        if (recv_pairing_token(cfd, token_buf, &token_len, &recv_bytes) != 0)
            goto cleanup;

        // [FIX-1] Enforce token policy with constant-time comparison
        if (allows_ztp_setup(policy,
                              token_len > 0 ? token_buf : NULL,
                              token_len) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: pairing rejected by policy\n");
            goto cleanup;
        }

        uint8_t bid_len_byte;
        if (recv_u8(cfd, &bid_len_byte, &recv_bytes) != 0) goto cleanup;
        if (bid_len_byte != BOOTSTRAP_ID_LEN) {
            fprintf(stderr, "Server[SETUP/ZTP]: invalid bootstrap_id length\n");
            goto cleanup;
        }

        uint8_t bootstrap_id[BOOTSTRAP_ID_LEN], bootstrap_secret[BOOTSTRAP_SECRET_LEN];
        uint8_t device_id[32], device_pub[32], client_nonce[32];

        if (recv_all(cfd, bootstrap_id,  BOOTSTRAP_ID_LEN, &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, device_id,     32,                &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, device_pub,    32,                &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, client_nonce,  32,                &recv_bytes) != 0) goto cleanup;

        // [FIX-7] Validate device_pub
        if (check_point(device_pub, "device_pub") != 0) goto cleanup;

        if (bootstrap_lookup(*boot, *boot_n, bootstrap_id, bootstrap_secret) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: unknown bootstrap_id\n");
            goto cleanup;
        }

        uint8_t existing_pub[32];
        int existing = reg_lookup(*reg, *reg_n, device_id, existing_pub);
        int is_new   = (existing != 0);
        if (!is_new && sodium_memcmp(existing_pub, device_pub, 32) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: device_id collision\n");
            goto cleanup;
        }

        uint8_t server_nonce[32];
        randombytes_buf(server_nonce, 32);

        if (send_all(cfd, server_pub,   32, &sent) != 0) goto cleanup;
        if (send_all(cfd, server_nonce, 32, &sent) != 0) goto cleanup;

        uint8_t A[32], s[32], bootstrap_mac[32], expected_mac[32];
        if (recv_all(cfd, A,             32, &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, s,             32, &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, bootstrap_mac, 32, &recv_bytes) != 0) goto cleanup;

        // [FIX-7] Validate received proof commitment point
        if (check_point(A, "setup_A") != 0) goto cleanup;

        if (schnorr_verify_setup(device_id, device_pub, server_nonce, A, s) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: Schnorr proof invalid\n");
            goto cleanup;
        }

        compute_bootstrap_mac(expected_mac, bootstrap_secret, bootstrap_id,
                               device_id, device_pub, server_pub,
                               client_nonce, server_nonce);

        // sodium_memcmp is already constant-time
        if (sodium_memcmp(expected_mac, bootstrap_mac, 32) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: bootstrap MAC invalid\n");
            goto cleanup;
        }

        int upsert = reg_upsert(reg, reg_n, device_id, device_pub);
        if (upsert < 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: registry update failed\n");
            goto cleanup;
        }

        char hex_id[65], hex_bid[65];
        sodium_bin2hex(hex_id,  sizeof hex_id,  device_id,    32);
        sodium_bin2hex(hex_bid, sizeof hex_bid,  bootstrap_id, BOOTSTRAP_ID_LEN);

        if (upsert == 1)
            printf("Server[SETUP/ZTP]: enrolled NEW device_id=%s bootstrap_id=%s\n",
                   hex_id, hex_bid);
        else
            printf("Server[SETUP/ZTP]: validated existing device_id=%s bootstrap_id=%s\n",
                   hex_id, hex_bid);

        sodium_memzero(bootstrap_secret, sizeof bootstrap_secret);
        sodium_memzero(expected_mac,     sizeof expected_mac);

    // ── MSG_AUTH_V2 ───────────────────────────────────────────────────────────
    } else if (msg_type == MSG_AUTH_V2) {

        // 1. Anonymous X25519 ephemeral key exchange
        uint8_t client_pk[32];
        if (recv_all(cfd, client_pk, 32, &recv_bytes) != 0) goto cleanup;

        uint8_t srv_eph_sk[crypto_kx_SECRETKEYBYTES];
        uint8_t srv_eph_pk[crypto_kx_PUBLICKEYBYTES];
        crypto_kx_keypair(srv_eph_pk, srv_eph_sk);

        if (send_all(cfd, srv_eph_pk, 32, &sent) != 0) goto cleanup;

        uint8_t x25519_shared[32]; // [FIX-8] kept for session key binding
        if (crypto_scalarmult(x25519_shared, srv_eph_sk, client_pk) != 0) {
            fprintf(stderr, "Server[AUTH]: invalid client X25519 key\n");
            goto cleanup;
        }

        // Blake2b-512 key derivation (matches libsodium crypto_kx)
        uint8_t hash[64];
        crypto_generichash_state bst;
        crypto_generichash_init(&bst, NULL, 0, 64);
        crypto_generichash_update(&bst, x25519_shared, 32);
        crypto_generichash_update(&bst, client_pk,     32);
        crypto_generichash_update(&bst, srv_eph_pk,    32);
        crypto_generichash_final(&bst, hash, 64);

        uint8_t rx_key[32], tx_key[32];
        memcpy(rx_key, hash + 32, 32); // C→S (server RX)
        memcpy(tx_key, hash,      32); // S→C (server TX)

        // [FIX-9] Separate nonce counters per direction
        nonce_ctr_t nonce_rx = NONCE_CTR_INIT;
        nonce_ctr_t nonce_tx = NONCE_CTR_INIT;

        // 2. Decrypt client identity payload
        uint32_t rx_len;
        // [FIX-4] Bounded allocation
        uint8_t *rx_ct = recv_encrypted_blob(cfd, &rx_len, &recv_bytes);
        if (!rx_ct) goto cleanup;

        uint8_t pt1[160];
        unsigned long long pt1_len;
        uint8_t nonce_rx_buf[12];
        nonce_next(&nonce_rx, nonce_rx_buf); // [FIX-9] nonce = 0

        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt1, &pt1_len, NULL,
                                                       rx_ct, rx_len,
                                                       NULL, 0,
                                                       nonce_rx_buf, rx_key) != 0) {
            fprintf(stderr, "Server[AUTH]: client payload decryption failed\n");
            free(rx_ct); goto cleanup;
        }
        free(rx_ct);

        if (pt1_len != 160) {
            fprintf(stderr, "Server[AUTH]: invalid payload size %llu\n", pt1_len);
            goto cleanup;
        }

        uint8_t device_id[32], A_c[32], s_c[32], nonce_c[32], eph_c[32];
        memcpy(device_id, pt1,       32);
        memcpy(A_c,       pt1 + 32,  32);
        memcpy(s_c,       pt1 + 64,  32);
        memcpy(nonce_c,   pt1 + 96,  32);
        memcpy(eph_c,     pt1 + 128, 32);

        // [FIX-7] Validate received Ristretto points
        if (check_point(A_c,   "A_c")   != 0) goto cleanup;
        if (check_point(eph_c, "eph_c") != 0) goto cleanup;

        // 3. Replay & Schnorr verification
        if (check_and_insert_replay(device_id, nonce_c) != 0) {
            fprintf(stderr, "Server[AUTH]: replay detected\n");
            goto cleanup;
        }

        uint8_t expected_pub[32];
        if (reg_lookup(*reg, *reg_n, device_id, expected_pub) != 0) {
            fprintf(stderr, "Server[AUTH]: unknown device_id\n");
            goto cleanup;
        }

        if (schnorr_verify_auth(device_id, expected_pub, A_c, s_c,
                                 nonce_c, eph_c) != 0) {
            fprintf(stderr, "Server[AUTH]: client Schnorr proof invalid\n");
            goto cleanup;
        }

        // 4. Build encrypted server response
        uint8_t nonce_s[32];
        randombytes_buf(nonce_s, 32);

        uint8_t eph_s_secret[32], eph_s[32];
        crypto_core_ristretto255_scalar_random(eph_s_secret);
        crypto_scalarmult_ristretto255_base(eph_s, eph_s_secret);

        uint8_t A_s[32], s_s[32];
        schnorr_prove_server(A_s, s_s, server_sk, server_pub, nonce_s, eph_s);

        // [FIX-C1] Canonical order: eph_c first, eph_s second
        // [FIX-8]  x25519_shared mixed in
        uint8_t session_key[32];
        if (derive_session_key(session_key,
                                eph_s_secret, eph_c,   // scalar, peer pub
                                nonce_c, nonce_s, device_id,
                                eph_c, eph_s,            // [FIX-C1]
                                x25519_shared) != 0) {   // [FIX-8]
            fprintf(stderr, "Server[AUTH]: session key derivation failed\n");
            goto cleanup;
        }

        uint8_t th[32];
        kc_transcript_hash(th, device_id, A_c, s_c, nonce_c, eph_c,
                            server_pub, A_s, s_s, nonce_s, eph_s);

        uint8_t k_s2c[32], k_c2s[32];
        derive_kc_keys(k_s2c, k_c2s, session_key, th);

        uint8_t tag_s[32];
        hmac_tag(tag_s, k_s2c, "server finished", th);

        uint8_t payload2[192];
        memcpy(payload2,       server_pub, 32);
        memcpy(payload2 + 32,  A_s,        32);
        memcpy(payload2 + 64,  s_s,        32);
        memcpy(payload2 + 96,  nonce_s,    32);
        memcpy(payload2 + 128, eph_s,      32);
        memcpy(payload2 + 160, tag_s,      32);

        uint8_t nonce_tx_buf[12];
        nonce_next(&nonce_tx, nonce_tx_buf); // [FIX-9] nonce = 0

        uint8_t ct2[192 + crypto_aead_chacha20poly1305_IETF_ABYTES];
        unsigned long long ct2_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(ct2, &ct2_len,
                                                   payload2, sizeof payload2,
                                                   NULL, 0, NULL,
                                                   nonce_tx_buf, tx_key);

        // [FIX-C2] Check return values
        if (send_u32_le(cfd, (uint32_t)ct2_len, &sent) != 0) goto cleanup;
        if (send_all(cfd, ct2, (size_t)ct2_len, &sent)  != 0) goto cleanup;

        // 5. Decrypt and verify client finished tag
        uint32_t rx_len2;
        // [FIX-4] Bounded allocation
        uint8_t *rx_ct2 = recv_encrypted_blob(cfd, &rx_len2, &recv_bytes);
        if (!rx_ct2) goto cleanup;

        uint8_t pt3[32];
        unsigned long long pt3_len;
        nonce_next(&nonce_rx, nonce_rx_buf); // [FIX-9] nonce = 1

        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt3, &pt3_len, NULL,
                                                       rx_ct2, rx_len2,
                                                       NULL, 0,
                                                       nonce_rx_buf, rx_key) != 0) {
            fprintf(stderr, "Server[AUTH]: tag_c decryption failed\n");
            free(rx_ct2); goto cleanup;
        }
        free(rx_ct2);

        if (pt3_len != 32) {
            fprintf(stderr, "Server[AUTH]: tag_c wrong length\n");
            goto cleanup;
        }

        uint8_t expected_tag_c[32];
        hmac_tag(expected_tag_c, k_c2s, "client finished", th);
        // sodium_memcmp is constant-time
        if (sodium_memcmp(expected_tag_c, pt3, 32) != 0) {
            fprintf(stderr, "Server[AUTH]: key confirmation failed (tag_c mismatch)\n");
            goto cleanup;
        }

        char hex_id[65], hex_sk[65];
        sodium_bin2hex(hex_id, sizeof hex_id, device_id,   32);
        sodium_bin2hex(hex_sk, sizeof hex_sk, session_key, 32);
        printf("Server[AUTH]: device_id=%s session_key=%s KC=OK\n", hex_id, hex_sk);

        sodium_memzero(eph_s_secret,  sizeof eph_s_secret);
        sodium_memzero(session_key,   sizeof session_key);
        sodium_memzero(k_s2c,         sizeof k_s2c);
        sodium_memzero(k_c2s,         sizeof k_c2s);
        sodium_memzero(srv_eph_sk,    sizeof srv_eph_sk);
        sodium_memzero(x25519_shared, sizeof x25519_shared);
        sodium_memzero(tx_key,        sizeof tx_key);
        sodium_memzero(rx_key,        sizeof rx_key);

    } else {
        fprintf(stderr, "Server: unknown msg_type 0x%02x\n", msg_type);
    }

cleanup:
    close(cfd);
    double dur = get_time_sec() - start_time;
    printf("SERVER METRICS -> %s Duration: %.3fms, Sent: %zu bytes, Received: %zu bytes\n",
           peer, dur * 1000.0, sent, recv_bytes);
}

// ─── Main ────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;

    const char *bind_str = "0.0.0.0:4000";
    pairing_policy_t policy;
    memset(&policy, 0, sizeof policy);

    uint8_t add_bootstrap_id[BOOTSTRAP_ID_LEN];
    uint8_t add_bootstrap_secret[BOOTSTRAP_SECRET_LEN];
    int have_add_bootstrap = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
            bind_str = argv[++i];
        } else if (!strcmp(argv[i], "--pairing")) {
            policy.enabled = 1;
        } else if (!strcmp(argv[i], "--pairing-token") && i + 1 < argc) {
            policy.token_configured = 1;
            snprintf(policy.token, sizeof policy.token, "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--pairing-seconds") && i + 1 < argc) {
            double secs = atof(argv[++i]);
            if (secs <= 0) { fprintf(stderr, "bad --pairing-seconds\n"); return 1; }
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            policy.deadline_sec = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9 + secs;
        } else if (!strcmp(argv[i], "--add-bootstrap") && i + 2 < argc) {
            size_t bin_len = 0;
            if (sodium_hex2bin(add_bootstrap_id, sizeof add_bootstrap_id,
                               argv[i+1], strlen(argv[i+1]),
                               NULL, &bin_len, NULL) != 0 ||
                bin_len != BOOTSTRAP_ID_LEN) {
                fprintf(stderr, "invalid bootstrap_id hex\n"); return 1;
            }
            if (sodium_hex2bin(add_bootstrap_secret, sizeof add_bootstrap_secret,
                               argv[i+2], strlen(argv[i+2]),
                               NULL, &bin_len, NULL) != 0 ||
                bin_len != BOOTSTRAP_SECRET_LEN) {
                fprintf(stderr, "invalid bootstrap_secret hex\n"); return 1;
            }
            have_add_bootstrap = 1;
            i += 2;
        } else {
            fprintf(stderr,
                    "Usage: %s [--bind 0.0.0.0:4000] [--pairing] "
                    "[--pairing-token TOKEN] [--pairing-seconds N] "
                    "[--add-bootstrap <id_hex> <secret_hex>]\n", argv[0]);
            return 1;
        }
    }

    bootstrap_entry_t *boot = NULL;
    size_t boot_n = 0;
    if (load_bootstrap_db(&boot, &boot_n) != 0) {
        fprintf(stderr, "Failed to load bootstrap DB\n"); return 1;
    }

    if (have_add_bootstrap) {
        if (bootstrap_upsert(&boot, &boot_n,
                              add_bootstrap_id, add_bootstrap_secret) < 0) {
            fprintf(stderr, "Failed to update bootstrap DB\n"); return 1;
        }
        char hex_bid[65];
        sodium_bin2hex(hex_bid, sizeof hex_bid, add_bootstrap_id, BOOTSTRAP_ID_LEN);
        printf("Server: added bootstrap_id=%s to %s\n", hex_bid, BOOTSTRAP_DB_FILE);
        sodium_memzero(add_bootstrap_secret, sizeof add_bootstrap_secret);
        free(boot);
        return 0;
    }

    // [FIX-5] Initialise two-generation replay cache
    if (replay_init() != 0) {
        fprintf(stderr, "Failed to initialise replay cache\n");
        free(boot); return 1;
    }

    char     ip[64];
    uint16_t port;
    if (parse_bind(bind_str, ip, &port) != 0) {
        fprintf(stderr, "bad --bind value\n"); free(boot); return 1;
    }

    uint8_t server_sk[32];
    if (file_exists(SERVER_SK_FILE)) {
        if (read_file_32(SERVER_SK_FILE, server_sk) != 0) {
            fprintf(stderr, "failed reading %s\n", SERVER_SK_FILE);
            free(boot); return 1;
        }
    } else {
        crypto_core_ristretto255_scalar_random(server_sk);
        if (write_file_32(SERVER_SK_FILE, server_sk) != 0) {
            fprintf(stderr, "failed writing %s\n", SERVER_SK_FILE);
            free(boot); return 1;
        }
    }

    uint8_t server_pub[32];
    crypto_scalarmult_ristretto255_base(server_pub, server_sk);
    // [FIX-7] Sanity-check our own public key
    if (crypto_core_ristretto255_is_valid_point(server_pub) != 1) {
        fprintf(stderr, "server_pub is invalid — corrupt server_sk?\n");
        free(boot); return 1;
    }

    reg_entry_t *reg = NULL;
    size_t reg_n = 0;
    if (load_registry(&reg, &reg_n) != 0) {
        fprintf(stderr, "Failed to load registry\n"); free(boot); return 1;
    }

    int lfd = listen_tcp(ip, port);
    if (lfd < 0) {
        fprintf(stderr, "listen failed\n"); free(reg); free(boot); return 1;
    }

    printf("C Server listening on %s\n", bind_str);
    printf("Server: pairing_enabled=%s token_configured=%s "
           "deadline=%s bootstrap_db_entries=%zu\n",
           policy.enabled          ? "true" : "false",
           policy.token_configured ? "true" : "false",
           policy.deadline_sec > 0.0 ? "set" : "none",
           boot_n);

    for (;;) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof peer_addr;
        int cfd = accept(lfd, (struct sockaddr *)&peer_addr, &peer_len);
        if (cfd < 0) continue;

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof peer_ip);

        char peer_str[64];
        snprintf(peer_str, sizeof peer_str, "%s:%d",
                 peer_ip, ntohs(peer_addr.sin_port));

        handle_client(cfd, peer_str, &reg, &reg_n,
                       &boot, &boot_n, server_sk, server_pub, &policy);
    }
}