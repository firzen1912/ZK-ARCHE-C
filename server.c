#define _POSIX_C_SOURCE 200112L
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>       /* FIX: per-connection threads */
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MSG_SETUP    0x01
#define MSG_AUTH_V2  0x03

#define REGISTRY_BIN          "/var/lib/iot-auth/server/registry.bin"
#define REGISTRY_BAK          "/var/lib/iot-auth/server/registry.bak"
#define SERVER_SK_FILE        "/var/lib/iot-auth/server/server_sk.bin"
#define SERVER_CERT_FILE      "/var/lib/iot-auth/server/server_cert.pem"
#define SERVER_CERT_KEY_FILE  "/var/lib/iot-auth/server/server_cert_key.pem"
#define CA_CERT_FILE          "/var/lib/iot-auth/server/ca_cert.pem"
#define MAX_ENCRYPTED_PAYLOAD  4096
#define REPLAY_GEN_MAX  25000
#define MAX_CERT_FILE_SIZE (128 * 1024)
#define MAX_SIG_SIZE 8192

/* FIX: recv timeout applied to every accepted socket to prevent slow-loris DoS */
#define RECV_TIMEOUT_SEC 10

typedef struct { uint64_t count; } nonce_ctr_t;
#define NONCE_CTR_INIT { 0 }

// Generates the next 96-bit nonce from the local monotonic counter.
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

typedef struct {
    int    enabled;
    int    token_configured;
    char   token[128];
    double deadline_sec;
} pairing_policy_t;

// Checks whether zero-touch setup is currently allowed under the pairing policy.
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

    if (pol->token_configured) {
        size_t expected_len = strlen(pol->token);
        if (!provided_token || provided_len != expected_len) return -1;
        if (sodium_memcmp(provided_token, pol->token, expected_len) != 0) return -1;
    }

    return 0;
}

// Checks whether the given file path exists.
static int file_exists(const char *path) { return access(path, F_OK) == 0; }

// Reads exactly 32 bytes from a file into the provided buffer.
static int read_file_32(const char *path, uint8_t out[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, 32, f);
    fclose(f);
    return (n == 32) ? 0 : -1;
}

// Writes exactly 32 bytes to a file.
static int write_file_32(const char *path, const uint8_t in[32]) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(in, 1, 32, f);
    fclose(f);
    return (n == 32) ? 0 : -1;
}

// Returns the current monotonic time in seconds.
static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

typedef struct { uint8_t id[32]; uint8_t pub[32]; } reg_entry_t;

/* FIX: mutex protecting the shared in-memory registry across threads */
static pthread_mutex_t g_reg_mutex = PTHREAD_MUTEX_INITIALIZER;

// Loads the device registry from disk into memory.
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

// Writes the current device registry to disk atomically.
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

// Looks up a device public key by device identifier.
// Caller must hold g_reg_mutex.
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

// Adds a new registry entry or validates an existing one before saving.
// Caller must hold g_reg_mutex.
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

typedef struct { uint8_t key[64]; } replay_key_t;

static replay_key_t *replay_curr  = NULL;
static replay_key_t *replay_prev  = NULL;
static size_t        replay_curr_n = 0;
static size_t        replay_prev_n = 0;
/* FIX: replay cache access is also covered by g_reg_mutex to avoid races */

// Allocates and initializes the replay-detection caches.
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

// Rejects replayed client nonces and records new ones.
// Caller must hold g_reg_mutex.
static int check_and_insert_replay(const uint8_t device_id[32],
                                   const uint8_t nonce_c[32]) {
    if (!replay_curr) return -1;

    uint8_t k[64];
    memcpy(k,      device_id, 32);
    memcpy(k + 32, nonce_c,   32);

    for (size_t i = 0; i < replay_curr_n; i++) {
        if (sodium_memcmp(replay_curr[i].key, k, 64) == 0) return -1;
    }
    for (size_t i = 0; i < replay_prev_n; i++) {
        if (sodium_memcmp(replay_prev[i].key, k, 64) == 0) return -1;
    }

    if (replay_curr_n >= REPLAY_GEN_MAX) {
        replay_key_t *tmp = replay_prev;
        replay_prev   = replay_curr;
        replay_prev_n = replay_curr_n;
        replay_curr   = tmp;
        replay_curr_n = 0;
    }

    memcpy(replay_curr[replay_curr_n++].key, k, 64);
    return 0;
}

// Sends the full buffer over the socket, retrying until complete or failed.
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

// Receives the full buffer from the socket, retrying until complete or failed.
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

// Receives a single byte from the socket.
static int recv_u8(int fd, uint8_t *out, size_t *recv_tracker) {
    return recv_all(fd, out, 1, recv_tracker);
}

// Sends a 32-bit little-endian integer over the socket.
static int send_u32_le(int fd, uint32_t val, size_t *sent_tracker) {
    uint8_t buf[4];
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    return send_all(fd, buf, 4, sent_tracker);
}

// Receives a 32-bit little-endian integer from the socket.
static int recv_u32_le(int fd, uint32_t *val, size_t *recv_tracker) {
    uint8_t buf[4];
    if (recv_all(fd, buf, 4, recv_tracker) != 0) return -1;
    *val = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 0;
}

// Receives an encrypted payload after validating its announced length.
static uint8_t *recv_encrypted_blob(int fd, uint32_t *out_len, size_t *recv_tracker) {
    uint32_t rx_len;
    if (recv_u32_le(fd, &rx_len, recv_tracker) != 0) return NULL;
    if (rx_len > MAX_ENCRYPTED_PAYLOAD) {
        fprintf(stderr, "payload too large: %u (max %d)\n", rx_len, MAX_ENCRYPTED_PAYLOAD);
        return NULL;
    }
    /* FIX: malloc(0) is implementation-defined; use at least 1 byte */
    uint8_t *buf = malloc(rx_len == 0 ? 1 : rx_len);
    if (!buf) return NULL;
    if (rx_len && recv_all(fd, buf, rx_len, recv_tracker) != 0) { free(buf); return NULL; }
    *out_len = rx_len;
    return buf;
}

// Receives the optional pairing token from the client.
// token_buf must be at least 129 bytes (128 payload + NUL terminator).
static int recv_pairing_token(int fd, char token_buf[129], size_t *out_len, size_t *recv_tracker) {
    uint8_t tlen;
    if (recv_u8(fd, &tlen, recv_tracker) != 0) return -1;
    *out_len = tlen;
    if (tlen == 0) return 0;
    /* FIX: was "> 128", allowing tlen==128 then writing token_buf[128] past the end.
       Use ">= 128" so the NUL terminator at token_buf[tlen] stays in bounds. */
    if (tlen >= 128) {
        fprintf(stderr, "pairing token too long\n");
        return -1;
    }
    if (recv_all(fd, (uint8_t *)token_buf, tlen, recv_tracker) != 0) return -1;
    token_buf[tlen] = '\0';
    return 0;
}

// Rejects invalid or identity Ristretto points before cryptographic use.
static int check_point(const uint8_t p[32], const char *what) {
    if (crypto_core_ristretto255_is_valid_point(p) != 1) {
        fprintf(stderr, "invalid or identity point: %s\n", what);
        return -1;
    }
    return 0;
}

typedef struct { uint8_t buf[4096]; size_t len; } transcript_t;

// Initializes a transcript with its domain separation label.
static void tr_init(transcript_t *tr, const char *domain) {
    tr->len = 0;
    size_t dlen = strlen(domain);
    if (dlen > 255) { fprintf(stderr, "domain too long\n"); exit(1); }
    tr->buf[tr->len++] = (uint8_t)dlen;
    memcpy(tr->buf + tr->len, domain, dlen);
    tr->len += dlen;
}

// Appends a labeled value to the transcript buffer.
static void tr_append(transcript_t *tr, const char *label, const uint8_t *val, uint32_t vlen) {
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

// Hashes the transcript and reduces it to a Ristretto scalar challenge.
static void tr_challenge_scalar(uint8_t c_out[32], const transcript_t *tr) {
    uint8_t h[64];
    crypto_hash_sha512(h, tr->buf, (unsigned long long)tr->len);
    crypto_core_ristretto255_scalar_reduce(c_out, h);
}

// Verifies the client Schnorr proof during setup.
static int schnorr_verify_setup(const uint8_t device_id[32], const uint8_t pubkey[32],
                                const uint8_t server_nonce[32], const uint8_t A[32], const uint8_t s[32]) {
    uint8_t c[32], left[32], cX[32], right[32];
    transcript_t tr;
    tr_init(&tr, "setup_schnorr_v1");
    tr_append(&tr, "device_id",    device_id,    32);
    tr_append(&tr, "pubkey",       pubkey,       32);
    tr_append(&tr, "a",            A,            32);
    tr_append(&tr, "server_nonce", server_nonce, 32);
    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cX, c, pubkey) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cX);
    return (sodium_memcmp(left, right, 32) == 0) ? 0 : -1;
}

// Verifies the client Schnorr proof during authentication.
static int schnorr_verify_auth(const uint8_t device_id[32], const uint8_t expected_pub[32],
                               const uint8_t A[32], const uint8_t s[32],
                               const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t c[32], left[32], cX[32], right[32];
    transcript_t tr;
    tr_init(&tr, "client_schnorr_v1");
    tr_append(&tr, "device_id", device_id,    32);
    tr_append(&tr, "pubkey",    expected_pub, 32);
    tr_append(&tr, "a",         A,            32);
    tr_append(&tr, "nonce_c",   nonce_c,      32);
    tr_append(&tr, "eph_c",     eph_c,        32);
    tr_challenge_scalar(c, &tr);
    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cX, c, expected_pub) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cX);
    return (sodium_memcmp(left, right, 32) == 0) ? 0 : -1;
}

// Builds the server Schnorr proof used during authentication.
static void schnorr_prove_server(uint8_t A[32], uint8_t s[32], const uint8_t server_sk[32],
                                 const uint8_t server_pub[32], const uint8_t nonce_s[32], const uint8_t eph_s[32]) {
    uint8_t r[32], c[32], cx[32];
    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);
    transcript_t tr;
    tr_init(&tr, "server_schnorr_v1");
    tr_append(&tr, "pubkey",  server_pub, 32);
    tr_append(&tr, "a",       A,          32);
    tr_append(&tr, "nonce_s", nonce_s,    32);
    tr_append(&tr, "eph_s",   eph_s,      32);
    tr_challenge_scalar(c, &tr);
    crypto_core_ristretto255_scalar_mul(cx, c, server_sk);
    crypto_core_ristretto255_scalar_add(s, r, cx);
    sodium_memzero(r, sizeof r);
    sodium_memzero(cx, sizeof cx);
    sodium_memzero(c, sizeof c);
}

// Runs the HKDF extract step with HMAC-SHA256.
static void hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);
}

// Runs the HKDF expand step with HMAC-SHA256.
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

// Derives the shared session key from the ephemeral key exchange inputs.
static int derive_session_key(uint8_t key[32], const uint8_t ristretto_eph_scalar[32],
                              const uint8_t ristretto_peer_pub[32], const uint8_t nonce_c[32],
                              const uint8_t nonce_s[32], const uint8_t device_id[32],
                              const uint8_t eph_c_pub[32], const uint8_t eph_s_pub[32],
                              const uint8_t x25519_shared[32]) {
    uint8_t shared[32];
    if (crypto_scalarmult_ristretto255(shared, ristretto_eph_scalar, ristretto_peer_pub) != 0) {
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
    memcpy(info + off, eph_c_pub,      32); off += 32;
    memcpy(info + off, eph_s_pub,      32); off += 32;
    memcpy(info + off, x25519_shared,  32); off += 32;

    uint8_t prk[32];
    hkdf_extract(prk, salt, sizeof salt, shared, sizeof shared);
    hkdf_expand(key, 32, prk, info, off);

    sodium_memzero(shared, sizeof shared);
    sodium_memzero(prk,    sizeof prk);
    return 0;
}

// Hashes the key-confirmation transcript for both peers.
static void kc_transcript_hash(uint8_t th[32], const uint8_t device_id[32],
                               const uint8_t a_c[32], const uint8_t s_c[32], const uint8_t nonce_c[32],
                               const uint8_t eph_c[32], const uint8_t server_pub[32], const uint8_t a_s[32],
                               const uint8_t s_s[32], const uint8_t nonce_s[32], const uint8_t eph_s[32]) {
    transcript_t tr;
    tr_init(&tr, "kc_v1");
    tr_append(&tr, "device_id",  device_id, 32);
    tr_append(&tr, "a_c",        a_c,       32);
    tr_append(&tr, "s_c",        s_c,       32);
    tr_append(&tr, "nonce_c",    nonce_c,   32);
    tr_append(&tr, "eph_c",      eph_c,     32);
    tr_append(&tr, "server_pub", server_pub,32);
    tr_append(&tr, "a_s",        a_s,       32);
    tr_append(&tr, "s_s",        s_s,       32);
    tr_append(&tr, "nonce_s",    nonce_s,   32);
    tr_append(&tr, "eph_s",      eph_s,     32);
    crypto_hash_sha256(th, tr.buf, (unsigned long long)tr.len);
}

// Derives directional key-confirmation keys from the session key and transcript hash.
static void derive_kc_keys(uint8_t k_s2c[32], uint8_t k_c2s[32],
                           const uint8_t session_key[32], const uint8_t th[32]) {
    uint8_t prk[32];
    hkdf_extract(prk, th, 32, session_key, 32);
    hkdf_expand(k_s2c, 32, prk, (const uint8_t *)"kc s2c", 6);
    hkdf_expand(k_c2s, 32, prk, (const uint8_t *)"kc c2s", 6);
    sodium_memzero(prk, sizeof prk);
}

// Computes an HMAC tag over a label and transcript hash.
static void hmac_tag(uint8_t out[32], const uint8_t key[32], const char *label, const uint8_t th[32]) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, 32);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)label,
                                  (unsigned long long)strlen(label));
    crypto_auth_hmacsha256_update(&st, th, 32);
    crypto_auth_hmacsha256_final(&st, out);
}

// Builds the mutual-certificate onboarding transcript hash.
static void ztp_cert_transcript_hash(uint8_t out[32],
                                   const uint8_t device_id[32], const uint8_t device_pub[32],
                                   const uint8_t client_nonce[32], const uint8_t server_nonce[32],
                                   const uint8_t *device_cert, uint32_t device_cert_len,
                                   const uint8_t *server_cert, uint32_t server_cert_len) {
    uint8_t dev_hash[32], srv_hash[32];
    transcript_t tr;
    crypto_hash_sha256(dev_hash, device_cert, device_cert_len);
    crypto_hash_sha256(srv_hash, server_cert, server_cert_len);
    tr_init(&tr, "ztp-mutual-cert-v1");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "device_pub", device_pub, 32);
    tr_append(&tr, "client_nonce", client_nonce, 32);
    tr_append(&tr, "server_nonce", server_nonce, 32);
    tr_append(&tr, "device_cert_hash", dev_hash, 32);
    tr_append(&tr, "server_cert_hash", srv_hash, 32);
    crypto_hash_sha256(out, tr.buf, (unsigned long long)tr.len);
}

// Sends a length-prefixed binary blob over the socket.
static int send_blob(int fd, const uint8_t *buf, uint32_t len, size_t *sent_tracker) {
    if (send_u32_le(fd, len, sent_tracker) != 0) return -1;
    return len ? send_all(fd, buf, len, sent_tracker) : 0;
}

// Receives a length-prefixed binary blob with a maximum size check.
static uint8_t *recv_blob(int fd, uint32_t *out_len, uint32_t max_len, size_t *recv_tracker) {
    uint32_t n;
    uint8_t *buf;
    if (recv_u32_le(fd, &n, recv_tracker) != 0) return NULL;
    if (n > max_len) return NULL;
    buf = malloc(n == 0 ? 1 : n);
    if (!buf) return NULL;
    if (n && recv_all(fd, buf, n, recv_tracker) != 0) { free(buf); return NULL; }
    *out_len = n;
    return buf;
}

// Converts binary data to lowercase hexadecimal text.
static void bin2hex_lower(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    /* sodium_bin2hex already emits lowercase; no secondary loop needed */
    sodium_bin2hex(out, out_len, in, in_len);
}

// Reads an entire file into memory up to the configured size limit.
static uint8_t *read_file_all(const char *path, size_t *out_len, size_t max_len) {
    FILE *f = fopen(path, "rb");
    uint8_t *buf = NULL;
    long sz;
    size_t n;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0 || (size_t)sz > max_len) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    buf = malloc((size_t)sz == 0 ? 1 : (size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { free(buf); return NULL; }
    *out_len = n;
    return buf;
}

// Parses an X.509 certificate from PEM or DER bytes.
static X509 *load_cert_from_bytes(const uint8_t *buf, size_t len) {
    BIO *bio = BIO_new_mem_buf(buf, (int)len);
    X509 *cert = NULL;
    if (!bio) return NULL;
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(bio);
        bio = BIO_new_mem_buf(buf, (int)len);
        if (!bio) return NULL;
        cert = d2i_X509_bio(bio, NULL);
    }
    BIO_free(bio);
    return cert;
}

// Parses a private key from PEM or DER bytes.
static EVP_PKEY *load_private_key_from_bytes(const uint8_t *buf, size_t len) {
    BIO *bio = BIO_new_mem_buf(buf, (int)len);
    EVP_PKEY *pkey = NULL;
    if (!bio) return NULL;
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        bio = BIO_new_mem_buf(buf, (int)len);
        if (!bio) return NULL;
        pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    BIO_free(bio);
    return pkey;
}

// Validates a certificate against the provided CA certificate.
static int verify_cert_against_ca(X509 *cert, X509 *ca_cert) {
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ok = 0;
    if (!store || !ctx) goto done;
    if (X509_STORE_add_cert(store, ca_cert) != 1) goto done;
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) goto done;
    ok = (X509_verify_cert(ctx) == 1) ? 0 : -1;
 done:
    if (ctx) X509_STORE_CTX_free(ctx);
    if (store) X509_STORE_free(store);
    return ok;
}

// Reads a certificate subject field and normalizes it to lowercase hex text.
static int cert_subject_field_hex(X509 *cert, int nid, char *out, size_t out_len) {
    X509_NAME *name = X509_get_subject_name(cert);
    int n;
    if (!name) return -1;
    n = X509_NAME_get_text_by_NID(name, nid, out, (int)out_len);
    if (n < 0 || (size_t)n >= out_len) return -1;
    /* sodium_bin2hex paths already produce lowercase; this handles CN/OU text fields */
    for (int i = 0; out[i]; i++) if (out[i] >= 'A' && out[i] <= 'Z') out[i] = (char)(out[i] - 'A' + 'a');
    return 0;
}

// Signs the supplied transcript hash with the given private key.
static int sign_transcript_hash(EVP_PKEY *pkey, const uint8_t th[32], uint8_t **sig_out, size_t *sig_len_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    uint8_t *sig = NULL;
    int pkey_id;
    if (!ctx) return -1;
    pkey_id = EVP_PKEY_base_id(pkey);
    if (pkey_id == EVP_PKEY_ED25519 || pkey_id == EVP_PKEY_ED448) {
        if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) goto err;
        if (EVP_DigestSign(ctx, NULL, &sig_len, th, 32) != 1) goto err;
        sig = malloc(sig_len ? sig_len : 1);
        if (!sig) goto err;
        if (EVP_DigestSign(ctx, sig, &sig_len, th, 32) != 1) goto err;
    } else {
        if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto err;
        if (EVP_DigestSignUpdate(ctx, th, 32) != 1) goto err;
        if (EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1) goto err;
        sig = malloc(sig_len ? sig_len : 1);
        if (!sig) goto err;
        if (EVP_DigestSignFinal(ctx, sig, &sig_len) != 1) goto err;
    }
    EVP_MD_CTX_free(ctx);
    *sig_out = sig;
    *sig_len_out = sig_len;
    return 0;
 err:
    EVP_MD_CTX_free(ctx);
    free(sig);
    return -1;
}

// Verifies a transcript-hash signature with the given public key.
static int verify_transcript_hash_sig(EVP_PKEY *pkey, const uint8_t th[32], const uint8_t *sig, size_t sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = -1;
    int pkey_id;
    if (!ctx) return -1;
    pkey_id = EVP_PKEY_base_id(pkey);
    if (pkey_id == EVP_PKEY_ED25519 || pkey_id == EVP_PKEY_ED448) {
        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) goto done;
        ok = (EVP_DigestVerify(ctx, sig, sig_len, th, 32) == 1) ? 0 : -1;
    } else {
        if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto done;
        if (EVP_DigestVerifyUpdate(ctx, th, 32) != 1) goto done;
        ok = (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) ? 0 : -1;
    }
 done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

// Creates, binds, and starts a TCP listening socket.
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

// Splits an ip:port bind string into address and port components.
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

// Processes one client connection for setup or authentication.
// reg and reg_n are protected by g_reg_mutex for all read/write accesses.
static void handle_client(int cfd, const char *peer, reg_entry_t **reg, size_t *reg_n,
                          const uint8_t server_sk[32], const uint8_t server_pub[32],
                          const pairing_policy_t *policy, const uint8_t *server_cert_buf, size_t server_cert_len,
                          EVP_PKEY *server_cert_key, X509 *server_cert, X509 *ca_cert) {
    double start_time = get_time_sec();
    size_t sent = 0, recv_bytes = 0;

    uint8_t msg_type;
    if (recv_u8(cfd, &msg_type, &recv_bytes) != 0) goto cleanup;

    if (msg_type == MSG_SETUP) {

        /* token_buf is 129 bytes: max 128 payload bytes + NUL terminator */
        char token_buf[129], expected_cn[65], expected_ou[65], cert_cn[128], cert_ou[128];
        size_t token_len = 0;
        uint8_t device_id[32], device_pub[32], client_nonce[32], server_nonce[32], transcript_hash[32];
        uint8_t A[32], s[32], ack = 0x01;
        uint8_t *device_cert_buf = NULL, *device_sig = NULL;
        uint32_t device_cert_len = 0, device_sig_len = 0;
        X509 *device_cert = NULL;
        EVP_PKEY *device_cert_pubkey = NULL;
        int upsert = -1;

        memset(token_buf, 0, sizeof token_buf);
        if (recv_pairing_token(cfd, token_buf, &token_len, &recv_bytes) != 0) goto cleanup;

        if (allows_ztp_setup(policy, token_len > 0 ? token_buf : NULL, token_len) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: pairing rejected by policy\n");
            goto cleanup;
        }

        if (recv_all(cfd, device_id, 32, &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, device_pub, 32, &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, client_nonce, 32, &recv_bytes) != 0) goto cleanup;
        device_cert_buf = recv_blob(cfd, &device_cert_len, MAX_CERT_FILE_SIZE, &recv_bytes);
        if (!device_cert_buf) {
            fprintf(stderr, "Server[SETUP/ZTP]: failed to receive device certificate");
            goto cleanup;
        }
        if (check_point(device_pub, "device_pub") != 0) goto cleanup;

        device_cert = load_cert_from_bytes(device_cert_buf, device_cert_len);
        if (!device_cert || verify_cert_against_ca(device_cert, ca_cert) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: device certificate verification failed");
            goto cleanup;
        }

        bin2hex_lower(device_id, 32, expected_cn, sizeof expected_cn);
        bin2hex_lower(device_pub, 32, expected_ou, sizeof expected_ou);
        if (cert_subject_field_hex(device_cert, NID_commonName, cert_cn, sizeof cert_cn) != 0 ||
            strcmp(cert_cn, expected_cn) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: device certificate CN mismatch");
            goto cleanup;
        }
        if (cert_subject_field_hex(device_cert, NID_organizationalUnitName, cert_ou, sizeof cert_ou) != 0 ||
            strcmp(cert_ou, expected_ou) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: device certificate OU mismatch");
            goto cleanup;
        }

        {
            uint8_t existing_pub[32];
            pthread_mutex_lock(&g_reg_mutex);
            int existing = reg_lookup(*reg, *reg_n, device_id, existing_pub);
            int is_new = (existing != 0);
            if (!is_new && sodium_memcmp(existing_pub, device_pub, 32) != 0) {
                pthread_mutex_unlock(&g_reg_mutex);
                fprintf(stderr, "Server[SETUP/ZTP]: device_id collision");
                goto cleanup;
            }
            pthread_mutex_unlock(&g_reg_mutex);
            (void)is_new;
        }

        randombytes_buf(server_nonce, 32);
        ztp_cert_transcript_hash(transcript_hash, device_id, device_pub, client_nonce, server_nonce,
                                 device_cert_buf, device_cert_len, server_cert_buf, (uint32_t)server_cert_len);
        {
            uint8_t *server_sig = NULL;
            size_t server_sig_len = 0;
            if (sign_transcript_hash(server_cert_key, transcript_hash, &server_sig, &server_sig_len) != 0) {
                fprintf(stderr, "Server[SETUP/ZTP]: failed to sign setup transcript");
                goto cleanup;
            }
            if (send_all(cfd, server_nonce, 32, &sent) != 0) { free(server_sig); goto cleanup; }
            if (send_blob(cfd, server_cert_buf, (uint32_t)server_cert_len, &sent) != 0) { free(server_sig); goto cleanup; }
            if (send_blob(cfd, server_sig, (uint32_t)server_sig_len, &sent) != 0) { free(server_sig); goto cleanup; }
            sodium_memzero(server_sig, server_sig_len);
            free(server_sig);
        }

        if (recv_all(cfd, A, 32, &recv_bytes) != 0) goto cleanup;
        if (recv_all(cfd, s, 32, &recv_bytes) != 0) goto cleanup;
        device_sig = recv_blob(cfd, &device_sig_len, MAX_SIG_SIZE, &recv_bytes);
        if (!device_sig) goto cleanup;

        if (check_point(A, "setup_A") != 0) goto cleanup;
        if (schnorr_verify_setup(device_id, device_pub, server_nonce, A, s) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: Schnorr proof invalid");
            goto cleanup;
        }

        device_cert_pubkey = X509_get_pubkey(device_cert);
        if (!device_cert_pubkey || verify_transcript_hash_sig(device_cert_pubkey, transcript_hash, device_sig, device_sig_len) != 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: device transcript signature invalid");
            goto cleanup;
        }

        pthread_mutex_lock(&g_reg_mutex);
        upsert = reg_upsert(reg, reg_n, device_id, device_pub);
        pthread_mutex_unlock(&g_reg_mutex);
        if (upsert < 0) {
            fprintf(stderr, "Server[SETUP/ZTP]: registry update failed\n");
            goto cleanup;
        }

        {
            char hex_id[65];
            sodium_bin2hex(hex_id, sizeof hex_id, device_id, 32);
            if (upsert == 1)
                printf("Server[SETUP/ZTP]: enrolled NEW device_id=%s via mutual certificate onboarding\n", hex_id);
            else
                printf("Server[SETUP/ZTP]: validated existing device_id=%s via mutual certificate onboarding\n", hex_id);
        }

        if (send_all(cfd, &ack, 1, &sent) != 0) goto cleanup;
        if (device_cert_pubkey) { EVP_PKEY_free(device_cert_pubkey); device_cert_pubkey = NULL; }
        if (device_cert) { X509_free(device_cert); device_cert = NULL; }
        if (device_sig) { sodium_memzero(device_sig, device_sig_len); free(device_sig); device_sig = NULL; }
        free(device_cert_buf); device_cert_buf = NULL;

    } else if (msg_type == MSG_AUTH_V2) {

        uint8_t client_pk[32];
        if (recv_all(cfd, client_pk, 32, &recv_bytes) != 0) goto cleanup;

        uint8_t srv_eph_sk[crypto_kx_SECRETKEYBYTES];
        uint8_t srv_eph_pk[crypto_kx_PUBLICKEYBYTES];
        crypto_kx_keypair(srv_eph_pk, srv_eph_sk);

        if (send_all(cfd, srv_eph_pk, 32, &sent) != 0) goto cleanup;

        uint8_t x25519_shared[32];
        if (crypto_scalarmult(x25519_shared, srv_eph_sk, client_pk) != 0) {
            fprintf(stderr, "Server[AUTH]: invalid client X25519 key\n");
            goto cleanup;
        }

        uint8_t hash[64];
        crypto_generichash_state bst;
        crypto_generichash_init(&bst, NULL, 0, 64);
        crypto_generichash_update(&bst, x25519_shared, 32);
        crypto_generichash_update(&bst, client_pk, 32);
        crypto_generichash_update(&bst, srv_eph_pk, 32);
        crypto_generichash_final(&bst, hash, 64);

        uint8_t rx_key[32], tx_key[32];
        memcpy(rx_key, hash + 32, 32);
        memcpy(tx_key, hash, 32);

        nonce_ctr_t nonce_rx = NONCE_CTR_INIT;
        nonce_ctr_t nonce_tx = NONCE_CTR_INIT;

        uint32_t rx_len;
        uint8_t *rx_ct = recv_encrypted_blob(cfd, &rx_len, &recv_bytes);
        if (!rx_ct) goto cleanup;

        uint8_t pt1[160];
        unsigned long long pt1_len;
        uint8_t nonce_rx_buf[12];
        nonce_next(&nonce_rx, nonce_rx_buf);

        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt1, &pt1_len, NULL, rx_ct, rx_len,
                                                      NULL, 0, nonce_rx_buf, rx_key) != 0) {
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

        if (check_point(A_c,   "A_c")   != 0) goto cleanup;
        if (check_point(eph_c, "eph_c") != 0) goto cleanup;

        pthread_mutex_lock(&g_reg_mutex);
        int replay_ok = check_and_insert_replay(device_id, nonce_c);
        pthread_mutex_unlock(&g_reg_mutex);
        if (replay_ok != 0) {
            fprintf(stderr, "Server[AUTH]: replay detected\n");
            goto cleanup;
        }

        uint8_t expected_pub[32];
        pthread_mutex_lock(&g_reg_mutex);
        int lookup_ok = reg_lookup(*reg, *reg_n, device_id, expected_pub);
        pthread_mutex_unlock(&g_reg_mutex);
        if (lookup_ok != 0) {
            fprintf(stderr, "Server[AUTH]: unknown device_id\n");
            goto cleanup;
        }

        if (schnorr_verify_auth(device_id, expected_pub, A_c, s_c, nonce_c, eph_c) != 0) {
            fprintf(stderr, "Server[AUTH]: client Schnorr proof invalid\n");
            goto cleanup;
        }

        uint8_t nonce_s[32];
        randombytes_buf(nonce_s, 32);

        uint8_t eph_s_secret[32], eph_s[32];
        crypto_core_ristretto255_scalar_random(eph_s_secret);
        crypto_scalarmult_ristretto255_base(eph_s, eph_s_secret);

        uint8_t A_s[32], s_s[32];
        schnorr_prove_server(A_s, s_s, server_sk, server_pub, nonce_s, eph_s);

        uint8_t session_key[32];
        if (derive_session_key(session_key, eph_s_secret, eph_c, nonce_c, nonce_s, device_id,
                               eph_c, eph_s, x25519_shared) != 0) {
            fprintf(stderr, "Server[AUTH]: session key derivation failed\n");
            goto cleanup;
        }

        uint8_t th[32];
        kc_transcript_hash(th, device_id, A_c, s_c, nonce_c, eph_c, server_pub, A_s, s_s, nonce_s, eph_s);

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
        nonce_next(&nonce_tx, nonce_tx_buf);

        uint8_t ct2[192 + crypto_aead_chacha20poly1305_IETF_ABYTES];
        unsigned long long ct2_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(ct2, &ct2_len, payload2, sizeof payload2,
                                                  NULL, 0, NULL, nonce_tx_buf, tx_key);

        if (send_u32_le(cfd, (uint32_t)ct2_len, &sent) != 0) goto cleanup;
        if (send_all(cfd, ct2, (size_t)ct2_len, &sent)  != 0) goto cleanup;

        uint32_t rx_len2;
        uint8_t *rx_ct2 = recv_encrypted_blob(cfd, &rx_len2, &recv_bytes);
        if (!rx_ct2) goto cleanup;

        uint8_t pt3[32];
        unsigned long long pt3_len;
        uint8_t nonce_rx_buf2[12];
        nonce_next(&nonce_rx, nonce_rx_buf2);

        if (crypto_aead_chacha20poly1305_ietf_decrypt(pt3, &pt3_len, NULL, rx_ct2, rx_len2,
                                                      NULL, 0, nonce_rx_buf2, rx_key) != 0) {
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
        if (sodium_memcmp(expected_tag_c, pt3, 32) != 0) {
            fprintf(stderr, "Server[AUTH]: key confirmation failed (tag_c mismatch)\n");
            goto cleanup;
        }

        /* FIX: session key removed from log — it must never appear in stdout/logs.
           Only the device_id (public identifier) is logged. */
        char hex_id[65];
        sodium_bin2hex(hex_id, sizeof hex_id, device_id, 32);
        printf("Server[AUTH]: device_id=%s KC=OK\n", hex_id);

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

// Loads the server static secret key or creates one if missing.
static int load_or_create_server_sk(uint8_t server_sk[32]) {
    if (file_exists(SERVER_SK_FILE)) {
        return read_file_32(SERVER_SK_FILE, server_sk);
    }
    crypto_core_ristretto255_scalar_random(server_sk);
    return write_file_32(SERVER_SK_FILE, server_sk);
}

/* FIX: per-connection thread argument bundle */
typedef struct {
    int              cfd;
    char             peer[64];
    reg_entry_t    **reg;
    size_t          *reg_n;
    uint8_t          server_sk[32];
    uint8_t          server_pub[32];
    pairing_policy_t policy;
    uint8_t         *server_cert_buf;   /* shared read-only */
    size_t           server_cert_len;
    EVP_PKEY        *server_cert_key;   /* shared read-only */
    X509            *server_cert;       /* shared read-only */
    X509            *ca_cert;           /* shared read-only */
} client_thread_args_t;

/* FIX: thread entry point — runs handle_client then frees the args bundle */
static void *client_thread_func(void *arg) {
    client_thread_args_t *a = (client_thread_args_t *)arg;
    handle_client(a->cfd, a->peer, a->reg, a->reg_n,
                  a->server_sk, a->server_pub, &a->policy,
                  a->server_cert_buf, a->server_cert_len,
                  a->server_cert_key, a->server_cert, a->ca_cert);
    sodium_memzero(a->server_sk, sizeof a->server_sk);
    free(a);
    return NULL;
}

// Parses command-line arguments and dispatches the requested program action.
int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;

    const char *bind_str = "0.0.0.0:4000";
    pairing_policy_t policy;
    memset(&policy, 0, sizeof policy);

    int print_pubkey = 0;

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
        } else if (!strcmp(argv[i], "--print-pubkey")) {
            print_pubkey = 1;
        } else {
            fprintf(stderr,
                    "Usage: %s [--bind 0.0.0.0:4000] [--pairing] "
                    "[--pairing-token TOKEN] [--pairing-seconds N] [--print-pubkey]\n", argv[0]);
            return 1;
        }
    }

    uint8_t server_sk[32];
    if (load_or_create_server_sk(server_sk) != 0) {
        fprintf(stderr, "failed reading/writing %s\n", SERVER_SK_FILE);
        return 1;
    }

    uint8_t server_pub[32];
    crypto_scalarmult_ristretto255_base(server_pub, server_sk);
    if (crypto_core_ristretto255_is_valid_point(server_pub) != 1) {
        fprintf(stderr, "server_pub is invalid — corrupt server_sk?\n");
        return 1;
    }

    if (print_pubkey) {
        char hex_pub[65];
        sodium_bin2hex(hex_pub, sizeof hex_pub, server_pub, 32);
        printf("%s\n", hex_pub);
        sodium_memzero(server_sk, sizeof server_sk);
        return 0;
    }

    size_t server_cert_len = 0, server_key_len = 0, ca_cert_len = 0;
    uint8_t *server_cert_buf = read_file_all(SERVER_CERT_FILE, &server_cert_len, MAX_CERT_FILE_SIZE);
    uint8_t *server_key_buf = read_file_all(SERVER_CERT_KEY_FILE, &server_key_len, MAX_CERT_FILE_SIZE);
    uint8_t *ca_cert_buf = read_file_all(CA_CERT_FILE, &ca_cert_len, MAX_CERT_FILE_SIZE);
    X509 *server_cert = NULL, *ca_cert = NULL;
    EVP_PKEY *server_cert_key = NULL;
    char expected_server_ou[65], cert_server_ou[128];

    if (!server_cert_buf || !server_key_buf || !ca_cert_buf) {
        fprintf(stderr, "Missing server_cert.pem, server_cert_key.pem, or ca_cert.pem\n");
        sodium_memzero(server_sk, sizeof server_sk);
        free(server_cert_buf); free(server_key_buf); free(ca_cert_buf);
        return 1;
    }
    server_cert = load_cert_from_bytes(server_cert_buf, server_cert_len);
    ca_cert = load_cert_from_bytes(ca_cert_buf, ca_cert_len);
    server_cert_key = load_private_key_from_bytes(server_key_buf, server_key_len);
    if (!server_cert || !ca_cert || !server_cert_key) {
        fprintf(stderr, "Failed to parse server certificate material\n");
        sodium_memzero(server_sk, sizeof server_sk);
        free(server_cert_buf); free(server_key_buf); free(ca_cert_buf);
        if (server_cert) X509_free(server_cert);
        if (ca_cert) X509_free(ca_cert);
        if (server_cert_key) EVP_PKEY_free(server_cert_key);
        return 1;
    }
    if (verify_cert_against_ca(server_cert, ca_cert) != 0) {
        fprintf(stderr, "Server certificate not issued by trusted CA\n");
        sodium_memzero(server_sk, sizeof server_sk);
        free(server_cert_buf); free(server_key_buf); free(ca_cert_buf);
        X509_free(server_cert); X509_free(ca_cert); EVP_PKEY_free(server_cert_key);
        return 1;
    }
    bin2hex_lower(server_pub, 32, expected_server_ou, sizeof expected_server_ou);
    if (cert_subject_field_hex(server_cert, NID_organizationalUnitName, cert_server_ou, sizeof cert_server_ou) != 0 || strcmp(cert_server_ou, expected_server_ou) != 0) {
        fprintf(stderr, "Server certificate OU does not match server_pub\n");
        sodium_memzero(server_sk, sizeof server_sk);
        free(server_cert_buf); free(server_key_buf); free(ca_cert_buf);
        X509_free(server_cert); X509_free(ca_cert); EVP_PKEY_free(server_cert_key);
        return 1;
    }
    sodium_memzero(server_key_buf, server_key_len);
    free(server_key_buf);
    free(ca_cert_buf);

    if (replay_init() != 0) {
        fprintf(stderr, "Failed to initialise replay cache\n");
        free(server_cert_buf);
        X509_free(server_cert);
        X509_free(ca_cert);
        EVP_PKEY_free(server_cert_key);
        sodium_memzero(server_sk, sizeof server_sk);
        return 1;
    }

    char ip[64];
    uint16_t port;
    if (parse_bind(bind_str, ip, &port) != 0) {
        fprintf(stderr, "bad --bind value\n");
        free(server_cert_buf);
        X509_free(server_cert);
        X509_free(ca_cert);
        EVP_PKEY_free(server_cert_key);
        sodium_memzero(server_sk, sizeof server_sk);
        return 1;
    }

    reg_entry_t *reg = NULL;
    size_t reg_n = 0;
    if (load_registry(&reg, &reg_n) != 0) {
        fprintf(stderr, "Failed to load registry\n");
        free(server_cert_buf);
        X509_free(server_cert);
        X509_free(ca_cert);
        EVP_PKEY_free(server_cert_key);
        sodium_memzero(server_sk, sizeof server_sk);
        return 1;
    }

    int lfd = listen_tcp(ip, port);
    if (lfd < 0) {
        fprintf(stderr, "listen failed\n");
        free(reg);
        free(server_cert_buf);
        X509_free(server_cert);
        X509_free(ca_cert);
        EVP_PKEY_free(server_cert_key);
        sodium_memzero(server_sk, sizeof server_sk);
        return 1;
    }

    char hex_pub[65];
    sodium_bin2hex(hex_pub, sizeof hex_pub, server_pub, 32);

    printf("C Server listening on %s\n", bind_str);
    printf("Server public key (pin this on client): %s\n", hex_pub);
    printf("Server: pairing_enabled=%s token_configured=%s deadline=%s mutual_cert_onboarding=true\n",
           policy.enabled          ? "true" : "false",
           policy.token_configured ? "true" : "false",
           policy.deadline_sec > 0.0 ? "set" : "none");

    for (;;) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof peer_addr;
        int cfd = accept(lfd, (struct sockaddr *)&peer_addr, &peer_len);
        if (cfd < 0) continue;

        /* FIX: apply recv timeout immediately so slow/stalled clients cannot
           block a thread indefinitely (slow-loris style). */
        struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof peer_ip);

        char peer_str[64];
        snprintf(peer_str, sizeof peer_str, "%s:%d", peer_ip, ntohs(peer_addr.sin_port));

        /* FIX: spawn a detached thread per connection so one slow or stalled
           client cannot block all subsequent connections. */
        client_thread_args_t *args = malloc(sizeof *args);
        if (!args) { close(cfd); continue; }

        args->cfd            = cfd;
        args->reg            = &reg;
        args->reg_n          = &reg_n;
        args->server_cert_buf  = server_cert_buf;
        args->server_cert_len  = server_cert_len;
        args->server_cert_key  = server_cert_key;
        args->server_cert      = server_cert;
        args->ca_cert          = ca_cert;
        args->policy           = policy;
        memcpy(args->peer,       peer_str,  sizeof args->peer);
        memcpy(args->server_sk,  server_sk, 32);
        memcpy(args->server_pub, server_pub, 32);

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, client_thread_func, args) != 0) {
            sodium_memzero(args->server_sk, sizeof args->server_sk);
            free(args);
            close(cfd);
        }
        pthread_attr_destroy(&attr);
    }
}
