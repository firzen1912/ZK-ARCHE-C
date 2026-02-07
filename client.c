#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

// -----------------------------
// Protocol constants
// -----------------------------
#define MSG_SETUP 0x01
#define MSG_AUTH  0x02

#define DEVICE_ID_FILE "device_id.bin"
#define DEVICE_X_FILE  "device_x.bin"

// Demo constant server identity binding (same as Rust)
static const uint8_t SERVER_ID[32] = { 0x53 };

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
// TCP helpers
// -----------------------------
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

// -----------------------------
// Transcript (Merlin replacement)
// domain_len(u8)||domain|| label_len(u8)||label|| value_len(u32le)||value ...
// c = scalar_reduce(SHA512(transcript_bytes))
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
// Schnorr proofs (setup + auth + server verify)
// Using Ristretto group and libsodium scalars.
// Verify: s*G == A + c*X
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
    tr_init(&tr, "setup_schnorr");
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
    tr_init(&tr, "client_schnorr");
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
                                 const uint8_t server_id[32],
                                 const uint8_t nonce_s[32],
                                 const uint8_t eph_s[32]) {
    uint8_t c[32], left[32], cX[32], right[32];

    transcript_t tr;
    tr_init(&tr, "server_schnorr");
    tr_append(&tr, "server_id", server_id, 32);
    tr_append(&tr, "pubkey", server_pub, 32);
    tr_append(&tr, "a", A, 32);
    tr_append(&tr, "nonce_s", nonce_s, 32);
    tr_append(&tr, "eph_s", eph_s, 32);

    tr_challenge_scalar(c, &tr);

    crypto_scalarmult_ristretto255_base(left, s);
    crypto_scalarmult_ristretto255(cX, c, server_pub);
    crypto_core_ristretto255_add(right, A, cX);

    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

// -----------------------------
// HKDF-SHA256 (RFC5869) using HMAC-SHA256
// salt = nonce_c||nonce_s
// info = "session key" || device_id || eph_c || eph_s
// ikm = shared = eph_secret * eph_s
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
                               const uint8_t eph_secret[32],
                               const uint8_t eph_s[32],
                               const uint8_t nonce_c[32],
                               const uint8_t nonce_s[32],
                               const uint8_t device_id[32],
                               const uint8_t eph_c[32]) {
    uint8_t shared[32];
    crypto_scalarmult_ristretto255(shared, eph_secret, eph_s);

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
// Setup + Auth flows
// -----------------------------
static int do_setup(const char *server, const uint8_t device_id[32], const uint8_t x[32]) {
    int fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return -1; }

    uint8_t pubkey[32];
    crypto_scalarmult_ristretto255_base(pubkey, x);

    // MSG_SETUP
    uint8_t msg = MSG_SETUP;
    if (send_all(fd, &msg, 1) != 0) return -1;

    // token_len = 0
    uint8_t tok = 0;
    if (send_all(fd, &tok, 1) != 0) return -1;

    if (send_all(fd, device_id, 32) != 0) return -1;
    if (send_all(fd, pubkey, 32) != 0) return -1;

    uint8_t server_nonce[32];
    if (recv_all(fd, server_nonce, 32) != 0) return -1;

    uint8_t A[32], s[32];
    schnorr_prove_setup(A, s, x, device_id, pubkey, server_nonce);

    if (send_all(fd, A, 32) != 0) return -1;
    if (send_all(fd, s, 32) != 0) return -1;

    close(fd);
    printf("C Client[SETUP]: OK\n");
    return 0;
}

static int do_auth(const char *server, const uint8_t device_id[32], const uint8_t x[32]) {
    int fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return -1; }

    uint8_t pubkey[32];
    crypto_scalarmult_ristretto255_base(pubkey, x);

    uint8_t nonce_c[32];
    randombytes_buf(nonce_c, 32);

    uint8_t eph_secret[32], eph_c[32];
    crypto_core_ristretto255_scalar_random(eph_secret);
    crypto_scalarmult_ristretto255_base(eph_c, eph_secret);

    // client proof (A,s)
    uint8_t A[32], s[32];
    schnorr_prove_auth(A, s, x, device_id, pubkey, nonce_c, eph_c);

    // send MSG_AUTH
    uint8_t msg = MSG_AUTH;
    if (send_all(fd, &msg, 1) != 0) return -1;
    if (send_all(fd, device_id, 32) != 0) return -1;
    if (send_all(fd, A, 32) != 0) return -1;
    if (send_all(fd, s, 32) != 0) return -1;
    if (send_all(fd, nonce_c, 32) != 0) return -1;
    if (send_all(fd, eph_c, 32) != 0) return -1;

    // recv server response
    uint8_t server_pub[32], A_s[32], s_s[32], nonce_s[32], eph_s[32];
    if (recv_all(fd, server_pub, 32) != 0) return -1;
    if (recv_all(fd, A_s, 32) != 0) return -1;
    if (recv_all(fd, s_s, 32) != 0) return -1;
    if (recv_all(fd, nonce_s, 32) != 0) return -1;
    if (recv_all(fd, eph_s, 32) != 0) return -1;

    // verify server proof
    if (schnorr_verify_server(server_pub, A_s, s_s, SERVER_ID, nonce_s, eph_s) != 0) {
        fprintf(stderr, "C Client[AUTH]: server proof invalid\n");
        close(fd);
        return -1;
    }

    uint8_t key[32];
    derive_session_key(key, eph_secret, eph_s, nonce_c, nonce_s, device_id, eph_c);

    printf("C Client[AUTH]: OK, session key = ");
    for (int i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\n");

    sodium_memzero(eph_secret, 32);
    sodium_memzero(key, 32);
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
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    uint8_t device_id[32], x[32];

    if (!file_exists(DEVICE_ID_FILE) || !file_exists(DEVICE_X_FILE)) {
        if (!setup) {
            fprintf(stderr, "Missing device creds; run with --setup\n");
            return 0;
        }
        randombytes_buf(device_id, 32);
        crypto_core_ristretto255_scalar_random(x);
        if (write_file_32(DEVICE_ID_FILE, device_id) != 0 ||
            write_file_32(DEVICE_X_FILE, x) != 0) {
            fprintf(stderr, "Failed writing device creds\n");
            return 1;
        }
    } else {
        if (read_file_32(DEVICE_ID_FILE, device_id) != 0 ||
            read_file_32(DEVICE_X_FILE, x) != 0) {
            fprintf(stderr, "Failed reading device creds\n");
            return 1;
        }
    }

    int rc = setup ? do_setup(server, device_id, x) : do_auth(server, device_id, x);
    sodium_memzero(x, 32);
    return (rc == 0) ? 0 : 1;
}
