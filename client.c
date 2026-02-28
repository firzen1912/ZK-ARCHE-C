// ==============================
// c_client.c  (DESIGN A: TOFU pin server pubkey + KEY CONFIRMATION MACs)
// ==============================
//
// Wire protocol (1-byte msg_type):
//   MSG_SETUP = 0x01
//     C->S: 0x01 | token_len(u8)=0 | device_id(32) | device_static_pub(32)
//     S->C: server_static_pub(32) | server_nonce(32)
//     C->S: A(32) | s(32)
//           Schnorr PoP over transcript("setup_schnorr_v1"):
//             device_id, pubkey(device_pub), A, server_nonce
//
//   MSG_AUTH  = 0x02
//     C->S: 0x02 | device_id(32) | A_c(32) | s_c(32) | nonce_c(32) | eph_c(32)
//     S->C: server_static_pub(32) | A_s(32) | s_s(32) | nonce_s(32) | eph_s(32) | tag_s(32)
//     C->S: tag_c(32)
//
// Client files:
//   device_id.bin   (32 bytes)
//   device_x.bin    (32 bytes scalar)
//   server_pub.bin  (32 bytes)  <-- pinned server identity (TOFU)
//
// Transcript encoding (C-compatible, no Merlin):
//   domain_len(u8)||domain
//   for each field: label_len(u8)||label||value_len(u32 LE)||value
//
// Schnorr challenge scalar:
//   c = scalar_reduce(SHA512(transcript))
//
// Key confirmation:
//   th = SHA256( transcript("kc_v1", ... all handshake fields ...) )
//   (k_s2c, k_c2s) = HKDF-Expand(salt=th, ikm=session_key, info="kc s2c"/"kc c2s")
//   tag_s = HMAC(k_s2c, "server finished" || th)
//   tag_c = HMAC(k_c2s, "client finished" || th)
//
// Build:
//   gcc -O2 -std=c11 -Wall -Wextra client.c -o c_client -lsodium
//
#define _POSIX_C_SOURCE 200112L
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

// -----------------------------
// Protocol constants
// -----------------------------
#define MSG_SETUP 0x01
#define MSG_AUTH  0x02

#define DEVICE_ID_FILE  "device_id.bin"
#define DEVICE_X_FILE   "device_x.bin"
#define SERVER_PUB_FILE "server_pub.bin"

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

    // Defensive: ensure transcript does not overflow fixed buffer
    if (tr->len + 1 + llen + 4 + (size_t)vlen > sizeof(tr->buf)) {
        fprintf(stderr, "transcript overflow\n");
        exit(1);
    }

    tr->buf[tr->len++] = (uint8_t)llen;
    memcpy(tr->buf + tr->len, label, llen);
    tr->len += llen;

    // u32 little-endian length
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

// Server verify (Design A): bind pubkey + A + nonce_s + eph_s
//
// IMPORTANT:
// crypto_scalarmult_ristretto255() can fail if server_pub is not a valid
// Ristretto point. Always check return value.
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

    // left = s*G
    crypto_scalarmult_ristretto255_base(left, s);

    // cX = c * server_pub  (must succeed)
    if (crypto_scalarmult_ristretto255(cX, c, server_pub) != 0) {
        return -1;
    }

    // right = A + cX
    crypto_core_ristretto255_add(right, A, cX);

    return sodium_memcmp(left, right, 32) == 0 ? 0 : -1;
}

// -----------------------------
// HKDF-SHA256 (RFC5869) using HMAC-SHA256
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

// -----------------------------
// Session key derivation (returns error if eph_s invalid)
//
// shared = eph_secret * eph_s
// salt   = nonce_c || nonce_s
// info   = "session key" || device_id || eph_c || eph_s
// -----------------------------
static int derive_session_key(uint8_t key[32],
                              const uint8_t eph_secret[32],
                              const uint8_t eph_s[32],
                              const uint8_t nonce_c[32],
                              const uint8_t nonce_s[32],
                              const uint8_t device_id[32],
                              const uint8_t eph_c[32]) {
    uint8_t shared[32];

    // IMPORTANT: eph_s comes from network; reject invalid points.
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
// Setup + Auth flows
// -----------------------------
static int do_setup(const char *server, const uint8_t device_id[32], const uint8_t x[32]) {
    int fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return -1; }

    uint8_t device_pub[32];
    crypto_scalarmult_ristretto255_base(device_pub, x);

    // 1) Send SETUP header
    uint8_t msg = MSG_SETUP;
    uint8_t toklen = 0;
    if (send_all(fd, &msg, 1) != 0) { close(fd); return -1; }
    if (send_all(fd, &toklen, 1) != 0) { close(fd); return -1; }

    // 2) Send device_id + device_pub
    if (send_all(fd, device_id, 32) != 0) { close(fd); return -1; }
    if (send_all(fd, device_pub, 32) != 0) { close(fd); return -1; }

    // 3) Receive server_static_pub + server_nonce
    uint8_t server_pub[32];
    uint8_t server_nonce[32];
    if (recv_all(fd, server_pub, 32) != 0) { close(fd); return -1; }
    if (recv_all(fd, server_nonce, 32) != 0) { close(fd); return -1; }

    // 4) TOFU pin server pubkey
    if (!file_exists(SERVER_PUB_FILE)) {
        if (write_file_32(SERVER_PUB_FILE, server_pub) != 0) {
            fprintf(stderr, "failed to write %s\n", SERVER_PUB_FILE);
            close(fd);
            return -1;
        }
        printf("C Client[SETUP]: pinned server_pub -> %s\n", SERVER_PUB_FILE);
    } else {
        uint8_t pinned[32];
        if (read_file_32(SERVER_PUB_FILE, pinned) != 0) {
            fprintf(stderr, "failed to read %s\n", SERVER_PUB_FILE);
            close(fd);
            return -1;
        }
        if (sodium_memcmp(pinned, server_pub, 32) != 0) {
            fprintf(stderr, "server pubkey mismatch vs pinned (refuse setup)\n");
            close(fd);
            return -1;
        }
        printf("C Client[SETUP]: server_pub matches pinned\n");
    }

    // 5) Send Schnorr PoP for device key
    uint8_t A[32], s[32];
    schnorr_prove_setup(A, s, x, device_id, device_pub, server_nonce);
    if (send_all(fd, A, 32) != 0) { close(fd); return -1; }
    if (send_all(fd, s, 32) != 0) { close(fd); return -1; }

    close(fd);
    printf("C Client[SETUP]: OK\n");
    return 0;
}

static int do_auth(const char *server, const uint8_t device_id[32], const uint8_t x[32]) {
    // Must have pinned server identity for Design A
    uint8_t pinned_server_pub[32];
    if (read_file_32(SERVER_PUB_FILE, pinned_server_pub) != 0) {
        fprintf(stderr, "Missing %s; run with --setup first\n", SERVER_PUB_FILE);
        return -1;
    }

    int fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return -1; }

    uint8_t device_pub[32];
    crypto_scalarmult_ristretto255_base(device_pub, x);

    // Client nonce
    uint8_t nonce_c[32];
    randombytes_buf(nonce_c, 32);

    // Client ephemeral ECDH key
    uint8_t eph_secret[32], eph_c[32];
    crypto_core_ristretto255_scalar_random(eph_secret);
    crypto_scalarmult_ristretto255_base(eph_c, eph_secret);

    // Client Schnorr proof (A_c, s_c)
    uint8_t A_c[32], s_c[32];
    schnorr_prove_auth(A_c, s_c, x, device_id, device_pub, nonce_c, eph_c);

    // Send AUTH request
    uint8_t msg = MSG_AUTH;
    if (send_all(fd, &msg, 1) != 0) { close(fd); return -1; }
    if (send_all(fd, device_id, 32) != 0) { close(fd); return -1; }
    if (send_all(fd, A_c, 32) != 0) { close(fd); return -1; }
    if (send_all(fd, s_c, 32) != 0) { close(fd); return -1; }
    if (send_all(fd, nonce_c, 32) != 0) { close(fd); return -1; }
    if (send_all(fd, eph_c, 32) != 0) { close(fd); return -1; }

    // Receive server response
    uint8_t server_pub[32], A_s[32], s_s[32], nonce_s[32], eph_s[32], tag_s[32];
    if (recv_all(fd, server_pub, 32) != 0) { close(fd); return -1; }

    // Enforce TOFU-pinned server identity
    if (sodium_memcmp(server_pub, pinned_server_pub, 32) != 0) {
        fprintf(stderr, "server pubkey mismatch vs pinned (refuse auth)\n");
        close(fd);
        return -1;
    }

    if (recv_all(fd, A_s, 32) != 0) { close(fd); return -1; }
    if (recv_all(fd, s_s, 32) != 0) { close(fd); return -1; }
    if (recv_all(fd, nonce_s, 32) != 0) { close(fd); return -1; }
    if (recv_all(fd, eph_s, 32) != 0) { close(fd); return -1; }
    if (recv_all(fd, tag_s, 32) != 0) { close(fd); return -1; }

    // Verify server Schnorr proof
    if (schnorr_verify_server(server_pub, A_s, s_s, nonce_s, eph_s) != 0) {
        fprintf(stderr, "C Client[AUTH]: server proof invalid\n");
        close(fd);
        return -1;
    }

    // Derive session key (reject invalid eph_s points)
    uint8_t session_key[32];
    if (derive_session_key(session_key, eph_secret, eph_s, nonce_c, nonce_s, device_id, eph_c) != 0) {
        fprintf(stderr, "C Client[AUTH]: invalid eph_s point\n");
        close(fd);
        return -1;
    }

    // -------- Key Confirmation --------
    uint8_t th[32];
    kc_transcript_hash(th, device_id, A_c, s_c, nonce_c, eph_c, server_pub, A_s, s_s, nonce_s, eph_s);

    uint8_t k_s2c[32], k_c2s[32];
    derive_kc_keys(k_s2c, k_c2s, session_key, th);

    // Verify tag_s
    uint8_t expected_s[32];
    hmac_tag(expected_s, k_s2c, "server finished", th);
    if (sodium_memcmp(expected_s, tag_s, 32) != 0) {
        fprintf(stderr, "C Client[AUTH]: server key confirmation failed\n");
        close(fd);
        return -1;
    }

    // Send tag_c
    uint8_t tag_c[32];
    hmac_tag(tag_c, k_c2s, "client finished", th);
    if (send_all(fd, tag_c, 32) != 0) { close(fd); return -1; }

    printf("C Client[AUTH]: OK, session key = ");
    for (int i = 0; i < 32; i++) printf("%02x", session_key[i]);
    printf("\n");

    sodium_memzero(eph_secret, 32);
    sodium_memzero(session_key, 32);
    sodium_memzero(k_s2c, 32);
    sodium_memzero(k_c2s, 32);

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

    // Create or load device identity
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