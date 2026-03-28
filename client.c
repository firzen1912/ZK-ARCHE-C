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
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MSG_SETUP    0x01
#define MSG_AUTH_V2  0x03
#define MSG_HEARTBEAT 0x10
#define MSG_HEARTBEAT_ACK 0x11
#define MSG_GOODBYE 0x15

#define STATE_DIR              "/var/lib/iot-auth"
#define CLIENT_STATE_DIR       "/var/lib/iot-auth/client"
#define DEVICE_ROOT_FILE       "/var/lib/iot-auth/client/device_root.bin"
#define SERVER_PUB_FILE        "/var/lib/iot-auth/client/server_pub.bin"
#define DEVICE_CERT_FILE       "/var/lib/iot-auth/client/device_cert.pem"
#define DEVICE_KEY_FILE        "/var/lib/iot-auth/client/device_key.pem"
#define CA_CERT_FILE           "/var/lib/iot-auth/client/ca_cert.pem"
#define OFFLINE_COUNTER_FILE   "/var/lib/iot-auth/client/offline_counter.bin"
#define CLIENT_CONT_FILE       "/var/lib/iot-auth/client/continuity.bin"
#define SERVER_CONT_TRACK_FILE "/var/lib/iot-auth/client/server_continuity_track.bin"
#define MAX_ENCRYPTED_PAYLOAD  4096
#define MAX_CERT_FILE_SIZE     (128 * 1024)
#define MAX_SIG_SIZE           8192
#define MAX_OFFLINE_FIELD      256

#define T_OFFLINE      "offline_schnorr_v1"
#define T_CLIENT_CONT  "client_continuity_v1"
#define T_SERVER_CONT  "server_continuity_v1"

typedef struct { uint64_t count; } nonce_ctr_t;
#define NONCE_CTR_INIT { 0 }

typedef struct {
    int fd;
    uint8_t session_key[32];
    uint8_t rx_key[32];
    uint8_t tx_key[32];
    nonce_ctr_t tx_nonce;
    nonce_ctr_t rx_nonce;
    time_t established_at;
    time_t last_rx;
    time_t last_tx;
} auth_session_t;

typedef struct {
    uint8_t  version;
    uint8_t  device_id[32];
    uint8_t  device_pub[32];
    uint64_t issued_at;
    uint64_t expires_at;
    uint64_t counter;
    uint16_t audience_len;
    uint8_t  audience[MAX_OFFLINE_FIELD];
    uint16_t scope_len;
    uint8_t  scope[MAX_OFFLINE_FIELD];
    uint8_t  request_hash[32];
    uint8_t  A[32];
    uint8_t  s[32];
} offline_proof_t;

typedef struct {
    uint8_t  version;
    uint8_t  role; /* 1 = client, 2 = server */
    uint8_t  identity[32];
    uint8_t  pubkey[32];
    uint64_t continuity_counter;
    uint64_t reconnect_epoch;
    uint8_t  last_peer_id[32];
    uint8_t  last_checkpoint_hash[32];
    uint8_t  state_hash[32];
} continuity_state_t;

typedef struct {
    uint8_t  version;
    uint8_t  role;
    uint8_t  identity[32];
    uint8_t  pubkey[32];
    uint8_t  peer_id[32];
    uint64_t issued_at;
    uint64_t expires_at;
    uint64_t continuity_counter;
    uint64_t reconnect_epoch;
    uint8_t  prev_checkpoint_hash[32];
    uint8_t  state_hash[32];
    uint8_t  checkpoint_hash[32];
    uint8_t  A[32];
    uint8_t  s[32];
} continuity_proof_t;

#define CONT_STATE_LEN 178u
#define CONT_PROOF_LEN 290u

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

// Checks whether the given file path exists.
static int file_exists(const char *path) { return access(path, F_OK) == 0; }

// Creates the client state directory tree if it does not already exist.
static int ensure_state_dir(void) {
    struct stat st;

    if (stat(STATE_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
    } else if (mkdir(STATE_DIR, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    if (stat(CLIENT_STATE_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
    } else if (mkdir(CLIENT_STATE_DIR, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    if (chmod(STATE_DIR, 0700) != 0) return -1;
    if (chmod(CLIENT_STATE_DIR, 0700) != 0) return -1;
    return 0;
}

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
    if (ensure_state_dir() != 0) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = fwrite(in, 1, 32, f);
    fclose(f);
    if (n != 32) return -1;
    return (chmod(path, 0600) == 0) ? 0 : -1;
}

// Loads the device root secret from disk or creates a new one when missing.
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

// Derives the stable device identifier from the device root secret.
static void derive_device_id(const uint8_t root[32], uint8_t device_id[32]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const unsigned char *)"device-id", 9);
    crypto_generichash_update(&st, root, 32);
    crypto_generichash_final(&st, device_id, 32);
}

// Derives the device authentication scalar from the device root secret.
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

// Builds the device identifier and private scalar from the stored root secret.
static int load_device_creds_from_root(uint8_t device_id[32], uint8_t x[32], int *created_root) {
    uint8_t root[32];
    if (load_or_create_device_root(root, created_root) != 0) return -1;
    derive_device_id(root, device_id);
    derive_device_scalar(root, x);
    sodium_memzero(root, sizeof root);
    return 0;
}

// Prints the device identifier and derived public key as lowercase hex.
static int print_device_identity(void) {
    uint8_t device_id[32], x[32], device_pub[32];
    int created_root = 0;
    char id_hex[65], pub_hex[65];

    if (load_device_creds_from_root(device_id, x, &created_root) != 0) {
        fprintf(stderr, "Failed loading/creating device root\n");
        return -1;
    }

    crypto_scalarmult_ristretto255_base(device_pub, x);

    /* FIX: sodium_bin2hex already emits lowercase; the manual A-F loop was dead code */
    sodium_bin2hex(id_hex, sizeof id_hex, device_id, 32);
    sodium_bin2hex(pub_hex, sizeof pub_hex, device_pub, 32);

    printf("%s %s\n", id_hex, pub_hex);

    sodium_memzero(x, sizeof x);
    sodium_memzero(device_id, sizeof device_id);
    sodium_memzero(device_pub, sizeof device_pub);
    return 0;
}

// Returns whether the client device root already exists on disk.
static int creds_exist(void) { return file_exists(DEVICE_ROOT_FILE); }

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

static int send_all(int fd, const uint8_t *buf, size_t len, size_t *sent_tracker);
static int recv_all(int fd, uint8_t *buf, size_t len, size_t *recv_tracker);
static int send_u32_le(int fd, uint32_t val, size_t *sent_tracker);
static int recv_u32_le(int fd, uint32_t *val, size_t *recv_tracker);

static void tr_append_u64(transcript_t *tr, const char *label, uint64_t v) {
    uint8_t le[8];
    le[0] = (uint8_t)(v);
    le[1] = (uint8_t)(v >> 8);
    le[2] = (uint8_t)(v >> 16);
    le[3] = (uint8_t)(v >> 24);
    le[4] = (uint8_t)(v >> 32);
    le[5] = (uint8_t)(v >> 40);
    le[6] = (uint8_t)(v >> 48);
    le[7] = (uint8_t)(v >> 56);
    tr_append(tr, label, le, 8);
}

static void tr_append_u8(transcript_t *tr, const char *label, uint8_t v) {
    tr_append(tr, label, &v, 1);
}

static uint64_t unix_time_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
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

static int read_file_u64(const char *path, uint64_t *out) {
    uint8_t buf[8];
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fread(buf, 1, 8, f) != 8) { fclose(f); return -1; }
    fclose(f);
    *out = le64_load(buf);
    return 0;
}

static int write_file_u64(const char *path, uint64_t v) {
    uint8_t buf[8];
    FILE *f;
    le64_store(buf, v);
    if (ensure_state_dir() != 0) return -1;
    f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, 8, f) != 8) { fclose(f); return -1; }
    fclose(f);
    return chmod(path, 0600);
}

static void sha256_file_hash(uint8_t out[32], const char *path) {
    size_t len = 0;
    uint8_t *buf = read_file_all(path, &len, 1u << 20);
    if (!buf) {
        memset(out, 0, 32);
        return;
    }
    crypto_hash_sha256(out, buf, (unsigned long long)len);
    free(buf);
}

static int parse_hash32_hex(const char *hex, uint8_t out[32]) {
    size_t n = 0;
    return (sodium_hex2bin(out, 32, hex, strlen(hex), NULL, &n, NULL) == 0 && n == 32) ? 0 : -1;
}

static void server_peer_id_from_pinned_pub(const uint8_t server_pub[32], uint8_t out[32]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const unsigned char *)"server-id-v1", 12);
    crypto_generichash_update(&st, server_pub, 32);
    crypto_generichash_final(&st, out, 32);
}

static void hash_client_cont_state(const uint8_t identity[32], const uint8_t pubkey[32],
                                   const uint8_t pinned_server_pub[32],
                                   uint64_t counter, uint64_t epoch,
                                   uint8_t out[32]) {
    uint8_t le[8];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const unsigned char *)"client-state-v1", 15);
    crypto_generichash_update(&st, identity, 32);
    crypto_generichash_update(&st, pubkey, 32);
    crypto_generichash_update(&st, pinned_server_pub, 32);
    le64_store(le, counter); crypto_generichash_update(&st, le, 8);
    le64_store(le, epoch);   crypto_generichash_update(&st, le, 8);
    crypto_generichash_final(&st, out, 32);
}

static void next_checkpoint_hash(const uint8_t prev[32], const uint8_t state_hash[32],
                                 uint64_t counter, uint64_t epoch, const uint8_t peer_id[32],
                                 uint8_t out[32]) {
    uint8_t le[8];
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const unsigned char *)"continuity-checkpoint-v1", 24);
    crypto_generichash_update(&st, prev, 32);
    crypto_generichash_update(&st, state_hash, 32);
    le64_store(le, counter); crypto_generichash_update(&st, le, 8);
    le64_store(le, epoch);   crypto_generichash_update(&st, le, 8);
    crypto_generichash_update(&st, peer_id, 32);
    crypto_generichash_final(&st, out, 32);
}

static int continuity_state_serialize(const continuity_state_t *st, uint8_t out[CONT_STATE_LEN]) {
    size_t off = 0;
    out[off++] = st->version;
    out[off++] = st->role;
    memcpy(out + off, st->identity, 32); off += 32;
    memcpy(out + off, st->pubkey, 32); off += 32;
    le64_store(out + off, st->continuity_counter); off += 8;
    le64_store(out + off, st->reconnect_epoch); off += 8;
    memcpy(out + off, st->last_peer_id, 32); off += 32;
    memcpy(out + off, st->last_checkpoint_hash, 32); off += 32;
    memcpy(out + off, st->state_hash, 32); off += 32;
    return off == CONT_STATE_LEN ? 0 : -1;
}

static int continuity_state_deserialize(continuity_state_t *st, const uint8_t *buf, size_t len) {
    size_t off = 0;
    if (len != CONT_STATE_LEN) return -1;
    memset(st, 0, sizeof *st);
    st->version = buf[off++];
    st->role = buf[off++];
    memcpy(st->identity, buf + off, 32); off += 32;
    memcpy(st->pubkey, buf + off, 32); off += 32;
    st->continuity_counter = le64_load(buf + off); off += 8;
    st->reconnect_epoch = le64_load(buf + off); off += 8;
    memcpy(st->last_peer_id, buf + off, 32); off += 32;
    memcpy(st->last_checkpoint_hash, buf + off, 32); off += 32;
    memcpy(st->state_hash, buf + off, 32); off += 32;
    return off == CONT_STATE_LEN ? 0 : -1;
}

static int continuity_proof_serialize(const continuity_proof_t *p, uint8_t out[CONT_PROOF_LEN]) {
    size_t off = 0;
    out[off++] = p->version;
    out[off++] = p->role;
    memcpy(out + off, p->identity, 32); off += 32;
    memcpy(out + off, p->pubkey, 32); off += 32;
    memcpy(out + off, p->peer_id, 32); off += 32;
    le64_store(out + off, p->issued_at); off += 8;
    le64_store(out + off, p->expires_at); off += 8;
    le64_store(out + off, p->continuity_counter); off += 8;
    le64_store(out + off, p->reconnect_epoch); off += 8;
    memcpy(out + off, p->prev_checkpoint_hash, 32); off += 32;
    memcpy(out + off, p->state_hash, 32); off += 32;
    memcpy(out + off, p->checkpoint_hash, 32); off += 32;
    memcpy(out + off, p->A, 32); off += 32;
    memcpy(out + off, p->s, 32); off += 32;
    return off == CONT_PROOF_LEN ? 0 : -1;
}

static int continuity_proof_deserialize(continuity_proof_t *p, const uint8_t *buf, size_t len) {
    size_t off = 0;
    if (len != CONT_PROOF_LEN) return -1;
    memset(p, 0, sizeof *p);
    p->version = buf[off++];
    p->role = buf[off++];
    memcpy(p->identity, buf + off, 32); off += 32;
    memcpy(p->pubkey, buf + off, 32); off += 32;
    memcpy(p->peer_id, buf + off, 32); off += 32;
    p->issued_at = le64_load(buf + off); off += 8;
    p->expires_at = le64_load(buf + off); off += 8;
    p->continuity_counter = le64_load(buf + off); off += 8;
    p->reconnect_epoch = le64_load(buf + off); off += 8;
    memcpy(p->prev_checkpoint_hash, buf + off, 32); off += 32;
    memcpy(p->state_hash, buf + off, 32); off += 32;
    memcpy(p->checkpoint_hash, buf + off, 32); off += 32;
    memcpy(p->A, buf + off, 32); off += 32;
    memcpy(p->s, buf + off, 32); off += 32;
    return off == CONT_PROOF_LEN ? 0 : -1;
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
    /* FIX: sodium_bin2hex already emits lowercase; the secondary uppercase loop was dead code */
    sodium_bin2hex(out, out_len, in, in_len);
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

// Returns the current monotonic time in seconds.
static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// Connects to the target host:port string over TCP.
static int tcp_connect(const char *hostport) {
    char host[256] = {0};
    char port[32]  = {0};
    const char *colon = strchr(hostport, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - hostport);
    if (hl >= sizeof(host)) return -1;
    memcpy(host, hostport, hl);
    strncpy(port, colon + 1, sizeof(port) - 1);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
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
        fprintf(stderr, "payload too large: %u bytes (max %d)\n", rx_len, MAX_ENCRYPTED_PAYLOAD);
        return NULL;
    }
    /* FIX: malloc(0) is implementation-defined; use at least 1 byte */
    uint8_t *buf = malloc(rx_len == 0 ? 1 : rx_len);
    if (!buf) return NULL;
    if (rx_len && recv_all(fd, buf, rx_len, recv_tracker) != 0) { free(buf); return NULL; }
    *out_len = rx_len;
    return buf;
}

static void offline_challenge_scalar(uint8_t c[32], const uint8_t device_id[32],
                                     const uint8_t device_pub[32], const uint8_t *aud, uint16_t aud_len,
                                     const uint8_t *scope, uint16_t scope_len,
                                     uint64_t issued_at, uint64_t expires_at, uint64_t counter,
                                     const uint8_t request_hash[32], const uint8_t A[32]) {
    transcript_t tr;
    tr_init(&tr, T_OFFLINE);
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey", device_pub, 32);
    tr_append(&tr, "audience", aud, aud_len);
    tr_append(&tr, "scope", scope, scope_len);
    tr_append_u64(&tr, "issued_at", issued_at);
    tr_append_u64(&tr, "expires_at", expires_at);
    tr_append_u64(&tr, "counter", counter);
    tr_append(&tr, "request_hash", request_hash, 32);
    tr_append(&tr, "a", A, 32);
    tr_challenge_scalar(c, &tr);
}

static void continuity_challenge_scalar(uint8_t c[32], const char *domain, uint8_t role,
                                        const uint8_t identity[32], const uint8_t pubkey[32],
                                        const uint8_t peer_id[32], uint64_t issued_at, uint64_t expires_at,
                                        uint64_t continuity_counter, uint64_t reconnect_epoch,
                                        const uint8_t prev_checkpoint_hash[32],
                                        const uint8_t state_hash[32],
                                        const uint8_t checkpoint_hash[32],
                                        const uint8_t A[32]) {
    transcript_t tr;
    tr_init(&tr, domain);
    tr_append_u8(&tr, "role", role);
    tr_append(&tr, "identity", identity, 32);
    tr_append(&tr, "pubkey", pubkey, 32);
    tr_append(&tr, "peer_id", peer_id, 32);
    tr_append_u64(&tr, "issued_at", issued_at);
    tr_append_u64(&tr, "expires_at", expires_at);
    tr_append_u64(&tr, "continuity_counter", continuity_counter);
    tr_append_u64(&tr, "reconnect_epoch", reconnect_epoch);
    tr_append(&tr, "prev_checkpoint_hash", prev_checkpoint_hash, 32);
    tr_append(&tr, "state_hash", state_hash, 32);
    tr_append(&tr, "checkpoint_hash", checkpoint_hash, 32);
    tr_append(&tr, "a", A, 32);
    tr_challenge_scalar(c, &tr);
}

static int load_or_init_client_continuity_state(continuity_state_t *st,
                                                const uint8_t device_id[32],
                                                const uint8_t device_pub[32],
                                                const uint8_t pinned_server_pub[32]) {
    uint8_t buf[CONT_STATE_LEN];
    uint8_t peer_id[32];
    server_peer_id_from_pinned_pub(pinned_server_pub, peer_id);
    if (file_exists(CLIENT_CONT_FILE)) {
        if (read_exact_file(CLIENT_CONT_FILE, buf, sizeof buf) != 0) return -1;
        if (continuity_state_deserialize(st, buf, sizeof buf) != 0) return -1;
        if (sodium_memcmp(st->identity, device_id, 32) != 0 ||
            sodium_memcmp(st->pubkey, device_pub, 32) != 0) return -1;
        return 0;
    }
    memset(st, 0, sizeof *st);
    st->version = 1;
    st->role = 1;
    memcpy(st->identity, device_id, 32);
    memcpy(st->pubkey, device_pub, 32);
    memcpy(st->last_peer_id, peer_id, 32);
    hash_client_cont_state(device_id, device_pub, pinned_server_pub, 0, 0, st->state_hash);
    continuity_state_serialize(st, buf);
    return write_exact_file(CLIENT_CONT_FILE, buf, sizeof buf, 0600);
}

static int save_client_continuity_state(const continuity_state_t *st) {
    uint8_t buf[CONT_STATE_LEN];
    if (continuity_state_serialize(st, buf) != 0) return -1;
    return write_exact_file(CLIENT_CONT_FILE, buf, sizeof buf, 0600);
}

static int load_server_track(continuity_state_t *st) {
    uint8_t buf[CONT_STATE_LEN];
    if (!file_exists(SERVER_CONT_TRACK_FILE)) return -1;
    if (read_exact_file(SERVER_CONT_TRACK_FILE, buf, sizeof buf) != 0) return -1;
    return continuity_state_deserialize(st, buf, sizeof buf);
}

static int save_server_track(const continuity_state_t *st) {
    uint8_t buf[CONT_STATE_LEN];
    if (continuity_state_serialize(st, buf) != 0) return -1;
    return write_exact_file(SERVER_CONT_TRACK_FILE, buf, sizeof buf, 0600);
}

static int load_and_increment_offline_counter(uint64_t *out_counter) {
    uint64_t cur = 0;
    if (file_exists(OFFLINE_COUNTER_FILE) && read_file_u64(OFFLINE_COUNTER_FILE, &cur) != 0) return -1;
    cur++;
    if (write_file_u64(OFFLINE_COUNTER_FILE, cur) != 0) return -1;
    *out_counter = cur;
    return 0;
}

static int build_offline_proof(offline_proof_t *p, const uint8_t device_id[32], const uint8_t x[32],
                               const char *audience, const char *scope, uint64_t expires_in,
                               const uint8_t request_hash[32]) {
    uint8_t r[32], c[32], cx[32];
    if (!audience || !scope) return -1;
    if (strlen(audience) == 0 || strlen(audience) > MAX_OFFLINE_FIELD) return -1;
    if (strlen(scope) == 0 || strlen(scope) > MAX_OFFLINE_FIELD) return -1;
    if (expires_in == 0 || expires_in > 300) return -1;

    memset(p, 0, sizeof *p);
    p->version = 1;
    memcpy(p->device_id, device_id, 32);
    crypto_scalarmult_ristretto255_base(p->device_pub, x);
    p->issued_at = unix_time_now();
    p->expires_at = p->issued_at + expires_in;
    if (load_and_increment_offline_counter(&p->counter) != 0) return -1;
    p->audience_len = (uint16_t)strlen(audience);
    memcpy(p->audience, audience, p->audience_len);
    p->scope_len = (uint16_t)strlen(scope);
    memcpy(p->scope, scope, p->scope_len);
    memcpy(p->request_hash, request_hash, 32);

    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(p->A, r);
    offline_challenge_scalar(c, p->device_id, p->device_pub, p->audience, p->audience_len,
                             p->scope, p->scope_len, p->issued_at, p->expires_at,
                             p->counter, p->request_hash, p->A);
    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(p->s, r, cx);
    sodium_memzero(r, sizeof r);
    sodium_memzero(c, sizeof c);
    sodium_memzero(cx, sizeof cx);
    return 0;
}

static int offline_proof_serialize(const offline_proof_t *p, uint8_t **out, size_t *out_len) {
    size_t len = 1 + 32 + 32 + 8 + 8 + 8 + 2 + p->audience_len + 2 + p->scope_len + 32 + 32 + 32;
    uint8_t *buf = malloc(len ? len : 1);
    size_t off = 0;
    if (!buf) return -1;
    buf[off++] = p->version;
    memcpy(buf + off, p->device_id, 32); off += 32;
    memcpy(buf + off, p->device_pub, 32); off += 32;
    le64_store(buf + off, p->issued_at); off += 8;
    le64_store(buf + off, p->expires_at); off += 8;
    le64_store(buf + off, p->counter); off += 8;
    buf[off++] = (uint8_t)p->audience_len; buf[off++] = (uint8_t)(p->audience_len >> 8);
    memcpy(buf + off, p->audience, p->audience_len); off += p->audience_len;
    buf[off++] = (uint8_t)p->scope_len; buf[off++] = (uint8_t)(p->scope_len >> 8);
    memcpy(buf + off, p->scope, p->scope_len); off += p->scope_len;
    memcpy(buf + off, p->request_hash, 32); off += 32;
    memcpy(buf + off, p->A, 32); off += 32;
    memcpy(buf + off, p->s, 32); off += 32;
    *out = buf; *out_len = off;
    return 0;
}

static int build_client_continuity_proof(continuity_proof_t *proof, continuity_state_t *st,
                                         const uint8_t device_id[32], const uint8_t x[32],
                                         uint64_t expires_in) {
    uint8_t pinned_server_pub[32], c[32], r[32], cx[32], checkpoint[32];
    uint8_t device_pub[32];
    if (expires_in == 0 || expires_in > 300) return -1;
    if (read_file_32(SERVER_PUB_FILE, pinned_server_pub) != 0) return -1;
    crypto_scalarmult_ristretto255_base(device_pub, x);
    if (load_or_init_client_continuity_state(st, device_id, device_pub, pinned_server_pub) != 0) return -1;

    st->continuity_counter++;
    st->reconnect_epoch++;
    hash_client_cont_state(st->identity, st->pubkey, pinned_server_pub,
                           st->continuity_counter, st->reconnect_epoch, st->state_hash);
    next_checkpoint_hash(st->last_checkpoint_hash, st->state_hash,
                         st->continuity_counter, st->reconnect_epoch, st->last_peer_id, checkpoint);

    memset(proof, 0, sizeof *proof);
    proof->version = 1;
    proof->role = 1;
    memcpy(proof->identity, st->identity, 32);
    memcpy(proof->pubkey, st->pubkey, 32);
    memcpy(proof->peer_id, st->last_peer_id, 32);
    proof->issued_at = unix_time_now();
    proof->expires_at = proof->issued_at + expires_in;
    proof->continuity_counter = st->continuity_counter;
    proof->reconnect_epoch = st->reconnect_epoch;
    memcpy(proof->prev_checkpoint_hash, st->last_checkpoint_hash, 32);
    memcpy(proof->state_hash, st->state_hash, 32);
    memcpy(proof->checkpoint_hash, checkpoint, 32);

    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(proof->A, r);
    continuity_challenge_scalar(c, T_CLIENT_CONT, proof->role, proof->identity, proof->pubkey,
                                proof->peer_id, proof->issued_at, proof->expires_at,
                                proof->continuity_counter, proof->reconnect_epoch,
                                proof->prev_checkpoint_hash, proof->state_hash,
                                proof->checkpoint_hash, proof->A);
    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(proof->s, r, cx);
    memcpy(st->last_checkpoint_hash, checkpoint, 32);
    save_client_continuity_state(st);
    sodium_memzero(r, sizeof r);
    sodium_memzero(c, sizeof c);
    sodium_memzero(cx, sizeof cx);
    return 0;
}


static int prepare_client_continuity_proof(continuity_proof_t *proof, continuity_state_t *st,
                                           const uint8_t device_id[32], const uint8_t x[32],
                                           uint64_t expires_in) {
    uint8_t pinned_server_pub[32], c[32], r[32], cx[32], checkpoint[32];
    uint8_t device_pub[32];
    if (expires_in == 0 || expires_in > 300) return -1;
    if (read_file_32(SERVER_PUB_FILE, pinned_server_pub) != 0) return -1;
    crypto_scalarmult_ristretto255_base(device_pub, x);
    if (load_or_init_client_continuity_state(st, device_id, device_pub, pinned_server_pub) != 0) return -1;

    st->continuity_counter++;
    st->reconnect_epoch++;
    hash_client_cont_state(st->identity, st->pubkey, pinned_server_pub,
                           st->continuity_counter, st->reconnect_epoch, st->state_hash);
    next_checkpoint_hash(st->last_checkpoint_hash, st->state_hash,
                         st->continuity_counter, st->reconnect_epoch, st->last_peer_id, checkpoint);

    memset(proof, 0, sizeof *proof);
    proof->version = 1;
    proof->role = 1;
    memcpy(proof->identity, st->identity, 32);
    memcpy(proof->pubkey, st->pubkey, 32);
    memcpy(proof->peer_id, st->last_peer_id, 32);
    proof->issued_at = unix_time_now();
    proof->expires_at = proof->issued_at + expires_in;
    proof->continuity_counter = st->continuity_counter;
    proof->reconnect_epoch = st->reconnect_epoch;
    memcpy(proof->prev_checkpoint_hash, st->last_checkpoint_hash, 32);
    memcpy(proof->state_hash, st->state_hash, 32);
    memcpy(proof->checkpoint_hash, checkpoint, 32);

    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(proof->A, r);
    continuity_challenge_scalar(c, T_CLIENT_CONT, proof->role, proof->identity, proof->pubkey,
                                proof->peer_id, proof->issued_at, proof->expires_at,
                                proof->continuity_counter, proof->reconnect_epoch,
                                proof->prev_checkpoint_hash, proof->state_hash,
                                proof->checkpoint_hash, proof->A);
    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(proof->s, r, cx);
    memcpy(st->last_checkpoint_hash, checkpoint, 32);
    sodium_memzero(r, sizeof r);
    sodium_memzero(c, sizeof c);
    sodium_memzero(cx, sizeof cx);
    return 0;
}

static int verify_server_continuity_proof_blob(const uint8_t *buf, size_t len, continuity_state_t *track_out) {
    continuity_proof_t proof;
    continuity_state_t track;
    uint8_t pinned_server_pub[32], expected_identity[32], device_id[32], x[32];
    uint8_t expected_checkpoint[32], c[32], left[32], cX[32], right[32];
    int created = 0;
    if (len != CONT_PROOF_LEN) return -1;
    if (read_file_32(SERVER_PUB_FILE, pinned_server_pub) != 0) return -1;
    server_peer_id_from_pinned_pub(pinned_server_pub, expected_identity);
    if (continuity_proof_deserialize(&proof, buf, len) != 0) return -1;
    if (proof.role != 2) return -1;
    if (sodium_memcmp(proof.identity, expected_identity, 32) != 0) return -1;
    if (sodium_memcmp(proof.pubkey, pinned_server_pub, 32) != 0) return -1;
    if (load_device_creds_from_root(device_id, x, &created) != 0) return -1;
    sodium_memzero(x, sizeof x);
    if (sodium_memcmp(proof.peer_id, device_id, 32) != 0) return -1;
    if (proof.issued_at >= proof.expires_at) return -1;
    if (unix_time_now() < proof.issued_at || unix_time_now() > proof.expires_at) return -1;
    if (load_server_track(&track) != 0) {
        memset(&track, 0, sizeof track);
        track.version = 1;
        track.role = 2;
        memcpy(track.identity, expected_identity, 32);
        memcpy(track.pubkey, pinned_server_pub, 32);
        memcpy(track.last_peer_id, device_id, 32);
    }
    if (proof.continuity_counter <= track.continuity_counter) return -1;
    if (sodium_memcmp(proof.prev_checkpoint_hash, track.last_checkpoint_hash, 32) != 0) return -1;
    next_checkpoint_hash(proof.prev_checkpoint_hash, proof.state_hash, proof.continuity_counter,
                         proof.reconnect_epoch, proof.peer_id, expected_checkpoint);
    if (sodium_memcmp(expected_checkpoint, proof.checkpoint_hash, 32) != 0) return -1;
    continuity_challenge_scalar(c, T_SERVER_CONT, proof.role, proof.identity, proof.pubkey, proof.peer_id,
                                proof.issued_at, proof.expires_at, proof.continuity_counter,
                                proof.reconnect_epoch, proof.prev_checkpoint_hash, proof.state_hash,
                                proof.checkpoint_hash, proof.A);
    crypto_scalarmult_ristretto255_base(left, proof.s);
    if (crypto_scalarmult_ristretto255(cX, c, proof.pubkey) != 0) return -1;
    crypto_core_ristretto255_add(right, proof.A, cX);
    if (sodium_memcmp(left, right, 32) != 0) return -1;
    track.continuity_counter = proof.continuity_counter;
    track.reconnect_epoch = proof.reconnect_epoch;
    memcpy(track.last_checkpoint_hash, proof.checkpoint_hash, 32);
    memcpy(track.state_hash, proof.state_hash, 32);
    if (track_out) *track_out = track;
    return 0;
}

static int verify_server_continuity_proof_from_file(const char *path) {
    continuity_proof_t proof;
    continuity_state_t track;
    uint8_t buf[CONT_PROOF_LEN], pinned_server_pub[32], expected_identity[32], device_id[32], x[32];
    uint8_t expected_checkpoint[32], c[32], left[32], cX[32], right[32];
    int created = 0;
    if (read_file_32(SERVER_PUB_FILE, pinned_server_pub) != 0) return -1;
    server_peer_id_from_pinned_pub(pinned_server_pub, expected_identity);
    if (read_exact_file(path, buf, sizeof buf) != 0) return -1;
    if (continuity_proof_deserialize(&proof, buf, sizeof buf) != 0) return -1;
    if (proof.role != 2) return -1;
    if (sodium_memcmp(proof.identity, expected_identity, 32) != 0) {
        fprintf(stderr, "server continuity identity mismatch\n");
        return -1;
    }
    if (sodium_memcmp(proof.pubkey, pinned_server_pub, 32) != 0) {
        fprintf(stderr, "server continuity pubkey mismatch\n");
        return -1;
    }
    if (load_device_creds_from_root(device_id, x, &created) != 0) return -1;
    sodium_memzero(x, sizeof x);
    if (sodium_memcmp(proof.peer_id, device_id, 32) != 0) {
        fprintf(stderr, "server continuity peer binding mismatch\n");
        return -1;
    }
    if (proof.issued_at >= proof.expires_at) return -1;
    if (unix_time_now() < proof.issued_at || unix_time_now() > proof.expires_at) return -1;
    if (load_server_track(&track) != 0) {
        memset(&track, 0, sizeof track);
        track.version = 1;
        track.role = 2;
        memcpy(track.identity, expected_identity, 32);
        memcpy(track.pubkey, pinned_server_pub, 32);
        memcpy(track.last_peer_id, device_id, 32);
    }
    if (proof.continuity_counter <= track.continuity_counter) return -1;
    if (sodium_memcmp(proof.prev_checkpoint_hash, track.last_checkpoint_hash, 32) != 0) return -1;
    next_checkpoint_hash(proof.prev_checkpoint_hash, proof.state_hash, proof.continuity_counter,
                         proof.reconnect_epoch, proof.peer_id, expected_checkpoint);
    if (sodium_memcmp(expected_checkpoint, proof.checkpoint_hash, 32) != 0) return -1;
    continuity_challenge_scalar(c, T_SERVER_CONT, proof.role, proof.identity, proof.pubkey, proof.peer_id,
                                proof.issued_at, proof.expires_at, proof.continuity_counter,
                                proof.reconnect_epoch, proof.prev_checkpoint_hash, proof.state_hash,
                                proof.checkpoint_hash, proof.A);
    crypto_scalarmult_ristretto255_base(left, proof.s);
    if (crypto_scalarmult_ristretto255(cX, c, proof.pubkey) != 0) return -1;
    crypto_core_ristretto255_add(right, proof.A, cX);
    if (sodium_memcmp(left, right, 32) != 0) return -1;
    track.continuity_counter = proof.continuity_counter;
    track.reconnect_epoch = proof.reconnect_epoch;
    memcpy(track.last_checkpoint_hash, proof.checkpoint_hash, 32);
    memcpy(track.state_hash, proof.state_hash, 32);
    if (save_server_track(&track) != 0) return -1;
    printf("Client[CONTINUITY]: verified returning server continuity proof file=%s counter=%llu reconnect_epoch=%llu\n",
           path, (unsigned long long)proof.continuity_counter, (unsigned long long)proof.reconnect_epoch);
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

// Builds the client Schnorr proof used during the setup flow.
static void schnorr_prove_setup(uint8_t A[32], uint8_t s[32], const uint8_t x[32],
                                const uint8_t device_id[32], const uint8_t pubkey[32],
                                const uint8_t server_nonce[32]) {
    uint8_t r[32], c[32], cx[32];
    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);

    transcript_t tr;
    tr_init(&tr, "setup_schnorr_v1");
    tr_append(&tr, "device_id",    device_id, 32);
    tr_append(&tr, "pubkey",       pubkey,    32);
    tr_append(&tr, "a",            A,         32);
    tr_append(&tr, "server_nonce", server_nonce, 32);
    tr_challenge_scalar(c, &tr);

    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(s, r, cx);

    sodium_memzero(r, sizeof r);
    sodium_memzero(cx, sizeof cx);
    sodium_memzero(c, sizeof c);
}

// Builds the client Schnorr proof used during the authentication flow.
static void schnorr_prove_auth(uint8_t A[32], uint8_t s[32], const uint8_t x[32],
                               const uint8_t device_id[32], const uint8_t pubkey[32],
                               const uint8_t nonce_c[32], const uint8_t eph_c[32]) {
    uint8_t r[32], c[32], cx[32];
    crypto_core_ristretto255_scalar_random(r);
    crypto_scalarmult_ristretto255_base(A, r);

    transcript_t tr;
    tr_init(&tr, "client_schnorr_v1");
    tr_append(&tr, "device_id", device_id, 32);
    tr_append(&tr, "pubkey",    pubkey,    32);
    tr_append(&tr, "a",         A,         32);
    tr_append(&tr, "nonce_c",   nonce_c,   32);
    tr_append(&tr, "eph_c",     eph_c,     32);
    tr_challenge_scalar(c, &tr);

    crypto_core_ristretto255_scalar_mul(cx, c, x);
    crypto_core_ristretto255_scalar_add(s, r, cx);

    sodium_memzero(r, sizeof r);
    sodium_memzero(cx, sizeof cx);
    sodium_memzero(c, sizeof c);
}

// Verifies the server Schnorr proof during authentication.
static int schnorr_verify_server(const uint8_t server_pub[32], const uint8_t A[32],
                                 const uint8_t s[32], const uint8_t nonce_s[32],
                                 const uint8_t eph_s[32]) {
    uint8_t c[32], left[32], cX[32], right[32];

    transcript_t tr;
    tr_init(&tr, "server_schnorr_v1");
    tr_append(&tr, "pubkey",  server_pub, 32);
    tr_append(&tr, "a",       A,          32);
    tr_append(&tr, "nonce_s", nonce_s,    32);
    tr_append(&tr, "eph_s",   eph_s,      32);
    tr_challenge_scalar(c, &tr);

    crypto_scalarmult_ristretto255_base(left, s);
    if (crypto_scalarmult_ristretto255(cX, c, server_pub) != 0) return -1;
    crypto_core_ristretto255_add(right, A, cX);
    return (sodium_memcmp(left, right, 32) == 0) ? 0 : -1;
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
    size_t t_len = 0, out = 0;
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
        out += take;
        ctr++;
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
    memcpy(salt, nonce_c, 32);
    memcpy(salt + 32, nonce_s, 32);

    uint8_t info[11 + 32 + 32 + 32 + 32];
    size_t off = 0;
    memcpy(info + off, "session key", 11); off += 11;
    memcpy(info + off, device_id, 32); off += 32;
    memcpy(info + off, eph_c_pub, 32); off += 32;
    memcpy(info + off, eph_s_pub, 32); off += 32;
    memcpy(info + off, x25519_shared, 32); off += 32;

    uint8_t prk[32];
    hkdf_extract(prk, salt, sizeof salt, shared, sizeof shared);
    hkdf_expand(key, 32, prk, info, off);

    sodium_memzero(shared, sizeof shared);
    sodium_memzero(prk, sizeof prk);
    return 0;
}

// Hashes the key-confirmation transcript for both peers.
static void kc_transcript_hash(uint8_t th[32], const uint8_t device_id[32],
                               const uint8_t a_c[32], const uint8_t s_c[32],
                               const uint8_t nonce_c[32], const uint8_t eph_c[32],
                               const uint8_t server_pub[32], const uint8_t a_s[32],
                               const uint8_t s_s[32], const uint8_t nonce_s[32],
                               const uint8_t eph_s[32]) {
    transcript_t tr;
    tr_init(&tr, "kc_v1");
    tr_append(&tr, "device_id",  device_id,  32);
    tr_append(&tr, "a_c",        a_c,        32);
    tr_append(&tr, "s_c",        s_c,        32);
    tr_append(&tr, "nonce_c",    nonce_c,    32);
    tr_append(&tr, "eph_c",      eph_c,      32);
    tr_append(&tr, "server_pub", server_pub, 32);
    tr_append(&tr, "a_s",        a_s,        32);
    tr_append(&tr, "s_s",        s_s,        32);
    tr_append(&tr, "nonce_s",    nonce_s,    32);
    tr_append(&tr, "eph_s",      eph_s,      32);
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
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)label, (unsigned long long)strlen(label));
    crypto_auth_hmacsha256_update(&st, th, 32);
    crypto_auth_hmacsha256_final(&st, out);
}

// ============================================================
// SETUP — ZTP provisioning handshake
// ============================================================
static int do_setup(const char *server, const uint8_t device_id[32], const uint8_t x[32],
                    const char *pairing_token, int allow_tofu_setup) {
    double start_time = get_time_sec();
    size_t sent = 0, recv = 0;
    size_t device_cert_len = 0, device_key_len = 0, ca_cert_len = 0;
    uint8_t *device_cert_buf = NULL, *device_key_buf = NULL, *ca_cert_buf = NULL;
    X509 *device_cert = NULL, *ca_cert = NULL, *server_cert = NULL;
    EVP_PKEY *device_key = NULL, *server_pubkey = NULL;
    uint8_t server_nonce[32], device_pub[32], client_nonce[32], server_pub[32], transcript_hash[32];
    uint8_t A[32], s[32], ack = 0;
    uint8_t *server_cert_buf = NULL, *server_sig = NULL, *device_sig = NULL;
    uint32_t server_cert_len = 0, server_sig_len = 0;
    size_t device_sig_len = 0;
    int fd = -1;
    int rc = -1;
    int have_pinned = 0;
    uint8_t pinned_server_pub[32];
    char expected_cn[65], expected_ou[65], server_ou[128];

    device_cert_buf = read_file_all(DEVICE_CERT_FILE, &device_cert_len, MAX_CERT_FILE_SIZE);
    device_key_buf  = read_file_all(DEVICE_KEY_FILE, &device_key_len, MAX_CERT_FILE_SIZE);
    ca_cert_buf     = read_file_all(CA_CERT_FILE, &ca_cert_len, MAX_CERT_FILE_SIZE);
    if (!device_cert_buf || !device_key_buf || !ca_cert_buf) {
        fprintf(stderr, "Client[SETUP/ZTP]: missing device_cert.pem, device_key.pem, or ca_cert.pem\n");
        goto cleanup;
    }

    device_cert = load_cert_from_bytes(device_cert_buf, device_cert_len);
    ca_cert     = load_cert_from_bytes(ca_cert_buf, ca_cert_len);
    device_key  = load_private_key_from_bytes(device_key_buf, device_key_len);
    if (!device_cert || !ca_cert || !device_key) {
        fprintf(stderr, "Client[SETUP/ZTP]: failed to parse certificate material\n");
        goto cleanup;
    }
    if (verify_cert_against_ca(device_cert, ca_cert) != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: device certificate not issued by trusted CA\n");
        goto cleanup;
    }

    crypto_scalarmult_ristretto255_base(device_pub, x);
    bin2hex_lower(device_id, 32, expected_cn, sizeof expected_cn);
    bin2hex_lower(device_pub, 32, expected_ou, sizeof expected_ou);
    if (cert_subject_field_hex(device_cert, NID_commonName, server_ou, sizeof server_ou) != 0 ||
        sodium_memcmp(server_ou, expected_cn, strlen(expected_cn)) != 0 || server_ou[strlen(expected_cn)] != '\0') {
        fprintf(stderr, "Client[SETUP/ZTP]: device certificate CN does not match device_id\n");
        goto cleanup;
    }
    if (cert_subject_field_hex(device_cert, NID_organizationalUnitName, server_ou, sizeof server_ou) != 0 ||
        sodium_memcmp(server_ou, expected_ou, strlen(expected_ou)) != 0 || server_ou[strlen(expected_ou)] != '\0') {
        fprintf(stderr, "Client[SETUP/ZTP]: device certificate OU does not match device_pub\n");
        goto cleanup;
    }

    have_pinned = (read_file_32(SERVER_PUB_FILE, pinned_server_pub) == 0);
    if (!have_pinned && !allow_tofu_setup) {
        fprintf(stderr,
                "Client[SETUP/ZTP]: first-time setup requires an out-of-band pinned server key. "
                "Run --pin-server-pub <hex> first, or pass --allow-tofu-setup for lab use.\n");
        goto cleanup;
    }
    fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); goto cleanup; }
    printf("Client[SETUP/ZTP]: Connected to %s\n", server);

    randombytes_buf(client_nonce, 32);

    {
        uint8_t msg = MSG_SETUP;
        if (send_all(fd, &msg, 1, &sent) != 0) goto cleanup;
    }

    if (pairing_token && *pairing_token) {
        size_t tlen = strlen(pairing_token);
        if (tlen > 128) {
            fprintf(stderr, "pairing token too long (max 128)\n");
            goto cleanup;
        }
        {
            uint8_t tlen_byte = (uint8_t)tlen;
            if (send_all(fd, &tlen_byte, 1, &sent) != 0) goto cleanup;
        }
        if (send_all(fd, (const uint8_t *)pairing_token, tlen, &sent) != 0) goto cleanup;
    } else {
        uint8_t zero = 0;
        if (send_all(fd, &zero, 1, &sent) != 0) goto cleanup;
    }

    if (send_all(fd, device_id, 32, &sent) != 0) goto cleanup;
    if (send_all(fd, device_pub, 32, &sent) != 0) goto cleanup;
    if (send_all(fd, client_nonce, 32, &sent) != 0) goto cleanup;
    if (send_blob(fd, device_cert_buf, (uint32_t)device_cert_len, &sent) != 0) goto cleanup;

    if (recv_all(fd, server_nonce, 32, &recv) != 0) goto cleanup;
    server_cert_buf = recv_blob(fd, &server_cert_len, MAX_CERT_FILE_SIZE, &recv);
    server_sig      = recv_blob(fd, &server_sig_len, MAX_SIG_SIZE, &recv);
    if (!server_cert_buf || !server_sig) {
        fprintf(stderr, "Client[SETUP/ZTP]: failed receiving server certificate/signature\n");
        goto cleanup;
    }

    server_cert = load_cert_from_bytes(server_cert_buf, server_cert_len);
    if (!server_cert || verify_cert_against_ca(server_cert, ca_cert) != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: server certificate verification failed\n");
        goto cleanup;
    }

    if (cert_subject_field_hex(server_cert, NID_organizationalUnitName, server_ou, sizeof server_ou) != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: server certificate missing OU binding\n");
        goto cleanup;
    }
    if (sodium_hex2bin(server_pub, sizeof server_pub, server_ou, strlen(server_ou), NULL, NULL, NULL) != 0 ||
        check_point(server_pub, "server_pub(cert)") != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: server certificate OU is not a valid Ristretto pubkey hex\n");
        goto cleanup;
    }
    if (have_pinned && sodium_memcmp(pinned_server_pub, server_pub, 32) != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: server cert bound pubkey mismatches pinned server_pub.bin\n");
        goto cleanup;
    }

    ztp_cert_transcript_hash(transcript_hash, device_id, device_pub, client_nonce, server_nonce,
                             device_cert_buf, (uint32_t)device_cert_len, server_cert_buf, server_cert_len);
    server_pubkey = X509_get_pubkey(server_cert);
    if (!server_pubkey || verify_transcript_hash_sig(server_pubkey, transcript_hash, server_sig, server_sig_len) != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: server transcript signature invalid\n");
        goto cleanup;
    }

    schnorr_prove_setup(A, s, x, device_id, device_pub, server_nonce);
    if (sign_transcript_hash(device_key, transcript_hash, &device_sig, &device_sig_len) != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: failed to sign setup transcript\n");
        goto cleanup;
    }

    if (send_all(fd, A, 32, &sent) != 0) goto cleanup;
    if (send_all(fd, s, 32, &sent) != 0) goto cleanup;
    if (send_blob(fd, device_sig, (uint32_t)device_sig_len, &sent) != 0) goto cleanup;

    if (recv_all(fd, &ack, 1, &recv) != 0 || ack != 0x01) {
        fprintf(stderr, "Client[SETUP/ZTP]: enrollment failed (missing/invalid ack)\n");
        goto cleanup;
    }

    if (write_file_32(SERVER_PUB_FILE, server_pub) != 0) {
        fprintf(stderr, "Client[SETUP/ZTP]: failed to persist server_pub.bin for AUTH_V2\n");
        goto cleanup;
    }

    {
        char hex_pub[65];
        bin2hex_lower(server_pub, 32, hex_pub, sizeof hex_pub);
        printf("Client[SETUP/ZTP]: Server certificate verified. Saved server_pub for AUTH_V2: %s\n", hex_pub);
    }

    {
        double duration = get_time_sec() - start_time;
        printf("Client[SETUP/ZTP]: Sent=%zu bytes, Received=%zu bytes. Enrolled with mutual cert onboarding.\n", sent, recv);
        printf("CLIENT METRICS -> Duration: %.3fms\n", duration * 1000.0);
    }
    rc = 0;

cleanup:
    sodium_memzero(server_nonce, sizeof server_nonce);
    sodium_memzero(device_pub, sizeof device_pub);
    sodium_memzero(client_nonce, sizeof client_nonce);
    sodium_memzero(server_pub, sizeof server_pub);
    sodium_memzero(transcript_hash, sizeof transcript_hash);
    sodium_memzero(A, sizeof A);
    sodium_memzero(s, sizeof s);
    sodium_memzero(pinned_server_pub, sizeof pinned_server_pub);
    if (fd >= 0) close(fd);
    if (device_sig) { sodium_memzero(device_sig, device_sig_len); free(device_sig); }
    if (device_key_buf) { sodium_memzero(device_key_buf, device_key_len); free(device_key_buf); }
    if (server_pubkey) EVP_PKEY_free(server_pubkey);
    if (device_key) EVP_PKEY_free(device_key);
    if (device_cert) X509_free(device_cert);
    if (ca_cert) X509_free(ca_cert);
    if (server_cert) X509_free(server_cert);
    free(device_cert_buf);
    free(ca_cert_buf);
    free(server_cert_buf);
    free(server_sig);
    return rc;
}

static int send_encrypted_record(int fd, const uint8_t *tx_key, nonce_ctr_t *tx_nonce,
                                 const uint8_t *pt, size_t pt_len, size_t *sent_tracker) {
    uint8_t nonce_buf[12];
    uint8_t ct[MAX_ENCRYPTED_PAYLOAD + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ct_len = 0;
    if (pt_len > MAX_ENCRYPTED_PAYLOAD) return -1;
    nonce_next(tx_nonce, nonce_buf);
    if (crypto_aead_chacha20poly1305_ietf_encrypt(ct, &ct_len, pt, (unsigned long long)pt_len,
                                                  NULL, 0, NULL, nonce_buf, tx_key) != 0) return -1;
    if (send_u32_le(fd, (uint32_t)ct_len, sent_tracker) != 0) return -1;
    return send_all(fd, ct, (size_t)ct_len, sent_tracker);
}

static int recv_encrypted_record(int fd, const uint8_t *rx_key, nonce_ctr_t *rx_nonce,
                                 uint8_t *pt, size_t pt_cap, size_t *pt_len, size_t *recv_tracker) {
    uint32_t rx_len = 0;
    uint8_t *rx_ct = recv_encrypted_blob(fd, &rx_len, recv_tracker);
    uint8_t nonce_buf[12];
    unsigned long long out_len = 0;
    if (!rx_ct) return -1;
    nonce_next(rx_nonce, nonce_buf);
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &out_len, NULL, rx_ct, rx_len,
                                                  NULL, 0, nonce_buf, rx_key) != 0) {
        free(rx_ct);
        return -1;
    }
    free(rx_ct);
    if (out_len > pt_cap) return -1;
    *pt_len = (size_t)out_len;
    return 0;
}

static int do_auth_v2_open_session(const char *server, const uint8_t device_id[32], const uint8_t x[32],
                                   auth_session_t *sess, size_t *sent_out, size_t *recv_out) {
    double start_time = get_time_sec();
    size_t sent = 0, recv = 0;

    if (!sess) return -1;
    memset(sess, 0, sizeof(*sess));
    sess->fd = -1;

    uint8_t pinned_server_pub[32];
    if (read_file_32(SERVER_PUB_FILE, pinned_server_pub) != 0) {
        fprintf(stderr, "Missing %s; run --setup first to enroll and pin the server key.\n", SERVER_PUB_FILE);
        return -1;
    }

    int fd = tcp_connect(server);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return -1; }
    printf("Client[AUTH]: Connected to %s\n", server);

    uint8_t client_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    uint8_t msg = MSG_AUTH_V2;
    if (send_all(fd, &msg, 1, &sent) != 0) { close(fd); return -1; }
    if (send_all(fd, client_pk, 32, &sent) != 0) { close(fd); return -1; }

    uint8_t server_pk[32];
    if (recv_all(fd, server_pk, 32, &recv) != 0) { close(fd); return -1; }

    uint8_t x25519_shared[32];
    if (crypto_scalarmult(x25519_shared, client_sk, server_pk) != 0) {
        fprintf(stderr, "Client[AUTH]: invalid server X25519 key\n");
        close(fd); return -1;
    }

    uint8_t hash[64];
    crypto_generichash_state bst;
    crypto_generichash_init(&bst, NULL, 0, 64);
    crypto_generichash_update(&bst, x25519_shared, 32);
    crypto_generichash_update(&bst, client_pk, 32);
    crypto_generichash_update(&bst, server_pk, 32);
    crypto_generichash_final(&bst, hash, 64);

    uint8_t rx_key[32], tx_key[32];
    continuity_proof_t client_cont_proof;
    continuity_state_t pending_client_state;
    continuity_state_t verified_server_track;
    uint8_t cont_wire[CONT_PROOF_LEN];
    memcpy(rx_key, hash, 32);
    memcpy(tx_key, hash + 32, 32);

    nonce_ctr_t nonce_tx = NONCE_CTR_INIT;
    nonce_ctr_t nonce_rx = NONCE_CTR_INIT;

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
    memcpy(payload1,       device_id, 32);
    memcpy(payload1 + 32,  A_c,       32);
    memcpy(payload1 + 64,  s_c,       32);
    memcpy(payload1 + 96,  nonce_c,   32);
    memcpy(payload1 + 128, eph_c,     32);

    uint8_t nonce_tx_buf[12];
    nonce_next(&nonce_tx, nonce_tx_buf);

    uint8_t ct1[160 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ct1_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(ct1, &ct1_len, payload1, sizeof(payload1),
                                              NULL, 0, NULL, nonce_tx_buf, tx_key);

    if (send_u32_le(fd, (uint32_t)ct1_len, &sent) != 0) { close(fd); return -1; }
    if (send_all(fd, ct1, (size_t)ct1_len, &sent) != 0) { close(fd); return -1; }

    uint32_t rx_len;
    uint8_t *rx_ct = recv_encrypted_blob(fd, &rx_len, &recv);
    if (!rx_ct) { close(fd); return -1; }

    uint8_t pt2[192];
    unsigned long long pt2_len;
    uint8_t nonce_rx_buf[12];
    nonce_next(&nonce_rx, nonce_rx_buf);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt2, &pt2_len, NULL, rx_ct, rx_len,
                                                  NULL, 0, nonce_rx_buf, rx_key) != 0) {
        fprintf(stderr, "Client[AUTH]: server payload decryption failed\n");
        free(rx_ct); close(fd); return -1;
    }
    free(rx_ct);

    if (pt2_len != 192) {
        fprintf(stderr, "Client[AUTH]: invalid server payload size %llu\n", pt2_len);
        close(fd); return -1;
    }

    uint8_t server_pub2[32], A_s[32], s_s[32], nonce_s[32], eph_s[32], tag_s[32];
    memcpy(server_pub2, pt2,       32);
    memcpy(A_s,         pt2 + 32,  32);
    memcpy(s_s,         pt2 + 64,  32);
    memcpy(nonce_s,     pt2 + 96,  32);
    memcpy(eph_s,       pt2 + 128, 32);
    memcpy(tag_s,       pt2 + 160, 32);

    if (check_point(server_pub2, "server_pub2") != 0) { close(fd); return -1; }
    if (check_point(A_s,         "A_s")         != 0) { close(fd); return -1; }
    if (check_point(eph_s,       "eph_s")       != 0) { close(fd); return -1; }

    if (sodium_memcmp(server_pub2, pinned_server_pub, 32) != 0) {
        fprintf(stderr, "Client[AUTH]: server pubkey mismatch vs pinned — MITM?\n");
        close(fd); return -1;
    }

    if (schnorr_verify_server(server_pub2, A_s, s_s, nonce_s, eph_s) != 0) {
        fprintf(stderr, "Client[AUTH]: server Schnorr proof FAILED\n");
        close(fd); return -1;
    }
    printf("Client[AUTH]: Server Schnorr authentication = true\n");

    uint8_t session_key[32];
    if (derive_session_key(session_key, eph_secret, eph_s, nonce_c, nonce_s, device_id,
                           eph_c, eph_s, x25519_shared) != 0) {
        fprintf(stderr, "Client[AUTH]: session key derivation failed\n");
        close(fd); return -1;
    }

    uint8_t th[32];
    kc_transcript_hash(th, device_id, A_c, s_c, nonce_c, eph_c, server_pub2, A_s, s_s, nonce_s, eph_s);

    uint8_t k_s2c[32], k_c2s[32];
    derive_kc_keys(k_s2c, k_c2s, session_key, th);

    uint8_t expected_s[32];
    hmac_tag(expected_s, k_s2c, "server finished", th);
    if (sodium_memcmp(expected_s, tag_s, 32) != 0) {
        fprintf(stderr, "Client[AUTH]: server key confirmation failed\n");
        close(fd); return -1;
    }
    printf("Client[AUTH]: Key confirmation (server finished) OK\n");

    uint8_t tag_c[32];
    hmac_tag(tag_c, k_c2s, "client finished", th);

    nonce_next(&nonce_tx, nonce_tx_buf);

    uint8_t ct3[32 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ct3_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(ct3, &ct3_len, tag_c, 32,
                                              NULL, 0, NULL, nonce_tx_buf, tx_key);

    if (send_u32_le(fd, (uint32_t)ct3_len, &sent) != 0) { close(fd); return -1; }
    if (send_all(fd, ct3, (size_t)ct3_len, &sent) != 0) { close(fd); return -1; }

    if (prepare_client_continuity_proof(&client_cont_proof, &pending_client_state,
                                        device_id, x, 300) != 0) {
        fprintf(stderr, "Client[CONT]: failed to prepare client continuity proof\n");
        close(fd); return -1;
    }
    if (continuity_proof_serialize(&client_cont_proof, cont_wire) != 0) {
        fprintf(stderr, "Client[CONT]: failed to serialize client continuity proof\n");
        close(fd); return -1;
    }
    if (send_encrypted_record(fd, tx_key, &nonce_tx, cont_wire, sizeof cont_wire, &sent) != 0) {
        fprintf(stderr, "Client[CONT]: failed sending client continuity proof\n");
        close(fd); return -1;
    }
    {
        uint8_t server_cont_wire[CONT_PROOF_LEN];
        size_t server_cont_len = 0;
        if (recv_encrypted_record(fd, rx_key, &nonce_rx,
                                  server_cont_wire, sizeof server_cont_wire,
                                  &server_cont_len, &recv) != 0) {
            fprintf(stderr, "Client[CONT]: failed receiving server continuity proof\n");
            close(fd); return -1;
        }
        if (verify_server_continuity_proof_blob(server_cont_wire, server_cont_len, &verified_server_track) != 0) {
            fprintf(stderr, "Client[CONT]: server continuity proof verification failed\n");
            close(fd); return -1;
        }
    }
    if (save_client_continuity_state(&pending_client_state) != 0) { close(fd); return -1; }
    if (save_server_track(&verified_server_track) != 0) { close(fd); return -1; }
    printf("Client[AUTH]: Sent encrypted client finished tag and continuity proof\n");

    double duration = get_time_sec() - start_time;
    printf("CLIENT METRICS -> Duration: %.3fms, Sent: %zu bytes, Received: %zu bytes\n",
           duration * 1000.0, sent, recv);

    sess->fd = fd;
    memcpy(sess->session_key, session_key, 32);
    memcpy(sess->tx_key, tx_key, 32);
    memcpy(sess->rx_key, rx_key, 32);
    sess->tx_nonce = nonce_tx;
    sess->rx_nonce = nonce_rx;
    sess->established_at = time(NULL);
    sess->last_rx = sess->established_at;
    sess->last_tx = sess->established_at;
    if (sent_out) *sent_out = sent;
    if (recv_out) *recv_out = recv;

    sodium_memzero(eph_secret,    sizeof eph_secret);
    sodium_memzero(session_key,   sizeof session_key);
    sodium_memzero(k_s2c,         sizeof k_s2c);
    sodium_memzero(k_c2s,         sizeof k_c2s);
    sodium_memzero(client_sk,     sizeof client_sk);
    sodium_memzero(x25519_shared, sizeof x25519_shared);
    sodium_memzero(tx_key,        sizeof tx_key);
    sodium_memzero(rx_key,        sizeof rx_key);

    return 0;
}

static void close_auth_session(auth_session_t *sess) {
    if (!sess) return;
    if (sess->fd >= 0) close(sess->fd);
    sodium_memzero(sess, sizeof(*sess));
    sess->fd = -1;
}

static int run_online_session(auth_session_t *sess, unsigned interval_secs) {
    uint8_t pt[32];
    size_t pt_len = 0, sent = 0, recv = 0;
    if (!sess || sess->fd < 0) return -1;
    printf("Client[ONLINE]: session established\n");
    for (;;) {
        uint8_t hb = MSG_HEARTBEAT;
        if (send_encrypted_record(sess->fd, sess->tx_key, &sess->tx_nonce, &hb, 1, &sent) != 0) {
            return -1;
        }
        sess->last_tx = time(NULL);
        printf("Client[HB]: sent\n");
        if (recv_encrypted_record(sess->fd, sess->rx_key, &sess->rx_nonce, pt, sizeof(pt), &pt_len, &recv) != 0) {
            return -1;
        }
        sess->last_rx = time(NULL);
        if (pt_len != 1) {
            fprintf(stderr, "Client[HB]: invalid ack\n");
            return -1;
        }
        if (pt[0] == MSG_HEARTBEAT_ACK) {
            printf("Client[HB]: ack\n");
        } else if (pt[0] == MSG_GOODBYE) {
            printf("Client[ONLINE]: server closed session\n");
            return 0;
        } else {
            fprintf(stderr, "Client[HB]: invalid ack\n");
            return -1;
        }
        sleep(interval_secs ? interval_secs : 5);
    }
}

// Performs the client authentication and key-confirmation flow.
static int do_auth_v2(const char *server, const uint8_t device_id[32], const uint8_t x[32]) {
    auth_session_t sess;
    if (do_auth_v2_open_session(server, device_id, x, &sess, NULL, NULL) != 0) return -1;
    close_auth_session(&sess);
    return 0;
}

static void daemon_backoff_sleep(unsigned *attempt) {
    unsigned a = *attempt;
    if (a > 6) a = 6;
    unsigned base_ms = 1000u << a;
    uint32_t jitter = randombytes_uniform(500u);
    unsigned total_ms = base_ms + jitter;
    printf("Client[DAEMON]: reconnecting after %.3fs\n", total_ms / 1000.0);
    usleep((useconds_t)total_ms * 1000u);
    if (*attempt < 10) (*attempt)++;
}

static int run_daemon(const char *server, const uint8_t device_id[32], const uint8_t x[32], unsigned interval_secs) {
    unsigned attempt = 0;
    for (;;) {
        auth_session_t sess;
        if (do_auth_v2_open_session(server, device_id, x, &sess, NULL, NULL) != 0) {
            fprintf(stderr, "Client[DAEMON]: connect/auth failed: %s\n", strerror(errno));
            daemon_backoff_sleep(&attempt);
            continue;
        }
        attempt = 0;
        if (run_online_session(&sess, interval_secs) != 0) {
            fprintf(stderr, "Client[DAEMON]: session lost: %s\n", strerror(errno));
        }
        close_auth_session(&sess);
        daemon_backoff_sleep(&attempt);
    }
}

// Prints the client command-line usage help.
static void usage(const char *p) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --server 127.0.0.1:4000 --setup [--pairing-token TOKEN]\n"
        "  %s --server 127.0.0.1:4000\n"
        "  %s --pin-server-pub <hex>\n"
        "  %s --print-device-identity\n"
        "  %s --make-offline-proof <file> --audience <name> --scope <scope> [--offline-expires-in <1..300>] [--request-hash <hex>|--request-file <path>]\n"
        "  %s --make-client-continuity-proof <file> [--continuity-expires-in <1..300>]\n"
        "  %s --verify-server-continuity-proof <file>\n"
        "  %s --server 127.0.0.1:4000 --daemon [--daemon-interval-secs N]\n", p, p, p, p, p, p, p, p);
}

// Parses command-line arguments and dispatches the requested program action.
int main(int argc, char **argv) {
    if (sodium_init() < 0) return 1;

    const char *server = "127.0.0.1:4000";
    const char *pairing_token = NULL;
    int setup = 0;
    int print_identity = 0;
    int allow_tofu_setup = 0;
    int daemon_mode = 0;
    unsigned daemon_interval_secs = 5;
    const char *offline_out = NULL, *offline_audience = NULL, *offline_scope = NULL;
    const char *offline_request_hash_hex = NULL, *offline_request_file = NULL;
    uint64_t offline_expires_in = 300;
    const char *client_cont_out = NULL;
    const char *verify_server_cont_file = NULL;
    uint64_t continuity_expires_in = 300;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--server") && i + 1 < argc) {
            server = argv[++i];
        } else if (!strcmp(argv[i], "--setup")) {
            setup = 1;
        } else if (!strcmp(argv[i], "--print-device-identity")) {
            print_identity = 1;
        } else if (!strcmp(argv[i], "--allow-tofu-setup")) {
            allow_tofu_setup = 1;
        } else if (!strcmp(argv[i], "--daemon")) {
            daemon_mode = 1;
        } else if (!strcmp(argv[i], "--daemon-interval-secs") && i + 1 < argc) {
            daemon_interval_secs = (unsigned)strtoul(argv[++i], NULL, 10);
            if (daemon_interval_secs == 0) daemon_interval_secs = 5;
        } else if (!strcmp(argv[i], "--make-offline-proof") && i + 1 < argc) {
            offline_out = argv[++i];
        } else if (!strcmp(argv[i], "--audience") && i + 1 < argc) {
            offline_audience = argv[++i];
        } else if (!strcmp(argv[i], "--scope") && i + 1 < argc) {
            offline_scope = argv[++i];
        } else if (!strcmp(argv[i], "--offline-expires-in") && i + 1 < argc) {
            offline_expires_in = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--request-hash") && i + 1 < argc) {
            offline_request_hash_hex = argv[++i];
        } else if (!strcmp(argv[i], "--request-file") && i + 1 < argc) {
            offline_request_file = argv[++i];
        } else if (!strcmp(argv[i], "--make-client-continuity-proof") && i + 1 < argc) {
            client_cont_out = argv[++i];
        } else if (!strcmp(argv[i], "--verify-server-continuity-proof") && i + 1 < argc) {
            verify_server_cont_file = argv[++i];
        } else if (!strcmp(argv[i], "--continuity-expires-in") && i + 1 < argc) {
            continuity_expires_in = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--pairing-token") && i + 1 < argc) {
            pairing_token = argv[++i];
        } else if (!strcmp(argv[i], "--pin-server-pub") && i + 1 < argc) {
            const char *hex_str = argv[++i];
            uint8_t pinned[32];
            size_t bin_len = 0;
            if (sodium_hex2bin(pinned, sizeof pinned, hex_str, strlen(hex_str), NULL, &bin_len, NULL) != 0 ||
                bin_len != 32) {
                fprintf(stderr, "invalid hex for pinned key\n");
                return 1;
            }
            if (crypto_core_ristretto255_is_valid_point(pinned) != 1) {
                fprintf(stderr, "pinned key is not a valid Ristretto point\n");
                return 1;
            }
            if (write_file_32(SERVER_PUB_FILE, pinned) != 0) {
                fprintf(stderr, "failed to write pinned key\n");
                return 1;
            }
            printf("Client: Successfully pinned server pubkey out-of-band.\n");
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (print_identity) {
        return (print_device_identity() == 0) ? 0 : 1;
    }

    if (verify_server_cont_file) {
        return verify_server_continuity_proof_from_file(verify_server_cont_file) == 0 ? 0 : 1;
    }

    if (!creds_exist() && !setup) {
        fprintf(stderr, "Client: device root missing (%s). Run --setup to enroll.\n", DEVICE_ROOT_FILE);
        return 0;
    }

    uint8_t device_id[32], x[32];
    int created_root = 0;
    if (load_device_creds_from_root(device_id, x, &created_root) != 0) {
        fprintf(stderr, "Failed loading/creating device root\n");
        return 1;
    }

    if (offline_out) {
        offline_proof_t p;
        uint8_t req_hash[32];
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        int ok = -1;
        if (!offline_audience || !offline_scope || (!offline_request_hash_hex && !offline_request_file)) {
            fprintf(stderr, "--make-offline-proof requires --audience, --scope, and one of --request-hash/--request-file\n");
            sodium_memzero(x, sizeof x);
            return 1;
        }
        if (offline_request_hash_hex) {
            if (parse_hash32_hex(offline_request_hash_hex, req_hash) != 0) {
                fprintf(stderr, "bad --request-hash\n");
                sodium_memzero(x, sizeof x);
                return 1;
            }
        } else {
            sha256_file_hash(req_hash, offline_request_file);
        }
        if (build_offline_proof(&p, device_id, x, offline_audience, offline_scope, offline_expires_in, req_hash) == 0 &&
            offline_proof_serialize(&p, &wire, &wire_len) == 0 &&
            write_exact_file(offline_out, wire, wire_len, 0600) == 0) {
            printf("Client[OFFLINE]: wrote offline proof to %s for audience='%s' scope='%s' counter=%llu issued_at=%llu expires_at=%llu request_hash=",
                   offline_out, offline_audience, offline_scope,
                   (unsigned long long)p.counter,
                   (unsigned long long)p.issued_at,
                   (unsigned long long)p.expires_at);
            for (size_t j = 0; j < 32; j++) printf("%02x", p.request_hash[j]);
            printf("\n");
            ok = 0;
        }
        free(wire);
        sodium_memzero(x, sizeof x);
        sodium_memzero(device_id, sizeof device_id);
        return ok == 0 ? 0 : 1;
    }

    if (client_cont_out) {
        continuity_state_t st;
        continuity_proof_t proof;
        uint8_t wire[CONT_PROOF_LEN];
        int ok = -1;
        if (build_client_continuity_proof(&proof, &st, device_id, x, continuity_expires_in) == 0 &&
            continuity_proof_serialize(&proof, wire) == 0 &&
            write_exact_file(client_cont_out, wire, sizeof wire, 0600) == 0) {
            char chk[65];
            bin2hex_lower(proof.checkpoint_hash, 32, chk, sizeof chk);
            printf("Client[CONTINUITY]: wrote client continuity proof to %s counter=%llu reconnect_epoch=%llu checkpoint_hash=%s\n",
                   client_cont_out,
                   (unsigned long long)st.continuity_counter,
                   (unsigned long long)st.reconnect_epoch,
                   chk);
            ok = 0;
        }
        sodium_memzero(x, sizeof x);
        sodium_memzero(device_id, sizeof device_id);
        return ok == 0 ? 0 : 1;
    }

    if (setup) {
        printf("Client[SETUP/ZTP]: %s\n", created_root
               ? "No device root found; generating NEW device root."
               : "Using existing device root for setup (idempotent).");
    }

    int rc = setup ? do_setup(server, device_id, x, pairing_token, allow_tofu_setup)
                   : (daemon_mode ? run_daemon(server, device_id, x, daemon_interval_secs)
                                  : do_auth_v2(server, device_id, x));

    sodium_memzero(x, sizeof x);
    sodium_memzero(device_id, sizeof device_id);
    return (rc == 0) ? 0 : 1;
}
