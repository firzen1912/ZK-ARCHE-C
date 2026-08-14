# ZK-ARCHE — C Implementation

ZK-ARCHE is a C/libsodium implementation of lightweight, privacy-oriented mutual authentication for constrained and IoT-style systems. The current `main` branch implements the **ZK-ARCHE v2 online-authentication design** using Ristretto255, Schnorr proofs, per-session pseudonyms, re-randomized role commitments, anonymous role-set membership proofs, ephemeral Ristretto Diffie-Hellman key agreement, and HMAC-based key confirmation.

> **Current implementation note:** the active protocol no longer uses certificate-based onboarding, X25519, or a ChaCha20-Poly1305 outer tunnel. Setup is raw-public-key (RPK) based, and v2 authentication payloads are sent directly over TCP. The session key is derived from the Ristretto ephemeral DH secret and confirmed with HMAC, but the current handshake payloads are not protected by an application-layer AEAD.

## Current protocol status

| Area | Current `main` behavior |
| --- | --- |
| Enrollment | Raw-public-key setup with mutual Schnorr proofs |
| Server trust | Pinned Ristretto server public key; explicit TOFU setup option for bootstrap/debug use |
| Device identity | Stable identity at enrollment; per-session `pid` during online AUTH |
| Client authentication | Schnorr proof over Ristretto255 |
| Server authentication | Schnorr proof of the pinned server static secret |
| Role authorization | Re-randomized role commitment plus CDS/OR-style set-membership proof |
| Allowed role set | `1` and `2` |
| Key agreement | Ephemeral Ristretto Diffie-Hellman |
| KDF | HKDF-SHA256 |
| Key confirmation | HMAC-SHA256 |
| Replay protection | Persistent server replay cache |
| Transport | TCP with 5-second I/O timeout |

## ZK-ARCHE v2 model

### Persistent device identity

The client stores a 32-byte root secret at:

```text
/var/lib/iot-auth/client/device_root.bin
```

The implementation deterministically derives a stable device identifier and Ristretto authentication key pair from that root. The stable device identifier is used during setup but is not the online AUTH identifier.

### Raw-public-key setup

Setup uses `MSG_SETUP = 0x01`. The device and server exchange static Ristretto public keys and prove possession of their corresponding secrets with transcript-bound Schnorr proofs. Enrollment is gated by the server pairing policy; an optional pairing token and expiration window can be configured.

The server key should normally be pinned before enrollment. `--allow-tofu-setup` permits trust-on-first-use for bootstrap/debug flows.

### Per-session pseudonym

Online authentication uses `MSG_AUTH_V2 = 0x03`. The client computes a fresh pseudonym from the enrolled device public key, client nonce, client ephemeral Ristretto public key, and server static public key:

```text
pid = SHA-256(domain || device_pub || nonce_c || eph_c || server_pub)
```

The server recomputes candidate PIDs from enrolled records to find the matching device without requiring the stable device ID on the wire.

### Anonymous role authorization

The server registry stores a role commitment for each enrolled device. During authentication, the client:

1. re-randomizes its enrolled commitment;
2. proves the fresh commitment is a valid re-randomization of the stored one; and
3. gives a CDS/OR-style zero-knowledge proof that the committed role belongs to the compiled allowed set.

The current allowed set is:

```text
[1, 2]
```

This proves membership in the authorized role class without revealing which allowed role is held.

### Mutual authentication and session key

The client authenticates with a Schnorr proof tied to the per-session PID. The server authenticates with a Schnorr proof of its pinned static key. Both sides derive a session key from ephemeral Ristretto Diffie-Hellman plus nonces and the PID using HKDF-SHA256, then exchange HMAC-SHA256 key-confirmation tags.

## Cryptographic building blocks

| Function | Primitive |
| --- | --- |
| Group | Ristretto255 via libsodium |
| Client/server knowledge proofs | Schnorr |
| Fiat-Shamir challenge hash | SHA-512 |
| Per-session pseudonym | SHA-256 |
| Device-root derivation | libsodium generic hash / BLAKE2b |
| Role commitment | Ristretto commitment with domain-derived attribute generator |
| Role privacy | Commitment re-randomization + CDS/OR set-membership proof |
| Ephemeral key agreement | Ristretto Diffie-Hellman |
| Session KDF | HKDF-SHA256 |
| Key confirmation | HMAC-SHA256 |
| Constant-time comparison | `sodium_memcmp` |
| Secret cleanup | `sodium_memzero` |

## State layout

### Client

```text
/var/lib/iot-auth/client/
├── device_root.bin
├── server_pub.bin
└── role_cred.bin
```

### Server

```text
/var/lib/iot-auth/server/
├── server_sk.bin
├── registry.bin
├── registry.bak
└── replay_cache.bin
```

The v2 server registry uses 96-byte records:

```text
device_id (32) || device_pub (32) || role_commitment (32)
```

This differs from earlier registry layouts and requires re-enrollment when upgrading from incompatible versions.

## Dependencies

The active client/server protocol code is based on **libsodium**. Build tooling in `zk-arche.sh` still links OpenSSL as a legacy dependency, but the current C source no longer uses the former X.509/certificate setup path.

Install the normal build prerequisites:

```bash
sudo apt update
sudo apt install -y build-essential gcc pkg-config libsodium-dev
```

If you use the helper script exactly as currently written, installing OpenSSL development packages also avoids linker/setup friction from its legacy build flags:

```bash
sudo apt install -y libssl-dev openssl
```

## Build

Recommended:

```bash
./zk-arche.sh build
```

Outputs:

```text
./c_server
./c_client
```

A minimal direct build for the active protocol source is:

```bash
gcc -O2 -std=c11 -Wall -Wextra -pedantic server.c -o c_server -lsodium -lpthread
gcc -O2 -std=c11 -Wall -Wextra -pedantic client.c -o c_client -lsodium
```

## Recommended local v2 flow

### Terminal 1

```bash
./zk-arche.sh build
sudo ./zk-arche.sh reset-all
sudo ./zk-arche.sh init-rpk
sudo ./zk-arche.sh server-local 127.0.0.1:4000
```

### Terminal 2

```bash
sudo ./zk-arche.sh client-local 127.0.0.1:4000 --allow-tofu-setup
sudo ./zk-arche.sh auth-device 127.0.0.1:4000
```

For a stronger deployment model, provision the server public key out of band and avoid TOFU.

## Raw binary CLI

### Server

```bash
./c_server --bind 0.0.0.0:4000
./c_server --bind 0.0.0.0:4000 --pairing
./c_server --bind 0.0.0.0:4000 --pairing --pairing-token TOKEN --pairing-seconds 120
./c_server --print-pubkey
```

### Client

```bash
./c_client --server 127.0.0.1:4000 --setup
./c_client --server 127.0.0.1:4000 --setup --pairing-token TOKEN
./c_client --server 127.0.0.1:4000 --setup --allow-tofu-setup
./c_client --server 127.0.0.1:4000
./c_client --pin-server-pub <64-hex-character-key>
./c_client --print-identity
```

## Current security behavior

The implementation includes:

- Ristretto point validation;
- persistent replay-cache state;
- private state-file permissions;
- transcript-bound Schnorr proofs;
- per-session pseudonyms;
- role-commitment re-randomization;
- anonymous role-set membership verification;
- ephemeral Ristretto DH key establishment;
- HKDF-based session derivation;
- HMAC key confirmation; and
- bounded socket I/O timeouts.

## Removed/stale feature references

Older versions of this repository used X.509 certificates, OpenSSL verification, X25519, ChaCha20-Poly1305, offline proof experiments, and continuity/reconnection mechanisms. Those descriptions are not representative of the current core client/server implementation.

`zk-arche.sh` still contains some legacy offline/continuity command text and state references. Treat its RPK initialization, server-key pinning, setup, authentication, state inspection, and reset flows as the reliable paths for the current binaries.

## Research limitations

- This is a research prototype and has not undergone a production-grade protocol or implementation audit.
- AUTH payloads are currently plaintext at the application protocol layer over TCP; confidentiality would need to come from another transport/protection layer or a future protocol revision.
- The server can identify the enrolled device after PID lookup; PID primarily avoids placing the stable identifier directly on the wire.
- Current PID lookup scans enrolled records and recomputes PIDs, so lookup cost grows with registry size.
- The allowed role set is compiled into both peers and must remain synchronized.
- Secure server-key provisioning is external to the core protocol; TOFU is a bootstrap/debug tradeoff.

## Repository scope

This implementation is intended for constrained-device experimentation, C/Rust cross-language interoperability testing, privacy-preserving authentication research, role-authorization proof evaluation, and performance/security comparison before production hardening.

For the Rust implementation, see `firzen1912/ZK-ARCHE-Rust`. For benchmarking against EDHOC and mTLS, see `firzen1912/zk-arche-compare`.
