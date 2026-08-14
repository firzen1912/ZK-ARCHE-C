# ZK-ARCHE — C Implementation

ZK-ARCHE is a C/libsodium research implementation of the current **ZK-ARCHE v2** authentication design for constrained and IoT-style systems. It uses Ristretto255 Schnorr proofs, per-session pseudonyms, re-randomized role commitments, anonymous role-set membership proofs, ephemeral Ristretto Diffie-Hellman, HKDF-SHA256, and HMAC-SHA256 key confirmation.

> Certificate onboarding, OpenSSL-based protocol logic, X25519, the ChaCha20-Poly1305 outer tunnel, daemon/heartbeat operation, offline proofs, and continuity proofs are not part of the current implementation or helper workflow.

## Current protocol

| Area | Current behavior |
| --- | --- |
| Enrollment | Raw-public-key setup with mutual Schnorr proofs |
| Server trust | Pinned Ristretto server key; explicit TOFU bootstrap option |
| Online identity | Per-session `pid` instead of stable `device_id` |
| Client authentication | Schnorr proof over Ristretto255 |
| Server authentication | Schnorr proof of pinned server static secret |
| Role authorization | Re-randomized commitment + CDS/OR role-set proof |
| Allowed roles | `1` and `2` |
| Key agreement | Ephemeral Ristretto DH |
| KDF | HKDF-SHA256 |
| Key confirmation | HMAC-SHA256 |
| Replay protection | Persistent server replay cache |
| Transport | TCP with 5-second I/O timeout |

## Protocol outline

### Enrollment

The client stores a persistent 32-byte device root at:

```text
/var/lib/iot-auth/client/device_root.bin
```

Setup uses `MSG_SETUP = 0x01`. Client and server prove possession of their static Ristretto secrets with transcript-bound Schnorr proofs while the server pairing policy is enabled.

### Per-session pseudonym

Online authentication uses `MSG_AUTH_V2 = 0x03` and computes:

```text
pid = SHA-256(domain || device_pub || nonce_c || eph_c || server_pub)
```

The stable device identifier is therefore not sent as the online authentication identifier.

### Private role authorization

The registry stores a role commitment. During authentication, the client re-randomizes that commitment, proves the re-randomization is tied to the enrolled commitment, and proves that the hidden role belongs to `[1, 2]` without revealing which allowed role it holds.

### Session establishment

The peers use ephemeral Ristretto DH, derive the session key using HKDF-SHA256, and exchange HMAC-SHA256 confirmation tags bound to the authentication transcript.

The current v2 handshake payloads are sent directly over TCP; there is no application-layer AEAD wrapper.

## Dependencies

The active C implementation depends on **libsodium**. OpenSSL is no longer required for protocol operation or for the repository helper build.

Ubuntu / Raspberry Pi OS:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libsodium-dev
```

## Build

Recommended:

```bash
./zk-arche.sh build
```

This produces:

```text
./c_server
./c_client
```

Equivalent manual commands:

```bash
gcc -O2 -std=c11 -Wall -Wextra -pedantic server.c -o c_server $(pkg-config --cflags --libs libsodium)
gcc -O2 -std=c11 -Wall -Wextra -pedantic client.c -o c_client $(pkg-config --cflags --libs libsodium)
```

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

The v2 registry record is 96 bytes: device ID, device public key, and role commitment. Old registry layouts require re-enrollment.

## Helper script

`zk-arche.sh` has been reduced to the active v2 workflow:

```text
build
init-rpk
pin-server
show-pinned-key
check-server-state
check-client-state
status
start-server
server-local
setup-device
auth-device
client-local
full-device-onboard
reset-client
reset-server
reset-all
```

Legacy certificate generation, OpenSSL linking, offline/continuity commands, and generated identity helpers have been removed from the helper workflow.

## Local smoke test

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

For deployment, pin the server public key through an authenticated provisioning channel rather than relying on TOFU.

## Raw CLI

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

## Research limitations

- Research prototype; not production-reviewed.
- AUTH payloads are not protected by an application-layer AEAD.
- PID removes the stable device identifier from online wire messages but does not hide enrollment identity from the server.
- PID lookup scales with enrolled registry size.
- Role policy is compiled into both peers.
- TOFU is a bootstrap tradeoff, not authenticated provisioning.

For the primary Rust implementation, see `firzen1912/ZK-ARCHE-Rust`. For comparative benchmarking against EDHOC and mTLS, see `firzen1912/zk-arche-compare`.
