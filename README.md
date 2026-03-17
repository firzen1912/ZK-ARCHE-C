# ZK-ARCHE (C Implementation)

Lightweight **Zero-Knowledge Proof Mutual Authentication** for IoT devices using **libsodium** and **OpenSSL**.

This C implementation targets **embedded / constrained environments** and now uses **mutual certificate-based onboarding** for Zero-Touch Provisioning. The setup path no longer relies on bootstrap secrets or first-contact TOFU for enrollment.

The system supports:

- **Mutual certificate-based Zero-Touch Provisioning (SETUP)**
- **Schnorr-based mutual authentication** for the operational protocol
- **An encrypted privacy-preserving transport tunnel** for `AUTH_V2`
- **Optional pairing-token restricted enrollment windows**

---

# Architecture

| Component              | Role                  |
| ---------------------- | --------------------- |
| Raspberry Pi 3 / 4 / 5 | Provers (IoT devices) |
| Ubuntu Server          | Verifier              |
| Local CA               | Enrollment trust root |
| Device Root Secret     | Persistent device identity |

---

# Cryptographic Design

| Primitive         | Algorithm                         |
| ----------------- | --------------------------------- |
| Group             | Ristretto255                      |
| ZKP               | Schnorr Identification            |
| Fiat-Shamir       | SHA-512                           |
| KDF               | HKDF-SHA256                       |
| AEAD              | ChaCha20-Poly1305                 |
| Anonymous Tunnel  | X25519 ECDHE + BLAKE2b-512        |
| Key Confirmation  | HMAC-SHA256 (server + client MAC) |
| Transcript        | Length-prefixed domain-separated  |
| Constant-time ops | libsodium (`sodium_memcmp`)       |
| Secret zeroising  | libsodium (`sodium_memzero`)      |
| PKI / X.509       | OpenSSL                           |
| Transport         | TCP                               |
| Libraries         | libsodium, OpenSSL                |

---

# Security Model

The protocol now separates **onboarding trust** from **operational authentication**.

---

## 1. Mutual Certificate-Based Onboarding (Provisioning)

Used during **Zero-Touch Provisioning (`--setup`)**.

During setup:

- the **device** presents a device certificate and proves possession of the matching private key
- the **server** presents a server certificate and proves possession of the matching private key
- both sides validate the presented certificate chain against a trusted CA
- both sides sign the same setup transcript
- the server only sends the `0x01` enrollment acknowledgment after all certificate, signature, and setup-proof checks pass

This removes the prior dependency on:

- `bootstrap_id`
- `bootstrap_secret`
- `bootstrap_registry.bin`
- TOFU as the root of trust for first setup

---

## 2. Operational Identity (Authentication)

Derived deterministically from the device root secret:

```text
device_root.bin  ->  device_id
              ->  device_private_scalar x
              ->  device_public_key = G * x
```

Authentication still uses a **Schnorr ZKP** over an **anonymous X25519 encrypted tunnel** so the device identity is hidden from passive observers. Mutual authentication is confirmed with **key confirmation MACs** over the session transcript.

In other words:

- **certificates** authorize enrollment
- **Schnorr + encrypted `AUTH_V2`** continue to protect the operational protocol

---

## 3. Server Identity Handling

For onboarding, the client validates the **server certificate** immediately, so **TOFU is no longer required** for first setup.

For compatibility with the existing `AUTH_V2` path, the client may still persist `server_pub.bin` after successful setup and may still support manual `--pin-server-pub`. That persisted value is now a compatibility anchor for the operational protocol, not the root of trust for enrollment.

---

# File Layout

## Client (Raspberry Pi)

```text
/var/lib/iot-auth/
    device_root.bin
    device_cert.pem
    device_key.pem
    ca_cert.pem
    server_pub.bin
```

| File              | Purpose |
| ----------------- | ------- |
| `device_root.bin` | Persistent device root secret for operational identity |
| `device_cert.pem` | Device enrollment certificate |
| `device_key.pem`  | Device private key matching the device cert |
| `ca_cert.pem`     | Trusted CA certificate used to validate the server |
| `server_pub.bin`  | Compatibility pin for the operational server key |

## Server (Verifier)

```text
registry.bin
server_sk.bin
server_cert.pem
server_cert_key.pem
ca_cert.pem
```

| File                | Purpose |
| ------------------- | ------- |
| `registry.bin`      | Enrolled device identities |
| `server_sk.bin`     | Verifier static private key used by the operational protocol |
| `server_cert.pem`   | Server enrollment certificate |
| `server_cert_key.pem` | Server private key matching the server cert |
| `ca_cert.pem`       | Trusted CA certificate used to validate device certs |

---

# Install Dependencies

**Ubuntu / Raspberry Pi OS:**

```bash
sudo apt update
sudo apt install build-essential libsodium-dev libssl-dev xxd openssl
```

---

# Compile

```bash
gcc -O2 -std=c11 -Wall -Wextra server.c -o c_server -lsodium -lssl -lcrypto
gcc -O2 -std=c11 -Wall -Wextra client.c -o c_client -lsodium -lssl -lcrypto
```

Or use the automation script:

```bash
./zk-arche.sh build
```

---

# Certificate Binding Convention

The updated C onboarding flow expects the certificates to bind protocol identity data.

Current convention used by the updated C sources:

- device cert **CN** = lowercase hex of `device_id`
- device cert **OU** = lowercase hex of compressed `device_pub`
- server cert **OU** = lowercase hex of compressed `server_pub`

This lets the certificate authorize the exact protocol identity being enrolled.

---

# Automation Script

All common operations can be run through `zk-arche.sh`:

```text
Usage:
  ./zk-arche.sh build
  ./zk-arche.sh make-certs [--device-id <hex>] [--device-pub <hex>] [--server-pub <hex>]
  ./zk-arche.sh install-client-certs
  ./zk-arche.sh check-server-certs
  ./zk-arche.sh check-client-certs
  ./zk-arche.sh start-server <bind_addr> [--pairing] [--pairing-token <t>] [--pairing-seconds <n>]
  ./zk-arche.sh server-local <bind_addr>
  ./zk-arche.sh setup-device <server_ip:port> [--pairing-token <t>]
  ./zk-arche.sh auth-device <server_ip:port>
  ./zk-arche.sh show-pinned-key
  ./zk-arche.sh pin-server <server_pub_hex>
  ./zk-arche.sh status
  ./zk-arche.sh client-local <server_ip:port> [--pairing-token <t>]
  ./zk-arche.sh full-device-onboard <server_ip:port> [--pairing-token <t>]
  ./zk-arche.sh reset-client | reset-server | reset-all
```

---

# Deployment

## Two-Machine Setup (Recommended)

### Server machine

```bash
./zk-arche.sh build
./zk-arche.sh make-certs
./zk-arche.sh start-server 0.0.0.0:4000 --pairing
```

### Client machine

Copy or install the client-side certificate materials so these files exist:

- `/var/lib/iot-auth/device_cert.pem`
- `/var/lib/iot-auth/device_key.pem`
- `/var/lib/iot-auth/ca_cert.pem`

Then run:

```bash
./zk-arche.sh build
./zk-arche.sh check-client-certs
./zk-arche.sh setup-device <server_ip>:4000
./zk-arche.sh auth-device <server_ip>:4000
```

---

## Single-Machine Local Test

**Terminal 1:**

```bash
./zk-arche.sh build
./zk-arche.sh make-certs
./zk-arche.sh install-client-certs
./zk-arche.sh server-local 127.0.0.1:4000
```

**Terminal 2:**

```bash
./zk-arche.sh client-local 127.0.0.1:4000
./zk-arche.sh auth-device 127.0.0.1:4000
```

---

## Optional: Pairing Token

To restrict which clients can enroll during a pairing window:

**Server:**
```bash
./zk-arche.sh start-server 0.0.0.0:4000 --pairing --pairing-token mysecrettoken --pairing-seconds 120
```

**Client:**
```bash
./zk-arche.sh setup-device <server_ip>:4000 --pairing-token mysecrettoken
```

---

## Optional: Manual Out-of-Band Operational Key Pinning

If you want to pin the server public key for the operational protocol before setup:

```bash
./zk-arche.sh pin-server <server_pub_hex>
./zk-arche.sh setup-device <server_ip>:4000
```

This is optional for onboarding trust. The onboarding trust root is the CA and the server certificate.

---

## Raw Binary Usage (without script)

**Server — start with pairing window:**
```bash
./c_server --bind 0.0.0.0:4000 --pairing
```

**Client — enroll with mutual certificate setup:**
```bash
./c_client --server <server_ip>:4000 --setup
```

**Client — authenticate:**
```bash
./c_client --server <server_ip>:4000
```

---

# `make-certs` Note

The integrated `make-certs` flow creates the CA, server cert, and client cert from one script.

If you do not pass explicit protocol public-key values to `make-certs`, the script may use placeholder values for certificate identity binding fields. If your final C sources strictly enforce `OU == device_pub/server_pub`, regenerate certs with the exact protocol public keys so the certificate subject fields match what the binaries verify.

---

# Inspecting State

```bash
./zk-arche.sh status
./zk-arche.sh check-server-certs
./zk-arche.sh check-client-certs
./zk-arche.sh show-pinned-key
```

---

# Reset Environment

```bash
./zk-arche.sh reset-all
```

Manual equivalents:

```bash
# Client
sudo rm -rf /var/lib/iot-auth

# Server
rm -f registry.bin registry.bak \
      server_sk.bin server_pub.bin server_pub.hex \
      server_cert.pem server_cert_key.pem ca_cert.pem ca_key.pem \
      device_cert.pem device_key.pem device.csr server.csr ca_cert.srl
```

---

# Research Notice

This project is a **research prototype** for:

- IoT authentication protocols
- Zero-knowledge identification systems
- Cross-language cryptographic interoperability
- Evaluation on constrained devices (Raspberry Pi, embedded Linux)

Not intended for production deployment without additional hardening.
