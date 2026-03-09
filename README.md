# ZK-ARCHE (C Implementation)

Lightweight **Zero-Knowledge Proof Mutual Authentication** for IoT devices using **libsodium**.

This C implementation targets **embedded / constrained environments** and is **fully interoperable with the Rust ZK-ARCHE implementation**.

The system supports **Zero-Touch Provisioning (ZTP)** for device onboarding and **Schnorr-based authentication** for secure operation.

---

# Architecture

| Component              | Role                         |
| ---------------------- | ---------------------------- |
| Raspberry Pi 3 / 4 / 5 | Provers (IoT devices)        |
| Ubuntu Server          | Verifier                     |
| Bootstrap Registry     | Device provisioning database |
| Device Root Secret     | Persistent device identity   |

---

# Cryptographic Design

| Primitive   | Algorithm              |
| ----------- | ---------------------- |
| Group       | Ristretto255           |
| ZKP         | Schnorr Identification |
| Fiat-Shamir | SHA-512                |
| KDF         | HKDF-SHA256            |
| AEAD        | ChaCha20-Poly1305      |
| Transport   | TCP                    |
| Library     | libsodium              |

---

# Security Model

The protocol separates **two identities**:

### 1️⃣ Bootstrap Identity (Provisioning)

Used **once during Zero-Touch Provisioning**.

Device proves knowledge of:

```
bootstrap_secret
```

Server validates against:

```
bootstrap_registry.bin
```

Used to securely enroll the device.

---

### 2️⃣ Operational Identity (Authentication)

Derived from:

```
device_root.bin
```

The client derives:

```
device_id
device_private_scalar x
device_public_key = G * x
```

Authentication uses a **Schnorr ZKP** proving knowledge of `x`.

---

# File Layout

## Client (Raspberry Pi)

```
/var/lib/iot-auth/

device_root.bin
bootstrap_id.bin
bootstrap_secret.bin
server_pub.bin
```

| File                 | Purpose                       |
| -------------------- | ----------------------------- |
| device_root.bin      | persistent device root secret |
| bootstrap_id.bin     | provisioning identifier       |
| bootstrap_secret.bin | bootstrap credential          |
| server_pub.bin       | pinned verifier public key    |

---

## Server (Verifier)

```
registry.bin
server_sk.bin
bootstrap_registry.bin
```

| File                   | Purpose                       |
| ---------------------- | ----------------------------- |
| registry.bin           | enrolled devices              |
| server_sk.bin          | verifier secret key           |
| bootstrap_registry.bin | allowed bootstrap credentials |

---

# Install Dependencies

Ubuntu / Raspberry Pi OS

```bash
sudo apt update
sudo apt install build-essential libsodium-dev
```

---

# Compile

Compile client:

```bash
gcc -O2 -std=c11 -Wall -Wextra client.c -o c_client -lsodium
```

Compile server:

```bash
gcc -O2 -std=c11 -Wall -Wextra server.c -o c_server -lsodium
```

---

# Server Setup

## 1️⃣ Add Bootstrap Credentials

Each device must have a **unique bootstrap credential**.

Generate credentials:

```bash
BOOTSTRAP_ID=$(openssl rand -hex 16)
BOOTSTRAP_SECRET=$(openssl rand -hex 32)
```

Register them on the server:

```bash
./c_server --add-bootstrap $BOOTSTRAP_ID $BOOTSTRAP_SECRET
```

---

## 2️⃣ Start Verifier

Enable provisioning window:

```bash
./c_server --bind 0.0.0.0:4000 --pairing
```

Without `--pairing`, setup is rejected.

---

# Device Provisioning (ZTP)

Before setup, the client must be provisioned with:

```
bootstrap_id
bootstrap_secret
server_pub
```

Provision bootstrap credential:

```bash
./c_client --provision-bootstrap <bootstrap_id_hex> <bootstrap_secret_hex>
```

Pin verifier public key:

```bash
./c_client --pin-server-pub <server_pub_hex>
```

Run provisioning:

```bash
./c_client --server <server_ip>:4000 --setup
```

After successful provisioning the device is enrolled.

---

# Authentication

Once enrolled, devices authenticate normally:

```bash
./c_client --server <server_ip>:4000
```

Authentication uses:

```
Schnorr Zero Knowledge Proof
```

and an encrypted transport tunnel.

---

# Example Deployment

Verifier:

```
Ubuntu Server
192.168.1.10
```

Provers:

```
Raspberry Pi 3  -> 192.168.1.101
Raspberry Pi 4  -> 192.168.1.102
Raspberry Pi 5  -> 192.168.1.103
```

Provision each device once, then authenticate repeatedly.

---

# Reset Environment

Client reset:

```bash
sudo rm -rf /var/lib/iot-auth
```

Server reset:

```bash
rm -f registry.bin bootstrap_registry.bin server_sk.bin
```

---

# Research Notice

This project is a **research prototype** for:

* IoT authentication
* Zero-knowledge identification protocols
* cross-language cryptographic interoperability
* evaluation on constrained devices

Not intended for production deployment without additional hardening.

