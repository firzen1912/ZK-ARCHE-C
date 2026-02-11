# ZK-ARCHE (C Implementation)

Lightweight Schnorr Zero-Knowledge Mutual Authentication using
libsodium.

------------------------------------------------------------------------

## Overview

C implementation of ZK-ARCHE representing embedded/legacy IoT
environments.

Fully interoperable with Rust implementation.

### Cryptographic Design

-   Group: Ristretto255 (libsodium)
-   Proof System: Schnorr ZKP (Fiat--Shamir)
-   Transcript: Deterministic C-compatible transcript
-   Hash: SHA-512
-   KDF: HKDF-SHA256
-   Transport: TCP

------------------------------------------------------------------------

## 1. Install Dependencies (Ubuntu / Raspberry Pi OS)

``` bash
sudo apt update
sudo apt install build-essential libsodium-dev
```

------------------------------------------------------------------------

## 2. Compile

Compile client:

``` bash
gcc -O2 -std=c11 -Wall -Wextra client.c -o c_client -lsodium
```

Compile server:

``` bash
gcc -O2 -std=c11 -Wall -Wextra server.c -o c_server -lsodium
```

------------------------------------------------------------------------

## 3. Run Server

``` bash
./c_server --bind 0.0.0.0:4000
```

------------------------------------------------------------------------

## 4. Provision Device (SETUP)

``` bash
./c_client --server 127.0.0.1:4000 --setup
```

------------------------------------------------------------------------

## 5. Authenticate (AUTH)

``` bash
./c_client --server 127.0.0.1:4000
```

------------------------------------------------------------------------

## 6. Reset Environment

``` bash
rm -f device_id.bin device_x.bin registry.bin server_sk.bin
```

------------------------------------------------------------------------

## Research Notice

Research prototype for interoperability and evaluation purposes.
