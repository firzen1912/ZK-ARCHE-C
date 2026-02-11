# ZK-ARCHE (C Implementation)

Lightweight Schnorr Zero-Knowledge Mutual Authentication using
libsodium.

## Overview

This repository contains the C implementation of ZK-ARCHE, designed to
represent embedded and constrained IoT environments.

Fully interoperable with the Rust implementation.

### Cryptographic Design

-   Group: Ristretto255 (libsodium)
-   Proof System: Schnorr Zero-Knowledge Proof (Fiat--Shamir)
-   Transcript: Deterministic C-compatible transcript
-   Hash: SHA-512
-   KDF: HKDF-SHA256
-   Transport: TCP

------------------------------------------------------------------------

## Requirements

Ubuntu / Debian:

sudo apt update\
sudo apt install build-essential libsodium-dev

------------------------------------------------------------------------

## Build

gcc -O2 -std=c11 -Wall -Wextra client.c -o c_client -lsodium\
gcc -O2 -std=c11 -Wall -Wextra server.c -o c_server -lsodium

------------------------------------------------------------------------

## Run Server

./c_server --bind 0.0.0.0:4000

------------------------------------------------------------------------

## Provisioning (SETUP)

./c_client --server 127.0.0.1:4000 --setup

------------------------------------------------------------------------

## Authentication (AUTH)

./c_client --server 127.0.0.1:4000

------------------------------------------------------------------------

## Reset

rm -f device_id.bin device_x.bin registry.bin server_sk.bin

------------------------------------------------------------------------

## Research Prototype Notice

For research and interoperability demonstration purposes only.
