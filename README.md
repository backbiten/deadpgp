# deadpgp

Forking old forgotten PGP protocols used in the 1980s and 1990s that are useful and purposeful in the modern 21st Century

## Overview

**deadpgp** revamps the classic PGP (Pretty Good Privacy) protocol with modern, audited cryptographic primitives while preserving the familiar workflow of key generation, hybrid encryption, digital signing, and ASCII-armor encoding.

| Classic PGP | deadpgp |
|---|---|
| RSA with PKCS#1 v1.5 padding | RSA-OAEP (SHA-256) or ECDH / X25519 |
| IDEA / 3DES symmetric cipher | AES-256-GCM (authenticated encryption) |
| MD5 / SHA-1 hashing | SHA-256 / SHA-512 |
| DSA + SHA-1 signing | RSA-PSS, ECDSA, or Ed25519 |

## Requirements

- Python ≥ 3.10
- [`cryptography`](https://cryptography.io) ≥ 41.0

## Installation

```bash
pip install .
```

## Command-line usage

### Key generation

```bash
# RSA-4096 (default)
deadpgp keygen --type rsa --output mykey

# RSA-2048 with passphrase
deadpgp keygen --type rsa --bits 2048 --passphrase "hunter2" --output mykey

# Elliptic-curve (NIST P-256)
deadpgp keygen --type ec --curve secp256r1 --output eckey

# Ed25519 (signing only)
deadpgp keygen --type ed25519 --output edkey

# X25519 (encryption only)
deadpgp keygen --type x25519 --output dhkey
```

This creates `<output>.pem` (private key) and `<output>.pub` (public key).

### Encryption

```bash
deadpgp encrypt --recipient mykey.pub plaintext.txt
# → plaintext.txt.dpgp

deadpgp encrypt --recipient mykey.pub --output encrypted.dpgp plaintext.txt
```

### Decryption

```bash
deadpgp decrypt --key mykey.pem encrypted.dpgp
# → encrypted (stripped of .dpgp suffix)

deadpgp decrypt --key mykey.pem --output plaintext.txt encrypted.dpgp
```

### Signing

```bash
deadpgp sign --key mykey.pem plaintext.txt
# → plaintext.txt.sig
```

### Verification

```bash
deadpgp verify --key mykey.pub plaintext.txt plaintext.txt.sig
# Prints: Signature valid.
# Exits with code 1 if the signature is invalid.
```

## Python API

```python
from deadpgp import (
    generate_rsa_keypair,
    generate_ec_keypair,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    encrypt,
    decrypt,
    sign,
    verify,
)
from deadpgp.armor import armor, dearmor, ARMOR_MESSAGE, ARMOR_SIGNATURE

# Key generation
priv, pub = generate_rsa_keypair(4096)

# Encrypt / decrypt
ciphertext = encrypt(b"secret message", pub)
plaintext  = decrypt(ciphertext, priv)

# Sign / verify
signature = sign(b"important document", priv)
assert verify(b"important document", signature, pub)

# ASCII armor
armored = armor(ciphertext, ARMOR_MESSAGE)
raw, typ = dearmor(armored)
```

## Running tests

```bash
pip install ".[dev]"
pytest
```

## Cryptographic design

### Hybrid encryption

1. A random 256-bit session key is generated (or derived via HKDF for ECDH/X25519).
2. For RSA: the session key is wrapped with RSA-OAEP (SHA-256 hash, MGF1-SHA-256 mask).  
   For EC / X25519: an ephemeral key-agreement is performed and the shared secret is passed through HKDF-SHA-256 to derive the session key.
3. The plaintext is encrypted with AES-256-GCM using a random 96-bit nonce, providing both confidentiality and integrity.

### Digital signatures

- **RSA keys** → RSA-PSS with SHA-256 and maximum salt length.
- **NIST EC keys** → ECDSA with SHA-256.
- **Ed25519 keys** → deterministic EdDSA (no hash needed; Ed25519 uses SHA-512 internally).

### ASCII armor

The wire format mirrors PGP ASCII armor (RFC 4880 §6): Base64-encoded body wrapped between `-----BEGIN DEADPGP <TYPE>-----` / `-----END DEADPGP <TYPE>-----` headers with a CRC-24 checksum line.
