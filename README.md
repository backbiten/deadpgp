# deadpgp

Old PGP protocols from the 1980s and 1990s, reinvented for the modern 21st century.

**deadpgp** is a Python library and command-line tool that takes the design ideas that made PGP great — hybrid encryption, digital signatures, and ASCII-armoured output — and rebuilds them on a foundation of modern, secure cryptographic primitives.

---

## Features

| Classic PGP idea | deadpgp implementation |
|---|---|
| Hybrid encryption (session key + public-key wrap) | RSA-OAEP (SHA-256) + AES-256-GCM |
| Digital signatures | RSA-PSS (SHA-256) |
| ASCII armor with CRC-24 checksum | RFC 4880 §6 compatible armor |
| Passphrase-protected private keys | PKCS#8 + AES-256-CBC + PBKDF2 |

---

## Requirements

- Python ≥ 3.9
- [cryptography](https://cryptography.io/) ≥ 41.0

---

## Installation

```bash
pip install deadpgp
```

---

## Quick start

### Generate a key pair

```bash
deadpgp keygen --out alice
# Produces alice.key (private) and alice.pub (public)
```

Generate with a passphrase-protected private key:

```bash
deadpgp keygen --out alice --passphrase "my secret"
```

### Encrypt a file

```bash
deadpgp encrypt --recipient alice.pub --in plaintext.txt --out message.asc
```

### Decrypt a message

```bash
deadpgp decrypt --key alice.key --in message.asc --out plaintext.txt
```

### Sign a file

```bash
deadpgp sign --key alice.key --in document.pdf --out document.sig.asc
```

### Verify a signature

```bash
deadpgp verify --key alice.pub --in document.pdf --sig document.sig.asc
```

---

## Python API

```python
from deadpgp import (
    generate_keypair,
    export_public_key, export_private_key,
    load_public_key, load_private_key,
    encrypt, decrypt,
    sign, verify,
    armor, dearmor,
)

# Key generation
private_key, public_key = generate_keypair(key_size=4096)

# Export / import
pub_pem = export_public_key(public_key)
priv_pem = export_private_key(private_key, password=b"passphrase")

# Encryption / decryption
ciphertext = encrypt(b"secret message", public_key)
plaintext = decrypt(ciphertext, private_key)

# Signing / verification
signature = sign(b"document bytes", private_key)
verify(b"document bytes", signature, public_key)   # raises on failure

# ASCII armor
armored = armor(ciphertext, "MESSAGE")
data, armor_type = dearmor(armored)
```

---

## Wire format

### Encrypted message

```
[4 bytes BE] length of RSA-encrypted session key
[N bytes]    RSA-OAEP encrypted AES-256 session key
[12 bytes]   AES-GCM nonce
[remaining]  AES-256-GCM ciphertext + 16-byte authentication tag
```

### Signature

```
[4 bytes BE] signature length
[N bytes]    RSA-PSS signature
```

Both blobs are wrapped in ASCII armor for transport.

---

## Running the tests

```bash
pip install pytest
pytest
```

---

## Background

PGP (Pretty Good Privacy) was created by Phil Zimmermann in 1991. It introduced
the idea of hybrid encryption — using a fast symmetric cipher for the bulk data
and a slow asymmetric cipher to protect the symmetric key — and popularised the
"web of trust" key model. The original protocols used RSA, IDEA, and MD5/SHA-1.

**deadpgp** keeps that same hybrid architecture but replaces the ageing
primitives with their modern equivalents:

- IDEA → AES-256-GCM (authenticated encryption prevents tampering)
- PKCS#1 v1.5 → OAEP (provably secure RSA encryption padding)
- RSA + PKCS#1 v1.5 signatures → RSA-PSS (stronger security proof)
- MD5 / SHA-1 → SHA-256

The result is a minimal, auditable implementation that can serve as a teaching
tool, a migration path for legacy systems, or the foundation for further
experimentation.
