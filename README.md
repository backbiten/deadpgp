# deadpgp

**DeadPGP** is a modern, beginner-friendly encryption tool inspired by PGP.  
It borrows the *armored block* format (paste into email!) and fingerprint UX  
from PGP, while using audited, modern cryptography under the hood.

> "Dead encryption is not living — it's just useless beyond regard."  
> It looks simple on the surface, but solid crypto powers it underneath.

---

## Features

- **Public-key encryption** — encrypt to a recipient's X25519 public key
- **Password encryption** — simple password-based sharing (Argon2id KDF)
- **Email-friendly armored output** — copy/paste blocks into any message
- **Beginner-friendly CLI** — three commands: `keygen`, `encrypt`, `decrypt`
- **Safe defaults** — no insecure algorithm options in v1

## Cryptographic profile

| Function         | Algorithm                    |
|------------------|------------------------------|
| Key exchange     | X25519                       |
| Key derivation   | HKDF-SHA-256                 |
| AEAD cipher      | ChaCha20-Poly1305            |
| Password KDF     | Argon2id (scrypt as fallback)|
| Key fingerprint  | SHA-256 of raw public key    |

---

## Installation

```bash
pip install deadpgp
```

Or from source:

```bash
git clone https://github.com/backbiten/deadpgp.git
cd deadpgp
pip install .
```

---

## Quick start

### 1. Generate a keypair

```bash
deadpgp keygen --name alice
```

Output:

```
Generated new X25519 keypair
  Fingerprint : 38bcb63b562d3a0f...
  Private key : alice.key
  Public key  : alice.pub
```

Share `alice.pub` with anyone who wants to send you encrypted messages.  
Keep `alice.key` private and never share it.

---

### 2. Encrypt a message (public-key mode)

```bash
# Encrypt a file to Alice
deadpgp encrypt --to alice.pub message.txt > message.dpgp

# Or pipe from stdin
echo "Hello, Alice!" | deadpgp encrypt --to alice.pub > message.dpgp
```

The output looks like:

```
-----BEGIN DEADPGP MESSAGE-----
Version: 1
Mode: pubkey
To: 38bcb63b562d3a0feef576e4f41bee5e1ce5411e2a256e69ac2b874bda2f8feb
EphemeralKey: RUcGcHWFu8o0rO16...
Nonce: zIoTmoNjgt7QASc8

EgSe6Y2J42POXR/IliyBbQ3i+O3JtN4+K5guja+OVXSgeM2tXlr...
-----END DEADPGP MESSAGE-----
```

Paste this block into an email, forum post, or chat message.

---

### 3. Decrypt a message (public-key mode)

```bash
# From a file
deadpgp decrypt --identity alice.key message.dpgp

# From stdin (paste the block)
deadpgp decrypt --identity alice.key < message.dpgp
```

---

### 4. Password-based encryption

Useful for quick sharing where you can't exchange public keys first:

```bash
# Encrypt
echo "Quick secret" | deadpgp encrypt --password > secret.dpgp
# (you will be prompted for a password)

# Decrypt
deadpgp decrypt secret.dpgp
# (password-mode is auto-detected; you will be prompted)
```

---

## Key files

Key files are plain JSON:

**Public key (`alice.pub`)**:
```json
{
  "version": 1,
  "type": "x25519",
  "fingerprint": "38bcb63b562d3a0feef576e4f41bee5e1ce5411e2a256e69ac2b874bda2f8feb",
  "public_key": "..."
}
```

**Private key (`alice.key`)** — additionally contains `"private_key"`.  
The file is created with `chmod 600` (readable only by you).

---

## Armored message format

### Public-key mode

```
-----BEGIN DEADPGP MESSAGE-----
Version: 1
Mode: pubkey
To: <recipient SHA-256 fingerprint (hex)>
EphemeralKey: <base64 ephemeral X25519 public key>
Nonce: <base64 12-byte nonce>

<base64 ciphertext + 16-byte Poly1305 authentication tag>
-----END DEADPGP MESSAGE-----
```

### Password mode

```
-----BEGIN DEADPGP MESSAGE-----
Version: 1
Mode: password-argon2id
Salt: <base64 16-byte random salt>
Params: t=3,m=65536,p=4
Nonce: <base64 12-byte nonce>

<base64 ciphertext + 16-byte Poly1305 authentication tag>
-----END DEADPGP MESSAGE-----
```

---

## CLI reference

```
deadpgp keygen [--name NAME] [--out DIR]
deadpgp encrypt (--to PUBKEY | --password) [--out FILE] [FILE]
deadpgp decrypt (--identity KEY | --password) [--out FILE] [FILE]
```

| Option | Description |
|---|---|
| `keygen --name NAME` | Base name for output files (default: short fingerprint) |
| `keygen --out DIR` | Directory to write key files |
| `encrypt --to FILE` | Recipient's public key file |
| `encrypt --password` | Use password-based encryption |
| `encrypt --out FILE` | Write output to file instead of stdout |
| `decrypt --identity FILE` | Your private key file |
| `decrypt --password` | Force password-mode decryption prompt |
| `decrypt --out FILE` | Write decrypted output to file instead of stdout |

---

## Development

```bash
pip install -e "."
pytest tests/ -v
```

---

## License

EPL-2.0 — see [LICENSE](LICENSE).
