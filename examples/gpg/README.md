# GPG Examples — Prerequisites and Commands

This directory contains small, self-contained shell scripts that demonstrate
common GnuPG operations aligned with the deadpgp project's security posture.

---

## Prerequisites

### GnuPG 2.1 or later

```bash
# Debian / Ubuntu
sudo apt install gnupg2

# macOS (Homebrew)
brew install gnupg

# Verify
gpg --version
# gpg (GnuPG) 2.x.x ...
```

All scripts use `gpg` (the command-line binary). GnuPG 2.1+ is required for
Ed25519 / Cv25519 (Curve25519) key generation.

### Recommended `~/.gnupg/gpg.conf` settings

```
# Prefer strong algorithms
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256

# Prefer full fingerprints over short key IDs
keyid-format 0xlong
with-fingerprint

# Do not include key ID hints in encrypted messages (metadata privacy)
# Uncomment if desired:
# throw-keyids
```

---

## Scripts in this directory

| Script | Description |
|---|---|
| [`keygen.sh`](keygen.sh) | Generate a new key pair with modern algorithm defaults |
| [`export-import.sh`](export-import.sh) | Export your public key; import someone else's |
| [`encrypt-decrypt.sh`](encrypt-decrypt.sh) | Encrypt and decrypt a file |
| [`sign-verify.sh`](sign-verify.sh) | Create and verify a detached signature |
| [`revocation.sh`](revocation.sh) | Generate and import a revocation certificate |

---

## Quick start

```bash
# 1. Generate a key pair
bash keygen.sh

# 2. Export your public key
bash export-import.sh export alice@example.com

# 3. Encrypt a file for a recipient
bash encrypt-decrypt.sh encrypt plaintext.txt bob@example.com

# 4. Decrypt a file
bash encrypt-decrypt.sh decrypt plaintext.txt.gpg

# 5. Sign a file
bash sign-verify.sh sign report.pdf alice@example.com

# 6. Verify a signature
bash sign-verify.sh verify report.pdf report.pdf.sig

# 7. Generate a revocation certificate
bash revocation.sh <FINGERPRINT>
```

---

## Security notes

- These scripts are **examples** intended for local testing and learning. Review
  them before using in any production or sensitive context.
- Never commit private keys, passphrases, or sensitive plaintext to version
  control.
- For passphrase management, use `gpg-agent` (started automatically by GnuPG
  2.1+) and a secure password manager for the passphrase itself.
- See [`docs/crypto-basics.md`](../../docs/crypto-basics.md) for algorithm
  guidance, offline primary key advice, and metadata caveats.
