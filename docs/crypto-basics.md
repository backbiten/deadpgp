# Cryptography Basics for deadpgp

This document provides a concise threat-modeling primer, explains the difference
between transport-layer and application-level encryption, and gives practical
OpenPGP/GnuPG guidance that aligns with the deadpgp project's goals.

---

## 1. Threat-Modeling Primer

Before choosing a cryptographic tool, ask:

| Question | What it shapes |
|---|---|
| **Who is the adversary?** | Passive eavesdropper, active MITM, insider threat, cloud provider? |
| **What is the asset?** | Data in transit, data at rest, keys, metadata? |
| **What is the impact of failure?** | Confidentiality breach, integrity loss, non-repudiation loss? |
| **What are your trust boundaries?** | Who controls the key material, the storage layer, the transport? |

**Key insight for deadpgp**: the system is designed to protect *data at rest* and
to govern *when and whether* a secret is revealed. TLS protects data *in motion*
between two live endpoints; OpenPGP protects data *independently of any network
session*.

---

## 2. TLS vs. OpenPGP — Different Jobs

| Property | TLS | OpenPGP |
|---|---|---|
| Protects | Data in transit | Data at rest / async messages |
| Trust root | CA certificate hierarchy | Web of trust / direct key exchange |
| Session lifetime | Ephemeral (PFS with ECDHE) | Long-lived key pairs |
| Authentication | Mutual TLS (mTLS) or server-only | Digital signatures by key fingerprint |
| Key storage | Handled by the TLS library | User/application responsibility |
| Metadata hidden? | Mostly (SNI leaks hostname) | **No** — see §5 |

> **Rule of thumb**: Use TLS for protecting a live connection. Use OpenPGP
> (or equivalent) when the sender and receiver are not simultaneously online, or
> when data must be independently verifiable long after transmission.

---

## 3. OpenPGP Best Practices

### 3.1 Offline primary key

Your **primary key** (the certification key) should be generated on an
air-gapped machine and kept offline (encrypted backup, hardware token, or
offline USB drive). Only **subkeys** should live on everyday devices.

```
[offline] primary key (certify/sign)
    └── [online]  signing subkey
    └── [online]  encryption subkey
    └── [online]  authentication subkey (optional)
```

If an online subkey is compromised you can revoke it without losing your
primary identity. If your primary key is compromised, your entire identity
must be rebuilt.

### 3.2 Signing vs. encryption subkeys

| Subkey type | Capability flag | Purpose |
|---|---|---|
| Signing | `S` | Detached signatures, certification |
| Encryption | `E` | Encrypting messages to you |
| Authentication | `A` | SSH / agent authentication |

Use **separate subkeys** for each capability. This limits blast radius if one
subkey is exposed.

### 3.3 Revocation certificate

Generate a revocation certificate *immediately* after key creation and store
it safely **offline**:

```bash
gpg --output revoke-<FINGERPRINT>.asc --gen-revoke <FINGERPRINT>
```

If your key is ever compromised or lost, import the revocation certificate to
notify others:

```bash
gpg --import revoke-<FINGERPRINT>.asc
gpg --keyserver hkps://keys.openpgp.org --send-keys <FINGERPRINT>
```

### 3.4 Passphrases

- Use a strong, randomly generated passphrase (e.g., 6-word diceware).
- Store it in a password manager or write it down and keep it physically secure.
- Never store the passphrase in plaintext on the same machine as the key.

### 3.5 Key rotation

- Set an expiry date on subkeys (1–2 years is common).
- Rotate the encryption subkey before expiry; keep the old one to decrypt old
  messages.
- A primary key expiry is optional but acts as a dead-man's switch if you stop
  maintaining the key.

---

## 4. Algorithm Guidance

### Preferred (modern)

| Use case | Algorithm | Notes |
|---|---|---|
| Primary key | Ed25519 | EdDSA on Curve25519; fast, small, strong |
| Encryption subkey | Cv25519 (X25519) | ECDH; PFS-friendly |
| Signing subkey | Ed25519 | Same curve as primary |
| Symmetric | AES-256-GCM | or ChaCha20-Poly1305 where supported |
| Hash (signatures) | SHA-256 / SHA-512 | |

GnuPG 2.1+ generates Ed25519 + Cv25519 keys with `--quick-gen-key` and the
`future-default` preset.

### Acceptable fallback (interoperability)

| Use case | Algorithm | Notes |
|---|---|---|
| RSA key | RSA-3072 or RSA-4096 | Minimum 3072-bit; prefer 4096 for new keys |
| Symmetric fallback | AES-256 (CBC with MDC) | Only if AEAD is not supported |

### Avoid

| Algorithm | Reason |
|---|---|
| RSA-1024 or RSA-2048 | Too small; 1024-bit is broken, 2048-bit is marginal |
| SHA-1 | Collision attacks demonstrated; avoid in new signatures |
| 3DES / CAST5 | Legacy ciphers; prefer AES |
| MD5 | Broken; never use for cryptographic purposes |
| DSA-1024 | Too small; deprecated |

> **GnuPG config tip**: Add the following to `~/.gnupg/gpg.conf` to prefer
> strong algorithms:
>
> ```
> personal-cipher-preferences AES256 AES192 AES
> personal-digest-preferences SHA512 SHA384 SHA256
> personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
> default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
> cert-digest-algo SHA512
> s2k-digest-algo SHA512
> s2k-cipher-algo AES256
> ```

---

## 5. Metadata Caveats

OpenPGP encryption **does not** hide:

- **Who is communicating with whom** — key IDs / UIDs are visible in the
  encrypted message header unless you use `--throw-keyids`.
- **When** a message was sent (timestamps in packets).
- **How often** parties communicate (traffic analysis).
- **File size / message length** (padding is not built in).

If hiding communication metadata matters, use additional layers:
- `gpg --throw-keyids` hides recipient key IDs (recipient must try all their
  keys).
- Route messages over Tor or I2P to hide IP-level metadata.
- Consider an anonymous transport (Signal, Cwtch, etc.) for real-time chat.

---

## 6. Further Reading

- [OpenPGP Best Practices (riseup.net)](https://riseup.net/en/security/message-security/openpgp/best-practices)
- [GnuPG documentation](https://www.gnupg.org/documentation/)
- [RFC 4880 — OpenPGP Message Format](https://www.rfc-editor.org/rfc/rfc4880)
- [RFC 9580 — OpenPGP (v6)](https://www.rfc-editor.org/rfc/rfc9580) *(draft standard)*
- [`docs/SPEC.md`](SPEC.md) — deadpgp protocol specification
