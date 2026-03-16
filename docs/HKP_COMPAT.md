# HKP Compatibility in Dead PGP Mode

This document describes how Dead PGP exposes an HKP-compatible keyserver interface
when operating in **dead (local/dev) mode**, and provides sample client commands for
interacting with it.

---

## What is HKP?

HKP (HTTP Keyserver Protocol) is the protocol originally designed by MIT's PGP
Keyserver project and later adopted by most OpenPGP keyservers (e.g., keys.openpgp.org,
SKS keyserver pool). It exposes key material over plain HTTP using two primary endpoints:

| Endpoint      | Method | Purpose                              |
|---------------|--------|--------------------------------------|
| `/pks/lookup` | GET    | Search for / retrieve a public key   |
| `/pks/add`    | POST   | Submit a new public key to the store |

Dead PGP implements a **local-only** variant of HKP that stores keys in memory (or on
disk, depending on configuration). It intentionally **never contacts external keyservers**.

---

## Running the Local HKP Stub

A simple reference implementation is provided in `examples/hkp_stub/`. To run it:

```bash
cd examples/hkp_stub
go run .
# Server starts on http://localhost:11371
```

The stub server stores submitted keys in memory and supports `op=get` and `op=index`
lookups against them.

---

## Dead Mode vs. Living Mode

| Feature                     | Dead Mode (local)          | Living Mode (networked)          |
|-----------------------------|----------------------------|----------------------------------|
| External keyserver sync     | ❌ Never                   | ✅ Yes (configurable peers)      |
| Authentication required     | ❌ No                      | ✅ Recommended                   |
| Key persistence             | In-memory / local file     | Database (PostgreSQL / SQLite)   |
| SKS reconciliation          | ❌ Not implemented         | ✅ Optional                      |
| Intended environment        | Local dev / air-gapped     | Production / shared keyserver    |

> **Warning:** The dead-mode stub leaves endpoints completely unauthenticated.
> Do **not** expose it on a public or shared network.

---

## Sample Client Commands

All examples assume the stub is running on `http://localhost:11371`.

### gpg — submit a key

```bash
gpg --keyserver hkp://localhost:11371 --send-keys <FINGERPRINT>
```

### gpg — retrieve a key

```bash
gpg --keyserver hkp://localhost:11371 --recv-keys <KEY_ID>
```

### gpg — search by email

```bash
gpg --keyserver hkp://localhost:11371 --search-keys alice@example.com
```

### curl — retrieve a key (machine-readable)

```bash
curl "http://localhost:11371/pks/lookup?op=get&search=0xDEADBEEFCAFEBABE&options=mr"
```

### curl — list keys matching an email (verbose index)

```bash
curl "http://localhost:11371/pks/lookup?op=vindex&search=alice@example.com&fingerprint=on&options=mr"
```

### curl — submit a key

```bash
# Export ASCII-armored key and URL-encode the keytext field
KEYTEXT=$(gpg --armor --export alice@example.com | python3 -c \
  "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")

curl -X POST http://localhost:11371/pks/add \
     -H "Content-Type: application/x-www-form-urlencoded" \
     --data-urlencode "keytext@-" <<< "$(gpg --armor --export alice@example.com)"
```

Or using `gpg --send-keys` as shown above (gpg handles encoding automatically).

---

## HKP Machine-Readable Index Format

When `options=mr` is set and `op=index` or `op=vindex` is requested, the server
returns a text/plain response in the standard HKP machine-readable format:

```
info:<version>:<count>
pub:<keyid>:<algo>:<keylen>:<creationdate>:<expirationdate>:<flags>
uid:<escaped_uid>:<creationdate>:<expirationdate>:<flags>
```

Example:

```
info:1:1
pub:DEADBEEFCAFEBABE:1:4096:1609459200::
uid:Alice <alice@example.com>:1609459200::
```

Field descriptions:

| Field            | Description                                                                    |
|------------------|--------------------------------------------------------------------------------|
| `keyid`          | 16 hex-character key ID                                                        |
| `algo`           | OpenPGP public-key algorithm ID (RFC 4880 §9.1). Common values: 1 = RSA,      |
|                  | 17 = DSA, 18 = ECDH, 19 = ECDSA. EdDSA (Ed25519) uses algorithm 22 per the    |
|                  | RFC 6637 / draft-ietf-openpgp-rfc4880bis extension.                            |
| `keylen`         | Key length in bits (e.g., 4096 for RSA-4096, 256 for Ed25519)                 |
| `creationdate`   | Unix timestamp of key creation                                                 |
| `expirationdate` | Unix timestamp of expiry, or empty if none                                     |
| `flags`          | `r` = revoked, `d` = disabled, `e` = expired                                  |

---

## OpenAPI Specification

A full OpenAPI 3.0.3 specification for the Dead PGP HKP-compatible API is provided
at the repository root as [`openapi_dead_pgp.yaml`](../openapi_dead_pgp.yaml).

You can explore it interactively with Swagger UI or Redoc:

```bash
# Using npx (requires Node.js)
npx @redocly/cli preview-docs ../openapi_dead_pgp.yaml

# Or open in Swagger Editor
open https://editor.swagger.io/
# Then File → Import URL or paste the YAML content
```

---

## Security Considerations

1. **Dead mode is for local / air-gapped use only.** The stub has no authentication,
   no rate limiting, and no spam/abuse protection.

2. **Key material is stored in memory** by the stub server and is lost when the process
   exits. For persistent storage, integrate with a local GPG keyring or SQLite database.

3. **Never submit private key material** to any HKP endpoint — HKP is designed for
   *public* keys only.

4. If you need a hardened local keyserver for production internal use, consider
   [Hockeypuck](https://github.com/hockeypuck/hockeypuck) or
   [keys.openpgp.org](https://keys.openpgp.org/) (Hagrid) instead.
