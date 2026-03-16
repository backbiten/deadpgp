# HKP Compatibility — Dead PGP Mode

This document describes Dead PGP's compatibility with the **HKP (HTTP Keyserver
Protocol)** as implemented by the [MIT PGP keyserver](https://pgp.mit.edu/) and
its successors (SKS, Hagrid, keys.openpgp.org).

---

## Background

The HTTP Keyserver Protocol (HKP) was defined informally in the early 1990s and
later formalised in the IETF draft
`draft-shaw-openpgp-hkp` (never published as an RFC). It specifies two
endpoints:

| Endpoint      | Method | Purpose                              |
|---------------|--------|--------------------------------------|
| `/pks/lookup` | GET    | Search for / retrieve a public key   |
| `/pks/add`    | POST   | Upload / import a public key         |

Dead PGP's **dead mode** implements the same two endpoints so that any existing
GnuPG client, Thunderbird / Enigmail, or custom tool that speaks HKP can be
pointed at a local Dead PGP instance without modification.

The OpenAPI specification for these endpoints lives at
[`openapi_dead_pgp.yaml`](../openapi_dead_pgp.yaml) in the repository root.

---

## Endpoints

### GET /pks/lookup

```
GET /pks/lookup?op=<operation>&search=<term>[&options=<flags>][&fingerprint=on][&exact=on]
```

#### Parameters

| Parameter     | Required | Description |
|---------------|----------|-------------|
| `op`          | yes      | `get` · `index` · `search` |
| `search`      | yes      | Key ID, fingerprint, UID, or email |
| `options`     | no       | Comma-separated flags (e.g. `mr` for machine-readable) |
| `fingerprint` | no       | `on` — include full fingerprint in index output |
| `exact`       | no       | `on` — disable UID substring matching |

#### Operations

| `op`     | Returns                                                    |
|----------|------------------------------------------------------------|
| `get`    | `application/pgp-keys` — ASCII-armored public key block    |
| `index`  | Key index (HTML, or plain text when `options=mr`)          |
| `search` | HTML summary listing of matching keys                      |

#### Search term formats

```
0xDEADBEEFCAFEBABE                          # 16-hex long key ID
0xDEADBEEFCAFEBABEDEADBEEFCAFEBABEDEADBEEF # 40-hex v4 fingerprint
alice@example.com                           # email address
Alice                                       # UID substring
```

---

### POST /pks/add

```
POST /pks/add
Content-Type: application/x-www-form-urlencoded

keytext=<percent-encoded-armored-key>
```

The server parses the submitted key, validates its OpenPGP structure, and stores
it locally. In Dead PGP mode there is **no peer synchronisation** — keys are
stored only on the local instance.

---

## Sample client commands

### GnuPG

```bash
# Send your public key to the local Dead PGP keyserver
gpg --keyserver hkp://localhost:11371 --send-keys <FINGERPRINT>

# Look up a key by email
gpg --keyserver hkp://localhost:11371 --search-keys alice@example.com

# Retrieve a specific key by key ID
gpg --keyserver hkp://localhost:11371 --recv-keys 0xDEADBEEFCAFEBABE
```

### curl

```bash
# Retrieve an armored key block (op=get)
curl "http://localhost:11371/pks/lookup?op=get&search=0xDEADBEEFCAFEBABE"

# Machine-readable index (op=index, options=mr)
curl "http://localhost:11371/pks/lookup?op=index&search=alice@example.com&options=mr"

# Upload a key
curl -X POST http://localhost:11371/pks/add \
  --data-urlencode "keytext@/path/to/pubkey.asc"
```

### Python (httpx / requests)

```python
import httpx

BASE = "http://localhost:11371"

# Lookup
resp = httpx.get(f"{BASE}/pks/lookup", params={"op": "get", "search": "0xDEADBEEF"})
print(resp.text)

# Upload
with open("pubkey.asc") as f:
    keytext = f.read()
resp = httpx.post(f"{BASE}/pks/add", data={"keytext": keytext})
print(resp.status_code)
```

---

## Machine-readable index format

When `op=index&options=mr`, the server returns a plain-text response with the
following structure (one record per key):

```
info:<version>:<count>
pub:<fingerprint>:<algorithm_id>:<key_length>:<creation_ts>:<expiration_ts>:<flags>
uid:<percent-encoded-uid>:<creation_ts>:<expiration_ts>:<flags>
```

Example:

```
info:1:1
pub:DEADBEEFCAFEBABE00001111222233334444AAAA:1:4096:1700000000::
uid:Alice%20%3Calice%40example.com%3E:1700000000::
```

Field notes:
- `algorithm_id`: 1=RSA, 17=DSA, 18=ECDH, 22=EdDSA (Ed25519/Ed448)
- `key_length`: 0 for ECC keys
- Timestamps: Unix epoch seconds (empty string if unknown)
- `flags`: `r` revoked · `d` disabled · `e` expired · empty = none

---

## Dead PGP mode specifics

| Behaviour                  | Dead PGP dead mode                                    |
|----------------------------|-------------------------------------------------------|
| Authentication             | **None** — endpoints are unauthenticated (local/dev)  |
| Key synchronisation        | **None** — no gossip / peer replication               |
| Validation                 | Basic OpenPGP packet syntax only                      |
| Signature verification     | Not performed                                         |
| Web-of-Trust checks        | Not performed                                         |
| Revocation propagation     | Local only                                            |
| Supported algorithms       | Any algorithm accepted by the underlying GnuPG/gpgme  |

---

## Running the stub server

A minimal Go stub server is provided in [`examples/hkp_stub/`](../examples/hkp_stub/)
for local testing. It stores keys in memory and is not suitable for production.

```bash
cd examples/hkp_stub
go run main.go            # starts on :11371 by default
go run main.go -addr :8080  # custom address
```

See [`examples/hkp_stub/main.go`](../examples/hkp_stub/main.go) for the full
source.
