# HKP Compatibility in Dead PGP Mode

Dead PGP exposes an **HKP (HTTP Keyserver Protocol)** compatible interface for
local development and testing. HKP is the protocol used by the original MIT PGP
keyserver network (and the modern SKS / OpenPGP.org keyserver ecosystem).

> **Dead mode only** — the stub server stores keys in memory and is intentionally
> unauthenticated. Do **not** expose it on a public network interface.

---

## Endpoints

| Method | Path                        | HKP op      | Description                      |
|--------|-----------------------------|-------------|----------------------------------|
| `GET`  | `/pks/lookup`               | `get`       | Retrieve an ASCII-armored key    |
| `GET`  | `/pks/lookup`               | `index`     | Human-readable key listing       |
| `GET`  | `/pks/lookup`               | `vindex`    | Machine-readable key listing     |
| `POST` | `/pks/add`                  | —           | Submit a public key              |
| `GET`  | `/pks/lookup/{fingerprint}` | convenience | Retrieve key by fingerprint path |

Default port: **11371** (the registered IANA port for HKP).

---

## Starting the stub server

```bash
cd examples/hkp_stub
go run .
# Server listening on :11371
```

To use a different port:

```bash
go run . -addr :8080
```

---

## Sample client commands

### GPG — direct HKP lookup

```bash
# Search by email (returns human-readable index)
gpg --keyserver hkp://localhost:11371 --search-keys alice@example.com

# Retrieve by key-ID
gpg --keyserver hkp://localhost:11371 --recv-keys DEADBEEF

# Send a local key to the stub
gpg --keyserver hkp://localhost:11371 --send-keys <FINGERPRINT>
```

### curl — raw HKP requests

```bash
# Retrieve a key (op=get, machine-readable, search by fingerprint)
curl "http://localhost:11371/pks/lookup?op=get&options=mr&search=0xDEADBEEFDEADBEEF"

# Search by email (op=index)
curl "http://localhost:11371/pks/lookup?op=index&search=alice@example.com"

# Verbose index (machine-readable)
curl "http://localhost:11371/pks/lookup?op=vindex&options=mr&search=alice@example.com"

# Submit a key (keytext must be form-encoded)
curl -X POST http://localhost:11371/pks/add \
  --data-urlencode "keytext@/path/to/pubkey.asc"

# Convenience path (non-standard, for tooling that prefers path params)
curl "http://localhost:11371/pks/lookup/DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
```

### Python — using `requests`

```python
import requests, urllib.parse

BASE = "http://localhost:11371"

# Retrieve a key
resp = requests.get(f"{BASE}/pks/lookup", params={
    "op": "get",
    "options": "mr",
    "search": "0xDEADBEEFDEADBEEF",
})
print(resp.text)

# Submit a key
with open("pubkey.asc") as fh:
    armored = fh.read()
resp = requests.post(f"{BASE}/pks/add", data={"keytext": armored})
print(resp.status_code, resp.text)
```

---

## Dead mode vs. Living mode

| Feature                  | Dead mode (this stub) | Living mode (future)          |
|--------------------------|-----------------------|-------------------------------|
| Persistence              | In-memory only        | Backend database / SKS sync   |
| Authentication           | None                  | API key / mTLS                |
| Electoral-College veto   | Disabled              | Enforced                      |
| AI-veto policy scan      | Disabled              | Enforced                      |
| Suitable for             | Local dev / testing   | Production deployments        |

---

## OpenAPI spec

The full OpenAPI 3.0.3 spec for Dead PGP mode (including HKP endpoints) is at
[`openapi_dead_pgp.yaml`](../openapi_dead_pgp.yaml) in the repository root.

---

## Notes

- The HKP protocol is informally documented in
  [draft-shaw-openpgp-hkp-00](https://datatracker.ietf.org/doc/html/draft-shaw-openpgp-hkp-00).
- Key parsing in the stub is intentionally minimal — it looks for the
  `-----BEGIN PGP PUBLIC KEY BLOCK-----` / `-----END PGP PUBLIC KEY BLOCK-----`
  delimiters and stores the raw armored text. Full OpenPGP parsing is out of scope
  for the stub.
- The stub does not implement `op=x-*` vendor extensions.
