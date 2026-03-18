# HKP Dead Mode — Local Keyserver Guide

The **dead mode** HKP stub is an in-memory HTTP Keyserver Protocol (HKP)
server intended **exclusively** for local development and testing. It mirrors
the interface used by the classic MIT PGP keyserver network and modern SKS /
OpenPGP.org infrastructure, but without authentication, persistence, or any
production-grade safeguards.

> ⚠️ **Security warning**: The dead-mode server is **unauthenticated** and
> stores keys only in memory. **Never** bind it to a non-loopback interface or
> expose it beyond your local machine. See [Safety Guidance](#safety-guidance).

---

## 1. Endpoints (from `openapi_dead_pgp.yaml`)

| Method | Path | HKP `op` | Description |
|---|---|---|---|
| `GET` | `/pks/lookup` | `get` | Retrieve an ASCII-armored public key |
| `GET` | `/pks/lookup` | `index` | Human-readable key listing |
| `GET` | `/pks/lookup` | `vindex` | Verbose machine-readable listing |
| `POST` | `/pks/add` | — | Submit (import) a public key |
| `GET` | `/pks/lookup/{fingerprint}` | convenience | Retrieve key by fingerprint path |

Default port: **11371** (the registered IANA port for HKP).

### Query parameters for `/pks/lookup`

| Parameter | Required | Values | Notes |
|---|---|---|---|
| `op` | Yes | `get`, `index`, `vindex` | Operation to perform |
| `search` | Yes | `0x<fingerprint>`, `0x<keyid>`, `<email>` | Search term |
| `options` | No | `mr` | `mr` = machine-readable output |
| `fingerprint` | No | `on` / `off` | Include full fingerprint in index output |
| `exact` | No | `on` / `off` | Require exact (non-substring) match |

---

## 2. Starting the Stub Server

```bash
cd examples/hkp_stub
go run .
# Server listening on :11371
```

To use a different port:

```bash
go run . -addr :8080
```

The server prints a startup line and accepts connections immediately. Stop it
with `Ctrl-C`; all stored keys are discarded on exit.

---

## 3. Safety Guidance

### 3.1 Bind to localhost only

The stub binds to `:11371` by default, which on most systems listens on all
interfaces. **Always** restrict it to the loopback interface:

```bash
go run . -addr 127.0.0.1:11371
```

Or add a firewall rule to block external access to port 11371:

```bash
# Linux — iptables (drop connections from outside loopback)
sudo iptables -A INPUT -p tcp --dport 11371 ! -i lo -j DROP

# macOS — pf (add to /etc/pf.conf)
# block in quick proto tcp from any to any port 11371
```

### 3.2 Do not expose publicly

- The server has **no authentication** — any client that can reach port 11371
  can add or retrieve keys.
- It has **no rate limiting** — it can be trivially flooded.
- Key data is held in memory with no integrity checks.

Use the stub only in isolated local dev environments (laptop, CI sandbox).
For any shared or networked deployment, the **living mode** with authentication
and an Electoral-College policy layer is required (see
[`docs/workflows/sequenced-reveal.md`](workflows/sequenced-reveal.md)).

### 3.3 Keys are ephemeral

Keys added to the stub disappear when the process exits. Do not rely on the
stub for key distribution in any workflow that requires persistence.

---

## 4. curl Examples

### 4.1 Submit a public key (`/pks/add`)

Export your key first:

```bash
gpg --armor --export alice@example.com > alice-pubkey.asc
```

Then submit to the stub:

```bash
curl -X POST http://localhost:11371/pks/add \
  --data-urlencode "keytext@alice-pubkey.asc"
# Expected response: Key imported successfully
```

### 4.2 Retrieve a key by email — `op=get`

```bash
curl "http://localhost:11371/pks/lookup?op=get&search=alice@example.com"
```

With machine-readable flag:

```bash
curl "http://localhost:11371/pks/lookup?op=get&options=mr&search=alice@example.com"
```

### 4.3 Retrieve a key by fingerprint — `op=get`

```bash
curl "http://localhost:11371/pks/lookup?op=get&search=0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
```

Or using the convenience path endpoint:

```bash
curl "http://localhost:11371/pks/lookup/DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
```

### 4.4 List keys — `op=index`

Human-readable listing by email:

```bash
curl "http://localhost:11371/pks/lookup?op=index&search=alice@example.com"
```

With full fingerprints included:

```bash
curl "http://localhost:11371/pks/lookup?op=index&fingerprint=on&search=alice@example.com"
```

### 4.5 Verbose listing — `op=vindex`

Machine-readable verbose listing (returns `info:1:N` header):

```bash
curl "http://localhost:11371/pks/lookup?op=vindex&options=mr&search=alice@example.com"
```

---

## 5. GPG Direct HKP Usage

GnuPG can speak HKP directly:

```bash
# Send your key to the stub
gpg --keyserver hkp://localhost:11371 --send-keys <FINGERPRINT>

# Search by email
gpg --keyserver hkp://localhost:11371 --search-keys alice@example.com

# Receive a key by ID / fingerprint
gpg --keyserver hkp://localhost:11371 --recv-keys DEADBEEF
```

---

## 6. Dead Mode vs. Living Mode

| Feature | Dead mode (stub) | Living mode (future) |
|---|---|---|
| Persistence | In-memory only | Backend database / SKS sync |
| Authentication | None | API key / mTLS |
| Electoral-College veto | Disabled | Enforced |
| AI-veto policy scan | Disabled | Enforced |
| Suitable for | Local dev / testing | Production deployments |

---

## 7. OpenAPI Specification

The full OpenAPI 3.0.3 spec is at
[`openapi_dead_pgp.yaml`](../openapi_dead_pgp.yaml) in the repository root.

---

## 8. References

- [HKP draft spec (draft-shaw-openpgp-hkp-00)](https://datatracker.ietf.org/doc/html/draft-shaw-openpgp-hkp-00)
- [keys.openpgp.org](https://keys.openpgp.org) — reference production keyserver
- [`docs/HKP_COMPAT.md`](HKP_COMPAT.md) — detailed HKP compatibility notes
