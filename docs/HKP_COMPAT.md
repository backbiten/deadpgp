# HKP Compatibility in Dead PGP Mode

This document describes the HKP (HTTP Keyserver Protocol) compatibility layer
implemented for **Dead PGP mode** — a local/dev-only in-memory keyserver.

---

## What is HKP?

HKP is the protocol originally developed at MIT to allow HTTP-based access to
PGP public keyservers. It defines two main endpoints:

| Endpoint        | Method | Description                         |
|-----------------|--------|-------------------------------------|
| `/pks/lookup`   | GET    | Retrieve or index keys              |
| `/pks/add`      | POST   | Submit a new public key             |

The standard HKP port is **11371** (TCP), though any port can be used.

---

## Dead Mode vs. Living Mode

| Feature                        | Dead Mode (this stub)     | Living Mode              |
|-------------------------------|--------------------------|--------------------------|
| Key persistence               | In-memory only           | Persistent database      |
| Authentication                | None                     | Signed tokens / policies |
| Key synchronization           | None                     | Peer gossip protocol     |
| Intended use                  | Local testing / CI       | Production               |
| Electoral College approval    | Bypassed                 | Required                 |
| AI-veto policy checks         | Skipped                  | Enforced                 |

> **Warning**: Dead mode endpoints are intentionally unauthenticated. Do **not**
> expose this server to a public network.

---

## Running the HKP Stub Server

The stub server lives in `examples/hkp_stub/`.

```bash
cd examples/hkp_stub
go mod tidy
go run .
# Server starts on http://localhost:8080
```

To use the standard HKP port:

```bash
PORT=11371 go run .
```

---

## Sample Client Commands

### Add a key (`POST /pks/add`)

```bash
# Add a key from a file
curl -X POST \
     --data-urlencode "keytext@alice.pub" \
     http://localhost:8080/pks/add

# Add a key inline (pipe from gpg export)
gpg --armor --export alice@example.test | \
  curl -X POST --data-urlencode keytext@- http://localhost:8080/pks/add
```

### Look up a key by email (`GET /pks/lookup?op=get`)

```bash
# ASCII-armored output (default)
curl "http://localhost:8080/pks/lookup?op=get&search=alice@example.test&format=armored"

# Machine-readable output
curl "http://localhost:8080/pks/lookup?op=get&search=alice@example.test&options=mr"
```

### Index keys (`GET /pks/lookup?op=index`)

```bash
# HTML index (browser-friendly)
curl "http://localhost:8080/pks/lookup?op=index&search=alice@example.test&format=html"

# Machine-readable index
curl "http://localhost:8080/pks/lookup?op=index&search=alice@example.test&options=mr"
```

### Look up a key by Key ID

```bash
curl "http://localhost:8080/pks/lookup?op=get&search=0xDEADBEEF"
```

### Use with GnuPG

You can configure GnuPG to use the stub server:

```bash
# One-shot
gpg --keyserver http://localhost:8080 --recv-keys DEADBEEF

# Or in ~/.gnupg/gpg.conf:
# keyserver http://localhost:8080
gpg --recv-keys DEADBEEF
```

---

## OpenAPI Specification

The full OpenAPI 3.0.3 specification for Dead PGP mode is in
[`openapi_dead_pgp.yaml`](../openapi_dead_pgp.yaml) at the repository root.

You can view it interactively with:

```bash
# With Swagger UI (Docker)
docker run -p 8081:8080 \
  -e SWAGGER_JSON=/spec/openapi_dead_pgp.yaml \
  -v $(pwd):/spec \
  swaggerapi/swagger-ui

# Then open http://localhost:8081
```

Or with the Stoplight Spectral linter:

```bash
npm install -g @stoplight/spectral-cli
spectral lint openapi_dead_pgp.yaml
```

---

## Notes

- The stub server stores keys in memory. All keys are lost on restart.
- No PGP signature verification is performed on submitted keys.
- The `format` query parameter is a non-standard extension for convenience.
  Standard HKP clients use `options=mr` for machine-readable output.
- Key ID lookups accept the `0x` prefix (e.g., `0xDEADBEEF`) or plain hex.
