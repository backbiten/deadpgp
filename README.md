# DeadPGP

> Modern encryption for everyone — forking the best ideas from PGP for the 21st century.

DeadPGP is a command-line encryption tool built on modern, audited cryptography
(X25519 key agreement, ChaCha20-Poly1305 AEAD, Argon2id KDF).  It includes a
built-in **QA/QC gate** that must pass before encrypt or decrypt operations are
allowed to run, and a **"Seat of Life"** backup system so the project can be
recovered even if it disappears from the internet.

---

## Install

```bash
pip install -e .
```

**Requirements:** Python ≥ 3.10, `cryptography ≥ 41`, `argon2-cffi ≥ 23.1`

---

## Usage

### Generate a keypair

```bash
deadpgp keygen --name alice --out ~/.deadpgp/keys/
```

### Encrypt a message

```bash
# Public-key mode
deadpgp encrypt --to alice.pub secret.txt > secret.txt.asc

# Password mode
deadpgp encrypt --password secret.txt > secret.txt.asc
```

### Decrypt a message

```bash
# Public-key mode
deadpgp decrypt --identity alice.key secret.txt.asc

# Password mode
deadpgp decrypt --password secret.txt.asc

# Emergency bypass (QA failed, decrypt only)
deadpgp decrypt --break-glass "I UNDERSTAND THIS IS UNSAFE" \
    --identity alice.key secret.txt.asc
```

### Run QA checks

```bash
deadpgp qa                 # fast direct checks (default)
deadpgp qa --proxy         # pytest + linter
deadpgp qa --all           # everything
```

### Validate repository structure

```bash
deadpgp doctor
```

---

## QA/QC Gate

Every `encrypt` and `decrypt` call first runs a **fast runtime QA gate**:

| Check | What it verifies |
|-------|-----------------|
| `package-version` | Version string is readable |
| `crypto-import` | `cryptography` library works (X25519 + ChaCha20-Poly1305) |
| `argon2-import` | `argon2-cffi` available (preferred KDF) |
| `required-modules` | All internal modules importable |
| `required-files` | Required repo files are present |

If any check fails:
- **`encrypt`** is always blocked — no bypass.
- **`decrypt`** is blocked unless `--break-glass "I UNDERSTAND THIS IS UNSAFE"` is passed.

Run `deadpgp qa` for a detailed report.

---

## QA/QC Role Hierarchy

DeadPGP uses a construction-industry–inspired hierarchy for code governance.
See `.deadpgp/qa_roles.yml` for the full mapping and `CODEOWNERS` for GitHub
enforcement.

| Role | Analogy | Responsibility |
|------|---------|---------------|
| Project Manager | General Superintendent | Release authority, signing key |
| Superintendent | General Foreman | Approves merges to `main` |
| Foreman / Lead Hand | Field supervisor | Reviews crypto/QA/release PRs |
| Journeyman | Experienced tradesperson | Opens PRs, runs full QA locally |
| Apprentice | Trainee | Opens PRs with foreman supervision |
| Laborer | Contributor | Issues + patches; all code gated by CI QA |

### Inspection flow

```
OUTBOUND (shipping):
  Laborer → commits → Journeyman reviews →
  Foreman approves → CI QA gate passes →
  Superintendent merges → PM signs release

INBOUND (monitoring):
  PM monitors release health
  Superintendent monitors branch health
  Foreman / Lead Hand monitors PR queue & QA failures
  Journeyman / Apprentice runs `deadpgp qa` locally
```

---

## Seat of Life (Backup & Recovery)

The **Seat of Life** tool creates deterministic source snapshots so DeadPGP
can be restored even if the repository disappears from the internet.

```bash
# Generate a snapshot (tar.gz + manifest.json)
python tools/seat_of_life/snapshot.py

# Encrypted snapshot
python tools/seat_of_life/snapshot.py --encrypt-password
```

Snapshots are automatically attached to every GitHub Release.

See [`tools/seat_of_life/README.md`](tools/seat_of_life/README.md) for full
restore documentation.

---

## Development

```bash
# Install in editable mode
pip install -e .

# Run tests
pytest

# Run full QA suite
deadpgp qa --all

# Validate repo structure
deadpgp doctor
```

---

## License

Eclipse Public License 2.0 — see [LICENSE](LICENSE).
