# deadpgp

An orchestration and policy layer around GnuPG that enforces a
**quorum-approval + AI-veto workflow** before any encrypted file is revealed.
DeadPGP does not invent new cryptography — it wraps `gpg --decrypt` with a
structured state machine, a configurable policy engine, and an immutable audit
trail.

---

## Current status

| Component | Status |
|---|---|
| `tools/openpgp_import/import.py` | ✅ Working — thin `gpg --decrypt` wrapper |
| `deadpgp/` Python package | ✅ Skeleton — policy, audit, workflow modules |
| `tools/deadpgp_reveal.py` | ✅ Working — full policy-gated reveal CLI |
| Signed votes | 🔲 Planned |
| Threshold decryption | 🔲 Planned |
| REST/gRPC API | 🔲 Planned |

---

## Quickstart

### Existing thin wrapper (unchanged)

```bash
python tools/openpgp_import/import.py secret.gpg output.txt
# with a custom GnuPG home directory:
python tools/openpgp_import/import.py secret.gpg output.txt --homedir ~/.gnupg-test
```

### Policy-gated reveal CLI

1. **Create a config file** (`deadpgp.yaml`):

```yaml
quorum: 1
approvers:
  - id: "alice"
    fingerprint: "AABBCCDDEEFF00112233445566778899AABBCCDD"
policy:
  allowed_purposes:
    - "incident-response"
  allowed_hours:
    start: 0
    end: 24
  max_daily_reveals: 100
audit:
  log_path: "audit.jsonl"
```

2. **Run the reveal command**:

```bash
python tools/deadpgp_reveal.py \
  --infile secret.gpg \
  --outfile output.txt \
  --operation-id op-001 \
  --purpose incident-response \
  --requester alice \
  --votes alice:APPROVE \
  --config deadpgp.yaml
```

The tool will:
- evaluate the policy rules,
- write an audit record to `audit.jsonl`,
- if allowed, call `gpg --decrypt` and write the plaintext.

3. **Check the audit log**:

```bash
cat audit.jsonl
```

---

## Roadmap

See [`docs/SPEC.md`](docs/SPEC.md) for the full protocol specification including:

- Terminology (Meta-IA electoral college, AI veto, Mid-IA orchestrator)
- Threat model and non-goals
- Reveal state machine (`REQUEST → VOTE → AI_VETO_CHECK → EXECUTE → AUDIT`)
- Policy rule model
- Configuration format (YAML)
- Audit log format (JSON Lines)

---

## Development

```bash
# install dev dependencies
pip install -e ".[dev]"

# run tests
pytest tests/

# run a specific test
pytest tests/test_policy.py -v
```

---

## License

Eclipse Public License 2.0 — see [LICENSE](LICENSE).
