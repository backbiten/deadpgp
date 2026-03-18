# Sequenced Reveal Workflow

The *sequenced reveal* is the core orchestration pattern of deadpgp. It ensures
that encrypted content is decrypted **only after** a defined set of conditions
is met — quorum approval, optional AI-veto scan, and a complete audit trail.

See also [`docs/SPEC.md`](../SPEC.md) for the low-level protocol definition.

---

## 1. High-Level State Machine

```
                        ┌─────────────┐
  new request ───────►  │   PENDING   │
                        └──────┬──────┘
                               │ quorum reached
                               ▼
                        ┌─────────────┐
                        │ AUTHORIZED  │
                        └──────┬──────┘
                               │ AI scan starts
                               ▼
                        ┌─────────────┐
                        │  SCANNING   │
                        └──────┬──────┘
                      ┌────────┴────────┐
              clean   │                 │ violation
              content │                 │ detected
                       ▼                 ▼
                ┌──────────┐      ┌──────────┐
                │ REVEALED │      │  VETOED  │
                └──────────┘      └──────────┘
```

| State | Description |
|---|---|
| `PENDING` | Decryption request created; awaiting enough elector signatures. |
| `AUTHORIZED` | Quorum threshold reached; system queues AI policy scan. |
| `SCANNING` | Local model is analyzing the plaintext for policy violations. |
| `REVEALED` | Content passed all checks; plaintext delivered to requester. |
| `VETOED` | AI scan triggered a veto; plaintext suppressed, alert logged. |

All transitions are **append-only** — a state can only move forward along this
chain. There is no way to go from `VETOED` back to `PENDING` for the same
request; a new request must be created.

---

## 2. Quorum Approvals

### 2.1 Elector configuration

An *elector list* is a JSON / YAML configuration object that specifies:

```jsonc
{
  "request_id": "req-2026-001",           // globally unique, immutable
  "encrypted_artifact": "secret.gpg",     // path or reference
  "electors": [                           // full 40-char v4 fingerprints
    "AABBCCDDEEFF00112233445566778899AABBCCDD",
    "11223344556677889900AABBCCDDEEFF11223344",
    "99887766554433221100FFEEDDCCBBAA99887766",
    "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
    "CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE"
  ],
  "quorum": 3                             // minimum approvals required
}
```

- Use **full 40-character fingerprints**, never short 8- or 16-character key IDs
  (short IDs are trivially spoofable).
- `quorum` must be `> len(electors) / 2` for a strict majority; adjust for your
  policy.

### 2.2 Approval token format

Each elector signals approval by creating a **PGP-signed JSON approval token**:

```json
{
  "request_id": "req-2026-001",
  "approver_fingerprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
  "timestamp": "2026-03-18T12:00:00Z",
  "action": "APPROVE"
}
```

The token is signed with the elector's signing key:

```bash
echo '{"request_id":"req-2026-001","approver_fingerprint":"AABB...","timestamp":"2026-03-18T12:00:00Z","action":"APPROVE"}' \
  | gpg --clearsign --local-user AABBCCDDEEFF00112233445566778899AABBCCDD \
  > approval-AABB.asc
```

The orchestrator:
1. Verifies the GPG signature.
2. Checks that the signing key's fingerprint is in the `electors` list.
3. Counts unique verified approvals against the `quorum` threshold.

### 2.3 Quorum check pseudocode

```python
def check_quorum(request, approval_tokens):
    verified = set()
    for token_path in approval_tokens:
        fp, ok = verify_signed_token(token_path, request["request_id"])
        if ok and fp in request["electors"]:
            verified.add(fp)
    return len(verified) >= request["quorum"]
```

---

## 3. JSONL Audit Log

Every state transition **must** be appended to an append-only `audit.jsonl`
file. Each line is a valid JSON object.

### 3.1 Required fields

| Field | Type | Description |
|---|---|---|
| `timestamp` | string (ISO 8601 UTC) | Wall-clock time of the event |
| `request_id` | string | The request this event belongs to |
| `event` | string | Event type (see below) |

### 3.2 Event types and example log lines

**Request created**
```json
{"timestamp":"2026-03-18T10:00:00Z","request_id":"req-2026-001","event":"REQUEST_CREATED","artifact":"secret.gpg","quorum":3,"elector_count":5}
```

**Individual approval received**
```json
{"timestamp":"2026-03-18T10:05:00Z","request_id":"req-2026-001","event":"APPROVAL_RECEIVED","approver_fingerprint":"AABBCCDDEEFF00112233445566778899AABBCCDD"}
```

**Quorum reached**
```json
{"timestamp":"2026-03-18T10:12:00Z","request_id":"req-2026-001","event":"QUORUM_REACHED","signatures":["AABB...","1122...","9988..."]}
```

**AI scan started**
```json
{"timestamp":"2026-03-18T10:12:01Z","request_id":"req-2026-001","event":"AI_SCAN_STARTED"}
```

**Content revealed**
```json
{"timestamp":"2026-03-18T10:12:03Z","request_id":"req-2026-001","event":"REVEALED","requester":"alice@example.com"}
```

**AI veto triggered**
```json
{"timestamp":"2026-03-18T10:12:03Z","request_id":"req-2026-001","event":"AI_VETO_TRIGGERED","reason":"PII_DETECTED","detail":"SSN pattern matched"}
```

**Veto overridden (unanimous)**
```json
{"timestamp":"2026-03-18T10:20:00Z","request_id":"req-2026-001","event":"VETO_OVERRIDDEN","unanimous_signers":["AABB...","1122...","9988...","DEAD...","CAFE..."]}
```

### 3.3 Log integrity

- The log file must be **append-only**. Never delete or modify existing lines.
- Consider computing a rolling SHA-256 hash chain (each entry includes the hash
  of the previous entry) for tamper detection.
- Rotate the log by archiving (gzip + sign the archive) rather than truncating.

---

## 4. Local Policy Checks (AI-Veto)

The AI-veto step runs **entirely offline** — no network calls are permitted
during the scan.

### 4.1 Veto conditions

| Condition | Example trigger |
|---|---|
| Unauthorized PII | SSN, passport number, date-of-birth patterns |
| Credentials / secrets | AWS key patterns (`AKIA…`), private key headers |
| Safe-harbour keyword list | Organisation-specific forbidden terms |

### 4.2 Override

A veto can only be lifted by a **unanimous vote** of the full elector set (all
`N` electors, not just the quorum threshold). This override is logged as
`VETO_OVERRIDDEN`.

### 4.3 Implementation notes

- The local model runs in a sandboxed subprocess with no network access
  (`PYTHONHTTPSVERIFY=0` and outbound firewall rules applied before scan).
- The scan receives the **plaintext** in memory; it must never be written to
  disk before the veto check is complete.
- If the model process crashes or times out, treat the result as `VETOED`
  (fail-closed).

---

## 5. End-to-End Example

```
1. Alice creates a decryption request for secret.gpg (quorum=3, electors=5).
   → audit: REQUEST_CREATED

2. Bob, Carol, and Dave each sign an approval token and send it to the orchestrator.
   → audit: APPROVAL_RECEIVED (×3)

3. Three unique approvals verified; quorum reached.
   → audit: QUORUM_REACHED, state → AUTHORIZED

4. Orchestrator decrypts secret.gpg in memory, passes plaintext to local AI model.
   → audit: AI_SCAN_STARTED, state → SCANNING

5a. No violations found → plaintext delivered to Alice.
   → audit: REVEALED, state → REVEALED

5b. PII pattern found → plaintext suppressed, alert sent to all electors.
   → audit: AI_VETO_TRIGGERED, state → VETOED
```
