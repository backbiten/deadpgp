# DeadPGP Protocol Specification

**Version:** 0.1.0-draft  
**Status:** Draft  
**Date:** 2026-03-11

---

## 1. Overview

DeadPGP is an orchestration and policy layer around GnuPG (OpenPGP). It does
**not** invent new cryptographic primitives. Instead it wraps GPG decrypt
operations with a structured approval workflow, an AI-driven veto mechanism, and
an immutable audit trail.

The guiding principle: *a secret should only be revealed when a quorum of
authorised approvers agree **and** an automated policy engine has no objection.*

---

## 2. Terminology

| Term | Meaning in this document |
|---|---|
| **Reveal** | The act of decrypting a GPG-encrypted file and making the plaintext available. |
| **Request** | A record created by any actor asking for a Reveal. |
| **Approver** | A human or agent identity (identified by a GPG fingerprint or a username) that can cast a `APPROVE` or `DENY` vote. |
| **Quorum** | The minimum number of `APPROVE` votes required for a Request to proceed. |
| **Meta-IA** | The "electoral college" tier — a configurable set of approvers whose collective vote determines whether to proceed. |
| **Mid-IA** | The orchestrator process that collects votes, checks policy, and drives the state machine. |
| **AI Veto** | An automated policy check (rule engine, ML model, or heuristic) that can block a Request even after sufficient human approval. |
| **Worker** | Any downstream process that receives the decrypted output. Workers have no role in the approval decision. |
| **Audit Log** | An append-only file of JSON Lines records, one per state transition. |

---

## 3. Threat Model

### 3.1 What DeadPGP protects against

* Unilateral decryption by a single privileged user (insider threat).
* Silent decryption without a traceable record.
* Automated pipelines that bypass human oversight.
* Replay of old approval tokens to authorise new Requests.

### 3.2 Non-goals

* DeadPGP does **not** protect against a compromised GnuPG installation.
* DeadPGP does **not** protect against a majority of approvers colluding.
* DeadPGP is **not** a key-management system; key distribution/revocation is out of scope.
* DeadPGP does **not** add post-quantum cryptography; that is a future concern.
* DeadPGP is **not** a replacement for full-disk encryption or TLS.

---

## 4. Reveal State Machine

A Reveal Request progresses through exactly the following states. Transitions
are described by the arrows; any violation of ordering is rejected.

```
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  ▼                                                         │
REQUEST ──► VOTE ──► AI_VETO_CHECK ──► EXECUTE ──► AUDIT ──┘
                │                │
                ▼                ▼
              DENIED           BLOCKED
```

| State | Description |
|---|---|
| `REQUEST` | A new Reveal request is created with a unique `operation_id`, the target encrypted file path, requester identity, purpose string, and timestamp. |
| `VOTE` | Each configured approver is notified (out-of-band today; future: signed messages). The orchestrator collects votes until quorum is reached or timeout expires. If quorum is not reached, the request moves to `DENIED`. |
| `AI_VETO_CHECK` | The policy engine (`deadpgp.policy`) evaluates the request against configured rules (allowed purposes, time windows, risk score). If any rule fails, the request moves to `BLOCKED`. |
| `EXECUTE` | GnuPG decrypt is invoked. The plaintext output is written to the specified path (or stdout). |
| `AUDIT` | A final JSONL audit record is appended. |
| `DENIED` | Quorum not reached; no decryption occurs. Audit record written. |
| `BLOCKED` | AI veto triggered; no decryption occurs. Audit record written. |

---

## 5. Policy Model

Policy is evaluated in `deadpgp/policy.py`. Each policy rule is a predicate on
the Request context. Rules are evaluated in order; the first `DENY` rule wins
(deny-overrides semantics).

### 5.1 Built-in rule types

| Rule key | Description |
|---|---|
| `require_quorum` | Request must have ≥ `quorum` approvals. |
| `allowed_purposes` | The `purpose` field must match one of the listed strings (or `"*"` to allow all). |
| `deny_purposes` | The `purpose` field must not match any of the listed strings. |
| `allowed_hours` | Current UTC hour must be within the range `[start, end)`. |
| `max_daily_reveals` | Total reveals in the last 24 h must not exceed this integer. |

A request is **allowed** when it passes all rules.

---

## 6. Configuration Format

Configuration is a YAML file (default: `deadpgp.yaml`).

```yaml
# deadpgp.yaml — example configuration

operation_id_prefix: "op"   # human-readable prefix for generated IDs

approvers:
  - id: "alice"
    fingerprint: "AABBCCDDEEFF00112233445566778899AABBCCDD"
  - id: "bob"
    fingerprint: "11223344556677889900AABBCCDDEEFF11223344"

quorum: 2                   # minimum APPROVE votes required

policy:
  allowed_purposes:
    - "incident-response"
    - "audit-review"
  deny_purposes: []
  allowed_hours:            # UTC; omit to allow all hours
    start: 8
    end: 20
  max_daily_reveals: 10

audit:
  log_path: "audit.jsonl"   # append-only file
```

---

## 7. Audit Log Format

The audit log is a file of newline-delimited JSON records (JSON Lines). Every
state transition appends one record.

```jsonc
{
  "schema_version": 1,
  "timestamp": "2026-03-11T16:00:00Z",   // ISO-8601 UTC
  "operation_id": "op-20260311-abc123",
  "state": "EXECUTE",                    // or DENIED / BLOCKED / AUDIT
  "infile": "/path/to/secret.gpg",
  "outfile": "/path/to/output.txt",
  "requester": "alice",
  "purpose": "incident-response",
  "votes": {"alice": "APPROVE", "bob": "APPROVE"},
  "policy_result": "ALLOW",
  "veto_reason": null,                   // set when state == BLOCKED
  "outcome": "SUCCESS",                  // SUCCESS | FAILURE | DENIED | BLOCKED
  "error": null
}
```

### 7.1 Field definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | int | yes | Incremented when breaking changes are made to this format. |
| `timestamp` | string | yes | UTC ISO-8601 timestamp of the state transition. |
| `operation_id` | string | yes | Unique identifier for this Reveal request. |
| `state` | string | yes | The state machine state at the time of this record. |
| `infile` | string | yes | Path to the encrypted input file. |
| `outfile` | string | yes | Path (or `"-"` for stdout) where plaintext is written. |
| `requester` | string | yes | Identity of the actor who created the Request. |
| `purpose` | string | yes | Free-text reason provided by the requester. |
| `votes` | object | yes | Map of approver id → `"APPROVE"` / `"DENY"`. |
| `policy_result` | string | yes | `"ALLOW"` or `"DENY"`. |
| `veto_reason` | string\|null | yes | Explains which policy rule triggered the veto, or `null`. |
| `outcome` | string | yes | `SUCCESS`, `FAILURE`, `DENIED`, or `BLOCKED`. |
| `error` | string\|null | yes | Exception message if `outcome == "FAILURE"`, otherwise `null`. |

---

## 8. Current Cryptographic Backend

All decryption is delegated to **GnuPG** via a subprocess call:

```
gpg [--homedir=<dir>] --output <outfile> --decrypt <infile>
```

DeadPGP makes no modifications to ciphertext, keys, or GPG trust database. The
policy/audit layer sits entirely above the crypto layer.

---

## 9. Future Work

* **Signed votes:** approvers sign their vote messages with their GPG key so
  votes cannot be forged.
* **Threshold decryption:** require M-of-N key shares to reconstruct the
  decryption key (eliminates single-approver secret exposure).
* **Time-lock reveal:** encrypt to a future timestamp using verifiable delay
  functions.
* **Post-quantum primitives:** add CRYSTALS-Kyber / ML-KEM key encapsulation
  alongside classical RSA/EC keys.
* **REST/gRPC API:** allow remote vote submission with TLS-authenticated
  identities.
