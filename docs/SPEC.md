# Living PGP (deadpgp) Protocol Specification

This document defines the "Living PGP" orchestration layer, which reframes legacy PGP as a safety-first, policy-driven reveal workflow.

## 1. Overview
Living PGP is a state machine that sits between the user and GnuPG. It ensures that decryption ("The Reveal") only occurs after specific organizational and safety conditions are met.

## 2. The "Electoral College" Approval Model
Decryption is guarded by a quorum of authorized GPG keys.

- **Electors**: A list of GPG fingerprints authorized to sign off on a decryption request.
- **Quorum**: The minimum number of unique valid signatures required (e.g., 3-of-5).
- **Approval Token**: A PGP-signed JSON message containing the `request_id` and `timestamp`.

## 3. Local AI-Veto Policy
Before the final plaintext is released to the user, a local (offline) AI model scans the content.
- **Veto Conditions**: The AI can trigger a veto if it detects:
  - Unauthorized PII (Personally Identifiable Information).
  - Credentials/Keys in the plaintext.
  - Keywords violating specific "Safe Harbour" policies.
- **Override**: A veto can only be overridden by a unanimous vote from the full Electoral College.

## 4. State Machine
1. **PENDING**: Request created, awaiting signatures.
2. **AUTHORIZED**: Quorum reached, awaiting AI scan.
3. **SCANNING**: Local AI-veto check in progress.
4. **REVEALED**: Content decrypted and logged.
5. **VETOED**: AI detected a violation; content suppressed.

## 5. Audit Logging (JSONL)
Every transition is recorded in an append-only `audit.jsonl` file:
```json
{"timestamp": "2026-03-14T12:00:00Z", "request_id": "req-123", "event": "QUORUM_REACHED", "signatures": ["FP1", "FP2", "FP3"]}
{"timestamp": "2026-03-14T12:00:05Z", "request_id": "req-123", "event": "AI_VETO_TRIGGERED", "reason": "PII_DETECTED"}
```