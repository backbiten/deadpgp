# deadpgp — monorepo

This repository is a **monorepo** that houses two independent projects:

| Project | Language | Path | Description |
|---------|----------|------|-------------|
| **deadpgp** | Python | [`./`](.) (root) | Forking old forgotten PGP protocols from the 1980s/1990s—reframed for modern, safety-focused workflows. |
| **32Hybrid** | Go | [`32Hybrid/`](32Hybrid/) | A reinvention of 32-bit architecture from the 70s/80s — Win32 compatibility runtime (HV subsystem) and an AVD execution system. |

Both projects are **independent**: they have separate build systems, dependency files, and toolchains. See each project's own README for details.

---

## deadpgp (Python — repository root)

Forking old forgotten PGP protocols used in the 1980s and 1990s—reframed for modern, safety-focused workflows.

### Current status (as of 2026-03-11)

- This repo is early-stage.
- Current tooling includes a small Python CLI that wraps `gpg --decrypt` (see `tools/openpgp_import/import.py`).

### Direction / Roadmap

This project is evolving toward an orchestration + policy layer over GnuPG/OpenPGP to support a *sequenced* "reveal" workflow with:

- **Electoral college approvals** (configured as a list of GPG key fingerprints + quorum rules)
- **Local AI-veto policy checks** (no network calls)
- **Auditable decisions** (JSONL audit log)

See `docs/SPEC.md` for the proposed protocol/state machine and configuration format.

### Documentation

| Document | Description |
|---|---|
| [`docs/crypto-basics.md`](docs/crypto-basics.md) | Threat-modeling primer, TLS vs PGP, OpenPGP best practices, algorithm guidance |
| [`docs/SPEC.md`](docs/SPEC.md) | Protocol/state machine specification (Living PGP) |
| [`docs/workflows/sequenced-reveal.md`](docs/workflows/sequenced-reveal.md) | Sequenced reveal state machine, quorum approvals, JSONL audit log, policy checks |
| [`docs/hkp-dead-mode.md`](docs/hkp-dead-mode.md) | HKP endpoints, safety guidance, curl/GPG examples for local keyserver stub |
| [`docs/HKP_COMPAT.md`](docs/HKP_COMPAT.md) | Detailed HKP compatibility notes and sample client code |
| [`examples/gpg/`](examples/gpg/) | Runnable shell scripts: key generation, export/import, encrypt/decrypt, sign/verify, revocation |

---

## 32Hybrid (Go — [`32Hybrid/`](32Hybrid/))

A reinvention and reinnovation of 32-bit architecture from the 70s and 80s. Contains two subsystems:

- **32HybridHV** — compatibility-first runtime appliance for running Win32 binaries unchanged past the Year 2038 problem, using Hyper-V + Wine.
- **32Hybrid AVD** — lets a user in an Azure Virtual Desktop session submit a Windows GUI application via gRPC and collect artifacts from Azure Blob Storage.

See [`32Hybrid/README.md`](32Hybrid/README.md) for full documentation, build instructions, and architecture details.
