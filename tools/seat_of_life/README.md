# Seat of Life — Source Snapshot & Recovery Tool

> **"Life without life"** — a program that re-enables DeadPGP after it has been
> lost or scrubbed from source trees, git repos, and cloud services.

## What is the Seat of Life?

The **Seat of Life** is a deterministic backup and recovery system for the
DeadPGP source code.  It solves the problem of a project disappearing from the
internet (deleted repository, cloud outage, account removal) by providing:

1. **A snapshot archive** (`snapshot.tar.gz`) — a gzipped tar of every tracked
   file in the repository at a specific commit.
2. **A manifest** (`manifest.json`) — a JSON file listing every file with its
   SHA-256 hash and size, allowing you to verify the snapshot against a trusted
   copy.
3. **Optional encryption** — the snapshot can be encrypted with a password or
   a recipient public key using DeadPGP itself, so it can be stored safely in
   untrusted locations.

Snapshots are automatically generated and attached to every GitHub Release.

---

## Quick start

### Generate a snapshot locally

```bash
# Plain snapshot + manifest (no encryption)
python tools/seat_of_life/snapshot.py

# Password-encrypted snapshot
python tools/seat_of_life/snapshot.py --encrypt-password

# Recipient-key encrypted snapshot
python tools/seat_of_life/snapshot.py --encrypt-to alice.pub

# Manifest only (no archive)
python tools/seat_of_life/snapshot.py --no-archive

# Custom output directory
python tools/seat_of_life/snapshot.py --output /path/to/backup
```

Output is written to `dist/seat_of_life/` by default.

---

## Verifying a snapshot

### 1. Check the manifest

```bash
python - << 'EOF'
import hashlib, json, pathlib, sys

manifest_path = pathlib.Path("manifest.json")
archive_root  = pathlib.Path(".")   # extracted snapshot directory

data = json.loads(manifest_path.read_text())
errors = []

for entry in data["files"]:
    fpath = archive_root / entry["path"]
    if not fpath.exists():
        errors.append(f"MISSING  {entry['path']}")
        continue
    h = hashlib.sha256(fpath.read_bytes()).hexdigest()
    if h != entry["sha256"]:
        errors.append(f"MISMATCH {entry['path']}")

if errors:
    print("Verification FAILED:")
    for e in errors:
        print(" ", e)
    sys.exit(1)
else:
    print(f"All {data['file_count']} files verified OK.")
EOF
```

### 2. Extract the archive

```bash
tar xzf snapshot.tar.gz -C /path/to/restore
```

### 3. Decrypt an encrypted snapshot (if needed)

```bash
# Password-encrypted:
deadpgp decrypt --password snapshot.tar.gz.asc --out snapshot.tar.gz

# Recipient-key encrypted:
deadpgp decrypt --identity my.key snapshot.tar.gz.asc --out snapshot.tar.gz
```

### 4. Restore from the extracted source

After extracting:

```bash
cd /path/to/restore
pip install -e .
deadpgp --help
```

---

## manifest.json format

```json
{
  "deadpgp_snapshot": true,
  "version": "1",
  "generated_at": "2026-03-10T15:00:00+00:00",
  "git_head": "a6810b54094fc77250ad9fdd46ea9805f911f5f6",
  "file_count": 42,
  "files": [
    {
      "path": "README.md",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 127
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `deadpgp_snapshot` | Always `true`; identifies this as a DeadPGP snapshot manifest |
| `version` | Manifest schema version (`"1"`) |
| `generated_at` | ISO-8601 timestamp (UTC) when the manifest was built |
| `git_head` | Full SHA of the commit captured in this snapshot |
| `file_count` | Total number of files in the snapshot |
| `files` | Array of file entries with `path`, `sha256`, and `size` |

---

## Storage recommendations

| Location | Notes |
|----------|-------|
| GitHub Releases | Automatic via CI (see `.github/workflows/release-snapshot.yml`) |
| Offline USB drive | Highly recommended; encrypt with `--encrypt-password` |
| Secondary git forge | Push a mirror to Codeberg, GitLab, or Gitea |
| Cloud storage | Encrypt before uploading (`--encrypt-password` or `--encrypt-to`) |

---

## Signing (TODO)

> Manifest signing is planned for a future release.
>
> Once a project signing key is established, the manifest will be signed with
> `manifest.sig`.  Until then, verify integrity using SHA-256 hashes from a
> trusted copy of `manifest.json`.

---

## Role responsibility (who maintains backups)

| Role | Responsibility |
|------|---------------|
| Project Manager / General Superintendent | Triggers releases; owns the signing key |
| Superintendent / General Foreman | Verifies release artifacts are uploaded |
| Foreman / Lead Hand | Confirms CI snapshot workflow passes on each release |
| Journeyman / Apprentice | Runs `snapshot.py` locally and stores a personal backup |

See `.deadpgp/qa_roles.yml` for the full role hierarchy.
