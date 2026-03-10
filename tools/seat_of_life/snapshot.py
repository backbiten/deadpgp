#!/usr/bin/env python3
"""Seat of Life — deterministic source snapshot and manifest generator.

Usage
-----
  python tools/seat_of_life/snapshot.py [options]

Options
-------
  --output DIR        Directory to write snapshot files (default: ./dist/seat_of_life)
  --encrypt-password  Encrypt snapshot archive with a password (DeadPGP password mode)
  --encrypt-to FILE   Encrypt snapshot archive for a recipient public key
  --no-archive        Skip archive creation; generate manifest only

Example
-------
  # Plain snapshot + manifest
  python tools/seat_of_life/snapshot.py

  # Encrypted with a password
  python tools/seat_of_life/snapshot.py --encrypt-password

  # Encrypted for a recipient
  python tools/seat_of_life/snapshot.py --encrypt-to alice.pub
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Locate repo root: two levels up from this script
_SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = _SCRIPT_DIR.parent.parent


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of the file at *path*."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_head(repo_root: Path) -> str:
    """Return the current HEAD commit SHA, or 'unknown' if git is unavailable."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def _collect_files(repo_root: Path) -> list[Path]:
    """Return a sorted list of tracked (non-ignored) files in the repo."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files"],
            capture_output=True,
            text=True,
            check=True,
        )
        paths = [
            repo_root / line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]
        return sorted(p for p in paths if p.is_file())
    except Exception:
        # Fallback: walk all non-hidden, non-build files
        exclude_dirs = {".git", "__pycache__", "dist", "build", ".venv", "*.egg-info"}
        paths: list[Path] = []
        for p in sorted(repo_root.rglob("*")):
            if p.is_file():
                parts = set(p.relative_to(repo_root).parts)
                if not parts.intersection(exclude_dirs):
                    paths.append(p)
        return paths


def build_manifest(repo_root: Path) -> dict:
    """Build and return the manifest dict."""
    files = _collect_files(repo_root)
    entries = []
    for fp in files:
        rel = str(fp.relative_to(repo_root))
        entries.append(
            {
                "path": rel,
                "sha256": _sha256_file(fp),
                "size": fp.stat().st_size,
            }
        )
    return {
        "deadpgp_snapshot": True,
        "version": "1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_head": _git_head(repo_root),
        "file_count": len(entries),
        "files": entries,
    }


# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------


def build_archive(repo_root: Path, output_path: Path) -> Path:
    """Create a deterministic .tar.gz archive of all tracked files.

    Returns the path to the created archive.
    """
    files = _collect_files(repo_root)
    archive_path = output_path / "snapshot.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for fp in files:
            arcname = str(fp.relative_to(repo_root))
            info = tarfile.TarInfo(name=arcname)
            info.size = fp.stat().st_size
            # Deterministic mtime
            # Zero mtime for determinism: identical source trees produce
            # identical archives regardless of when files were last modified.
            info.mtime = 0
            with fp.open("rb") as f:
                tar.addfile(info, f)
    return archive_path


# ---------------------------------------------------------------------------
# Optional encryption via DeadPGP
# ---------------------------------------------------------------------------


def encrypt_archive_password(archive_path: Path, password: str) -> Path:
    """Encrypt *archive_path* with *password* using DeadPGP password mode.

    Returns the path to the encrypted file (``<archive>.asc``).
    """
    sys.path.insert(0, str(REPO_ROOT))
    from deadpgp import crypto_pwd

    plaintext = archive_path.read_bytes()
    armored = crypto_pwd.encrypt(plaintext, password)
    enc_path = archive_path.with_suffix(".tar.gz.asc")
    enc_path.write_text(armored, encoding="utf-8")
    return enc_path


def encrypt_archive_recipient(archive_path: Path, pubkey_path: Path) -> Path:
    """Encrypt *archive_path* for the recipient at *pubkey_path* (public-key mode).

    Returns the path to the encrypted file (``<archive>.asc``).
    """
    sys.path.insert(0, str(REPO_ROOT))
    from deadpgp import crypto_box, keys as _keys

    recipient = _keys.load_key_file(pubkey_path)
    plaintext = archive_path.read_bytes()
    armored = crypto_box.encrypt(plaintext, recipient)
    enc_path = archive_path.with_suffix(".tar.gz.asc")
    enc_path.write_text(armored, encoding="utf-8")
    return enc_path


# ---------------------------------------------------------------------------
# TODO: manifest signing
# ---------------------------------------------------------------------------
# Signing support is planned for a future release.  When a project signing key
# is available, call:
#
#   sign_manifest(manifest_path, signing_key_path) -> manifest.sig
#
# For now the manifest is unsigned; consumers should verify SHA-256 hashes
# manually against a trusted copy.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="snapshot.py",
        description="Seat of Life — deterministic source snapshot and manifest generator.",
    )
    p.add_argument(
        "--output",
        metavar="DIR",
        default=str(REPO_ROOT / "dist" / "seat_of_life"),
        help="Output directory (default: dist/seat_of_life).",
    )
    p.add_argument(
        "--no-archive",
        action="store_true",
        help="Skip archive creation; generate manifest only.",
    )
    p.add_argument(
        "--encrypt-password",
        action="store_true",
        help="Encrypt the snapshot archive with a password (prompts at runtime).",
    )
    p.add_argument(
        "--encrypt-to",
        metavar="PUBKEY",
        help="Encrypt the snapshot archive for a recipient public key file.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build manifest
    print("Building manifest…")
    manifest = build_manifest(REPO_ROOT)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  Manifest written: {manifest_path}  ({manifest['file_count']} files)")

    if args.no_archive:
        print("Skipping archive (--no-archive).")
        return 0

    # 2. Build archive
    print("Building archive…")
    archive_path = build_archive(REPO_ROOT, output_dir)
    print(f"  Archive written:  {archive_path}")

    # 3. Optional encryption
    if args.encrypt_password:
        pw = getpass.getpass("Enter encryption password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Passwords do not match. Aborting.", file=sys.stderr)
            return 1
        enc_path = encrypt_archive_password(archive_path, pw)
        print(f"  Encrypted (password): {enc_path}")

    elif args.encrypt_to:
        pubkey_path = Path(args.encrypt_to)
        if not pubkey_path.exists():
            print(f"Public key not found: {pubkey_path}", file=sys.stderr)
            return 1
        enc_path = encrypt_archive_recipient(archive_path, pubkey_path)
        print(f"  Encrypted (pubkey):   {enc_path}")

    print()
    print("Seat of Life snapshot complete.")
    print(f"  Output: {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
