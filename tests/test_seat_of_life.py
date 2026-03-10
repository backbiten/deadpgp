"""Tests for the Seat of Life snapshot and manifest generator."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import pytest

# Adjust sys.path so the tools module can be imported
import sys
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from tools.seat_of_life.snapshot import (
    build_manifest,
    build_archive,
    _sha256_file,
    _collect_files,
    REPO_ROOT,
)


# ---------------------------------------------------------------------------
# _sha256_file
# ---------------------------------------------------------------------------


class TestSha256File:
    def test_known_content(self, tmp_path):
        f = tmp_path / "hello.txt"
        f.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert _sha256_file(f) == expected

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert _sha256_file(f) == expected


# ---------------------------------------------------------------------------
# build_manifest
# ---------------------------------------------------------------------------


class TestBuildManifest:
    def test_manifest_schema(self, tmp_path):
        """build_manifest returns a dict with the expected top-level keys."""
        # Use the actual repo root so we get real files
        manifest = build_manifest(REPO_ROOT)
        assert manifest["deadpgp_snapshot"] is True
        assert manifest["version"] == "1"
        assert "generated_at" in manifest
        assert "git_head" in manifest
        assert isinstance(manifest["file_count"], int)
        assert isinstance(manifest["files"], list)

    def test_file_count_matches_files_list(self, tmp_path):
        manifest = build_manifest(REPO_ROOT)
        assert manifest["file_count"] == len(manifest["files"])

    def test_each_file_entry_has_required_fields(self, tmp_path):
        manifest = build_manifest(REPO_ROOT)
        for entry in manifest["files"]:
            assert "path" in entry, f"entry missing 'path': {entry}"
            assert "sha256" in entry, f"entry missing 'sha256': {entry}"
            assert "size" in entry, f"entry missing 'size': {entry}"

    def test_sha256_values_are_hex_strings(self):
        manifest = build_manifest(REPO_ROOT)
        for entry in manifest["files"]:
            sha = entry["sha256"]
            assert len(sha) == 64, f"bad sha256 length: {sha!r}"
            assert all(c in "0123456789abcdef" for c in sha), f"non-hex: {sha!r}"

    def test_file_paths_are_relative(self):
        manifest = build_manifest(REPO_ROOT)
        for entry in manifest["files"]:
            assert not Path(entry["path"]).is_absolute(), (
                f"path should be relative: {entry['path']}"
            )

    def test_sha256_matches_actual_file(self):
        """Spot-check: at least one file's hash matches the actual content."""
        manifest = build_manifest(REPO_ROOT)
        # Check the first file in the manifest
        first = manifest["files"][0]
        actual_hash = _sha256_file(REPO_ROOT / first["path"])
        assert actual_hash == first["sha256"]

    def test_manifest_is_json_serializable(self):
        manifest = build_manifest(REPO_ROOT)
        serialized = json.dumps(manifest)
        decoded = json.loads(serialized)
        assert decoded["deadpgp_snapshot"] is True

    def test_small_repo_manifest(self, tmp_path):
        """build_manifest works with a tiny ad-hoc directory."""
        # Create a minimal fake repo with a few files (no git)
        (tmp_path / "README.md").write_text("# Test")
        (tmp_path / "file.py").write_text("x = 1")

        # Patch _collect_files to return our tmp files directly
        from unittest.mock import patch
        fake_files = sorted(tmp_path.rglob("*"))
        fake_files = [f for f in fake_files if f.is_file()]

        with patch("tools.seat_of_life.snapshot._collect_files", return_value=fake_files):
            manifest = build_manifest(tmp_path)

        assert manifest["file_count"] == 2
        paths = {e["path"] for e in manifest["files"]}
        assert "README.md" in paths
        assert "file.py" in paths


# ---------------------------------------------------------------------------
# build_archive
# ---------------------------------------------------------------------------


class TestBuildArchive:
    def test_creates_tar_gz(self, tmp_path):
        archive_path = build_archive(REPO_ROOT, tmp_path)
        assert archive_path.exists()
        assert archive_path.suffix == ".gz"

    def test_archive_is_valid_tar(self, tmp_path):
        archive_path = build_archive(REPO_ROOT, tmp_path)
        assert tarfile.is_tarfile(str(archive_path))

    def test_archive_contains_expected_files(self, tmp_path):
        archive_path = build_archive(REPO_ROOT, tmp_path)
        with tarfile.open(archive_path, "r:gz") as tar:
            names = set(tar.getnames())
        # At minimum README.md should be in the archive
        assert any("README.md" in n for n in names), f"README not found in {names}"

    def test_archive_entries_have_zero_mtime(self, tmp_path):
        """All entries should have mtime=0 for determinism."""
        archive_path = build_archive(REPO_ROOT, tmp_path)
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                assert member.mtime == 0, (
                    f"non-zero mtime for {member.name}: {member.mtime}"
                )
