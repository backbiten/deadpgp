"""Tests for deadpgp.audit — audit log writing and reading."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from deadpgp.audit import append_record, build_record, read_records, SCHEMA_VERSION


# ---------------------------------------------------------------------------
# build_record tests
# ---------------------------------------------------------------------------


class TestBuildRecord:
    def test_required_fields_present(self):
        rec = build_record(
            operation_id="op-001",
            state="AUDIT",
            infile="secret.gpg",
            outfile="output.txt",
            requester="alice",
            purpose="incident-response",
            votes={"alice": "APPROVE"},
            policy_result="ALLOW",
            outcome="SUCCESS",
        )
        assert rec["schema_version"] == SCHEMA_VERSION
        assert rec["operation_id"] == "op-001"
        assert rec["state"] == "AUDIT"
        assert rec["infile"] == "secret.gpg"
        assert rec["outfile"] == "output.txt"
        assert rec["requester"] == "alice"
        assert rec["purpose"] == "incident-response"
        assert rec["votes"] == {"alice": "APPROVE"}
        assert rec["policy_result"] == "ALLOW"
        assert rec["outcome"] == "SUCCESS"
        assert rec["veto_reason"] is None
        assert rec["error"] is None

    def test_custom_timestamp(self):
        rec = build_record(
            operation_id="op-002",
            state="BLOCKED",
            infile="a.gpg",
            outfile="b.txt",
            requester="bob",
            purpose="fishing",
            votes={},
            policy_result="DENY",
            outcome="BLOCKED",
            veto_reason="purpose not allowed",
            timestamp="2026-01-01T00:00:00Z",
        )
        assert rec["timestamp"] == "2026-01-01T00:00:00Z"
        assert rec["veto_reason"] == "purpose not allowed"

    def test_auto_timestamp_format(self):
        rec = build_record(
            operation_id="op-003",
            state="AUDIT",
            infile="a.gpg",
            outfile="b.txt",
            requester="carol",
            purpose="audit-review",
            votes={"carol": "APPROVE"},
            policy_result="ALLOW",
            outcome="SUCCESS",
        )
        # Timestamp should be a non-empty string ending in 'Z'
        assert isinstance(rec["timestamp"], str)
        assert rec["timestamp"].endswith("Z")

    def test_error_field(self):
        rec = build_record(
            operation_id="op-004",
            state="AUDIT",
            infile="a.gpg",
            outfile="b.txt",
            requester="dave",
            purpose="incident-response",
            votes={"dave": "APPROVE"},
            policy_result="ALLOW",
            outcome="FAILURE",
            error="gpg: decryption failed",
        )
        assert rec["outcome"] == "FAILURE"
        assert rec["error"] == "gpg: decryption failed"


# ---------------------------------------------------------------------------
# append_record / read_records tests
# ---------------------------------------------------------------------------


class TestAppendAndRead:
    def test_append_creates_file(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        rec = build_record(
            operation_id="op-001",
            state="AUDIT",
            infile="a.gpg",
            outfile="b.txt",
            requester="alice",
            purpose="incident-response",
            votes={"alice": "APPROVE"},
            policy_result="ALLOW",
            outcome="SUCCESS",
        )
        append_record(log, rec)
        assert Path(log).exists()

    def test_append_multiple_records(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        for i in range(3):
            rec = build_record(
                operation_id=f"op-{i:03d}",
                state="AUDIT",
                infile="a.gpg",
                outfile="b.txt",
                requester="alice",
                purpose="incident-response",
                votes={"alice": "APPROVE"},
                policy_result="ALLOW",
                outcome="SUCCESS",
            )
            append_record(log, rec)

        records = read_records(log)
        assert len(records) == 3
        assert records[0]["operation_id"] == "op-000"
        assert records[2]["operation_id"] == "op-002"

    def test_each_line_is_valid_json(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        rec = build_record(
            operation_id="op-001",
            state="AUDIT",
            infile="a.gpg",
            outfile="b.txt",
            requester="alice",
            purpose="incident-response",
            votes={"alice": "APPROVE"},
            policy_result="ALLOW",
            outcome="SUCCESS",
        )
        append_record(log, rec)
        raw_lines = Path(log).read_text(encoding="utf-8").splitlines()
        for line in raw_lines:
            if line.strip():
                parsed = json.loads(line)
                assert parsed["schema_version"] == SCHEMA_VERSION

    def test_read_records_missing_file(self, tmp_path):
        records = read_records(str(tmp_path / "nonexistent.jsonl"))
        assert records == []

    def test_append_creates_parent_dirs(self, tmp_path):
        log = str(tmp_path / "nested" / "deep" / "audit.jsonl")
        rec = build_record(
            operation_id="op-001",
            state="AUDIT",
            infile="a.gpg",
            outfile="b.txt",
            requester="alice",
            purpose="incident-response",
            votes={"alice": "APPROVE"},
            policy_result="ALLOW",
            outcome="SUCCESS",
        )
        append_record(log, rec)
        assert Path(log).exists()
