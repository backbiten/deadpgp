"""Tests for deadpgp.workflow — state machine logic.

GPG subprocess calls are mocked so these tests run without GnuPG installed.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from deadpgp.policy import PolicyConfig
from deadpgp.workflow import (
    OUTCOME_BLOCKED,
    OUTCOME_DENIED,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    RevealRequest,
    run_reveal,
)


def _policy(**kwargs) -> PolicyConfig:
    defaults = dict(
        quorum=1,
        allowed_purposes=["incident-response"],
        deny_purposes=[],
        allowed_hours_start=None,
        allowed_hours_end=None,
        max_daily_reveals=None,
    )
    defaults.update(kwargs)
    return PolicyConfig(**defaults)


def _request(**kwargs) -> RevealRequest:
    defaults = dict(
        operation_id="op-001",
        infile="secret.gpg",
        outfile="output.txt",
        requester="alice",
        purpose="incident-response",
        votes={"alice": "APPROVE"},
    )
    defaults.update(kwargs)
    return RevealRequest(**defaults)


class TestRunReveal:
    def test_allowed_calls_gpg(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        with patch("deadpgp.workflow._gpg_decrypt") as mock_gpg:
            result = run_reveal(_request(), _policy(), log)
        mock_gpg.assert_called_once_with(
            infile="secret.gpg", outfile="output.txt", homedir=None
        )
        assert result.outcome == OUTCOME_SUCCESS
        assert result.policy_result == "ALLOW"

    def test_audit_record_written_on_success(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        with patch("deadpgp.workflow._gpg_decrypt"):
            run_reveal(_request(), _policy(), log)
        records = json.loads(Path(log).read_text().strip())
        assert records["outcome"] == "SUCCESS"
        assert records["policy_result"] == "ALLOW"

    def test_quorum_not_met_writes_denied_record(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        result = run_reveal(
            _request(votes={}),
            _policy(quorum=1),
            log,
        )
        assert result.outcome == OUTCOME_DENIED
        records = json.loads(Path(log).read_text().strip())
        assert records["outcome"] == "DENIED"
        assert records["state"] == "DENIED"

    def test_policy_veto_writes_blocked_record(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        result = run_reveal(
            _request(purpose="exfiltration"),
            _policy(allowed_purposes=["incident-response"], quorum=1),
            log,
        )
        assert result.outcome == OUTCOME_BLOCKED
        records = json.loads(Path(log).read_text().strip())
        assert records["outcome"] == "BLOCKED"
        assert records["state"] == "BLOCKED"

    def test_gpg_failure_writes_failure_record(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        with patch(
            "deadpgp.workflow._gpg_decrypt",
            side_effect=RuntimeError("gpg: decryption failed"),
        ):
            result = run_reveal(_request(), _policy(), log)
        assert result.outcome == OUTCOME_FAILURE
        records = json.loads(Path(log).read_text().strip())
        assert records["outcome"] == "FAILURE"
        assert "decryption failed" in records["error"]

    def test_gpg_not_called_when_denied(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        with patch("deadpgp.workflow._gpg_decrypt") as mock_gpg:
            run_reveal(_request(votes={}), _policy(quorum=1), log)
        mock_gpg.assert_not_called()

    def test_homedir_passed_to_gpg(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        with patch("deadpgp.workflow._gpg_decrypt") as mock_gpg:
            run_reveal(
                _request(homedir="/custom/gnupg"),
                _policy(),
                log,
            )
        mock_gpg.assert_called_once_with(
            infile="secret.gpg", outfile="output.txt", homedir="/custom/gnupg"
        )
