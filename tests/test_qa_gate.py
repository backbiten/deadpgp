"""Tests for the QA/QC gate and break-glass bypass."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from deadpgp.qa import (
    BREAK_GLASS_PHRASE,
    QAGateError,
    QAReport,
    CheckResult,
    enforce_gate,
    run_direct_checks,
)


# ---------------------------------------------------------------------------
# QAReport
# ---------------------------------------------------------------------------


class TestQAReport:
    def test_passed_when_all_checks_pass(self):
        r = QAReport()
        r.add(CheckResult("foo", True))
        r.add(CheckResult("bar", True))
        assert r.passed is True

    def test_failed_when_any_check_fails(self):
        r = QAReport()
        r.add(CheckResult("foo", True))
        r.add(CheckResult("bar", False, "something wrong"))
        assert r.passed is False

    def test_empty_report_passes(self):
        r = QAReport()
        assert r.passed is True

    def test_print_report_pass(self, capsys):
        r = QAReport()
        r.add(CheckResult("check-a", True, "all good"))
        r.print_report()
        out = capsys.readouterr().out
        assert "QA PASSED" in out
        assert "✔" in out

    def test_print_report_fail(self, capsys):
        r = QAReport()
        r.add(CheckResult("check-a", False, "broken"))
        r.print_report()
        out = capsys.readouterr().out
        assert "QA FAILED" in out
        assert "✘" in out


# ---------------------------------------------------------------------------
# run_direct_checks passes in normal installation
# ---------------------------------------------------------------------------


class TestRunDirectChecks:
    def test_direct_checks_pass_in_normal_env(self):
        """In a properly installed environment all direct checks should pass."""
        report = run_direct_checks()
        # argon2 may not be present in all environments; skip that one check
        crypto_check = next(
            (c for c in report.checks if c.name == "crypto-import"), None
        )
        assert crypto_check is not None
        assert crypto_check.passed, f"crypto-import failed: {crypto_check.message}"

        version_check = next(
            (c for c in report.checks if c.name == "package-version"), None
        )
        assert version_check is not None
        assert version_check.passed, f"package-version failed: {version_check.message}"


# ---------------------------------------------------------------------------
# enforce_gate — normal pass
# ---------------------------------------------------------------------------


class TestEnforceGatePass:
    def test_no_exception_when_checks_pass(self):
        """enforce_gate should not raise when all direct checks pass."""
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _passing_report()
            enforce_gate()  # should not raise

    def test_no_exception_with_none_break_glass_when_checks_pass(self):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _passing_report()
            enforce_gate(break_glass=None)  # should not raise


# ---------------------------------------------------------------------------
# enforce_gate — encrypt blocks when QA fails
# ---------------------------------------------------------------------------


class TestEnforceGateBlock:
    def test_raises_qa_gate_error_on_failure(self):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("some-check")
            with pytest.raises(QAGateError):
                enforce_gate()

    def test_error_message_contains_failed_check_name(self):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("crypto-import")
            with pytest.raises(QAGateError, match="crypto-import"):
                enforce_gate()


# ---------------------------------------------------------------------------
# enforce_gate — break-glass (decrypt only)
# ---------------------------------------------------------------------------


class TestBreakGlass:
    def test_correct_phrase_allows_bypass(self, capsys):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("some-check")
            enforce_gate(break_glass=BREAK_GLASS_PHRASE)  # must NOT raise
        err = capsys.readouterr().err
        assert "BREAK-GLASS" in err

    def test_wrong_phrase_raises_qa_gate_error(self):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("some-check")
            with pytest.raises(QAGateError):
                enforce_gate(break_glass="wrong phrase")

    def test_empty_phrase_raises_qa_gate_error(self):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("some-check")
            with pytest.raises(QAGateError):
                enforce_gate(break_glass="")

    def test_phrase_case_sensitive(self):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("some-check")
            with pytest.raises(QAGateError):
                enforce_gate(break_glass=BREAK_GLASS_PHRASE.lower())

    def test_break_glass_not_needed_when_qa_passes(self, capsys):
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _passing_report()
            # Even with a phrase supplied, if QA passes → no warning
            enforce_gate(break_glass=BREAK_GLASS_PHRASE)
        err = capsys.readouterr().err
        assert "BREAK-GLASS" not in err


# ---------------------------------------------------------------------------
# CLI integration: encrypt blocked, decrypt blocked / bypassed
# ---------------------------------------------------------------------------


class TestCLIGate:
    def test_encrypt_blocked_when_qa_fails(self):
        """cmd_encrypt should return exit code 2 when QA gate raises."""
        from deadpgp.cli import cmd_encrypt
        import argparse

        args = argparse.Namespace(
            file=None, password=False, to=None, out=None
        )
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("crypto-import")
            rc = cmd_encrypt(args)
        assert rc == 2

    def test_decrypt_blocked_without_break_glass(self, tmp_path):
        """cmd_decrypt should return exit code 2 when QA gate raises and no break-glass."""
        from deadpgp.cli import cmd_decrypt
        import argparse

        # Create a minimal valid armored message so the function reaches the gate
        from deadpgp import crypto_pwd
        armored = crypto_pwd.encrypt(b"test", "pw")
        f = tmp_path / "msg.asc"
        f.write_text(armored)

        args = argparse.Namespace(
            file=str(f), password=True, identity=None, out=None, break_glass=None
        )
        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("some-check")
            rc = cmd_decrypt(args)
        assert rc == 2

    def test_decrypt_succeeds_with_correct_break_glass(self, tmp_path, capsys):
        """cmd_decrypt with correct break-glass phrase bypasses QA gate."""
        from deadpgp.cli import cmd_decrypt
        from deadpgp import crypto_pwd
        import argparse

        plaintext = b"secret"
        password = "mypassword"
        armored = crypto_pwd.encrypt(plaintext, password)
        f = tmp_path / "msg.asc"
        f.write_text(armored)
        out_f = tmp_path / "out.bin"

        args = argparse.Namespace(
            file=str(f),
            password=True,
            identity=None,
            out=str(out_f),
            break_glass=BREAK_GLASS_PHRASE,
        )

        with patch("deadpgp.qa.run_direct_checks") as mock_run:
            mock_run.return_value = _failing_report("some-check")
            with patch("getpass.getpass", return_value=password):
                rc = cmd_decrypt(args)

        assert rc == 0
        assert out_f.read_bytes() == plaintext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _passing_report() -> QAReport:
    r = QAReport()
    r.add(CheckResult("dummy-check", True, "OK"))
    return r


def _failing_report(*names: str) -> QAReport:
    r = QAReport()
    for name in names:
        r.add(CheckResult(name, False, "simulated failure"))
    return r
