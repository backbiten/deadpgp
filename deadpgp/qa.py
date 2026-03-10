"""DeadPGP QA/QC gate engine.

This module implements the runtime quality-assurance gate that is evaluated
before every ``encrypt`` and ``decrypt`` operation, as well as the full
``deadpgp qa`` audit command.

Check tiers
-----------
DIRECT (fast, offline, always run before encrypt/decrypt)
    - required package files present
    - version string readable
    - required crypto algorithms importable and functional

PROXY (heavier, run via ``deadpgp qa``)
    - invoke pytest
    - invoke ruff / flake8 if available

ALL
    - DIRECT + PROXY + docs health checks
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# ── public constants ──────────────────────────────────────────────────────────

BREAK_GLASS_PHRASE = "I UNDERSTAND THIS IS UNSAFE"

# ── result types ─────────────────────────────────────────────────────────────


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str = ""


@dataclass
class QAReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def add(self, result: CheckResult) -> None:
        self.checks.append(result)

    def print_report(self, verbose: bool = True) -> None:
        for c in self.checks:
            icon = "✔" if c.passed else "✘"
            line = f"  [{icon}] {c.name}"
            if c.message:
                line += f": {c.message}"
            print(line)
        print()
        if self.passed:
            print("QA PASSED — all checks green.")
        else:
            failed = [c for c in self.checks if not c.passed]
            print(f"QA FAILED — {len(failed)} check(s) did not pass.")
            for c in failed:
                print(f"       ✘  {c.name}: {c.message}")


# ── check helpers ─────────────────────────────────────────────────────────────


def _check_package_version() -> CheckResult:
    """Verify that the package version is readable."""
    try:
        from deadpgp import __version__
        return CheckResult("package-version", True, f"v{__version__}")
    except Exception as exc:
        return CheckResult("package-version", False, str(exc))


def _check_crypto_import() -> CheckResult:
    """Verify cryptography library is importable and functional."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        # Smoke-test: generate a key pair
        priv = X25519PrivateKey.generate()
        priv.public_key()
        return CheckResult("crypto-import", True, "cryptography OK")
    except Exception as exc:
        return CheckResult("crypto-import", False, str(exc))


def _check_argon2_import() -> CheckResult:
    """Verify argon2-cffi (preferred KDF) is importable.

    A missing argon2-cffi is not a hard failure: password-mode encryption
    will fall back to scrypt automatically.  We report a warning message
    but mark the check as passed so the QA gate is not blocked.
    """
    try:
        import argon2.low_level  # noqa: F401
        return CheckResult("argon2-import", True, "argon2-cffi OK")
    except ImportError:
        return CheckResult(
            "argon2-import",
            True,
            "argon2-cffi not installed; password-mode will use scrypt fallback",
        )


def _check_required_modules() -> CheckResult:
    """Verify all internal DeadPGP modules are importable."""
    modules = [
        "deadpgp.armor",
        "deadpgp.keys",
        "deadpgp.crypto_box",
        "deadpgp.crypto_pwd",
        "deadpgp.cli",
    ]
    for mod in modules:
        try:
            importlib.import_module(mod)
        except Exception as exc:
            return CheckResult("required-modules", False, f"{mod}: {exc}")
    return CheckResult("required-modules", True, "all modules importable")


def _check_required_files() -> CheckResult:
    """Verify required repository files exist."""
    # Locate repo root: walk up from this file's location
    here = Path(__file__).resolve().parent.parent
    required = [
        "README.md",
        "LICENSE",
        "pyproject.toml",
        "deadpgp/__init__.py",
        "deadpgp/cli.py",
        "deadpgp/armor.py",
        "deadpgp/crypto_box.py",
        "deadpgp/crypto_pwd.py",
        "deadpgp/keys.py",
    ]
    missing = [f for f in required if not (here / f).exists()]
    if missing:
        return CheckResult(
            "required-files", False, "missing: " + ", ".join(missing)
        )
    return CheckResult("required-files", True, "all required files present")


# ── direct checks (fast gate) ─────────────────────────────────────────────────

_DIRECT_CHECKS: list[Callable[[], CheckResult]] = [
    _check_package_version,
    _check_crypto_import,
    _check_argon2_import,
    _check_required_modules,
    _check_required_files,
]


def run_direct_checks() -> QAReport:
    """Run fast, offline checks.  Used by the encrypt/decrypt QA gate."""
    report = QAReport()
    for check in _DIRECT_CHECKS:
        report.add(check())
    return report


# ── proxy checks (heavier, subprocess-based) ──────────────────────────────────


def _check_pytest() -> CheckResult:
    """Run pytest and report pass/fail."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--tb=short", "-q"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        # Extract summary line
        lines = result.stdout.strip().splitlines()
        summary = lines[-1] if lines else "tests passed"
        return CheckResult("pytest", True, summary)
    else:
        # Show first few lines of failure
        output = (result.stdout + result.stderr).strip()
        snippet = "\n".join(output.splitlines()[:10])
        return CheckResult("pytest", False, snippet)


def _check_linter() -> CheckResult:
    """Run ruff (if available) or report skip."""
    result = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "deadpgp/"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return CheckResult("lint-ruff", True, "no issues")
    # ruff not installed → skip gracefully
    if "No module named ruff" in (result.stderr or ""):
        return CheckResult("lint-ruff", True, "ruff not installed (skipped)")
    output = (result.stdout + result.stderr).strip()
    snippet = "\n".join(output.splitlines()[:5])
    return CheckResult("lint-ruff", False, snippet)


_PROXY_CHECKS: list[Callable[[], CheckResult]] = [
    _check_pytest,
    _check_linter,
]


def run_proxy_checks() -> QAReport:
    """Run subprocess-based checks (pytest, linter)."""
    report = QAReport()
    for check in _PROXY_CHECKS:
        report.add(check())
    return report


# ── docs checks ───────────────────────────────────────────────────────────────


def _check_readme_sections() -> CheckResult:
    """Verify README.md contains required sections."""
    here = Path(__file__).resolve().parent.parent
    readme = here / "README.md"
    if not readme.exists():
        return CheckResult("readme-sections", False, "README.md not found")
    text = readme.read_text(encoding="utf-8").lower()
    required = ["install", "usage", "license"]
    missing = [s for s in required if s not in text]
    if missing:
        return CheckResult(
            "readme-sections", False, "missing sections: " + ", ".join(missing)
        )
    return CheckResult("readme-sections", True, "required sections present")


_DOCS_CHECKS: list[Callable[[], CheckResult]] = [
    _check_readme_sections,
]


def run_docs_checks() -> QAReport:
    """Run documentation health checks."""
    report = QAReport()
    for check in _DOCS_CHECKS:
        report.add(check())
    return report


# ── combined runners ──────────────────────────────────────────────────────────


def run_all_checks() -> QAReport:
    """Run DIRECT + PROXY + DOCS checks and return a combined report."""
    report = QAReport()
    for sub in (run_direct_checks, run_proxy_checks, run_docs_checks):
        sub_report = sub()
        report.checks.extend(sub_report.checks)
    return report


# ── gate function used by encrypt/decrypt ─────────────────────────────────────


class QAGateError(RuntimeError):
    """Raised when the runtime QA gate fails and the operation is blocked."""


def enforce_gate(*, break_glass: str | None = None) -> None:
    """Run the direct QA checks.

    Parameters
    ----------
    break_glass:
        If provided (decrypt-only), the caller is requesting a bypass.
        Must equal :data:`BREAK_GLASS_PHRASE` exactly.

    Raises
    ------
    QAGateError
        If QA fails and either no break-glass was provided (encrypt context)
        or the break-glass phrase is wrong.
    """
    report = run_direct_checks()
    if report.passed:
        return

    failed_names = [c.name for c in report.checks if not c.passed]
    summary = "QA gate failed: " + ", ".join(failed_names)

    if break_glass is not None:
        if break_glass == BREAK_GLASS_PHRASE:
            # Print loud warning but allow decrypt to continue
            print(
                "\n"
                "╔══════════════════════════════════════════════════════════╗\n"
                "║  ⚠  BREAK-GLASS ACTIVATED — QA CHECKS FAILED  ⚠        ║\n"
                "║  Proceeding with decryption despite QA failure.         ║\n"
                "║  This mode is UNSAFE. Use only in emergencies.          ║\n"
                "╚══════════════════════════════════════════════════════════╝\n",
                file=sys.stderr,
            )
            print(f"  QA failures: {', '.join(failed_names)}", file=sys.stderr)
            return
        else:
            raise QAGateError(
                f"{summary}\n\n"
                "To proceed with decryption despite QA failure, use:\n"
                f'  deadpgp decrypt --break-glass "{BREAK_GLASS_PHRASE}" ...\n'
                f"Provided phrase does not match. Operation blocked."
            )

    raise QAGateError(
        f"{summary}\n\n"
        "Run `deadpgp qa` for a detailed report and remediation hints.\n"
        "Encrypt is always blocked when QA fails.\n"
        "For decrypt-only emergency access, use:\n"
        f'  deadpgp decrypt --break-glass "{BREAK_GLASS_PHRASE}" ...'
    )
