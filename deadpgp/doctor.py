"""DeadPGP source-tree / repository-structure validator.

``deadpgp doctor`` prints the expected repository layout and validates
that all required files are present and non-empty (where applicable).
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Expected tree definition
# ---------------------------------------------------------------------------

#: Tuples of (path-relative-to-repo-root, description, required)
EXPECTED_TREE: list[tuple[str, str, bool]] = [
    # Core package
    ("README.md", "Project readme", True),
    ("LICENSE", "Project license", True),
    ("pyproject.toml", "Package metadata & build config", True),
    ("deadpgp/__init__.py", "Package init (version string)", True),
    ("deadpgp/armor.py", "Armor encode/decode", True),
    ("deadpgp/cli.py", "Command-line interface", True),
    ("deadpgp/crypto_box.py", "Public-key encryption (X25519 + ChaCha20-Poly1305)", True),
    ("deadpgp/crypto_pwd.py", "Password-based encryption (Argon2id / scrypt)", True),
    ("deadpgp/keys.py", "Key generation and management", True),
    ("deadpgp/qa.py", "QA/QC gate engine", True),
    ("deadpgp/doctor.py", "Repo-structure validator (this file)", True),
    # Tests
    ("tests/__init__.py", "Test package marker", True),
    ("tests/test_armor.py", "Armor encode/decode tests", True),
    ("tests/test_encrypt_decrypt.py", "Encrypt/decrypt roundtrip tests", True),
    ("tests/test_qa_gate.py", "QA gate & break-glass tests", True),
    ("tests/test_seat_of_life.py", "Seat-of-life manifest tests", True),
    # QA/QC config
    (".deadpgp/qa_roles.yml", "Role mapping (PM → Lead Hand → Journeyman)", True),
    # Seat of Life tooling
    ("tools/seat_of_life/snapshot.py", "Snapshot & manifest generator", True),
    ("tools/seat_of_life/README.md", "Restore documentation", True),
    # CI / GitHub
    (".github/workflows/qa.yml", "CI QA gate workflow", True),
    (".github/workflows/release-snapshot.yml", "Release snapshot workflow", True),
    ("CODEOWNERS", "Code ownership & review requirements", True),
]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_tree(repo_root: Path) -> list[tuple[str, str, bool]]:
    """Check each entry in :data:`EXPECTED_TREE` against the filesystem.

    Returns a list of ``(path, description, found)`` tuples.
    """
    results: list[tuple[str, str, bool]] = []
    for rel_path, description, required in EXPECTED_TREE:
        full = repo_root / rel_path
        found = full.exists() and (full.is_file() or full.is_dir())
        results.append((rel_path, description, found))
    return results


def print_tree_report(results: list[tuple[str, str, bool]]) -> bool:
    """Print the tree report and return True if everything required was found."""
    print("DeadPGP — expected repository structure")
    print("=" * 60)
    all_ok = True
    for rel_path, description, found in results:
        icon = "✔" if found else "✘"
        print(f"  [{icon}] {rel_path:<48}  {description}")
        if not found:
            all_ok = False
    print()
    if all_ok:
        print("Repository structure OK — all required files present.")
    else:
        missing = [r for r in results if not r[2]]
        print(
            f"Repository structure INCOMPLETE — {len(missing)} file(s) missing:"
        )
        for rel_path, description, _ in missing:
            print(f"       ✘  {rel_path}  ({description})")
    return all_ok


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def cmd_doctor(repo_root: Path | None = None) -> int:
    """Run the doctor check and return an exit code (0 = OK, 1 = issues)."""
    if repo_root is None:
        # Locate repo root as the parent of the deadpgp package directory
        repo_root = Path(__file__).resolve().parent.parent

    results = validate_tree(repo_root)
    ok = print_tree_report(results)
    return 0 if ok else 1
