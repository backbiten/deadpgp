#!/usr/bin/env python3
"""deadpgp_reveal.py — policy-gated GPG reveal CLI.

Usage example::

    python tools/deadpgp_reveal.py \\
        --infile secret.gpg \\
        --outfile output.txt \\
        --operation-id op-001 \\
        --purpose incident-response \\
        --requester alice \\
        --votes alice:APPROVE bob:APPROVE \\
        --config deadpgp.yaml

The tool evaluates policy rules, writes an audit record to the configured
log path, and (if allowed) calls ``gpg --decrypt``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running this script directly without installing the package.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from deadpgp.policy import load_config, parse_policy
from deadpgp.workflow import RevealRequest, run_reveal


def _parse_votes(vote_strings: list) -> dict:
    """Parse a list of ``"id:VOTE"`` strings into a dict."""
    votes: dict = {}
    for item in vote_strings:
        if ":" not in item:
            raise argparse.ArgumentTypeError(
                f"Invalid vote format '{item}'. Expected 'id:APPROVE' or 'id:DENY'."
            )
        approver_id, vote = item.split(":", 1)
        vote = vote.upper()
        if vote not in ("APPROVE", "DENY"):
            raise argparse.ArgumentTypeError(
                f"Invalid vote value '{vote}'. Must be APPROVE or DENY."
            )
        votes[approver_id.strip()] = vote
    return votes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Policy-gated GPG reveal with audit logging.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--infile", required=True, help="Input GPG encrypted file.")
    parser.add_argument(
        "--outfile", required=True, help="Output path for decrypted plaintext."
    )
    parser.add_argument(
        "--operation-id",
        required=True,
        dest="operation_id",
        help="Unique identifier for this reveal operation.",
    )
    parser.add_argument(
        "--purpose",
        required=True,
        help="Reason for the reveal (must match policy allowed_purposes).",
    )
    parser.add_argument(
        "--requester",
        required=True,
        help="Identity of the actor requesting the reveal.",
    )
    parser.add_argument(
        "--votes",
        nargs="+",
        default=[],
        metavar="ID:VOTE",
        help=(
            "One or more votes in 'approver_id:APPROVE' or 'approver_id:DENY' format."
        ),
    )
    parser.add_argument(
        "--config",
        default="deadpgp.yaml",
        help="Path to the YAML configuration file (default: deadpgp.yaml).",
    )
    parser.add_argument(
        "--homedir",
        default=None,
        help="Alternate GnuPG home directory (passed to gpg --homedir).",
    )
    parser.add_argument(
        "--daily-reveal-count",
        type=int,
        default=0,
        dest="daily_reveal_count",
        help="Number of reveals already performed today (for rate-limit policy).",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        raw_config = load_config(args.config)
    except FileNotFoundError:
        print(f"ERROR: config file not found: {args.config}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to load config: {exc}", file=sys.stderr)
        return 2

    policy = parse_policy(raw_config)

    audit_section = raw_config.get("audit", {}) or {}
    audit_log_path = audit_section.get("log_path", "audit.jsonl")

    try:
        votes = _parse_votes(args.votes)
    except argparse.ArgumentTypeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    request = RevealRequest(
        operation_id=args.operation_id,
        infile=args.infile,
        outfile=args.outfile,
        requester=args.requester,
        purpose=args.purpose,
        votes=votes,
        homedir=args.homedir,
    )

    result = run_reveal(
        request=request,
        policy=policy,
        audit_log_path=audit_log_path,
        daily_reveal_count=args.daily_reveal_count,
    )

    if result.outcome == "SUCCESS":
        print(f"[OK] Reveal succeeded. Audit record written to: {audit_log_path}")
        return 0

    if result.outcome == "DENIED":
        print(
            f"[DENIED] Quorum not met. Reason: {result.veto_reason}",
            file=sys.stderr,
        )
        print(f"         Audit record written to: {audit_log_path}", file=sys.stderr)
        return 1

    if result.outcome == "BLOCKED":
        print(
            f"[BLOCKED] AI veto triggered. Reason: {result.veto_reason}",
            file=sys.stderr,
        )
        print(f"          Audit record written to: {audit_log_path}", file=sys.stderr)
        return 1

    # FAILURE — GPG error
    print(f"[FAILURE] GPG decrypt failed: {result.error}", file=sys.stderr)
    print(f"          Audit record written to: {audit_log_path}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
