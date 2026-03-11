"""Reveal workflow state machine for DeadPGP.

Implements the REQUEST → VOTE → AI_VETO_CHECK → EXECUTE → AUDIT sequence
described in docs/SPEC.md.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from deadpgp.audit import append_record, build_record
from deadpgp.policy import PolicyConfig, PolicyResult, evaluate_policy


# ---------------------------------------------------------------------------
# State constants
# ---------------------------------------------------------------------------

STATE_REQUEST = "REQUEST"
STATE_VOTE = "VOTE"
STATE_AI_VETO_CHECK = "AI_VETO_CHECK"
STATE_EXECUTE = "EXECUTE"
STATE_AUDIT = "AUDIT"
STATE_DENIED = "DENIED"
STATE_BLOCKED = "BLOCKED"

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_FAILURE = "FAILURE"
OUTCOME_DENIED = "DENIED"
OUTCOME_BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Request dataclass
# ---------------------------------------------------------------------------


@dataclass
class RevealRequest:
    """Represents a single Reveal request."""

    operation_id: str
    infile: str
    outfile: str
    requester: str
    purpose: str
    votes: Dict[str, str] = field(default_factory=dict)
    homedir: Optional[str] = None


# ---------------------------------------------------------------------------
# Workflow runner
# ---------------------------------------------------------------------------


@dataclass
class WorkflowResult:
    """Result of running the full Reveal workflow."""

    state: str
    outcome: str
    policy_result: str
    veto_reason: Optional[str] = None
    error: Optional[str] = None


def run_reveal(
    request: RevealRequest,
    policy: PolicyConfig,
    audit_log_path: str,
    daily_reveal_count: int = 0,
) -> WorkflowResult:
    """Execute the full Reveal workflow for a given request.

    States visited in order:
    1. ``AI_VETO_CHECK`` — policy evaluation.
    2. ``EXECUTE`` — GnuPG decrypt (only if policy allows).
    3. ``AUDIT`` — final audit record.

    Note: The ``REQUEST`` and ``VOTE`` states are handled externally (e.g. by
    the CLI) before calling this function.  The ``votes`` field on *request*
    must already be populated.

    Args:
        request: The :class:`RevealRequest` to process.
        policy: The parsed :class:`~deadpgp.policy.PolicyConfig`.
        audit_log_path: Path to the JSON Lines audit log file.
        daily_reveal_count: Number of reveals already performed today.

    Returns:
        A :class:`WorkflowResult` summarising the final state.
    """
    # --- AI_VETO_CHECK ---
    policy_eval: PolicyResult = evaluate_policy(
        policy=policy,
        votes=request.votes,
        purpose=request.purpose,
        daily_reveal_count=daily_reveal_count,
    )

    if not policy_eval.allowed:
        # Determine whether this is a quorum failure (DENIED) or a policy
        # veto (BLOCKED).
        approve_count = sum(1 for v in request.votes.values() if v == "APPROVE")
        if approve_count < policy.quorum:
            final_state = STATE_DENIED
            final_outcome = OUTCOME_DENIED
        else:
            final_state = STATE_BLOCKED
            final_outcome = OUTCOME_BLOCKED

        record = build_record(
            operation_id=request.operation_id,
            state=final_state,
            infile=request.infile,
            outfile=request.outfile,
            requester=request.requester,
            purpose=request.purpose,
            votes=request.votes,
            policy_result="DENY",
            outcome=final_outcome,
            veto_reason=policy_eval.reason,
        )
        append_record(audit_log_path, record)
        return WorkflowResult(
            state=final_state,
            outcome=final_outcome,
            policy_result="DENY",
            veto_reason=policy_eval.reason,
        )

    # --- EXECUTE ---
    error: Optional[str] = None
    try:
        _gpg_decrypt(
            infile=request.infile,
            outfile=request.outfile,
            homedir=request.homedir,
        )
        final_state = STATE_AUDIT
        final_outcome = OUTCOME_SUCCESS
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
        final_state = STATE_AUDIT
        final_outcome = OUTCOME_FAILURE

    # --- AUDIT ---
    record = build_record(
        operation_id=request.operation_id,
        state=final_state,
        infile=request.infile,
        outfile=request.outfile,
        requester=request.requester,
        purpose=request.purpose,
        votes=request.votes,
        policy_result="ALLOW",
        outcome=final_outcome,
        error=error,
    )
    append_record(audit_log_path, record)

    return WorkflowResult(
        state=final_state,
        outcome=final_outcome,
        policy_result="ALLOW",
        error=error,
    )


def _gpg_decrypt(infile: str, outfile: str, homedir: Optional[str] = None) -> None:
    """Invoke GnuPG to decrypt *infile* into *outfile*.

    This mirrors the logic in ``tools/openpgp_import/import.py`` so both
    code paths behave identically.
    """
    command: List[str] = ["gpg", "--output", outfile, "--decrypt", infile]
    if homedir:
        command.insert(1, f"--homedir={homedir}")
    subprocess.run(command, check=True)
