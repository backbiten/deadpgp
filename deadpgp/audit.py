"""Audit log writer for DeadPGP.

Appends JSON Lines records to the configured audit log file.  Each record
represents a single state transition in the Reveal workflow.
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


SCHEMA_VERSION = 1


def build_record(
    operation_id: str,
    state: str,
    infile: str,
    outfile: str,
    requester: str,
    purpose: str,
    votes: Dict[str, str],
    policy_result: str,
    outcome: str,
    veto_reason: Optional[str] = None,
    error: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a single audit log record dictionary.

    Args:
        operation_id: Unique identifier for the Reveal request.
        state: The state machine state (e.g. ``"EXECUTE"``, ``"BLOCKED"``).
        infile: Path to the encrypted input file.
        outfile: Path (or ``"-"`` for stdout) where plaintext is written.
        requester: Identity of the actor who created the Request.
        purpose: Free-text reason provided by the requester.
        votes: Mapping of approver-id → ``"APPROVE"`` / ``"DENY"``.
        policy_result: ``"ALLOW"`` or ``"DENY"``.
        outcome: ``"SUCCESS"``, ``"FAILURE"``, ``"DENIED"``, or ``"BLOCKED"``.
        veto_reason: Explains which policy rule triggered the veto, or ``None``.
        error: Exception message if ``outcome == "FAILURE"``, otherwise ``None``.
        timestamp: ISO-8601 UTC timestamp string; defaults to current UTC time.

    Returns:
        A dictionary ready to be serialised as a JSON Lines record.
    """
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp,
        "operation_id": operation_id,
        "state": state,
        "infile": infile,
        "outfile": outfile,
        "requester": requester,
        "purpose": purpose,
        "votes": votes,
        "policy_result": policy_result,
        "veto_reason": veto_reason,
        "outcome": outcome,
        "error": error,
    }


def append_record(log_path: str, record: Dict[str, Any]) -> None:
    """Append a single record to the audit log file.

    The file is created if it does not exist.  The directory must already exist.

    Args:
        log_path: Path to the JSON Lines audit log file.
        record: The record dictionary to append (will be serialised to JSON).
    """
    path = Path(log_path)
    # Ensure the parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + os.linesep)


def read_records(log_path: str) -> list:
    """Read all records from an audit log file.

    Returns an empty list if the file does not exist.

    Args:
        log_path: Path to the JSON Lines audit log file.

    Returns:
        List of record dictionaries.
    """
    path = Path(log_path)
    if not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
