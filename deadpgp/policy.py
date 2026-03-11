"""Policy engine for DeadPGP.

Loads a YAML configuration file and evaluates whether a Reveal request
should be allowed or denied based on configured rules.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass
class PolicyConfig:
    """Parsed policy section of the YAML config."""

    quorum: int = 1
    allowed_purposes: List[str] = field(default_factory=lambda: ["*"])
    deny_purposes: List[str] = field(default_factory=list)
    allowed_hours_start: Optional[int] = None
    allowed_hours_end: Optional[int] = None
    max_daily_reveals: Optional[int] = None


@dataclass
class PolicyResult:
    """Result of a policy evaluation."""

    allowed: bool
    reason: Optional[str] = None


def load_config(config_path: str) -> Dict[str, Any]:
    """Load and return the raw YAML configuration dictionary."""
    if yaml is None:
        raise ImportError("PyYAML is required. Install it with: pip install pyyaml")
    path = Path(config_path)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data or {}


def parse_policy(config: Dict[str, Any]) -> PolicyConfig:
    """Extract a PolicyConfig from the raw config dictionary."""
    quorum = int(config.get("quorum", 1))
    policy_section = config.get("policy", {}) or {}

    allowed_purposes = policy_section.get("allowed_purposes", ["*"])
    deny_purposes = policy_section.get("deny_purposes", [])

    allowed_hours = policy_section.get("allowed_hours")
    allowed_hours_start: Optional[int] = None
    allowed_hours_end: Optional[int] = None
    if allowed_hours:
        allowed_hours_start = int(allowed_hours.get("start", 0))
        allowed_hours_end = int(allowed_hours.get("end", 24))

    max_daily_reveals = policy_section.get("max_daily_reveals")
    if max_daily_reveals is not None:
        max_daily_reveals = int(max_daily_reveals)

    return PolicyConfig(
        quorum=quorum,
        allowed_purposes=allowed_purposes,
        deny_purposes=deny_purposes,
        allowed_hours_start=allowed_hours_start,
        allowed_hours_end=allowed_hours_end,
        max_daily_reveals=max_daily_reveals,
    )


def evaluate_policy(
    policy: PolicyConfig,
    votes: Dict[str, str],
    purpose: str,
    daily_reveal_count: int = 0,
    now: Optional[datetime.datetime] = None,
) -> PolicyResult:
    """Evaluate whether a Reveal request should be allowed.

    Args:
        policy: The parsed PolicyConfig.
        votes: Mapping of approver-id → "APPROVE" or "DENY".
        purpose: The requester's stated purpose string.
        daily_reveal_count: Number of reveals already performed today (used for
            the ``max_daily_reveals`` rule).
        now: Current UTC datetime (injectable for testing; defaults to
            ``datetime.datetime.utcnow()``).

    Returns:
        A :class:`PolicyResult` with ``allowed=True`` or ``allowed=False``
        and a human-readable ``reason`` string explaining any denial.
    """
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    # --- Quorum check ---
    approve_count = sum(1 for v in votes.values() if v == "APPROVE")
    if approve_count < policy.quorum:
        return PolicyResult(
            allowed=False,
            reason=(
                f"quorum not met: {approve_count} APPROVE votes, "
                f"need {policy.quorum}"
            ),
        )

    # --- Deny-purposes check (deny-overrides) ---
    for denied in policy.deny_purposes:
        if purpose == denied:
            return PolicyResult(
                allowed=False,
                reason=f"purpose '{purpose}' is explicitly denied",
            )

    # --- Allowed-purposes check ---
    if policy.allowed_purposes and policy.allowed_purposes != ["*"]:
        if purpose not in policy.allowed_purposes:
            return PolicyResult(
                allowed=False,
                reason=(
                    f"purpose '{purpose}' is not in the allowed list: "
                    f"{policy.allowed_purposes}"
                ),
            )

    # --- Allowed-hours check ---
    if (
        policy.allowed_hours_start is not None
        and policy.allowed_hours_end is not None
    ):
        current_hour = now.hour
        if not (policy.allowed_hours_start <= current_hour < policy.allowed_hours_end):
            return PolicyResult(
                allowed=False,
                reason=(
                    f"current hour {current_hour} UTC is outside the allowed window "
                    f"[{policy.allowed_hours_start}, {policy.allowed_hours_end})"
                ),
            )

    # --- Max daily reveals check ---
    if policy.max_daily_reveals is not None:
        if daily_reveal_count >= policy.max_daily_reveals:
            return PolicyResult(
                allowed=False,
                reason=(
                    f"daily reveal limit reached: {daily_reveal_count} of "
                    f"{policy.max_daily_reveals} allowed"
                ),
            )

    return PolicyResult(allowed=True)
