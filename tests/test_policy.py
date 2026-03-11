"""Tests for deadpgp.policy — policy evaluation logic."""

from __future__ import annotations

import datetime
import io
import textwrap
import pytest

from deadpgp.policy import PolicyConfig, PolicyResult, evaluate_policy, load_config, parse_policy


# ---------------------------------------------------------------------------
# evaluate_policy tests
# ---------------------------------------------------------------------------


def _policy(**kwargs) -> PolicyConfig:
    defaults = dict(
        quorum=2,
        allowed_purposes=["incident-response", "audit-review"],
        deny_purposes=[],
        allowed_hours_start=None,
        allowed_hours_end=None,
        max_daily_reveals=None,
    )
    defaults.update(kwargs)
    return PolicyConfig(**defaults)


def _votes_approve(*ids) -> dict:
    return {i: "APPROVE" for i in ids}


class TestQuorum:
    def test_quorum_met_exactly(self):
        result = evaluate_policy(
            _policy(quorum=2),
            votes=_votes_approve("alice", "bob"),
            purpose="incident-response",
        )
        assert result.allowed is True

    def test_quorum_exceeded(self):
        result = evaluate_policy(
            _policy(quorum=2),
            votes=_votes_approve("alice", "bob", "carol"),
            purpose="incident-response",
        )
        assert result.allowed is True

    def test_quorum_not_met(self):
        result = evaluate_policy(
            _policy(quorum=2),
            votes=_votes_approve("alice"),
            purpose="incident-response",
        )
        assert result.allowed is False
        assert "quorum" in result.reason.lower()

    def test_quorum_zero_votes(self):
        result = evaluate_policy(
            _policy(quorum=1),
            votes={},
            purpose="incident-response",
        )
        assert result.allowed is False

    def test_deny_votes_do_not_count_toward_quorum(self):
        result = evaluate_policy(
            _policy(quorum=2),
            votes={"alice": "APPROVE", "bob": "DENY"},
            purpose="incident-response",
        )
        assert result.allowed is False


class TestPurpose:
    def test_allowed_purpose(self):
        result = evaluate_policy(
            _policy(quorum=1, allowed_purposes=["incident-response"]),
            votes=_votes_approve("alice"),
            purpose="incident-response",
        )
        assert result.allowed is True

    def test_disallowed_purpose(self):
        result = evaluate_policy(
            _policy(quorum=1, allowed_purposes=["incident-response"]),
            votes=_votes_approve("alice"),
            purpose="fishing",
        )
        assert result.allowed is False
        assert "purpose" in result.reason.lower()

    def test_wildcard_allows_any_purpose(self):
        result = evaluate_policy(
            _policy(quorum=1, allowed_purposes=["*"]),
            votes=_votes_approve("alice"),
            purpose="anything-goes",
        )
        assert result.allowed is True

    def test_deny_purpose_overrides_allowed(self):
        result = evaluate_policy(
            _policy(
                quorum=1,
                allowed_purposes=["*"],
                deny_purposes=["exfiltration"],
            ),
            votes=_votes_approve("alice"),
            purpose="exfiltration",
        )
        assert result.allowed is False
        assert "denied" in result.reason.lower()


class TestAllowedHours:
    _FIXED_HOUR = 14  # 14:00 UTC

    def _now(self, hour: int) -> datetime.datetime:
        return datetime.datetime(2026, 3, 11, hour, 0, 0)

    def test_within_allowed_hours(self):
        result = evaluate_policy(
            _policy(quorum=1, allowed_hours_start=8, allowed_hours_end=20),
            votes=_votes_approve("alice"),
            purpose="incident-response",
            now=self._now(14),
        )
        assert result.allowed is True

    def test_outside_allowed_hours(self):
        result = evaluate_policy(
            _policy(quorum=1, allowed_hours_start=8, allowed_hours_end=20),
            votes=_votes_approve("alice"),
            purpose="incident-response",
            now=self._now(3),
        )
        assert result.allowed is False
        assert "hour" in result.reason.lower()

    def test_at_boundary_start_inclusive(self):
        result = evaluate_policy(
            _policy(quorum=1, allowed_hours_start=8, allowed_hours_end=20),
            votes=_votes_approve("alice"),
            purpose="incident-response",
            now=self._now(8),
        )
        assert result.allowed is True

    def test_at_boundary_end_exclusive(self):
        result = evaluate_policy(
            _policy(quorum=1, allowed_hours_start=8, allowed_hours_end=20),
            votes=_votes_approve("alice"),
            purpose="incident-response",
            now=self._now(20),
        )
        assert result.allowed is False


class TestMaxDailyReveals:
    def test_under_limit(self):
        result = evaluate_policy(
            _policy(quorum=1, max_daily_reveals=10),
            votes=_votes_approve("alice"),
            purpose="incident-response",
            daily_reveal_count=9,
        )
        assert result.allowed is True

    def test_at_limit(self):
        result = evaluate_policy(
            _policy(quorum=1, max_daily_reveals=10),
            votes=_votes_approve("alice"),
            purpose="incident-response",
            daily_reveal_count=10,
        )
        assert result.allowed is False
        assert "limit" in result.reason.lower()

    def test_no_limit_set(self):
        result = evaluate_policy(
            _policy(quorum=1, max_daily_reveals=None),
            votes=_votes_approve("alice"),
            purpose="incident-response",
            daily_reveal_count=9999,
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# parse_policy / load_config tests
# ---------------------------------------------------------------------------


class TestParsePolicy:
    def test_defaults(self):
        policy = parse_policy({})
        assert policy.quorum == 1
        assert policy.allowed_purposes == ["*"]
        assert policy.deny_purposes == []
        assert policy.allowed_hours_start is None
        assert policy.max_daily_reveals is None

    def test_full_config(self):
        raw = {
            "quorum": 3,
            "policy": {
                "allowed_purposes": ["a", "b"],
                "deny_purposes": ["c"],
                "allowed_hours": {"start": 9, "end": 17},
                "max_daily_reveals": 5,
            },
        }
        policy = parse_policy(raw)
        assert policy.quorum == 3
        assert policy.allowed_purposes == ["a", "b"]
        assert policy.deny_purposes == ["c"]
        assert policy.allowed_hours_start == 9
        assert policy.allowed_hours_end == 17
        assert policy.max_daily_reveals == 5


class TestLoadConfig:
    def test_load_yaml(self, tmp_path):
        cfg = tmp_path / "deadpgp.yaml"
        cfg.write_text(
            textwrap.dedent("""\
                quorum: 2
                approvers:
                  - id: alice
                    fingerprint: AABB
                policy:
                  allowed_purposes:
                    - incident-response
                audit:
                  log_path: audit.jsonl
            """),
            encoding="utf-8",
        )
        data = load_config(str(cfg))
        assert data["quorum"] == 2
        assert data["approvers"][0]["id"] == "alice"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "nonexistent.yaml"))
