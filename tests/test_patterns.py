"""Tests for the L5 auto-remediation pattern engine."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vmware_policy.patterns import Pattern, PatternEngine, PatternMatch


_SIGNED_ISCSI_PATTERN = """\
schema_version: 1
pattern_id: iscsi-rescan-test

description: PoC pattern for tests.

classification:
  risk: low
  reversible: true
  repeatable: true

trigger:
  skill: vmware-storage
  tool: storage_iscsi_status

action:
  skill: vmware-storage
  tool: storage_rescan

validation:
  delay_seconds: 30

on_validation_failure: escalate_l4

rate_limit:
  max_per_hour_per_host: 4
  max_per_day_per_cluster: 20

circuit_breaker:
  consecutive_validation_failures: 3
  disable_seconds: 60

expires_at: "2099-01-01"

approval:
  status: approved
  signed_by: test-reviewer@example.com
  signed_at: "2026-01-01T00:00:00Z"
"""

_UNSIGNED_PATTERN = """\
schema_version: 1
pattern_id: nsx-rescan-unsigned

classification:
  risk: low
  reversible: true
  repeatable: true

action:
  skill: vmware-nsx
  tool: refresh_transport_node

approval:
  status: poc_unsigned
"""

_HIGH_RISK_PATTERN = """\
schema_version: 1
pattern_id: vm-delete-rejected

classification:
  risk: high
  reversible: false
  repeatable: true

action:
  skill: vmware-aiops
  tool: vm_delete

approval:
  status: approved
  signed_by: test@example.com
"""

_MISSING_KEY_PATTERN = """\
schema_version: 1
pattern_id: bad-pattern

# missing classification block entirely
action:
  skill: vmware-storage
  tool: storage_rescan
"""


def _write(tmp_dir: Path, name: str, content: str) -> Path:
    p = tmp_dir / f"{name}.yaml"
    p.write_text(content, encoding="utf-8")
    return p


@pytest.fixture()
def tmp_patterns_dir(tmp_path: Path) -> Path:
    d = tmp_path / "patterns"
    d.mkdir()
    return d


@pytest.fixture()
def signed_engine(tmp_patterns_dir: Path) -> PatternEngine:
    _write(tmp_patterns_dir, "iscsi", _SIGNED_ISCSI_PATTERN)
    return PatternEngine(tmp_patterns_dir)


@pytest.mark.unit
class TestPatternLoading:
    def test_loads_valid_pattern(self, signed_engine):
        loaded = signed_engine.loaded_patterns()
        assert len(loaded) == 1
        assert loaded[0].pattern_id == "iscsi-rescan-test"
        assert loaded[0].is_armable is True

    def test_unsigned_pattern_not_armable(self, tmp_patterns_dir):
        _write(tmp_patterns_dir, "unsigned", _UNSIGNED_PATTERN)
        engine = PatternEngine(tmp_patterns_dir)
        loaded = engine.loaded_patterns()
        assert len(loaded) == 1
        assert loaded[0].is_armable is False
        assert loaded[0].risk == "unsigned"

    def test_high_risk_pattern_not_armable(self, tmp_patterns_dir):
        _write(tmp_patterns_dir, "high", _HIGH_RISK_PATTERN)
        engine = PatternEngine(tmp_patterns_dir)
        loaded = engine.loaded_patterns()
        assert len(loaded) == 1
        assert loaded[0].is_armable is False  # risk != "low"

    def test_malformed_pattern_skipped_not_crashed(self, tmp_patterns_dir):
        _write(tmp_patterns_dir, "good", _SIGNED_ISCSI_PATTERN)
        _write(tmp_patterns_dir, "bad", _MISSING_KEY_PATTERN)
        engine = PatternEngine(tmp_patterns_dir)
        loaded = engine.loaded_patterns()
        # Bad one skipped; good one loaded
        assert len(loaded) == 1
        assert loaded[0].pattern_id == "iscsi-rescan-test"

    def test_missing_dir_returns_no_patterns(self, tmp_path):
        engine = PatternEngine(tmp_path / "does-not-exist")
        assert engine.loaded_patterns() == []

    def test_expired_pattern_not_armable(self, tmp_patterns_dir):
        expired = _SIGNED_ISCSI_PATTERN.replace('"2099-01-01"', '"2020-01-01"')
        _write(tmp_patterns_dir, "expired", expired)
        engine = PatternEngine(tmp_patterns_dir)
        loaded = engine.loaded_patterns()
        assert loaded[0].is_armable is False
        assert loaded[0].is_expired is True


@pytest.mark.unit
class TestPatternMatching:
    def test_match_returns_armed_for_valid_action(self, signed_engine):
        result = signed_engine.match("vmware-storage", "storage_rescan", target="esxi-01")
        assert result is not None
        assert result.armed is True
        assert result.pattern.pattern_id == "iscsi-rescan-test"

    def test_no_match_for_different_tool(self, signed_engine):
        result = signed_engine.match("vmware-storage", "list_datastores", target="esxi-01")
        assert result is None

    def test_no_match_for_different_skill(self, signed_engine):
        result = signed_engine.match("vmware-aiops", "storage_rescan", target="esxi-01")
        assert result is None

    def test_unsigned_pattern_matches_but_not_armed(self, tmp_patterns_dir):
        _write(tmp_patterns_dir, "unsigned", _UNSIGNED_PATTERN)
        engine = PatternEngine(tmp_patterns_dir)
        result = engine.match("vmware-nsx", "refresh_transport_node", target="nsx-1")
        assert result is not None
        assert result.armed is False
        assert "not armable" in result.reason


@pytest.mark.unit
class TestRateLimiting:
    def test_hourly_cap_enforced(self, signed_engine):
        # Pattern has max_per_hour_per_host = 4
        for _ in range(4):
            r = signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
            assert r.armed is True

        r = signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
        assert r.armed is False
        assert "hourly cap" in r.reason

    def test_per_target_isolation(self, signed_engine):
        # Saturate host-A
        for _ in range(4):
            signed_engine.match("vmware-storage", "storage_rescan", target="host-A")

        # host-B is fresh
        r = signed_engine.match("vmware-storage", "storage_rescan", target="host-B")
        assert r.armed is True


@pytest.mark.unit
class TestCircuitBreaker:
    def test_three_consecutive_failures_trips_breaker(self, signed_engine):
        # First arm + report 3 failures → circuit breaks
        for _ in range(3):
            r = signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
            assert r.armed is True
            signed_engine.report_outcome("iscsi-rescan-test", "host-A", success=False)

        r = signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
        assert r.armed is False
        assert "circuit-broken" in r.reason

    def test_success_resets_failure_counter(self, signed_engine):
        # 2 failures, then a success, then 1 more failure — should NOT trip
        # (4 arms total = exactly at the 4/hour cap).
        for _ in range(2):
            signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
            signed_engine.report_outcome("iscsi-rescan-test", "host-A", success=False)

        signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
        signed_engine.report_outcome("iscsi-rescan-test", "host-A", success=True)

        # Counter is reset; 4th arm is the rate-limit boundary, not a circuit-break
        r = signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
        assert r.armed is True
        signed_engine.report_outcome("iscsi-rescan-test", "host-A", success=False)

        # 5th arm hits hourly cap, but the cause is rate limit, NOT circuit breaker.
        # Distinguish between the two failure modes.
        r = signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
        assert r.armed is False
        assert "hourly cap" in r.reason
        assert "circuit-broken" not in r.reason

    def test_breaker_isolated_per_target(self, signed_engine):
        for _ in range(3):
            signed_engine.match("vmware-storage", "storage_rescan", target="host-A")
            signed_engine.report_outcome("iscsi-rescan-test", "host-A", success=False)

        # host-A broken; host-B unaffected
        r = signed_engine.match("vmware-storage", "storage_rescan", target="host-B")
        assert r.armed is True


@pytest.mark.unit
class TestHotReload:
    def test_new_file_picked_up(self, tmp_patterns_dir):
        engine = PatternEngine(tmp_patterns_dir)
        assert engine.loaded_patterns() == []

        _write(tmp_patterns_dir, "iscsi", _SIGNED_ISCSI_PATTERN)
        # Force mtime difference
        time.sleep(0.01)

        # Calling match() triggers maybe_reload
        result = engine.match("vmware-storage", "storage_rescan", target="x")
        assert result is not None
        assert result.armed is True
