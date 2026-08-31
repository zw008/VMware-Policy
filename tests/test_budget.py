"""Tests for vmware_policy.budget — token/call hard budget + runaway breaker.

Guards the 2026-06-22 incident class: a tool stuck in a poll/retry loop
consuming unbounded calls/wall-time (the "delete one snapshot, burn 26k tokens"
failure mode).
"""

from __future__ import annotations

import os

import pytest

from vmware_policy.audit import AuditEngine
import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
from vmware_policy.budget import BudgetExceeded, get_budget
from vmware_policy.decorators import vmware_tool


@pytest.fixture(autouse=True)
def _fresh_singletons(tmp_path):
    audit_mod._engine = AuditEngine(tmp_path / "b.db")
    policy_mod._engine = None
    yield audit_mod._engine
    audit_mod._engine = None
    policy_mod._engine = None


@pytest.mark.unit
class TestBudgetTracker:
    def test_no_limits_by_default_never_trips(self):
        b = get_budget()
        for _ in range(200):  # well above the runaway max, but varied params
            b.check_and_record("vm_get", {"name": f"vm-{_}"})  # unique fp each time
        # No exception: hard ceilings are opt-in, varied params don't run away.
        assert b.snapshot()["total_calls"] == 200

    def test_call_ceiling_enforced(self):
        os.environ["VMWARE_MAX_TOOL_CALLS"] = "3"
        b = get_budget()
        for i in range(3):
            b.check_and_record("vm_list", {"i": i})
        with pytest.raises(BudgetExceeded) as ei:
            b.check_and_record("vm_list", {"i": 99})
        assert ei.value.rule == "budget_calls"
        assert "budget" in str(ei.value).lower()

    def test_time_ceiling_enforced(self):
        os.environ["VMWARE_MAX_TOOL_SECONDS"] = "1"
        b = get_budget()
        b.check_and_record("vm_migrate", {"n": 1})
        b.add_duration(5.0)  # blow the 1s cumulative budget
        with pytest.raises(BudgetExceeded) as ei:
            b.check_and_record("vm_migrate", {"n": 2})
        assert ei.value.rule == "budget_seconds"

    def test_runaway_breaker_identical_calls(self):
        os.environ["VMWARE_RUNAWAY_MAX"] = "5"
        os.environ["VMWARE_RUNAWAY_WINDOW_SEC"] = "60"
        b = get_budget()
        params = {"task_id": "task-1"}  # identical → same fingerprint
        for _ in range(5):
            b.check_and_record("vm_task_status", params)
        with pytest.raises(BudgetExceeded) as ei:
            b.check_and_record("vm_task_status", params)
        assert ei.value.rule == "budget_runaway"
        assert "loop" in str(ei.value).lower()

    def test_runaway_does_not_trip_on_varied_params(self):
        os.environ["VMWARE_RUNAWAY_MAX"] = "5"
        b = get_budget()
        for i in range(20):  # different task_id each call
            b.check_and_record("vm_task_status", {"task_id": f"task-{i}"})

    def test_runaway_disabled_when_max_zero(self):
        os.environ["VMWARE_RUNAWAY_MAX"] = "0"
        b = get_budget()
        for _ in range(100):
            b.check_and_record("vm_x", {"same": "args"})  # would trip if enabled


@pytest.mark.unit
class TestBudgetThroughDecorator:
    def test_runaway_trips_through_vmware_tool_and_audits_denial(self, _fresh_singletons):
        os.environ["VMWARE_RUNAWAY_MAX"] = "3"
        os.environ["VMWARE_RUNAWAY_WINDOW_SEC"] = "60"

        @vmware_tool
        def poll(target: str = "t1") -> str:
            return "running"

        for _ in range(3):
            assert poll() == "running"
        with pytest.raises(BudgetExceeded):
            poll()

        # The tripped call is audited as a budget_exceeded denial, not an error.
        rows = _fresh_singletons.query(limit=5)
        assert any(r["status"] == "budget_exceeded" for r in rows)

    def test_policy_denied_calls_do_not_consume_budget(self, _fresh_singletons, tmp_path):
        # A denied call must not count toward the runaway window.
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n  - name: block_poll\n    operations: [poll]\n    reason: nope\n"
        , encoding="utf-8")
        policy_mod._engine = policy_mod.PolicyEngine(rules)

        from vmware_policy.decorators import PolicyDenied

        @vmware_tool
        def poll(target: str = "t1") -> str:
            return "ok"

        for _ in range(10):
            with pytest.raises(PolicyDenied):
                poll()
        # None recorded — denied before budget.check_and_record.
        assert get_budget().snapshot()["total_calls"] == 0
