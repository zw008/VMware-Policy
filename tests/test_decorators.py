"""Tests for vmware_policy.decorators — the @vmware_tool decorator."""

import tempfile
from pathlib import Path

import pytest

from vmware_policy.audit import AuditEngine, _engine
from vmware_policy.decorators import PolicyDenied, vmware_tool
import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod


@pytest.fixture(autouse=True)
def _fresh_singletons(tmp_path):
    """Reset audit and policy singletons for each test."""
    db_path = tmp_path / "test_audit.db"
    engine = AuditEngine(db_path)
    audit_mod._engine = engine
    policy_mod._engine = None
    yield engine
    audit_mod._engine = None
    policy_mod._engine = None


@pytest.mark.unit
class TestVmwareTool:
    def test_bare_decorator(self, _fresh_singletons):
        """@vmware_tool without arguments."""
        @vmware_tool
        def list_segments(target: str = "") -> list:
            return ["seg1", "seg2"]

        result = list_segments()
        assert result == ["seg1", "seg2"]

    def test_decorator_with_args(self, _fresh_singletons):
        """@vmware_tool(risk_level='high')."""
        @vmware_tool(risk_level="high", sensitive_params=["password"])
        def delete_vm(name: str, password: str = "") -> str:
            return f"deleted {name}"

        result = delete_vm(name="test-vm", password="secret123")
        assert result == "deleted test-vm"

    def test_metadata_attached(self):
        @vmware_tool(risk_level="critical", idempotent=True, timeout_seconds=60)
        def my_tool() -> None:
            pass

        assert my_tool._is_vmware_tool is True
        assert my_tool._risk_level == "critical"
        assert my_tool._idempotent is True
        assert my_tool._timeout_seconds == 60

    def test_audit_log_written(self, _fresh_singletons):
        engine = _fresh_singletons

        @vmware_tool
        def my_op(target: str = "") -> str:
            return "done"

        my_op(target="vcenter1")
        rows = engine.query(limit=10)
        assert len(rows) == 1
        assert rows[0]["tool"] == "my_op"
        assert rows[0]["status"] == "ok"

    def test_error_logged(self, _fresh_singletons):
        engine = _fresh_singletons

        @vmware_tool
        def failing_op() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            failing_op()

        rows = engine.query(limit=10)
        assert len(rows) == 1
        assert rows[0]["status"] == "error"

    def test_sensitive_params_redacted(self, _fresh_singletons):
        engine = _fresh_singletons

        @vmware_tool(sensitive_params=["password", "token"])
        def login(user: str, password: str, token: str = "") -> str:
            return "ok"

        login(user="admin", password="secret", token="abc123")
        rows = engine.query(limit=1)
        params = rows[0]["params"]
        assert "secret" not in params
        assert "abc123" not in params
        assert "***" in params
        assert "admin" in params

    def test_preserves_function_name(self):
        @vmware_tool
        def original_name() -> None:
            """Original docstring."""
            pass

        assert original_name.__name__ == "original_name"
        assert original_name.__doc__ == "Original docstring."

    def test_duration_recorded(self, _fresh_singletons):
        import time

        engine = _fresh_singletons

        @vmware_tool
        def slow_op() -> str:
            time.sleep(0.05)
            return "done"

        slow_op()
        rows = engine.query(limit=1)
        assert rows[0]["duration_ms"] >= 40


@pytest.mark.unit
class TestPolicyDenied:
    def test_denied_logged_with_status(self, _fresh_singletons, tmp_path):
        engine = _fresh_singletons

        # Create a policy with deny rule
        rules_path = tmp_path / "rules.yaml"
        rules_path.write_text(
            "deny:\n"
            "  - name: no-delete\n"
            '    operations: ["delete_*"]\n'
            "    reason: Deletion not allowed\n"
        )
        policy_mod._engine = None
        import vmware_policy.policy as pm
        pm._engine = pm.PolicyEngine(rules_path)

        @vmware_tool(risk_level="high")
        def delete_segment(name: str) -> str:
            return "deleted"

        with pytest.raises(PolicyDenied, match="Deletion not allowed"):
            delete_segment(name="seg1")

        rows = engine.query(limit=1)
        assert rows[0]["status"] == "denied"
