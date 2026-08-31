"""Regression tests for the v1.5.35+ fix batch.

Covers:
  1. timeout_seconds advisory warning
  2. async def tools get full audit/policy semantics
  3. pattern matcher prefers armable matches
  4. positional args are audited + env-scoped
  5. malformed maintenance window fails CLOSED
  6. singleton path-mismatch warning + reset helpers
  7. WAL checkpoint before audit DB rotation
  8. detect_agent / sanitize / __all__ hygiene
  9. v1.5.35 fixes: nested redaction, bypass-mode names-only logging,
     sanitized exception text, concurrent audit writes
"""

import asyncio
import json
import logging
import sqlite3
import threading

import pytest

import vmware_policy.audit as audit_mod
import vmware_policy.patterns as patterns_mod
import vmware_policy.policy as policy_mod
from vmware_policy.audit import AuditEngine, detect_agent, get_engine, reset_engine
from vmware_policy.decorators import PolicyDenied, vmware_tool
from vmware_policy.patterns import PatternEngine
from vmware_policy.policy import PolicyEngine, get_policy_engine, reset_policy_engine
from vmware_policy.sanitize import sanitize


@pytest.fixture(autouse=True)
def _fresh_singletons(tmp_path):
    """Reset audit / policy / pattern singletons for each test."""
    engine = AuditEngine(tmp_path / "audit.db")
    audit_mod._engine = engine
    policy_mod._engine = None
    patterns_mod._engine = None
    yield engine
    audit_mod._engine = None
    policy_mod._engine = None
    patterns_mod._engine = None


# ── 1. timeout_seconds advisory warning ───────────────────────────────


@pytest.mark.unit
class TestTimeoutWarning:
    def test_warning_logged_when_duration_exceeds_timeout(self, caplog):
        import time

        # Fractional timeout keeps the test fast; the comparison is in ms.
        @vmware_tool(timeout_seconds=0.01)
        def slow_op() -> str:
            time.sleep(0.05)
            return "done"

        with caplog.at_level(logging.WARNING, logger="vmware-policy.decorators"):
            slow_op()
        assert any("exceeded timeout_seconds" in r.message for r in caplog.records)

    def test_no_warning_when_within_timeout(self, caplog):
        @vmware_tool(timeout_seconds=300)
        def fast_op() -> str:
            return "done"

        with caplog.at_level(logging.WARNING, logger="vmware-policy.decorators"):
            fast_op()
        assert not any("exceeded timeout_seconds" in r.message for r in caplog.records)


# ── 2. async tools ────────────────────────────────────────────────────


@pytest.mark.unit
class TestAsyncTools:
    def test_async_tool_returns_value_and_audits_ok(self, _fresh_singletons):
        @vmware_tool(risk_level="low")
        async def async_list(target: str = "") -> dict:
            await asyncio.sleep(0)
            return {"vms": ["a"]}

        result = asyncio.run(async_list(target="vc1"))
        assert result == {"vms": ["a"]}
        rows = _fresh_singletons.query(limit=1)
        assert rows[0]["tool"] == "async_list"
        assert rows[0]["status"] == "ok"

    def test_async_tool_error_audited(self, _fresh_singletons):
        @vmware_tool
        async def async_boom() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(async_boom())
        rows = _fresh_singletons.query(limit=1)
        assert rows[0]["status"] == "error"

    def test_async_tool_policy_denied(self, tmp_path, _fresh_singletons):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: no-delete\n"
            '    operations: ["delete_*"]\n'
            "    reason: Deletion not allowed\n"
        , encoding="utf-8")
        policy_mod._engine = PolicyEngine(rules)

        @vmware_tool(risk_level="high")
        async def delete_thing(name: str) -> str:
            return "deleted"

        with pytest.raises(PolicyDenied, match="Deletion not allowed"):
            asyncio.run(delete_thing(name="x"))
        rows = _fresh_singletons.query(limit=1)
        assert rows[0]["status"] == "denied"

    def test_async_metadata_attached(self):
        @vmware_tool(risk_level="high", idempotent=True)
        async def meta_tool() -> None:
            pass

        assert meta_tool._is_vmware_tool is True
        assert meta_tool._risk_level == "high"


# ── 3. pattern matcher prefers armable match ──────────────────────────

_PATTERN_TMPL = (
    "schema_version: 1\n"
    "pattern_id: {pid}\n"
    "classification:\n"
    "  risk: low\n"
    "  reversible: true\n"
    "  repeatable: true\n"
    "action:\n"
    "  skill: aiops\n"
    "  tool: vm_restart\n"
    "{approval}"
)

_APPROVED = "approval:\n  status: approved\n  signed_by: ops@example.com\n"
_UNSIGNED = "approval:\n  status: pending\n"


@pytest.mark.unit
class TestArmableMatchPreferred:
    def test_armable_pattern_not_shadowed_by_earlier_non_armable(self, tmp_path):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        # Loaded in sorted filename order: unsigned pattern first.
        (pdir / "a_unsigned.yaml").write_text(
            _PATTERN_TMPL.format(pid="pat-unsigned", approval=_UNSIGNED)
        , encoding="utf-8")
        (pdir / "b_signed.yaml").write_text(
            _PATTERN_TMPL.format(pid="pat-signed", approval=_APPROVED)
        , encoding="utf-8")
        engine = PatternEngine(pdir)
        m = engine.match(skill="aiops", tool="vm_restart", target="esxi-01")
        assert m is not None
        assert m.armed is True
        assert m.pattern.pattern_id == "pat-signed"

    def test_non_armable_returned_when_no_armable_exists(self, tmp_path):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        (pdir / "a_unsigned.yaml").write_text(
            _PATTERN_TMPL.format(pid="pat-unsigned", approval=_UNSIGNED)
        , encoding="utf-8")
        engine = PatternEngine(pdir)
        m = engine.match(skill="aiops", tool="vm_restart", target="esxi-01")
        assert m is not None
        assert m.armed is False
        assert m.pattern.pattern_id == "pat-unsigned"

    def test_no_match_returns_none(self, tmp_path):
        pdir = tmp_path / "patterns"
        pdir.mkdir()
        engine = PatternEngine(pdir)
        assert engine.match(skill="aiops", tool="vm_restart", target="") is None


# ── 4. positional args audited + env-scoped ───────────────────────────


@pytest.mark.unit
class TestPositionalArgs:
    def test_positional_args_appear_in_audit(self, _fresh_singletons):
        @vmware_tool
        def power_on(vm_name: str, target: str = "") -> str:
            return "ok"

        power_on("web-01", "vcenter-prod")  # all positional
        rows = _fresh_singletons.query(limit=1)
        params = json.loads(rows[0]["params"])
        assert params["vm_name"] == "web-01"
        assert params["target"] == "vcenter-prod"

    def test_positional_target_is_env_scoped(self, tmp_path, _fresh_singletons):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: prod-freeze\n"
            '    operations: ["*"]\n'
            '    environments: ["prod"]\n'
            "    reason: prod is frozen\n"
        , encoding="utf-8")
        policy_mod._engine = PolicyEngine(rules)
        # env now comes from the target's declared environment, not its name.
        from vmware_policy.environment import set_environment_resolver

        set_environment_resolver(lambda target: "prod" if "prod" in target else "lab")

        @vmware_tool
        def reconfigure(vm_name: str, target: str = "") -> str:
            return "ok"

        # Positional target must reach the policy env check
        with pytest.raises(PolicyDenied, match="prod is frozen"):
            reconfigure("web-01", "prod")
        assert reconfigure("web-01", "dev") == "ok"

    def test_positional_sensitive_param_redacted(self, _fresh_singletons):
        @vmware_tool(sensitive_params=["password"])
        def login(user: str, password: str) -> str:
            return "ok"

        login("admin", "supersecret")  # positional password
        params = _fresh_singletons.query(limit=1)[0]["params"]
        assert "supersecret" not in params
        assert "***" in params


# ── 5. malformed maintenance window fails CLOSED ──────────────────────


@pytest.mark.unit
class TestMaintenanceWindowFailClosed:
    def _engine_with_window(self, tmp_path, window_yaml: str) -> PolicyEngine:
        rules = tmp_path / "rules.yaml"
        rules.write_text("maintenance_window:\n" + window_yaml, encoding="utf-8")
        return PolicyEngine(rules)

    def test_malformed_window_denies_high_risk(self, tmp_path, caplog):
        engine = self._engine_with_window(tmp_path, '  start: "garbage"\n  end: "06:00"\n')
        with caplog.at_level(logging.ERROR, logger="vmware-policy.policy"):
            result = engine.check_allowed("delete_vm", risk_level="high")
        assert result.allowed is False
        assert result.rule == "maintenance_window_malformed"
        assert "HH:MM" in result.reason  # teaching message
        assert any("failing CLOSED" in r.message for r in caplog.records)

    def test_malformed_window_still_allows_low_risk(self, tmp_path):
        engine = self._engine_with_window(tmp_path, '  start: "garbage"\n  end: "06:00"\n')
        assert engine.check_allowed("list_vms", risk_level="low").allowed is True

    def test_wellformed_window_unaffected(self, tmp_path):
        engine = self._engine_with_window(tmp_path, '  start: "00:00"\n  end: "23:59"\n')
        assert engine.check_allowed("delete_vm", risk_level="high").allowed is True


# ── 6. singleton path-mismatch warning + reset helpers ────────────────


@pytest.mark.unit
class TestSingletonHygiene:
    def test_get_engine_warns_on_different_path(self, tmp_path, caplog):
        reset_engine()
        try:
            first = get_engine(tmp_path / "a.db")
            with caplog.at_level(logging.WARNING, logger="vmware-policy.audit"):
                second = get_engine(tmp_path / "b.db")
            assert second is first
            assert any("reset_engine()" in r.message for r in caplog.records)
        finally:
            reset_engine()

    def test_reset_engine_rebinds(self, tmp_path):
        reset_engine()
        try:
            first = get_engine(tmp_path / "a.db")
            reset_engine()
            second = get_engine(tmp_path / "b.db")
            assert second is not first
            assert second._path == tmp_path / "b.db"
        finally:
            reset_engine()

    def test_get_policy_engine_warns_on_different_path(self, tmp_path, caplog):
        reset_policy_engine()
        try:
            (tmp_path / "a.yaml").write_text("", encoding="utf-8")
            first = get_policy_engine(tmp_path / "a.yaml")
            with caplog.at_level(logging.WARNING, logger="vmware-policy.policy"):
                second = get_policy_engine(tmp_path / "b.yaml")
            assert second is first
            assert any("reset_policy_engine()" in r.message for r in caplog.records)
        finally:
            reset_policy_engine()

    def test_reset_policy_engine_rebinds(self, tmp_path):
        reset_policy_engine()
        try:
            first = get_policy_engine(tmp_path / "a.yaml")
            reset_policy_engine()
            second = get_policy_engine(tmp_path / "b.yaml")
            assert second is not first
        finally:
            reset_policy_engine()


# ── 7. WAL checkpoint before rotation ─────────────────────────────────


@pytest.mark.unit
class TestRotationWalCheckpoint:
    def test_rotation_preserves_wal_resident_rows(self, tmp_path, monkeypatch):
        db = tmp_path / "audit.db"
        engine = AuditEngine(db)
        # Hold a second connection open so SQLite does NOT auto-checkpoint
        # the WAL when the engine's per-log connections close.
        holder = sqlite3.connect(str(db))
        try:
            holder.execute("SELECT 1")
            for i in range(3):
                engine.log(skill="s", tool=f"tool_{i}")
            wal = db.with_name("audit.db-wal")
            assert wal.exists() and wal.stat().st_size > 0

            monkeypatch.setattr(audit_mod, "_MAX_DB_SIZE_BYTES", 1)
            engine.log(skill="s", tool="after_rotate")
        finally:
            holder.close()

        archives = list(tmp_path.glob("audit.*.db"))
        assert len(archives) == 1
        # Without the pre-rename checkpoint, the 3 rows would be stranded in
        # the orphaned -wal sidecar and the archive would be empty.
        conn = sqlite3.connect(str(archives[0]))
        try:
            count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        finally:
            conn.close()
        assert count == 3

        rows = engine.query(limit=10)
        assert len(rows) == 1
        assert rows[0]["tool"] == "after_rotate"


# ── 8. detect_agent / __all__ hygiene ─────────────────────────────────


@pytest.mark.unit
class TestHygiene:
    def test_openai_api_key_is_not_a_codex_marker(self, monkeypatch):
        for var in ("CLAUDE_SESSION_ID", "CLAUDE_CODE", "CODEX_SESSION",
                    "OLLAMA_HOST", "DEERFLOW_SESSION"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-whatever")
        assert detect_agent() == "unknown"

    def test_codex_session_still_detected(self, monkeypatch):
        for var in ("CLAUDE_SESSION_ID", "CLAUDE_CODE"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("CODEX_SESSION", "1")
        assert detect_agent() == "codex"

    def test_public_exports(self):
        import vmware_policy

        for name in ("vmware_tool", "sanitize", "PolicyDenied", "get_engine",
                     "get_policy_engine", "AuditEngine"):
            assert name in vmware_policy.__all__
            assert hasattr(vmware_policy, name)


# ── 9. v1.5.35 fixes (previously untested) ────────────────────────────


@pytest.mark.unit
class TestV1535Fixes:
    def test_nested_list_redaction(self, _fresh_singletons):
        @vmware_tool(sensitive_params=["password"])
        def multi_login(targets: list) -> str:
            return "ok"

        multi_login(targets=[{"host": "h1", "password": "p1"},
                             {"host": "h2", "password": "p2"}])
        params = _fresh_singletons.query(limit=1)[0]["params"]
        assert "p1" not in params and "p2" not in params
        assert params.count("***") == 2
        assert "h1" in params

    def test_nested_tuple_redaction(self, _fresh_singletons):
        @vmware_tool(sensitive_params=["token"])
        def tuple_op(pair: tuple = ()) -> str:
            return "ok"

        tuple_op(pair=({"token": "tok-123"}, "plain"))
        params = _fresh_singletons.query(limit=1)[0]["params"]
        assert "tok-123" not in params
        assert "***" in params

    def test_bypass_mode_logs_param_names_only(self, tmp_path, caplog, monkeypatch):
        monkeypatch.setenv("VMWARE_POLICY_DISABLED", "1")
        engine = PolicyEngine(tmp_path / "rules.yaml")
        with caplog.at_level(logging.WARNING, logger="vmware-policy.policy"):
            result = engine.check_allowed(
                "delete_vm", env="prod", risk_level="high",
                params={"vm_name": "web-01", "password": "supersecret"},
            )
        assert result.allowed is True
        assert result.rule == "policy_disabled"
        log_text = " ".join(r.getMessage() for r in caplog.records)
        assert "supersecret" not in log_text
        assert "web-01" not in log_text  # values never logged, only names
        assert "password" in log_text

    def test_exception_text_sanitized_in_audit_row(self, _fresh_singletons):
        @vmware_tool
        def failing_login() -> None:
            raise RuntimeError("connect failed password=supersecret host=vc1")

        with pytest.raises(RuntimeError):
            failing_login()
        row = _fresh_singletons.query(limit=1)[0]
        assert "supersecret" not in row["result"]
        assert "***" in row["result"]

    def test_concurrent_audit_writes(self, tmp_path):
        engine = AuditEngine(tmp_path / "hammer.db")
        errors: list[Exception] = []

        def hammer(thread_id: int) -> None:
            try:
                for i in range(50):
                    engine.log(skill="s", tool=f"t{thread_id}_{i}")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=hammer, args=(t,)) for t in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        rows = engine.query(limit=200)
        assert len(rows) == 100

    def test_sanitize_strips_format_chars_before_truncation(self):
        # Zero-width-space (Cf) padding must not shield the payload either
        padded = "​" * 600 + "payload"
        assert sanitize(padded) == "payload"


class TestPolicyGlobMatching:
    """Leading-wildcard patterns silently matched nothing (2026-07-18).

    ``_pattern_match`` handled only a trailing ``*`` — every other pattern fell
    through to an equality test. So a rule written ``operations: ["*_delete"]``
    compiled fine, read correctly, and never fired. A deny rule that looks
    configured but is inert is worse than no rule at all, because the operator
    stops looking. Fixed by delegating to ``fnmatch.fnmatchcase``.
    """

    @staticmethod
    def _match(pattern: str, value: str) -> bool:
        from vmware_policy.policy import PolicyEngine

        return PolicyEngine._pattern_match(pattern, value)

    def test_trailing_wildcard_still_works(self):
        assert self._match("delete_*", "delete_segment")
        assert not self._match("delete_*", "vm_delete")

    def test_leading_wildcard_now_matches(self):
        assert self._match("*_delete", "vm_delete")
        assert self._match("*_delete", "cluster_delete")
        assert not self._match("*_delete", "delete_segment")

    def test_infix_wildcard_now_matches(self):
        assert self._match("vm_*_snapshot", "vm_create_snapshot")
        assert not self._match("vm_*_snapshot", "vm_create_plan")

    def test_bare_star_matches_everything(self):
        assert self._match("*", "anything_at_all")

    def test_exact_name_still_requires_exact_match(self):
        assert self._match("vm_delete", "vm_delete")
        assert not self._match("vm_delete", "vm_delete_snapshot")

    def test_matching_is_case_sensitive(self):
        """Tool names are snake_case identifiers; a case-insensitive policy
        would match things the operator never wrote."""
        assert not self._match("vm_*", "VM_Delete")

    def test_deny_rule_with_leading_wildcard_actually_denies(self, tmp_path):
        """End-to-end: the shape that was silently inert before."""
        from vmware_policy.policy import PolicyEngine

        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: no-deletes\n"
            '    operations: ["*_delete"]\n'
            '    reason: "blocked"\n'
        , encoding="utf-8")
        engine = PolicyEngine(rules_path=rules)
        assert engine.check_allowed("vm_delete").allowed is False
        assert engine.check_allowed("vm_info").allowed is True
