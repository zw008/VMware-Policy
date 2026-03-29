"""Tests for vmware_policy.audit."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from vmware_policy.audit import AuditEngine, detect_agent


@pytest.mark.unit
class TestAuditEngine:
    def setup_method(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.db_path = Path(self._tmp.name)
        self.engine = AuditEngine(self.db_path)

    def teardown_method(self):
        self.db_path.unlink(missing_ok=True)

    def test_creates_db_and_table(self):
        conn = sqlite3.connect(str(self.db_path))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        conn.close()
        assert ("audit_log",) in tables

    def test_wal_mode_enabled(self):
        conn = sqlite3.connect(str(self.db_path))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode == "wal"

    def test_log_writes_record(self):
        self.engine.log(skill="aiops", tool="vm_power_on", status="ok")
        rows = self.engine.query(limit=10)
        assert len(rows) == 1
        assert rows[0]["skill"] == "aiops"
        assert rows[0]["tool"] == "vm_power_on"
        assert rows[0]["status"] == "ok"

    def test_log_denied_writes_record(self):
        self.engine.log(skill="nsx", tool="delete_segment", status="denied")
        rows = self.engine.query(status="denied")
        assert len(rows) == 1
        assert rows[0]["status"] == "denied"

    def test_query_filters(self):
        self.engine.log(skill="aiops", tool="vm_power_on", status="ok")
        self.engine.log(skill="nsx", tool="delete_segment", status="denied")
        self.engine.log(skill="aiops", tool="vm_power_off", status="error")

        assert len(self.engine.query(skill="aiops")) == 2
        assert len(self.engine.query(status="denied")) == 1
        assert len(self.engine.query(tool="vm_power_on")) == 1

    def test_stats(self):
        self.engine.log(skill="aiops", tool="a", status="ok")
        self.engine.log(skill="aiops", tool="b", status="ok")
        self.engine.log(skill="nsx", tool="c", status="denied")
        data = self.engine.stats(days=1)
        assert data["total"] == 3
        assert data["by_skill"]["aiops"] == 2
        assert data["by_status"]["denied"] == 1

    def test_log_never_raises(self):
        """Audit logging should swallow errors, not crash the tool."""
        # Use an invalid path that can't be written
        bad_engine = AuditEngine("/nonexistent/path/audit.db")
        bad_engine.log(skill="test", tool="test")  # should not raise

    def test_sensitive_params_stored(self):
        self.engine.log(
            skill="aiops",
            tool="guest_exec",
            params={"command": "ls", "password": "***"},
            status="ok",
        )
        rows = self.engine.query(limit=1)
        assert "***" in rows[0]["params"]


@pytest.mark.unit
class TestDetectAgent:
    def test_default_unknown(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_SESSION_ID", raising=False)
        monkeypatch.delenv("CLAUDE_CODE", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        monkeypatch.delenv("DEERFLOW_SESSION", raising=False)
        monkeypatch.delenv("CODEX_SESSION", raising=False)
        assert detect_agent() == "unknown"

    def test_detect_claude(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE", "1")
        assert detect_agent() == "claude"

    def test_detect_local(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_SESSION_ID", raising=False)
        monkeypatch.delenv("CLAUDE_CODE", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("CODEX_SESSION", raising=False)
        monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
        assert detect_agent() == "local"
