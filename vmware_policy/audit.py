"""Unified audit logging engine — all VMware skills write to a single SQLite database.

Replaces 7 per-skill JSON Lines audit loggers with one shared ``~/.vmware/audit.db``.
Framework-agnostic: works with Claude, Codex, local agents, or any MCP client.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_log = logging.getLogger("vmware-policy.audit")

_DEFAULT_DB = Path("~/.vmware/audit.db").expanduser()
_MAX_DB_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
_MAX_ARCHIVES = 5
_BUSY_TIMEOUT_MS = 5000

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    skill       TEXT    NOT NULL,
    tool        TEXT    NOT NULL,
    params      TEXT    NOT NULL DEFAULT '{}',
    result      TEXT    NOT NULL DEFAULT '{}',
    status      TEXT    NOT NULL DEFAULT 'ok',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    agent       TEXT    NOT NULL DEFAULT 'unknown',
    workflow_id TEXT    NOT NULL DEFAULT '',
    user        TEXT    NOT NULL DEFAULT 'unknown',
    risk_level  TEXT    NOT NULL DEFAULT 'low'
)
"""

_INSERT = """\
INSERT INTO audit_log (ts, skill, tool, params, result, status, duration_ms, agent, workflow_id, user, risk_level)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class AuditEngine:
    """Append-only audit logger backed by SQLite with WAL mode.

    Thread-safe for concurrent writes from multiple skill processes.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._path = Path(db_path).expanduser() if db_path else _DEFAULT_DB
        self._ok = False
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
            self._ok = True
        except Exception:
            _log.warning("Cannot initialize audit DB at %s", self._path, exc_info=True)

    def _init_db(self) -> None:
        conn = self._connect()
        conn.execute(_CREATE_TABLE)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=_BUSY_TIMEOUT_MS / 1000)
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        return conn

    def log(
        self,
        *,
        skill: str,
        tool: str,
        params: dict[str, Any] | None = None,
        result: Any = None,
        status: str = "ok",
        duration_ms: int = 0,
        agent: str = "unknown",
        workflow_id: str = "",
        user: str = "",
        risk_level: str = "low",
    ) -> None:
        """Write one audit record.  Never raises — swallows errors to avoid
        disrupting the actual tool execution."""
        if not self._ok:
            return
        try:
            self._maybe_rotate()
            conn = self._connect()
            conn.execute(
                _INSERT,
                (
                    datetime.now(tz=timezone.utc).isoformat(),
                    skill,
                    tool,
                    _safe_json(params),
                    _safe_json(result),
                    status,
                    duration_ms,
                    agent,
                    workflow_id,
                    user or _current_user(),
                    risk_level,
                ),
            )
            conn.commit()
            conn.close()
            _log.debug("[AUDIT] %s.%s -> %s (%dms)", skill, tool, status, duration_ms)
        except Exception:
            _log.warning("Failed to write audit log", exc_info=True)

    # ── Rotation ──────────────────────────────────────────────────────

    def _maybe_rotate(self) -> None:
        """Archive the DB if it exceeds size limit."""
        try:
            if not self._path.exists():
                return
            if self._path.stat().st_size < _MAX_DB_SIZE_BYTES:
                return
            archive_name = self._path.with_suffix(
                f".{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
            )
            self._path.rename(archive_name)
            self._init_db()
            self._cleanup_archives()
            _log.info("Audit DB rotated → %s", archive_name.name)
        except Exception:
            _log.warning("Audit DB rotation failed", exc_info=True)

    def _cleanup_archives(self) -> None:
        """Keep only the most recent N archive files."""
        archives = sorted(
            self._path.parent.glob("audit.*.db"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in archives[_MAX_ARCHIVES:]:
            old.unlink(missing_ok=True)

    # ── Query helpers (used by CLI) ───────────────────────────────────

    def query(
        self,
        *,
        skill: str | None = None,
        tool: str | None = None,
        status: str | None = None,
        workflow_id: str | None = None,
        since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query audit records with optional filters."""
        clauses: list[str] = []
        values: list[Any] = []

        if skill:
            clauses.append("skill = ?")
            values.append(skill)
        if tool:
            clauses.append("tool = ?")
            values.append(tool)
        if status:
            clauses.append("status = ?")
            values.append(status)
        if workflow_id:
            clauses.append("workflow_id = ?")
            values.append(workflow_id)
        if since:
            clauses.append("ts >= ?")
            values.append(since)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?"
        values.append(limit)

        conn = self._connect()
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, values).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def stats(self, days: int = 7) -> dict[str, Any]:
        """Aggregate statistics over the last N days."""
        since = datetime.now(tz=timezone.utc).isoformat()[:10]  # rough
        conn = self._connect()
        conn.row_factory = sqlite3.Row

        total = conn.execute(
            "SELECT COUNT(*) as c FROM audit_log WHERE ts >= ?", (since,)
        ).fetchone()["c"]

        by_status = {
            r["status"]: r["c"]
            for r in conn.execute(
                "SELECT status, COUNT(*) as c FROM audit_log WHERE ts >= ? GROUP BY status",
                (since,),
            ).fetchall()
        }

        by_skill = {
            r["skill"]: r["c"]
            for r in conn.execute(
                "SELECT skill, COUNT(*) as c FROM audit_log WHERE ts >= ? GROUP BY skill",
                (since,),
            ).fetchall()
        }

        conn.close()
        return {"total": total, "by_status": by_status, "by_skill": by_skill, "days": days}


# ── Module-level helpers ──────────────────────────────────────────────

def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _safe_json(obj: Any) -> str:
    """Serialize to JSON, falling back to str() for non-serializable objects."""
    if obj is None:
        return "{}"
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"_raw": str(obj)})


def detect_agent() -> str:
    """Infer the calling AI agent from environment variables."""
    if os.environ.get("CLAUDE_SESSION_ID") or os.environ.get("CLAUDE_CODE"):
        return "claude"
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("CODEX_SESSION"):
        return "codex"
    if os.environ.get("OLLAMA_HOST"):
        return "local"
    if os.environ.get("DEERFLOW_SESSION"):
        return "deerflow"
    return "unknown"


# Singleton — shared across all skills in the same process
_engine: AuditEngine | None = None


def get_engine(db_path: Path | str | None = None) -> AuditEngine:
    """Return the global AuditEngine singleton (lazy-initialized)."""
    global _engine
    if _engine is None:
        _engine = AuditEngine(db_path)
    return _engine
