"""Policy engine — rule-based access control for VMware MCP tools.

Rules are loaded from ``~/.vmware/rules.yaml`` with hot-reload on file change.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger("vmware-policy.policy")

_DEFAULT_RULES_PATH = Path("~/.vmware/rules.yaml").expanduser()

# ── Data structures ───────────────────────────────────────────────────


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of a policy check."""

    allowed: bool
    rule: str = ""
    reason: str = ""


# ── Risk levels ───────────────────────────────────────────────────────

RISK_LEVELS = ("low", "medium", "high", "critical")


def risk_requires_confirmation(risk_level: str, env: str = "") -> bool:
    """Determine if a risk level requires human confirmation.

    - critical: always requires confirmation + approval in production
    - high: requires confirmation
    - medium/low: no confirmation
    """
    if risk_level == "critical":
        return True
    if risk_level == "high":
        return True
    return False


# ── Rule loading with hot-reload ──────────────────────────────────────


class PolicyEngine:
    """Evaluate operations against a YAML rule set.

    Rules file is re-read when its mtime changes (hot-reload, no restart needed).
    """

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self._path = Path(rules_path).expanduser() if rules_path else _DEFAULT_RULES_PATH
        self._rules: dict[str, Any] = {}
        self._mtime: float = 0.0
        self._load_rules()

    def _load_rules(self) -> None:
        """Load rules from YAML file.  Missing file → empty rules (allow all)."""
        if not self._path.exists():
            self._rules = {}
            self._mtime = 0.0
            return
        try:
            import yaml

            self._mtime = self._path.stat().st_mtime
            with open(self._path) as fh:
                self._rules = yaml.safe_load(fh) or {}
            _log.debug("Loaded %d policy rules from %s", len(self._rules), self._path)
        except Exception:
            _log.warning("Failed to load policy rules from %s", self._path, exc_info=True)
            self._rules = {}

    def _maybe_reload(self) -> None:
        """Hot-reload if file changed."""
        if not self._path.exists():
            return
        try:
            current_mtime = self._path.stat().st_mtime
            if current_mtime != self._mtime:
                self._load_rules()
        except Exception:
            pass

    def check_allowed(
        self,
        operation: str,
        *,
        env: str = "",
        risk_level: str = "low",
        params: dict[str, Any] | None = None,
    ) -> PolicyResult:
        """Check if an operation is allowed by policy.

        Args:
            operation: Tool function name (e.g. 'delete_segment').
            env: Target environment name (e.g. 'production').
            risk_level: Risk level declared by @vmware_tool.
            params: Operation parameters for rule evaluation.

        Returns:
            PolicyResult with allowed=True/False and reason.
        """
        # Bypass mode (still logs as bypassed — handled by decorator)
        if os.environ.get("VMWARE_POLICY_DISABLED") == "1":
            return PolicyResult(allowed=True, rule="policy_disabled")

        self._maybe_reload()

        # No rules file → allow everything
        if not self._rules:
            return PolicyResult(allowed=True, rule="no_rules")

        # ── Evaluate deny rules ───────────────────────────────────────
        deny_rules = self._rules.get("deny", [])
        for rule in deny_rules:
            if self._rule_matches(rule, operation, env, risk_level, params):
                reason = rule.get("reason", f"Denied by rule: {rule.get('name', 'unnamed')}")
                return PolicyResult(allowed=False, rule=rule.get("name", "deny"), reason=reason)

        # ── Evaluate maintenance window ───────────────────────────────
        window = self._rules.get("maintenance_window")
        if window and risk_level in ("high", "critical"):
            if not self._in_maintenance_window(window):
                return PolicyResult(
                    allowed=False,
                    rule="maintenance_window",
                    reason=f"High-risk operations only allowed during {window.get('start', '?')}-{window.get('end', '?')}",
                )

        # ── Evaluate change limits ────────────────────────────────────
        limits = self._rules.get("change_limits", {})
        if params and limits:
            result = self._check_limits(limits, params, operation)
            if result and not result.allowed:
                return result

        return PolicyResult(allowed=True, rule="default_allow")

    def _rule_matches(
        self,
        rule: dict[str, Any],
        operation: str,
        env: str,
        risk_level: str,
        params: dict[str, Any] | None,
    ) -> bool:
        """Check if a deny rule matches the current operation."""
        # Match by operation pattern
        ops = rule.get("operations", [])
        if ops and not any(self._pattern_match(op, operation) for op in ops):
            return False

        # Match by environment
        envs = rule.get("environments", [])
        if envs and env and env not in envs:
            return False

        # Match by risk level (minimum)
        min_risk = rule.get("min_risk_level")
        if min_risk:
            if RISK_LEVELS.index(risk_level) < RISK_LEVELS.index(min_risk):
                return False

        return True

    @staticmethod
    def _pattern_match(pattern: str, value: str) -> bool:
        """Simple glob: 'delete_*' matches 'delete_segment'."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return value.startswith(pattern[:-1])
        return pattern == value

    @staticmethod
    def _in_maintenance_window(window: dict[str, str]) -> bool:
        """Check if current time is within the maintenance window."""
        from datetime import datetime

        now = datetime.now()
        try:
            start_h, start_m = map(int, window.get("start", "22:00").split(":"))
            end_h, end_m = map(int, window.get("end", "06:00").split(":"))
        except (ValueError, AttributeError):
            return True  # malformed → allow

        current_minutes = now.hour * 60 + now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        if start_minutes <= end_minutes:
            return start_minutes <= current_minutes <= end_minutes
        # Wraps midnight (e.g. 22:00 - 06:00)
        return current_minutes >= start_minutes or current_minutes <= end_minutes

    @staticmethod
    def _check_limits(
        limits: dict[str, Any], params: dict[str, Any], operation: str
    ) -> PolicyResult | None:
        """Check parameter-based limits (e.g. max CPU change %)."""
        max_cpu_pct = limits.get("max_cpu_change_pct")
        if max_cpu_pct and "cpu" in params:
            # Placeholder — actual implementation needs before-state
            pass
        return None


# ── Singleton ─────────────────────────────────────────────────────────

_engine: PolicyEngine | None = None


def get_policy_engine(rules_path: Path | str | None = None) -> PolicyEngine:
    """Return the global PolicyEngine singleton."""
    global _engine
    if _engine is None:
        _engine = PolicyEngine(rules_path)
    return _engine
