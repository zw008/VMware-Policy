"""Policy engine — rule-based access control for VMware MCP tools.

Rules are loaded from ``~/.vmware/rules.yaml`` with hot-reload on file change.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from vmware_policy.paths import ops_path

_log = logging.getLogger("vmware-policy.policy")

# ── Data structures ───────────────────────────────────────────────────


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of a policy check."""

    allowed: bool
    rule: str = ""
    reason: str = ""


class PolicyDenied(Exception):
    """Raised when an operation is denied by policy — a ``deny`` rule matched, or
    a closed maintenance window blocked a high/critical op. Carries the
    ``PolicyResult`` so callers can read the rule name and teaching reason.

    Defined here beside ``PolicyResult`` (rather than in ``decorators``) so the
    surface-agnostic ``guard()`` can raise it without importing the decorator
    module — which imports ``guard`` in turn (HLD §4, avoids the import cycle).
    """

    def __init__(self, result: PolicyResult) -> None:
        self.result = result
        super().__init__(result.reason)


# ── Risk levels ───────────────────────────────────────────────────────

RISK_LEVELS = ("low", "medium", "high", "critical")

#: The policy baseline shipped with the package, used when the operator has
#: written no ``~/.vmware/rules.yaml`` of their own.
DEFAULT_RULES_PATH = Path(__file__).parent / "rules_default.yaml"


def _risk_index(risk_level: str) -> int:
    """RISK_LEVELS.index that cannot raise: unknown reads as critical.

    ``vmware-audit policy --risk hgih`` used to traceback with ValueError out
    of check_allowed. An unrecognised level is treated as the most restrictive
    one — a typo must not weaken a gate, and must not crash it either.
    """
    try:
        return RISK_LEVELS.index(risk_level)
    except ValueError:
        return len(RISK_LEVELS) - 1


def _min_risk_index(min_risk: Any) -> int:
    """Index for a rule's ``min_risk_level`` that cannot raise.

    The counterpart to :func:`_risk_index`, for the other direction. That one
    guards the level declared in code by ``@vmware_tool``; this one guards the
    level an operator hand-writes in rules.yaml, which is never validated and
    is the far likelier place for a typo — ``mediun``, or simply ``MEDIUM``.

    Unknown reads as index 0, so the rule matches every risk level instead of
    almost none. The direction matters: this threshold gates whether a rule
    *applies*, so a typo must widen the rule (deny more), never quietly narrow
    it to the point of never firing — a wider match can only raise the bar.
    """
    if isinstance(min_risk, str):
        normalised = min_risk.strip().lower()
        if normalised in RISK_LEVELS:
            return RISK_LEVELS.index(normalised)
    _log.warning(
        "Unrecognised min_risk_level %r in a policy rule — treating it as %r so "
        "the rule still applies. Expected one of: %s.",
        min_risk,
        RISK_LEVELS[0],
        ", ".join(RISK_LEVELS),
    )
    return 0


# ── Rule loading with hot-reload ──────────────────────────────────────


class PolicyEngine:
    """Evaluate operations against a YAML rule set.

    Rules file is re-read when its mtime changes (hot-reload, no restart needed).
    """

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self._path = Path(rules_path).expanduser() if rules_path else ops_path("rules.yaml")
        self._rules: dict[str, Any] = {}
        self._mtime: float = 0.0
        self._source: str = "none"
        #: ``None`` only after a rule set was genuinely loaded. Everything else
        #: — decode error, YAML syntax error, unreadable packaged baseline —
        #: leaves a message here and every check fails CLOSED on it. It is a
        #: separate field, not an empty ``_rules``, precisely because an empty
        #: rule set is a legitimate loaded state that must keep allowing.
        self._load_error: str | None = None
        self._load_rules()

    def _load_rules(self) -> None:
        """Load the user's rules; fall back to the packaged baseline if absent.

        The baseline is a *fallback*, never a merge — an operator who writes
        ``rules.yaml`` owns policy completely, and an empty ``deny: []`` in their
        file means exactly that (no denials, not "inherit the baseline's").

        A user file that exists but cannot be read does NOT fall back to the
        shipped baseline — applying rules the operator never wrote, while their
        real ones are broken, is the wrong surprise. It fails CLOSED instead:
        ``_load_error`` is set and :meth:`check_allowed` denies everything until
        the file is fixed. See that method for why "everything".

        Files are read as UTF-8 explicitly. Letting ``open()`` pick the locale's
        codec is what disarmed this engine on a cp936 (GBK) Windows host: a UTF-8
        ``rules.yaml`` raised ``UnicodeDecodeError``, and — before the CLOSED
        state above existed — a ``freeze-production-writes`` rule flipped to
        ALLOW. GBK is worse than it looks: many UTF-8 byte pairs *are* valid GBK,
        so the alternative outcome is silent mojibake rather than an exception.
        """
        import yaml

        if not self._path.exists():
            try:
                with open(DEFAULT_RULES_PATH, encoding="utf-8") as fh:
                    self._rules = yaml.safe_load(fh) or {}
                self._source = "packaged-default"
                self._load_error = None
                self._mtime = 0.0
                _log.debug("No %s — using packaged policy baseline", self._path)
            except Exception as exc:
                _log.error(
                    "Packaged policy baseline %s is unreadable — failing CLOSED",
                    DEFAULT_RULES_PATH,
                    exc_info=True,
                )
                self._rules = {}
                self._source = "baseline-unreadable"
                self._load_error = self._describe_load_failure(DEFAULT_RULES_PATH, exc)
                self._mtime = 0.0
            return

        try:
            self._mtime = self._path.stat().st_mtime
            with open(self._path, encoding="utf-8") as fh:
                self._rules = yaml.safe_load(fh) or {}
            self._source = "user"
            self._load_error = None
            _log.debug("Loaded %d policy rules from %s", len(self._rules), self._path)
        except Exception as exc:
            _log.error(
                "Failed to load policy rules from %s — failing CLOSED: every "
                "operation is denied until the file loads",
                self._path,
                exc_info=True,
            )
            self._rules = {}
            self._source = "user-unreadable"
            self._load_error = self._describe_load_failure(self._path, exc)

    @staticmethod
    def _describe_load_failure(path: Path, exc: Exception) -> str:
        """The teaching text an operator sees on every denied call.

        It has to name the file, say what is wrong with it, and give the way out
        — a gate with no documented exit is an outage. The encoding case gets its
        own sentence because "invalid YAML" is the wrong thing to go looking for
        when the real problem is that the file is not UTF-8.

        Collapsed to a single line: callers surface ``reason`` as one message,
        and a raw ``yaml.ParserError`` is five lines with the file quoted twice.
        The full traceback is still in the log, via ``exc_info``.
        """
        if isinstance(exc, UnicodeDecodeError):
            detail = (
                f"it is not valid UTF-8 ({exc.reason} at byte {exc.start}). "
                "Re-save it as UTF-8 — on Windows, Notepad's 'Save as' encoding "
                "dropdown, or `Set-Content -Encoding utf8`."
            )
        else:
            detail = f"{type(exc).__name__}: {exc}"
        detail = " ".join(detail.split())
        return (
            f"Policy rules could not be loaded from {path}: {detail} "
            "Every operation is denied until it loads — the engine cannot know "
            "which operations that file was gating. Fix the file (it is re-read "
            "automatically), or set VMWARE_POLICY_DISABLED=1 to run with no "
            "policy at all."
        )

    def active_rules_source(self) -> str:
        """Where the rules in force came from.

        One of ``user`` (the operator's rules.yaml), ``packaged-default`` (the
        shipped baseline, because no user file exists), ``user-unreadable`` (their
        file exists but would not load — **nothing is permitted** until it does),
        or ``baseline-unreadable`` (no user file and the shipped baseline is
        broken too — likewise nothing is permitted). Surfaced so an operator can
        tell "my policy is active" from "my policy failed to load" without
        reading logs.

        The two ``*-unreadable`` names replaced ``user-invalid``/``none`` in the
        cp936 fix. The rename is deliberate: those strings were documented as
        "rules are empty, nothing is enforced", which is now the exact opposite
        of what they mean, and a reader who pattern-matched the old name would
        have carried the old assumption across silently.
        """
        self._maybe_reload()
        return self._source

    def _maybe_reload(self) -> None:
        """Hot-reload if file changed."""
        if not self._path.exists():
            if self._source == "user":
                _log.warning(
                    "Policy rules file deleted: %s — falling back to the packaged baseline",
                    self._path,
                )
                self._load_rules()
            elif self._source not in ("packaged-default", "baseline-unreadable"):
                self._load_rules()
            return
        try:
            current_mtime = self._path.stat().st_mtime
            if current_mtime != self._mtime:
                self._load_rules()
        except Exception:
            _log.warning("Failed to check policy rules file: %s", self._path, exc_info=True)

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
        # Bypass mode — log context for audit trail. Log only parameter NAMES,
        # never values: param values may carry passwords/tokens, and this path
        # can be reached by callers that did not pre-redact.
        if os.environ.get("VMWARE_POLICY_DISABLED") == "1":
            param_names = sorted(params.keys()) if isinstance(params, dict) else []
            _log.warning(
                "Policy DISABLED — bypassing check: operation=%s env=%s risk=%s param_keys=%s",
                operation,
                env,
                risk_level,
                param_names,
            )
            return PolicyResult(allowed=True, rule="policy_disabled")

        self._maybe_reload()

        # ── Rules could not be loaded → deny everything ───────────────
        # The failure direction this engine got wrong until 2026-08-30: a
        # rules file that would not decode left `_rules` empty, which is
        # indistinguishable from "the operator wrote no rules", so a measured
        # `freeze-production-writes` deny came back ALLOW on a GBK host.
        #
        # "Closed" here means *every* operation, not just writes, and not just
        # the high-risk ones. Three narrower definitions were considered:
        #
        #   - refuse to construct the engine — turns a one-line YAML typo into
        #     an import-time traceback in 15 skills with nothing to read;
        #   - deny only writes — assumes reads are safe, which is false in this
        #     family: `get_supervisor_kubeconfig` is a READ tool that returns a
        #     live Supervisor JWT, and freezing exactly that is a rule an
        #     operator plausibly writes;
        #   - deny only what the missing rules would have gated — unknowable.
        #     Not knowing is the whole condition; guessing narrow is guessing
        #     permissive.
        #
        # So: everything, with a reason that names the file and the way out.
        # `VMWARE_POLICY_DISABLED=1` is checked above this line on purpose —
        # the escape hatch must not itself depend on the rules loading.
        if self._load_error is not None:
            return PolicyResult(
                allowed=False, rule="rules_unreadable", reason=self._load_error
            )

        # Loaded, and empty — the operator wrote no rules. Allow everything.
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
            try:
                in_window = self._in_maintenance_window(window)
            except (ValueError, TypeError, AttributeError):
                # Fail CLOSED: a malformed window must not silently allow
                # high-risk operations around the clock.
                _log.error(
                    "Malformed maintenance_window %r in %s — failing CLOSED: "
                    "high-risk operations are blocked until the rule is fixed. "
                    "Expected 'start' and 'end' as 'HH:MM' strings, e.g. "
                    'start: "22:00" / end: "06:00".',
                    window,
                    self._path,
                )
                return PolicyResult(
                    allowed=False,
                    rule="maintenance_window_malformed",
                    reason=(
                        f"maintenance_window in {self._path} is malformed "
                        f"({window!r}). High-risk operations are blocked until it is "
                        "fixed. Expected 'start' and 'end' as 'HH:MM' strings, "
                        'e.g. start: "22:00" / end: "06:00".'
                    ),
                )
            if not in_window:
                return PolicyResult(
                    allowed=False,
                    rule="maintenance_window",
                    reason=f"High-risk operations only allowed during {window.get('start', '?')}-{window.get('end', '?')}",
                )

        # ── Evaluate change limits (reserved, not implemented) ────────
        # change_limits is NOT an enforced feature: _check_limits only warns
        # that configured limits are ignored (it can't compute deltas without
        # before-state). Kept so misconfiguration is surfaced, not silent.
        limits = self._rules.get("change_limits", {})
        if params and limits:
            result = self._check_limits(limits, params, operation)
            if result and not result.allowed:
                return result

        # Read/write authorization beyond the operator's own deny rules is the
        # vCenter/NSX account's job (RBAC, HLD §1/§5). The v1.8 "require the
        # target to declare an environment, and refuse it otherwise" gate was
        # removed in v1.8.7 — an unlabelled target is simply not matched by any
        # environment-scoped deny rule, never refused for lack of a label.
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
        # Note: "operations" key absent → match all (no filter).
        # "operations: []" → match nothing (explicit empty = no operations apply).
        if "operations" in rule:
            ops = rule["operations"]
            if not ops or not any(self._pattern_match(op, operation) for op in ops):
                return False

        # Match by environment. env is the target's *declared* environment
        # ("" for every unlabelled target), so a rule scoped to environments must
        # not fire when the call has no env — otherwise a production-scoped deny
        # would match every unlabelled / lab target (2026-07-18 review).
        envs = rule.get("environments", [])
        if envs and not env:
            return False  # rule scoped to envs but target declares none → no match
        if envs and not any(self._pattern_match(e, env) for e in envs):
            return False

        # Match by risk level (minimum)
        min_risk = rule.get("min_risk_level")
        if min_risk:
            if _risk_index(risk_level) < _min_risk_index(min_risk):
                return False

        return True

    @staticmethod
    def _pattern_match(pattern: str, value: str) -> bool:
        """Glob match: 'delete_*', '*_delete' and 'vm_*_snapshot' all work.

        Previously only a trailing ``*`` was honoured — every other pattern fell
        through to an equality test, so a rule written ``operations:
        ["*_delete"]`` silently matched nothing. A deny rule that looks
        configured but never fires is worse than no rule, so this now delegates
        to :func:`fnmatch.fnmatchcase` and handles the full glob syntax.

        Case-sensitive: tool names are snake_case identifiers, and a policy that
        quietly matched ``VM_Delete`` would be surprising in the other direction.
        """
        if pattern == "*":
            return True
        return fnmatchcase(value, pattern)

    @staticmethod
    def _in_maintenance_window(window: dict[str, str]) -> bool:
        """Check if current time is within the maintenance window (UTC).

        Raises ValueError/TypeError/AttributeError when the window is
        malformed — the caller fails CLOSED with a teaching message.
        """
        from datetime import datetime, timezone

        now = datetime.now(tz=timezone.utc)
        start_h, start_m = map(int, str(window.get("start", "22:00")).split(":"))
        end_h, end_m = map(int, str(window.get("end", "06:00")).split(":"))

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
        """Check parameter-based limits (e.g. max CPU change %).

        NOTE: Not yet implemented — requires before-state to compute deltas.
        Logs a warning when limits are configured so operators know they are
        not being enforced.
        """
        if limits:
            _log.warning(
                "change_limits configured for '%s' but limit enforcement is not yet "
                "implemented — limits are NOT being enforced. Params: %s",
                operation,
                list(params.keys()),
            )
        return None


# ── Singleton ─────────────────────────────────────────────────────────

_engine: PolicyEngine | None = None
_engine_lock = threading.Lock()


def get_policy_engine(rules_path: Path | str | None = None) -> PolicyEngine:
    """Return the global PolicyEngine singleton (lazy, lock-guarded).

    A ``rules_path`` differing from the one the singleton was created with is
    ignored with a warning — call :func:`reset_policy_engine` first to rebind.
    """
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = PolicyEngine(rules_path)
                return _engine
    if rules_path is not None:
        requested = Path(rules_path).expanduser()
        if requested != _engine._path:
            _log.warning(
                "get_policy_engine(%s) ignored — singleton already initialized "
                "with %s; call reset_policy_engine() first to rebind.",
                requested,
                _engine._path,
            )
    return _engine


def reset_policy_engine() -> None:
    """Reset the singleton. Mirrors patterns.reset_pattern_engine()."""
    global _engine
    with _engine_lock:
        _engine = None
