"""The ``@vmware_tool`` decorator — mandatory wrapper for all VMware MCP tool functions.

Responsibilities:
  1. Pre-check: evaluate policy rules (deny, maintenance window)
  2. Execute: run the actual tool function
  3. Post-log: write audit record to ``~/.vmware/audit.db``, with credentials
     scrubbed out of both the arguments and the return value
  4. Metadata: attach risk_level, idempotent, timeout, sensitive_params

Usage::

    from vmware_policy import vmware_tool

    @vmware_tool(risk_level="high", sensitive_params=["password"])
    def delete_segment(name: str, env: str) -> dict:
        ...

Registration enforcement::

    # In your MCP server startup
    for tool in tools:
        assert getattr(tool, "_is_vmware_tool", False), f"{tool.__name__} missing @vmware_tool"
"""

from __future__ import annotations

import contextvars
import inspect
import logging
import os
import re
import time
import traceback
from functools import wraps
from typing import Any

from vmware_policy.audit import detect_agent
from vmware_policy.budget import BudgetExceeded, get_budget
from vmware_policy.guard import audit_call, guard
from vmware_policy.skills import skill_name
from vmware_policy.patterns import PatternMatch, get_pattern_engine
from vmware_policy.policy import PolicyDenied, PolicyResult
from vmware_policy.sanitize import sanitize

_log = logging.getLogger("vmware-policy.decorators")

# PolicyDenied moved to policy.py (beside PolicyResult) so guard.py can raise it
# without importing this module (which imports guard). The import above binds it
# into this namespace, so `from vmware_policy.decorators import PolicyDenied` and
# the package __init__ keep working.


# ── Returned failures ─────────────────────────────────────────────────────

#: Set by ``report_tool_failure`` for the innermost in-flight tool call. The
#: wrapper rebinds it per call and restores the previous binding afterwards, so
#: an inner tool's failure cannot mark its caller failed — skills delegate
#: in-process (vmware-aiops runs vmware-monitor's library) and an outer tool
#: that catches and recovers is still a successful call.
_failure_signal: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "vmware_policy_tool_failure", default=None
)


def report_tool_failure(message: str) -> None:
    """Declare that the in-flight tool call failed, though it will *return*.

    Most tools signal failure by raising, which the wrapper already records. A
    tool that instead returns an error payload looks identical to a successful
    one, so it must say so explicitly::

        try:
            ...
        except Exception as exc:
            report_tool_failure(str(exc))
            return f"Error: {msg}"

    Dict-shaped payloads carrying a truthy ``error`` key are detected without
    this call — that is the family's own documented envelope, so reading it is
    following a convention rather than guessing. String returns are *not*
    sniffed: skills that hand back console text can legitimately emit output
    beginning with "Error:" as data, and marking those calls failed would be the
    same lie in the opposite direction. Such skills call this instead.

    No-op outside a tool call.
    """
    _failure_signal.set(message)


def _returned_failure(result: Any) -> bool:
    """True if ``result`` is the family's documented error envelope.

    Narrow on purpose. ``{"error": <truthy>}`` and a one-element list of the
    same are exactly what the family's error wrappers produce. A falsy ``error``
    key is a result reporting that nothing went wrong, and a multi-element list
    is a batch that returned partial results — a successful call either way.

    **Where the boundary is, and why it is not narrower.** A survey of every
    error-keyed dict in the family found 122 of 130 caught-error payloads are
    exactly ``{error, hint}`` — so requiring ``hint`` looks tempting. It would
    also stop detecting ~25 genuine failures that carry no hint: the plan guards
    in vmware-aiops (``{"error": "Plan 'x' not found"}``) and vmware-pilot's
    terminal-state refusals (``{"error": ..., "state": ..., "workflow_id": ...}``).
    Under-detecting reintroduces the bug this function exists to fix, in the
    other direction, so the rule stays keyed on ``error`` alone.

    The cost is that a *successful* call whose result happens to describe some
    other object's failure reads as a failed call. That ambiguity belongs to the
    payload, not to this rule: ``{"state": "error", "error": ...}`` cannot tell a
    model whether the call failed or the thing it polled did, either. Such
    payloads name the field for what it is (``task_error``) rather than being
    special-cased here.
    """
    if isinstance(result, dict):
        return bool(result.get("error"))
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict):
        return bool(result[0].get("error"))
    return False


def vmware_tool(
    fn: Any = None,
    *,
    risk_level: str = "low",
    idempotent: bool = False,
    timeout_seconds: int = 300,
    sensitive_params: list[str] | None = None,
    sensitive_result: bool = False,
    undo: Any = None,
) -> Any:
    """Decorator for all VMware MCP tool functions.

    Can be used with or without arguments::

        @vmware_tool
        def list_segments(...): ...

        @vmware_tool(risk_level="critical", sensitive_params=["password"])
        def delete_vm(...): ...

    Args:
        risk_level: One of 'low', 'medium', 'high', 'critical'.
        idempotent: Whether the operation can be safely retried on failure.
        timeout_seconds: Maximum execution time before warning — exceeding it
            logs a warning (no hard cancellation).
        sensitive_params: Parameter names to redact in audit logs.
        sensitive_result: The tool's return value *is* a credential — a
            kubeconfig, a bearer token, a password. The audit row then records
            the call (who, when, which arguments, whether it succeeded) but
            files the result as ``"[redacted: return value declared
            sensitive]"``. The caller still receives the real value; only the
            audit copy is redacted. See :func:`_redact_credential_keys` for the
            net that catches a tool which forgets to declare.
        undo: Optional callable ``(params, result) -> dict | None`` returning an
            inverse descriptor ``{"tool", "params", "skill"?, "note"?}``. On a
            successful call the inverse is recorded to ~/.vmware/undo.db and the
            result dict gains an ``_undo_id``. Return None for "no safe inverse".
            Recording only — execution is vmware-pilot's job.
    """
    _sensitive = set(sensitive_params or [])

    def decorator(func: Any) -> Any:
        # Cache the signature at decoration time so positional args can be
        # mapped to parameter names on every call (audit + env scoping).
        signature = inspect.signature(func)

        if inspect.iscoroutinefunction(func):
            # ── Async tools get an async wrapper with identical audit /
            # policy / circuit-breaker semantics (a sync wrapper would return
            # an un-awaited coroutine and audit it as "ok").
            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                state = _CallState(
                    func,
                    args,
                    kwargs,
                    signature,
                    _sensitive,
                    risk_level,
                    timeout_seconds,
                    undo,
                    sensitive_result,
                )
                # Fresh binding per call, restored below: a nested tool's
                # `report_tool_failure` must not mark its caller failed, and a
                # signal must not survive into the next call on this task.
                token = _failure_signal.set(None)
                try:
                    _pre_check(state)
                    return _annotate_result(state, await func(*args, **kwargs))
                except (PolicyDenied, BudgetExceeded) as exc:
                    # `_pre_check` sets the status before raising, so a denial of
                    # *this* call is already recorded. One arriving from inside
                    # the body — a nested @vmware_tool call policy refused,
                    # propagating outward — left the default "ok", so the
                    # orchestrating call audited as a success it never was.
                    if state.status == "ok":
                        state.status = (
                            "denied" if isinstance(exc, PolicyDenied) else "budget_exceeded"
                        )
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                finally:
                    _finalize(state)
                    _failure_signal.reset(token)
        else:

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                state = _CallState(
                    func,
                    args,
                    kwargs,
                    signature,
                    _sensitive,
                    risk_level,
                    timeout_seconds,
                    undo,
                    sensitive_result,
                )
                # Fresh binding per call, restored below: a nested tool's
                # `report_tool_failure` must not mark its caller failed, and a
                # signal must not survive into the next call on this task.
                token = _failure_signal.set(None)
                try:
                    _pre_check(state)
                    return _annotate_result(state, func(*args, **kwargs))
                except (PolicyDenied, BudgetExceeded) as exc:
                    # `_pre_check` sets the status before raising, so a denial of
                    # *this* call is already recorded. One arriving from inside
                    # the body — a nested @vmware_tool call policy refused,
                    # propagating outward — left the default "ok", so the
                    # orchestrating call audited as a success it never was.
                    if state.status == "ok":
                        state.status = (
                            "denied" if isinstance(exc, PolicyDenied) else "budget_exceeded"
                        )
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                finally:
                    _finalize(state)
                    _failure_signal.reset(token)

        # ── Attach metadata for harness / introspection ───────────
        wrapper._is_vmware_tool = True
        wrapper._risk_level = risk_level
        wrapper._idempotent = idempotent
        wrapper._timeout_seconds = timeout_seconds
        wrapper._sensitive_params = list(_sensitive)
        wrapper._sensitive_result = sensitive_result
        return wrapper

    # Support @vmware_tool and @vmware_tool(...)
    if fn is not None:
        return decorator(fn)
    return decorator


# ── Internal helpers ──────────────────────────────────────────────────


class _CallState:
    """Per-call context shared by the sync and async wrapper bodies.

    Built once per invocation; the helper functions (`_pre_check`,
    `_annotate_result`, `_capture_error`, `_finalize`) read and mutate it so
    both wrappers keep identical audit / policy / circuit-breaker semantics.
    """

    __slots__ = (
        "skill",
        "tool_name",
        "agent",
        "start",
        "status",
        "result",
        "policy_result",
        "pattern_match",
        "safe_params",
        "target",
        "risk_level",
        "timeout_seconds",
        "rationale",
        "approved_by",
        "undo",
        "sensitive_result",
    )

    def __init__(
        self,
        func: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        signature: inspect.Signature,
        sensitive: set[str],
        risk_level: str,
        timeout_seconds: int,
        undo: Any = None,
        sensitive_result: bool = False,
    ) -> None:
        self.undo = undo
        self.sensitive_result = sensitive_result
        self.skill = _infer_skill(func)
        self.tool_name = func.__name__
        self.agent = detect_agent()
        self.start = time.time()
        self.status = "ok"
        self.result: Any = None
        self.policy_result: PolicyResult | None = None
        self.pattern_match: PatternMatch | None = None
        self.risk_level = risk_level
        self.timeout_seconds = timeout_seconds

        # Map positional args to parameter names so they appear in the audit
        # log and participate in env scoping (previously only kwargs did).
        params = _bind_params(signature, args, kwargs)
        self.safe_params = _redact(params, sensitive)
        # Keep the target name: the pattern engine's rate limits and circuit
        # breakers are keyed per-TARGET (feeding them the environment pooled
        # every 'production' vCenter into one counter — one flaky target tripped
        # the breaker for all of them, 2026-07-18 review). The environment itself
        # is resolved inside guard() for policy scoping, so it is not stored here.
        target = params.get("target", params.get("env", ""))
        self.target = str(target) if target else ""

        # Accountability trail (SOC2 / 等保: who authorized this, and why).
        # Self-attested audit enrichment, not authorization (HLD §8.3): sourced
        # from env so an approval workflow / pilot can inject context without
        # changing every tool signature.
        self.rationale = os.environ.get("VMWARE_AUDIT_RATIONALE", "")
        self.approved_by = os.environ.get("VMWARE_AUDIT_APPROVED_BY", "")


def _bind_params(
    signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Build a full name→value param dict from positional + keyword args.

    Falls back to kwargs-only if binding fails (the actual call will raise
    the matching TypeError; audit should not mask it with its own).
    """
    try:
        bound = signature.bind_partial(*args, **kwargs)
        # Apply declared defaults so env scoping and risk-tier matching see the
        # effective target/tags even when the caller relied on a default value
        # (bind_partial alone only captures explicitly-passed arguments).
        bound.apply_defaults()
    except TypeError:
        return dict(kwargs)
    params: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        kind = signature.parameters[name].kind
        if kind == inspect.Parameter.VAR_KEYWORD:
            params.update(value)
        elif kind == inspect.Parameter.VAR_POSITIONAL:
            params[name] = list(value)
        else:
            params[name] = value
    return params


def _pre_check(state: _CallState) -> None:
    """Policy pre-check + L5 auto-remediation pattern consult.

    Raises PolicyDenied when policy denies the call. Pattern engine failures
    never block the call (fail-open by design — a broken pattern file must
    not take down every MCP tool).
    """
    # Authorize through the shared guard so the CLI and MCP surfaces apply the
    # exact same policy (HLD §4, I-3). guard() is a no-op unless the operator
    # wrote deny / maintenance rules. Approval tiers were removed in v1.8.7:
    # read/write authorization is the vCenter account's job (RBAC), not a
    # per-call gate (HLD §5/§9). Preserve the denied-call audit shape by
    # recording the reason/rule before re-raising.
    try:
        state.policy_result = guard(
            state.skill,
            state.tool_name,
            state.safe_params,
            risk_level=state.risk_level,
            target=state.target,
        )
    except PolicyDenied as exc:
        state.status = "denied"
        state.result = {"error": exc.result.reason, "rule": exc.result.rule}
        raise

    # Budget / runaway guard — only for calls policy already allowed, so denied
    # calls do not count. A trip raises BudgetExceeded (a hard stop); record the
    # denial on state so _finalize audits it.
    try:
        get_budget().check_and_record(state.tool_name, state.safe_params)
    except BudgetExceeded as exc:
        state.status = "budget_exceeded"
        state.result = {"error": exc.reason, "rule": exc.rule}
        raise

    try:
        state.pattern_match = get_pattern_engine().match(
            skill=state.skill, tool=state.tool_name, target=state.target
        )
    except Exception:  # noqa: BLE001 — fail-open by design
        state.pattern_match = None


def _annotate_result(state: _CallState, result: Any) -> Any:
    """Record the result, surface pattern context, and record an undo token.

    Runs on every path that returns a value — which is not the same as the
    success path. A tool can fail and still return: the family's error wrappers
    catch the exception and hand back an error payload, so the function returns
    normally and nothing here would otherwise notice. That gap made the audit
    row say ``ok`` for a failed operation, recorded an undo token for a change
    that never happened, and fed ``success=True`` to the circuit breaker, which
    is why layer three of CLAUDE.md's recovery model never tripped for most of
    the family. Detecting the returned failure first restores all three.

    A tool that declared ``sensitive_result`` contributes only the sentinel to
    the audit row — the credential itself never lands on ``state``, so no later
    step can carry it into a column the redaction does not cover. The caller
    still receives the real object, and ``_record_undo`` below still sees it.
    """
    state.result = _REDACTED_DECLARED if state.sensitive_result else result
    if _returned_failure(result) or _failure_signal.get() is not None:
        state.status = "error"
    if state.pattern_match and state.pattern_match.armed and isinstance(result, dict):
        result.setdefault("_pattern_id", state.pattern_match.pattern.pattern_id)
        result.setdefault("_pattern_armed", True)
    _record_undo(state, result)
    return result


def _record_undo(state: _CallState, result: Any) -> None:
    """Compute and persist the inverse descriptor for a successful write.

    Best-effort: a broken undo callable or store must never fail the call.
    Attaches ``_undo_id`` to dict results so the agent / pilot can reference it.

    Skipped once the call is known to have failed: an undo token asserts that a
    change happened and can be reversed, and offering to reverse a write that
    never landed is worse than offering nothing.
    """
    if state.undo is None or state.status != "ok":
        return
    try:
        descriptor = state.undo(state.safe_params, result)
    except Exception:  # noqa: BLE001 — undo computation must not fail the call
        _log.warning("undo callable for %s.%s raised", state.skill, state.tool_name, exc_info=True)
        return
    if not descriptor:
        return
    try:
        from vmware_policy.undo import get_undo_store

        undo_id = get_undo_store().record(
            skill=state.skill,
            tool=state.tool_name,
            undo_descriptor=descriptor,
            orig_params=state.safe_params,
        )
        if undo_id and isinstance(result, dict):
            result.setdefault("_undo_id", undo_id)
    except Exception:  # noqa: BLE001 — recording is best-effort
        _log.warning("failed to record undo for %s.%s", state.skill, state.tool_name, exc_info=True)


def _capture_error(state: _CallState, exc: Exception) -> None:
    """Record a failed call. Exception text and tracebacks can carry
    connection strings, credentials, internal paths — sanitize before
    persisting to the audit row."""
    state.status = "error"
    state.result = {
        "error": sanitize(_redact_secrets_text(str(exc)), 500),
        "traceback": sanitize(_redact_secrets_text(traceback.format_exc()[-500:]), 500),
    }


def _finalize(state: _CallState) -> None:
    """Audit + circuit-breaker bookkeeping. Runs in the wrapper's finally."""
    duration = int((time.time() - state.start) * 1000)

    # Accumulate wall-time toward the cumulative time budget (best-effort).
    try:
        get_budget().add_duration(time.time() - state.start)
    except Exception:  # noqa: BLE001 — bookkeeping must never fail the call
        pass

    # timeout_seconds is advisory: exceeding it logs a warning, no hard
    # cancellation (cancelling mid-flight vSphere/NSX calls is worse).
    if state.timeout_seconds and duration > state.timeout_seconds * 1000:
        _log.warning(
            "%s.%s took %dms — exceeded timeout_seconds=%d (advisory, not cancelled)",
            state.skill,
            state.tool_name,
            duration,
            state.timeout_seconds,
        )

    bypassed = state.policy_result and state.policy_result.rule == "policy_disabled"
    final_status = f"{state.status}_bypassed" if bypassed else state.status

    # Update circuit-breaker state for armed patterns
    if state.pattern_match and state.pattern_match.armed:
        try:
            get_pattern_engine().report_outcome(
                pattern_id=state.pattern_match.pattern.pattern_id,
                target=state.target,
                success=(state.status == "ok"),
            )
        except Exception:  # noqa: BLE001 — never let bookkeeping fail the call
            pass

    pattern_id = state.pattern_match.pattern.pattern_id if state.pattern_match else ""
    pattern_armed = bool(state.pattern_match and state.pattern_match.armed)

    # Single audit sink for every surface (I-8). risk_tier is gone with the
    # approval tiers; `user` is left to AuditEngine.log, which fills the OS user.
    audit_call(
        state.skill,
        state.tool_name,
        params=state.safe_params,
        result=_with_pattern_context(
            _redact_credential_keys(state.result), pattern_id, pattern_armed
        ),
        status=final_status,
        duration_ms=duration,
        agent=state.agent,
        risk_level=state.risk_level,
        rationale=state.rationale,
        approved_by=state.approved_by,
    )


def _infer_skill(func: Any) -> str:
    """Infer skill name from the function's module path.

    ``vmware_aiops.ops.vm_lifecycle`` → ``aiops``
    ``mcp_server.server`` → try the parent package → ``unknown``
    """
    return skill_name(getattr(func, "__module__", "") or "")


def _redact(params: dict[str, Any], sensitive: set[str]) -> dict[str, Any]:
    """Return a copy of params with sensitive values replaced by '***'.

    Recurses into nested dicts AND lists/tuples so credentials buried inside
    collections (e.g. ``{"targets": [{"password": "x"}]}``) are redacted too.
    """
    if not sensitive:
        return params
    result: dict[str, Any] = {}
    for k, v in params.items():
        if k in sensitive:
            result[k] = "***"
        else:
            result[k] = _redact_value(v, sensitive)
    return result


def _redact_value(value: Any, sensitive: set[str]) -> Any:
    """Recursively redact sensitive keys inside dicts, lists, and tuples."""
    if isinstance(value, dict):
        return _redact(value, sensitive)
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(item, sensitive) for item in value)
    return value


# ── Result redaction ──────────────────────────────────────────────────
#
# The audit row exists to answer "this tool was called, by whom, when, with
# which arguments, and did it succeed". A credential the tool *returned* is no
# part of that answer, and audit.db is the artefact most likely to be copied off
# the machine and attached to a ticket — so a secret filed there is worse than
# one in a log. Both redactions below rewrite the audit copy only; the caller
# always receives the real value, which is the entire point of tools like
# vmware-vks's ``get_supervisor_kubeconfig``.

#: What a tool that declared ``sensitive_result=True`` contributes instead of
#: its return value. A truncated or hashed secret is still a finding, so the
#: field is either absent or says plainly that it was dropped.
_REDACTED_DECLARED = "[redacted: return value declared sensitive]"

#: What replaces a value filed under one of :data:`_CREDENTIAL_KEYS`.
_REDACTED_KEY = "[redacted: credential-shaped key]"

#: Key names whose value is never stored in an audit row, declaration or not.
#:
#: The declaration is the contract; this is the net for when a tool forgets it,
#: which CLAUDE.md 形态 #7 says will happen — a family-wide pattern fixed in one
#: repo and left alone in the other fourteen is this project's most repeated
#: failure. A new tool returning ``{"kubeconfig": ...}`` or ``{"token": ...}``
#: is therefore safe before anyone has thought about it.
#:
#: Matching is an EXACT (case-insensitive, ``-``/``_`` folded) key comparison,
#: not a substring search: ``token_count`` and ``secret_manager_url`` are not
#: credentials, and a check whose name promises more than it verifies is its own
#: recurring defect (形态 #4). A credential under a key not listed here — say
#: ``avi_password`` — is exactly what ``sensitive_result=True`` is for.
_CREDENTIAL_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "auth_token",
        "authorization",
        "bearer",
        "bearer_token",
        "client_secret",
        "credential",
        "credentials",
        "kubeconfig",
        "passwd",
        "password",
        "private_key",
        "pwd",
        "refresh_token",
        "secret",
        "session_key",
        "session_token",
        "sessionkey",
        "token",
    }
)


def _is_credential_key(key: Any) -> bool:
    return str(key).strip().lower().replace("-", "_") in _CREDENTIAL_KEYS


def _redact_credential_keys(value: Any) -> Any:
    """Return ``value`` with credential-keyed entries replaced, recursively.

    Returns the *same object* when nothing matched, so an ordinary tool's result
    reaches the audit row byte-identical to what it returned and nothing is
    copied for no reason. When something does match, new containers are built —
    the object handed back to the caller is never mutated.
    """
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        changed = False
        for key, item in value.items():
            if _is_credential_key(key):
                redacted[key] = _REDACTED_KEY
                changed = True
            else:
                new_item = _redact_credential_keys(item)
                changed = changed or new_item is not item
                redacted[key] = new_item
        return redacted if changed else value
    if isinstance(value, (list, tuple)):
        items = [_redact_credential_keys(item) for item in value]
        if all(new is old for new, old in zip(items, value)):
            return value
        return items if isinstance(value, list) else tuple(items)
    return value


# ── Free-form text redaction ──────────────────────────────────────────
#
# The other half of _redact_credential_keys. Key-based redaction cannot reach a
# credential that is inside an *exception message*: that is one string, not a
# dict, and the credential is in the middle of it.
#
# The keyword alternation is DERIVED from _CREDENTIAL_KEYS rather than written
# out again. Two hand-maintained lists of the same names drift, and the drift is
# invisible — a name added to one is simply not redacted by the other (CLAUDE.md
# 形态 #6). ``_`` is relaxed to ``[_-]?`` so ``api_key`` also covers ``api-key``
# and ``apikey``.
_SECRET_WORDS = "|".join(
    re.escape(k).replace("_", "[_-]?")
    for k in sorted(_CREDENTIAL_KEYS, key=len, reverse=True)
)

#: A credential name may be the *tail* of a longer identifier — ``access_token``,
#: ``client_secret``, ``VMWARE_VC_PASSWORD``, ``config.password``. The previous
#: pattern anchored on ``\b`` before the keyword, so every one of those leaked.
#: The keyword still has to end the identifier: the separator that follows can
#: only be ``:``/``=`` (optionally quoted), which is why ``token_count=5120`` and
#: ``secret_manager_url=...`` are not credentials and stay readable.
_KEY_PREFIX = r"[\w.\-]*(?:" + _SECRET_WORDS + r")"

#: Value characters. ``@`` is *included* — ``password=P@ssw0rd`` used to redact a
#: single character and print the rest. DSN userinfo, which is why ``@`` was
#: excluded, has its own rule below and runs first.
#:
#: ``(`` is excluded as well as ``)``. With only the closing paren excluded,
#: ``auth=('admin', 'PASS')`` matched the opening paren alone and produced
#: ``auth=***'admin', 'PASS')`` — it destroyed the message *and* printed the
#: password. That is the most common way httpx and requests spell credentials,
#: so it reaches a traceback easily.
_VALUE = r"[^\s'\",;&\[\]\{\}\(\)<>]+"

#: Words that are a *report about* a credential, not a credential. Redacting
#: them inverts the sentence: ``password: not set`` became ``password: *** set``,
#: which reads as "a password is set". Measured over this family's own status
#: vocabulary, 12 of 17 phrases were rewritten and two of them reversed meaning.
#: Listed values are never secrets, so skipping them costs nothing.
_STATUS_WORDS = (
    r"(?!(?:not|no|none|null|unset|empty|missing|absent|set|configured|provided|"
    r"required|ok|yes|true|false|n/?a|was|is|were|are|will|has|have|been|"
    r"\*\*\*|<[^>]*>)\b)"
)

#: HTTP auth schemes. The Authorization rule below deliberately leaves the scheme
#: visible ("Basic" vs "Bearer" is the difference between two different
#: diagnoses), so the generic key=value rule that runs after it must not come
#: back and redact the scheme it just preserved.
_AUTH_SCHEMES = r"basic|bearer|digest|negotiate|ntlm|token|apikey"
_NOT_A_SCHEME = r"(?!(?:" + _AUTH_SCHEMES + r")\s)"

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # A credential pair spelled as a tuple: auth=('admin', 'hunter2'). This is
    # how httpx and requests are called, so it is what a traceback prints. The
    # generic key=value rule cannot help: its value class has to exclude the
    # parentheses, or it matches the opening paren alone and yields
    # ``auth=***'admin', 'PASS')`` -- the message destroyed and the password
    # still there. Redacting the whole group is the only reading that is safe
    # whichever element holds the secret.
    (
        re.compile(r"(?i)\b(" + r"[\w.\-]*(?:auth|credential|credentials)" + r")(\s*=\s*)\([^()]*\)"),
        r"\1\2(***)",
    ),
    # PEM private key blocks — no key=value shape at all, previously untouched.
    (
        re.compile(
            r"(-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)"
            r".*?"
            r"(-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)",
            re.DOTALL,
        ),
        r"\1***\2",
    ),
    # URL / DSN userinfo: scheme://user:secret@host
    #
    # Both halves may contain ``@`` and the old classes excluded it from both.
    # A vSphere SSO username *always* contains one (``administrator@vsphere.local``),
    # so the rule did not fire at all on this family's own URLs; and a password
    # containing one made the match stop early and print the tail
    # (``https://admin:***@c1QJwp@nsx/`` — a real password fragment).
    # The username is non-greedy and the password greedy up to the last ``@``
    # before the host, which is what a URL parser does.
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s/:]*?):([^\s/]*)@(?=[^\s/@]*(?:[/\s?#]|$))"),
        r"\1:***@",
    ),
    # Cookie / Set-Cookie: the whole header value is credential material.
    (re.compile(r"(?i)\b((?:set-)?cookie)(\s*[:=]\s*)[^\r\n]+"), r"\1\2***"),
    # Authorization: <scheme> <credential>. The scheme is diagnostic and stays;
    # everything after it goes. The old pattern masked the word "Basic" and left
    # the base64 — the example named in the re-test report.
    (
        re.compile(
            r"(?i)\b((?:proxy-)?authorization)"
            r"(\s*['\"]?\s*[:=]\s*['\"]?\s*)"
            r"(" + _AUTH_SCHEMES + r")"
            r"(\s+)"
            r"[^\s'\",;]+"
        ),
        r"\1\2\3\4***",
    ),
    # A bare scheme + credential, with no Authorization: in front of it. The
    # length floor keeps "Basic health check passed" and "Bearer of record"
    # readable — over-redaction destroys the teaching errors.
    (
        re.compile(r"(?i)\b(basic|bearer)(\s+)([A-Za-z0-9+/=_.\-]{16,})(?![\w+/=.\-])"),
        r"\1\2***",
    ),
    # SOAP / XML element: <password>secret</password>
    (
        re.compile(r"(?i)<(" + _KEY_PREFIX + r")>[^<]*</\1>"),
        r"<\1>***</\1>",
    ),
    # Quoted value — how a traceback prints a dict: {"token": "x"} / {'pwd': 'x'}
    (
        re.compile(
            r"(?i)(" + _KEY_PREFIX + r")(['\"]?\s*[:=]\s*)(['\"])"
            + _NOT_A_SCHEME
            + r"[^'\"\r\n]*\3"
        ),
        r"\1\2\3***\3",
    ),
    # CLI flag: --password secret / -token secret (whitespace separator, but only
    # after a dash, so "password policy requires 15 characters" survives).
    (
        re.compile(
            r"(?i)(-{1,2}[\w\-]*(?:" + _SECRET_WORDS + r"))(\s+)"
            + _STATUS_WORDS + r"[^\s'\",;]+"
        ),
        r"\1\2***",
    ),
    # Tools that carry the credential in a flag with no credential-sounding name.
    # ``curl -u user:pass``, ``--user``, ``sshpass -p``. Nothing in the text says
    # "password", so every keyword rule above walks straight past them.
    (
        re.compile(r"(?i)(\B-u|--user)(\s+)([^\s'\",;:]+):[^\s'\",;]+"),
        r"\1\2\3:***",
    ),
    (
        re.compile(r"(?i)\b(sshpass\s+-p)(\s*)[^\s'\",;]+"),
        r"\1\2***",
    ),
    # netrc: ``machine host login user password secret``. Whitespace-separated
    # with no dash, which the flag rule above deliberately requires so that
    # "password policy requires 15 characters" survives. Anchoring on the
    # preceding ``login <user>`` keeps that sentence readable.
    (
        re.compile(r"(?i)\b(login\s+\S+\s+password)(\s+)[^\s'\",;]+"),
        r"\1\2***",
    ),
    # Unquoted key=value / key: value.
    (
        re.compile(
            r"(?i)(" + _KEY_PREFIX + r")(\s*[:=]\s*)"
            + _NOT_A_SCHEME + _STATUS_WORDS + _VALUE
        ),
        r"\1\2***",
    ),
    # A bare JWT with no key in front of it — a Supervisor token pasted into an
    # error message is self-identifying and needs no keyword.
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),
        "***",
    ),
)


def _redact_secrets_text(text: str) -> str:
    """Redact credential values in free-form text (exception messages, tracebacks).

    Ordered rules, most specific first: the DSN rule has to run before the
    generic ``key=value`` one, and the ``Authorization:`` rule before the bare
    ``Basic``/``Bearer`` one, or the broader pattern eats the narrower one's
    context and the result is less readable for no gain in safety.

    Idempotent: re-running it over already-redacted text leaves it unchanged, so
    a string that passes through two layers is not corrupted.
    """
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _with_pattern_context(result: Any, pattern_id: str, armed: bool) -> Any:
    """Attach pattern metadata to an audit row's result field.

    Only mutates dict results; non-dict results (errors, primitives) are
    returned unchanged so the audit log preserves them faithfully.
    """
    if not pattern_id:
        return result
    if isinstance(result, dict):
        annotated = dict(result)
        annotated.setdefault("_pattern_id", pattern_id)
        annotated.setdefault("_pattern_armed", armed)
        return annotated
    return result
