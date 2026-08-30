"""``@guarded`` — the CLI counterpart to ``@vmware_tool`` (HLD §4.1).

A CLI command that changes remote state routes through the SAME shared
``guard()`` + ``audit_call()`` as the MCP surface, so ``vmware-aiops vm delete``
run through Bash is authorized and recorded exactly like the ``vm_delete`` MCP
tool — invariants I-1 (no unguarded write door), I-3 (surface-symmetric policy)
and I-8 (every write audited, one store). The interactive double-confirm stays
layered on top as the surface-specific confirmation (HLD §7).

Leaner than ``@vmware_tool`` on purpose: no budget / pattern / undo machinery
(those are agent-loop concerns), just the two guarantees a CLI write needs —
optional policy authorization and one un-bypassable audit row in
``~/.vmware/audit.db``.

Param binding, redaction and skill inference are imported from ``decorators`` so
the two surfaces bind ``(tool, params, target)`` from a call **identically**: I-3
is a property of sharing the code, not of two implementations agreeing by
inspection. (These are internal helpers today; if a third surface ever needs
them they should move to a small shared reflection module.)
"""
from __future__ import annotations

import inspect
import os
import time
from functools import wraps
from typing import Any, Callable

from vmware_policy.audit import detect_agent
from vmware_policy.decorators import (
    _bind_params,
    _infer_skill,
    _redact,
    _redact_credential_keys,
)
from vmware_policy.guard import audit_call, guard
from vmware_policy.policy import PolicyDenied
from vmware_policy.sanitize import sanitize

# ``@guarded`` only ever wraps a Typer command, so click (Typer's engine) is
# present wherever it runs. Soft-import it anyway: vmware_policy is also a pure
# MCP dependency, and importing click there must not become mandatory. An empty
# tuple makes ``except ()`` a no-op, so the classification below degrades to
# "any non-return exit is an error" when click is genuinely absent.
try:  # pragma: no cover - exercised via the CLI, not the MCP path
    from click.exceptions import Abort as _Abort
    from click.exceptions import Exit as _Exit

    _ABORT: tuple[type[BaseException], ...] = (_Abort,)
    _EXIT: tuple[type[BaseException], ...] = (_Exit,)
except ImportError:  # pragma: no cover
    _ABORT = ()
    _EXIT = ()


def guarded(
    tool: str | None = None,
    *,
    risk_level: str = "low",
    sensitive_params: list[str] | None = None,
) -> Callable:
    """Authorize + audit a CLI command through the shared enforcement core.

    Apply it **beneath** the skill's error-translation decorator so a
    :class:`PolicyDenied` becomes a teaching message rather than a traceback::

        @vm_app.command("delete")
        @cli_errors
        @guarded(risk_level="critical")
        def vm_delete(vm_name: str, target: TargetOption = None, ...):
            ...

    Args:
        tool: Operation name recorded in the audit row and matched by deny rules.
            Defaults to the wrapped function's ``__name__`` — keep it equal to the
            matching MCP tool name so one deny rule scopes both surfaces at once.
        risk_level: 'low' | 'medium' | 'high' | 'critical'; feeds the
            maintenance-window rule.
        sensitive_params: Parameter names to redact before the audit row.
    """
    sensitive = set(sensitive_params or [])

    def decorator(func: Callable) -> Callable:
        signature = inspect.signature(func)
        tool_name = tool or func.__name__
        skill = _infer_skill(func)

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            params = _bind_params(signature, args, kwargs)
            safe = _redact(params, sensitive)
            raw_target = params.get("target", params.get("env", ""))
            target = str(raw_target) if raw_target else ""
            start = time.time()
            status = "ok"
            result: Any = None
            try:
                # Same authorization gate as @vmware_tool (I-3). A no-op unless the
                # operator wrote deny / maintenance rules; raises PolicyDenied.
                guard(skill, tool_name, safe, risk_level=risk_level, target=target)
                result = func(*args, **kwargs)
                return result
            except PolicyDenied as exc:
                status = "denied"
                result = {"error": exc.result.reason, "rule": exc.result.rule}
                raise
            except _ABORT:
                # The operator declined the double-confirm — a deliberate refusal,
                # not a failure. Record it truthfully; the write never ran.
                status = "rejected"
                raise
            except _EXIT as exc:
                # typer.Exit(0) is a clean early return; a non-zero code is a
                # failure the command chose to signal itself.
                status = "ok" if getattr(exc, "exit_code", 0) == 0 else "error"
                raise
            except Exception as exc:
                status = "error"
                result = {"error": sanitize(str(exc), 500)}
                raise
            finally:
                # One audit row per invocation, to the single sink (I-8). Never
                # raises — audit_call swallows its own errors.
                audit_call(
                    skill,
                    tool_name,
                    # Same credential-key net as @vmware_tool: both surfaces
                    # write the one audit sink, so scrubbing only one of them
                    # would leave the leak reachable from the other (I-3/I-8,
                    # and CLAUDE.md 形态 #7). There is no ``sensitive_result``
                    # counterpart here because a Typer command returns None and
                    # prints instead — add one the day a CLI command returns a
                    # credential, not before.
                    params=safe,
                    result=_redact_credential_keys(result),
                    status=status,
                    duration_ms=int((time.time() - start) * 1000),
                    agent=detect_agent(),
                    risk_level=risk_level,
                    rationale=os.environ.get("VMWARE_AUDIT_RATIONALE", ""),
                    approved_by=os.environ.get("VMWARE_AUDIT_APPROVED_BY", ""),
                )

        wrapper._is_guarded = True
        wrapper._risk_level = risk_level
        wrapper._guarded_tool = tool_name
        return wrapper

    return decorator
