"""The ``@vmware_tool`` decorator — mandatory wrapper for all VMware MCP tool functions.

Responsibilities:
  1. Pre-check: evaluate policy rules (deny, maintenance window, limits)
  2. Execute: run the actual tool function
  3. Post-log: write audit record to ``~/.vmware/audit.db``
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

import time
import traceback
from functools import wraps
from typing import Any

from vmware_policy.audit import AuditEngine, detect_agent, get_engine
from vmware_policy.policy import PolicyEngine, PolicyResult, get_policy_engine
from vmware_policy.sanitize import sanitize


class PolicyDenied(Exception):
    """Raised when an operation is denied by policy."""

    def __init__(self, result: PolicyResult) -> None:
        self.result = result
        super().__init__(result.reason)


def vmware_tool(
    fn: Any = None,
    *,
    risk_level: str = "low",
    idempotent: bool = False,
    timeout_seconds: int = 300,
    sensitive_params: list[str] | None = None,
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
        timeout_seconds: Maximum execution time before warning.
        sensitive_params: Parameter names to redact in audit logs.
    """
    _sensitive = set(sensitive_params or [])

    def decorator(func: Any) -> Any:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            skill = _infer_skill(func)
            tool_name = func.__name__
            agent = detect_agent()
            start = time.time()
            status = "ok"
            result: Any = None
            policy_result: PolicyResult | None = None
            audit = get_engine()
            policy = get_policy_engine()

            # ── Redact sensitive params for logging ───────────────
            safe_params = _redact(kwargs, _sensitive)

            try:
                # ── Policy pre-check ──────────────────────────────
                env = kwargs.get("target", kwargs.get("env", ""))
                policy_result = policy.check_allowed(
                    tool_name,
                    env=str(env) if env else "",
                    risk_level=risk_level,
                    params=kwargs,
                )

                if not policy_result.allowed:
                    status = "denied"
                    result = {"error": policy_result.reason, "rule": policy_result.rule}
                    raise PolicyDenied(policy_result)

                # ── Execute ───────────────────────────────────────
                result = func(*args, **kwargs)
                return result

            except PolicyDenied:
                raise

            except Exception as exc:
                status = "error"
                result = {"error": str(exc), "traceback": traceback.format_exc()[-500:]}
                raise

            finally:
                duration = int((time.time() - start) * 1000)
                bypassed = policy_result and policy_result.rule == "policy_disabled"
                final_status = f"{status}_bypassed" if bypassed else status

                audit.log(
                    skill=skill,
                    tool=tool_name,
                    params=safe_params,
                    result=result,
                    status=final_status,
                    duration_ms=duration,
                    agent=agent,
                    user="",
                    risk_level=risk_level,
                )

        # ── Attach metadata for harness / introspection ───────────
        wrapper._is_vmware_tool = True
        wrapper._risk_level = risk_level
        wrapper._idempotent = idempotent
        wrapper._timeout_seconds = timeout_seconds
        wrapper._sensitive_params = list(_sensitive)
        return wrapper

    # Support @vmware_tool and @vmware_tool(...)
    if fn is not None:
        return decorator(fn)
    return decorator


# ── Internal helpers ──────────────────────────────────────────────────


def _infer_skill(func: Any) -> str:
    """Infer skill name from the function's module path.

    ``vmware_aiops.ops.vm_lifecycle`` → ``aiops``
    ``mcp_server.server`` → try the parent package → ``unknown``
    """
    module = getattr(func, "__module__", "") or ""
    parts = module.split(".")
    for part in parts:
        if part.startswith("vmware_"):
            return part.replace("vmware_", "", 1)
    return "unknown"


def _redact(params: dict[str, Any], sensitive: set[str]) -> dict[str, Any]:
    """Return a copy of params with sensitive values replaced by '***'."""
    if not sensitive:
        return params
    return {k: "***" if k in sensitive else v for k, v in params.items()}
