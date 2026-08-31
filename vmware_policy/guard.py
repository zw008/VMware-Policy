"""The surface-agnostic enforcement core: one authorization gate, one audit sink.

Both entry surfaces — MCP's ``@vmware_tool`` and the CLI's ``@guarded`` — route
every operation through the same two calls, so they cannot drift on what is
authorized or what is recorded (HLD §4; invariants I-1 / I-3 / I-8):

    guard(...)      — policy authorization (the operator's deny rules / window)
    audit_call(...) — the one and only writer to ~/.vmware/audit.db

Read/write *authorization* is deliberately NOT here: that is the vCenter/NSX
account's job (RBAC, HLD §1/§5). ``guard()`` only applies the operator's optional
``deny``/maintenance rules and is a **no-op when none are written** — the default
install ships full read+write and lets the account's privilege decide what lands.
"""

from __future__ import annotations

from typing import Any

from vmware_policy.audit import detect_agent, get_engine
from vmware_policy.environment import resolve_environment
from vmware_policy.policy import PolicyDenied, PolicyResult, get_policy_engine


def guard(
    skill: str,
    tool: str,
    params: dict[str, Any] | None = None,
    *,
    risk_level: str = "low",
    target: str = "",
) -> PolicyResult:
    """Authorize an operation. Returns the :class:`PolicyResult`, or raises
    :class:`PolicyDenied` when a ``deny`` rule matches or a closed maintenance
    window blocks a high/critical op.

    A no-op (``allowed=True``) when no ``~/.vmware/rules.yaml`` exists — the
    default. ``target`` is resolved to its declared environment for
    environment-scoped deny rules; an undeclared target simply matches no such
    rule and is never refused for lack of a label (HLD §6, D-3).

    Resolution is UNCONDITIONAL — an empty ``target`` is passed to the resolver,
    not short-circuited. Most tools take ``target`` as optional and fall back to
    the config's ``default_target``, so the resolver is the only thing that knows
    which environment an omitted target actually means; short-circuiting here
    would silently disable every env-scoped deny rule on the default target
    (``resolve_environment``'s documented contract, and what ``@vmware_tool`` did
    at HEAD via ``self.env = resolve_environment(self.target)``).
    """
    env = resolve_environment(target, skill=skill)
    result = get_policy_engine().check_allowed(
        tool, env=env, risk_level=risk_level, params=params or {}
    )
    if not result.allowed:
        raise PolicyDenied(result)
    return result


def audit_call(
    skill: str,
    tool: str,
    *,
    params: dict[str, Any] | None = None,
    result: Any = None,
    status: str = "ok",
    duration_ms: int = 0,
    agent: str | None = None,
    risk_level: str = "low",
    rationale: str = "",
    approved_by: str = "",
) -> None:
    """Write exactly one row to ``~/.vmware/audit.db`` — the single audit sink for
    every surface (I-8). Never raises: ``AuditEngine.log`` swallows its own errors
    and degrades to a stderr warning, so audit failure cannot break the operation.

    ``params``/``result`` are recorded as given — the caller sanitizes/redacts
    first (``audit.py`` does not re-sanitize). ``agent`` defaults to the detected
    caller. ``rationale``/``approved_by`` are self-attested audit enrichment, not
    authorization (HLD §8.3).
    """
    get_engine().log(
        skill=skill,
        tool=tool,
        params=params or {},
        result=result,
        status=status,
        duration_ms=duration_ms,
        agent=agent if agent is not None else detect_agent(),
        risk_level=risk_level,
        rationale=rationale,
        approved_by=approved_by,
    )
