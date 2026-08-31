"""Direct tests of the shared enforcement core, ``vmware_policy.guard``.

``guard()`` is what BOTH surfaces route every operation through (MCP's
``@vmware_tool`` and the CLI ``@guarded`` decorator), so a regression here is a
family-wide regression. Two things pinned that no other suite covered:

1. **guard() resolves the environment UNCONDITIONALLY** — including for an
   omitted ``target`` that falls back to the config's ``default_target``. A
   short-circuit on empty target silently disables every env-scoped ``deny``
   rule on the default target (the "inert control" failure class). The autouse
   ``_declared_environment`` fixture in ``conftest.py`` returns a non-empty env
   for *every* target, which masks this — so here we register our own resolver
   that labels ONLY the empty/default target, the exact case that broke.
2. **resolve_environment's contract** — its unit tests moved here when
   ``test_declared_environment.py`` was retired with the declared-environment
   gate. resolve_environment survives and is load-bearing for guard(); it must
   stay covered.
"""

from __future__ import annotations

import pytest

from vmware_policy import guard as guard_mod
from vmware_policy.environment import resolve_environment, set_environment_resolver
from vmware_policy.guard import guard
from vmware_policy.policy import PolicyDenied, PolicyEngine


@pytest.fixture
def rules(tmp_path, monkeypatch):
    """Make guard() authorize against a temp rules file (fresh engine, no singleton)."""

    def make(text: str) -> PolicyEngine:
        p = tmp_path / "rules.yaml"
        p.write_text(text, encoding="utf-8")
        eng = PolicyEngine(rules_path=p)
        monkeypatch.setattr(guard_mod, "get_policy_engine", lambda: eng)
        return eng

    return make


# ── guard() resolves env unconditionally (the HIGH-1 regression) ─────────────


def test_env_scoped_deny_fires_for_omitted_target_via_default_resolution(rules):
    """default_target is production, operator wrote a prod-scoped deny: a write
    that OMITS target must still be denied. Short-circuiting env resolution on an
    empty target silently lets it through — an inert security control."""
    rules(
        "deny:\n"
        "  - name: prod-freeze\n"
        '    operations: ["vm_delete"]\n'
        '    environments: ["production"]\n'
        "    reason: prod frozen\n"
    )
    # Label ONLY the empty/default target as production — the conftest autouse
    # resolver returns 'lab' for everything and would hide this.
    set_environment_resolver(lambda t: "production" if t == "" else None)
    try:
        with pytest.raises(PolicyDenied):
            guard("aiops", "vm_delete", {"vm_name": "web-01"}, risk_level="high", target="")
    finally:
        set_environment_resolver(None)


def test_guard_allows_when_no_rules(rules):
    rules("")  # empty rules → allow-all baseline
    assert guard("aiops", "vm_delete", {}, risk_level="critical", target="").allowed


def test_guard_raises_policydenied_on_matching_deny(rules):
    rules(
        "deny:\n"
        "  - name: no-clean-slate\n"
        '    operations: ["vm_clean_slate"]\n'
        "    reason: never\n"
    )
    with pytest.raises(PolicyDenied):
        guard("aiops", "vm_clean_slate", {}, risk_level="critical", target="prod")


# ── resolve_environment contract (restored from test_declared_environment) ───


def test_registered_resolver_result_is_returned():
    set_environment_resolver(lambda t: "production")
    try:
        assert resolve_environment("prod-vc01") == "production"
    finally:
        set_environment_resolver(None)


def test_unregistered_resolver_answers_empty():
    set_environment_resolver(None)
    assert resolve_environment("anything") == ""


def test_blank_declaration_answers_empty():
    set_environment_resolver(lambda t: "   ")
    try:
        assert resolve_environment("x") == ""
    finally:
        set_environment_resolver(None)


def test_raising_resolver_answers_empty_not_a_crash():
    def boom(_t):
        raise RuntimeError("config broken")

    set_environment_resolver(boom)
    try:
        assert resolve_environment("x") == ""
    finally:
        set_environment_resolver(None)
