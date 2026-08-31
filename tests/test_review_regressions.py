"""Regressions from the 2026-07-18 pre-release review (Fable code review).

The subset that survives v1.8.7's removal of read-only, approval tiers, and the
require-declared-environment gate: deny-rule env scoping, risk-index robustness,
the CLI layout, and per-target pattern keying. (The regressions tied to those
removed features were retired along with them.)
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from vmware_policy.policy import PolicyEngine


@pytest.fixture
def rules(tmp_path):
    def make(text: str) -> PolicyEngine:
        p = tmp_path / "rules.yaml"
        p.write_text(text, encoding="utf-8")
        return PolicyEngine(rules_path=p)

    return make


# ---------------------------------------------------------------------------
# deny rules: env scoping (glob + no-empty-match)
# ---------------------------------------------------------------------------


def test_env_scoped_deny_does_not_match_undeclared_targets(rules):
    """env="" means 'environment unknown'. A production-only freeze firing on
    every unlabelled lab target is an availability regression, not a policy."""
    engine = rules(
        "deny:\n"
        "  - name: prod-freeze\n"
        '    operations: ["vm_delete"]\n'
        '    environments: ["production"]\n'
        "    reason: prod frozen\n"
    )
    assert engine.check_allowed("vm_delete", env="", risk_level="critical").allowed


def test_env_scoped_deny_supports_globs(rules):
    """A deny written 'prod*' that silently never fires is the inert-control
    failure class itself."""
    engine = rules(
        "deny:\n"
        "  - name: prod-freeze\n"
        '    operations: ["vm_delete"]\n'
        '    environments: ["prod*"]\n'
        "    reason: prod frozen\n"
    )
    assert engine.check_allowed("vm_delete", env="production", risk_level="critical").allowed is False
    assert engine.check_allowed("vm_delete", env="lab", risk_level="critical").allowed is True


# ---------------------------------------------------------------------------
# unknown risk_level must not raise, and reads as the most restrictive level
# ---------------------------------------------------------------------------


def test_unknown_risk_level_is_treated_as_critical_not_a_crash(rules):
    """`vmware-audit policy --risk hgih` used to traceback with ValueError.
    An unknown level reads as the most restrictive one, so a deny scoped to
    min_risk_level still fires for it instead of crashing."""
    engine = rules(
        "deny:\n"
        "  - name: no-high-risk\n"
        '    operations: ["vm_delete"]\n'
        "    min_risk_level: high\n"
        "    reason: change freeze\n"
    )
    # Unknown 'hgih' → treated as critical (>= high) → the deny fires, no crash.
    assert engine.check_allowed("vm_delete", risk_level="hgih").allowed is False
    # A genuinely low-risk call is below the threshold and still runs.
    assert engine.check_allowed("vm_delete", risk_level="low").allowed is True


# ---------------------------------------------------------------------------
# the CLI's policy command must be registered under python -m execution
# ---------------------------------------------------------------------------


def test_policy_command_registers_before_main_guard():
    """The command was appended AFTER `if __name__ == "__main__": app()`, so
    `python -m vmware_policy.cli policy` ran the app before the command
    existed. Pin the module layout: no code after the __main__ guard."""
    src = pathlib.Path("vmware_policy/cli.py").read_text(encoding="utf-8")
    guard = src.index('if __name__ == "__main__"')
    assert "def policy(" in src[:guard], "policy command must be defined before the __main__ guard"
    tail = src[guard:].splitlines()[2:]
    assert not any(line.startswith(("def ", "@app.")) for line in tail), (
        "nothing may be defined after the __main__ guard — it would not exist "
        "under script execution"
    )


def test_policy_command_works_via_module_execution():
    proc = subprocess.run(
        [sys.executable, "-m", "vmware_policy.cli", "policy"],
        capture_output=True,
        text=True, encoding="utf-8",
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Rules in force" in proc.stdout


# ---------------------------------------------------------------------------
# pattern engine keys by target NAME; policy scopes by environment
# ---------------------------------------------------------------------------


def test_pattern_engine_receives_target_name_not_environment(tmp_path, monkeypatch):
    """Rate limits and circuit breakers are per-target. Feeding them the
    resolved environment pools every 'production' vCenter into one counter —
    one flaky target trips the breaker for all of them."""
    import vmware_policy.audit as audit_mod
    import vmware_policy.patterns as patterns_mod
    from vmware_policy.audit import AuditEngine
    from vmware_policy.decorators import vmware_tool
    from vmware_policy.environment import set_environment_resolver

    audit_mod._engine = AuditEngine(tmp_path / "a.db")
    set_environment_resolver(lambda t: "production")

    seen: list[str] = []
    real_engine = patterns_mod.get_pattern_engine()
    monkeypatch.setattr(
        real_engine,
        "match",
        lambda skill, tool, target="", params=None: (seen.append(target), None)[1],
    )

    @vmware_tool(risk_level="low")
    def vm_info(target: str = "") -> str:
        return "ok"

    vm_info(target="prod-vc01")
    audit_mod._engine = None
    set_environment_resolver(None)
    assert seen == ["prod-vc01"], (
        f"pattern engine got {seen} — must be the target name, not the environment"
    )
