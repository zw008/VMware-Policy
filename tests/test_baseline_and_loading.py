"""Baseline + rule-loading behaviour that survives v1.8.7.

Consolidates the still-relevant coverage from the old test_default_rules.py and
test_20260719_review.py after approval tiers and the require-declared-environment
gate were removed: the packaged baseline is allow-all + audit-all, a user
rules.yaml replaces it entirely, an unreadable user file fails closed-and-loud,
and a hand-written min_risk typo widens a deny rule rather than crashing.
"""

from __future__ import annotations

import pytest

from vmware_policy.policy import DEFAULT_RULES_PATH, PolicyEngine


@pytest.fixture
def engine(tmp_path):
    def make(text: str | None) -> PolicyEngine:
        p = tmp_path / "rules.yaml"
        if text is not None:
            p.write_text(text, encoding="utf-8")
        return PolicyEngine(rules_path=p)

    return make


def test_packaged_baseline_file_exists():
    assert DEFAULT_RULES_PATH.exists(), "the shipped rules_default.yaml must be packaged"


def test_missing_user_rules_falls_back_to_baseline(engine):
    """No ~/.vmware/rules.yaml → the packaged baseline is loaded, and the source
    says so rather than pretending rules are user-authored."""
    eng = engine(None)
    assert eng.active_rules_source() == "packaged-default"


def test_baseline_blocks_nothing_by_default(engine):
    """The v1.8.7 baseline ships allow-all: authorization is the vCenter account's
    job (RBAC), not this file. Even a critical destructive op is allowed."""
    eng = engine(None)
    for op in ("vm_delete", "cluster_delete", "delete_dfw_policy"):
        assert eng.check_allowed(op, env="production", risk_level="critical").allowed


def test_user_file_wins_entirely(engine):
    """A user rules.yaml replaces the baseline, it is never merged — a deny the
    operator writes takes effect, and the source reports 'user'."""
    eng = engine(
        "deny:\n"
        "  - name: no-clean-slate\n"
        '    operations: ["vm_clean_slate"]\n'
        "    reason: never\n"
    )
    assert eng.active_rules_source() == "user"
    assert eng.check_allowed("vm_clean_slate", risk_level="critical").allowed is False


def test_unreadable_user_file_fails_closed_and_loud(engine):
    """A user file that exists but will not load does NOT fall back to the
    shipped baseline (applying rules the operator never wrote is the wrong
    surprise) and does NOT continue permissively.

    This assertion was inverted until 2026-08-30. It read "enforces nothing"
    and passed, which is how a UTF-8 rules.yaml on a cp936 host could turn a
    ``freeze-production-writes`` deny into an ALLOW with every test green: the
    suite had written the wrong failure direction down as the contract. See
    ``tests/eval/regression/test_gbk_locale_rules_load.py``.
    """
    eng = engine("deny: [ unclosed\n")
    assert eng.active_rules_source() == "user-unreadable"
    assert eng.check_allowed("vm_delete", risk_level="critical").allowed is False


def test_deny_min_risk_typo_widens_rather_than_crashing(engine):
    """A hand-written min_risk_level typo must not crash check_allowed, and must
    widen the rule (deny more) rather than silently never firing."""
    eng = engine(
        "deny:\n"
        "  - name: freeze\n"
        '    operations: ["vm_delete"]\n'
        "    min_risk_level: hihg\n"  # typo for 'high'
        "    reason: change freeze\n"
    )
    # Unknown min_risk reads as index 0, so the rule applies at every level.
    assert eng.check_allowed("vm_delete", risk_level="low").allowed is False
    assert eng.check_allowed("vm_delete", risk_level="critical").allowed is False


def test_env_scoped_deny_still_matches_declared_targets(engine):
    """environment is kept as an optional label a deny rule may scope to."""
    eng = engine(
        "deny:\n"
        "  - name: prod-freeze\n"
        '    operations: ["vm_delete"]\n'
        '    environments: ["production"]\n'
        "    reason: prod frozen\n"
    )
    assert eng.check_allowed("vm_delete", env="production", risk_level="high").allowed is False
    assert eng.check_allowed("vm_delete", env="lab", risk_level="high").allowed is True
