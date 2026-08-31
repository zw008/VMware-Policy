"""Tests for vmware_policy.policy — the policy engine."""

import pytest

from vmware_policy.policy import PolicyEngine


@pytest.mark.unit
class TestPolicyEngine:
    def test_empty_rules_allow_all(self, tmp_path):
        """An operator who writes an empty rules file gets no enforcement."""
        rules_path = tmp_path / "rules.yaml"
        rules_path.write_text("", encoding="utf-8")
        engine = PolicyEngine(rules_path)
        result = engine.check_allowed("delete_vm")
        assert result.allowed is True
        assert result.rule == "no_rules"

    def test_missing_rules_file_uses_baseline_and_still_denies_nothing(self, tmp_path):
        """A missing file now falls back to the packaged baseline (see
        test_default_rules.py). The baseline defines approval tiers but no deny
        rules, so nothing that previously succeeded is blocked."""
        engine = PolicyEngine(tmp_path / "nonexistent.yaml")
        assert engine.active_rules_source() == "packaged-default"
        assert engine.check_allowed("delete_vm").allowed is True

    def test_deny_rule_blocks(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: no-delete\n"
            '    operations: ["delete_*"]\n'
            "    reason: No deletions allowed\n"
        , encoding="utf-8")
        engine = PolicyEngine(rules)
        result = engine.check_allowed("delete_segment")
        assert result.allowed is False
        assert result.rule == "no-delete"
        assert "No deletions" in result.reason

    def test_deny_rule_env_filter(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: no-delete-prod\n"
            '    operations: ["delete_*"]\n'
            '    environments: ["production"]\n'
            "    reason: No deletions in prod\n"
        , encoding="utf-8")
        engine = PolicyEngine(rules)

        prod = engine.check_allowed("delete_vm", env="production")
        assert prod.allowed is False

        dev = engine.check_allowed("delete_vm", env="development")
        assert dev.allowed is True

    def test_deny_rule_risk_filter(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: no-critical\n"
            "    min_risk_level: critical\n"
            "    reason: Critical ops blocked\n"
        , encoding="utf-8")
        engine = PolicyEngine(rules)

        crit = engine.check_allowed("any_op", risk_level="critical")
        assert crit.allowed is False

        low = engine.check_allowed("any_op", risk_level="low")
        assert low.allowed is True

    def test_wildcard_pattern(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: block-all\n"
            '    operations: ["*"]\n'
            "    reason: Everything blocked\n"
        , encoding="utf-8")
        engine = PolicyEngine(rules)
        assert engine.check_allowed("anything").allowed is False

    def test_exact_match(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: specific\n"
            '    operations: ["vm_power_off"]\n'
            "    reason: Blocked\n"
        , encoding="utf-8")
        engine = PolicyEngine(rules)
        assert engine.check_allowed("vm_power_off").allowed is False
        assert engine.check_allowed("vm_power_on").allowed is True

    def test_hot_reload(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("", encoding="utf-8")
        engine = PolicyEngine(rules)
        assert engine.check_allowed("delete_vm").allowed is True

        # Update rules file
        rules.write_text(
            "deny:\n"
            "  - name: new-rule\n"
            '    operations: ["delete_*"]\n'
            "    reason: Now blocked\n"
        , encoding="utf-8")
        # Force mtime change detection
        import os
        os.utime(rules, (rules.stat().st_mtime + 1, rules.stat().st_mtime + 1))

        assert engine.check_allowed("delete_vm").allowed is False

    def test_bypass_mode(self, tmp_path, monkeypatch):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: block-all\n"
            '    operations: ["*"]\n'
            "    reason: Blocked\n"
        , encoding="utf-8")
        engine = PolicyEngine(rules)

        monkeypatch.setenv("VMWARE_POLICY_DISABLED", "1")
        result = engine.check_allowed("delete_vm")
        assert result.allowed is True
        assert result.rule == "policy_disabled"

    def test_change_limits_is_reserved_not_enforced(self, tmp_path, caplog):
        """Issue #2: change_limits is a documented-but-unimplemented no-op.

        Configuring it must NOT block an over-limit operation (nothing treats
        'limits' as a working feature) — it only emits a 'NOT enforced' warning.
        """
        import logging

        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "change_limits:\n"
            "  max_cpu_change_pct: 20\n"
        , encoding="utf-8")
        engine = PolicyEngine(rules)

        with caplog.at_level(logging.WARNING, logger="vmware-policy.policy"):
            result = engine.check_allowed(
                "reconfigure_vm", params={"cpu_change_pct": 80}
            )

        # Reserved feature: the operation is allowed despite "exceeding" limits.
        assert result.allowed is True
        assert result.rule == "default_allow"
        assert any("not yet" in r.message.lower() for r in caplog.records)
