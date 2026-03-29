"""Tests for vmware_policy.policy — the policy engine."""

import pytest

from vmware_policy.policy import PolicyEngine


@pytest.mark.unit
class TestPolicyEngine:
    def test_no_rules_allows_all(self, tmp_path):
        rules_path = tmp_path / "nonexistent.yaml"
        engine = PolicyEngine(rules_path)
        result = engine.check_allowed("delete_vm")
        assert result.allowed is True
        assert result.rule == "no_rules"

    def test_deny_rule_blocks(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: no-delete\n"
            '    operations: ["delete_*"]\n'
            "    reason: No deletions allowed\n"
        )
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
        )
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
        )
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
        )
        engine = PolicyEngine(rules)
        assert engine.check_allowed("anything").allowed is False

    def test_exact_match(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "deny:\n"
            "  - name: specific\n"
            '    operations: ["vm_power_off"]\n'
            "    reason: Blocked\n"
        )
        engine = PolicyEngine(rules)
        assert engine.check_allowed("vm_power_off").allowed is False
        assert engine.check_allowed("vm_power_on").allowed is True

    def test_hot_reload(self, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("")
        engine = PolicyEngine(rules)
        assert engine.check_allowed("delete_vm").allowed is True

        # Update rules file
        rules.write_text(
            "deny:\n"
            "  - name: new-rule\n"
            '    operations: ["delete_*"]\n'
            "    reason: Now blocked\n"
        )
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
        )
        engine = PolicyEngine(rules)

        monkeypatch.setenv("VMWARE_POLICY_DISABLED", "1")
        result = engine.check_allowed("delete_vm")
        assert result.allowed is True
        assert result.rule == "policy_disabled"
