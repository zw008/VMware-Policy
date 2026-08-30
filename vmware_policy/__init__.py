"""VMware Policy — unified audit, policy enforcement, and sanitization for VMware MCP skills."""

__version__ = "1.11.0"

from vmware_policy.audit import AuditEngine, get_engine
from vmware_policy.budget import BudgetExceeded, BudgetTracker, get_budget
from vmware_policy.cli_guard import guarded
from vmware_policy.decorators import PolicyDenied, report_tool_failure, vmware_tool
from vmware_policy.toolschema import describe_tool_parameters, parse_args_section
from vmware_policy.envelope import ENVELOPE_KEYS, paginated
from vmware_policy.environment import (
    mtime_cached_loader,
    resolve_environment,
    set_environment_resolver,
)
# NOTE: `guard` / `audit_call` are intentionally NOT re-exported here. The name
# `guard` would shadow the submodule `vmware_policy.guard` in this package's
# namespace, so `vmware_policy.guard.<x>` (and monkeypatch's string-path
# resolution) would hit the function, not the module. Import them from the
# submodule: `from vmware_policy.guard import guard, audit_call`.
from vmware_policy.patterns import Pattern, PatternMatch, get_pattern_engine
from vmware_policy.policy import get_policy_engine
from vmware_policy.sanitize import sanitize
from vmware_policy.undo import UndoStore, get_undo_store

__all__ = [
    "vmware_tool",
    "describe_tool_parameters",
    "parse_args_section",
    "guarded",
    "report_tool_failure",
    "sanitize",
    "paginated",
    "ENVELOPE_KEYS",
    "mtime_cached_loader",
    "set_environment_resolver",
    "resolve_environment",
    "Pattern",
    "PatternMatch",
    "get_pattern_engine",
    "PolicyDenied",
    "get_engine",
    "get_policy_engine",
    "AuditEngine",
    "BudgetExceeded",
    "BudgetTracker",
    "get_budget",
    "UndoStore",
    "get_undo_store",
]
