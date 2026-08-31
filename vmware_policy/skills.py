"""The one place a skill's short name is derived.

``guard()`` keys policy decisions by this name, ``audit_call()`` records it, and
:func:`vmware_policy.set_environment_resolver` keys environment resolvers by it.
Three callers deriving it three ways is how the keys drift apart, and a key that
drifts silently resolves to the wrong skill's environment -- so they all call
here.
"""

from __future__ import annotations


def skill_name(module: str) -> str:
    """``"vmware_nsx_security.mcp_server.server"`` -> ``"nsx_security"``.

    Returns ``"unknown"`` when no ``vmware_*`` package appears in the path,
    which is what a bare ``mcp_server.server`` module produced before the
    packages were namespaced (踩坑 #41).
    """
    for part in (module or "").split("."):
        if part.startswith("vmware_"):
            return part.replace("vmware_", "", 1)
    return "unknown"
