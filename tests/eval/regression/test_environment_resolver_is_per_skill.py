"""One skill's environment resolver must not answer for another skill.

Round 3 of the VCF 9 field testing measured this as a live control failure, not
a code smell: with the resolver registry a single process-global slot, importing
``vmware_harden.mcp_server.server`` replaced whatever resolver was there. Harden
answers a deliberate constant (``local``) that is true of its own tools -- it
only writes its local DuckDB twin -- and false of every other skill's targets.
A ``freeze-production-writes`` deny rule on ``prod-vc01`` went DENY -> ALLOW
from nothing but that import.

The fix is the key, not the constant: Harden's answer is right for Harden.
"""

from __future__ import annotations

import pytest

from vmware_policy.environment import (
    resolve_environment,
    set_environment_resolver,
)


@pytest.fixture(autouse=True)
def _clear_registry():
    yield
    set_environment_resolver(None)
    set_environment_resolver(None, skill="monitor")
    set_environment_resolver(None, skill="harden")


def test_a_siblings_constant_does_not_answer_for_this_skill():
    set_environment_resolver(lambda t: "production" if t == "prod-vc01" else "", skill="monitor")
    set_environment_resolver(lambda t: "local", skill="harden")

    assert resolve_environment("prod-vc01", skill="monitor") == "production"
    assert resolve_environment("prod-vc01", skill="harden") == "local"


def test_registration_order_does_not_decide_the_answer():
    """The failure mode was last-writer-wins, so register in both orders."""
    set_environment_resolver(lambda t: "local", skill="harden")
    set_environment_resolver(lambda t: "production", skill="monitor")
    assert resolve_environment("prod-vc01", skill="monitor") == "production"

    set_environment_resolver(lambda t: "production", skill="monitor")
    set_environment_resolver(lambda t: "local", skill="harden")
    assert resolve_environment("prod-vc01", skill="monitor") == "production"


def test_a_skill_with_no_registration_is_unlabelled_not_borrowed():
    """An unregistered skill must read as undeclared -- never inherit a sibling's.

    Falling back to whichever keyed resolver happens to exist would reintroduce
    the same defect with extra steps. The legacy slot is cleared first because
    falling back to *that* is the deliberate mixed-version contract, covered
    below.
    """
    set_environment_resolver(None)
    set_environment_resolver(lambda t: "production", skill="monitor")
    assert resolve_environment("prod-vc01", skill="nsx") == ""


def test_the_unkeyed_slot_still_works_for_older_skills():
    """A skill built against a pre-1.12 vmware-policy must keep resolving.

    Its registration lands in the legacy slot, and a call that names no skill
    still finds it -- mixed versions degrade to the old behaviour, never worse.
    """
    set_environment_resolver(lambda t: "staging")
    assert resolve_environment("prod-vc01") == "staging"


def test_a_keyed_resolver_beats_the_legacy_slot():
    set_environment_resolver(lambda t: "staging")
    set_environment_resolver(lambda t: "production", skill="monitor")
    assert resolve_environment("prod-vc01", skill="monitor") == "production"


def test_guard_passes_the_skill_through():
    """The wiring, not just the registry: guard() must key by its own skill arg.

    Without this the registry is per-skill and every lookup still asks for the
    same (absent) key, which is the same bug with a dict in front of it.
    """
    from vmware_policy.guard import guard

    seen: list[str] = []

    def _resolver(target: str) -> str:
        seen.append(target)
        return "production"

    set_environment_resolver(_resolver, skill="monitor")
    guard("monitor", "list_vms", {}, target="prod-vc01")
    assert seen == ["prod-vc01"], "guard() did not consult the monitor-keyed resolver"
