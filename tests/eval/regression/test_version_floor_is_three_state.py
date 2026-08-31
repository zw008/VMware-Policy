"""A version floor must never turn "we don't know" into "you're too old".

``vmware_policy.compat`` exists because a 404 from a call that only exists on a
newer appliance was being explained as a bad id. Its whole value is the wording
of a failure, so the failure modes below are the product, not edge cases.
"""

from __future__ import annotations

from vmware_policy.compat import Requires, at_least, parse_version, version_remedy

REQ = Requires(product="VCF Operations", minimum=(9, 0), feature="Fleet queries")


def test_an_older_appliance_is_named_and_the_id_is_exonerated() -> None:
    msg = version_remedy(REQ, "8.6.4")
    assert msg is not None
    assert "8.6.4" in msg and "9.0" in msg
    # The point of the whole module: stop sending people after the UUID.
    assert "id you passed is not the problem" in msg


def test_an_appliance_that_meets_the_floor_gets_no_version_remedy() -> None:
    """None means "not a version problem" so the caller keeps its own remedy.

    Firing here would tell someone on 9.1 to upgrade to 9.0 — worse than saying
    nothing, and it would bury the real cause of their 404.
    """
    assert version_remedy(REQ, "9.1.0.0200") is None
    assert version_remedy(REQ, "9.0") is None
    assert version_remedy(REQ, "10.0.1") is None


def test_a_bare_major_meets_a_dotted_floor() -> None:
    """``(9,) >= (9, 0)`` is False in Python — the shorter tuple loses.

    Compared as raw tuples, an appliance reporting "9" would be told to upgrade
    to the version it is already running: a wrong branch taken silently, which
    is the exact shape this module exists to prevent.
    """
    assert at_least((9,), (9, 0))
    assert version_remedy(REQ, "9") is None


def test_an_unreadable_version_asserts_nothing_about_the_build() -> None:
    """The third state. Absent it, "could not read" renders as "too old"."""
    for unreadable in (None, "", "   ", "unknown", "N/A"):
        msg = version_remedy(REQ, unreadable)
        assert msg is not None, f"{unreadable!r} produced no explanation at all"
        assert "could not be read" in msg
        # It must not claim their appliance is below the floor.
        assert "requires" not in msg or "or newer; this appliance reports" not in msg


def test_version_parsing_tolerates_what_this_estate_actually_reports() -> None:
    assert parse_version("9.1.0.0200") == (9, 1, 0, 200)  # vCenter, zero-padded build
    assert parse_version("8.6.4") == (8, 6, 4)
    assert parse_version("4.1.2.3.0") == (4, 1, 2, 3, 0)  # NSX
    assert parse_version("9.1.0-build-12345") == (9, 1, 0)  # trailing junk ends it
    assert parse_version("unknown") is None  # -> the honest branch, not (0,)


def test_a_garbage_version_never_reads_as_ancient() -> None:
    """``parse_version`` must not fall back to a zero tuple.

    ``(0,)`` compares below every floor, so a garbage string would produce a
    confident "your appliance is too old" about a version nobody read.
    """
    assert parse_version("garbage") is None
    assert "could not be read" in (version_remedy(REQ, "garbage") or "")
