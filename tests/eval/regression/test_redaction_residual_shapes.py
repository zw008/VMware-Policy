"""The leak shapes round 3 found still standing, and the two it found inverted.

The redaction pass went from 25/60 to 60/60 on its own corpus in v1.11.0. Round 3
rebuilt the corpus from this lab's real password shapes and found six shapes still
passing through and one that both destroyed the message *and* printed the secret:

    auth=('admin','PASS')   ->   auth=***'admin', 'PASS')

Every one of them was unreachable from the current code paths -- the family calls
``httpx.BasicAuth()``, not ``auth=(...)`` -- so they are hardening rather than a
live leak. They are worth closing anyway: a traceback is exactly where an
unreachable shape becomes reachable, and two of them are this family's own URLs.

The over-redaction half is not cosmetic. ``password: not set`` became
``password: *** set``, which reads as the opposite of what happened.
"""

from __future__ import annotations

import pytest

from vmware_policy.decorators import _redact_secrets_text as redact

SECRET = "c1QJwp"


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("auth=('admin', 'c1QJwp')", "httpx/requests' most common spelling"),
        ("credentials=('admin','c1QJwp')", "same shape, different key"),
        ("curl -u admin:c1QJwp https://vc/api", "no credential keyword anywhere"),
        ("curl --user admin:c1QJwp https://vc", "long form of the same flag"),
        ("sshpass -p c1QJwp ssh root@esxi01", "the flag is -p, not --password"),
        ("machine nsx login admin password c1QJwp", "netrc: whitespace, no dash"),
        (
            "https://admin:c1QJwp@nsx.corp/api",
            "plain DSN — the control for the two below",
        ),
        (
            "https://administrator@vsphere.local:c1QJwp@nsx.corp/api",
            "a vSphere SSO username always contains @, and the old class excluded it",
        ),
        (
            "https://admin:pw@c1QJwp@nsx.corp/api",
            "an @ in the password truncated the match and printed the tail",
        ),
    ],
)
def test_the_secret_does_not_survive(text, why):
    assert SECRET not in redact(text), why


def test_the_tuple_form_does_not_also_mangle_the_message():
    """The original produced ``auth=***'admin', 'PASS')`` — worse than either failure."""
    out = redact("auth=('admin', 'c1QJwp')")
    assert out == "auth=(***)", out


@pytest.mark.parametrize(
    "text",
    [
        "password: not set",
        "secret: not configured",
        "token: none",
        "credential: missing",
        "doctor --skip-auth was passed",
        "password policy requires 15 characters",
        "Basic health check passed",
        "token_count=5120",
        "authentication failed",
        "auth=None",
    ],
)
def test_a_report_about_a_credential_is_not_rewritten(text):
    """``password: not set`` -> ``password: *** set`` reverses the sentence."""
    assert redact(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=P@ssw0rd", "password=***"),
        ('{"token": "abc123"}', '{"token": "***"}'),
        ("Authorization: Basic YWRtaW46aHVudGVyMg==", "Authorization: Basic ***"),
        ("<password>c1QJwp</password>", "<password>***</password>"),
    ],
)
def test_the_shapes_that_already_worked_still_work(text, expected):
    """Control: the new exclusions must not have opened anything."""
    assert redact(text) == expected


def test_redaction_is_still_idempotent():
    once = redact("auth=('admin', 'c1QJwp') password=c1QJwp")
    assert redact(once) == once
