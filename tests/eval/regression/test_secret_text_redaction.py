"""Free-form text redaction: the corpus, and both directions of failing it.

``_redact_secrets_text`` is the last thing standing between a credential that
appears inside an *exception message* and the audit database. Key-based
redaction (``_redact_credential_keys``) cannot help here: an exception is one
string, not a dict, and the credential is inside it.

A prior round claimed to have widened this pattern. Measured against the corpus
below at HEAD~ it redacted **25 of 60** shapes (41.7%) and over-redacted 2 of 10
benign messages. The named example from the re-test —
``Authorization: Basic <base64>`` — masked the literal word ``Basic`` and left
the base64 credential in the clear, because the value pattern stopped at the
first space.

The corpus is shapes that actually turn up in vSphere / NSX / AVI / Aria
exception text and tracebacks, grouped by *why* the old pattern missed them:

  - ``\\b`` before the keyword, so ``access_token=`` / ``client_secret=`` /
    ``VMWARE_VC_PASSWORD=`` never matched (the keyword was not at a word start);
  - the separator had to be ``=``/``:``/whitespace, so ``{"token": "x"}`` and
    ``{'password': 'x'}`` — how a traceback actually prints a dict — never
    matched;
  - the value class excluded ``@``, so ``password=P@ssw0rd`` redacted one
    character;
  - no notion of HTTP auth schemes, cookies, PEM blocks, URL userinfo, or bare
    JWTs at all.

Both directions are asserted. A pattern that redacts everything would pass every
leak case and destroy every error message, so :data:`KEEP_CASES` is not
decoration — it is the other half of the test.
"""

from __future__ import annotations

import pytest

from vmware_policy.decorators import _CREDENTIAL_KEYS, _redact_secrets_text

SECRET = "hunter2AAA"
B64 = "dXNlcjpodW50ZXIyQUFB"  # base64("user:hunter2AAA")
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.7XmQzHc0Kk2t3vv1cQFakeSig"
PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA3ZxQfakekeymaterialAAAA\n"
    "bXVjaG1vcmVrZXltYXRlcmlhbEJCQkI=\n"
    "-----END RSA PRIVATE KEY-----"
)
PEM_BODY = "MIIEowIBAAKCAQEA3ZxQfakekeymaterialAAAA"

#: (label, text that could reach the audit row, substring that must not survive)
LEAK_CASES = [
    # ── plain key=value / key: value ───────────────────────────────
    ("kv_password_eq", f"login failed: password={SECRET}", SECRET),
    ("kv_password_colon", f"login failed: password: {SECRET}", SECRET),
    ("kv_password_flag", f"vmware-nsx auth --password {SECRET} failed", SECRET),
    ("kv_passwd", f"passwd={SECRET}", SECRET),
    ("kv_pwd", f"pwd={SECRET}", SECRET),
    ("kv_upper", f"PASSWORD={SECRET}", SECRET),
    ("kv_quoted_double", f'password="{SECRET}"', SECRET),
    ("kv_quoted_single", f"password='{SECRET}'", SECRET),
    ("kv_token", f"token={SECRET}", SECRET),
    ("kv_secret", f"secret={SECRET}", SECRET),
    ("kv_api_key_underscore", f"api_key={SECRET}", SECRET),
    ("kv_api_key_dash", f"api-key={SECRET}", SECRET),
    ("kv_apikey", f"apikey={SECRET}", SECRET),
    ("kv_bearer_word", f"bearer={SECRET}", SECRET),
    # ── passwords with punctuation (routine in the field) ──────────
    ("pw_with_at", "password=P@ssw0rdLong", "ssw0rdLong"),
    ("pw_with_at_quoted", 'password="P@ssw0rdLong"', "ssw0rdLong"),
    ("pw_with_bang", "password=Vmware1!Secret", "Vmware1!Secret"),
    # ── prefixed identifiers (the \b problem) ──────────────────────
    ("prefix_access_token", f"access_token={SECRET}", SECRET),
    ("prefix_refresh_token", f"refresh_token={SECRET}", SECRET),
    ("prefix_auth_token", f"auth_token={SECRET}", SECRET),
    ("prefix_client_secret", f"client_secret={SECRET}", SECRET),
    ("prefix_session_token", f"session_token={SECRET}", SECRET),
    ("prefix_vc_password", f"vcenter_password={SECRET}", SECRET),
    ("prefix_nsx_api_key", f"nsx_api_key={SECRET}", SECRET),
    ("prefix_dot_notation", f"config.password={SECRET}", SECRET),
    ("prefix_x_api_key_header", f"X-API-Key: {SECRET}", SECRET),
    # ── dict / JSON reprs (what a traceback actually prints) ───────
    ("json_token", f'{{"token": "{SECRET}"}}', SECRET),
    ("json_password", f'{{"password":"{SECRET}"}}', SECRET),
    ("pyrepr_password", f"{{'password': '{SECRET}'}}", SECRET),
    ("pyrepr_kwargs", f"connect(host='vc', password='{SECRET}')", SECRET),
    ("json_access_token", f'{{"access_token": "{SECRET}"}}', SECRET),
    ("yaml_password", f"targets:\n  - password: {SECRET}", SECRET),
    # ── Authorization headers ──────────────────────────────────────
    ("hdr_auth_basic", f"Authorization: Basic {B64}", B64),
    ("hdr_auth_bearer", f"Authorization: Bearer {JWT}", JWT),
    ("hdr_proxy_auth_basic", f"Proxy-Authorization: Basic {B64}", B64),
    ("hdr_auth_lower", f"authorization: basic {B64}", B64),
    ("hdr_auth_quoted", f'headers={{"Authorization": "Basic {B64}"}}', B64),
    ("bare_basic", f"sent Basic {B64} to vc", B64),
    ("bare_bearer", f"retrying with Bearer {JWT}", JWT),
    ("hdr_auth_digest", f"Authorization: Digest response={B64}", B64),
    # ── bare JWTs / session ids / cookies ──────────────────────────
    ("bare_jwt", f"supervisor rejected {JWT}", JWT),
    ("jwt_in_kubeconfig", f"users:\n- user:\n    token: {JWT}", JWT),
    ("vmware_session_cookie", f'Cookie: vmware_soap_session="{B64}"', B64),
    ("set_cookie", f"Set-Cookie: JSESSIONID={B64}; Path=/", B64),
    ("cookie_header", f"Cookie: SESSION={B64}", B64),
    # ── URLs / connection strings ──────────────────────────────────
    ("url_userinfo", f"could not connect to https://admin:{SECRET}@vc.example.com/sdk", SECRET),
    ("dsn_postgres", f"postgresql://harden:{SECRET}@db.example.com:5432/twin", SECRET),
    ("dsn_amqp", f"amqp://svc:{SECRET}@mq:5672/", SECRET),
    ("qs_access_token", f"GET /api?access_token={SECRET}&limit=50 -> 401", SECRET),
    ("qs_api_key", f"https://avi/api/pool?api_key={SECRET}", SECRET),
    ("qs_token_amp", f"https://vc/sdk?token={SECRET}&x=1", SECRET),
    # ── private keys ───────────────────────────────────────────────
    ("pem_private_key", f"failed to load key:\n{PEM}", PEM_BODY),
    ("kv_private_key", f"private_key={SECRET}", SECRET),
    ("kv_ssh_key", f"ssh_private_key: {SECRET}", SECRET),
    # ── misc real shapes ───────────────────────────────────────────
    ("kubeconfig_kv", f"kubeconfig={SECRET}", SECRET),
    ("credential_kv", f"credential={SECRET}", SECRET),
    ("cli_flag_token", f"vmware-vks login --token {SECRET}", SECRET),
    ("env_dump", f"VMWARE_VC_PASSWORD={SECRET}", SECRET),
    ("soap_body", f"<password>{SECRET}</password>", SECRET),
    ("ini_style", f"password = {SECRET}", SECRET),
]

#: Must survive byte-identical. Over-redaction quietly destroys the teaching
#: error messages this family spent several releases building.
KEEP_CASES = [
    ("plain_notfound", "VM 'web-99' not found on target 'vcenter-prod'. Did you mean 'web-09'?"),
    ("token_count", "response truncated: token_count=5120 exceeds budget"),
    ("secret_manager", "secret_manager_url=https://vault.example.com/v1/vmware"),
    ("authorized_word", "the account is not authorized for this operation"),
    ("basic_word", "Basic health check passed on 8 hosts"),
    ("bearer_word", "Bearer of record: operations team"),
    ("host_port", "connection to vc.example.com:443 refused"),
    ("tokenizer", "tokenizer failed on rule id cis-1.2.3"),
    ("password_policy", "password policy requires 15 characters"),
    ("no_secret_url", "GET https://vc.example.com/sdk?limit=50 -> 503"),
]


@pytest.mark.parametrize("label,text,secret", LEAK_CASES, ids=[c[0] for c in LEAK_CASES])
def test_secret_does_not_survive_redaction(label, text, secret):
    out = _redact_secrets_text(text)
    assert secret not in out, f"{label}: credential survived redaction -> {out!r}"


@pytest.mark.parametrize("label,text", KEEP_CASES, ids=[c[0] for c in KEEP_CASES])
def test_benign_text_is_untouched(label, text):
    assert _redact_secrets_text(text) == text, f"{label}: over-redacted"


def test_reported_example_keeps_the_scheme_and_masks_the_credential():
    """The example named in the re-test report.

    ``Authorization: Basic <base64>`` used to come out as ``Authorization: ***``
    followed by the untouched base64 — the pattern masked the word ``Basic`` and
    stopped at the space. The scheme is diagnostic and should stay; the
    credential is not and must not.
    """
    out = _redact_secrets_text(f"Authorization: Basic {B64}")
    assert B64 not in out
    assert "Basic" in out, "the auth scheme is diagnostic — do not redact it away"


def test_full_corpus_hit_rate_is_total():
    """Reported as one number, so a regression shows up as a rate, not a name."""
    leaked = [lbl for lbl, txt, sec in LEAK_CASES if sec in _redact_secrets_text(txt)]
    assert not leaked, (
        f"{len(LEAK_CASES) - len(leaked)}/{len(LEAK_CASES)} redacted; still leaking: {leaked}"
    )


def test_keyword_alternation_is_derived_from_the_key_list():
    """One list, not two.

    ``_CREDENTIAL_KEYS`` (used for dict keys) and the text pattern's keywords are
    the same set of names for the same thing. Kept as two hand-maintained lists
    they drift, and the drift is invisible — a credential name added to one is
    simply not redacted by the other (CLAUDE.md 形态 #6).
    """
    for key in _CREDENTIAL_KEYS:
        text = f"{key}={SECRET}"
        assert SECRET not in _redact_secrets_text(text), (
            f"{key!r} is in _CREDENTIAL_KEYS but its text form leaks"
        )


def test_redaction_is_idempotent():
    """Audit text can pass through more than one layer; a second pass must not
    corrupt an already-redacted string."""
    for _, text, _ in LEAK_CASES:
        once = _redact_secrets_text(text)
        assert _redact_secrets_text(once) == once


def test_multiple_secrets_in_one_message_all_go():
    text = (
        f"retry failed: password={SECRET} then Authorization: Bearer {JWT} "
        f"against postgresql://svc:{SECRET}@db:5432/x"
    )
    out = _redact_secrets_text(text)
    assert SECRET not in out
    assert JWT not in out
