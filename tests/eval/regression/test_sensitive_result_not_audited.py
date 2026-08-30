"""The audit row must not become the place a credential is filed.

2026-08-30, real-hardware round. ``@vmware_tool`` persists a tool's return
value verbatim. VKS's ``get_supervisor_kubeconfig`` returns a kubeconfig whose
own docstring says *"treat it as a credential, do not log or share"* — and the
decorator was logging it, so a live Supervisor JWT sat in plaintext in
``~/.vmware/audit.db``, written by the machinery that exists to make operations
accountable. The audit DB is also the artefact most likely to be copied off the
machine and attached to a ticket, which is what makes it worse than a log leak.

These tests assert the fix from both sides, because either half alone is a
different bug:

  * the secret is gone from the row — searched across the **whole row**, not
    just the ``result`` column, since a leak that migrates one column over is
    exactly how this survives a narrow test;
  * an ordinary tool's result is **still recorded**, and the sensitive tool's
    row still carries who / when / which arguments / whether it succeeded.
    A decorator that redacted everything would pass the leak test and destroy
    the audit trail.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
from vmware_policy.audit import AuditEngine
from vmware_policy.decorators import vmware_tool

TOKEN = "eyJhbGciOiJSUzI1NiJ9.SUPERVISOR_SESSION_JWT_DO_NOT_LOG.sig"

KUBECONFIG = f"""apiVersion: v1
kind: Config
clusters:
- name: supervisor
  cluster: {{server: 'https://10.0.0.5:6443'}}
users:
- name: vsphere-user
  user:
    token: {TOKEN}
current-context: supervisor-context
"""


@pytest.fixture
def audit_db(tmp_path):
    """A private audit.db, plus a reader that returns whole rows."""
    db_path = tmp_path / "audit.db"
    audit_mod._engine = AuditEngine(db_path)
    policy_mod._engine = None
    yield db_path
    audit_mod._engine = None
    policy_mod._engine = None


def _rows(db_path) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
    finally:
        conn.close()


def _whole_row_text(row: dict) -> str:
    """Every column concatenated.

    The point of the test is that the secret is nowhere in the record. Reading
    only ``result`` would miss it reappearing in ``params``, in a traceback, or
    in a column added later.
    """
    return "\n".join(f"{k}={v}" for k, v in row.items())


# ── The leak ──────────────────────────────────────────────────────────


@pytest.mark.unit
def test_declared_sensitive_result_is_absent_from_the_whole_audit_row(audit_db):
    @vmware_tool(risk_level="low", sensitive_result=True)
    def get_supervisor_kubeconfig(namespace: str, target: str = "") -> dict:
        """Carries a short-lived session token — do not log or share."""
        return {"namespace": namespace, "kubeconfig": KUBECONFIG}

    get_supervisor_kubeconfig(namespace="ns-prod", target="vcenter-prod")

    (row,) = _rows(audit_db)
    assert TOKEN not in _whole_row_text(row)
    assert row["result"] == json.dumps("[redacted: return value declared sensitive]")


@pytest.mark.unit
def test_the_caller_still_receives_the_real_credential(audit_db):
    """Redaction is for the audit copy only — the tool must still work."""

    @vmware_tool(sensitive_result=True)
    def get_supervisor_kubeconfig(namespace: str) -> dict:
        return {"namespace": namespace, "kubeconfig": KUBECONFIG}

    result = get_supervisor_kubeconfig(namespace="ns-prod")
    assert result["kubeconfig"] == KUBECONFIG


@pytest.mark.unit
def test_credential_shaped_key_is_redacted_without_any_declaration(audit_db):
    """The net for a tool that forgets to declare (CLAUDE.md 形态 #7).

    A per-tool opt-in is a marker some tool will forget, and this family has
    been bitten by that shape repeatedly. So the shared layer also refuses to
    store values filed under a credential key name, declaration or not.
    """

    @vmware_tool
    def some_new_tool(target: str = "") -> dict:
        return {"cluster": "tkc-1", "kubeconfig": KUBECONFIG, "token": TOKEN}

    some_new_tool()

    (row,) = _rows(audit_db)
    assert TOKEN not in _whole_row_text(row)
    stored = json.loads(row["result"])
    assert stored["cluster"] == "tkc-1"
    assert stored["kubeconfig"] == "[redacted: credential-shaped key]"
    assert stored["token"] == "[redacted: credential-shaped key]"


@pytest.mark.unit
def test_credential_key_nested_in_dicts_and_lists_is_redacted(audit_db):
    @vmware_tool
    def workflow_status(target: str = "") -> dict:
        return {
            "workflow_id": "wf-1",
            "steps": [
                {"tool": "vm_guest_exec", "params": {"user": "root", "password": TOKEN}},
            ],
        }

    workflow_status()

    (row,) = _rows(audit_db)
    assert TOKEN not in _whole_row_text(row)
    stored = json.loads(row["result"])
    assert stored["steps"][0]["params"]["user"] == "root"
    assert stored["steps"][0]["params"]["password"] == "[redacted: credential-shaped key]"


@pytest.mark.unit
def test_redaction_does_not_mutate_the_object_handed_back(audit_db):
    payload = {"cluster": "tkc-1", "kubeconfig": KUBECONFIG}

    @vmware_tool
    def get_tkc_kubeconfig(target: str = "") -> dict:
        return payload

    returned = get_tkc_kubeconfig()
    assert returned is payload
    assert payload["kubeconfig"] == KUBECONFIG


# ── The controls: the audit trail must survive the fix ────────────────


@pytest.mark.unit
def test_an_ordinary_tools_result_is_still_recorded_in_full(audit_db):
    """Positive control.

    A decorator that redacted every result would pass the leak test above and
    quietly destroy the reason the result column exists.
    """

    @vmware_tool
    def list_namespaces(target: str = "") -> dict:
        return {"items": [{"name": "ns-a", "phase": "Running"}], "total": 1}

    list_namespaces(target="vcenter-prod")

    (row,) = _rows(audit_db)
    assert json.loads(row["result"]) == {
        "items": [{"name": "ns-a", "phase": "Running"}],
        "total": 1,
    }


@pytest.mark.unit
def test_sensitive_tools_row_still_carries_who_when_what_and_whether_it_worked(audit_db):
    """Dropping the whole record would be a different bug, not a fix."""

    @vmware_tool(risk_level="low", sensitive_result=True)
    def get_supervisor_kubeconfig(namespace: str, target: str = "") -> dict:
        return {"namespace": namespace, "kubeconfig": KUBECONFIG}

    get_supervisor_kubeconfig(namespace="ns-prod", target="vcenter-prod")

    (row,) = _rows(audit_db)
    assert row["tool"] == "get_supervisor_kubeconfig"
    assert row["status"] == "ok"
    assert row["user"]  # OS user, filled by AuditEngine.log
    assert row["ts"]
    assert json.loads(row["params"]) == {"namespace": "ns-prod", "target": "vcenter-prod"}
    assert row["duration_ms"] >= 0


@pytest.mark.unit
def test_a_sensitive_tool_that_fails_still_records_why(audit_db):
    """``sensitive_result`` covers the *return value*.

    An exception record is authored by the decorator and already secret-scrubbed
    (``_redact_secrets_text``); blanking it would cost the diagnostic for no
    gain in safety.
    """

    @vmware_tool(sensitive_result=True)
    def get_tkc_kubeconfig(name: str, target: str = "") -> dict:
        raise RuntimeError("cluster 'tkc-1' has no control plane endpoint yet")

    with pytest.raises(RuntimeError):
        get_tkc_kubeconfig(name="tkc-1")

    (row,) = _rows(audit_db)
    assert row["status"] == "error"
    assert "no control plane endpoint" in row["result"]


@pytest.mark.unit
def test_the_cli_surface_redacts_the_same_keys(audit_db):
    """Both surfaces write the same sink, so both must scrub it (HLD I-3/I-8).

    Fixing the family pattern in one of the two surfaces and leaving the other
    is CLAUDE.md 形态 #7 — the single most repeated defect in this project.
    """
    from vmware_policy.cli_guard import guarded

    @guarded(risk_level="low")
    def kubeconfig_get(name: str, target: str = "") -> dict:
        return {"cluster": name, "kubeconfig": KUBECONFIG}

    kubeconfig_get(name="tkc-1")

    (row,) = _rows(audit_db)
    assert TOKEN not in _whole_row_text(row)
    assert json.loads(row["result"])["kubeconfig"] == "[redacted: credential-shaped key]"


@pytest.mark.unit
def test_the_cli_surface_still_records_an_ordinary_result(audit_db):
    """Positive control for the CLI half."""
    from vmware_policy.cli_guard import guarded

    @guarded(risk_level="low")
    def namespace_list(target: str = "") -> dict:
        return {"items": ["ns-a"], "total": 1}

    namespace_list()

    (row,) = _rows(audit_db)
    assert json.loads(row["result"]) == {"items": ["ns-a"], "total": 1}


@pytest.mark.unit
def test_declaration_is_visible_on_the_wrapper(audit_db):
    """Harnesses introspect the other flags this way; this one is no different."""

    @vmware_tool(sensitive_result=True)
    def get_supervisor_kubeconfig(namespace: str) -> dict:
        return {"kubeconfig": KUBECONFIG}

    @vmware_tool
    def list_namespaces() -> dict:
        return {}

    assert get_supervisor_kubeconfig._sensitive_result is True
    assert list_namespaces._sensitive_result is False
