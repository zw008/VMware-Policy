"""The policy engine must not be disarmed by the machine's text encoding.

Reported from a VCF 9.1 re-test on Windows Server 2025 with locale cp936 (GBK):
a ``rules.yaml`` written in UTF-8 — the encoding every editor in that family's
docs produces, and the one the 等保 2.0 examples are written in — could not be
decoded by ``open()``'s locale default. The ``UnicodeDecodeError`` was swallowed,
the engine continued with an empty rule set, and a ``freeze-production-writes``
rule that should DENY returned ALLOW.

Two independent defects, tested separately here so neither can be "fixed" by
the other:

1. **Encoding.** ``open()`` with no ``encoding=`` decodes with the locale's
   codec. Reading a UTF-8 file on a non-UTF-8 machine either raises (cp936
   cannot decode most UTF-8 lead/trail pairs) or, worse, silently mojibakes.
   Every text read in this package must declare ``encoding="utf-8"``.

2. **Failure direction.** A policy engine that cannot load its rules must fail
   CLOSED. "Rules unreadable" and "no rules written" were the same state — an
   empty ``self._rules`` — so the first was indistinguishable from the second,
   which legitimately allows everything.

Reproducing the locale honestly
-------------------------------
cp936 does not exist on macOS/Linux, so this does not try to install it. What it
reproduces is the *mechanism*: a child interpreter whose ``open()`` default is a
non-UTF-8 codec, reading the real file through the real loader. ``LC_ALL=C`` with
UTF-8 mode and locale coercion switched off gives ``US-ASCII``, and a UTF-8 file
with Chinese in it then raises ``UnicodeDecodeError`` from exactly the line the
tester hit.

The fixture is additionally asserted to be *invalid GBK*, so the bytes under test
are bytes that genuinely fail on the reporter's machine and not merely
"non-ASCII" — and the child asserts its own default codec is not UTF-8 before it
does anything, so this file can never pass by never entering the decode path
(CLAUDE.md 形态 #3, and 形态 #1: a check that stops checking must go red, not
green).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# A deny rule an operator on a GBK machine would plausibly write. Its UTF-8
# bytes are invalid GBK — asserted below, not assumed.
CHINESE_RULES = (
    "deny:\n"
    "  - name: freeze-production-writes\n"
    '    operations: ["vm_*", "*_delete"]\n'
    '    environments: ["production"]\n'
    "    reason: 生产环境禁止写操作 — 等保 2.0 变更冻结期\n"
)

ASCII_RULES = (
    "deny:\n"
    "  - name: freeze-production-writes\n"
    '    operations: ["vm_*", "*_delete"]\n'
    '    environments: ["production"]\n'
    "    reason: production change freeze\n"
)

# Runs inside the non-UTF-8 child. Refuses to report anything unless the child's
# default codec really is not UTF-8.
_CHILD = textwrap.dedent(
    """
    import json, locale, sys
    enc = locale.getencoding()
    if enc.lower().replace("-", "") in ("utf8",):
        print("CHILD-LOCALE-NOT-APPLIED:" + enc, file=sys.stderr)
        raise SystemExit(99)
    from vmware_policy.policy import PolicyEngine
    eng = PolicyEngine(rules_path=sys.argv[1])
    r = eng.check_allowed("vm_delete", env="production", risk_level="critical")
    print(json.dumps({
        "encoding": enc,
        "source": eng.active_rules_source(),
        "allowed": r.allowed,
        "rule": r.rule,
        "reason": r.reason,
    }))
    """
)


def _run_under_ascii_locale(rules_path: Path) -> dict:
    """Load ``rules_path`` in a child whose ``open()`` default is not UTF-8."""
    env = dict(os.environ)
    env.pop("LANG", None)
    env.pop("LC_CTYPE", None)
    env.update(
        LC_ALL="C",
        PYTHONUTF8="0",
        PYTHONCOERCECLOCALE="0",
        PYTHONDONTWRITEBYTECODE="1",
    )
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, str(rules_path)],
        capture_output=True,
        text=True, encoding="utf-8",
        env=env,
        cwd=str(Path(__file__).resolve().parents[3]),
    )
    if proc.returncode == 99:
        pytest.fail(
            "this interpreter would not give the child a non-UTF-8 default codec, "
            "so the decode path was never entered: " + proc.stderr.strip()
        )
    assert proc.returncode == 0, f"child failed:\n{proc.stdout}\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ── fixture control: these bytes really do fail on a GBK machine ──────


def test_fixture_bytes_are_valid_utf8_and_invalid_gbk():
    """Positive control on the corpus itself.

    If someone later "simplifies" CHINESE_RULES to ASCII, the locale tests below
    would still pass while testing nothing. This asserts the fixture keeps the
    property that makes it a reproduction: decodable as UTF-8, undecodable as
    GBK — the reporter's codec.
    """
    raw = CHINESE_RULES.encode("utf-8")
    assert raw.decode("utf-8") == CHINESE_RULES
    with pytest.raises(UnicodeDecodeError):
        raw.decode("gbk")


# ── finding 1a: the encoding ──────────────────────────────────────────


def test_utf8_rules_load_on_a_non_utf8_machine(tmp_path):
    """The reported failure, end to end.

    Before the fix the child's ``open()`` raised UnicodeDecodeError, the engine
    swallowed it, and ``vm_delete`` in production came back ALLOWED against a
    rules file that denies it.
    """
    p = tmp_path / "rules.yaml"
    p.write_bytes(CHINESE_RULES.encode("utf-8"))

    out = _run_under_ascii_locale(p)

    assert out["source"] == "user", (
        f"UTF-8 rules.yaml did not load under {out['encoding']}: source={out['source']!r}"
    )
    assert out["allowed"] is False, (
        "freeze-production-writes flipped to ALLOW because the rules file could "
        f"not be decoded under {out['encoding']}"
    )
    assert out["rule"] == "freeze-production-writes"


def test_ascii_rules_still_enforce_on_a_non_utf8_machine(tmp_path):
    """Control for the harness: an ASCII rules file, same child, same locale.

    This passes both before and after the fix. It is here so a red result above
    is attributable to the decode path and not to the subprocess plumbing.
    """
    p = tmp_path / "rules.yaml"
    p.write_bytes(ASCII_RULES.encode("ascii"))

    out = _run_under_ascii_locale(p)

    assert out["source"] == "user"
    assert out["allowed"] is False


def test_utf8_rules_load_and_enforce_on_a_utf8_machine(tmp_path):
    """Control: the same Chinese rules file in-process, on this UTF-8 host.

    A fix that fails closed on everything would pass every leak test in this
    file; this is the assertion it cannot pass.
    """
    from vmware_policy.policy import PolicyEngine

    p = tmp_path / "rules.yaml"
    p.write_bytes(CHINESE_RULES.encode("utf-8"))
    eng = PolicyEngine(rules_path=p)

    assert eng.active_rules_source() == "user"
    denied = eng.check_allowed("vm_delete", env="production", risk_level="critical")
    assert denied.allowed is False
    assert "等保" in denied.reason, "the rule's Chinese reason must survive the round trip"
    assert eng.check_allowed("list_vms", env="lab", risk_level="low").allowed


# ── finding 1b: the failure direction ─────────────────────────────────


def test_unreadable_rules_file_fails_closed(tmp_path):
    """A rules file that exists and will not parse denies every operation.

    The engine cannot know what the operator wrote in it. It cannot therefore
    know which subset of operations was gated, and "allow everything" is the one
    answer that is wrong in the direction that matters.
    """
    from vmware_policy.policy import PolicyEngine

    p = tmp_path / "rules.yaml"
    p.write_text("deny: [ unclosed\n", encoding="utf-8")
    eng = PolicyEngine(rules_path=p)

    for op, risk in (("vm_delete", "critical"), ("list_vms", "low")):
        r = eng.check_allowed(op, risk_level=risk)
        assert r.allowed is False, f"{op} was allowed while rules were unreadable"
        assert str(p) in r.reason, "the denial must name the file the operator has to fix"
        assert "VMWARE_POLICY_DISABLED" in r.reason, (
            "the denial must state the documented way out, or an operator who "
            "typos their YAML is locked out with no instructions"
        )
        assert "\n" not in r.reason, (
            "PolicyResult.reason is surfaced as one message by every caller; a "
            "raw yaml.ParserError is five lines with the file quoted twice"
        )


def test_undecodable_rules_file_fails_closed_and_says_so(tmp_path):
    """The GBK case as a load error: a rules file this process cannot decode.

    Mirror image of the reported bug — there the file was UTF-8 and the reader
    was GBK; here the file is GBK and the reader is UTF-8. Either way the engine
    holds no rules, and either way it must deny rather than continue.
    """
    from vmware_policy.policy import PolicyEngine

    p = tmp_path / "rules.yaml"
    p.write_bytes(CHINESE_RULES.encode("gbk"))
    eng = PolicyEngine(rules_path=p)

    r = eng.check_allowed("vm_delete", env="production", risk_level="critical")
    assert r.allowed is False
    # Not just the token "utf-8": a raw UnicodeDecodeError message contains that
    # too ("'utf-8' codec can't decode byte ..."), so asserting on it alone would
    # pass with no teaching text at all — a check promising more than it verifies
    # (CLAUDE.md 形态 #4). Demand the instruction.
    assert "re-save" in r.reason.lower(), (
        f"a decode failure must tell the operator how to fix it; got: {r.reason!r}"
    )
    assert "utf-8" in r.reason.lower(), r.reason


def test_unreadable_rules_source_is_not_mistakable_for_a_loaded_engine(tmp_path):
    """``active_rules_source()`` must report the broken state distinctly."""
    from vmware_policy.policy import PolicyEngine

    p = tmp_path / "rules.yaml"
    p.write_text("deny: [ unclosed\n", encoding="utf-8")
    eng = PolicyEngine(rules_path=p)

    source = eng.active_rules_source()
    assert source not in ("user", "packaged-default")
    assert "unreadable" in source


def test_fixing_the_file_rearms_the_engine(tmp_path):
    """Fail-closed must be recoverable without a restart.

    A gate that cannot be reopened by fixing the cause is an outage, not a gate.
    """
    from vmware_policy.policy import PolicyEngine

    p = tmp_path / "rules.yaml"
    p.write_text("deny: [ unclosed\n", encoding="utf-8")
    eng = PolicyEngine(rules_path=p)
    assert eng.check_allowed("list_vms", risk_level="low").allowed is False

    # mtime granularity: make the change unambiguous.
    p.write_text(ASCII_RULES, encoding="utf-8")
    os.utime(p, (0, 0))

    assert eng.active_rules_source() == "user"
    assert eng.check_allowed("list_vms", env="lab", risk_level="low").allowed
    assert eng.check_allowed("vm_delete", env="production", risk_level="high").allowed is False


# ── controls: the states that legitimately allow must keep allowing ───


def test_empty_rules_file_still_allows_everything(tmp_path):
    """An operator who writes an empty rules.yaml means "no rules", not "deny".

    This is the control that separates "cannot load" from "loaded, and it is
    empty". Conflating them is what made the bug invisible.
    """
    from vmware_policy.policy import PolicyEngine

    p = tmp_path / "rules.yaml"
    p.write_text("", encoding="utf-8")
    eng = PolicyEngine(rules_path=p)

    assert eng.active_rules_source() == "user"
    assert eng.check_allowed("vm_delete", env="production", risk_level="critical").allowed


def test_no_rules_file_still_falls_back_to_the_packaged_baseline(tmp_path):
    from vmware_policy.policy import PolicyEngine

    eng = PolicyEngine(rules_path=tmp_path / "absent.yaml")
    assert eng.active_rules_source() == "packaged-default"
    assert eng.check_allowed("vm_delete", env="production", risk_level="critical").allowed


def test_policy_disabled_still_bypasses_a_broken_rules_file(tmp_path, monkeypatch):
    """The documented escape hatch has to survive fail-closed, or an operator
    with a typo'd YAML on a production bridge call has no way back."""
    from vmware_policy.policy import PolicyEngine

    p = tmp_path / "rules.yaml"
    p.write_text("deny: [ unclosed\n", encoding="utf-8")
    eng = PolicyEngine(rules_path=p)
    monkeypatch.setenv("VMWARE_POLICY_DISABLED", "1")

    r = eng.check_allowed("vm_delete", env="production", risk_level="critical")
    assert r.allowed is True
    assert r.rule == "policy_disabled"


# ── the mechanical link: no undeclared-encoding reads in the package ──


def test_every_text_read_in_the_package_declares_utf8():
    """Sweep, not spot-fix.

    The reported line was ``policy.py:142``. Two more reads had the same defect.
    A grep-free future depends on this staying mechanical rather than on someone
    remembering (CLAUDE.md 形态 #6).
    """
    import ast

    pkg = Path(__file__).resolve().parents[3] / "vmware_policy"
    sources = sorted(pkg.rglob("*.py"))
    assert sources, f"no sources found under {pkg}"

    offenders: list[str] = []
    for src in sources:
        tree = ast.parse(src.read_text(encoding="utf-8"), filename=str(src))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else ""
            )
            if name not in ("open", "read_text", "write_text"):
                continue
            mode = ""
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if name == "open" and len(node.args) >= 2:
                arg = node.args[1]
                if isinstance(arg, ast.Constant):
                    mode = str(arg.value)
            if "b" in mode:
                continue  # binary read, no codec involved
            if not any(kw.arg == "encoding" for kw in node.keywords):
                offenders.append(f"{src.relative_to(pkg.parent)}:{node.lineno} {name}()")

    assert not offenders, (
        "text I/O without encoding='utf-8' decodes with the machine's locale "
        "codec and breaks on cp936/Shift-JIS/latin-1 hosts:\n  "
        + "\n  ".join(offenders)
    )
