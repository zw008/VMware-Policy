## v1.11.0 — the policy engine stopped failing open

**Read this before upgrading: one behaviour changes visibly.** An operator whose
`rules.yaml` cannot be read moves from *everything allowed* to *everything
denied*. That is the correct direction and it is why this is a minor bump rather
than a patch.

On a Windows host with locale cp936, reading the UTF-8 `rules.yaml` raised a
decode error, the exception was swallowed, and the engine continued with no
rules — so a `freeze-production-writes` rule that should DENY came back ALLOW.
Reproduced end to end in a child interpreter with an ASCII default codec, on
bytes asserted to be valid UTF-8 and invalid GBK, not by mocking the codec.

Two independent defects, fixed separately. `encoding="utf-8"` on all three text
reads — the report named one, and GBK often mojibakes rather than raising, so a
mis-decoded `pattern_id` would arm the wrong pattern rather than none. And
"unreadable" and "the operator wrote no rules" were the same state; they are now
distinct, and the first denies.

Every operation is denied, not just writes: `get_supervisor_kubeconfig` is a
READ tool that returns a live Supervisor JWT, and freezing exactly that is a
plausible operator rule. The denial names the file and the exit;
`VMWARE_POLICY_DISABLED=1` is checked above the rules, so the escape hatch does
not depend on rules loading, and a corrected file re-arms on the next call.

**The secret-redaction pattern was catching 41.7% of what it claimed.** Measured
against 60 leak shapes drawn from real vSphere/NSX/AVI/Aria exception text: 25
redacted before, 60 after, with no over-redaction of 10 benign controls. Four
distinct causes, not one — a `\b` anchor that let `access_token=` through, a
separator that could not be `":"` so `{"token": "abc"}` never matched, `@`
excluded from the value class, and whole shapes with no rule at all.
`Authorization: Basic <base64>` masked the word `Basic` and left the credential.
The keyword list is now derived from `_CREDENTIAL_KEYS` rather than written a
second time.

Also: a test named `test_unreadable_user_file_fails_permissive_and_loud`
asserted the fail-open and passed. The suite had the wrong failure direction
written down as the contract. It is inverted and renamed.

## v1.10.0 — the audit row stopped filing the credentials it records

Two additions, both consumed by every skill in the family. **Release this
before any dependant that uses them, and raise that dependant's floor to
1.10.0 first** — a skill calling the new API against 1.9.0 dies at import.

**The audit database was storing tool return values verbatim.**
`get_supervisor_kubeconfig`'s own docstring says "do not log or share", and the
`@vmware_tool` decorator wrapping it was logging it: a live Supervisor JWT,
plaintext, in `~/.vmware/audit.db`. Reproduced by reading the row back out of
SQLite, not inferred. The audit log is also the artefact most likely to be
copied off the machine, attached to a ticket, or handed to a vendor, which is
what makes it worse than an ordinary log leak.

Redaction that existed covered arguments (`sensitive_params`) and exception
text, and nothing at all covered a return value. Now two layers, both in the
shared decorator rather than in each tool, because a per-tool marker is one some
tool will forget (形态 #7):

- `@vmware_tool(sensitive_result=True)` — the declaration; the result becomes
  exactly `"[redacted: return value declared sensitive]"`, not truncated and not
  hashed, because a partial token in a log is still a finding.
- a credential-key net that runs on **every** audited result, declared or not.
  Exact key match, case-insensitive with `-`/`_` folded — not substring, so
  `token_count` survives.

The record itself is untouched: who, when, with what arguments, and whether it
succeeded. The returned secret was never part of that, which is why dropping it
costs nothing.

**Parameter descriptions now reach the JSON schema.** Across the family, 327
tools and roughly a thousand parameters had 0% coverage of `description`,
`enum` and `additionalProperties` — while 949 of those parameters were already
described in a Google-style `Args:` block that no client ever sees. On a real
estate that produced a silent failure with no error at any stage: a parameter
name guessed wrong is discarded and the tool returns the full unfiltered result;
a value guessed wrong (`power_state="running"`) returns 0 rows where there were
11.

`describe_tool_parameters(mcp._tool_manager._tools)` copies what is already
written, so the docstring becomes load-bearing and the two cannot drift. It
removes the `Args:` block from the description once copied — both travel in
every `tools/list` response, and leaving it bills the same sentences twice
against each manifest's token budget.

## v1.9.0 — packaging metadata: the PyPI page now links back to the source

`vmware-policy` is a transitive dependency of every skill in the family, so its
PyPI page is where a security reviewer lands when they ask what the thing
auditing their vCenter operations actually is. That page carried no Homepage,
no Source, no Issues link — the only route back to the repository was whatever
the README body happened to say.

- `[project.urls]` now declares Homepage / Repository / Issues / Changelog
  against `github.com/vmware-skills/VMware-Policy`.
- `README-CN.md` carries the `mcp-name` marker that most of the family already
  had. Functionally inert (the registry reads the README PyPI renders), but it
  removes an inconsistency that reads as an oversight.
- Ships as a Claude Code plugin (`.claude-plugin/plugin.json`). Policy has no
  MCP server — it is the audit and policy library the other skills depend on —
  so the manifest correctly declares no server.

No behaviour change: no new API, no changed signature, nothing in
`@vmware_tool`, `audit`, `policy`, `budget`, `undo` or `paths` moves. Skills
pinning `vmware-policy>=1.8.5,<2.0` need no action.

## v1.8.9 — moved to vmware-skills org + MCP Registry namespace io.github.vmware-skills/vmware-policy

Repo transferred from github.com/zw008 to github.com/vmware-skills (redirects preserve old links).
MCP Registry server renamed to `io.github.vmware-skills/*`; the old `io.github.zw008/*` entry is deprecated.
All in-repo links updated. No functional code change on this line beyond the org move.

## v1.8.8 — add the `guarded` CLI decorator (the CLI counterpart to `@vmware_tool`)

`vmware_policy.guarded` wraps a CLI command so it routes through the same
`guard()` + `audit_call()` core the MCP surface uses (HLD §4.1; invariants
I-1/I-3/I-8): one authorization gate, one audit row to `~/.vmware/audit.db`, on
every surface. It is leaner than `@vmware_tool` (no budget/pattern/undo machinery)
and classifies a declined confirmation as `rejected` rather than an error. Both
surfaces bind `(tool, params, target)` through the same reflection helpers, so a
deny rule scopes the CLI and MCP identically.

The skills adopt it in their own 1.8.8 releases; this release makes the core
available.

## v1.8.7 (2026-07-21) — the skill-level read-only switch is removed; read/write authorization is the vCenter account's job (RBAC)

### Removed: `VMWARE_READ_ONLY` / `read_only:` — give the agent a read-only service account instead

The skill-level read-only switch is gone. It was enforced only on the MCP tool
registry, and any agent with a shell (every SKILL.md grants `allowed-tools: Bash`)
could reach the same change one CLI command away — so it withheld the *tool*, not
the *capability*. It was never a real boundary.

To run an agent read-only, give it a **read-only vCenter/NSX service account
(RBAC)**. Writes are then refused at the platform, un-bypassably, regardless of
surface or shell — the one place read/write control cannot be stepped around. A
config still carrying `read_only: true` is ignored, with a one-time warning that
names the replacement (no silent behavior change).

### Removed: approval tiers and the declared-environment gate (via vmware-policy)

The graduated-autonomy approval tiers (`confirm`/`dual`/`review`) and the "declare
an environment or be refused" baseline are removed — they only ever fired on the
rarest configuration while carrying the family's most complex machinery. Opt-in
`deny` rules and the maintenance window remain, and apply identically wherever a
tool runs.

### Added: offline / air-gapped install docs

The README now covers installing from source without editable mode (for older
`pip`) and building wheels to carry onto an air-gapped host — the modern PEP 517
layout has no `setup.py` by design, which is expected, not a missing file.

This release also carries the accumulated fixes staged since 1.8.5.

## v1.8.5 (2026-07-20) — a denial from inside a tool body is a denial

### Fixed — an orchestrating call audited as a success it never was

`_pre_check` sets the status before raising, so a policy denial of *this* call
has always been recorded correctly. A denial arriving from **inside** the body —
a nested `@vmware_tool` call that policy refused, propagating outward — reached
the `except (PolicyDenied, BudgetExceeded): raise` branch with the status left at
its `"ok"` default. The outer call then audited as a success, and an armed
pattern's circuit breaker was told the same.

This is the shape vmware-pilot produces: a workflow step denied mid-chain, with
the audit trail showing the orchestrating tool completing normally.

Both wrappers are fixed. The sync and async wrappers are written out separately
in this file, and a mutation deleting the guard from the async one alone survived
the first version of the test — so there are now async tests for each.

### Documented — where `_returned_failure`'s boundary is, and why it is not narrower

v1.8.4 taught the decorator to read a returned error payload as a failure. The
rule keys on a truthy `error` key alone, which is wider than it looks: a result
that merely *describes* some other object's failure reads as a failed call.

Requiring `hint` alongside `error` would fix that — 122 of the family's 130
caught-error payloads are exactly `{error, hint}`. It would also stop detecting
roughly 25 genuine failures that carry no hint (vmware-aiops' plan guards,
vmware-pilot's terminal-state refusals), which is the original bug in the
opposite direction. Under-detecting is the worse failure, so the rule stays.

The cost lands where the ambiguity actually is. `{"state": "error", "error": ...}`
cannot tell a *model* whether the call failed or the thing it polled did either,
so those payloads now name the field for what it is — `vm_task_status` returns
`task_error`. The reasoning is recorded in the function's docstring rather than
left for the next reader to rediscover.

### Note for skill authors

`report_tool_failure()` shipped in 1.8.4 with no callers. Every skill that
returns a string error payload now calls it; see those release notes.

## v1.8.4 (2026-07-20) — a failure that is returned is now audited as a failure

### Fixed — `@vmware_tool` recorded returned failures as successes

A skill reports a failure in one of two ways. It raises, which the decorator has
always recorded correctly. Or it catches the exception and **returns** an error
payload — what `tool_errors` does for ~41 tools in vmware-aiops, and what every
hand-written `except` block across the family does. To the wrapper, the second
kind looked exactly like a successful call.

One missing distinction, three consequences:

| | before | now |
|---|---|---|
| audit row | `status=ok` for an operation that failed | `status=error` |
| undo store | a token recorded for a change that never happened | nothing recorded |
| circuit breaker | told `success=True` | told `success=False` |

The audit one matters most: in a family whose stated purpose is a trustworthy
audit trail, the log was not merely incomplete, it was affirmatively wrong. The
undo one broke an invariant `_record_undo`'s own docstring states — *"a recorded
undo always corresponds to a change that actually happened"* — so vmware-pilot
could offer to reverse a write that never landed. And the breaker is the third
layer of the recovery model CLAUDE.md mandates; a tool that fails by returning
could never trip it, which is why that layer had effectively never fired.

**Dict-shaped payloads are detected without any change in the skills.**
`{"error": <truthy>}`, and a one-element list of the same, are the family's own
documented envelope, so recognising them is reading a convention rather than
guessing. A falsy `error` key is a result reporting that nothing went wrong; a
multi-element list is a batch that returned partial results. Both stay `ok`.

### Added — `report_tool_failure()` for payloads that cannot carry a marker

```python
from vmware_policy import report_tool_failure

except Exception as exc:
    report_tool_failure(str(exc))
    return f"Error: {msg}"
```

Strings are deliberately **not** sniffed. Skills that hand back console text
(vmware-avi, vmware-log-insight) can legitimately emit output beginning with
"Error:" as *data*, and marking those calls failed would be the same misreport in
the opposite direction. Those skills call this instead.

The signal is a context variable rebound per call, so an inner tool's failure
cannot mark its caller failed — skills delegate in-process (vmware-aiops runs
vmware-monitor's library), and an outer tool that catches and recovers is still a
successful call.

### Note for skill authors

Skills adopt `report_tool_failure` from this release onward; the dict detection
needs no skill change and applies immediately.

## v1.8.3 (2026-07-20) — credentials resolve as a pair; documented env vars now exist

### Changed — version alignment

No functional change in this skill. The family release adds an env-var override for the per-target username in the credential-bearing skills; this package has no per-target credentials.

### Changed — `family_smoke.sh` 89 → 90 checks

Added the credential-variable comparison above. Also corrected one check's label:
it claimed "All [READ] list tools return the paginated envelope" while only
testing for a declared `list[dict]` return type. A tool annotated `-> dict` that
returns `{"total": N, "rows": [...]}` was invisible to it — including
vmware-monitor's own `list_virtual_machines`, which has its own auto-compact
shape. Verifying the real invariant means inspecting the returned value, so the
check keeps its narrower scope under an accurate name rather than a broad claim
it never enforced.

## v1.8.2 (2026-07-20) — the MCP server moves into the package namespace

### Fixed — co-installing two skills broke all but the last one

Every skill shipped its MCP server as a **top-level `mcp_server` package**. Python
has one top-level namespace, so installing any two of them into one environment let
the second overwrite the first — silently, with no error and no warning.

    uv tool install vmware-aiops   ->  49 tools   (correct)
    uv pip  install vmware-aiops   ->  27 tools   (Monitor's read-only server)

vmware-aiops depends on vmware-monitor, so this was not an edge case: **every pip
install hit it**, and the operator got 27 read-only tools where 49 were expected,
with all 35 write tools missing. Docker images, shared MCP hosts and CI runners that
install more than one skill were affected the same way.

The server now lives at `vmware_<skill>/mcp_server/`, a name only this package can
claim. Introduced 2026-02-26; it survived 70 releases because every test ran against
a single package in its own repo, where the local directory shadows site-packages —
the conflict was invisible by construction.

**Migration.** Console scripts are unchanged: `vmware-<skill>` and
`vmware-<skill>-mcp` work exactly as before, as does `"command": "vmware-<skill>",
"args": ["mcp"]` in an MCP client config. Only a direct `python -m mcp_server`
breaks; use `python -m vmware_<skill>.mcp_server`.

### Added — `references/agent-guardrails.md` in every skill

The operating rules for local and small models (Llama 3.3 70B, Qwen, Mistral via
Goose / Ollama / OpenShift AI) existed in two skills. They now ship in all 13, each
with its own tool counts and failure modes, and are linked from every SKILL.md.

### Changed — `family_smoke.sh` 85 -> 89 checks

Four additions, each closing a blind spot this release exposed:

- **No two packages may claim the same top-level import name.** The invariant behind
  the bug above. It does not test behaviour — it tests structure, because the
  conflict only *exists* when two packages coexist and every test ran against one.
- **A tool named in an error message must exist** in the family registry.
- **Feature-surface coverage** — a family-wide feature must appear on every layer
  that teaches it (README, SKILL.md body, setup-guide, capabilities, doctor).
- **Progressive Disclosure limits** — SKILL.md bodies <=3000 words, descriptions
  <=1024 chars.

## v1.8.1 (2026-07-19) — read-only mode reaches the surfaces that teach it

v1.8.0 put read-only mode in the code and documented it in the README only.
Every other layer was empty, and each serves a different reader: SKILL.md is what
the agent loads, setup-guide is what an operator reads while configuring, `doctor`
is where they verify it took. The gap had two concrete costs.

An agent read SKILL.md, called a write tool the gate had withheld, and got nothing
back — with no way to learn that the absence was a deliberate lockdown rather than
a fault. It reads as a broken tool, so the model retries or hunts for a workaround.

An operator who set the switch had no way to confirm it. The only signal was a line
in the MCP server's start-up log.

### Added — `read_only_status()`

Resolves read-only mode *and* reports where the answer came from
(`ReadOnlyStatus(enabled, source, raw, recognised)`), so each skill's `doctor` can
show the state without re-implementing the precedence chain. Ten copies of "build
the env var name, walk the chain" is ten chances to drift from the gate that
enforces it. A test pins that its verdict matches `read_only_enabled` case by case.

### Added — the gate is documented in this package's own SKILL.md

vmware-policy implements `apply_read_only_gate()` and said nothing about it in the
layer skill authors and agents actually read. SKILL.md, setup-guide and
capabilities now cover the API, the six-level classification ladder, all three
`FORCE_WRITE` entries with their rationale, and the exact fail-closed semantics —
two conditions abort startup, the unparseable-value case does not.

### Changed — `family_smoke.sh` 85 → 87 checks

Two additions, both closing gaps this release exposed:

- **Feature-surface coverage.** A family-wide feature must appear on every surface
  that teaches it. Read-only mode is the first entry; add the next feature to the
  manifest when it lands. This check would have caught the v1.8.0 gap the day it
  shipped. It looks at the SKILL.md *body*, because a mention inside the metadata
  JSON is a declaration for scanners, not instruction an agent reads — counting it
  as coverage is precisely what hid the gap.
- **Progressive Disclosure limits.** SKILL.md bodies ≤3000 words, descriptions
  ≤1024 chars. Neither was enforced anywhere, and both were breached during v1.8.0
  — found by a reviewer reading files rather than by CI.

## v1.8.0 (2026-07-18) — read-only mode, policy baseline that actually loads, list envelope

Driven by [VMware-AIops#31](https://github.com/vmware-skills/VMware-AIops/issues/31), where an
operator running Llama 3.3 70B (Goose / OpenShift AI, on-prem H100) had to hand-write 17
prompt guardrails to make tool calling reliable. A prompt is advisory; a model can ignore
it. Every guardrail that could be moved into the harness has been.

### Added

- **Read-only mode** (`readonly.py`). `apply_read_only_gate(mcp, skill, config_flag)`
  removes every write tool from a FastMCP registry, so `list_tools()` never offers them
  and the model cannot call what it cannot see. Resolution order: per-skill env
  (`VMWARE_<SKILL>_READ_ONLY`) → family env (`VMWARE_READ_ONLY`) → config `read_only:` →
  off. **Off by default** — nothing changes unless an operator turns it on.
  - Classification prefers the `[READ]`/`[WRITE]` docstring marker over the
    `readOnlyHint` annotation: the marker covers 245/245 tools, while vmware-harden and
    vmware-debug register through a `build_server()` factory that passes no annotations.
  - `FORCE_WRITE` overrides tools whose marker under-reports their effect. Currently three,
    all the same shape — read-only upstream, write-effecting locally: `vm_guest_download`
    reads only from the guest, but writes an operator-supplied local path and takes guest
    credentials; `get_supervisor_kubeconfig` and `get_tkc_kubeconfig` materialise a
    session-token credential file at a model-supplied local path.
  - **Fail-closed throughout.** An unenumerable registry or a removal that does not
    take effect aborts startup with `ReadOnlyGateError` rather than running open. An
    unparseable switch value (`VMWARE_READ_ONLY=ture`) does not abort — it resolves to
    *on* with a warning, so a typo locks the deployment down instead of leaving it open.

- **List-result envelope** (`envelope.py`). `paginated(items, limit, total, **extra)`
  returns `{items, returned, limit, total, truncated, hint}` — always all six keys,
  unknown values as explicit `None`. Fixes the reported failure where long responses were
  summarised as "no data returned": a bare `list[dict]` cannot distinguish a complete
  answer from page one, so the model guessed. Not yet adopted by the skills.

- **Declared environments** (`environment.py`). Skills register
  `set_environment_resolver(fn)` mapping a target name to the `environment:` its config
  declares, so policy scopes by a real declaration instead of by the target's name.

### Fixed

- **Policy rules never loaded on a fresh install.** The engine read only
  `~/.vmware/rules.yaml`; `rules_default.yaml` shipped as a fully commented-out template
  no engine ever read. Every deny rule, maintenance window and approval tier was
  therefore inert for anyone who had not hand-authored a rules file — which is to say,
  the entire graduated-autonomy engine added in v1.6.0 had never once run. A missing user
  file now falls back to the packaged baseline. A user file that exists but fails to
  parse does NOT fall back (applying rules the operator never wrote while theirs are
  broken is the wrong surprise); `active_rules_source()` and `vmware-audit policy` report
  which case you are in.

- **Glob patterns with a leading wildcard silently matched nothing.**
  `_pattern_match` honoured only a trailing `*`; everything else fell through to string
  equality. A rule written `operations: ["*_delete"]` parsed fine, read correctly, and
  never fired. Now delegates to `fnmatch.fnmatchcase`, so `*_delete` and `vm_*_snapshot`
  work. Environment patterns match by glob too, for the same reason.

- **Pre-release review** (same day, before publish): warn-mode no longer bypasses deny
  rules / maintenance windows; env-scoped deny rules no longer match undeclared targets
  and now glob like tier rules; quoted `'false'` switch values parse correctly; unknown
  risk levels and blank env-var values no longer crash or fail open; pattern-engine rate
  limits stay keyed per target; VKS kubeconfig tools force-classified as writes.

### Changed — migration, read this

- **Approval tiers now ship active.** Writes at medium risk and above are stamped with a
  `confirm` tier in the audit row (informational, never blocks). Irreversible operations
  and guest execution against a target declaring `production`/`prod` require a named
  approver via `VMWARE_AUDIT_APPROVED_BY` — a two-person rule that, until now, existed in
  code but could not fire.

- **`require_declared_environment: warn`** — the first half of a two-step migration.
  A state-changing operation against a target that declares no `environment:` still runs,
  but logs a warning naming the fix. **The next major release ships `true` and refuses
  it.** Declare `environment:` on your targets now and that upgrade is a no-op:

      targets:
        prod-vc01:
          host: vc01.corp.local
          environment: production

  Read-only operations are never affected, in either release. Preview what applies to a
  target with `vmware-audit policy --operation vm_delete --env <env>`. Opt out entirely
  with `require_declared_environment: false` or your own `rules.yaml`.

- **Rules written against the old `environments:` semantics go quiet.** Before 1.8.0,
  `environments:` was matched against the *target name*; a rule written
  `environments: ["prod-vc01"]` stops firing once that target declares
  `environment: production`. Rewrite such rules against declared environment names.

- **The missing-file kill-switch changed.** Pre-1.8.0, deleting `~/.vmware/rules.yaml`
  disabled all policy ("allow all"); now it falls back to the packaged baseline. The
  explicit off-switches are `require_declared_environment: false` in your own
  `rules.yaml`, or an empty `rules.yaml` (`risk_tiers: []`), or
  `VMWARE_POLICY_DISABLED=1` for a true emergency bypass.

### Notes

- Skills requiring these APIs must depend on `vmware-policy>=1.8.0`. Publish this package
  to PyPI **before** the skills that import from it.
- Version jumps 1.6.1 → 1.8.0 to rejoin the family line; the intervening releases were
  skipped under the "no empty version bumps" exception, which no longer applies.

### Fixed — pre-release review (2026-07-19)

- **A typo in `min_risk_level` crashed every tool call in the family.** `_risk_index`
  guarded the risk level declared in code, but the level an operator hand-writes in
  `rules.yaml` still reached a raw `RISK_LEVELS.index()`. `min_risk_level: mediun` — or
  simply `MEDIUM` — raised `ValueError` out of `check_allowed` on every call in all 12
  skills, naming neither the rule nor the file, and the audit row blamed the tool. This
  is the first release in which rules actually load, so it is the first release in which
  anyone writes that file. Values are now case- and whitespace-insensitive; an
  unrecognised one widens the rule (deny more, require a higher tier) with a warning,
  rather than narrowing it to the point of never firing.
- **`vmware-audit policy` reported ENFORCED for a switch that was off.** The command
  branched on truthiness while the engine parses three values, so the quoted string
  `'false'` printed "ENFORCED" directly above an "allowed" verdict for the same call. It
  now branches on `_parse_requirement` and prints an explicit OFF, which is
  distinguishable from the key being absent.

## v1.6.1 (2026-06-24) — version alignment

No functional changes — version bumped to stay aligned with the VMware skill family release.

## v1.6.0 (unreleased) — trust architecture (token budget, accountability, risk tiers, undo)

Substantial, backward-compatible harness upgrades from the 2026-06-22 strategy review
(BACKLOG.md P0, direction A). All additive — existing skills keep working unchanged
until they opt into the new features. **Affects the whole family on next install.**

### Added
- **Token/call hard budget + runaway breaker** (`budget.py`). Per-process ceilings via
  `VMWARE_MAX_TOOL_CALLS` / `VMWARE_MAX_TOOL_SECONDS` (opt-in), plus an on-by-default
  guard that trips when the same `(tool, params)` is hammered in a short window
  (`VMWARE_RUNAWAY_MAX`=25 / `VMWARE_RUNAWAY_WINDOW_SEC`=120). Raises `BudgetExceeded`
  (a hard stop) — the structural fix for the "delete one snapshot, burn 26k tokens"
  unbounded-call failure mode. Enforced from `@vmware_tool`.
- **Audit accountability fields** (`audit.py`): `rationale`, `approved_by`, `risk_tier`
  columns, with in-place ALTER migration for existing audit.db files. The decorator
  sources rationale/approver from `VMWARE_AUDIT_RATIONALE` / `VMWARE_AUDIT_APPROVED_BY`.
- **Graduated-autonomy risk tiers** (`policy.py` `required_approval_tier`): rules.yaml
  `risk_tiers` map environment / resource tag / min-risk → tier (none/confirm/dual/review);
  dual/review tiers are denied without a recorded approver.
- **Undo-token primitive** (`undo.py`): `@vmware_tool(undo=...)` records a write's inverse
  descriptor to `~/.vmware/undo.db` and tags the result with `_undo_id`. CLI
  `vmware-audit undo-list` / `undo-show`. Recording only — execution stays in vmware-pilot.
- **Relocatable state dir** (`paths.py` `ops_home()`): `OPS_HOME` relocates harness state
  (default `~/.vmware`, fully back-compat); budget env vars accept an `OPS_*` alias.

### Notes
- `_bind_params` now applies declared defaults so env scoping + risk-tier matching see the
  effective target/tags even when a caller relied on a default value.
- 120 tests pass; bandit 0 Medium+. Version/publish coordination with the family is a
  release-time decision (candidate: family-wide v1.6.0).

## v1.5.37 (2026-06-12) — backlog: stop advertising an unimplemented feature

### Changed
- "limits" removed from the `@vmware_tool` feature list / docs — `change_limits` was a documented no-op;
  it's now clearly marked reserved/not-enforced (still logs a warning) rather than implying enforcement. (#2)

## v1.5.36 (2026-06-12) — shared-decorator correctness (affects the whole family)

### Fixed
- **`@vmware_tool` now supports async tools** — an `async def` tool was previously audited as "ok"
  with an un-awaited coroutine as its result.
- **Positional arguments are now audited and policy-scoped** — only `kwargs` were captured before, so
  a positionally-passed `target` vanished from the audit log and bypassed environment deny-rules.
- **Malformed maintenance window now fails closed** (deny + teaching error) instead of allowing
  high-risk operations 24/7.
- **Audit-log rotation checkpoints the WAL before renaming** — un-checkpointed frames could be lost.
- **Pattern matcher prefers an armable match** instead of letting an expired/unsigned pattern shadow it.
- `timeout_seconds` now logs a warning when exceeded (documented as advisory); `sanitize()` strips
  control characters before truncating and returns "" for None.

### Added
- `reset_engine()` / `reset_policy_engine()`, lock-guarded singletons, and a path-mismatch warning.

## v1.5.35 (2026-06-10) — security hardening: stop leaking credentials in logs & audit (affects all skills)

Shared dependency — these fixes protect every skill in the family.

### Fixed
- **Bypass-mode logging** no longer prints parameter *values* (which could carry
  passwords/tokens). When `VMWARE_POLICY_DISABLED=1`, only parameter *names* are logged.
- **Policy check** now receives the already-redacted `safe_params`, not the raw `kwargs`.
- **`_redact()`** recurses into lists/tuples, so secrets nested in collections
  (e.g. `{"targets": [{"password": "..."}]}`) are masked in audit records.
- **Exception text and tracebacks** are sanitized and secret-pattern–redacted
  (`password=…`, `token: …`) before being written to the audit DB.
- **Audit storage** directory is created 0700 and the DB (incl. WAL/SHM) 0600.

This release aligns the whole family back to a single version (1.5.35); vmware-policy and vmware-pilot return to the shared number after sitting at 1.5.22.

## v1.5.22 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **align:** Tracks v1.5.22 family bump driven by Smithery onboarding for vmware-avi / vmware-harden / vmware-pilot.

## v1.5.21 (2026-05-08)

**Family alignment** — no source changes in this library. Skipped v1.5.20 family bump; this is the catch-up release.

- **chore:** Untracked `.venv/` from the repository (was committed by mistake; `.gitignore` already excludes it). Removed 1832 files from version control with no functional change.
- **align:** Tracks family v1.5.20 + v1.5.21 alignment.

## v1.5.19 (2026-05-06)

**Security + concurrency fixes** in pattern engine.

- **fix(patterns):** Approval gate now requires BOTH `signed_by` AND `approval.status == "approved"`. The previous AND-style condition (`if not signed_by AND status != "approved"`) let signed-but-rejected patterns retain their original risk classification, which was the opposite of intended behavior (yjs review 2026-05-06; CLAUDE.md 踩坑 #30).
- **fix(patterns):** `get_pattern_engine` singleton initialization now uses `threading.Lock` with double-checked locking to prevent multiple PatternEngine instances under concurrent first-access in multi-threaded callers.
- **smoke:** Family `scripts/family_smoke.sh` now recursively walks every Typer subcommand to trigger lazy imports.
- **align:** Family version bump to v1.5.19.

## v1.5.18 (2026-05-02)

**Bug fix from external code review (2026-05-02 by Hermes Agent / MiniMax-M2.7)**

- **fix:** `patterns.py` — pattern YAML now accepts the canonical rate-limit keys `max_per_hour` / `max_per_day` alongside the legacy `max_per_hour_per_host` / `max_per_day_per_cluster`. The dataclass field is `rate_max_per_hour_per_target` (target-agnostic), and the new keys remove the host/cluster naming mismatch flagged in review. Old keys still work — zero breakage for existing pattern files.
- **dev:** `[dependency-groups]` block aligned with the rest of the family — `pytest`, `pytest-cov`, `ruff` all available via `uv sync --group dev`.
- **align:** Family version bump to v1.5.18.

Tests: 16/16 pattern engine pass.

## v1.5.17 (2026-05-01)

**L5 auto-remediation pattern matcher integrated into `@vmware_tool`** — the v1.5.16 PoC scaffolding (design doc + extractor) now has a runtime engine.

- **feat:** New module `vmware_policy/patterns.py` — `PatternEngine` singleton. Loads signed YAML patterns from `~/.vmware/auto-remediation-patterns/*.yaml` with hot-reload on mtime. Validates schema, action signatures, and approval state.
- **feat:** `@vmware_tool` decorator integration — matched + armed calls have `_pattern_id` and `_pattern_armed` annotated on the result dict and the audit row. Outcome reporting in the `finally` block updates circuit-breaker state.
- **feat:** Per-`(pattern_id, target)` rate limiting — sliding hourly + daily windows. Per-target circuit breaker — configurable threshold (default 3 consecutive failures) and cooldown (default 24h).
- **safety:** Patterns must be signed (`approval.signed_by` non-empty + `status=approved`) AND classified `risk: low + reversible: true + repeatable: true` to be armable. Unsigned and high-risk patterns load for inspection but never arm. Failure modes are fail-open: load/match errors never block tool calls.
- **docs:** `docs/auto-remediation-patterns.md` now reflects the shipped surface and the deferred items (trigger-against-historical-audit, auto-execution daemon, post-action validation, persistent state across restarts).
- **align:** Family version bump to v1.5.17.

Tests: 34 → 52 passing (16 pattern engine + 2 decorator integration).

## v1.5.16 (2026-04-30)

**Enterprise Harness Engineering alignment** — adapted from the Linkloud × addxai framework articles ([part 1](https://mp.weixin.qq.com/s/hz4W7ILHJ1yz_pG0Z1xP-A), [part 2](https://mp.weixin.qq.com/s/F3qYbyB3S8oIqx-Y4BrWNQ)).

- **feat (PoC):** New `docs/auto-remediation-patterns.md` design doc — schema, lifecycle, and three hard conditions (risk:low + reversible + repeatable) for the L5 automation level from the EHE framework.
- **feat (PoC):** New `scripts/extract_patterns.py` — scans `~/.vmware/audit.db` for candidate L5 patterns, applies thresholds (≥5 successes, 0 failures, ≥2 distinct operators, low-risk only, denylist), prints YAML stubs for human authoring.
- **align:** Family version bump 1.5.14 → 1.5.16 (skipping 1.5.15 to align with the rest of the family).

## v1.5.14 (2026-04-21)

**Bug fixes from code review by @yjs-2026 (follow-up)**

- **fix:** `audit.py` — `query()` and `stats()` SQLite connections now wrapped in try/finally to prevent leaks on exception
- **fix:** `audit.py` — archive filename now uses `datetime.now(tz=timezone.utc)` consistent with audit record timestamps

## v1.5.13 (2026-04-21)

**Bug fixes from code review 2026-04-20**

- **fix(P0):** `audit.py` — `stats(days=N)` now correctly computes date range using `timedelta(days=days)` instead of ignoring the `days` parameter entirely
- **fix:** `policy.py` — `_check_limits()` now logs a warning when `change_limits` are configured but not enforced, instead of silently doing nothing
- **fix:** `policy.py` — `_in_maintenance_window()` now uses `datetime.now(tz=timezone.utc)` instead of naive `datetime.now()` for correct timezone handling
- **fix(security):** `decorators.py` — `_redact()` now recurses into nested dicts to redact sensitive values at any depth

# VMware Policy — Release Notes

## v1.5.12 (2026-04-17)

**Security & bug fixes from code review by @yjs-2026**

- **fix(security):** `_rule_matches` empty `operations: []` bypass — deny rules with empty operations list matched ALL operations instead of none, causing whitelist leak
- **fix(security):** `sanitize()` now strips Unicode Format characters (Cf category: zero-width spaces, bidi overrides) — closes prompt injection vector
- **fix:** `_maybe_reload` clears stale rules and logs warning when policy file is deleted, instead of silently using outdated rules
- **fix:** `_maybe_reload` logs exceptions instead of silently swallowing them (`except Exception: pass`)
- **fix:** `VMWARE_POLICY_DISABLED=1` bypass now logs full operation context (operation, env, risk_level, params) for audit trail

## v1.5.11 (2026-04-17)

- Align with VMware skill family v1.5.11 (AVI 22.x fixes from @timwangbc)

## v1.5.10 (2026-04-16)

- Align with VMware skill family v1.5.10

## v1.5.8 (2026-04-15)

- Align with VMware skill family v1.5.8 (NSX/AVI/Aria/AIops bug fixes)

## v1.5.7 (2026-04-15)

- Align with VMware skill family v1.5.7 (Pilot `__from_step_N__` fix + VKS SSL/timeout fix)

## v1.5.6 (2026-04-15)

- Align with VMware skill family v1.5.6

## v1.5.5 (2026-04-15)

- Align with VMware skill family v1.5.5

## v1.5.4 (2026-04-14)

- Security: bump pytest 9.0.2→9.0.3 (CVE-2025-71176, insecure tmpdir handling)
- Align version with VMware skill family v1.5.4

## v1.5.0 (2026-04-12)

### Anthropic Best Practices Integration

- **[READ]/[WRITE] tool prefixes**: All MCP tool descriptions now start with [READ] or [WRITE] to clearly indicate operation type
- **Read/write split counts**: SKILL.md MCP Tools section header shows exact read vs write tool counts
- **Negative routing**: Description frontmatter includes "Do NOT use when..." clause to prevent misrouting
- **Broadcom author attestation**: README.md, README-CN.md, and pyproject.toml include VMware by Broadcom author identity (wei-wz.zhou@broadcom.com) to resolve Snyk E005 brand warnings

### Policy-specific

- **Security fix**: Removed unused VMWARE_POLICY_CONFIG from metadata
- **Agent detection transparency**: Added documentation explaining which env vars are inspected for audit logging and why

## v1.4.5 — 2026-04-03

- **Security**: bump pygments 2.19.2 → 2.20.0 (fix ReDoS CVE in GUID matching regex)
- **Infrastructure**: add uv.lock for reproducible builds and Dependabot security tracking

## v1.4.0 — 2026-03-29

Initial release. Unified audit, policy enforcement, and sanitization for the VMware MCP skill family.

- `@vmware_tool` decorator: mandatory wrapper for all 162 MCP tools across 8 skills
- `AuditEngine`: SQLite WAL at ~/.vmware/audit.db, framework-agnostic (Claude/Codex/local)
- `PolicyEngine`: rules.yaml with hot-reload, deny rules, maintenance windows, risk-level gating
- `sanitize()`: consolidated from 22 duplicate implementations across 7 skills
- `vmware-audit` CLI: log/export/stats commands for querying audit trail
- Agent detection: auto-identify calling AI agent from environment variables
- Log rotation: 100MB threshold, keep 5 archives
- 34 unit tests, 70%+ coverage