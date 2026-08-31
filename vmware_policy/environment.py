"""Resolve a target name to the environment its config declares.

Policy rules scope by environment ("destructive work in production needs two
people"). The engine used to receive the *target's name* for that — so the rule
only fired when an operator happened to name their target the exact string in
the rule. Real target names are ``prod-vc01`` and ``vcenter-lab``, never the
literal word ``production``, so environment-scoped rules were configured and
inert.

Environment is now an explicit declaration in each skill's config::

    targets:
      prod-vc01:
        host: vc01.corp.local
        environment: production

vmware-policy cannot read those files itself — every skill has its own config
schema and loader — so each skill registers a lookup at server start:

    from vmware_policy import set_environment_resolver
    set_environment_resolver(lambda target: _config().environment_for(target))

An unregistered resolver, an unknown target, a blank declaration, and a
resolver that raises all produce the same answer: ``""`` (unlabeled). An
unlabeled target simply does not match any environment-scoped ``deny`` rule — it
is **never refused** for lack of a label (HLD §6, D-3). Environment is an
optional convenience for writing env-scoped rules, not a mandatory declaration;
the v1.8 "a future release will refuse undeclared targets" plan was cut in v1.8.7.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Optional

_log = logging.getLogger("vmware_policy.environment")

#: Maps a target name to its declared environment, or None when it has none.
EnvironmentResolver = Callable[[str], Optional[str]]

_resolver: Optional[EnvironmentResolver] = None

#: Per-skill resolvers, keyed by the skill name ``guard()`` is called with.
#: The unkeyed ``_resolver`` above is the pre-1.12 slot, kept so a skill built
#: against an older vmware-policy still resolves its own targets.
_resolvers: dict[str, EnvironmentResolver] = {}

_lock = threading.Lock()

#: Emitted once per target so a misconfigured estate does not flood the log.
_warned: set[str] = set()


def set_environment_resolver(
    resolver: Optional[EnvironmentResolver], *, skill: Optional[str] = None
) -> None:
    """Register (or clear, with ``None``) the target → environment lookup.

    Pass ``skill`` — the same name the skill gives :func:`guard` — so the lookup
    is stored under that key. Without it the resolver lands in one
    process-global slot, and that slot is a real hazard rather than a
    theoretical one: on 2026-08-30 importing a sibling's server module was
    measured turning a ``freeze-production-writes`` rule from DENY to ALLOW,
    because twelve skills registered into the same slot at import time and the
    last one won for all of them. One of the twelve answers a deliberate
    constant (``vmware-harden`` only ever writes its own local store), which is
    true of its own tools and false of everybody else's targets.

    Keying does not make registering at import time wrong any more — a skill's
    resolver now only ever answers for that skill.

    The unkeyed form still works and still warns on replacement, so a skill
    built against an older release keeps behaving exactly as it did.
    """
    global _resolver  # noqa: PLW0603
    with _lock:
        if skill:
            _resolvers[skill] = resolver  # type: ignore[assignment]
            if resolver is None:
                _resolvers.pop(skill, None)
            _warned.clear()
            return
        if resolver is not None and _resolver is not None and resolver is not _resolver:
            # Two skills' servers imported into one process, both built before
            # keyed registration existed: the second registration takes over
            # environment resolution for both, so the first skill's targets
            # resolve against the wrong config and its environment-scoped rules
            # quietly stop applying.
            _log.warning(
                "Environment resolver replaced (%s -> %s) in the unkeyed slot. "
                "Environment resolution without a `skill=` key is "
                "process-global: if two skills are loaded in one process, the "
                "last registration wins for both, and rules scoped by "
                "environment may stop applying to the first. Pass "
                "skill=\"vmware-<name>\" to set_environment_resolver() to make "
                "the registration per-skill.",
                getattr(_resolver, "__qualname__", _resolver),
                getattr(resolver, "__qualname__", resolver),
            )
        _resolver = resolver
        _warned.clear()


def resolve_environment(target: str, skill: Optional[str] = None) -> str:
    """Return the environment ``target`` declares, or ``""`` if it declares none.

    An empty ``target`` is passed to the resolver rather than short-circuited:
    most tools take ``target`` as optional and fall back to the config's
    ``default_target``, so the skill's resolver is the only thing that knows
    which target an omitted argument actually means. Short-circuiting here would
    refuse every "use my default vCenter" call even when that target declares an
    environment perfectly well.

    Never raises. Every failure path answers ``""`` so the caller's fail-closed
    policy decides what that means, rather than an exception escaping into a
    tool call.
    """
    resolver = _resolvers.get(skill) if skill else None
    if resolver is None:
        # No keyed registration for this skill: either it predates keying, or it
        # genuinely registered nothing. The unkeyed slot is the compatibility
        # answer for the first case; for the second it is empty and the target
        # reads as unlabeled, which is the documented no-label behaviour.
        resolver = _resolver
    if resolver is None:
        _warn_once(
            target,
            "No environment resolver registered — targets read as unlabeled, so "
            "environment-scoped 'deny' rules (if any) will not match. Harmless "
            "unless you use them; register one with set_environment_resolver() at "
            "start-up if you do.",
        )
        return ""

    try:
        declared = resolver(target)
    except Exception:  # noqa: BLE001 — a broken config must not break the call
        _log.warning("Environment resolver failed for target %r", target, exc_info=True)
        return ""

    if not declared or not str(declared).strip():
        _warn_once(
            target,
            f"Target {target!r} declares no environment label, so any "
            f"environment-scoped 'deny' rules will not match it. Harmless unless "
            f"you rely on such rules; add 'environment: <name>' to its config "
            f"entry if you do.",
        )
        return ""
    return str(declared).strip()


def _warn_once(target: str, message: str) -> None:
    if target in _warned:
        return
    _warned.add(target)
    _log.warning("%s", message)


def mtime_cached_loader(
    env_var: str, default_path: Any, loader: Callable[[Any], Any]
) -> Callable[[], Any]:
    """Wrap a config loader so it re-parses only when the file actually changed.

    The environment resolver runs on *every* tool call, and a resolver that
    calls ``load_config()`` directly pays a full YAML parse each time — a
    50-call triage session performed 50 parses to answer a question whose
    answer changes essentially never (2026-07-18 review). This trades that for
    one ``os.stat`` per call, the same technique ``PolicyEngine._maybe_reload``
    already uses, and preserves the hot-reload contract exactly: an edit to the
    file is picked up on the next call.

    Args:
        env_var: Name of the per-skill config-path override variable
            (e.g. ``VMWARE_ARIA_CONFIG``), re-read on every call so the
            override keeps working mid-process.
        default_path: Path used when the variable is unset.
        loader: ``loader(path) -> config``; called only on first use and
            whenever the effective path or its mtime changes.

    The returned callable re-raises whatever ``loader`` raises — callers keep
    their own except-means-undeclared handling.
    """
    state: dict[str, Any] = {"path": None, "mtime": None, "value": None, "loaded": False}

    def cached() -> Any:
        raw = os.environ.get(env_var)
        path = Path(raw) if raw else Path(default_path)
        try:
            mtime: Optional[float] = path.stat().st_mtime
        except OSError:
            mtime = None
        if not state["loaded"] or state["path"] != path or state["mtime"] != mtime:
            state["value"] = loader(path if raw else None)
            state["path"] = path
            state["mtime"] = mtime
            state["loaded"] = True
        return state["value"]

    return cached
