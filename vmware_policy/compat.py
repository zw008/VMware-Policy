"""Product-version gating for calls that only exist on newer appliances.

Why this is not a version-string ``if`` scattered through the ops layer
---------------------------------------------------------------------
Most calls in this family work identically on 7.x, 8.x and 9.x, and those must
not grow a version branch — a branch that never differs is a place for a future
reader to introduce a difference by accident. This module exists only for the
minority of call sites that genuinely do not exist on older appliances.

For those, the failure today is a 404 whose remedy says "verify the id — list
the parent collection first and copy an exact UUID". That advice is wrong: the
id was fine, the endpoint is not there. The operator goes hunting for a UUID
that was never the problem.

Three states, never two
-----------------------
``detected`` is the version string read off the appliance, and reading it can
fail. "We could not read the version" must never render as "your version is too
old" — that is 形态 #1 (an unknown read as a no) in the one place whose whole
job is to explain a failure. So:

    detected is None          -> say the endpoint is absent AND name the floor,
                                 without asserting anything about their build
    parsed  <  minimum        -> definitive: name both versions
    parsed  >= minimum        -> NOT a version problem; the caller must fall
                                 through to its ordinary 404 remedy, because
                                 telling someone on 9.1 to upgrade to 9.1 is
                                 worse than saying nothing

Version comparison is deliberately weak
---------------------------------------
Real strings seen in this estate: ``9.1.0.0200`` (vCenter, four parts),
``8.6.4`` (vROps), ``4.1.2.3.0`` (NSX). Anything non-numeric ends the parse
rather than raising, and a string that yields no leading number at all parses
to ``None`` — which routes to the "could not read" branch above, not to a
false "too old".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

__all__ = ["Requires", "at_least", "parse_version", "version_remedy"]

_NUMERIC = re.compile(r"\d+")


@dataclass(frozen=True)
class Requires:
    """Declares the oldest appliance a single call site works on.

    Attach it next to the path constant it guards, so the requirement and the
    request it describes cannot drift apart (形态 #6 — the two must be one
    edit, not two).

    ``feature`` names the capability in the operator's words ("fleet
    certificate inventory"), not the function name.
    """

    product: str
    minimum: tuple[int, ...]
    feature: str

    @property
    def minimum_str(self) -> str:
        return ".".join(str(p) for p in self.minimum)


def parse_version(raw: Optional[str]) -> Optional[tuple[int, ...]]:
    """``"9.1.0.0200"`` -> ``(9, 1, 0, 200)``; unparseable -> ``None``.

    ``None`` means "we do not know", and every caller must treat it as such.
    Note ``"0200"`` becomes ``200``: appliance builds are zero-padded and the
    padding carries no ordering information.
    """
    if not raw:
        return None
    parts: list[int] = []
    for chunk in str(raw).split("."):
        match = _NUMERIC.match(chunk.strip())
        if not match:
            break
        parts.append(int(match.group()))
    return tuple(parts) if parts else None


def at_least(parsed: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    """Is ``parsed`` >= ``minimum``, comparing them as equal-length versions?

    Plain tuple comparison is wrong here and wrong in the dangerous direction:
    an appliance reporting bare ``"9"`` parses to ``(9,)``, and ``(9,) >= (9, 0)``
    is ``False`` in Python — the shorter tuple loses — so a box that meets the
    floor would be told to upgrade to the version it is already running. Pad
    both sides with zeros first: an omitted segment means zero, not absent.
    """
    width = max(len(parsed), len(minimum))
    pad = lambda v: v + (0,) * (width - len(v))  # noqa: E731
    return pad(parsed) >= pad(minimum)

def version_remedy(req: Requires, detected: Optional[str]) -> Optional[str]:
    """Explain a 404 as a version floor, or return ``None`` if it is not one.

    ``None`` is the important return: it means this call site's requirement is
    satisfied (or the requirement does not explain the failure), so the caller
    keeps its ordinary remedy. A version explanation that fires on an appliance
    that already meets the floor sends the operator to upgrade something that
    is already new enough.
    """
    parsed = parse_version(detected)

    if parsed is None:
        return (
            f"{req.feature} is a {req.product} {req.minimum_str}+ capability and "
            f"this appliance does not expose it. The running version could not be "
            f"read, so this is not a statement about your build — check the "
            f"appliance version, and if it is below {req.minimum_str} that is the "
            f"reason."
        )

    if at_least(parsed, req.minimum):
        return None

    detected_str = str(detected).strip()
    return (
        f"{req.feature} requires {req.product} {req.minimum_str} or newer; this "
        f"appliance reports {detected_str}. The id you passed is not the problem "
        f"— the endpoint does not exist on this version. Upgrade, or point at a "
        f"{req.minimum_str}+ appliance."
    )
