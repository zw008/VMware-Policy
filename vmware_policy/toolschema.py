"""Copy parameter descriptions out of docstrings and into the JSON schema.

An MCP client sees a tool's *schema*. It does not see the docstring — that text
becomes the tool's single `description` string, where a model has to find the
right sentence for the right argument by reading prose.

On a real VCF 9.1 estate in 2026-08-30 that produced a three-stage silent
failure: a parameter name guessed wrong is discarded by FastMCP and the tool
returns the full unfiltered result; a *value* guessed wrong
(``power_state="running"``) returns 0 rows where there were 11. Nothing errors
at any stage. Across the family, `description`, `enum` and
`additionalProperties` coverage was 0% — while 949 of ~1000 parameters were
already described in a Google-style ``Args:`` block.

So this copies what is already written rather than asking fifteen repos to
write it a second time. The docstring becomes load-bearing: edit it and the
schema changes with it, which is the only arrangement in which the two cannot
drift (形态 #6).

Call it once, after the tools are registered::

    from vmware_policy import describe_tool_parameters
    describe_tool_parameters(mcp._tool_manager._tools)
"""

from __future__ import annotations

import inspect
import re
from typing import Any

__all__ = ["describe_tool_parameters", "parse_args_section"]

#: The ``Args:`` block, up to the next Google-style section or the end.
_ARGS_BLOCK = re.compile(
    # `(?:\A|\n)` rather than `\n`: inspect.getdoc strips the leading blank
    # line, so a docstring that opens with `Args:` has no newline in front of
    # it and was silently skipped.
    r"(?P<head>(?:\A|\n)[ \t]*Args:[ \t]*\n)(?P<body>.*?)"
    r"(?=\n[ \t]*(?:Returns|Raises|Yields|Examples?|Notes?|Attributes|Todo)s?:|\Z)",
    re.S,
)
#: One entry: ``name: text`` or ``name (type): text``, indented under Args.
_ENTRY = re.compile(r"^[ \t]{2,}(\*{0,2}\w+)[ \t]*(?:\([^)]*\))?[ \t]*:[ \t]*(.*)$")


def parse_args_section(doc: str | None) -> dict[str, str]:
    """``{parameter: description}`` from a Google-style ``Args:`` block.

    Continuation lines are folded into one sentence, because a description
    broken across source lines is still one description.
    """
    if not doc:
        return {}
    match = _ARGS_BLOCK.search(doc)
    if not match:
        return {}
    found: dict[str, str] = {}
    current: str | None = None
    for line in match.group("body").splitlines():
        if not line.strip():
            continue
        entry = _ENTRY.match(line)
        if entry:
            current = entry.group(1).lstrip("*")
            found[current] = entry.group(2).strip()
        elif current:
            found[current] = f"{found[current]} {line.strip()}".strip()
    return {name: text for name, text in found.items() if text}


def _strip_args_section(doc: str) -> str:
    """The docstring with its ``Args:`` block removed.

    Not cosmetic. The description and the schema both travel in every
    ``tools/list`` response, so leaving the block in place bills the same
    sentences twice against each manifest's token budget — and the narrowest
    headroom in this family was already close enough to its floor that this
    alone would have broken it.
    """
    return _ARGS_BLOCK.sub("\n", doc).rstrip() + "\n" if _ARGS_BLOCK.search(doc) else doc


def describe_tool_parameters(tools: dict[str, Any]) -> int:
    """Fill in each tool's schema from its docstring. Returns how many it filled.

    ``tools`` is FastMCP's registry — ``mcp._tool_manager._tools``. Each value
    needs ``.fn``, ``.parameters`` and ``.description``.

    Deliberately narrow about what it will touch:

    * a parameter that already has a ``description`` keeps it — someone wrote
      that ``Field(description=...)`` on purpose and outranks the prose;
    * a documented name that is not in the schema is ignored, because
      docstrings describe things the wire never sees (``si``, ``self``, an
      argument removed two releases ago), and inventing schema properties for
      them would advertise arguments the tool rejects;
    * ``additionalProperties`` is closed, per this family's tool-design rule: an
      open schema is room for a model to invent arguments that are then
      silently discarded — one half of the failure this exists to fix.

    Idempotent: servers are built more than once in a process, and a second
    pass must not consume the text it already moved. The count is returned
    rather than logged so a caller can assert it described something; a helper
    that silently did nothing is the shape this family keeps rediscovering
    (形态 #1).
    """
    described = 0
    for tool in tools.values():
        schema = getattr(tool, "parameters", None)
        if not isinstance(schema, dict):
            continue
        schema.setdefault("additionalProperties", False)
        properties = schema.get("properties")
        if not isinstance(properties, dict) or not properties:
            continue

        doc = inspect.getdoc(tool.fn)
        documented = parse_args_section(doc)
        if not documented:
            continue

        for name, text in documented.items():
            prop = properties.get(name)
            if isinstance(prop, dict) and not prop.get("description"):
                prop["description"] = text
                described += 1

        trimmed = _strip_args_section(doc or "")
        if trimmed != doc:
            tool.description = trimmed.strip()
    return described
