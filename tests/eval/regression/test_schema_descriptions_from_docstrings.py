"""Parameter descriptions must reach the schema, which is all an agent can read.

Real-hardware finding, 2026-08-30. Across 327 MCP tools and roughly a thousand
parameters, the JSON schema an agent receives had **0%** coverage of
`description`, `enum` and `additionalProperties`. The prose docstrings are good
— 949 of those parameters were already described in a Google-style ``Args:``
block — but not one word of it reached the schema, and the schema is the only
contract the model can see.

The consequence measured on the estate was a three-stage silent failure: a
parameter name guessed wrong is discarded and the tool returns the full
unfiltered result; a *value* guessed wrong (``power_state="running"``) returns
0 rows where there were 11.

This copies what is already written rather than asking fifteen repos to write
it twice. That is the point: the docstring becomes load-bearing, so the two
cannot drift apart the way a duplicated description would.

``Args:`` is removed from the description once copied. Leaving it would bill the
same text twice against each manifest's token budget — vmware-debug's headroom
against its floor was already the narrowest in the family, and it is what would
have broken first.
"""

from __future__ import annotations

import pytest

from vmware_policy import describe_tool_parameters


class _Tool:
    """Stands in for a FastMCP Tool: a docstring-bearing fn and a schema dict."""

    def __init__(self, fn, parameters):
        self.fn = fn
        self.parameters = parameters
        self.description = (fn.__doc__ or "").strip()


def _schema(*names):
    return {"type": "object", "properties": {n: {"title": n.title()} for n in names}}


def _mgr(*tools):
    return {f"t{i}": t for i, t in enumerate(tools)}


@pytest.mark.unit
def test_a_documented_parameter_reaches_the_schema():
    def fn(target=None):
        """[READ] List things.

        Args:
            target: vCenter/ESXi target name from config. Defaults to the first.
        """

    tools = _mgr(_Tool(fn, _schema("target")))
    n = describe_tool_parameters(tools)

    assert n == 1
    assert tools["t0"].parameters["properties"]["target"]["description"] == (
        "vCenter/ESXi target name from config. Defaults to the first."
    )


@pytest.mark.unit
def test_a_multi_line_entry_is_joined():
    def fn(cluster=None):
        """Do a thing.

        Args:
            cluster: Cluster MoID, e.g. domain-c123, as the REST API
                requires; get it from inventory clusters.
        """

    tools = _mgr(_Tool(fn, _schema("cluster")))
    describe_tool_parameters(tools)

    assert tools["t0"].parameters["properties"]["cluster"]["description"] == (
        "Cluster MoID, e.g. domain-c123, as the REST API requires; get it "
        "from inventory clusters."
    )


@pytest.mark.unit
def test_the_args_block_is_removed_from_the_description():
    """The token-budget half. Copying without removing bills the same sentences
    twice against every manifest that lists this tool."""
    def fn(target=None):
        """[READ] List things.

        Returns the family list envelope.

        Args:
            target: Target name.
        """

    tools = _mgr(_Tool(fn, _schema("target")))
    describe_tool_parameters(tools)

    desc = tools["t0"].description
    assert "Args:" not in desc
    assert "Target name." not in desc
    # ...but everything that was not a parameter entry survives intact.
    assert "[READ] List things." in desc
    assert "Returns the family list envelope." in desc


@pytest.mark.unit
def test_a_tool_with_no_args_block_is_left_alone():
    """The control. A helper that mangled descriptions it had nothing to copy
    from would pass every test above and quietly damage every other tool."""
    def fn(target=None):
        """[READ] List things. No Args section here."""

    tools = _mgr(_Tool(fn, _schema("target")))
    n = describe_tool_parameters(tools)

    assert n == 0
    assert tools["t0"].description == "[READ] List things. No Args section here."
    assert "description" not in tools["t0"].parameters["properties"]["target"]


@pytest.mark.unit
def test_an_existing_description_is_not_overwritten():
    """A parameter that already carries a hand-written Field(description=...)
    outranks the docstring: someone chose that wording deliberately."""
    def fn(target=None, other=None):
        """[READ] Thing.

        Args:
            target: from the docstring.
            other: also from the docstring.
        """

    schema = _schema("target", "other")
    schema["properties"]["target"]["description"] = "from Field()"
    tools = _mgr(_Tool(fn, schema))
    n = describe_tool_parameters(tools)

    props = tools["t0"].parameters["properties"]
    assert props["target"]["description"] == "from Field()"
    # Second parameter asserted too, or this test passes whenever the parser
    # matched nothing at all — which is exactly how it passed while a docstring
    # opening with `Args:` was being skipped entirely (形态 #4).
    assert props["other"]["description"] == "also from the docstring."
    assert n == 1


@pytest.mark.unit
def test_a_documented_name_that_is_not_a_parameter_is_ignored():
    """Docstrings document things that are not in the signature — `si`, `self`,
    or a parameter that has since been removed. Injecting those would invent
    schema properties the tool does not accept."""
    def fn(target=None):
        """[READ] Thing.

        Args:
            si: vSphere ServiceInstance.
            target: Target name.
            gone: removed in 1.8.0.
        """

    tools = _mgr(_Tool(fn, _schema("target")))
    n = describe_tool_parameters(tools)

    props = tools["t0"].parameters["properties"]
    assert set(props) == {"target"}
    # Asserted, because `set(props) == {"target"}` also holds when the parser
    # found nothing at all — which is how this test passed while a docstring
    # opening with `Args:` was silently unparsed (形态 #4, third time today).
    assert n == 1
    assert props["target"]["description"] == "Target name."


@pytest.mark.unit
def test_additional_properties_is_closed():
    """CLAUDE.md's tool-design rule: an open schema is room for a model to
    invent arguments that are then silently discarded."""
    def fn(target=None):
        """Args:
            target: Target name.
        """

    tools = _mgr(_Tool(fn, _schema("target")))
    describe_tool_parameters(tools)

    assert tools["t0"].parameters["additionalProperties"] is False


@pytest.mark.unit
def test_it_reports_how_many_it_described():
    """A helper that silently described nothing is the failure this family
    keeps rediscovering (形态 #1), so the count is returned and callers can
    assert on it."""
    def a(x=None):
        """[READ] A thing.

        Args:
            x: ex.
        """

    def b(y=None):
        """No args block."""

    assert describe_tool_parameters(_mgr(_Tool(a, _schema("x")), _Tool(b, _schema("y")))) == 1


@pytest.mark.unit
def test_running_twice_changes_nothing_further():
    """Servers get built more than once in a process (tests, build_server()),
    and a second pass must not eat the description it already trimmed."""
    def fn(target=None):
        """[READ] Thing.

        Args:
            target: Target name.
        """

    tools = _mgr(_Tool(fn, _schema("target")))
    describe_tool_parameters(tools)
    first_desc = tools["t0"].description
    first_param = dict(tools["t0"].parameters["properties"]["target"])

    assert describe_tool_parameters(tools) == 0
    assert tools["t0"].description == first_desc
    assert tools["t0"].parameters["properties"]["target"] == first_param


@pytest.mark.unit
def test_entries_must_be_indented_under_the_heading():
    """A documented limit, not an oversight.

    ``inspect.getdoc`` dedents, so a docstring whose *first* line is ``Args:``
    loses the indentation of everything under it and its entries arrive at
    column zero. Those are not parsed, deliberately: at column zero there is
    nothing to distinguish a parameter entry from any other ``word: text``
    sentence in the prose, and guessing would invent descriptions.

    Every tool in this family opens with a summary line, so ``Args:`` is
    indented and its entries more so — which is why the same parser measured
    949 of ~1000 parameters as already documented.
    """
    def fn(x=None):
        """Args:
x: at column zero, indistinguishable from prose.
        """

    tools = _mgr(_Tool(fn, _schema("x")))

    assert describe_tool_parameters(tools) == 0
