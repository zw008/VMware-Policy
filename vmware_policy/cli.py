"""CLI for querying the unified VMware audit log.

Usage::

    vmware-audit log --last 20
    vmware-audit log --skill vmware-nsx --status denied --since 2026-03-28
    vmware-audit export --format json > audit.json
    vmware-audit stats --days 7
"""

from __future__ import annotations

import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from vmware_policy.audit import get_engine

app = typer.Typer(
    name="vmware-audit",
    help="Query the unified VMware audit log (~/.vmware/audit.db).",
    no_args_is_help=True,
)
console = Console()


@app.command()
def log(
    last: int = typer.Option(20, help="Number of recent entries to show"),
    skill: Optional[str] = typer.Option(None, help="Filter by skill name"),
    tool: Optional[str] = typer.Option(None, help="Filter by tool name"),
    status: Optional[str] = typer.Option(None, help="Filter by status (ok/denied/error)"),
    workflow_id: Optional[str] = typer.Option(None, "--workflow-id", help="Filter by workflow ID"),
    since: Optional[str] = typer.Option(None, help="Show entries after date (ISO format)"),
) -> None:
    """Show recent audit log entries."""
    engine = get_engine()
    rows = engine.query(
        skill=skill,
        tool=tool,
        status=status,
        workflow_id=workflow_id,
        since=since,
        limit=last,
    )

    if not rows:
        console.print("[dim]No audit records found.[/dim]")
        return

    table = Table(title=f"Audit Log (last {len(rows)} entries)", show_lines=False)
    table.add_column("Time", style="dim", width=20)
    table.add_column("Skill", style="cyan", width=10)
    table.add_column("Tool", style="green", width=24)
    table.add_column("Status", width=10)
    table.add_column("Agent", style="dim", width=8)
    table.add_column("Duration", justify="right", width=8)

    for row in reversed(rows):  # oldest first
        ts = row["ts"][:19].replace("T", " ")
        st = row["status"]
        style = "red" if "denied" in st or "error" in st else ""
        table.add_row(
            ts,
            row["skill"],
            row["tool"],
            f"[{style}]{st}[/{style}]" if style else st,
            row["agent"],
            f"{row['duration_ms']}ms",
        )

    console.print(table)


@app.command()
def export(
    format: str = typer.Option("json", help="Export format: json"),
    skill: Optional[str] = typer.Option(None, help="Filter by skill"),
    since: Optional[str] = typer.Option(None, help="Export entries after date"),
    limit: int = typer.Option(10000, help="Max entries to export"),
) -> None:
    """Export audit log as JSON to stdout."""
    engine = get_engine()
    rows = engine.query(skill=skill, since=since, limit=limit)
    json.dump(rows, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


@app.command()
def stats(
    days: int = typer.Option(7, help="Number of days to analyze"),
) -> None:
    """Show aggregate audit statistics."""
    engine = get_engine()
    data = engine.stats(days=days)

    console.print(f"\n[bold]Audit Statistics (last {days} days)[/bold]\n")
    console.print(f"  Total operations: [bold]{data['total']}[/bold]")

    if data["by_status"]:
        console.print("\n  By status:")
        for st, count in sorted(data["by_status"].items()):
            style = "red" if "denied" in st or "error" in st else "green"
            console.print(f"    [{style}]{st}[/{style}]: {count}")

    if data["by_skill"]:
        console.print("\n  By skill:")
        for sk, count in sorted(data["by_skill"].items(), key=lambda x: -x[1]):
            console.print(f"    [cyan]{sk}[/cyan]: {count}")

    console.print()


if __name__ == "__main__":
    app()
