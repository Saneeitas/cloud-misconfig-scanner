"""Rich table formatter for human-readable terminal output."""

from rich.console import Console
from rich.table import Table

from scanner.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


def format_table(result: ScanResult, console: Console | None = None) -> None:
    """Render scan results as a color-coded Rich table."""
    if console is None:
        console = Console()

    if not result.findings:
        # Never report a pass unless every selected check actually ran.
        if not result.incomplete:
            console.print("\n[green]✓ No findings — all checks passed.[/green]\n")
        return

    table = Table(title="Scan Findings", show_lines=True)
    table.add_column("Check ID", style="bold", width=12)
    table.add_column("Title", width=35)
    table.add_column("Severity", width=10)
    table.add_column("Provider", width=8)
    table.add_column("Resource", width=40, overflow="fold")
    table.add_column("Region", width=15)

    for finding in result.findings:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        table.add_row(
            finding.check_id,
            finding.title,
            f"[{color}]{finding.severity.value}[/{color}]",
            finding.cloud_provider.upper(),
            finding.resource_id,
            finding.region,
        )

    console.print()
    console.print(table)

    # Summary
    summary = _severity_summary(result)
    console.print(f"\n[bold]Summary:[/bold] {result.checks_run} checks run, "
                  f"{len(result.findings)} findings")
    console.print(f"  Critical: {summary['Critical']} | High: {summary['High']} | "
                  f"Medium: {summary['Medium']} | Low: {summary['Low']}\n")


def _severity_summary(result: ScanResult) -> dict[str, int]:
    """Count findings by severity."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in result.findings:
        counts[f.severity.value] += 1
    return counts
