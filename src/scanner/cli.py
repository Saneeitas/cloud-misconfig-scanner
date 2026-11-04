"""CLI interface built with Click."""

import sys

import click
from rich.console import Console

from scanner.context import ScanContext
from scanner.engine import ScannerEngine
from scanner.formatters import format_json, format_table
from scanner.models import ScanResult, Severity


@click.group()
def main():
    """Cloud Misconfiguration Scanner — multi-cloud security audit tool."""
    pass


@main.command()
@click.option("--provider", type=click.Choice(["aws", "azure", "all"]), default="all",
              help="Cloud provider to scan.")
@click.option("--profile", default=None, help="AWS credential profile name.")
@click.option("--region", default="us-east-1", help="AWS region to scan.")
@click.option("--subscription-id", default=None, help="Azure subscription ID.")
@click.option("--output", "output_format", type=click.Choice(["table", "json"]),
              default="table", help="Output format.")
@click.option("--output-file", default=None, type=click.Path(),
              help="Write output to file (JSON mode).")
@click.option("--severity-threshold", default="low",
              type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
              help="Filter findings below this severity.")
@click.option("--checks", default=None,
              help="Comma-separated check IDs to run (e.g., AWS-S3-001,AWS-IAM-001).")
def scan(provider, profile, region, subscription_id, output_format,
         output_file, severity_threshold, checks):
    """Run security misconfiguration checks against cloud resources."""
    console = Console(stderr=True)
    threshold = Severity.from_string(severity_threshold)
    check_ids = [c.strip() for c in checks.split(",")] if checks else None

    # Build scan context
    context = _build_context(provider, profile, region, subscription_id, console)
    if context is None:
        sys.exit(2)

    # Run engine
    engine = ScannerEngine(
        context=context,
        provider=provider,
        severity_threshold=threshold,
        check_ids=check_ids,
    )

    console.print(f"[bold]Scanning {provider} resources...[/bold]")
    result = engine.run()

    # Output
    if output_format == "table":
        format_table(result, Console())
    else:
        json_str = format_json(result, provider, region)
        if output_file:
            with open(output_file, "w") as f:
                f.write(json_str)
            console.print(f"Results written to {output_file}")
        else:
            click.echo(json_str)

    _warn_if_incomplete(result, console)

    # Exit codes for CI gating: 1 = findings, 2 = no findings but the scan
    # can't be trusted, 0 = every selected check ran and found nothing.
    if result.findings:
        sys.exit(1)
    if result.incomplete:
        sys.exit(2)
    sys.exit(0)


def _warn_if_incomplete(result: ScanResult, console: Console) -> None:
    """Tell the user when a scan did not evaluate everything it was asked to."""
    if not result.incomplete:
        return
    if result.checks_run == 0:
        console.print("Scan incomplete: no checks ran, so nothing was evaluated.",
                      style="bold yellow", markup=False)
        return
    console.print(f"Scan incomplete: {len(result.errors)} of {result.checks_run} checks "
                  "failed, so results may be missing.", style="bold yellow", markup=False)
    for error in result.errors:
        console.print(f"  {error}", style="yellow", markup=False)


def _build_context(provider: str, profile: str | None, region: str,
                   subscription_id: str | None, console: Console) -> ScanContext | None:
    """Build ScanContext with appropriate read-only clients."""
    context = ScanContext()

    if provider in ("aws", "all"):
        try:
            import boto3
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            from scanner.clients.aws_client import ReadOnlyAWSClient
            context.aws_client = ReadOnlyAWSClient(session=session, region=region)
            context.aws_region = region
        except Exception as e:
            if provider == "aws":
                console.print(f"[red]Failed to initialize AWS client: {e}[/red]")
                return None
            console.print(f"[yellow]AWS credentials not available, skipping: {e}[/yellow]")

    if provider in ("azure", "all"):
        try:
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
            sub_id = subscription_id or ""
            from scanner.clients.azure_client import ReadOnlyAzureClient
            context.azure_client = ReadOnlyAzureClient(
                credential=credential, subscription_id=sub_id
            )
            context.azure_subscription_id = sub_id
        except Exception as e:
            if provider == "azure":
                console.print(f"[red]Failed to initialize Azure client: {e}[/red]")
                return None
            console.print(f"[yellow]Azure credentials not available, skipping: {e}[/yellow]")

    return context
