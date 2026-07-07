"""Command-line entry point: `python cli.py scan|triage|report|tokens|serve`."""
from __future__ import annotations

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from orchestrator import Orchestrator
from runtime_settings import get_settings, has_api_key
from store import FindingsStore
from token_store import TokenStore
from triage_runner import TokenBudgetExceeded, triage_app

app = typer.Typer(help="Run OWASP Top 10 DAST agents against a live application you own.")
console = Console()


@app.command()
def scan(
    target_url: str = typer.Argument(..., help="Live application URL to test, e.g. https://staging.example.com"),
    app_name: str = typer.Option(None, "--app-name", help="Label for this app in the dashboard (defaults to the URL's hostname)"),
):
    """Spider + actively scan TARGET_URL via ZAP (black-box, max thoroughness).
    No Anthropic API key needed - findings are queued for triage, not
    reviewed yet. Run `triage` next."""
    orchestrator = Orchestrator(target_url=target_url, app_name=app_name)
    findings = orchestrator.scan()
    console.print(
        f"[bold]{len(findings)}[/bold] findings queued for [bold]{orchestrator.app_name}[/bold]. "
        f"Run [bold]python cli.py triage --app-name \"{orchestrator.app_name}\"[/bold] to review them with AI."
    )


@app.command()
def triage(
    app_name: str = typer.Option(None, "--app-name", help="Only triage this app's pending findings (default: all apps)"),
):
    """Approve AI review of pending findings - this is the step that
    actually spends Anthropic tokens."""
    if not get_settings()["ai_enabled"]:
        console.print("[red]AI integration is turned off.[/red] Enable it via the Settings tab (or the API) before triaging.")
        raise typer.Exit(1)
    if not has_api_key():
        console.print("[red]No credentials set.[/red] Add an Anthropic API key, or an Azure Foundry endpoint + key, via the Settings tab or .env before triaging.")
        raise typer.Exit(1)
    token_limit = get_settings()["token_limit"]
    try:
        result = triage_app(app_name=app_name, token_limit=token_limit)
    except TokenBudgetExceeded as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(f"Triaged [bold]{result['triaged_count']}[/bold] findings.")
    if result["stopped_early"]:
        console.print(f"[yellow]Stopped early - token budget reached. {result['remaining_pending']} still pending.[/yellow]")
    console.print(f"Total tokens used so far: [bold]{result['tokens_used_total']}[/bold]")


@app.command()
def report():
    """Print a quick severity summary from the store."""
    store = FindingsStore()
    table = Table(title="Open findings by severity")
    table.add_column("Severity")
    table.add_column("Count")
    for severity, count in store.severity_summary().items():
        table.add_row(severity, str(count))
    console.print(table)


@app.command()
def tokens():
    """Print current token usage and budget."""
    token_store = TokenStore()
    limit = get_settings()["token_limit"]
    used = token_store.total_used()
    console.print(f"Used: [bold]{used}[/bold] tokens")
    console.print(f"Limit: [bold]{limit if limit else 'unlimited'}[/bold]")
    table = Table(title="Usage by category")
    table.add_column("Category")
    table.add_column("Tokens")
    for category, total in token_store.usage_by_category().items():
        table.add_row(category, str(total))
    console.print(table)


@app.command()
def serve(port: int = 9000):
    """Run the dashboard API and browser UI."""
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    app()
