"""
CYBERSHIELD X - Terminal CLI Interface
Unified command line tool for SecOps, Attack Surface Discovery, SIEM Ingestion, and AI Triage.
"""
import asyncio
import sys
import os
from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import click
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Safe console for Windows cp1252 and Linux UTF-8
console = Console(force_terminal=True, legacy_windows=False)

from cybershield.app.config import settings
from cybershield.app.database import init_db, AsyncSessionLocal
from cybershield.app.modules.asm.scope import check_scope, extract_host
from cybershield.app.modules.asm.scanner import ASMScanner
from cybershield.app.modules.vuln.manager import VulnerabilityManager
from cybershield.app.modules.ai_analyst.analyst import ai_analyst_service

@click.group()
def cli():
    """CYBERSHIELD X - Enterprise AI-Assisted SOC & Attack Surface Management Platform"""
    pass

@cli.command()
def status():
    """Display program scope, AI configurations, and active rules."""
    console.print(Panel(
        f"[bold cyan]{settings.app_name} v{settings.version}[/bold cyan]\n"
        f"[bold white]Program:[/bold white] {settings.program}\n"
        f"[bold white]Environment:[/bold white] {settings.environment}\n"
        f"[bold white]AI Model:[/bold white] {settings.ai.model} ({settings.ai.base_url})\n"
        f"[bold white]Rate Limit:[/bold white] {settings.rate_limit.requests_per_second} req/sec (burst: {settings.rate_limit.burst})",
        title="[bold green]System Status[/bold green]",
        border_style="cyan"
    ))

    table = Table(title="Scope Policy Enforcement", border_style="cyan")
    table.add_column("Type", style="bold")
    table.add_column("Rule / Pattern", style="white")

    for pat in settings.in_scope:
        table.add_row("[green]IN-SCOPE[/green]", pat)
    for pat in settings.out_of_scope:
        table.add_row("[red]OUT-OF-SCOPE[/red]", pat)

    console.print(table)

@cli.command("check-scope")
@click.argument("target")
def check_scope_cmd(target: str):
    """Verify target authorization before conducting security operations."""
    host = extract_host(target)
    is_ok, reason = check_scope(host, settings.in_scope, settings.out_of_scope)
    if is_ok:
        console.print(f"[bold green][IN SCOPE][/bold green] {target} ({reason})")
    else:
        console.print(f"[bold red][OUT OF SCOPE][/bold red] {target} ({reason})")
        sys.exit(1)

@cli.command()
@click.argument("target")
@click.option("--output", "-o", default=None, help="Save report to specified path.")
def scan(target: str, output: str):
    """Execute Attack Surface discovery & automated vulnerability analysis."""
    async def _run():
        await init_db()
        host = extract_host(target)
        is_ok, reason = check_scope(host, settings.in_scope, settings.out_of_scope)
        if not is_ok:
            console.print(f"[bold red][!] ABORTED: Target '{host}' is OUT OF SCOPE - {reason}[/bold red]")
            sys.exit(1)

        console.print(f"[bold cyan][>] Probing target surface:[/bold cyan] {host}")
        scanner = ASMScanner()
        asm_data = await scanner.scan_domain(host)

        console.print(f"[bold green][OK] Discovery Complete:[/bold green] Found {len(asm_data.get('ip_addresses', []))} IPs, {len(asm_data.get('open_ports', []))} open ports.")

        # Ports
        p_table = Table(title="Open Services & Ports", border_style="cyan")
        p_table.add_column("Port", style="bold white")
        p_table.add_column("Service", style="green")
        p_table.add_column("State", style="cyan")
        for p in asm_data.get("open_ports", []):
            p_table.add_row(str(p["port"]), p["service"], p["state"])
        console.print(p_table)

        # Vulns
        console.print("[bold yellow][>] Executing OWASP Top 10 Surface Probes...[/bold yellow]")
        vuln_mgr = VulnerabilityManager()
        findings = await vuln_mgr.run_owasp_checks(host, asm_data)

        console.print(f"[bold green][OK] Findings Collected: {len(findings)}[/bold green]\n")
        for idx, f in enumerate(findings, 1):
            sev_color = "red" if f["severity"] == "CRITICAL" else "yellow" if f["severity"] == "HIGH" else "cyan"
            console.print(Panel(
                f"[bold]Target:[/bold] {f['asset_target']}\n"
                f"[bold]Type:[/bold] {f['vulnerability_type']} | [bold]CVSS:[/bold] {f['cvss_score']}\n"
                f"[bold]Evidence:[/bold] {f['evidence']}\n"
                f"[bold]Business Impact:[/bold] {f['business_impact']}\n"
                f"[bold green]Remediation:[/bold green] {f['remediation']}",
                title=f"[{sev_color}][{f['severity']}] {f['title']}[/{sev_color}]",
                border_style=sev_color
            ))

        # AI Analyst Assessment
        console.print("[bold cyan][>] Dispatching to AI Security Analyst...[/bold cyan]")
        context_str = f"Target: {host}\nOpen Ports: {asm_data.get('open_ports')}\nFindings: {json.dumps(findings, indent=2)}"
        dossier = await ai_analyst_service.investigate(context_str, {"title": f"Scan Assessment of {host}", "severity": "HIGH"})

        console.print(Panel(
            f"[bold]Assessed Severity:[/bold] {dossier.get('assessed_severity')}\n"
            f"[bold]Summary:[/bold] {dossier.get('incident_summary')}\n\n"
            f"[bold red]Immediate Actions:[/bold red]\n" + "\n".join(f"* {a}" for a in dossier.get("immediate_containment_actions", [])) + "\n\n"
            f"[bold green]Hardening Playbook:[/bold green]\n" + "\n".join(f"* {a}" for a in dossier.get("eradication_and_remediation", [])),
            title="[bold magenta]AI Security Analyst Dossier[/bold magenta]",
            border_style="magenta"
        ))

    asyncio.run(_run())

@cli.command()
@click.option("--host", default="127.0.0.1", help="Host interface to bind")
@click.option("--port", default=8000, type=int, help="Port to listen on")
def serve(host: str, port: int):
    """Launch the CYBERSHIELD X Web Dashboard and API server."""
    console.print(Panel(
        f"[bold cyan]CYBERSHIELD X Server Starting[/bold cyan]\n"
        f"Web Dashboard: [bold underline green]http://{host}:{port}[/bold underline green]\n"
        f"Swagger API Docs: [bold underline cyan]http://{host}:{port}/docs[/bold underline cyan]",
        title="[bold green]Server Initialized[/bold green]",
        border_style="green"
    ))
    uvicorn.run("cybershield.app.main:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    cli()
