import asyncio
import sys
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

console = Console(force_terminal=True, legacy_windows=False)

from cyberfusion.app.config import settings
from cyberfusion.app.database import init_db
from cyberfusion.app.modules.asm.scope import check_scope, extract_host
from cyberfusion.app.modules.asm.scanner import ASMScanner
from cyberfusion.app.modules.cspm.scanner import cspm_scanner
from cyberfusion.app.modules.api_sec.auditor import api_auditor
from cyberfusion.app.modules.phishing.analyzer import phishing_analyzer
from cyberfusion.app.modules.ransomware.monitor import ransomware_monitor
from cyberfusion.app.modules.ai_analyst.correlation import unified_correlator
from cyberfusion.app.modules.ai_analyst.analyst import ai_analyst
from cyberfusion.app.modules.pentest_tools import nmap_runner, caido_client, tool_registry

@click.group()
def cli():
    """CYBERFUSION X - Unified AI Enterprise Cyber Defense & Pentest Suite"""
    pass

@cli.command()
def status():
    """Display platform status, attack surface counts, and active defense modules."""
    console.print(Panel(
        f"[bold cyan]{settings.app_name} v{settings.version}[/bold cyan]\n"
        f"[bold white]Subtitle:[/bold white] {settings.subtitle}\n"
        f"[bold white]Program:[/bold white] {settings.program}\n"
        f"[bold white]AI Model:[/bold white] {settings.ai.model} ({settings.ai.base_url})\n\n"
        f"[bold yellow]Active Defense & Pentest Tools (8 Integrated):[/bold yellow]\n"
        f"1. Nmap Network Scanner            5. Identity (UEBA)\n"
        f"2. Caido Web Auditing Proxy        6. API Security (BOLA/Auth)\n"
        f"3. Nuclei Vulnerability Scanner    7. Phishing Defense\n"
        f"4. Cloud Security (CSPM)           8. Ransomware Defense",
        title="[bold green]Enterprise Cyber Defense Status[/bold green]",
        border_style="cyan"
    ))

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

@cli.command("run-nmap")
@click.argument("target")
@click.option("--ports", "-p", default="21,22,25,53,80,110,143,443,3306,3389,5432,6379,8080,8443", help="Target port list")
@click.option("--scripts", is_flag=True, default=False, help="Run NSE vulnerability scripts")
def run_nmap_cmd(target: str, ports: str, scripts: bool):
    """Execute authorized Nmap network discovery and service version audit."""
    async def _run():
        host = extract_host(target)
        is_ok, reason = check_scope(host, settings.in_scope, settings.out_of_scope)
        if not is_ok:
            console.print(f"[bold red][!] Target {host} is OUT OF SCOPE — {reason}[/bold red]")
            sys.exit(1)

        console.print(f"[bold cyan][>] Running Nmap on:[/bold cyan] {host} (Ports: {ports})")
        res = await nmap_runner.scan_target(host, ports, scripts)
        console.print(f"[bold green][OK] Engine: {res['engine']}[/bold green]")
        
        table = Table(title=f"Nmap Service Scan Results for {host}", border_style="cyan")
        table.add_column("Port", style="bold white")
        table.add_column("Service", style="green")
        table.add_column("Product / Version", style="yellow")
        for s in res.get("open_services", []):
            table.add_row(str(s["port"]), s["service"], f"{s['product']} {s.get('version', '')}")
        console.print(table)

        if res.get("findings"):
            console.print("[bold red]Vulnerabilities Identified:[/bold red]")
            for f in res["findings"]:
                console.print(f"  • [{f['severity']}] {f['title']}")

    asyncio.run(_run())

@cli.command("caido-status")
def caido_status_cmd():
    """Check Caido web auditing proxy connection & upstream settings."""
    async def _run():
        res = await caido_client.check_connection()
        if res.get("connected"):
            console.print(f"[bold green][OK] Caido Proxy Active at {res['proxy_url']}[/bold green]")
        else:
            console.print(f"[bold yellow][!] Caido Status: {res.get('note')}[/bold yellow]")
        console.print(f"[bold cyan]Upstream Proxy Settings:[/bold cyan] http://127.0.0.1:8080")
        console.print("Route your browser or API scanner through port 8080 to intercept and replay requests in Caido.")
    asyncio.run(_run())

@cli.command("list-tools")
def list_tools_cmd():
    """List all integrated pentesting and bug hunting tools."""
    table = Table(title="Bug Hunting & Pentest Tools Suite", border_style="cyan")
    table.add_column("Tool", style="bold cyan")
    table.add_column("Category", style="white")
    table.add_column("Status", style="green")
    table.add_column("Capabilities", style="yellow")

    for t in tool_registry.get_tool_inventory():
        status = "[green]Available[/green]" if t["installed"] else "[dim]Parser Ready[/dim]"
        table.add_row(t["name"], t["category"], status, ", ".join(t["capabilities"][:3]))
    console.print(table)

@cli.command("scan-cloud")
def scan_cloud():
    """Audit AWS/Azure/GCP cloud accounts for misconfigurations."""
    async def _run():
        res = await cspm_scanner.audit_cloud_account("aws", "123456789012")
        console.print(f"[bold cyan]CSPM Cloud Audit - Compliance: {res['compliance_score']}%[/bold cyan]")
        for f in res["findings"]:
            console.print(f"[{f['severity']}] {f['title']} ({f['service']})")
    asyncio.run(_run())

@cli.command("audit-api")
def audit_api():
    """Audit API inventory for OWASP API Top 10 vulnerabilities."""
    async def _run():
        res = await api_auditor.audit_api_surface()
        console.print(f"[bold cyan]API Surface Audit - Total Endpoints: {res['total_endpoints']}[/bold cyan]")
        for f in res["findings"]:
            console.print(f"[{f['severity']}] {f['endpoint_path']} - {f['finding_type']}")
    asyncio.run(_run())

@cli.command("analyze-phishing")
@click.argument("url")
def analyze_phishing(url: str):
    """Analyze URL/domain for credential harvesting and phishing lures."""
    res = phishing_analyzer.analyze(target_url=url)
    console.print(Panel(
        f"URL: {res['target_url']}\n"
        f"Verdict: [{res['risk_verdict']}] (Probability: {res['risk_score']}%)\n"
        f"Indicators: {', '.join(res['indicators'])}",
        title="Phishing Analysis Result",
        border_style="red" if res['risk_verdict'] == 'CRITICAL' else "yellow"
    ))

@cli.command("simulate-ransomware")
def simulate_ransomware():
    """Defensive behavioral simulation: mass file modifications & endpoint isolation."""
    res = ransomware_monitor.evaluate_behavior("workstation-09.corp", "cryptolocker.exe", 1284, 45)
    console.print(Panel(
        f"Process: {res['process_name']} (PID {res['pid']}) on {res['host']}\n"
        f"Telemetry: {res['files_modified_count']} files / {res['duration_seconds']}s (Rate: {res['modification_rate_per_sec']} files/s)\n"
        f"Entropy: {res['entropy_score']} (Encryption Uniformity)\n"
        f"[bold red]Response: {res['containment_action']} (Host Isolated: {res['is_isolated']})[/bold red]",
        title="Ransomware Behavioral Defense",
        border_style="red"
    ))

@cli.command("threat-hunt")
def threat_hunt():
    """Correlate 7-vector attack chain into unified incident & timeline."""
    async def _run():
        incident = unified_correlator.build_cross_domain_incident()
        dossier = await ai_analyst.investigate(incident)
        console.print(Panel(
            f"[bold]Title:[/bold] {incident['title']}\n"
            f"[bold]Vector:[/bold] {incident['attack_vector']}\n"
            f"[bold red]Summary:[/bold red] {dossier.get('executive_summary')}\n\n"
            f"[bold green]Immediate Actions:[/bold green]\n" + "\n".join(f"• {a}" for a in dossier.get("immediate_containment_actions", [])),
            title="AI Security Analyst Cross-Domain Dossier",
            border_style="magenta"
        ))
    asyncio.run(_run())

@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8899, type=int)
def serve(host: str, port: int):
    """Launch the CYBERFUSION X Command Center."""
    console.print(Panel(
        f"[bold cyan]CYBERFUSION X Unified Defense & Pentest Suite[/bold cyan]\n"
        f"Web Command Center: [bold underline green]http://{host}:{port}[/bold underline green]\n"
        f"REST API Docs: [bold underline cyan]http://{host}:{port}/docs[/bold underline cyan]",
        title="[bold green]Platform Online[/bold green]",
        border_style="green"
    ))
    uvicorn.run("cyberfusion.app.main:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    cli()
