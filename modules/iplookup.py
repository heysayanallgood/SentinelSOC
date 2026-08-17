from rich.console import Console
from rich.table import Table

from core.threat_api import ip_reputation

console = Console()


def run():

    console.print("\n[bold cyan]🌍 IP Reputation Lookup[/bold cyan]\n")

    ip = input("Enter IP Address: ").strip()

    console.print("\n[yellow]Checking AbuseIPDB...[/yellow]\n")

    result = ip_reputation(ip)

    if result is None:
        console.print("[red]Unable to contact AbuseIPDB.[/red]")
        input("\nPress Enter...")
        return

    data = result["data"]

    table = Table(title="Threat Intelligence Report")

    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("IP", str(data.get("ipAddress")))
    table.add_row("Risk Score", str(data.get("abuseConfidenceScore")))
    table.add_row("Country", str(data.get("countryCode")))
    table.add_row("ISP", str(data.get("isp")))
    table.add_row("Domain", str(data.get("domain")))
    table.add_row("Usage", str(data.get("usageType")))
    table.add_row("Reports", str(data.get("totalReports")))
    table.add_row("Last Report", str(data.get("lastReportedAt")))

    console.print(table)

    if data.get("abuseConfidenceScore", 0) >= 75:
        console.print("\n[bold red]HIGH RISK[/bold red]")
    elif data.get("abuseConfidenceScore", 0) >= 25:
        console.print("\n[yellow]MEDIUM RISK[/yellow]")
    else:
        console.print("\n[green]LOW RISK[/green]")

    input("\nPress Enter...")


