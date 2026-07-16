from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.nvd_api import cve_lookup

console = Console()


def run():

    console.print(
        Panel.fit(
            "[bold cyan]🛡 CVE Search[/bold cyan]",
            border_style="cyan"
        )
    )

    cve = input("\nEnter CVE ID (Example: CVE-2024-3094): ").strip()

    console.print("\n[yellow]Searching NVD Database...[/yellow]\n")

    result = cve_lookup(cve)

    if result is None:
        console.print("[red]Unable to contact NVD.[/red]")
        input("\nPress Enter...")
        return

    vulnerabilities = result.get("vulnerabilities", [])

    if not vulnerabilities:
        console.print("[red]No CVE found.[/red]")
        input("\nPress Enter...")
        return

    vuln = vulnerabilities[0]["cve"]

    description = vuln["descriptions"][0]["value"]

    table = Table(title="CVE Information")

    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("CVE", cve)
    table.add_row("Published", vuln.get("published", "Unknown"))
    table.add_row("Last Modified", vuln.get("lastModified", "Unknown"))
    table.add_row("Status", vuln.get("vulnStatus", "Unknown"))
    table.add_row("Description", description[:250] + "...")

    console.print(table)

    input("\nPress Enter...")
