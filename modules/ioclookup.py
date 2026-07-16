from core.otx_api import lookup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import re

console = Console()


def detect(value):

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
        return "IPv4", "IPv4"

    if value.startswith("http"):
        return "URL", "url"

    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "MD5", "file"

    return "Domain", "domain"


def run():

    console.print(
        Panel.fit(
            "[bold cyan]IOC Analyzer[/bold cyan]"
        )
    )

    value = input("\nIOC : ")

    display_type, api_type = detect(value)

    console.print(f"\nDetected : [green]{display_type}[/green]")

    console.print("\nFetching AlienVault Intelligence...\n")

    result = lookup(api_type, value)

    if result is None:

        console.print("[red]No intelligence found.[/red]")

        input("\nPress Enter...")

        return

    table = Table(title="AlienVault OTX")

    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Indicator", value)
    table.add_row("Type", display_type)
    table.add_row("Pulse Count", str(result.get("pulse_info", {}).get("count", 0)))
    table.add_row("Country", str(result.get("country_name", "Unknown")))
    table.add_row("ASN", str(result.get("asn", "Unknown")))
    table.add_row("Reputation", str(result.get("reputation", "Unknown")))

    console.print(table)

    input("\nPress Enter...")
