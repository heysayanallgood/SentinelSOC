from rich.console import Console
from rich.table import Table

from core.vt_api import url_lookup

console = Console()


def run():

    console.print("\n[bold cyan]URL Reputation Lookup[/bold cyan]\n")

    url = input("Enter URL: ").strip()

    result = url_lookup(url)

    if result is None:
        console.print("[red]Unable to retrieve VirusTotal data.[/red]")
        input("\nPress Enter...")
        return

    stats = result["data"]["attributes"]["last_analysis_stats"]

    table = Table(title="VirusTotal URL Report")

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    for key, value in stats.items():
        table.add_row(key.capitalize(), str(value))

    console.print(table)

    input("\nPress Enter...")
