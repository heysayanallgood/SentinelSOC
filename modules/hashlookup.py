from rich.console import Console
from rich.table import Table

from core.vt_hash import hash_lookup

console = Console()


def run():

    console.print("\n[bold cyan]🦠 Malware Hash Lookup[/bold cyan]\n")

    file_hash = input("Enter MD5/SHA1/SHA256: ").strip()

    console.print("\n[yellow]Querying VirusTotal...[/yellow]\n")

    result = hash_lookup(file_hash)

    if result is None:
        console.print("[red]Hash not found or API Error[/red]")
        input("\nPress Enter...")
        return

    data = result["data"]["attributes"]

    stats = data["last_analysis_stats"]

    table = Table(title="VirusTotal Malware Report")

    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Meaningful Name", str(data.get("meaningful_name", "Unknown")))
    table.add_row("File Type", str(data.get("type_description", "Unknown")))
    table.add_row("Size", str(data.get("size", "Unknown")) + " bytes")
    table.add_row("Malicious", str(stats.get("malicious", 0)))
    table.add_row("Suspicious", str(stats.get("suspicious", 0)))
    table.add_row("Harmless", str(stats.get("harmless", 0)))
    table.add_row("Undetected", str(stats.get("undetected", 0)))

    console.print(table)

    if stats.get("malicious", 0) > 0:
        console.print("\n[bold red]⚠ MALICIOUS FILE DETECTED[/bold red]")
    else:
        console.print("\n[bold green]✓ No malicious detections[/bold green]")

    input("\nPress Enter...")
