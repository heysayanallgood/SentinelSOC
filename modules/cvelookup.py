from rich.console import Console
from rich.panel import Panel

console = Console()

def run():

    console.print(Panel.fit("🛡 CVE Lookup"))

    cve = input("Enter CVE ID: ")

    console.print()

    console.print(f"[green]Searching for {cve}[/green]")

    console.print()

    console.print("Visit https://nvd.nist.gov/vuln/search")

    input("\nPress Enter...")
