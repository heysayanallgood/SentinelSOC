from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.mitre_search import search

console = Console()


def run():
    while True:
        console.clear()

        console.print(
            Panel.fit(
                "[bold cyan]MITRE ATT&CK Enterprise Search[/bold cyan]"
            )
        )

        console.print("""
1. Search Technique ID
2. Search Technique Name
0. Back
""")

        choice = input("Choice: ").strip()

        if choice == "0":
            break

        elif choice == "1":
            keyword = input("Enter Technique ID (e.g. T1059): ").strip()

        elif choice == "2":
            keyword = input("Enter Technique Name: ").strip()

        else:
            console.print("[red]Invalid Choice[/red]")
            input("\nPress Enter...")
            continue

        results = search(keyword)

        if not results:
            console.print("\n[red]No techniques found.[/red]")
            input("\nPress Enter...")
            continue

        table = Table(title=f"Search Results ({len(results)})")

        table.add_column("Technique ID", style="cyan", no_wrap=True)
        table.add_column("Technique Name", style="green")
        table.add_column("Description", style="white")

        for tech in results:
            desc = tech["description"].replace("\n", " ")
            if len(desc) > 120:
                desc = desc[:120] + "..."

            table.add_row(
                tech["id"],
                tech["name"],
                desc
            )

        console.print(table)

        input("\nPress Enter to continue...")
