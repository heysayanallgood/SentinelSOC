from rich.console import Console
from rich.panel import Panel

console = Console()

def run():

    console.print(
        Panel.fit(
            "⚔ MITRE ATT&CK Explorer",
            border_style="red"
        )
    )

    technique = input("Technique ID (Example T1059): ")

    console.print()

    console.print(f"[green]Searching for {technique}[/green]")

    console.print()

    console.print("https://attack.mitre.org")

    input("\nPress Enter...")
