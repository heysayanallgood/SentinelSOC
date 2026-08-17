from rich.console import Console
from rich.panel import Panel

console = Console()

def threat_menu():

    console.print()

    console.print(
        Panel.fit(
            "[bold cyan]Threat Intelligence Center[/bold cyan]",
            border_style="cyan"
        )
    )

    console.print("[green]1[/green]  🌍 IP Reputation Lookup")
    console.print("[green]2[/green]  🔗 URL Reputation")
    console.print("[green]3[/green]  🦠 Malware Hash Lookup")
    console.print("[green]4[/green]  🛡 CVE Search")
    console.print("[green]5[/green]  📌 IOC Lookup")
    console.print("[green]6[/green]  ⚔ MITRE ATT&CK Lookup")
    console.print("[green]0[/green]  🔙 Back")

    choice = input("\nThreatIntel > ")

    return choice
