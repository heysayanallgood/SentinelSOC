import socket
from rich.console import Console
from rich.panel import Panel

console = Console()

def run():

    console.print(
        Panel.fit(
            "🌍 IP Information",
            border_style="cyan"
        )
    )

    ip = input("Enter IP or Hostname: ")

    try:

        resolved = socket.gethostbyname(ip)

        console.print()

        console.print(f"[green]Resolved IP : {resolved}")

    except Exception:

        console.print("[red]Unable to resolve[/red]")

    input("\nPress Enter...")



