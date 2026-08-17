import socket
from rich.console import Console

console = Console()

def dns_lookup():

    host = input("\nEnter Domain: ")

    try:
        ip = socket.gethostbyname(host)

        console.print(f"\n[green]IP Address : {ip}[/green]")

    except Exception:

        console.print("[red]Unable to resolve domain.[/red]")
