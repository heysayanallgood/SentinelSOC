import socket
from rich.console import Console

console = Console()

def reverse_dns():

    ip = input("\nEnter IP Address: ")

    try:

        host = socket.gethostbyaddr(ip)

        console.print(f"\nHostname : {host[0]}")

    except:

        console.print("[red]Reverse lookup failed.[/red]")
