import whois
from rich.console import Console

console = Console()

def whois_lookup():

    domain = input("\nEnter Domain: ")

    try:

        data = whois.whois(domain)

        console.print(data)

    except:

        console.print("[red]WHOIS lookup failed.[/red]")
