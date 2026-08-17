from rich.console import Console

from modules.ping import ping_host
from modules.dnslookup import dns_lookup
from modules.whoislookup import whois_lookup
from modules.httpheaders import http_headers
from modules.reversedns import reverse_dns
from modules.portscanner import port_scan

console = Console()

def network():

    while True:

        console.print("\n[bold cyan]🌐 Network Toolkit[/bold cyan]\n")

        console.print("1. Ping Host")
        console.print("2. DNS Lookup")
        console.print("3. WHOIS Lookup")
        console.print("4. HTTP Header Analyzer")
        console.print("5. Reverse DNS")
        console.print("6. Port Scanner")
        console.print("0. Back")

        choice = input("\nNetwork > ")

        if choice=="1":
            ping_host()

        elif choice=="2":
            dns_lookup()

        elif choice=="3":
            whois_lookup()

        elif choice=="4":
            http_headers()

        elif choice=="5":
            reverse_dns()

        elif choice=="6":
            port_scan()

        elif choice=="0":
            break

        else:
            console.print("[red]Invalid Option[/red]")
