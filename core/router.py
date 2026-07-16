from rich.console import Console

from core.dashboard import create_dashboard

from modules.network import network
from modules.loganalysis import loganalysis
from modules.forensics import forensics
from modules.incident import incident
from modules.reporting import reporting

from modules import threatintel
from modules import iplookup
from modules import urlscan
from modules import hashlookup
from modules import cvelookup
from modules import ioclookup
from modules import mitre

console = Console()


def route(choice):

    if choice == "1":
        create_dashboard()

    elif choice == "2":
        network()

    elif choice == "3":

        while True:

            option = threatintel.threat_menu()

            if option == "1":
                iplookup.run()

            elif option == "2":
                urlscan.run()

            elif option == "3":
                hashlookup.run()

            elif option == "4":
                cvelookup.run()

            elif option == "5":
                ioclookup.run()

            elif option == "6":
                mitre.run()

            elif option == "0":
                break

            else:
                console.print("[red]Invalid Option[/red]")

    elif choice == "4":
        loganalysis()

    elif choice == "5":
        forensics()

    elif choice == "6":
        incident()

    elif choice == "7":
        reporting()

    elif choice == "8":
        console.print("[cyan]Settings Module Coming Soon[/cyan]")

    elif choice == "9":
        console.print("[green]SentinelSOC v1.0[/green]")
        console.print("[cyan]Built by Sayan Chowdhury[/cyan]")

    elif choice == "0":
        console.print("[bold red]Goodbye![/bold red]")

    else:
        console.print("[red]Invalid Choice[/red]")
