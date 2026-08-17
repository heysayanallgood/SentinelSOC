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
from modules.settings import settings_menu
from modules.about import about_menu

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
        loganalysis.run()

    elif choice == "5":
        from modules.digital_forensics import menu as digital_forensics_menu
        digital_forensics_menu()
    elif choice == "6":
        from modules.incident_response import menu as incident_response_menu
        incident_response_menu()
    elif choice == "7":
        reporting()

    elif choice == "8":
        try:
            settings_menu()
        except KeyboardInterrupt:
            print("\n[i] Settings operation cancelled.")
        except Exception as exc:
            print(f"\n[!] Settings module error: {exc}")
    elif choice == "9":
        try:
            about_menu()
        except KeyboardInterrupt:
            print("\n[i] About dossier cancelled.")
        except Exception as exc:
            print(f"\n[!] About module error: {exc}")
    elif choice == "0":
        console.print("[bold red]Goodbye![/bold red]")

    else:
        console.print("[red]Invalid Choice[/red]")
