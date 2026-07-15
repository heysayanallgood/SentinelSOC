from rich.console import Console

from core.dashboard import create_dashboard
from modules.network import network
from modules.threatintel import threatintel
from modules.loganalysis import loganalysis
from modules.forensics import forensics
from modules.incident import incident
from modules.reporting import reporting

console = Console()

def route(choice):

    if choice == "1":
        create_dashboard()

    elif choice == "2":
        network()

    elif choice == "3":
        threatintel()

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
        console.print("Built by Sayan Chowdhury")

    elif choice == "0":
        console.print("[bold red]Goodbye![/bold red]")

    else:
        console.print("[red]Invalid Choice[/red]")
