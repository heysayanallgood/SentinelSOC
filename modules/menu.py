from rich.console import Console
from rich.table import Table

console = Console()

def show_menu():
    table = Table(title="Main Menu")

    table.add_column("Option", style="cyan")
    table.add_column("Module", style="green")

    table.add_row("1", "Dashboard")
    table.add_row("2", "Network Analysis")
    table.add_row("3", "Threat Intelligence")
    table.add_row("4", "Log Analysis")
    table.add_row("5", "Digital Forensics")
    table.add_row("6", "Incident Response")
    table.add_row("7", "Reporting")
    table.add_row("0", "Exit")

    console.print(table)
