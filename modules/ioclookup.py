from rich.console import Console

console = Console()

def run():

    ioc = input("Enter IOC: ")

    console.print()

    if "." in ioc:

        console.print("[yellow]Looks like Domain/IP[/yellow]")

    else:

        console.print("[yellow]Looks like File Hash/String[/yellow]")

    input("\nPress Enter...")
