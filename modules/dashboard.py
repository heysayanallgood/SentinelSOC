from rich.console import Console
from rich.table import Table
import platform
import socket
import datetime
import getpass

console = Console()

def show_dashboard():

    table = Table(title="🛡 SentinelSOC Dashboard")

    table.add_column("Information", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Current User", getpass.getuser())
    table.add_row("Platform", platform.system())
    table.add_row("Release", platform.release())
    table.add_row("Python", platform.python_version())
    table.add_row("Hostname", socket.gethostname())
    table.add_row("Date", str(datetime.datetime.now()))

    console.print(table)
