from rich.console import Console
import subprocess
import platform

console = Console()

def ping_host():

    host = input("\nEnter Host/IP: ")

    if platform.system().lower() == "windows":
        command = ["ping", "-n", "4", host]
    else:
        command = ["ping", "-c", "4", host]

    try:
        subprocess.run(command)
    except Exception as e:
        console.print(f"[red]{e}[/red]")
