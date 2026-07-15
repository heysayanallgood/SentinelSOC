import socket
from rich.console import Console

console = Console()

def port_scan():

    host = input("\nHost/IP: ")

    console.print("\nScanning...\n")

    for port in range(1,101):

        sock = socket.socket()

        sock.settimeout(0.5)

        result = sock.connect_ex((host,port))

        if result == 0:

            console.print(f"[green]Port {port} Open[/green]")

        sock.close()
