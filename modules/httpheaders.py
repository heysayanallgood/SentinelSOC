import requests
from rich.console import Console

console = Console()

def http_headers():

    url = input("\nEnter URL (https://...): ")

    try:

        response = requests.get(url)

        console.print(response.headers)

    except:

        console.print("[red]Request failed.[/red]")
