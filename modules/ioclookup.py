import re

from rich.console import Console
from rich.panel import Panel

console = Console()


def detect(value):

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
        return "IPv4"

    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "MD5"

    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "SHA1"

    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "SHA256"

    if value.startswith("http"):
        return "URL"

    return "Domain"


def run():

    console.print(
        Panel.fit(
            "[bold cyan]IOC Analyzer[/bold cyan]"
        )
    )

    value = input("\nIOC : ")

    t = detect(value)

    console.print(f"\nDetected Type : [green]{t}[/green]")

    console.print("\nAlienVault Integration coming next...")

    input("\nPress Enter...")
