import hashlib
from rich.console import Console

console = Console()

def run():

    text = input("Enter text/file string: ")

    md5 = hashlib.md5(text.encode()).hexdigest()
    sha256 = hashlib.sha256(text.encode()).hexdigest()

    console.print()

    console.print(f"[cyan]MD5[/cyan]     : {md5}")
    console.print(f"[green]SHA256[/green] : {sha256}")

    input("\nPress Enter...")
