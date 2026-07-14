from rich.console import Console

console = Console()

def route(choice):

    if choice == "1":
        console.print("[green]Opening Dashboard...[/green]")

    elif choice == "2":
        console.print("[cyan]Opening Network Analysis...[/cyan]")

    elif choice == "3":
        console.print("[yellow]Opening Threat Intelligence...[/yellow]")

    elif choice == "4":
        console.print("[magenta]Opening Log Analysis...[/magenta]")

    elif choice == "5":
        console.print("[blue]Opening Digital Forensics...[/blue]")

    elif choice == "6":
        console.print("[red]Opening Incident Response...[/red]")

    elif choice == "7":
        console.print("[white]Opening Reports...[/white]")

    elif choice == "0":
        console.print("[bold red]Goodbye![/bold red]")

    else:
        console.print("[bold red]Invalid Choice![/bold red]")
