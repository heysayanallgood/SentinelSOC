import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def resolve_target(target):
    """
    Resolve hostname/domain to an IPv4 address.
    If an IP is supplied, it is returned directly.
    """

    target = target.strip()

    if not target:
        return None

    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan_port(target, port, timeout=0.5):
    """
    Scan a single TCP port.

    Returns:
        (port, is_open, latency_ms, service)
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start = time.perf_counter()

    try:
        result = sock.connect_ex((target, port))

        latency = (time.perf_counter() - start) * 1000

        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"

            return port, True, latency, service

        return port, False, latency, None

    except (socket.timeout, socket.error):
        return port, False, 0, None

    finally:
        sock.close()


def port_scan():
    """
    Interactive SentinelSOC TCP port scanner.
    """

    console.clear()

    console.print(
        Panel.fit(
            "[bold cyan]🌐 SentinelSOC Port Scanner[/bold cyan]\n"
            "[green]Dynamic TCP Connect Scanner[/green]",
            border_style="cyan"
        )
    )

    target_input = input("\nEnter Host/IP: ").strip()

    if not target_input:
        console.print("[red]No target entered.[/red]")
        input("\nPress Enter...")
        return

    console.print("\n[yellow]Resolving target...[/yellow]")

    target_ip = resolve_target(target_input)

    if not target_ip:
        console.print(
            f"[red]Unable to resolve target:[/red] {target_input}"
        )
        input("\nPress Enter...")
        return

    console.print(
        f"[green]Target:[/green] {target_input}"
    )

    console.print(
        f"[green]Resolved IP:[/green] {target_ip}"
    )

    # -----------------------------
    # PORT RANGE
    # -----------------------------

    console.print("\n[cyan]Port Range[/cyan]")
    console.print("Examples: 1-1000, 20-80, 443")

    port_range = input("Enter port range [1-1000]: ").strip()

    if not port_range:
        port_range = "1-1000"

    try:

        if "-" in port_range:

            parts = port_range.split("-", 1)

            start_port = int(parts[0])
            end_port = int(parts[1])

        else:

            start_port = int(port_range)
            end_port = start_port

        if start_port < 1 or end_port > 65535:
            raise ValueError

        if start_port > end_port:
            raise ValueError

    except ValueError:

        console.print(
            "[red]Invalid port range.[/red]"
        )

        input("\nPress Enter...")
        return

    ports = range(start_port, end_port + 1)

    total_ports = end_port - start_port + 1

    console.print(
        f"\n[cyan]Scanning:[/cyan] "
        f"{target_ip}:{start_port}-{end_port}"
    )

    console.print(
        f"[cyan]Ports:[/cyan] {total_ports}"
    )

    console.print(
        "[yellow]Starting TCP scan...[/yellow]\n"
    )

    start_time = time.perf_counter()

    open_ports = []

    # -----------------------------
    # MULTITHREADED SCAN
    # -----------------------------

    max_workers = 100

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                target_ip,
                port
            ): port
            for port in ports
        }

        completed = 0

        for future in as_completed(futures):

            completed += 1

            try:

                port, is_open, latency, service = future.result()

                if is_open:

                    open_ports.append(
                        (
                            port,
                            latency,
                            service
                        )
                    )

                    console.print(
                        f"[green][OPEN][/green] "
                        f"{port}/tcp "
                        f"[cyan]{service}[/cyan] "
                        f"({latency:.1f} ms)"
                    )

            except Exception:
                pass

    elapsed = time.perf_counter() - start_time

    open_ports.sort(key=lambda x: x[0])

    console.print(
        f"\n[cyan]Scan completed in "
        f"{elapsed:.2f} seconds.[/cyan]"
    )

    # -----------------------------
    # RESULTS TABLE
    # -----------------------------

    table = Table(
        title="SentinelSOC Port Scan Results",
        border_style="cyan"
    )

    table.add_column(
        "Port",
        style="cyan"
    )

    table.add_column(
        "Protocol",
        style="green"
    )

    table.add_column(
        "State",
        style="green"
    )

    table.add_column(
        "Service",
        style="yellow"
    )

    table.add_column(
        "Latency",
        style="magenta"
    )

    for port, latency, service in open_ports:

        table.add_row(
            str(port),
            "TCP",
            "OPEN",
            service,
            f"{latency:.1f} ms"
        )

    if open_ports:

        console.print()
        console.print(table)

        console.print(
            f"\n[green]Open ports found: "
            f"{len(open_ports)}[/green]"
        )

    else:

        console.print(
            "\n[yellow]No open TCP ports found "
            "in the selected range.[/yellow]"
        )

    input("\nPress Enter to continue...")
