from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
import platform
import socket
import getpass
import datetime

console = Console()

# ---------------- SYSTEM PANEL ---------------- #

def system_panel():
    table = Table(show_header=False, expand=True)

    table.add_column(style="cyan")
    table.add_column(style="green")

    table.add_row("👤 User", getpass.getuser())
    table.add_row("💻 Platform", platform.system())
    table.add_row("⚙ Release", platform.release())
    table.add_row("🏗 Machine", platform.machine())
    table.add_row("🐍 Python", platform.python_version())
    table.add_row("🏠 Hostname", socket.gethostname())

    return Panel(table, title="👤 System Information", border_style="cyan")


# ---------------- STATUS PANEL ---------------- #

def status_panel():
    table = Table(show_header=False, expand=True)

    table.add_column(style="yellow")
    table.add_column(style="green")

    table.add_row("📅 Date", str(datetime.date.today()))
    table.add_row("🕒 Time", datetime.datetime.now().strftime("%H:%M:%S"))
    table.add_row("🌐 Internet", "🟢 Connected")
    table.add_row("🛡 Status", "Operational")
    table.add_row("📦 Version", "v0.3")

    return Panel(table, title="🌐 Live Status", border_style="green")


# ---------------- NETWORK PANEL ---------------- #

def network_panel():
    table = Table(show_header=False, expand=True)

    table.add_column(style="cyan")
    table.add_column(style="green")

    try:
        ip = socket.gethostbyname(socket.gethostname())
    except:
        ip = "Unavailable"

    table.add_row("🏠 Local IP", ip)
    table.add_row("📡 Host", socket.gethostname())
    table.add_row("🔌 Interface", "Termux")
    table.add_row("🌍 Public IP", "Coming Soon")

    return Panel(table, title="📡 Network", border_style="blue")


# ---------------- SECURITY PANEL ---------------- #

def security_panel():
    table = Table(show_header=False, expand=True)

    table.add_column(style="yellow")
    table.add_column(style="green")

    table.add_row("🔎 Port Scans", "0")
    table.add_row("🌐 DNS Queries", "0")
    table.add_row("📄 Reports", "0")
    table.add_row("🛡 Threat Checks", "0")

    return Panel(table, title="🛡 Security Summary", border_style="red")


# ---------------- ACTIVITY PANEL ---------------- #

def activity_panel():

    text = """[green]
✔ SentinelSOC Started

✔ Dashboard Loaded

✔ Ready...

[/green]"""

    return Panel(text, title="📜 Recent Activity", border_style="magenta")


# ---------------- QUICK ACTION PANEL ---------------- #

def quick_panel():

    text = """[cyan]

[1] Network Toolkit

[2] Threat Intelligence

[3] Log Analysis

[4] Digital Forensics

[5] Reports

[/cyan]"""

    return Panel(text, title="⚡ Quick Actions", border_style="yellow")


# ---------------- MAIN DASHBOARD ---------------- #

def create_dashboard():

    layout = Layout()

    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="footer", size=3)
    )

    layout["main"].split_column(
        Layout(name="row1"),
        Layout(name="row2"),
        Layout(name="row3")
    )

    layout["row1"].split_row(
        Layout(name="system"),
        Layout(name="status")
    )

    layout["row2"].split_row(
        Layout(name="network"),
        Layout(name="security")
    )

    layout["row3"].split_row(
        Layout(name="activity"),
        Layout(name="quick")
    )

    layout["header"].update(
        Panel(
            Align.center("[bold cyan]🛡 SentinelSOC Dashboard[/bold cyan]"),
            border_style="cyan"
        )
    )

    layout["system"].update(system_panel())
    layout["status"].update(status_panel())
    layout["network"].update(network_panel())
    layout["security"].update(security_panel())
    layout["activity"].update(activity_panel())
    layout["quick"].update(quick_panel())

    layout["footer"].update(
        Panel(
            Align.center("[bold green]Detect • Analyze • Defend | SentinelSOC v0.3[/bold green]"),
            border_style="green"
        )
    )

    console.print(layout)
