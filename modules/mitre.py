import os
import re
import json
import sqlite3
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "assets", "mitre", "sentinel_mitre.db"
)


# ============================================================
# DATABASE
# ============================================================

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# STIX / MITRE HELPERS
# ============================================================

def raw(obj):
    try:
        return json.loads(obj["raw_json"] or "{}")
    except Exception:
        return {}


def attack_id(obj):
    data = raw(obj)

    for ref in data.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            if ref.get("external_id"):
                return ref["external_id"]

    match = re.search(
        r'"external_id"\s*:\s*"((?:T|G|S|M)\d+(?:\.\d+)?)"',
        obj["raw_json"] or ""
    )

    return match.group(1) if match else ""


def tactics(obj):
    data = raw(obj)

    result = []

    for phase in data.get("kill_chain_phases", []):
        name = phase.get("phase_name", "")

        if name:
            name = name.replace("-", " ").title()

            if name not in result:
                result.append(name)

    return result


def aliases(obj):
    data = raw(obj)

    result = []

    for key in ("aliases", "x_mitre_aliases"):
        values = data.get(key, [])

        if isinstance(values, list):
            result.extend(values)

    return list(dict.fromkeys(result))


def attribution(obj):
    data = raw(obj)

    # Look for explicit attribution-like fields if present
    for key in (
        "x_mitre_attribution",
        "x_mitre_country",
        "country",
        "countries",
        "origin",
        "x_mitre_origin"
    ):
        value = data.get(key)

        if value:
            if isinstance(value, list):
                return ", ".join(map(str, value))
            return str(value)

    return "Not specified by MITRE ATT&CK"


# ============================================================
# TECHNIQUE SEARCH
# ============================================================

def search_id():
    value = input(
        "Technique ID (example T1078 or T1059.001): "
    ).strip().upper()

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM objects
        WHERE type='attack-pattern'
        """
    ).fetchall()

    conn.close()

    results = [
        row for row in rows
        if attack_id(row).upper() == value
    ]

    if not results:
        console.print(
            "[bold red]No technique found.[/bold red]"
        )
        return

    for row in results:
        technique_profile(row)


def search_name():
    value = input(
        "Technique Name: "
    ).strip().lower()

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM objects
        WHERE type='attack-pattern'
        AND LOWER(name) LIKE ?
        ORDER BY name
        """,
        (f"%{value}%",)
    ).fetchall()

    conn.close()

    if not rows:
        console.print(
            "[bold red]No techniques found.[/bold red]"
        )
        return

    show_technique_results(rows)


def show_technique_results(rows):

    table = Table(
        title=f"MITRE ATT&CK Techniques ({len(rows)})"
    )

    table.add_column("ID", style="cyan")
    table.add_column("Technique", style="green")
    table.add_column("Tactics", style="yellow")
    table.add_column("Description")

    for obj in rows:

        table.add_row(
            attack_id(obj) or "N/A",
            obj["name"] or "Unknown",
            ", ".join(tactics(obj)) or "N/A",
            (obj["description"] or "No description")[:300]
        )

    console.print(table)


# ============================================================
# TECHNIQUE PROFILE
# ============================================================

def technique_profile(technique):

    conn = db()

    relationships = conn.execute(
        """
        SELECT *
        FROM relationships
        WHERE source_ref=?
           OR target_ref=?
        """,
        (technique["id"], technique["id"])
    ).fetchall()

    groups = {}
    campaigns = {}

    for rel in relationships:

        other_id = (
            rel["target_ref"]
            if rel["source_ref"] == technique["id"]
            else rel["source_ref"]
        )

        obj = conn.execute(
            """
            SELECT *
            FROM objects
            WHERE id=?
            """,
            (other_id,)
        ).fetchone()

        if not obj:
            continue

        if obj["type"] == "intrusion-set":
            groups[obj["id"]] = obj

        elif obj["type"] == "campaign":
            campaigns[obj["id"]] = obj

    conn.close()

    console.print()

    console.print(
        Panel(
            f"[bold cyan]Technique ID:[/bold cyan] "
            f"{attack_id(technique) or 'N/A'}\n"
            f"[bold cyan]Technique:[/bold cyan] "
            f"{technique['name']}\n"
            f"[bold cyan]Tactics:[/bold cyan] "
            f"{', '.join(tactics(technique)) or 'N/A'}\n"
            f"[bold cyan]Associated Groups:[/bold cyan] "
            f"{len(groups)}\n"
            f"[bold cyan]Associated Campaigns:[/bold cyan] "
            f"{len(campaigns)}",
            title="⚔ MITRE ATT&CK TECHNIQUE PROFILE",
            border_style="cyan"
        )
    )

    console.print(
        Panel(
            technique["description"] or
            "No description available.",
            title="📖 MITRE DESCRIPTION",
            border_style="green"
        )
    )

    if groups:

        table = Table(
            title=f"🎯 Associated Threat Groups ({len(groups)})"
        )

        table.add_column("Group", style="red")
        table.add_column("Attribution", style="yellow")
        table.add_column("Aliases", style="cyan")

        for group in groups.values():

            table.add_row(
                group["name"] or "Unknown",
                attribution(group),
                ", ".join(aliases(group)) or "N/A"
            )

        console.print(table)


# ============================================================
# THREAT GROUP SEARCH
# ============================================================

def search_group():

    value = input(
        "Threat Group / Actor Name: "
    ).strip().lower()

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM objects
        WHERE type='intrusion-set'
        AND LOWER(name) LIKE ?
        ORDER BY name
        """,
        (f"%{value}%",)
    ).fetchall()

    conn.close()

    if not rows:

        # Search aliases as well
        conn = db()

        all_groups = conn.execute(
            """
            SELECT *
            FROM objects
            WHERE type='intrusion-set'
            """
        ).fetchall()

        conn.close()

        rows = [
            group
            for group in all_groups
            if value in " ".join(
                aliases(group)
            ).lower()
        ]

    if not rows:

        console.print(
            "[bold red]No threat groups found.[/bold red]"
        )
        return

    for group in rows:
        group_profile(group)


# ============================================================
# THREAT GROUP PROFILE
# ============================================================

def group_profile(group):

    conn = db()

    relationships = conn.execute(
        """
        SELECT *
        FROM relationships
        WHERE source_ref=?
           OR target_ref=?
        """,
        (group["id"], group["id"])
    ).fetchall()

    techniques = {}
    campaigns = {}
    software = {}

    for rel in relationships:

        other_id = (
            rel["target_ref"]
            if rel["source_ref"] == group["id"]
            else rel["source_ref"]
        )

        obj = conn.execute(
            """
            SELECT *
            FROM objects
            WHERE id=?
            """,
            (other_id,)
        ).fetchone()

        if not obj:
            continue

        if obj["type"] == "attack-pattern":
            techniques[obj["id"]] = obj

        elif obj["type"] == "campaign":
            campaigns[obj["id"]] = obj

        elif obj["type"] == "malware":
            software[obj["id"]] = obj

        elif obj["type"] == "tool":
            software[obj["id"]] = obj

    conn.close()

    console.print()

    console.print(
        Panel(
            f"[bold cyan]Threat Group:[/bold cyan] "
            f"{group['name']}\n"
            f"[cyan]MITRE Type:[/cyan] "
            f"{group['type']}\n"
            f"[cyan]Attribution:[/cyan] "
            f"{attribution(group)}\n"
            f"[cyan]Aliases:[/cyan] "
            f"{', '.join(aliases(group)) or 'N/A'}\n"
            f"[cyan]Associated Techniques:[/cyan] "
            f"{len(techniques)}\n"
            f"[cyan]Associated Campaigns:[/cyan] "
            f"{len(campaigns)}\n"
            f"[cyan]Associated Software:[/cyan] "
            f"{len(software)}",
            title="⚔ MITRE ATT&CK THREAT ACTOR PROFILE",
            border_style="red"
        )
    )

    console.print(
        Panel(
            group["description"] or
            "No description available.",
            title="📖 GROUP DESCRIPTION",
            border_style="green"
        )
    )

    if techniques:

        table = Table(
            title=f"🎯 Techniques Associated With {group['name']}"
        )

        table.add_column("ID", style="cyan")
        table.add_column("Technique", style="green")
        table.add_column("Tactics", style="yellow")

        for technique in techniques.values():

            table.add_row(
                attack_id(technique) or "N/A",
                technique["name"] or "Unknown",
                ", ".join(tactics(technique)) or "N/A"
            )

        console.print(table)

    if campaigns:

        table = Table(
            title="📌 Associated Campaigns"
        )

        table.add_column("Campaign", style="magenta")
        table.add_column("Description")

        for campaign in campaigns.values():

            table.add_row(
                campaign["name"] or "Unknown",
                (campaign["description"] or "N/A")[:300]
            )

        console.print(table)


# ============================================================
# TACTIC SEARCH
# ============================================================

def search_tactic():

    value = input(
        "Tactic name: "
    ).strip().lower()

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM objects
        WHERE type='attack-pattern'
        """
    ).fetchall()

    conn.close()

    results = []

    for obj in rows:

        obj_tactics = [
            x.lower()
            for x in tactics(obj)
        ]

        if any(
            value in tactic
            for tactic in obj_tactics
        ):
            results.append(obj)

    if not results:

        console.print(
            "[bold red]No techniques found for this tactic.[/bold red]"
        )
        return

    console.print(
        Panel(
            f"Tactic: {value.title()}\n"
            f"Techniques: {len(results)}",
            title="🎯 MITRE ATT&CK TACTIC",
            border_style="yellow"
        )
    )

    show_technique_results(results)


# ============================================================
# LIST EVERYTHING
# ============================================================

def list_techniques():

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM objects
        WHERE type='attack-pattern'
        ORDER BY name
        """
    ).fetchall()

    conn.close()

    show_technique_results(rows)


def list_groups():

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM objects
        WHERE type='intrusion-set'
        ORDER BY name
        """
    ).fetchall()

    conn.close()

    table = Table(
        title=f"MITRE ATT&CK Threat Groups ({len(rows)})"
    )

    table.add_column("#", style="cyan")
    table.add_column("Group", style="green")
    table.add_column("Attribution", style="yellow")
    table.add_column("Aliases", style="magenta")

    for i, group in enumerate(rows, 1):

        table.add_row(
            str(i),
            group["name"] or "Unknown",
            attribution(group),
            ", ".join(aliases(group)) or "N/A"
        )

    console.print(table)


def list_tactics():

    conn = db()

    rows = conn.execute(
        """
        SELECT *
        FROM objects
        WHERE type='attack-pattern'
        """
    ).fetchall()

    conn.close()

    tactic_map = {}

    for obj in rows:

        for tactic in tactics(obj):

            tactic_map.setdefault(
                tactic,
                []
            ).append(obj)

    table = Table(
        title=f"MITRE ATT&CK Tactics ({len(tactic_map)})"
    )

    table.add_column("Tactic", style="yellow")
    table.add_column("Techniques", style="cyan")

    for tactic, techniques_list in sorted(
        tactic_map.items()
    ):

        table.add_row(
            tactic,
            str(len(techniques_list))
        )

    console.print(table)


# ============================================================
# MAIN MENU
# ============================================================

def run():

    while True:

        console.print()

        console.print(
            Panel(
                "MITRE ATT&CK Intelligence Center\n"
                "Dynamic Local SQLite Threat Knowledge Base",
                border_style="cyan"
            )
        )

        console.print(
            "[cyan]1.[/cyan] Search Technique ID\n"
            "[cyan]2.[/cyan] Search Technique Name\n"
            "[cyan]3.[/cyan] Search Threat Group\n"
            "[cyan]4.[/cyan] Search Tactic\n"
            "[cyan]5.[/cyan] List All Techniques\n"
            "[cyan]6.[/cyan] List All Threat Groups\n"
            "[cyan]7.[/cyan] List All Tactics\n"
            "[cyan]0.[/cyan] Back"
        )

        choice = input("\nMITRE > ").strip()

        if choice == "1":
            search_id()

        elif choice == "2":
            search_name()

        elif choice == "3":
            search_group()

        elif choice == "4":
            search_tactic()

        elif choice == "5":
            list_techniques()

        elif choice == "6":
            list_groups()

        elif choice == "7":
            list_tactics()

        elif choice == "0":
            break

        else:
            console.print(
                "[bold red]Invalid option.[/bold red]"
            )

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    run()
