#!/usr/bin/env python3

"""
SentinelSOC - Dynamic Reporting Engine
=======================================

Dynamic defensive reporting engine for:
    HTML
    PDF
    JSON
    CSV
    IAM / Identity & Access Management

No sample data is generated.
All report content is collected from the current SentinelSOC
installation and the current host/Termux environment.

Designed for:
    Termux
    Kali Linux
    Debian/Ubuntu
    Android + Termux
    Other Linux-like environments

Compatibility:
    Existing SentinelSOC router/main.py
"""

from __future__ import annotations

import csv
import datetime as dt
import html
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


# ============================================================
# PATH CONFIGURATION
# ============================================================

MODULE_FILE = Path(__file__).resolve()
ROOT = MODULE_FILE.parent.parent

ASSETS = ROOT / "assets"
REPORTS = ROOT / "reports"
GENERATED = REPORTS / "generated"

INCIDENT_ROOT = ASSETS / "incident_response"
INCIDENT_EVIDENCE = INCIDENT_ROOT / "evidence"
INCIDENT_REPORTS = INCIDENT_ROOT / "reports"
INCIDENT_CASES = INCIDENT_ROOT / "cases"
INCIDENT_TRIAGE = INCIDENT_ROOT / "adhoc_triage"

GENERATED.mkdir(parents=True, exist_ok=True)


# ============================================================
# COLORS / UI
# ============================================================

RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BLUE = "\033[94m"
DIM = "\033[2m"


def c(text, color):
    return f"{color}{text}{RESET}"


def banner(title="SENTINELSOC | REPORTING ENGINE"):
    print()
    print(c("=" * 72, CYAN))
    print(c(f" {title}", CYAN))
    print(c("=" * 72, CYAN))


def pause():
    try:
        input("\nPress Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


# ============================================================
# GENERAL UTILITIES
# ============================================================

def now():
    return dt.datetime.now().astimezone()


def timestamp():
    return now().strftime("%Y%m%d_%H%M%S")


def iso_now():
    return now().isoformat()


def run_command(command, timeout=10):
    """
    Execute a local defensive collection command.

    No shell=True is used.
    Output is returned as text.
    """
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )

        output = result.stdout.strip()

        if not output and result.stderr:
            output = result.stderr.strip()

        return output

    except FileNotFoundError:
        return ""

    except subprocess.TimeoutExpired:
        return "[collector timeout]"

    except Exception as exc:
        return f"[collector error: {exc}]"


def command_exists(name):
    return shutil.which(name) is not None


def read_text(path, max_bytes=1024 * 1024):
    try:
        p = Path(path)

        if not p.exists() or not p.is_file():
            return ""

        with p.open("rb") as fh:
            data = fh.read(max_bytes)

        return data.decode("utf-8", errors="replace")

    except Exception:
        return ""


def file_metadata(path):
    p = Path(path)

    try:
        st = p.stat()

        return {
            "path": str(p),
            "exists": True,
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o777),
            "modified": dt.datetime.fromtimestamp(
                st.st_mtime
            ).astimezone().isoformat(),
        }

    except Exception as exc:
        return {
            "path": str(p),
            "exists": False,
            "error": str(exc),
        }


def safe_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def json_size_mb(path):
    try:
        return round(Path(path).stat().st_size / (1024 * 1024), 2)
    except Exception:
        return 0


# ============================================================
# SYSTEM COLLECTION
# ============================================================

def collect_system():
    data = {
        "timestamp": iso_now(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "architecture": platform.architecture()[0],
        "python": platform.python_version(),
        "cwd": str(Path.cwd()),
        "sentinelsoc_root": str(ROOT),
    }

    uptime = Path("/proc/uptime")

    if uptime.exists():
        try:
            seconds = float(
                uptime.read_text(errors="replace").split()[0]
            )

            data["uptime_seconds"] = seconds
            data["uptime_human"] = format_duration(seconds)

        except Exception:
            pass

    if command_exists("getprop"):
        data["android_version"] = run_command(
            ["getprop", "ro.build.version.release"]
        )

        data["android_sdk"] = run_command(
            ["getprop", "ro.build.version.sdk"]
        )

        data["android_device"] = run_command(
            ["getprop", "ro.product.model"]
        )

        data["android_manufacturer"] = run_command(
            ["getprop", "ro.product.manufacturer"]
        )

    return data


def format_duration(seconds):
    try:
        seconds = int(seconds)

        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)

        parts = []

        if days:
            parts.append(f"{days}d")

        if hours:
            parts.append(f"{hours}h")

        if minutes:
            parts.append(f"{minutes}m")

        parts.append(f"{seconds}s")

        return " ".join(parts)

    except Exception:
        return "unknown"


# ============================================================
# PROCESS COLLECTION
# ============================================================

def collect_processes():
    rows = []

    command = [
        "ps",
        "-eo",
        "pid,ppid,user,stat,comm,args",
        "--no-headers",
    ]

    output = run_command(command, timeout=8)

    if output.startswith("[collector"):
        return {
            "count": 0,
            "processes": [],
            "raw": output,
        }

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split(None, 5)

        if len(parts) < 5:
            continue

        row = {
            "pid": parts[0],
            "ppid": parts[1] if len(parts) > 1 else "",
            "user": parts[2] if len(parts) > 2 else "",
            "stat": parts[3] if len(parts) > 3 else "",
            "command": parts[4] if len(parts) > 4 else "",
            "args": parts[5] if len(parts) > 5 else "",
        }

        rows.append(row)

    return {
        "count": len(rows),
        "processes": rows,
    }


# ============================================================
# NETWORK COLLECTION
# ============================================================

def collect_network():
    output = ""

    if command_exists("ss"):
        output = run_command(
            ["ss", "-tunap"],
            timeout=10,
        )

    elif command_exists("netstat"):
        output = run_command(
            ["netstat", "-tunap"],
            timeout=10,
        )

    elif Path("/proc/net/tcp").exists():
        output = read_text("/proc/net/tcp")

    return {
        "tool": (
            "ss"
            if command_exists("ss")
            else "netstat"
            if command_exists("netstat")
            else "/proc/net/tcp"
        ),
        "raw": output,
        "lines": output.splitlines()[:300],
    }


def collect_listening_ports():
    output = ""

    if command_exists("ss"):
        output = run_command(
            ["ss", "-lntup"],
            timeout=10,
        )

    elif command_exists("netstat"):
        output = run_command(
            ["netstat", "-lntup"],
            timeout=10,
        )

    ports = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith(("netid", "active", "proto")):
            continue

        matches = re.findall(
            r"(?:\*|0\.0\.0\.0|\[::\]|::):(\d+)",
            line,
        )

        for port in matches:

            item = {
                "port": int(port),
                "line": line,
            }

            if item not in ports:
                ports.append(item)

    return {
        "count": len(ports),
        "ports": ports,
        "raw": output,
    }


# ============================================================
# PERSISTENCE COLLECTION
# ============================================================

def collect_persistence():

    candidates = [
        Path.home() / ".bashrc",
        Path.home() / ".profile",
        Path.home() / ".bash_profile",
        Path.home() / ".zshrc",
        Path.home() / ".config/autostart",
        Path.home() / ".termux/boot",
        Path("/etc/rc.local"),
        Path("/etc/crontab"),
        Path("/etc/systemd/system"),
        Path("/etc/systemd/user"),
    ]

    found = []

    for p in candidates:

        if not p.exists():
            continue

        info = file_metadata(p)

        if p.is_dir():
            try:
                children = []

                for child in p.iterdir():
                    children.append(
                        file_metadata(child)
                    )

                info["children"] = children[:100]

            except Exception:
                info["children"] = []

        else:
            content = read_text(p, max_bytes=100_000)

            info["lines"] = len(content.splitlines())

            suspicious_terms = [
                "curl ",
                "wget ",
                "nc ",
                "netcat",
                "python ",
                "bash -c",
                "sh -c",
                "base64",
            ]

            info["interesting_lines"] = [
                line.strip()
                for line in content.splitlines()
                if any(term in line.lower() for term in suspicious_terms)
            ][:50]

        found.append(info)

    cron = run_command(
        ["sh", "-c", "crontab -l 2>/dev/null"],
        timeout=5,
    )

    return {
        "locations": found,
        "crontab": cron.splitlines()[:100],
    }


# ============================================================
# SENTINELSOC DATABASE COLLECTION
# ============================================================

def database_tables(db_path):

    db = Path(db_path)

    if not db.exists():
        return []

    tables = []

    try:

        with sqlite3.connect(str(db)) as conn:

            rows = conn.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                ORDER BY name
                """
            ).fetchall()

            for row in rows:

                table = row[0]

                if table.startswith("sqlite_"):
                    continue

                try:
                    count = conn.execute(
                        f'SELECT COUNT(*) FROM "{table}"'
                    ).fetchone()[0]
                except Exception:
                    count = None

                columns = []

                try:
                    info = conn.execute(
                        f'PRAGMA table_info("{table}")'
                    ).fetchall()

                    columns = [
                        x[1]
                        for x in info
                    ]

                except Exception:
                    pass

                tables.append({
                    "name": table,
                    "rows": count,
                    "columns": columns,
                })

    except Exception as exc:
        return [{
            "error": str(exc)
        }]

    return tables


def collect_databases():

    candidates = []

    direct = [
        ASSETS / "sentinel_events.db",
        INCIDENT_ROOT / "incidents.db",
        INCIDENT_ROOT / "cases.db",
    ]

    for db in direct:

        if db.exists():
            candidates.append(db)

    for base in [ASSETS, INCIDENT_ROOT, ROOT / "data"]:

        if not base.exists():
            continue

        try:

            for db in base.rglob("*.db"):

                if db not in candidates:
                    candidates.append(db)

        except Exception:
            pass

    databases = []

    for db in candidates:

        info = file_metadata(db)

        info["size_mb"] = json_size_mb(db)
        info["tables"] = database_tables(db)

        databases.append(info)

    return {
        "count": len(databases),
        "databases": databases,
    }


# ============================================================
# SENTINELSOC EVENT COLLECTION
# ============================================================

def collect_events():

    db_candidates = [
        ASSETS / "sentinel_events.db",
        INCIDENT_ROOT / "incidents.db",
        INCIDENT_ROOT / "cases.db",
    ]

    for db in db_candidates:

        if not db.exists():
            continue

        try:

            with sqlite3.connect(str(db)) as conn:

                tables = database_tables(db)

                total = 0

                for table in tables:

                    if "name" not in table:
                        continue

                    rows = table.get("rows")

                    if isinstance(rows, int):
                        total += rows

                return {
                    "database": str(db),
                    "total_rows": total,
                    "tables": tables,
                }

        except Exception:
            continue

    return {
        "database": None,
        "total_rows": 0,
        "tables": [],
    }


# ============================================================
# INCIDENT / EVIDENCE COLLECTION
# ============================================================

def inventory_directory(path, max_items=300):

    p = Path(path)

    if not p.exists():
        return []

    result = []

    try:

        for item in p.rglob("*"):

            if len(result) >= max_items:
                break

            if item.is_file():
                result.append(file_metadata(item))

    except Exception:
        pass

    return result


def collect_incidents():

    return {
        "incident_root": str(INCIDENT_ROOT),
        "evidence": inventory_directory(
            INCIDENT_EVIDENCE
        ),
        "reports": inventory_directory(
            INCIDENT_REPORTS
        ),
        "cases": inventory_directory(
            INCIDENT_CASES
        ),
        "triage": inventory_directory(
            INCIDENT_TRIAGE
        ),
    }


# ============================================================
# MITRE STATUS
# ============================================================

def collect_mitre():

    possible = [
        ASSETS / "mitre",
        ROOT / "data",
        ROOT / "modules",
    ]

    found = []

    for base in possible:

        if not base.exists():
            continue

        try:

            for p in base.rglob("*"):

                if not p.is_file():
                    continue

                name = p.name.lower()

                if "mitre" in name or "enterprise-attack" in name:

                    found.append({
                        "path": str(p),
                        "size_mb": json_size_mb(p),
                        "exists": True,
                    })

        except Exception:
            pass

    return {
        "artifacts": found[:200],
    }


# ============================================================
# IAM COLLECTION
# ============================================================

def collect_local_identity():

    identity = {
        "id": run_command(["id"]),
        "whoami": run_command(["whoami"]),
        "groups": run_command(["id", "-Gn"]),
    }

    passwd = Path("/etc/passwd")

    users = []

    if passwd.exists():

        content = read_text(passwd)

        for line in content.splitlines():

            parts = line.split(":")

            if len(parts) >= 7:

                try:
                    uid = int(parts[2])
                except Exception:
                    uid = -1

                try:
                    gid = int(parts[3])
                except Exception:
                    gid = -1

                users.append({
                    "username": parts[0],
                    "uid": uid,
                    "gid": gid,
                    "home": parts[5],
                    "shell": parts[6],
                })

    identity["local_users"] = users

    group_file = Path("/etc/group")

    groups = []

    if group_file.exists():

        content = read_text(group_file)

        for line in content.splitlines():

            parts = line.split(":")

            if len(parts) >= 4:

                groups.append({
                    "group": parts[0],
                    "gid": parts[2],
                    "members": [
                        x for x in parts[3].split(",")
                        if x
                    ],
                })

    identity["local_groups"] = groups

    return identity


def collect_android_users():

    outputs = []

    commands = [
        ["cmd", "user", "list"],
        ["pm", "list", "users"],
    ]

    for command in commands:

        if not command_exists(command[0]):
            continue

        output = run_command(
            command,
            timeout=10,
        )

        if output:
            outputs.append({
                "command": " ".join(command),
                "output": output.splitlines()[:200],
            })

    return outputs


def collect_android_packages():

    commands = [
        ["cmd", "package", "list", "packages", "-U"],
        ["pm", "list", "packages", "-U"],
    ]

    output = ""

    for command in commands:

        if command_exists(command[0]):

            output = run_command(
                command,
                timeout=20,
            )

            if output:
                break

    packages = []

    for line in output.splitlines():

        line = line.strip()

        if not line.startswith("package:"):
            continue

        package_name = line

        uid = None

        match = re.search(
            r"uid:(\d+)",
            line,
            re.IGNORECASE,
        )

        if match:
            uid = int(match.group(1))

        package_name = re.sub(
            r"\s+uid:\d+.*$",
            "",
            package_name,
            flags=re.IGNORECASE,
        )

        package_name = package_name.replace(
            "package:",
            "",
            1,
        )

        packages.append({
            "package": package_name.strip(),
            "uid": uid,
            "raw": line,
        })

    return {
        "count": len(packages),
        "packages": packages,
        "collector": (
            "cmd package"
            if output
            else "unavailable"
        ),
    }


def collect_ssh_metadata():

    ssh_dir = Path.home() / ".ssh"

    result = {
        "directory": str(ssh_dir),
        "exists": ssh_dir.exists(),
        "files": [],
    }

    if not ssh_dir.exists():
        return result

    try:

        for p in ssh_dir.iterdir():

            if not p.is_file():
                continue

            name = p.name.lower()

            # Never read private key contents.
            if (
                "private" in name
                or name.startswith("id_")
                and not name.endswith(".pub")
            ):
                classification = "potential_private_key"

            elif "authorized_keys" in name:
                classification = "authorized_keys"

            elif name.endswith(".pub"):
                classification = "public_key"

            else:
                classification = "ssh_file"

            info = file_metadata(p)

            info["classification"] = classification

            result["files"].append(info)

    except Exception:
        pass

    return result


def collect_iam():

    local = collect_local_identity()

    sudo = {
        "sudo_available": command_exists("sudo"),
        "sudo_path": shutil.which("sudo"),
    }

    ssh = collect_ssh_metadata()

    android_users = collect_android_users()
    android_packages = collect_android_packages()

    privileged_packages = []

    for package in android_packages.get("packages", []):

        uid = package.get("uid")

        if uid in (0, 1000, 2000):
            privileged_packages.append(package)

    return {
        "generated_at": iso_now(),
        "identity": local,
        "sudo": sudo,
        "android_users": android_users,
        "android_packages": android_packages,
        "privileged_packages": privileged_packages,
        "ssh": ssh,
    }


# ============================================================
# MASTER COLLECTION
# ============================================================

def collect_all():

    report = {
        "report": {
            "name": "SentinelSOC Dynamic Security Report",
            "generated_at": iso_now(),
            "generator": "SentinelSOC Reporting Engine",
            "version": "2.0",
            "sample_data": False,
        },

        "system": collect_system(),

        "processes": collect_processes(),

        "network": collect_network(),

        "listening_ports": collect_listening_ports(),

        "persistence": collect_persistence(),

        "databases": collect_databases(),

        "events": collect_events(),

        "incidents": collect_incidents(),

        "mitre": collect_mitre(),

        "iam": collect_iam(),
    }

    return report


# ============================================================
# SUMMARY
# ============================================================

def build_summary(data):

    processes = data.get("processes", {})
    network = data.get("network", {})
    ports = data.get("listening_ports", {})
    persistence = data.get("persistence", {})
    events = data.get("events", {})
    incidents = data.get("incidents", {})
    iam = data.get("iam", {})
    packages = iam.get("android_packages", {})

    return {
        "generated_at": data["report"]["generated_at"],
        "process_count": processes.get("count", 0),
        "network_lines": len(network.get("lines", [])),
        "listening_ports": ports.get("count", 0),
        "persistence_locations": len(
            persistence.get("locations", [])
        ),
        "event_records": events.get("total_rows", 0),
        "evidence_files": len(
            incidents.get("evidence", [])
        ),
        "case_files": len(
            incidents.get("cases", [])
        ),
        "incident_reports": len(
            incidents.get("reports", [])
        ),
        "android_packages": packages.get(
            "count", 0
        ),
        "privileged_packages": len(
            iam.get("privileged_packages", [])
        ),
        "local_users": len(
            iam.get("identity", {}).get(
                "local_users", []
            )
        ),
        "local_groups": len(
            iam.get("identity", {}).get(
                "local_groups", []
            )
        ),
        "ssh_files": len(
            iam.get("ssh", {}).get(
                "files", []
            )
        ),
    }


# ============================================================
# JSON REPORT
# ============================================================

def write_json(data):

    path = GENERATED / f"sentinelsoc_report_{timestamp()}.json"

    payload = dict(data)
    payload["summary"] = build_summary(data)

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fh:

        json.dump(
            payload,
            fh,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    return path


# ============================================================
# CSV REPORT
# ============================================================

def write_csv(data):

    path = GENERATED / f"sentinelsoc_report_{timestamp()}.csv"

    summary = build_summary(data)

    rows = []

    for key, value in summary.items():

        rows.append({
            "section": "summary",
            "item": key,
            "value": value,
        })

    for process in data.get(
        "processes",
        {}
    ).get("processes", []):

        rows.append({
            "section": "process",
            "item": process.get("pid", ""),
            "value": json.dumps(
                process,
                ensure_ascii=False,
            ),
        })

    for port in data.get(
        "listening_ports",
        {}
    ).get("ports", []):

        rows.append({
            "section": "listening_port",
            "item": port.get("port", ""),
            "value": port.get("line", ""),
        })

    for package in data.get(
        "iam",
        {}
    ).get("android_packages", {}).get(
        "packages",
        []
    ):

        rows.append({
            "section": "android_package",
            "item": package.get(
                "package",
                "",
            ),
            "value": package.get(
                "uid",
                "",
            ),
        })

    for user in data.get(
        "iam",
        {}
    ).get("identity", {}).get(
        "local_users",
        []
    ):

        rows.append({
            "section": "local_user",
            "item": user.get(
                "username",
                "",
            ),
            "value": json.dumps(
                user,
                ensure_ascii=False,
            ),
        })

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as fh:

        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "section",
                "item",
                "value",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)

    return path


# ============================================================
# TEXT REPRESENTATION
# ============================================================

def report_lines(data):

    lines = []

    summary = build_summary(data)

    lines.append(
        "SENTINELSOC DYNAMIC SECURITY REPORT"
    )
    lines.append(
        "=" * 72
    )
    lines.append(
        f"Generated: {data['report']['generated_at']}"
    )
    lines.append(
        "Sample data: NO"
    )
    lines.append("")

    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 72)

    for key, value in summary.items():

        lines.append(
            f"{key}: {value}"
        )

    lines.append("")

    lines.append("SYSTEM")
    lines.append("-" * 72)

    for key, value in data.get(
        "system",
        {}
    ).items():

        lines.append(
            f"{key}: {value}"
        )

    lines.append("")

    lines.append("PROCESS INVENTORY")
    lines.append("-" * 72)

    for process in data.get(
        "processes",
        {}
    ).get("processes", [])[:150]:

        lines.append(
            "{pid:>6} {user:<16} {command:<25} {args}".format(
                pid=process.get("pid", ""),
                user=process.get("user", "")[:16],
                command=process.get("command", "")[:25],
                args=process.get("args", "")[:120],
            )
        )

    lines.append("")

    lines.append("NETWORK")
    lines.append("-" * 72)

    for line in data.get(
        "network",
        {}
    ).get("lines", [])[:150]:

        lines.append(line[:200])

    lines.append("")

    lines.append("LISTENING PORTS")
    lines.append("-" * 72)

    for port in data.get(
        "listening_ports",
        {}
    ).get("ports", []):

        lines.append(
            f"Port {port.get('port')}: "
            f"{port.get('line', '')}"
        )

    lines.append("")

    lines.append("PERSISTENCE")
    lines.append("-" * 72)

    for item in data.get(
        "persistence",
        {}
    ).get("locations", []):

        lines.append(
            f"{item.get('path')} | "
            f"mode={item.get('mode', '')}"
        )

        for interesting in item.get(
            "interesting_lines",
            []
        ):

            lines.append(
                f"  interesting: {interesting}"
            )

    lines.append("")

    lines.append("SENTINELSOC DATABASES")
    lines.append("-" * 72)

    for db in data.get(
        "databases",
        {}
    ).get("databases", []):

        lines.append(
            f"{db.get('path')} | "
            f"{db.get('size_mb', 0)} MB"
        )

        for table in db.get(
            "tables",
            []
        ):

            lines.append(
                f"  table={table.get('name')} "
                f"rows={table.get('rows')}"
            )

    lines.append("")

    lines.append("INCIDENT / EVIDENCE INVENTORY")
    lines.append("-" * 72)

    incidents = data.get(
        "incidents",
        {}
    )

    lines.append(
        f"Evidence files: "
        f"{len(incidents.get('evidence', []))}"
    )

    lines.append(
        f"Case files: "
        f"{len(incidents.get('cases', []))}"
    )

    lines.append(
        f"Incident reports: "
        f"{len(incidents.get('reports', []))}"
    )

    lines.append(
        f"Triage artifacts: "
        f"{len(incidents.get('triage', []))}"
    )

    lines.append("")

    lines.append("IAM / IDENTITY & ACCESS MANAGEMENT")
    lines.append("-" * 72)

    iam = data.get(
        "iam",
        {}
    )

    identity = iam.get(
        "identity",
        {}
    )

    lines.append(
        f"Current identity: "
        f"{identity.get('whoami', '')}"
    )

    lines.append(
        f"Identity command: "
        f"{identity.get('id', '')}"
    )

    lines.append(
        f"Groups: "
        f"{identity.get('groups', '')}"
    )

    lines.append(
        f"Local users: "
        f"{len(identity.get('local_users', []))}"
    )

    lines.append(
        f"Local groups: "
        f"{len(identity.get('local_groups', []))}"
    )

    sudo = iam.get("sudo", {})

    lines.append(
        f"Sudo available: "
        f"{sudo.get('sudo_available')}"
    )

    android_users = iam.get(
        "android_users",
        []
    )

    lines.append(
        f"Android user collectors: "
        f"{len(android_users)}"
    )

    packages = iam.get(
        "android_packages",
        {}
    )

    lines.append(
        f"Android packages: "
        f"{packages.get('count', 0)}"
    )

    lines.append(
        f"Privileged package UIDs: "
        f"{len(iam.get('privileged_packages', []))}"
    )

    ssh = iam.get(
        "ssh",
        {}
    )

    lines.append(
        f"SSH metadata files: "
        f"{len(ssh.get('files', []))}"
    )

    lines.append("")

    lines.append("LOCAL USERS")
    lines.append("-" * 72)

    for user in identity.get(
        "local_users",
        []
    ):

        lines.append(
            f"{user.get('username')} "
            f"UID={user.get('uid')} "
            f"GID={user.get('gid')} "
            f"HOME={user.get('home')} "
            f"SHELL={user.get('shell')}"
        )

    lines.append("")

    lines.append("ANDROID / PACKAGE UID INVENTORY")
    lines.append("-" * 72)

    for package in packages.get(
        "packages",
        []
    )[:300]:

        lines.append(
            f"{package.get('package')} "
            f"UID={package.get('uid')}"
        )

    lines.append("")

    lines.append("SSH METADATA")
    lines.append("-" * 72)

    for item in ssh.get(
        "files",
        []
    ):

        lines.append(
            f"{item.get('path')} "
            f"class={item.get('classification')} "
            f"mode={item.get('mode')}"
        )

    lines.append("")

    lines.append("MITRE STATUS")
    lines.append("-" * 72)

    for artifact in data.get(
        "mitre",
        {}
    ).get("artifacts", []):

        lines.append(
            f"{artifact.get('path')} "
            f"{artifact.get('size_mb')} MB"
        )

    lines.append("")

    lines.append("=" * 72)
    lines.append("END OF SENTINELSOC DYNAMIC REPORT")
    lines.append("=" * 72)

    return lines


# ============================================================
# HTML REPORT
# ============================================================

def write_html(data):

    path = GENERATED / f"sentinelsoc_report_{timestamp()}.html"

    summary = build_summary(data)
    lines = report_lines(data)

    rows = ""

    for key, value in summary.items():

        rows += (
            "<tr>"
            f"<td>{html.escape(str(key))}</td>"
            f"<td>{html.escape(str(value))}</td>"
            "</tr>"
        )

    body = ""

    for line in lines:

        body += (
            "<div class='line'>"
            f"{html.escape(line)}"
            "</div>"
        )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>SentinelSOC Dynamic Security Report</title>

<style>

body {{
    margin: 0;
    background: #05070a;
    color: #e8f7ff;
    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        Consolas,
        monospace;
}}

header {{
    padding: 28px;
    border-bottom: 1px solid #00d9ff;
}}

h1 {{
    margin: 0;
    color: #00e5ff;
}}

h2 {{
    color: #00ff88;
}}

.container {{
    padding: 24px;
}}

.card {{
    border: 1px solid #174b5c;
    background: #081117;
    padding: 18px;
    margin-bottom: 20px;
    border-radius: 10px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    border: 1px solid #174b5c;
    padding: 8px;
    text-align: left;
}}

th {{
    color: #00e5ff;
}}

.line {{
    white-space: pre-wrap;
    line-height: 1.45;
}}

.footer {{
    color: #73838c;
    margin-top: 30px;
}}

</style>
</head>

<body>

<header>
<h1>SentinelSOC</h1>
<div>Dynamic Blue Team / SOC Security Report</div>
<div>Generated: {html.escape(data['report']['generated_at'])}</div>
</header>

<div class="container">

<div class="card">
<h2>Executive Summary</h2>

<table>
<tr>
<th>Metric</th>
<th>Value</th>
</tr>
{rows}
</table>

</div>

<div class="card">

<h2>Complete Dynamic Collection</h2>

{body}

</div>

<div class="footer">
SentinelSOC Reporting Engine — No sample data generated.
</div>

</div>

</body>
</html>
"""

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fh:

        fh.write(document)

    return path


# ============================================================
# MINIMAL NATIVE PDF ENGINE
# ============================================================

def pdf_escape(text):

    text = str(text)

    text = (
        text
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )

    return text.encode(
        "latin-1",
        "replace",
    ).decode("latin-1")


def write_native_pdf(path, lines):

    # A dependency-free PDF writer.
    # Uses Helvetica and ASCII-safe replacement for unsupported
    # Unicode characters.

    max_lines = 52
    pages = [
        lines[i:i + max_lines]
        for i in range(
            0,
            len(lines),
            max_lines,
        )
    ]

    if not pages:
        pages = [["SentinelSOC Dynamic Report"]]

    objects = []

    # Object 1: catalog
    objects.append(
        "<< /Type /Catalog /Pages 2 0 R >>"
    )

    # Object 2 is inserted later.
    objects.append("")

    # Object 3: font
    objects.append(
        "<< /Type /Font "
        "/Subtype /Type1 "
        "/BaseFont /Helvetica >>"
    )

    page_objects = []
    content_objects = []

    next_object = 4

    for page_lines in pages:

        page_obj = next_object
        content_obj = next_object + 1

        page_objects.append(page_obj)
        content_objects.append(content_obj)

        next_object += 2

    kids = " ".join(
        f"{obj} 0 R"
        for obj in page_objects
    )

    objects[1] = (
        "<< /Type /Pages "
        f"/Kids [{kids}] "
        f"/Count {len(page_objects)} >>"
    )

    for page_lines, page_obj, content_obj in zip(
        pages,
        page_objects,
        content_objects,
    ):

        content_lines = [
            "BT",
            "/F1 9 Tf",
            "40 790 Td",
            "11 TL",
        ]

        for line in page_lines:

            safe = pdf_escape(
                str(line)[:180]
            )

            content_lines.append(
                f"({safe}) Tj"
            )

            content_lines.append(
                "T*"
            )

        content_lines.append(
            "ET"
        )

        stream = "\n".join(
            content_lines
        )

        objects.append(
            "<< /Type /Page "
            "/Parent 2 0 R "
            "/MediaBox [0 0 595 842] "
            "/Resources << "
            "/Font << /F1 3 0 R >> "
            ">> "
            f"/Contents {content_obj} 0 R >>"
        )

        objects.append(
            "<< "
            f"/Length {len(stream.encode('latin-1'))}"
            " >>\n"
            "stream\n"
            f"{stream}\n"
            "endstream"
        )

    output = bytearray()
    output.extend(b"%PDF-1.4\n")
    output.extend(b"%\xe2\xe3\xcf\xd3\n")

    offsets = [0]

    for number, obj in enumerate(
        objects,
        start=1,
    ):

        offsets.append(
            len(output)
        )

        output.extend(
            f"{number} 0 obj\n".encode()
        )

        output.extend(
            obj.encode(
                "latin-1",
                "replace",
            )
        )

        output.extend(
            b"\nendobj\n"
        )

    xref_offset = len(output)

    output.extend(
        f"xref\n0 {len(objects) + 1}\n".encode()
    )

    output.extend(
        b"0000000000 65535 f \n"
    )

    for offset in offsets[1:]:

        output.extend(
            f"{offset:010d} 00000 n \n".encode()
        )

    output.extend(
        (
            "trailer\n"
            f"<< /Size {len(objects) + 1} "
            "/Root 1 0 R >>\n"
            "startxref\n"
            f"{xref_offset}\n"
            "%%EOF\n"
        ).encode()
    )

    with open(
        path,
        "wb",
    ) as fh:

        fh.write(output)

    return path


def write_pdf(data):

    path = GENERATED / f"sentinelsoc_report_{timestamp()}.pdf"

    lines = report_lines(data)

    # Use ReportLab if already available.
    # Otherwise use the dependency-free native PDF engine.

    try:

        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        pdf = canvas.Canvas(
            str(path),
            pagesize=A4,
        )

        width, height = A4

        x = 40
        y = height - 40

        pdf.setFont(
            "Helvetica",
            8,
        )

        for line in lines:

            text = str(line)

            # Wrap very long lines.
            chunks = [
                text[i:i + 115]
                for i in range(
                    0,
                    len(text),
                    115,
                )
            ]

            if not chunks:
                chunks = [""]

            for chunk in chunks:

                pdf.drawString(
                    x,
                    y,
                    chunk.encode(
                        "latin-1",
                        "replace",
                    ).decode(
                        "latin-1"
                    ),
                )

                y -= 10

                if y < 40:

                    pdf.showPage()

                    pdf.setFont(
                        "Helvetica",
                        8,
                    )

                    y = height - 40

        pdf.save()

        return path

    except Exception:

        return write_native_pdf(
            path,
            lines,
        )


# ============================================================
# IAM DEDICATED REPORT
# ============================================================

def write_iam_report(data):

    path = GENERATED / f"sentinelsoc_iam_{timestamp()}.html"

    iam = data.get(
        "iam",
        {}
    )

    identity = iam.get(
        "identity",
        {}
    )

    packages = iam.get(
        "android_packages",
        {}
    )

    privileged = iam.get(
        "privileged_packages",
        []
    )

    users_html = ""

    for user in identity.get(
        "local_users",
        []
    ):

        users_html += (
            "<tr>"
            f"<td>{html.escape(str(user.get('username')))}</td>"
            f"<td>{html.escape(str(user.get('uid')))}</td>"
            f"<td>{html.escape(str(user.get('gid')))}</td>"
            f"<td>{html.escape(str(user.get('home')))}</td>"
            f"<td>{html.escape(str(user.get('shell')))}</td>"
            "</tr>"
        )

    package_html = ""

    for package in packages.get(
        "packages",
        []
    ):

        package_html += (
            "<tr>"
            f"<td>{html.escape(str(package.get('package')))}</td>"
            f"<td>{html.escape(str(package.get('uid')))}</td>"
            "</tr>"
        )

    privileged_html = ""

    for package in privileged:

        privileged_html += (
            "<li>"
            f"{html.escape(str(package.get('package')))} "
            f"(UID {html.escape(str(package.get('uid')))})"
            "</li>"
        )

    ssh_html = ""

    for item in iam.get(
        "ssh",
        {}
    ).get("files", []):

        ssh_html += (
            "<tr>"
            f"<td>{html.escape(str(item.get('path')))}</td>"
            f"<td>{html.escape(str(item.get('classification')))}</td>"
            f"<td>{html.escape(str(item.get('mode')))}</td>"
            "</tr>"
        )

    document = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">

<title>SentinelSOC IAM Report</title>

<style>

body {{
    background:#05070a;
    color:#e8f7ff;
    font-family:monospace;
    padding:30px;
}}

h1 {{
    color:#00e5ff;
}}

h2 {{
    color:#00ff88;
    margin-top:30px;
}}

table {{
    width:100%;
    border-collapse:collapse;
}}

th,td {{
    border:1px solid #24515e;
    padding:8px;
}}

th {{
    color:#00e5ff;
}}

.card {{
    background:#091117;
    border:1px solid #174b5c;
    padding:18px;
    margin:20px 0;
}}

.warning {{
    color:#ffcc00;
}}

</style>
</head>

<body>

<h1>SentinelSOC IAM REPORT</h1>

<div class="card">

<h2>Current Identity</h2>

<p><b>whoami:</b>
{html.escape(str(identity.get('whoami')))}
</p>

<p><b>id:</b>
{html.escape(str(identity.get('id')))}
</p>

<p><b>groups:</b>
{html.escape(str(identity.get('groups')))}
</p>

<p><b>sudo available:</b>
{html.escape(str(iam.get('sudo', {}).get('sudo_available')))}
</p>

</div>

<div class="card">

<h2>Local Users</h2>

<table>

<tr>
<th>User</th>
<th>UID</th>
<th>GID</th>
<th>Home</th>
<th>Shell</th>
</tr>

{users_html}

</table>

</div>

<div class="card">

<h2>Android Package / UID Inventory</h2>

<p>
Packages discovered:
{html.escape(str(packages.get('count', 0)))}
</p>

<table>

<tr>
<th>Package</th>
<th>UID</th>
</tr>

{package_html}

</table>

</div>

<div class="card">

<h2>Privileged UID Review</h2>

<ul>

{privileged_html if privileged_html else '<li>No privileged package UID detected by the available collector.</li>'}

</ul>

</div>

<div class="card">

<h2>SSH Metadata</h2>

<p>
Private key contents are never included in this report.
Only file metadata and classification are collected.
</p>

<table>

<tr>
<th>Path</th>
<th>Classification</th>
<th>Mode</th>
</tr>

{ssh_html}

</table>

</div>

<div class="card">

<h2>Android Users</h2>

<pre>
{html.escape(
    json.dumps(
        iam.get('android_users', []),
        indent=2,
        ensure_ascii=False,
    )
)}
</pre>

</div>

<footer>
Generated dynamically by SentinelSOC.
No sample IAM data was generated.
</footer>

</body>
</html>
"""

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as fh:

        fh.write(document)

    return path


# ============================================================
# REPORT GENERATION
# ============================================================

def generate_report(report_type):

    print()
    print(
        c(
            "[*] Collecting LIVE SentinelSOC data...",
            CYAN,
        )
    )

    data = collect_all()

    if report_type == "html":

        path = write_html(data)

    elif report_type == "pdf":

        path = write_pdf(data)

    elif report_type == "json":

        path = write_json(data)

    elif report_type == "csv":

        path = write_csv(data)

    elif report_type == "iam":

        path = write_iam_report(data)

    else:

        raise ValueError(
            f"Unknown report type: {report_type}"
        )

    print(
        c(
            "[+] Report generated successfully",
            GREEN,
        )
    )

    print(
        f"[+] Type : {report_type.upper()}"
    )

    print(
        f"[+] File : {path}"
    )

    print(
        f"[+] Size : "
        f"{round(path.stat().st_size / 1024, 2)} KB"
    )

    return path


def generate_all():

    print()
    print(
        c(
            "[*] Starting complete dynamic report generation...",
            CYAN,
        )
    )

    data = collect_all()

    paths = []

    paths.append(
        write_html(data)
    )

    paths.append(
        write_pdf(data)
    )

    paths.append(
        write_json(data)
    )

    paths.append(
        write_csv(data)
    )

    paths.append(
        write_iam_report(data)
    )

    print()

    print(
        c(
            "[+] ALL DYNAMIC REPORTS GENERATED",
            GREEN,
        )
    )

    for path in paths:

        print(
            f"[+] {path}"
        )

    return paths


# ============================================================
# REPORT HISTORY
# ============================================================

def list_reports():

    files = []

    if GENERATED.exists():

        try:

            files = sorted(
                [
                    p
                    for p in GENERATED.iterdir()
                    if p.is_file()
                ],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )

        except Exception:
            files = []

    banner(
        "SENTINELSOC | REPORT HISTORY"
    )

    if not files:

        print(
            c(
                "[i] No generated reports yet.",
                YELLOW,
            )
        )

        return

    for index, path in enumerate(
        files,
        start=1,
    ):

        size = round(
            path.stat().st_size / 1024,
            2,
        )

        modified = dt.datetime.fromtimestamp(
            path.stat().st_mtime
        ).astimezone().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        print(
            f"{index:>3}. "
            f"{path.name:<60} "
            f"{size:>8} KB  "
            f"{modified}"
        )


# ============================================================
# OPEN LATEST REPORT
# ============================================================

def open_latest():

    if not GENERATED.exists():

        print(
            c(
                "[i] No reports directory.",
                YELLOW,
            )
        )

        return

    files = sorted(
        [
            p
            for p in GENERATED.iterdir()
            if p.is_file()
        ],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not files:

        print(
            c(
                "[i] No reports generated yet.",
                YELLOW,
            )
        )

        return

    latest = files[0]

    print(
        f"[+] Latest report: {latest}"
    )

    # Android / Termux
    if command_exists("termux-open"):

        subprocess.Popen(
            [
                "termux-open",
                str(latest),
            ]
        )

        print(
            c(
                "[+] Opening with Termux...",
                GREEN,
            )
        )

        return

    # Linux desktop
    if command_exists("xdg-open"):

        subprocess.Popen(
            [
                "xdg-open",
                str(latest),
            ]
        )

        print(
            c(
                "[+] Opening with system viewer...",
                GREEN,
            )
        )

        return

    print(
        "[i] Automatic viewer unavailable."
    )

    print(
        f"[i] Open manually: {latest}"
    )


# ============================================================
# REPORT MENU
# ============================================================

def reporting_menu():

    while True:

        banner(
            "SENTINELSOC | DYNAMIC REPORTING"
        )

        print(
            c(
                "Live defensive reporting engine",
                DIM,
            )
        )

        print()

        print(
            "1. Generate HTML Report"
        )

        print(
            "2. Generate PDF Report"
        )

        print(
            "3. Generate JSON Report"
        )

        print(
            "4. Generate CSV Report"
        )

        print(
            "5. Generate IAM Report"
        )

        print(
            "6. Generate ALL Reports"
        )

        print(
            "7. Report History"
        )

        print(
            "8. Open Latest Report"
        )

        print(
            "9. Live Report Summary"
        )

        print(
            "0. Back"
        )

        print()

        try:

            choice = input(
                c(
                    "Reporting > ",
                    WHITE,
                )
            ).strip()

        except (
            EOFError,
            KeyboardInterrupt,
        ):

            return

        if choice == "1":

            try:
                generate_report("html")
            except Exception as exc:
                print(
                    c(
                        f"[!] HTML generation failed: {exc}",
                        RED,
                    )
                )

            pause()

        elif choice == "2":

            try:
                generate_report("pdf")
            except Exception as exc:
                print(
                    c(
                        f"[!] PDF generation failed: {exc}",
                        RED,
                    )
                )

            pause()

        elif choice == "3":

            try:
                generate_report("json")
            except Exception as exc:
                print(
                    c(
                        f"[!] JSON generation failed: {exc}",
                        RED,
                    )
                )

            pause()

        elif choice == "4":

            try:
                generate_report("csv")
            except Exception as exc:
                print(
                    c(
                        f"[!] CSV generation failed: {exc}",
                        RED,
                    )
                )

            pause()

        elif choice == "5":

            try:
                generate_report("iam")
            except Exception as exc:
                print(
                    c(
                        f"[!] IAM generation failed: {exc}",
                        RED,
                    )
                )

            pause()

        elif choice == "6":

            try:
                generate_all()
            except Exception as exc:
                print(
                    c(
                        f"[!] Complete generation failed: {exc}",
                        RED,
                    )
                )

            pause()

        elif choice == "7":

            list_reports()
            pause()

        elif choice == "8":

            open_latest()
            pause()

        elif choice == "9":

            try:

                data = collect_all()
                summary = build_summary(data)

                banner(
                    "SENTINELSOC | LIVE REPORT SUMMARY"
                )

                for key, value in summary.items():

                    print(
                        f"{key:<28}: "
                        f"{value}"
                    )

            except Exception as exc:

                print(
                    c(
                        f"[!] Collection failed: {exc}",
                        RED,
                    )
                )

            pause()

        elif choice == "0":

            return

        else:

            print(
                c(
                    "[!] Invalid option.",
                    RED,
                )
            )

            time.sleep(0.7)


# ============================================================
# COMPATIBILITY ALIASES
# ============================================================

def menu():
    return reporting_menu()


def run():
    return reporting_menu()


def main():
    return reporting_menu()


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":
    main()


# Router compatibility alias
reporting = reporting_menu
