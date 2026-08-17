#!/usr/bin/env python3

import os
import re
import csv
import json
import glob
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    Console = None
    Table = None
    Panel = None

console = Console() if Console else None


# ============================================================
# OUTPUT
# ============================================================

def out(text="", style=None):
    if console:
        console.print(text, style=style)
    else:
        print(text)


def pause():
    input("\nPress Enter to continue...")


def panel(text, title="SentinelSOC"):
    if console and Panel:
        console.print(
            Panel(
                text,
                title=title,
                border_style="cyan"
            )
        )
    else:
        print("\n" + "=" * 70)
        print(title)
        print("=" * 70)
        print(text)


# ============================================================
# SOURCE DISCOVERY
# ============================================================

COMMON_LOGS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/system.log",
    "/var/log/kern.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/suricata/eve.json",
    "/var/log/zeek/current/conn.log",
    "/opt/zeek/logs/current/conn.log",
]


def discover_logs():
    found = []

    for path in COMMON_LOGS:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            found.append(path)

    patterns = [
        "/var/log/*.log",
        "/var/log/*.log.*",
        "/var/log/apache2/*",
        "/var/log/nginx/*",
        "/var/log/suricata/*",
        "/var/log/zeek/current/*",
        "/opt/zeek/logs/current/*",
    ]

    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isfile(path) and os.access(path, os.R_OK):
                found.append(path)

    return list(dict.fromkeys(found))


def journal_available():
    try:
        r = subprocess.run(
            ["journalctl", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        return r.returncode == 0
    except Exception:
        return False


def load_journal():
    try:
        r = subprocess.run(
            [
                "journalctl",
                "--no-pager",
                "-n",
                "10000",
                "-o",
                "short"
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        if r.returncode == 0:
            return r.stdout.splitlines()

    except Exception:
        pass

    return []


# ============================================================
# FILE READING
# ============================================================

def read_file(path):
    try:
        with open(
            path,
            "r",
            errors="replace"
        ) as f:
            return f.readlines()

    except PermissionError:
        out(
            f"[red]Permission denied:[/red] {path}"
        )

    except Exception as e:
        out(
            f"[red]Unable to read {path}: {e}[/red]"
        )

    return []


def collect_directory(directory):
    records = []

    extensions = {
        ".log",
        ".txt",
        ".csv",
        ".json",
        ".jsonl",
        ".xml",
        ".tsv"
    }

    try:
        for root, dirs, files in os.walk(directory):

            dirs[:] = [
                d for d in dirs
                if d not in {
                    ".git",
                    "__pycache__",
                    "node_modules"
                }
            ]

            for filename in files:

                path = os.path.join(
                    root,
                    filename
                )

                if Path(filename).suffix.lower() in extensions:

                    try:
                        if os.path.getsize(path) > 100 * 1024 * 1024:
                            continue
                    except Exception:
                        pass

                    records.extend(
                        read_file(path)
                    )

    except Exception as e:
        out(
            f"[red]Directory scan error: {e}[/red]"
        )

    return records


def choose_source():

    discovered = discover_logs()

    if journal_available():
        discovered.insert(
            0,
            "JOURNALCTL"
        )

    if discovered:

        if console and Table:

            table = Table(
                title="Detected Real Security Log Sources"
            )

            table.add_column(
                "Option",
                style="cyan"
            )

            table.add_column(
                "Source",
                style="green"
            )

            for i, source in enumerate(
                discovered,
                1
            ):
                table.add_row(
                    str(i),
                    source
                )

            console.print(table)

        else:

            for i, source in enumerate(
                discovered,
                1
            ):
                print(
                    f"{i}. {source}"
                )

        print(
            "\n0. Enter a file/directory manually"
        )

        choice = input(
            "\nSelect source: "
        ).strip()

        try:

            n = int(choice)

            if n == 0:
                return manual_source()

            if 1 <= n <= len(discovered):
                return discovered[n - 1]

        except ValueError:
            pass

    return manual_source()


def manual_source():

    path = input(
        "Enter log FILE or DIRECTORY path: "
    ).strip()

    path = os.path.expanduser(path)

    if os.path.isfile(path):
        return path

    if os.path.isdir(path):
        return path

    out(
        "[red]Path does not exist.[/red]"
    )

    return None


def load_source(source):

    if source == "JOURNALCTL":
        return load_journal()

    if os.path.isdir(source):
        return collect_directory(source)

    return read_file(source)


# ============================================================
# FORMAT DETECTION
# ============================================================

def detect_format(source, lines):

    name = str(source).lower()

    if "suricata" in name:
        return "SURICATA_EVE_JSON"

    if "zeek" in name or "conn.log" in name:
        return "ZEEK"

    if "apache" in name:
        return "APACHE"

    if "nginx" in name:
        return "NGINX"

    if "auth.log" in name or "secure" in name:
        return "LINUX_AUTH"

    if "syslog" in name or "messages" in name:
        return "LINUX_SYSLOG"

    sample = "\n".join(lines[:30])

    stripped = sample.lstrip()

    if stripped.startswith("{"):

        try:
            obj = json.loads(
                stripped.splitlines()[0]
            )

            if isinstance(obj, dict):

                if "event_type" in obj:
                    return "SURICATA_EVE_JSON"

                if "ts" in obj and (
                    "uid" in obj or
                    "id.orig_h" in obj
                ):
                    return "ZEEK_JSON"

        except Exception:
            pass

    if "\t" in sample and (
        "#separator" in sample or
        "\tuid\t" in sample or
        "\tid.orig_h\t" in sample
    ):
        return "ZEEK_TSV"

    if "," in sample:

        first = sample.lower()

        windows_terms = [
            "eventid",
            "event id",
            "computer",
            "provider",
            "level",
            "logon",
            "account name"
        ]

        if any(
            x in first
            for x in windows_terms
        ):
            return "WINDOWS_CSV"

        return "CSV"

    if "<event" in sample.lower():
        return "WINDOWS_XML"

    if re.search(
        r'"\s+(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+',
        sample
    ):
        return "WEB_ACCESS"

    if "sshd" in sample.lower():
        return "SSH"

    return "GENERIC"


# ============================================================
# IP EXTRACTION
# ============================================================

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def extract_ips(text):
    return IP_RE.findall(text)


def first_ip(text):
    ips = extract_ips(text)
    return ips[0] if ips else "unknown"


# ============================================================
# EVENT CLASSIFICATION
# ============================================================

FAILED_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"authentication failed",
    r"login failed",
    r"failed login",
    r"invalid user",
    r"incorrect password",
    r"logon failure",
    r"status.*0xc000006d",
    r"event.?id.?4625",
]

SUCCESS_PATTERNS = [
    r"accepted password",
    r"accepted publickey",
    r"accepted keyboard",
    r"successful login",
    r"login successful",
    r"session opened",
    r"logon success",
    r"event.?id.?4624",
]

SUDO_PATTERNS = [
    r"\bsudo:",
    r"sudo command",
    r"privilege",
    r"elevation",
]

WEB_PATTERNS = [
    r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b",
    r"HTTP/\d",
]


def classify_line(line):

    lower = line.lower()

    if any(
        re.search(p, lower)
        for p in FAILED_PATTERNS
    ):
        return "FAILED_AUTHENTICATION"

    if any(
        re.search(p, lower)
        for p in SUCCESS_PATTERNS
    ):
        return "SUCCESSFUL_AUTHENTICATION"

    if any(
        re.search(p, lower)
        for p in SUDO_PATTERNS
    ):
        return "PRIVILEGE_EVENT"

    if any(
        re.search(p, lower)
        for p in WEB_PATTERNS
    ):
        return "WEB_REQUEST"

    if (
        "alert" in lower or
        "signature" in lower or
        "malware" in lower or
        "trojan" in lower
    ):
        return "THREAT_EVENT"

    if (
        "error" in lower or
        "exception" in lower
    ):
        return "ERROR"

    return "OTHER"


# ============================================================
# SURICATA
# ============================================================

def parse_suricata(lines):

    events = []

    for line in lines:

        try:

            obj = json.loads(line)

            if not isinstance(obj, dict):
                continue

            event_type = obj.get(
                "event_type",
                "unknown"
            )

            src_ip = obj.get(
                "src_ip",
                "unknown"
            )

            dst_ip = obj.get(
                "dest_ip",
                "unknown"
            )

            alert = obj.get(
                "alert",
                {}
            )

            signature = ""

            if isinstance(alert, dict):
                signature = alert.get(
                    "signature",
                    ""
                )

            events.append({
                "type": (
                    "SURICATA_ALERT"
                    if event_type == "alert"
                    else "SURICATA_" +
                    str(event_type).upper()
                ),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "signature": signature,
                "timestamp": obj.get(
                    "timestamp",
                    ""
                ),
                "raw": line.strip()
            })

        except Exception:
            continue

    return events


# ============================================================
# ZEEK
# ============================================================

def parse_zeek(lines):

    events = []

    headers = []

    for line in lines:

        if line.startswith("#fields"):
            headers = line.strip().split("\t")[1:]
            continue

        if line.startswith("#"):
            continue

        if not headers:
            continue

        values = line.rstrip(
            "\n"
        ).split("\t")

        record = dict(
            zip(
                headers,
                values
            )
        )

        src = record.get(
            "id.orig_h",
            record.get(
                "src",
                "unknown"
            )
        )

        dst = record.get(
            "id.resp_h",
            record.get(
                "dst",
                "unknown"
            )
        )

        events.append({
            "type": "ZEEK_NETWORK_EVENT",
            "source_ip": src,
            "destination_ip": dst,
            "timestamp": record.get(
                "ts",
                ""
            ),
            "raw": line.strip()
        })

    return events


# ============================================================
# GENERIC EVENT PARSER
# ============================================================

def parse_generic(lines):

    events = []

    for line in lines:

        if not line.strip():
            continue

        event_type = classify_line(
            line
        )

        events.append({
            "type": event_type,
            "source_ip": first_ip(line),
            "destination_ip": (
                extract_ips(line)[1]
                if len(extract_ips(line)) > 1
                else "unknown"
            ),
            "timestamp": extract_timestamp(
                line
            ),
            "raw": line.strip()
        })

    return events


# ============================================================
# CSV / WINDOWS
# ============================================================

def parse_csv_lines(lines):

    events = []

    try:

        reader = csv.DictReader(
            lines
        )

        for row in reader:

            text = " ".join(
                str(v)
                for v in row.values()
                if v is not None
            )

            event_type = classify_line(
                text
            )

            events.append({
                "type": event_type,
                "source_ip": first_ip(text),
                "destination_ip": (
                    extract_ips(text)[1]
                    if len(extract_ips(text)) > 1
                    else "unknown"
                ),
                "timestamp": (
                    row.get("TimeCreated")
                    or row.get("Timestamp")
                    or row.get("Date")
                    or ""
                ),
                "raw": text
            })

    except Exception:

        return parse_generic(
            lines
        )

    return events


# ============================================================
# XML / WINDOWS
# ============================================================

def parse_xml_lines(lines):

    events = []

    for line in lines:

        if not line.strip():
            continue

        event_type = classify_line(
            line
        )

        events.append({
            "type": event_type,
            "source_ip": first_ip(line),
            "destination_ip": (
                extract_ips(line)[1]
                if len(extract_ips(line)) > 1
                else "unknown"
            ),
            "timestamp": extract_timestamp(
                line
            ),
            "raw": line.strip()
        })

    return events


# ============================================================
# TIMESTAMP
# ============================================================

def extract_timestamp(line):

    patterns = [
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
        r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})",
        r"(\d{4}-\d{2}-\d{2})",
        r"(\d{1,2}/\d{1,2}/\d{4}[^,]*)",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            line
        )

        if match:
            return match.group(1)

    return "Unknown"


# ============================================================
# UNIFIED PARSER
# ============================================================

def parse_logs(source, lines):

    fmt = detect_format(
        source,
        lines
    )

    if fmt == "SURICATA_EVE_JSON":
        events = parse_suricata(lines)

    elif fmt in {
        "ZEEK",
        "ZEEK_TSV"
    }:
        events = parse_zeek(lines)

    elif fmt == "ZEEK_JSON":

        events = parse_generic(
            lines
        )

    elif fmt in {
        "WINDOWS_CSV",
        "CSV"
    }:
        events = parse_csv_lines(
            lines
        )

    elif fmt == "WINDOWS_XML":
        events = parse_xml_lines(
            lines
        )

    else:
        events = parse_generic(
            lines
        )

    return fmt, events


# ============================================================
# SUMMARY
# ============================================================

def show_summary(
    source,
    lines,
    fmt,
    events
):

    types = Counter(
        e["type"]
        for e in events
    )

    ips = Counter(
        e["source_ip"]
        for e in events
        if e["source_ip"] != "unknown"
    )

    failed = sum(
        1
        for e in events
        if e["type"] == "FAILED_AUTHENTICATION"
    )

    successful = sum(
        1
        for e in events
        if e["type"] ==
        "SUCCESSFUL_AUTHENTICATION"
    )

    threats = sum(
        1
        for e in events
        if (
            "THREAT" in e["type"]
            or "ALERT" in e["type"]
        )
    )

    panel(
        f"Source: {source}\n"
        f"Detected format: {fmt}\n"
        f"Records analyzed: {len(lines)}\n"
        f"Events parsed: {len(events)}\n"
        f"Failed authentications: {failed}\n"
        f"Successful authentications: {successful}\n"
        f"Threat/alert events: {threats}\n"
        f"Unique source IPs: {len(ips)}",
        "🔎 REAL LOG ANALYSIS"
    )

    if console and Table and types:

        table = Table(
            title="Event Classification"
        )

        table.add_column(
            "Event Type",
            style="cyan"
        )

        table.add_column(
            "Count",
            style="yellow"
        )

        for event_type, count in types.most_common():

            table.add_row(
                event_type,
                str(count)
            )

        console.print(table)

    if console and Table and ips:

        table = Table(
            title="Top Source IPs"
        )

        table.add_column(
            "Source IP",
            style="red"
        )

        table.add_column(
            "Events",
            style="yellow"
        )

        for ip, count in ips.most_common(20):

            table.add_row(
                ip,
                str(count)
            )

        console.print(table)


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================

def authentication_analysis():

    source = choose_source()

    if not source:
        pause()
        return

    lines = load_source(
        source
    )

    if not lines:

        out(
            "[yellow]No readable records found.[/yellow]"
        )

        pause()
        return

    fmt, events = parse_logs(
        source,
        lines
    )

    auth_events = [
        e
        for e in events
        if e["type"] in {
            "FAILED_AUTHENTICATION",
            "SUCCESSFUL_AUTHENTICATION"
        }
    ]

    show_summary(
        source,
        lines,
        fmt,
        auth_events
    )

    if console and Table and auth_events:

        table = Table(
            title="Authentication Events"
        )

        table.add_column(
            "Type",
            style="yellow"
        )

        table.add_column(
            "Source IP",
            style="red"
        )

        table.add_column(
            "Timestamp",
            style="cyan"
        )

        table.add_column(
            "Event"
        )

        for event in auth_events[-50:]:

            table.add_row(
                event["type"],
                event["source_ip"],
                str(event["timestamp"]),
                event["raw"][:120]
            )

        console.print(table)

    pause()


# ============================================================
# BRUTE FORCE
# ============================================================

def brute_force_detection():

    source = choose_source()

    if not source:
        pause()
        return

    lines = load_source(
        source
    )

    if not lines:
        pause()
        return

    fmt, events = parse_logs(
        source,
        lines
    )

    failed = [
        e
        for e in events
        if e["type"] ==
        "FAILED_AUTHENTICATION"
    ]

    counts = Counter(
        e["source_ip"]
        for e in failed
        if e["source_ip"] != "unknown"
    )

    threshold = 5

    suspicious = {
        ip: count
        for ip, count in counts.items()
        if count >= threshold
    }

    panel(
        f"Source: {source}\n"
        f"Format: {fmt}\n"
        f"Failed authentication events: {len(failed)}\n"
        f"Unique attacking sources: {len(counts)}\n"
        f"Detection threshold: {threshold}\n"
        f"Potential brute-force sources: "
        f"{len(suspicious)}",
        "🚨 BRUTE-FORCE DETECTION"
    )

    if console and Table and suspicious:

        table = Table(
            title="Potential Brute-Force Sources"
        )

        table.add_column(
            "Source IP",
            style="red"
        )

        table.add_column(
            "Failed Attempts",
            style="yellow"
        )

        table.add_column(
            "Severity",
            style="magenta"
        )

        for ip, count in sorted(
            suspicious.items(),
            key=lambda x: x[1],
            reverse=True
        ):

            severity = (
                "CRITICAL"
                if count >= 50
                else
                "HIGH"
                if count >= 20
                else
                "MEDIUM"
            )

            table.add_row(
                ip,
                str(count),
                severity
            )

        console.print(table)

    elif not suspicious:

        out(
            "[green]No source crossed the "
            "brute-force threshold.[/green]"
        )

    pause()


# ============================================================
# FULL SECURITY ANALYSIS
# ============================================================

def full_analysis():

    source = choose_source()

    if not source:
        pause()
        return

    lines = load_source(
        source
    )

    if not lines:
        pause()
        return

    fmt, events = parse_logs(
        source,
        lines
    )

    show_summary(
        source,
        lines,
        fmt,
        events
    )

    if console and Table:

        table = Table(
            title="Recent Security Events"
        )

        table.add_column(
            "Type",
            style="yellow"
        )

        table.add_column(
            "Source IP",
            style="red"
        )

        table.add_column(
            "Destination",
            style="blue"
        )

        table.add_column(
            "Timestamp",
            style="cyan"
        )

        for event in events[-50:]:

            table.add_row(
                event["type"],
                event["source_ip"],
                event["destination_ip"],
                str(event["timestamp"])
            )

        console.print(table)

    pause()


# ============================================================
# SECURITY TIMELINE
# ============================================================

def security_timeline():

    source = choose_source()

    if not source:
        pause()
        return

    lines = load_source(
        source
    )

    if not lines:
        pause()
        return

    fmt, events = parse_logs(
        source,
        lines
    )

    panel(
        f"Source: {source}\n"
        f"Format: {fmt}\n"
        f"Timeline events: {len(events)}",
        "🕒 SECURITY TIMELINE"
    )

    if console and Table:

        table = Table()

        table.add_column(
            "Timestamp",
            style="cyan"
        )

        table.add_column(
            "Type",
            style="yellow"
        )

        table.add_column(
            "Source",
            style="red"
        )

        table.add_column(
            "Event"
        )

        for event in events[-100:]:

            table.add_row(
                str(event["timestamp"]),
                event["type"],
                event["source_ip"],
                event["raw"][:120]
            )

        console.print(table)

    pause()


# ============================================================
# LIVE MONITOR
# ============================================================

def live_monitor():

    source = choose_source()

    if not source:
        pause()
        return

    if os.path.isdir(source):

        out(
            "[yellow]Live monitoring requires "
            "a specific log file, not a directory.[/yellow]"
        )

        pause()
        return

    if source == "JOURNALCTL":

        command = [
            "journalctl",
            "-f",
            "-o",
            "short"
        ]

    else:

        command = [
            "tail",
            "-F",
            source
        ]

    panel(
        f"Monitoring: {source}\n"
        "Press Ctrl+C to stop.",
        "📡 LIVE SECURITY LOG MONITOR"
    )

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in process.stdout:

            line = line.strip()

            if not line:
                continue

            event_type = classify_line(
                line
            )

            ip = first_ip(
                line
            )

            if event_type == "FAILED_AUTHENTICATION":

                out(
                    f"[bold red]🚨 FAILED AUTH[/bold red] "
                    f"{ip} | {line}"
                )

            elif event_type == "SUCCESSFUL_AUTHENTICATION":

                out(
                    f"[bold green]✓ SUCCESSFUL AUTH[/bold green] "
                    f"{ip} | {line}"
                )

            elif event_type == "THREAT_EVENT":

                out(
                    f"[bold red]⚠ THREAT[/bold red] "
                    f"{ip} | {line}"
                )

            elif event_type == "PRIVILEGE_EVENT":

                out(
                    f"[bold yellow]⬆ PRIVILEGE EVENT[/bold yellow] "
                    f"{ip} | {line}"
                )

            else:

                print(
                    f"[{event_type}] {line}"
                )

    except KeyboardInterrupt:

        try:
            process.terminate()
        except Exception:
            pass

        out(
            "\n[cyan]Live monitor stopped.[/cyan]"
        )

    except Exception as e:

        out(
            f"[red]Live monitor error: {e}[/red]"
        )

    pause()


# ============================================================
# LOG SOURCES
# ============================================================

def list_sources():

    sources = discover_logs()

    panel(
        "\n".join(
            sources
        )
        if sources
        else
        "No standard system logs detected.\n"
        "This is normal on Termux/Android.",
        "📁 REAL LOG SOURCES"
    )

    if journal_available():

        out(
            "[green]✓ journalctl available[/green]"
        )

    else:

        out(
            "[yellow]journalctl unavailable "
            "(normal on Termux).[/yellow]"
        )

    pause()


# ============================================================
# MAIN MENU
# ============================================================

def run():

    while True:

        panel(
            "Automatically detects and analyzes:\n"
            "• Linux / syslog / auth.log\n"
            "• SSH\n"
            "• Apache / Nginx\n"
            "• Windows exported logs\n"
            "• Suricata EVE JSON\n"
            "• Zeek logs\n"
            "• Generic security logs\n\n"
            "Real files/directories only.",
            "🧾 SentinelSOC Log Analysis"
        )

        print(
            "1. Authentication Log Analysis\n"
            "2. SSH / Authentication Brute-Force Detection\n"
            "3. Security Timeline\n"
            "4. Live Log Monitor\n"
            "5. Detect Available Log Sources\n"
            "6. Analyze Any Log File / Directory\n"
            "7. Full Automatic Security Analysis\n"
            "0. Back"
        )

        choice = input(
            "\nLog Analysis > "
        ).strip()

        if choice == "1":
            authentication_analysis()

        elif choice == "2":
            brute_force_detection()

        elif choice == "3":
            security_timeline()

        elif choice == "4":
            live_monitor()

        elif choice == "5":
            list_sources()

        elif choice == "6":
            full_analysis()

        elif choice == "7":
            full_analysis()

        elif choice == "0":
            break

        else:
            out(
                "[red]Invalid option.[/red]"
            )


# ============================================================
# ROUTER COMPATIBILITY
# ============================================================

# Your existing router imports:
#
# from modules.loganalysis import loganalysis
#
# Therefore expose this module as "loganalysis".
import sys
loganalysis = sys.modules[__name__]


if __name__ == "__main__":
    run()
