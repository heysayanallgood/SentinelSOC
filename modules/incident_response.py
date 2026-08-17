#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path
# ============================================================
# SENTINELSOC INCIDENT RESPONSE PATH CONFIGURATION
# ============================================================

from pathlib import Path

ASSETS = Path("assets")
CASE_ROOT = ASSETS / "incident_response"
EVIDENCE_ROOT = CASE_ROOT / "evidence"
REPORTS_ROOT = CASE_ROOT / "reports"
CASES_ROOT = CASE_ROOT / "cases"

# Existing SentinelSOC event database
DB = ASSETS / "sentinel_events.db"

# Incident-response case database
CASE_DB = CASE_ROOT / "incidents.db"

# Create required directories safely.
ASSETS.mkdir(parents=True, exist_ok=True)
CASE_ROOT.mkdir(parents=True, exist_ok=True)
EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
CASES_ROOT.mkdir(parents=True, exist_ok=True)
ASSETS.mkdir(parents=True, exist_ok=True)
try:
    import psutil
except ImportError:
    psutil = None
# ============================================================================
# SENTINELSOC RUNTIME COMPATIBILITY DEFINITIONS
# ============================================================================
# ANSI terminal colours
RESET   = "\033[0m"
BLACK   = "\033[30m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

# Stable SentinelSOC incident-response database

# ---------------------------------------------------------------------------
# SENTINELSOC UI HEADER HELPER
# ---------------------------------------------------------------------------
def header(title="", subtitle="", width=64):
    """SentinelSOC SOC/DFIR terminal header."""
    if isinstance(subtitle, int):
        width = subtitle
        subtitle = ""

    if not isinstance(width, int):
        width = 64

    line = "=" * width

    print()
    print(line)

    if title:
        print(f"  {title}")

    if subtitle:
        print(f"  {subtitle}")

    print(line)
def init_db():
    with sqlite3.connect(DB) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                summary TEXT,
                tags TEXT,
                evidence_dir TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                action TEXT NOT NULL,
                mode TEXT NOT NULL,
                result TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                source TEXT NOT NULL,
                stored_path TEXT,
                sha256 TEXT,
                size INTEGER,
                notes TEXT
            )
        """)

init_db()

# ----------------------------------------------------------------------
# UTILITIES
# ----------------------------------------------------------------------

def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def banner(title, subtitle=""):
    print()
    print(f"{CYAN}{'=' * 72}{RESET}")
    print(f"{CYAN}      SENTINELSOC | SOC INCIDENT RESPONSE & DFIR{RESET}")
    print(f"{CYAN}{'=' * 72}{RESET}")
    print(f"{MAGENTA}{title}{RESET}")
    if subtitle:
        print(f"{DIM}{subtitle}{RESET}")
    print()


def run_cmd(command, timeout=10):
    try:
        p = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        return {
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr
        }

    except Exception as e:
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": str(e)
        }


def command_exists(name):
    return shutil.which(name) is not None


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str
        ),
        encoding="utf-8"
    )


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ----------------------------------------------------------------------
# DEVICE / HOST TRIAGE
# ----------------------------------------------------------------------

def device_information():

    data = {
        "timestamp": now(),
        "hostname": "",
        "kernel": "",
        "user": os.environ.get("USER") or os.environ.get("USERNAME"),
        "prefix": os.environ.get("PREFIX"),
        "android_version": None,
        "android_sdk": None,
    }

    r = run_cmd(["sh", "-c", "hostname"])
    data["hostname"] = r["stdout"].strip()

    r = run_cmd(["uname", "-a"])
    data["kernel"] = r["stdout"].strip()

    if command_exists("getprop"):

        r = run_cmd([
            "getprop",
            "ro.build.version.release"
        ])

        data["android_version"] = r["stdout"].strip()

        r = run_cmd([
            "getprop",
            "ro.build.version.sdk"
        ])

        data["android_sdk"] = r["stdout"].strip()

    if command_exists("termux-info"):

        r = run_cmd(
            ["termux-info"],
            timeout=15
        )

        data["termux_info"] = r["stdout"][-6000:]

    return data


# ----------------------------------------------------------------------
# PROCESS INVENTORY
# ----------------------------------------------------------------------

def process_inventory():

    if psutil is not None:

        processes = []

        for p in psutil.process_iter([
            "pid",
            "ppid",
            "username",
            "name",
            "cmdline",
            "create_time"
        ]):

            try:

                info = p.info

                processes.append({
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "user": info.get("username"),
                    "name": info.get("name"),
                    "cmdline": " ".join(
                        info.get("cmdline") or []
                    ),
                    "created": (
                        dt.datetime.fromtimestamp(
                            info["create_time"]
                        ).isoformat(timespec="seconds")
                        if info.get("create_time")
                        else None
                    )
                })

            except Exception:
                pass

        return processes

    r = run_cmd([
        "ps",
        "-A",
        "-o",
        "PID,PPID,USER,NAME,ARGS"
    ])

    return [
        {"raw": line}
        for line in r["stdout"].splitlines()
        if line.strip()
    ]


# ----------------------------------------------------------------------
# NETWORK TRIAGE
# ----------------------------------------------------------------------

def network_connections():

    if psutil is not None:

        results = []

        try:

            for c in psutil.net_connections(
                kind="inet"
            ):

                local = ""

                remote = ""

                if c.laddr:
                    local = (
                        f"{c.laddr.ip}:{c.laddr.port}"
                    )

                if c.raddr:
                    remote = (
                        f"{c.raddr.ip}:{c.raddr.port}"
                    )

                results.append({
                    "local": local,
                    "remote": remote,
                    "status": c.status,
                    "pid": c.pid
                })

            return results

        except Exception:
            pass

    commands = [
        ["ss", "-tunap"],
        ["netstat", "-tunap"],
        ["netstat", "-an"]
    ]

    for command in commands:

        if command_exists(command[0]):

            r = run_cmd(command)

            if r["stdout"].strip():

                return [
                    {"raw": line}
                    for line in r["stdout"].splitlines()
                ]

    return []


def listening_ports():

    if psutil is not None:

        listeners = []

        try:

            for c in psutil.net_connections(
                kind="inet"
            ):

                if c.status != "LISTEN":
                    continue

                listeners.append({
                    "local": (
                        f"{c.laddr.ip}:{c.laddr.port}"
                        if c.laddr
                        else ""
                    ),
                    "pid": c.pid
                })

            return listeners

        except Exception:
            pass

    commands = [
        ["ss", "-lntup"],
        ["netstat", "-lntup"],
        ["netstat", "-lnt"]
    ]

    for command in commands:

        if command_exists(command[0]):

            r = run_cmd(command)

            if r["stdout"].strip():

                return [
                    {"raw": line}
                    for line in r["stdout"].splitlines()
                ]

    return []


# ----------------------------------------------------------------------
# STARTUP / PERSISTENCE
# ----------------------------------------------------------------------

def startup_persistence():

    results = []

    prefix = os.environ.get("PREFIX")

    candidates = [
        Path.home() / ".bashrc",
        Path.home() / ".profile",
        Path.home() / ".zshrc",
        Path.home() / ".termux" / "boot",
        Path.home() / ".termux" / "tasker",
    ]

    if prefix:

        candidates.extend([
            Path(prefix) / "etc" / "profile",
            Path(prefix) / "etc" / "profile.d"
        ])

    for path in candidates:

        try:

            if path.is_file():

                results.append({
                    "path": str(path),
                    "type": "file"
                })

            elif path.is_dir():

                results.append({
                    "path": str(path),
                    "type": "directory",
                    "entries": [
                        x.name
                        for x in path.iterdir()
                    ][:200]
                })

        except Exception:
            pass

    if command_exists("crontab"):

        r = run_cmd([
            "crontab",
            "-l"
        ])

        if r["stdout"].strip():

            results.append({
                "path": "crontab",
                "type": "schedule",
                "content": r["stdout"][-5000:]
            })

    return results


# ----------------------------------------------------------------------
# LIVE LOGCAT
# ----------------------------------------------------------------------

def recent_logcat(limit=250):

    if not command_exists("logcat"):

        return {
            "available": False,
            "lines": []
        }

    r = run_cmd(
        [
            "logcat",
            "-d",
            "-v",
            "threadtime",
            "-t",
            str(limit)
        ],
        timeout=20
    )

    return {
        "available": True,
        "lines": r["stdout"].splitlines()[-limit:]
    }


# ----------------------------------------------------------------------
# SENTINELSOC EVENT DB
# ----------------------------------------------------------------------

def recent_sentinelsoc_events(limit=100):

    db = ASSETS / "sentinel_events.db"

    if not db.exists():
        return []

    try:

        with sqlite3.connect(
            f"file:{db}?mode=ro",
            uri=True
        ) as conn:

            rows = conn.execute(
                """
                SELECT
                    id,
                    timestamp,
                    event_type,
                    severity,
                    risk,
                    risk_score,
                    app,
                    permission,
                    resource
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "event_type": row[2],
                "severity": row[3],
                "risk": row[4],
                "risk_score": row[5],
                "app": row[6],
                "permission": row[7],
                "resource": row[8]
            }
            for row in rows
        ]

    except Exception as e:

        return [{
            "error": str(e)
        }]


# ----------------------------------------------------------------------
# IOC EXTRACTION
# ----------------------------------------------------------------------

def extract_iocs(text):

    findings = {}

    for name, pattern in IOC_PATTERNS.items():

        matches = sorted(
            set(pattern.findall(text))
        )

        if matches:
            findings[name] = matches[:200]

    return findings


def scan_text_file(path):

    try:

        if path.stat().st_size > 8 * 1024 * 1024:
            return ""

        return path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except Exception:

        return ""


# ----------------------------------------------------------------------
# SUSPICIOUS PROCESS HEURISTICS
# ----------------------------------------------------------------------

def suspicious_processes(processes):

    terms = [
        "nc ",
        "netcat",
        "ncat",
        "socat",
        "curl ",
        "wget ",
        "python -c",
        "python3 -c",
        "sh -c",
        "bash -c",
        "powershell",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "ngrok",
        "frpc"
    ]

    results = []

    for process in processes:

        text = json.dumps(
            process
        ).lower()

        matches = [
            term
            for term in terms
            if term.lower() in text
        ]

        if matches:

            results.append({
                "process": process,
                "matched": matches
            })

    return results


# ----------------------------------------------------------------------
# EVENT CORRELATION
# ----------------------------------------------------------------------

def enrich_event(event):

    result = {
        "event": event,
        "alert": None,
        "mitre": []
    }

    try:

        from modules.alert_engine import create_alert

        result["alert"] = create_alert(event)

    except Exception:
        pass

    try:

        from modules.mitre_attack import map_event

        result["mitre"] = map_event(event)

    except Exception:
        pass

    return result


# ----------------------------------------------------------------------
# TRIAGE SNAPSHOT
# ----------------------------------------------------------------------

def triage_snapshot():

    header(
        "LIVE INCIDENT TRIAGE",
        "Read-only SOC collection and correlation"
    )

    processes = process_inventory()

    snapshot = {

        "timestamp": now(),

        "device": device_information(),

        "processes": processes,

        "network_connections":
            network_connections(),

        "listening_ports":
            listening_ports(),

        "startup_persistence":
            startup_persistence(),

        "recent_logcat":
            recent_logcat(),

        "sentinelsoc_events":
            recent_sentinelsoc_events(),

        "suspicious_processes":
            suspicious_processes(processes)

    }

    folder = (
        CASE_ROOT /
        "adhoc_triage"
    )

    folder.mkdir(
        parents=True,
        exist_ok=True
    )

    filename = (
        "triage_" +
        dt.datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        ) +
        ".json"
    )

    output = folder / filename

    save_json(
        output,
        snapshot
    )

    print(
        f"{GREEN}[+] TRIAGE SNAPSHOT SAVED{RESET}"
    )

    print(
        f"Processes          : "
        f"{len(snapshot['processes'])}"
    )

    print(
        f"Connections        : "
        f"{len(snapshot['network_connections'])}"
    )

    print(
        f"Listening ports    : "
        f"{len(snapshot['listening_ports'])}"
    )

    print(
        f"Persistence items  : "
        f"{len(snapshot['startup_persistence'])}"
    )

    print(
        f"Suspicious process : "
        f"{len(snapshot['suspicious_processes'])}"
    )

    print(
        f"Recent events      : "
        f"{len(snapshot['sentinelsoc_events'])}"
    )

    print(
        f"\nEvidence: {output}"
    )

    return snapshot


# ----------------------------------------------------------------------
# CASE MANAGEMENT
# ----------------------------------------------------------------------

def create_case():

    title = input(
        "Incident title: "
    ).strip()

    if not title:
        title = "Untitled Incident"

    severity = input(
        "Severity [LOW/MEDIUM/HIGH/CRITICAL]: "
    ).strip().upper()

    if severity not in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }:
        severity = "MEDIUM"

    summary = input(
        "Incident summary: "
    ).strip()

    tags = input(
        "Tags (comma separated): "
    ).strip()

    case_id = (
        "IR-" +
        dt.datetime.now().strftime(
            "%Y%m%d-%H%M%S"
        ) +
        "-" +
        uuid.uuid4().hex[:6].upper()
    )

    case_dir = (
        CASE_ROOT /
        "cases" /
        case_id
    )

    case_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    with sqlite3.connect(DB) as conn:

        conn.execute(
            """
            INSERT INTO cases(
                case_id,
                created_at,
                title,
                severity,
                status,
                summary,
                tags,
                evidence_dir
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                case_id,
                now(),
                title,
                severity,
                "OPEN",
                summary,
                tags,
                str(case_dir)
            )
        )

    save_json(
        case_dir / "case.json",
        {
            "case_id": case_id,
            "created_at": now(),
            "title": title,
            "severity": severity,
            "status": "OPEN",
            "summary": summary,
            "tags": [
                tag.strip()
                for tag in tags.split(",")
                if tag.strip()
            ]
        }
    )

    print(
        f"{GREEN}[+] CASE CREATED: "
        f"{case_id}{RESET}"
    )

    return case_id


def latest_case():

    with sqlite3.connect(DB) as conn:

        row = conn.execute(
            """
            SELECT case_id
            FROM cases
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()

    return row[0] if row else None


def get_case(case_id=None):

    case_id = (
        case_id
        or latest_case()
    )

    if not case_id:
        return None

    with sqlite3.connect(DB) as conn:

        conn.row_factory = sqlite3.Row

        row = conn.execute(
            "SELECT * FROM cases WHERE case_id=?",
            (case_id,)
        ).fetchone()

    return (
        dict(row)
        if row
        else None
    )


def add_finding(
    case_id,
    category,
    severity,
    title,
    details
):

    with sqlite3.connect(DB) as conn:

        conn.execute(
            """
            INSERT INTO findings(
                case_id,
                created_at,
                category,
                severity,
                title,
                details
            )
            VALUES(?,?,?,?,?,?)
            """,
            (
                case_id,
                now(),
                category,
                severity,
                title,
                details
            )
        )


def add_action(
    case_id,
    action,
    mode,
    result
):

    with sqlite3.connect(DB) as conn:

        conn.execute(
            """
            INSERT INTO actions(
                case_id,
                created_at,
                action,
                mode,
                result
            )
            VALUES(?,?,?,?,?)
            """,
            (
                case_id,
                now(),
                action,
                mode,
                result
            )
        )


# ----------------------------------------------------------------------
# EVIDENCE COLLECTION
# ----------------------------------------------------------------------

def collect_case_evidence(case_id):

    case = get_case(case_id)

    if not case:

        print(
            f"{RED}[!] Case not found.{RESET}"
        )

        return

    snapshot = triage_snapshot()

    case_dir = Path(
        case["evidence_dir"]
    )

    output = (
        case_dir /
        "triage_snapshot.json"
    )

    save_json(
        output,
        snapshot
    )

    add_finding(
        case_id,
        "TRIAGE",
        "INFO",
        "Initial forensic triage collected",
        str(output)
    )

    add_action(
        case_id,
        "collect_triage",
        "EXECUTED",
        "Read-only SOC triage collected"
    )

    print(
        f"{GREEN}[+] CASE EVIDENCE SAVED{RESET}"
    )


def collect_file_evidence(case_id):

    case = get_case(case_id)

    if not case:
        print(
            f"{RED}[!] Case not found.{RESET}"
        )
        return

    target = input(
        "Evidence file/directory: "
    ).strip().strip('"').strip("'")

    path = Path(
        target
    ).expanduser()

    if not path.exists():

        print(
            f"{RED}[!] Target not found.{RESET}"
        )

        return

    evidence_dir = (
        Path(case["evidence_dir"]) /
        "files"
    )

    evidence_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    if path.is_file():

        try:

            destination = (
                evidence_dir /
                path.name
            )

            shutil.copy2(
                path,
                destination
            )

            digest = sha256_file(
                destination
            )

            size = destination.stat().st_size

            manifest = {
                "source": str(path),
                "stored": str(destination),
                "sha256": digest,
                "size": size,
                "collected_at": now()
            }

            save_json(
                destination.with_suffix(
                    destination.suffix +
                    ".manifest.json"
                ),
                manifest
            )

            with sqlite3.connect(DB) as conn:

                conn.execute(
                    """
                    INSERT INTO evidence(
                        case_id,
                        collected_at,
                        source,
                        stored_path,
                        sha256,
                        size,
                        notes
                    )
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        case_id,
                        now(),
                        str(path),
                        str(destination),
                        digest,
                        size,
                        "Original copied without modification"
                    )
                )

            add_finding(
                case_id,
                "EVIDENCE",
                "INFO",
                f"Evidence collected: {path.name}",
                json.dumps(manifest)
            )

            add_action(
                case_id,
                "collect_file",
                "EXECUTED",
                str(destination)
            )

            print(
                f"{GREEN}[+] Evidence copied:{RESET} "
                f"{destination}"
            )

            print(
                f"{CYAN}SHA256:{RESET} "
                f"{digest}"
            )

        except Exception as e:

            print(
                f"{RED}[!] Collection failed: "
                f"{e}{RESET}"
            )

            add_action(
                case_id,
                "collect_file",
                "FAILED",
                str(e)
            )

        return

    # Directory mode = forensic manifest/hash inventory
    manifest = []

    for file in list(
        path.rglob("*")
    )[:5000]:

        if not file.is_file():
            continue

        try:

            manifest.append({
                "path": str(file),
                "size": file.stat().st_size,
                "sha256": sha256_file(file)
            })

        except Exception:
            pass

    output = (
        evidence_dir /
        f"{path.name}_manifest.json"
    )

    save_json(
        output,
        manifest
    )

    add_finding(
        case_id,
        "EVIDENCE",
        "INFO",
        "Directory evidence manifest created",
        f"{len(manifest)} files hashed"
    )

    add_action(
        case_id,
        "directory_manifest",
        "EXECUTED",
        str(output)
    )

    print(
        f"{GREEN}[+] Directory manifest created:{RESET}"
    )

    print(
        f"    Files: {len(manifest)}"
    )

    print(
        f"    Output: {output}"
    )


# ----------------------------------------------------------------------
# IOC SWEEP
# ----------------------------------------------------------------------

def ioc_sweep(case_id=None):

    target = input(
        "IOC scan file/directory: "
    ).strip().strip('"').strip("'")

    path = Path(
        target
    ).expanduser()

    if not path.exists():

        print(
            f"{RED}[!] Target not found.{RESET}"
        )

        return

    text_chunks = []

    files = []

    if path.is_file():

        files = [path]

    else:

        files = [
            x
            for x in path.rglob("*")
            if x.is_file()
        ][:500]

    for file in files:

        try:

            if file.stat().st_size > (
                8 * 1024 * 1024
            ):
                continue

            text_chunks.append(
                file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )
            )

        except Exception:
            pass

    findings = extract_iocs(
        "\n".join(text_chunks)
    )

    banner(
        "IOC DISCOVERY",
        "IP / URL / email / hash extraction"
    )

    total = 0

    for kind, values in findings.items():

        print(
            f"{MAGENTA}{kind}{RESET}"
        )

        for value in values:

            print(
                f"  {value}"
            )

            total += 1

    if not findings:

        print(
            f"{GREEN}[+] No IOCs found.{RESET}"
        )

    else:

        print(
            f"\n{YELLOW}[+] Total IOC values: "
            f"{total}{RESET}"
        )

    if case_id:

        add_finding(
            case_id,
            "IOC",
            "MEDIUM" if findings else "INFO",
            "IOC sweep completed",
            json.dumps(findings)
        )

        add_action(
            case_id,
            "ioc_sweep",
            "EXECUTED",
            f"{total} IOC values"
        )


# ----------------------------------------------------------------------
# INCIDENT CORRELATION
# ----------------------------------------------------------------------

def correlate_sentinelsoc():

    events = recent_sentinelsoc_events(
        100
    )

    if not events:

        print(
            f"{YELLOW}"
            "[i] SentinelSOC event database "
            "not available."
            f"{RESET}"
        )

        return

    banner(
        "SENTINELSOC EVENT CORRELATION",
        "Existing security events + alert/MITRE enrichment"
    )

    high_risk = 0

    for event in events:

        risk = str(
            event.get("risk") or ""
        ).upper()

        severity = str(
            event.get("severity") or ""
        ).upper()

        if risk in (
            "HIGH",
            "CRITICAL"
        ) or severity == "HIGH":

            high_risk += 1

            print(
                f"{RED}[!] "
                f"{event.get('timestamp')} "
                f"{event.get('event_type')} "
                f"RISK={risk} "
                f"SCORE={event.get('risk_score')}"
                f"{RESET}"
            )

            enriched = enrich_event({
                "type": event.get(
                    "event_type"
                ),
                "severity": severity,
                "fields": {
                    "app": event.get("app"),
                    "permission": event.get(
                        "permission"
                    ),
                    "resource": event.get(
                        "resource"
                    )
                },
                "timestamp": event.get(
                    "timestamp"
                )
            })

            if enriched["alert"]:

                alert = enriched["alert"]

                print(
                    f"  {MAGENTA}"
                    f"ALERT: "
                    f"{alert.get('risk')} "
                    f"{alert.get('risk_score')}"
                    f"{RESET}"
                )

            for technique in (
                enriched["mitre"]
                or []
            ):

                print(
                    f"  {YELLOW}"
                    f"MITRE: "
                    f"{technique.get('id')} - "
                    f"{technique.get('name')}"
                    f"{RESET}"
                )

    print()
    print(
        f"{RED}High-risk events:{RESET} "
        f"{high_risk}"
    )


# ----------------------------------------------------------------------
# CONTAINMENT / RESPONSE SIMULATION
# ----------------------------------------------------------------------

def containment_simulation(case_id):

    case = get_case(case_id)

    if not case:

        print(
            f"{RED}[!] Case not found.{RESET}"
        )

        return

    banner(
        "INCIDENT CONTAINMENT SIMULATION",
        "No destructive endpoint action is executed"
    )

    plan = [
        "Validate alert and affected scope",
        "Preserve volatile evidence",
        "Preserve files and hashes",
        "Identify suspicious processes",
        "Review active connections",
        "Review persistence mechanisms",
        "Block confirmed malicious indicators",
        "Isolate affected asset through approved controls",
        "Rotate exposed credentials/tokens",
        "Eradicate persistence",
        "Recover and monitor",
        "Document lessons learned"
    ]

    for index, action in enumerate(
        plan,
        1
    ):

        print(
            f"{YELLOW}"
            f"[{index:02d}] "
            f"{action}"
            f"{RESET}"
        )

        add_action(
            case_id,
            action,
            "SIMULATION",
            "PROPOSED_ONLY"
        )

    add_finding(
        case_id,
        "RESPONSE",
        "MEDIUM",
        "Containment response plan generated",
        "Simulation only; no destructive endpoint changes."
    )

    print()
    print(
        f"{GREEN}"
        "[+] Response plan recorded in case timeline."
        f"{RESET}"
    )


# ----------------------------------------------------------------------
# CASE REPORT
# ----------------------------------------------------------------------

def generate_report(case_id):

    case = get_case(case_id)

    if not case:

        print(
            f"{RED}[!] Case not found.{RESET}"
        )

        return

    with sqlite3.connect(DB) as conn:

        conn.row_factory = sqlite3.Row

        findings = [
            dict(x)
            for x in conn.execute(
                """
                SELECT *
                FROM findings
                WHERE case_id=?
                ORDER BY id
                """,
                (case_id,)
            ).fetchall()
        ]

        actions = [
            dict(x)
            for x in conn.execute(
                """
                SELECT *
                FROM actions
                WHERE case_id=?
                ORDER BY id
                """,
                (case_id,)
            ).fetchall()
        ]

        evidence = [
            dict(x)
            for x in conn.execute(
                """
                SELECT *
                FROM evidence
                WHERE case_id=?
                ORDER BY id
                """,
                (case_id,)
            ).fetchall()
        ]

    report = {
        "report": "SentinelSOC Incident Response Report",
        "generated_at": now(),
        "case": case,
        "findings": findings,
        "actions": actions,
        "evidence": evidence,
        "workflow": [
            "Identification",
            "Validation",
            "Triage",
            "Evidence Preservation",
            "Scoping",
            "Containment",
            "Eradication",
            "Recovery",
            "Lessons Learned"
        ]
    }

    folder = Path(
        case["evidence_dir"]
    )

    json_report = (
        folder /
        "incident_report.json"
    )

    save_json(
        json_report,
        report
    )

    html_rows = ""

    for finding in findings:

        html_rows += (
            "<tr>"
            f"<td>{finding['category']}</td>"
            f"<td>{finding['severity']}</td>"
            f"<td>{finding['title']}</td>"
            f"<td><pre>"
            f"{finding.get('details') or ''}"
            f"</pre></td>"
            "</tr>"
        )

    html_report = (
        folder /
        "incident_report.html"
    )

    html_report.write_text(
        f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{case['case_id']} - SentinelSOC</title>
<style>
body {{
    background:#0b1117;
    color:#e6edf3;
    font-family:Arial,sans-serif;
    padding:30px;
}}
h1 {{ color:#66d9ef; }}
table {{
    border-collapse:collapse;
    width:100%;
}}
th,td {{
    border:1px solid #334155;
    padding:10px;
    vertical-align:top;
}}
th {{
    background:#16202b;
}}
pre {{
    white-space:pre-wrap;
    word-break:break-word;
}}
.badge {{
    padding:4px 8px;
    border:1px solid #666;
    border-radius:6px;
}}
</style>
</head>
<body>
<h1>SentinelSOC Incident Response Report</h1>

<p><b>Case ID:</b> {case['case_id']}</p>
<p><b>Title:</b> {case['title']}</p>
<p><b>Severity:</b> {case['severity']}</p>
<p><b>Status:</b> {case['status']}</p>
<p><b>Created:</b> {case['created_at']}</p>

<h2>Summary</h2>
<p>{case.get('summary') or ''}</p>

<h2>Findings</h2>

<table>
<tr>
<th>Category</th>
<th>Severity</th>
<th>Title</th>
<th>Details</th>
</tr>

{html_rows}

</table>

</body>
</html>
""",
        encoding="utf-8"
    )

    print(
        f"{GREEN}[+] JSON report:{RESET}"
    )

    print(
        json_report
    )

    print(
        f"{GREEN}[+] HTML report:{RESET}"
    )

    print(
        html_report
    )


# ----------------------------------------------------------------------
# CASE LIST / VIEW
# ----------------------------------------------------------------------

def list_cases():

    banner(
        "CASE MANAGEMENT",
        "Incident lifecycle tracking"
    )

    with sqlite3.connect(DB) as conn:

        rows = conn.execute(
            """
            SELECT
                case_id,
                created_at,
                title,
                severity,
                status
            FROM cases
            ORDER BY created_at DESC
            LIMIT 100
            """
        ).fetchall()

    if not rows:

        print(
            f"{YELLOW}"
            "[i] No incident cases."
            f"{RESET}"
        )

        return

    print(
        f"{'CASE ID':<32}"
        f"{'SEVERITY':<10}"
        f"{'STATUS':<10}"
        f"TITLE"
    )

    print(
        "-" * 90
    )

    for row in rows:

        print(
            f"{row[0]:<32}"
            f"{row[3]:<10}"
            f"{row[4]:<10}"
            f"{row[2]}"
        )


def show_case():

    case = get_case()

    if not case:

        print(
            f"{YELLOW}"
            "[i] No current case."
            f"{RESET}"
        )

        return

    banner(
        "CASE DETAILS",
        case["case_id"]
    )

    print(
        json.dumps(
            case,
            indent=2
        )
    )

    with sqlite3.connect(DB) as conn:

        findings = conn.execute(
            """
            SELECT
                category,
                severity,
                title,
                created_at
            FROM findings
            WHERE case_id=?
            ORDER BY id DESC
            LIMIT 50
            """,
            (case["case_id"],)
        ).fetchall()

    print()

    print(
        f"{CYAN}RECENT FINDINGS{RESET}"
    )

    for row in findings:

        print(
            f"[{row[1]}] "
            f"{row[0]} | "
            f"{row[2]} | "
            f"{row[3]}"
        )


# ----------------------------------------------------------------------
# WATCH MODE
# ----------------------------------------------------------------------

def live_watch():

    banner(
        "SOC LIVE INCIDENT WATCH",
        "Change-oriented monitoring; Ctrl+C to stop"
    )

    previous = None

    try:

        while True:

            processes = process_inventory()

            connections = network_connections()

            listeners = listening_ports()

            high_risk_events = [
                x
                for x in recent_sentinelsoc_events(50)
                if str(
                    x.get("risk") or ""
                ).upper()
                in (
                    "HIGH",
                    "CRITICAL"
                )
            ]

            snapshot = (
                len(processes),
                len(connections),
                len(listeners),
                len(high_risk_events)
            )

            if snapshot != previous:

                print(
                    f"{CYAN}"
                    f"{now()}"
                    f"{RESET} "
                    f"PROC={snapshot[0]} "
                    f"CONN={snapshot[1]} "
                    f"LISTEN={snapshot[2]} "
                    f"HIGH-RISK-EVENTS={snapshot[3]}"
                )

                suspicious = (
                    suspicious_processes(
                        processes
                    )
                )

                if suspicious:

                    print(
                        f"{RED}"
                        f"[!] Suspicious process "
                        f"patterns: "
                        f"{len(suspicious)}"
                        f"{RESET}"
                    )

                if high_risk_events:

                    print(
                        f"{RED}"
                        f"[!] SentinelSOC HIGH/CRITICAL "
                        f"events: "
                        f"{len(high_risk_events)}"
                        f"{RESET}"
                    )

            previous = snapshot

            time.sleep(4)

    except KeyboardInterrupt:

        print(
            f"\n{YELLOW}"
            "[i] Live monitoring stopped."
            f"{RESET}"
        )


# ----------------------------------------------------------------------
# MAIN MENU
# ----------------------------------------------------------------------

def menu():

    init_db()

    while True:

        banner(
            "INCIDENT RESPONSE OPERATIONS",
            "Modern SOC simulation / DFIR workflow"
        )

        print(
            "1.  Live Incident Triage"
        )

        print(
            "2.  Running Services / Process Inventory"
        )

        print(
            "3.  Active Network Connections"
        )

        print(
            "4.  Listening Ports"
        )

        print(
            "5.  Startup / Persistence Review"
        )

        print(
            "6.  Suspicious Process Detection"
        )

        print(
            "7.  IOC Sweep"
        )

        print(
            "8.  Create Incident Case"
        )

        print(
            "9.  Collect Current Case Evidence"
        )

        print(
            "10. Collect File / Directory Evidence"
        )

        print(
            "11. Containment / Response Simulation"
        )

        print(
            "12. Generate Incident Report"
        )

        print(
            "13. Case List"
        )

        print(
            "14. Current / Latest Case"
        )

        print(
            "15. SOC Live Watch"
        )

        print(
            "16. SentinelSOC Alert + MITRE Correlation"
        )

        print(
            "0.  Back"
        )

        choice = input(
            "\nIncident Response > "
        ).strip()

        if choice == "0":

            return

        elif choice == "1":

            triage_snapshot()

        elif choice == "2":

            rows = process_inventory()

            print(
                f"\n{GREEN}"
                f"Processes: {len(rows)}"
                f"{RESET}\n"
            )

            for row in rows[:150]:

                print(
                    row
                )

        elif choice == "3":

            rows = network_connections()

            print(
                f"\n{GREEN}"
                f"Connections: {len(rows)}"
                f"{RESET}\n"
            )

            for row in rows[:150]:

                print(
                    row
                )

        elif choice == "4":

            rows = listening_ports()

            print(
                f"\n{GREEN}"
                f"Listening endpoints: {len(rows)}"
                f"{RESET}\n"
            )

            for row in rows[:150]:

                print(
                    row
                )

        elif choice == "5":

            banner(
                "PERSISTENCE REVIEW"
            )

            print(
                json.dumps(
                    startup_persistence(),
                    indent=2
                )
            )

        elif choice == "6":

            results = suspicious_processes(
                process_inventory()
            )

            if not results:

                print(
                    f"{GREEN}"
                    "[+] No suspicious process "
                    "patterns detected."
                    f"{RESET}"
                )

            else:

                print(
                    f"{RED}"
                    f"[!] Suspicious process findings: "
                    f"{len(results)}"
                    f"{RESET}"
                )

                for result in results:

                    print(
                        json.dumps(
                            result,
                            indent=2,
                            default=str
                        )
                    )

        elif choice == "7":

            ioc_sweep(
                latest_case()
            )

        elif choice == "8":

            create_case()

        elif choice == "9":

            case_id = latest_case()

            if not case_id:

                print(
                    f"{YELLOW}"
                    "[i] Create a case first."
                    f"{RESET}"
                )

            else:

                collect_case_evidence(
                    case_id
                )

        elif choice == "10":

            case_id = latest_case()

            if not case_id:

                print(
                    f"{YELLOW}"
                    "[i] Create a case first."
                    f"{RESET}"
                )

            else:

                collect_file_evidence(
                    case_id
                )

        elif choice == "11":

            case_id = latest_case()

            if not case_id:

                print(
                    f"{YELLOW}"
                    "[i] Create a case first."
                    f"{RESET}"
                )

            else:

                containment_simulation(
                    case_id
                )

        elif choice == "12":

            case_id = latest_case()

            if not case_id:

                print(
                    f"{YELLOW}"
                    "[i] Create a case first."
                    f"{RESET}"
                )

            else:

                generate_report(
                    case_id
                )

        elif choice == "13":

            list_cases()

        elif choice == "14":

            show_case()

        elif choice == "15":

            live_watch()

        elif choice == "16":

            correlate_sentinelsoc()

        else:

            print(
                f"{RED}"
                "[!] Invalid choice."
                f"{RESET}"
            )


if __name__ == "__main__":

    try:

        menu()

    except KeyboardInterrupt:

        print(
            f"\n{YELLOW}"
            "[i] Incident Response stopped."
            f"{RESET}"
        )

    except Exception as e:

        print(
            f"\n{RED}"
            f"[!] Incident Response error: "
            f"{type(e).__name__}: {e}"
            f"{RESET}"
        )

# Compatibility alias for older callers.
def recent_sentinel_soc_events(limit=100):
    return recent_sentinelsoc_events(limit)
