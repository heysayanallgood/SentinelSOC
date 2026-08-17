#!/usr/bin/env python3

import subprocess
import re
import json
import sqlite3
from pathlib import Path
from datetime import datetime

from modules.alert_engine import create_alert
from modules.mitre_attack import map_event


# ============================================================
# SENTINELSOC ANDROID LOGCAT MONITOR
# IOC + ALERT ENGINE + MITRE + PERSISTENCE
# ============================================================


DB_PATH = Path("assets/sentinel_events.db")


# ============================================================
# DATABASE
# ============================================================

def init_database():

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            risk TEXT,
            risk_score INTEGER,
            app TEXT,
            permission TEXT,
            resource TEXT,
            device TEXT,
            iocs TEXT,
            mitre TEXT,
            raw TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_event(event, alert, matches):

    fields = event.get("fields", {})
    iocs = event.get("iocs", {})

    mitre_data = []

    for m in matches:
        mitre_data.append({
            "id": m.get("id"),
            "name": m.get("name")
        })

    conn = sqlite3.connect(DB_PATH)

    conn.execute("""
        INSERT INTO events (
            timestamp,
            event_type,
            severity,
            risk,
            risk_score,
            app,
            permission,
            resource,
            device,
            iocs,
            mitre,
            raw
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp"),
        event.get("type"),
        event.get("severity"),
        alert.get("risk"),
        alert.get("risk_score"),
        fields.get("app"),
        fields.get("permission"),
        fields.get("resource"),
        fields.get("device"),
        json.dumps(iocs),
        json.dumps(mitre_data),
        event.get("raw", "")
    ))

    conn.commit()
    conn.close()


# ============================================================
# IOC ENGINE
# ============================================================

IP_RE = re.compile(
    r'(?<!\d)'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}'
    r'(?!\d)'
)

URL_RE = re.compile(
    r'https?://[^\s\'"]+',
    re.IGNORECASE
)

HASH_RE = re.compile(
    r'\b[a-fA-F0-9]{32}\b|'
    r'\b[a-fA-F0-9]{40}\b|'
    r'\b[a-fA-F0-9]{64}\b'
)

PACKAGE_RE = re.compile(
    r'\b[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+){2,}\b'
)

PATH_RE = re.compile(
    r'(?<!\w)(/(?:data|system|vendor|sdcard|storage|tmp|proc|dev|etc|usr)'
    r'/[^\s,"\']+)'
)


def unique(values):
    return list(dict.fromkeys(values))


def extract_iocs(event):

    raw = event.get("raw", "")
    fields = event.get("fields", {})

    text = raw + " " + " ".join(
        str(v) for v in fields.values()
    )

    return {
        "ips": unique(IP_RE.findall(text)),
        "urls": unique(URL_RE.findall(text)),
        "hashes": unique(HASH_RE.findall(text)),
        "paths": unique(PATH_RE.findall(text)),
        "packages": [
            pkg for pkg in unique(PACKAGE_RE.findall(text))
            if not (
                pkg.startswith("android.")
                or pkg.startswith("androidx.")
                or pkg.startswith("com.android.")
                or pkg.startswith("com.google.android.")
                or pkg.startswith("com.google.")
                or pkg.startswith("java.")
                or pkg.startswith("javax.")
                or pkg.startswith("kotlin.")
                or pkg.startswith("dalvik.")
            )
        ]
    }


# ============================================================
# NORMALIZER
# ============================================================

def normalize(line):

    line = line.strip()

    if not line:
        return None

    # --------------------------------------------------------
    # Android threadtime timestamp
    # Example:
    # 08-17 18:05:00.726
    # --------------------------------------------------------

    timestamp_match = re.search(
        r'^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)',
        line
    )

    timestamp = (
        timestamp_match.group(1)
        if timestamp_match
        else datetime.now().strftime("%m-%d %H:%M:%S.%f")[:-3]
    )

    # --------------------------------------------------------
    # PERMISSION DENIED / AVC
    # --------------------------------------------------------

    if "avc: denied" in line.lower():

        permission_match = re.search(
            r'avc:\s+denied\s+\{\s*([^}]+)\s*\}',
            line,
            re.IGNORECASE
        )

        permission = (
            permission_match.group(1).strip()
            if permission_match
            else "unknown"
        )

        app_match = re.search(
            r'app=([^\s]+)',
            line
        )

        app = (
            app_match.group(1)
            if app_match
            else "unknown"
        )

        resource_match = re.search(
            r'name="([^"]+)"',
            line
        )

        resource = (
            resource_match.group(1)
            if resource_match
            else "unknown"
        )

        device_match = re.search(
            r'dev="([^"]+)"',
            line
        )

        device = (
            device_match.group(1)
            if device_match
            else "unknown"
        )

        return {
            "timestamp": timestamp,
            "type": "PERMISSION_DENIED",
            "severity": "HIGH",
            "fields": {
                "app": app,
                "permission": permission,
                "resource": resource,
                "device": device
            },
            "raw": line
        }

    # --------------------------------------------------------
    # COMMAND NOT FOUND
    # --------------------------------------------------------

    if "command-not-found" in line.lower():

        return {
            "timestamp": timestamp,
            "type": "COMMAND_NOT_FOUND",
            "severity": "MEDIUM",
            "fields": {},
            "raw": line
        }

    # --------------------------------------------------------
    # SYSTEM / OTHER
    # --------------------------------------------------------

    return {
        "timestamp": timestamp,
        "type": "SYSTEM",
        "severity": "LOW",
        "fields": {},
        "raw": line
    }


# ============================================================
# LIVE MONITOR
# ============================================================

def live():

    init_database()

    print()
    print("=" * 60)
    print(" SENTINELSOC LIVE ANDROID SECURITY MONITOR")
    print("=" * 60)
    print(" Monitoring RAW Android logcat events.")
    print(" IOC extraction       : ENABLED")
    print(" Risk engine          : ENABLED")
    print(" MITRE ATT&CK         : ENABLED")
    print(" Event persistence    : ENABLED")
    print(" Deduplication        : ENABLED")
    print(" Database             :", DB_PATH)
    print(" Press CTRL+C to stop.")
    print("=" * 60)
    print()

    process = None

    # Prevent repeated identical events from flooding output
    last_event = None
    last_event_time = 0

    try:

        process = subprocess.Popen(
            ["logcat", "-v", "threadtime"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:

            line = line.strip()

            if not line:
                continue

            event = normalize(line)

            if not event:
                continue

            # ------------------------------------------------
            # IOC EXTRACTION
            # ------------------------------------------------

            event["iocs"] = extract_iocs(event)

            # ------------------------------------------------
            # DEDUPLICATION
            # ------------------------------------------------

            current_key = (
                event["type"],
                json.dumps(event["fields"], sort_keys=True),
                event["raw"]
            )

            now = datetime.now().timestamp()

            if (
                current_key == last_event
                and now - last_event_time < 5
            ):
                continue

            last_event = current_key
            last_event_time = now

            # ------------------------------------------------
            # ALERT ENGINE
            # ------------------------------------------------

            alert = create_alert(event)

            # ------------------------------------------------
            # MITRE ATT&CK
            # ------------------------------------------------

            matches = map_event(event)

            # ------------------------------------------------
            # SAVE EVERYTHING
            # ------------------------------------------------

            save_event(
                event,
                alert,
                matches
            )

            # ------------------------------------------------
            # DISPLAY EVENT
            # ------------------------------------------------

            print()
            print("-" * 60)
            print("[+] SECURITY EVENT DETECTED")
            print("-" * 60)

            print(f"TYPE       : {event['type']}")
            print(f"SEVERITY   : {event['severity']}")
            print(f"TIMESTAMP  : {event['timestamp']}")
            print(f"FIELDS     : {event['fields']}")

            print()
            print("[+] ALERT ENGINE")
            print(f"    RISK       : {alert['risk']}")
            print(f"    RISK SCORE : {alert['risk_score']}")

            # ------------------------------------------------
            # IOC DISPLAY
            # ------------------------------------------------

            found_ioc = False

            for key, values in event["iocs"].items():

                if values:

                    if not found_ioc:
                        print()
                        print("[+] IOC EXTRACTION")

                    found_ioc = True

                    print(
                        f"    {key.upper():10}: "
                        + ", ".join(values)
                    )

            if not found_ioc:
                print()
                print("[i] IOC EXTRACTION : No IOC detected")

            # ------------------------------------------------
            # CRITICAL / HIGH ALERT
            # ------------------------------------------------

            if alert["risk_score"] >= 70:

                print()
                print("🚨 SENTINELSOC SECURITY ALERT")
                print("=" * 48)

                fields = event.get("fields", {})

                print(
                    f"APP        : "
                    f"{fields.get('app', '-')}"
                )

                print(
                    f"PERMISSION : "
                    f"{fields.get('permission', '-')}"
                )

                print(
                    f"RESOURCE   : "
                    f"{fields.get('resource', '-')}"
                )

                print(
                    f"DEVICE     : "
                    f"{fields.get('device', '-')}"
                )

                print(
                    f"RISK       : "
                    f"{alert['risk']}"
                )

                print(
                    f"RISK SCORE : "
                    f"{alert['risk_score']}"
                )

                # --------------------------------------------
                # MITRE
                # --------------------------------------------

                print()
                print("MITRE ATT&CK CORRELATION")

                if matches:

                    for match in matches:

                        print(
                            f"[+] {match['id']} - "
                            f"{match['name']}"
                        )

                else:

                    print("[-] No MITRE match")

                print("=" * 48)

            else:

                print()
                print("[i] Event below alert threshold")

            print()

    except KeyboardInterrupt:

        print()
        print("[i] Live monitoring stopped.")

    except Exception as e:

        print()
        print("[!] Live monitor error:", e)

    finally:

        if process:

            try:
                process.terminate()
            except Exception:
                pass


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    live()
