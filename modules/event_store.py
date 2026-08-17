#!/usr/bin/env python3

import json
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path("assets/sentinel_events.db")


def get_connection():
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
    return conn


def save_event(event, alert=None, mitre=None):

    fields = event.get("fields", {})
    iocs = event.get("iocs", {})

    mitre = mitre or []

    conn = get_connection()

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
        alert.get("risk") if alert else None,
        alert.get("risk_score") if alert else None,
        fields.get("app"),
        fields.get("permission"),
        fields.get("resource"),
        fields.get("device"),
        json.dumps(iocs),
        json.dumps([
            {
                "id": m.get("id"),
                "name": m.get("name")
            }
            for m in mitre
        ]),
        event.get("raw", "")
    ))

    conn.commit()
    conn.close()


def recent_events(limit=20):

    conn = get_connection()

    rows = conn.execute("""
        SELECT
            id,
            timestamp,
            event_type,
            severity,
            risk,
            risk_score,
            app,
            permission,
            resource,
            device
        FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()

    conn.close()
    return rows
