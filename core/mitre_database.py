import json
import sqlite3
from pathlib import Path
from datetime import datetime


MITRE_FILE = Path("assets/mitre/enterprise-attack.json")
DB_FILE = Path("assets/mitre/sentinel_mitre.db")


def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def create_database(conn):
    cur = conn.cursor()

    cur.executescript("""
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;

    DROP TABLE IF EXISTS relationships;
    DROP TABLE IF EXISTS objects;
    DROP TABLE IF EXISTS techniques;
    DROP TABLE IF EXISTS groups;
    DROP TABLE IF EXISTS software;
    DROP TABLE IF EXISTS campaigns;
    DROP TABLE IF EXISTS mitigations;
    DROP TABLE IF EXISTS data_sources;
    DROP TABLE IF EXISTS data_components;
    DROP TABLE IF EXISTS detection_strategies;
    DROP TABLE IF EXISTS attack_analytics;

    CREATE TABLE objects (
        id TEXT PRIMARY KEY,
        type TEXT,
        name TEXT,
        description TEXT,
        created TEXT,
        modified TEXT,
        revoked INTEGER DEFAULT 0,
        deprecated INTEGER DEFAULT 0,
        raw_json TEXT
    );

    CREATE TABLE techniques (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        tactic TEXT,
        platforms TEXT,
        is_subtechnique INTEGER DEFAULT 0,
        parent_attack_id TEXT,
        url TEXT
    );

    CREATE TABLE groups (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        aliases TEXT,
        country TEXT,
        url TEXT
    );

    CREATE TABLE software (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        software_type TEXT,
        platforms TEXT,
        url TEXT
    );

    CREATE TABLE campaigns (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        aliases TEXT,
        url TEXT
    );

    CREATE TABLE mitigations (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        url TEXT
    );

    CREATE TABLE data_sources (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        url TEXT
    );

    CREATE TABLE data_components (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        url TEXT
    );

    CREATE TABLE detection_strategies (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        url TEXT
    );

    CREATE TABLE attack_analytics (
        stix_id TEXT PRIMARY KEY,
        attack_id TEXT,
        name TEXT,
        description TEXT,
        url TEXT
    );

    CREATE TABLE relationships (
        id TEXT PRIMARY KEY,
        source_ref TEXT,
        target_ref TEXT,
        relationship_type TEXT,
        description TEXT,
        created TEXT,
        modified TEXT,
        raw_json TEXT
    );

    CREATE INDEX idx_tech_attack_id
        ON techniques(attack_id);

    CREATE INDEX idx_tech_name
        ON techniques(name);

    CREATE INDEX idx_group_attack_id
        ON groups(attack_id);

    CREATE INDEX idx_group_name
        ON groups(name);

    CREATE INDEX idx_software_attack_id
        ON software(attack_id);

    CREATE INDEX idx_campaign_attack_id
        ON campaigns(attack_id);

    CREATE INDEX idx_rel_source
        ON relationships(source_ref);

    CREATE INDEX idx_rel_target
        ON relationships(target_ref);

    CREATE INDEX idx_rel_type
        ON relationships(relationship_type);
    """)

    conn.commit()


def external_id(obj):
    for ref in obj.get("external_references", []):
        ext = ref.get("external_id")
        if ext and (
            ext.startswith("T")
            or ext.startswith("G")
            or ext.startswith("S")
            or ext.startswith("C")
            or ext.startswith("M")
            or ext.startswith("DS")
            or ext.startswith("DET")
            or ext.startswith("AN")
        ):
            return ext
    return None


def mitre_url(obj):
    for ref in obj.get("external_references", []):
        url = ref.get("url")
        if url and "attack.mitre.org" in url:
            return url
    return None


def get_description(obj):
    return obj.get("description") or ""


def load():
    if not MITRE_FILE.exists():
        raise FileNotFoundError(
            f"MITRE dataset not found: {MITRE_FILE}"
        )

    print("[+] Loading MITRE ATT&CK STIX dataset...")
    print(f"[+] Source: {MITRE_FILE}")

    with open(MITRE_FILE, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    print(f"[+] STIX objects found: {len(objects)}")

    conn = connect()
    create_database(conn)

    cur = conn.cursor()

    technique_objects = {}
    group_objects = {}
    software_objects = {}
    campaign_objects = {}

    # ---------------------------------------------------------
    # Store all objects
    # ---------------------------------------------------------

    for obj in objects:

        obj_id = obj.get("id")

        if not obj_id:
            continue

        cur.execute("""
            INSERT OR REPLACE INTO objects
            (
                id,
                type,
                name,
                description,
                created,
                modified,
                revoked,
                deprecated,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            obj_id,
            obj.get("type"),
            obj.get("name"),
            get_description(obj),
            obj.get("created"),
            obj.get("modified"),
            int(bool(obj.get("revoked"))),
            int(bool(obj.get("x_mitre_deprecated"))),
            json.dumps(obj, ensure_ascii=False)
        ))

        obj_type = obj.get("type")

        if obj_type == "attack-pattern":
            technique_objects[obj_id] = obj

        elif obj_type == "intrusion-set":
            group_objects[obj_id] = obj

        elif obj_type == "malware" or obj_type == "tool":
            software_objects[obj_id] = obj

        elif obj_type == "campaign":
            campaign_objects[obj_id] = obj

    # ---------------------------------------------------------
    # Techniques
    # ---------------------------------------------------------

    for obj_id, obj in technique_objects.items():

        attack_id = external_id(obj)

        if not attack_id:
            continue

        tactics = obj.get("x_mitre_version")
        kill_chain = obj.get("kill_chain_phases", [])

        tactic_names = [
            x.get("phase_name", "").replace("-", " ").title()
            for x in kill_chain
        ]

        platforms = obj.get("x_mitre_platforms", [])

        parent = None

        if "." in attack_id:
            parent = attack_id.split(".")[0]

        cur.execute("""
            INSERT OR REPLACE INTO techniques
            (
                stix_id,
                attack_id,
                name,
                description,
                tactic,
                platforms,
                is_subtechnique,
                parent_attack_id,
                url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            obj_id,
            attack_id,
            obj.get("name", ""),
            get_description(obj),
            ", ".join(tactic_names),
            ", ".join(platforms),
            int("." in attack_id),
            parent,
            mitre_url(obj)
        ))

    # ---------------------------------------------------------
    # Groups
    # ---------------------------------------------------------

    for obj_id, obj in group_objects.items():

        attack_id = external_id(obj)

        if not attack_id:
            continue

        aliases = obj.get("aliases", [])

        cur.execute("""
            INSERT OR REPLACE INTO groups
            (
                stix_id,
                attack_id,
                name,
                description,
                aliases,
                country,
                url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            obj_id,
            attack_id,
            obj.get("name", ""),
            get_description(obj),
            ", ".join(aliases),
            "",
            mitre_url(obj)
        ))

    # ---------------------------------------------------------
    # Software
    # ---------------------------------------------------------

    for obj_id, obj in software_objects.items():

        attack_id = external_id(obj)

        if not attack_id:
            continue

        cur.execute("""
            INSERT OR REPLACE INTO software
            (
                stix_id,
                attack_id,
                name,
                description,
                software_type,
                platforms,
                url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            obj_id,
            attack_id,
            obj.get("name", ""),
            get_description(obj),
            obj.get("x_mitre_aliases", [""])[0]
            if obj.get("x_mitre_aliases")
            else obj.get("type", ""),
            ", ".join(obj.get("x_mitre_platforms", [])),
            mitre_url(obj)
        ))

    # ---------------------------------------------------------
    # Campaigns
    # ---------------------------------------------------------

    for obj_id, obj in campaign_objects.items():

        attack_id = external_id(obj)

        if not attack_id:
            continue

        cur.execute("""
            INSERT OR REPLACE INTO campaigns
            (
                stix_id,
                attack_id,
                name,
                description,
                aliases,
                url
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            obj_id,
            attack_id,
            obj.get("name", ""),
            get_description(obj),
            ", ".join(obj.get("aliases", [])),
            mitre_url(obj)
        ))

    # ---------------------------------------------------------
    # Relationships
    # ---------------------------------------------------------

    relationship_count = 0

    for obj in objects:

        if obj.get("type") != "relationship":
            continue

        rel_id = obj.get("id")

        if not rel_id:
            continue

        cur.execute("""
            INSERT OR REPLACE INTO relationships
            (
                id,
                source_ref,
                target_ref,
                relationship_type,
                description,
                created,
                modified,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rel_id,
            obj.get("source_ref"),
            obj.get("target_ref"),
            obj.get("relationship_type"),
            obj.get("description", ""),
            obj.get("created"),
            obj.get("modified"),
            json.dumps(obj, ensure_ascii=False)
        ))

        relationship_count += 1

    conn.commit()

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    def count(table):
        return cur.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]

    print()
    print("==========================================")
    print("       SENTINELSOC MITRE DATABASE")
    print("==========================================")
    print(f"Objects          : {count('objects')}")
    print(f"Techniques       : {count('techniques')}")
    print(f"Groups           : {count('groups')}")
    print(f"Software         : {count('software')}")
    print(f"Campaigns        : {count('campaigns')}")
    print(f"Relationships    : {relationship_count}")
    print(f"Database         : {DB_FILE}")
    print("==========================================")

    conn.close()


if __name__ == "__main__":
    load()
