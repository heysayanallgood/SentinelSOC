import sqlite3


DB = "assets/mitre/sentinel_mitre.db"


def connect():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def technique_by_id(attack_id):

    conn = connect()

    row = conn.execute("""
        SELECT *
        FROM techniques
        WHERE UPPER(attack_id)=UPPER(?)
    """, (attack_id,)).fetchone()

    conn.close()

    return row


def group_by_name(name):

    conn = connect()

    row = conn.execute("""
        SELECT *
        FROM groups
        WHERE LOWER(name)=LOWER(?)
           OR LOWER(aliases) LIKE LOWER(?)
        LIMIT 1
    """, (name, f"%{name}%")).fetchone()

    conn.close()

    return row


def related_objects(stix_id, relationship_type=None):

    conn = connect()

    if relationship_type:

        rows = conn.execute("""
            SELECT *
            FROM relationships
            WHERE
                (source_ref=? OR target_ref=?)
                AND relationship_type=?
        """, (
            stix_id,
            stix_id,
            relationship_type
        )).fetchall()

    else:

        rows = conn.execute("""
            SELECT *
            FROM relationships
            WHERE source_ref=?
               OR target_ref=?
        """, (
            stix_id,
            stix_id
        )).fetchall()

    conn.close()

    return rows


def object_by_stix(stix_id):

    conn = connect()

    row = conn.execute("""
        SELECT *
        FROM objects
        WHERE id=?
    """, (stix_id,)).fetchone()

    conn.close()

    return row


def technique_profile(attack_id):

    technique = technique_by_id(attack_id)

    if not technique:
        return None

    relationships = related_objects(
        technique["stix_id"]
    )

    groups = []
    software = []
    campaigns = []
    mitigations = []
    detections = []

    for rel in relationships:

        if rel["source_ref"] == technique["stix_id"]:
            other_id = rel["target_ref"]
        else:
            other_id = rel["source_ref"]

        obj = object_by_stix(other_id)

        if not obj:
            continue

        if obj["type"] == "intrusion-set":
            groups.append(obj)

        elif obj["type"] in ("malware", "tool"):
            software.append(obj)

        elif obj["type"] == "campaign":
            campaigns.append(obj)

        elif obj["type"] == "course-of-action":
            mitigations.append(obj)

        elif obj["type"] == "x-mitre-detection-strategy":
            detections.append(obj)

    return {
        "technique": technique,
        "groups": groups,
        "software": software,
        "campaigns": campaigns,
        "mitigations": mitigations,
        "detections": detections
    }


def print_profile(attack_id):

    profile = technique_profile(attack_id)

    if not profile:
        print("Technique not found.")
        return

    t = profile["technique"]

    print()
    print("=" * 70)
    print("             MITRE ATT&CK THREAT PROFILE")
    print("=" * 70)

    print(f"Technique : {t['attack_id']}")
    print(f"Name      : {t['name']}")
    print(f"Tactics   : {t['tactic']}")
    print(f"Platforms : {t['platforms']}")

    print()
    print("DESCRIPTION")
    print("-" * 70)
    print(t["description"])

    print()
    print("THREAT GROUPS")
    print("-" * 70)

    seen = set()

    for g in profile["groups"]:

        if g["id"] in seen:
            continue

        seen.add(g["id"])

        print(f"• {g['name']}")

    print()
    print("SOFTWARE")
    print("-" * 70)

    seen = set()

    for s in profile["software"]:

        if s["id"] in seen:
            continue

        seen.add(s["id"])

        print(f"• {s['name']}")

    print()
    print("CAMPAIGNS")
    print("-" * 70)

    for c in profile["campaigns"]:
        print(f"• {c['name']}")

    print()
    print("RELATIONSHIPS")
    print("-" * 70)

    print(
        f"Threat Groups : {len(profile['groups'])}"
    )

    print(
        f"Software      : {len(profile['software'])}"
    )

    print(
        f"Campaigns     : {len(profile['campaigns'])}"
    )

    print("=" * 70)


if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:
        print("Usage:")
        print("python core/mitre_intelligence.py T1078")
        sys.exit(1)

    print_profile(sys.argv[1])


def group_profile(name):

    group = group_by_name(name)

    if not group:
        return None

    relationships = related_objects(group["id"])

    techniques = []
    software = []
    campaigns = []

    for rel in relationships:

        other_id = (
            rel["target_ref"]
            if rel["source_ref"] == group["id"]
            else rel["source_ref"]
        )

        obj = object_by_stix(other_id)

        if not obj:
            continue

        if obj["type"] == "attack-pattern":
            techniques.append(obj)

        elif obj["type"] in ("malware", "tool"):
            software.append(obj)

        elif obj["type"] == "campaign":
            campaigns.append(obj)

    return {
        "group": group,
        "techniques": techniques,
        "software": software,
        "campaigns": campaigns
    }
