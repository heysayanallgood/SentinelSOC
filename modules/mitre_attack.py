import json
import re
from pathlib import Path

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

MITRE_FILE = DATA_DIR / "mobile-attack.json"

MITRE_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/"
    "mobile-attack/mobile-attack.json"
)


def download_mitre():
    import requests

    print("[*] Downloading MITRE ATT&CK Mobile dataset...")

    r = requests.get(MITRE_URL, timeout=30)
    r.raise_for_status()

    MITRE_FILE.write_text(r.text)

    print("[+] MITRE Mobile dataset downloaded")
    return MITRE_FILE


def load_mitre():
    if not MITRE_FILE.exists():
        download_mitre()

    return json.loads(MITRE_FILE.read_text())


def techniques():
    data = load_mitre()

    return [
        obj for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]


def search(query):
    query = query.lower()

    results = []

    for technique in techniques():
        name = technique.get("name", "")
        description = technique.get("description", "")

        if query in name.lower() or query in description.lower():
            refs = technique.get("external_references", [])

            attack_id = next(
                (
                    x.get("external_id")
                    for x in refs
                    if x.get("source_name") == "mitre-attack"
                ),
                "N/A"
            )

            results.append({
                "id": attack_id,
                "name": name,
                "description": description[:300]
            })

    return results


def map_event(event):
    text = json.dumps(event).lower()

    mappings = [
        (
            ["permission_denied", "selinux", "avc: denied"],
            "T1629.001",
            "System Binary Proxy Execution"
        ),
        (
            ["shell", "sh ", "bash", "command"],
            "T1059",
            "Command and Scripting Interpreter"
        ),
        (
            ["download", "http", "https", "curl", "wget"],
            "T1105",
            "Ingress Tool Transfer"
        ),
        (
            ["credential", "password", "authentication"],
            "T1555",
            "Credentials from Password Stores"
        ),
    ]

    matches = []

    for keywords, attack_id, name in mappings:
        if any(keyword in text for keyword in keywords):
            matches.append({
                "id": attack_id,
                "name": name
            })

    return matches


def test():
    print("\n=== SENTINELSOC MITRE ATT&CK ===")

    data = load_mitre()

    print(f"[+] Loaded {len(data.get('objects', []))} STIX objects")
    print(f"[+] Techniques: {len(techniques())}")

    print("\nSample techniques:")

    for t in techniques()[:10]:
        refs = t.get("external_references", [])

        attack_id = next(
            (
                x.get("external_id")
                for x in refs
                if x.get("source_name") == "mitre-attack"
            ),
            "N/A"
        )

        print(f"  {attack_id} - {t.get('name')}")


if __name__ == "__main__":
    test()
