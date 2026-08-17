#!/usr/bin/env python3

import os
import sys
import re
import json
import math
import hashlib
import mimetypes
import zipfile
import sqlite3
import subprocess
import shutil
import datetime
import csv
from pathlib import Path
from collections import Counter

# ============================================================
# SENTINELSOC - DIGITAL FORENSICS ENGINE
# APK | EXE | PDF | DOC/DOCX | PPT/PPTX | XLS/XLSX
# IMAGE | ARCHIVE | SQLITE | BROWSER | GENERIC FILE
# HASH | METADATA | STRINGS | ENTROPY | IOC | TIMELINE
# YARA (OPTIONAL) | SIGNATURE | SUSPICIOUS INDICATORS
# ============================================================

VERSION = "2.0"
REPORT_DIR = Path.home() / "SentinelSOC" / "modules" / "forensics_reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

IOC_PATTERNS = {
    "IPv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "URL": re.compile(
        r"\bhttps?://[^\s\"'<>]+",
        re.I
    ),
    "Domain": re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|biz|xyz|top|ru|cn|in|io|dev|app|online|site|me|co|uk|de|fr|live|tech)\b",
        re.I
    ),
    "Email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "WindowsPath": re.compile(r"[A-Za-z]:\\[^\"'\r\n]+"),
    "UnixPath": re.compile(r"/(?:bin|tmp|var|etc|usr|home|data)/[A-Za-z0-9_./-]+"),
}

SUSPICIOUS_TERMS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "schtasks",
    "startup",
    "autorun",
    "appdata",
    "temp",
    "download",
    "invoke-expression",
    "base64",
    "frombase64string",
    "mimikatz",
    "keylogger",
    "credential",
    "password",
    "token",
    "cookie",
    "webhook",
    "reverse shell",
    "shell",
    "chmod +x",
    "nc -e",
    "bash -i",
    "eval(",
    "exec(",
]

FILE_TYPES = {
    ".apk": "Android APK",
    ".aab": "Android App Bundle",
    ".exe": "Windows PE Executable",
    ".dll": "Windows PE DLL",
    ".sys": "Windows Driver",
    ".pdf": "PDF Document",
    ".doc": "Microsoft Word",
    ".docx": "Microsoft Word OOXML",
    ".ppt": "Microsoft PowerPoint",
    ".pptx": "Microsoft PowerPoint OOXML",
    ".xls": "Microsoft Excel",
    ".xlsx": "Microsoft Excel OOXML",
    ".xlsm": "Excel Macro Workbook",
    ".jpg": "JPEG Image",
    ".jpeg": "JPEG Image",
    ".png": "PNG Image",
    ".gif": "GIF Image",
    ".bmp": "Bitmap Image",
    ".webp": "WebP Image",
    ".zip": "ZIP Archive",
    ".rar": "RAR Archive",
    ".7z": "7-Zip Archive",
    ".tar": "TAR Archive",
    ".gz": "GZIP Archive",
    ".db": "SQLite Database",
    ".sqlite": "SQLite Database",
    ".sqlite3": "SQLite Database",
    ".log": "Log File",
    ".txt": "Text File",
    ".json": "JSON File",
    ".xml": "XML File",
    ".csv": "CSV File",
}

# ============================================================
# UI
# ============================================================

def banner():
    print("\033[96m")
    print("=" * 72)
    print("              SENTINELSOC DIGITAL FORENSICS")
    print("=" * 72)
    print("\033[0m")
    print(f"Engine Version : {VERSION}")
    print("Analysis       : Static / Offline / Read-Only")
    print("Supported      : APK EXE PDF DOC PPT XLS Images Archives DB Logs")
    print()

def ask_path():
    p = input("Enter file or directory path: ").strip()
    p = p.strip('"').strip("'")
    return Path(p).expanduser()

def human_size(n):
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

def timestamp():
    return datetime.datetime.now().isoformat(timespec="seconds")

# ============================================================
# HASHING
# ============================================================

def calculate_hashes(path):
    hashes = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256(),
    }

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                for h in hashes.values():
                    h.update(chunk)

        return {k: v.hexdigest() for k, v in hashes.items()}
    except Exception as e:
        return {"error": str(e)}

# ============================================================
# ENTROPY
# ============================================================

def entropy(path):
    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 1024)

        if not data:
            return 0.0

        counts = Counter(data)
        length = len(data)

        result = 0.0
        for count in counts.values():
            p = count / length
            result -= p * math.log2(p)

        return round(result, 4)
    except Exception:
        return 0.0

# ============================================================
# STRINGS
# ============================================================

def extract_strings(path, minimum=5):
    results = []

    try:
        with open(path, "rb") as f:
            data = f.read()

        ascii_strings = re.findall(
            rb"[\x20-\x7e]{%d,}" % minimum,
            data
        )

        for s in ascii_strings:
            try:
                results.append(s.decode("utf-8", errors="ignore"))
            except Exception:
                pass

        # UTF-16LE strings
        utf16 = re.findall(
            rb"(?:[\x20-\x7e]\x00){%d,}" % minimum,
            data
        )

        for s in utf16:
            try:
                results.append(
                    s.decode("utf-16le", errors="ignore")
                )
            except Exception:
                pass

        return list(dict.fromkeys(results))

    except Exception:
        return []

# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(text):
    findings = {}

    for name, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings[name] = sorted(set(matches))

    return findings

# ============================================================
# SUSPICIOUS INDICATORS
# ============================================================

def suspicious_indicators(text):
    lower = text.lower()
    findings = []

    for term in SUSPICIOUS_TERMS:
        if term.lower() in lower:
            findings.append(term)

    return sorted(set(findings))

# ============================================================
# FILE SIGNATURE
# ============================================================

def file_signature(path):
    try:
        with open(path, "rb") as f:
            magic = f.read(32)

        if magic.startswith(b"MZ"):
            return "PE / Windows executable"

        if magic.startswith(b"%PDF"):
            return "PDF"

        if magic.startswith(b"PK"):
            return "ZIP / OOXML / APK container"

        if magic.startswith(b"\x89PNG"):
            return "PNG"

        if magic.startswith(b"\xff\xd8\xff"):
            return "JPEG"

        if magic.startswith(b"GIF8"):
            return "GIF"

        if magic.startswith(b"SQLite format 3"):
            return "SQLite database"

        if magic.startswith(b"\x7fELF"):
            return "ELF executable"

        return "Unknown / Generic"

    except Exception as e:
        return f"Error: {e}"

# ============================================================
# METADATA
# ============================================================

def metadata(path):
    stat = path.stat()

    return {
        "name": path.name,
        "extension": path.suffix.lower(),
        "size": stat.st_size,
        "size_human": human_size(stat.st_size),
        "created": datetime.datetime.fromtimestamp(
            stat.st_ctime
        ).isoformat(timespec="seconds"),
        "modified": datetime.datetime.fromtimestamp(
            stat.st_mtime
        ).isoformat(timespec="seconds"),
        "accessed": datetime.datetime.fromtimestamp(
            stat.st_atime
        ).isoformat(timespec="seconds"),
        "mime": mimetypes.guess_type(str(path))[0],
        "signature": file_signature(path),
    }

# ============================================================
# APK ANALYSIS
# ============================================================

def analyze_apk(path):
    result = {
        "type": "APK",
        "files": [],
        "manifest": [],
        "dex": [],
        "native": [],
        "permissions": [],
    }

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            result["files"] = names[:500]

            for n in names:
                if n.startswith("classes") and n.endswith(".dex"):
                    result["dex"].append(n)

                if n.endswith(".so"):
                    result["native"].append(n)

                if "AndroidManifest.xml" in n:
                    result["manifest"].append(n)

            strings = extract_strings(path, 6)
            text = "\n".join(strings)

            permission_pattern = re.compile(
                r"android\.permission\.[A-Z0-9_]+"
            )

            result["permissions"] = sorted(
                set(permission_pattern.findall(text))
            )

    except Exception as e:
        result["error"] = str(e)

    return result

# ============================================================
# PE / EXE ANALYSIS
# ============================================================

def analyze_pe(path):
    result = {
        "type": "PE",
        "imports": [],
        "sections": [],
        "indicators": [],
    }

    try:
        data = path.read_bytes()

        if not data.startswith(b"MZ"):
            result["error"] = "Not a valid MZ/PE file"
            return result

        result["mz_header"] = True

        # Basic PE offset
        if len(data) >= 0x40:
            pe_offset = int.from_bytes(
                data[0x3c:0x40],
                "little"
            )

            result["pe_header_offset"] = pe_offset

            if (
                pe_offset + 4 <= len(data)
                and data[pe_offset:pe_offset + 4] == b"PE\x00\x00"
            ):
                result["valid_pe_signature"] = True

        strings = extract_strings(path)
        text = "\n".join(strings)

        interesting = [
            s for s in strings
            if any(
                x.lower() in s.lower()
                for x in [
                    "kernel32",
                    "advapi32",
                    "user32",
                    "wininet",
                    "ws2_32",
                    "powershell",
                    "cmd.exe",
                    "http",
                    "https",
                    "VirtualAlloc",
                    "CreateRemoteThread",
                    "WriteProcessMemory",
                ]
            )
        ]

        result["indicators"] = interesting[:200]

    except Exception as e:
        result["error"] = str(e)

    return result

# ============================================================
# OOXML: DOCX / PPTX / XLSX
# ============================================================

def analyze_ooxml(path):
    result = {
        "type": "OOXML",
        "files": [],
        "metadata": {},
        "macros": [],
        "external_links": [],
        "relationships": [],
    }

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()

            result["files"] = names[:500]

            for n in names:
                low = n.lower()

                if "vba" in low or low.endswith(".bin"):
                    result["macros"].append(n)

                if "external" in low or "hyperlink" in low:
                    result["external_links"].append(n)

                if "_rels" in low or low.endswith(".rels"):
                    result["relationships"].append(n)

                if "core.xml" in low:
                    try:
                        content = z.read(n).decode(
                            "utf-8",
                            errors="ignore"
                        )
                        result["metadata"]["core_xml"] = content[:5000]
                    except Exception:
                        pass

    except Exception as e:
        result["error"] = str(e)

    return result

# ============================================================
# PDF ANALYSIS
# ============================================================

def analyze_pdf(path):
    result = {
        "type": "PDF",
        "objects": [],
        "javascript": False,
        "embedded_files": False,
        "urls": [],
    }

    try:
        data = path.read_bytes()
        text = data.decode("latin-1", errors="ignore")

        result["objects"] = re.findall(
            r"\b\d+\s+\d+\s+obj\b",
            text
        )[:500]

        result["javascript"] = bool(
            re.search(
                r"/JavaScript|/JS\b",
                text,
                re.I
            )
        )

        result["embedded_files"] = bool(
            re.search(
                r"/EmbeddedFile",
                text,
                re.I
            )
        )

        result["urls"] = sorted(
            set(
                re.findall(
                    r"https?://[^\s()<>\"]+",
                    text,
                    re.I
                )
            )
        )

    except Exception as e:
        result["error"] = str(e)

    return result

# ============================================================
# ARCHIVE ANALYSIS
# ============================================================

def analyze_archive(path):
    result = {
        "type": "ARCHIVE",
        "files": [],
        "suspicious": [],
    }

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                result["files"] = names[:1000]

                for n in names:
                    low = n.lower()

                    if (
                        low.endswith(
                            (
                                ".exe",
                                ".dll",
                                ".js",
                                ".vbs",
                                ".ps1",
                                ".bat",
                                ".cmd",
                                ".apk",
                                ".scr"
                            )
                        )
                    ):
                        result["suspicious"].append(n)

        else:
            result["note"] = (
                "Non-ZIP archive detected; install native archive "
                "tools for deeper extraction."
            )

    except Exception as e:
        result["error"] = str(e)

    return result

# ============================================================
# SQLITE ANALYSIS
# ============================================================

def analyze_sqlite(path):
    result = {
        "type": "SQLITE",
        "tables": [],
        "row_counts": {},
    }

    try:
        conn = sqlite3.connect(
            f"file:{path}?mode=ro",
            uri=True
        )

        cur = conn.cursor()

        tables = cur.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type='table'
            ORDER BY name
            """
        ).fetchall()

        result["tables"] = [
            x[0] for x in tables
        ]

        for table in result["tables"]:
            try:
                safe = table.replace('"', '""')

                count = cur.execute(
                    f'SELECT COUNT(*) FROM "{safe}"'
                ).fetchone()[0]

                result["row_counts"][table] = count

            except Exception:
                pass

        conn.close()

    except Exception as e:
        result["error"] = str(e)

    return result

# ============================================================
# BROWSER ARTIFACT DETECTION
# ============================================================

def browser_artifacts(path):
    result = []

    browser_terms = [
        "chrome",
        "chromium",
        "firefox",
        "edge",
        "brave",
        "cookies",
        "history",
        "bookmarks",
        "login data",
        "web data",
        "session",
        "cache",
    ]

    if path.is_file():
        text = path.name.lower()
        for term in browser_terms:
            if term in text:
                result.append(term)

    return sorted(set(result))

# ============================================================
# DIRECTORY ANALYSIS
# ============================================================

def analyze_directory(path):
    files = []

    try:
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    files.append({
                        "path": str(p),
                        "size": p.stat().st_size,
                        "extension": p.suffix.lower(),
                    })
                except Exception:
                    pass

        return files

    except Exception as e:
        return [{"error": str(e)}]

# ============================================================
# TIMELINE
# ============================================================

def build_timeline(path):
    events = []

    targets = []

    if path.is_file():
        targets = [path]
    elif path.is_dir():
        try:
            targets = [
                x for x in path.rglob("*")
                if x.is_file()
            ]
        except Exception:
            targets = []

    for p in targets[:5000]:
        try:
            s = p.stat()

            events.append({
                "path": str(p),
                "created": datetime.datetime.fromtimestamp(
                    s.st_ctime
                ).isoformat(timespec="seconds"),
                "modified": datetime.datetime.fromtimestamp(
                    s.st_mtime
                ).isoformat(timespec="seconds"),
                "accessed": datetime.datetime.fromtimestamp(
                    s.st_atime
                ).isoformat(timespec="seconds"),
            })

        except Exception:
            pass

    return events

# ============================================================
# OPTIONAL YARA
# ============================================================

def yara_scan(path):
    result = {
        "available": False,
        "matches": []
    }

    try:
        import yara

        result["available"] = True

        # Generic built-in heuristic rules
        rule_source = r'''
        rule Suspicious_PowerShell {
            strings:
                $a = "powershell" nocase
                $b = "Invoke-Expression" nocase
                $c = "FromBase64String" nocase
            condition:
                1 of them
        }

        rule Suspicious_Command {
            strings:
                $a = "cmd.exe" nocase
                $b = "rundll32" nocase
                $c = "regsvr32" nocase
            condition:
                1 of them
        }

        rule Suspicious_Network {
            strings:
                $a = "http://" nocase
                $b = "https://" nocase
                $c = "socket" nocase
            condition:
                2 of them
        }
        '''

        rules = yara.compile(source=rule_source)
        matches = rules.match(str(path))

        result["matches"] = [
            m.rule for m in matches
        ]

    except ImportError:
        result["note"] = (
            "Python yara module not installed; "
            "YARA scan skipped."
        )

    except Exception as e:
        result["error"] = str(e)

    return result

# ============================================================
# MAIN FORENSIC ENGINE
# ============================================================

def analyze(path):

    if not path.exists():
        print("\033[91m[!] Path does not exist.\033[0m")
        return

    if path.is_dir():
        print("\n\033[96m[+] DIRECTORY FORENSICS\033[0m")
        files = analyze_directory(path)

        print(f"[+] Files discovered : {len(files)}")

        ext_counter = Counter(
            x.get("extension", "")
            for x in files
            if isinstance(x, dict)
        )

        print("\n[+] FILE TYPE DISTRIBUTION")
        for ext, count in ext_counter.most_common():
            print(f"    {ext or '[no extension]'} : {count}")

        timeline = build_timeline(path)

        report = {
            "timestamp": timestamp(),
            "target": str(path),
            "mode": "directory",
            "file_count": len(files),
            "extensions": dict(ext_counter),
            "timeline": timeline,
        }

        save_report(report, path)

        print("\n\033[92m[✓] Directory forensic analysis complete.\033[0m")
        return

    print("\n\033[96m[+] FILE FORENSIC ANALYSIS\033[0m")

    meta = metadata(path)
    hashes = calculate_hashes(path)
    ent = entropy(path)
    strings = extract_strings(path)
    text = "\n".join(strings)

    iocs = extract_iocs(text)
    suspicious = suspicious_indicators(text)

    print("\n" + "=" * 64)
    print("FILE INFORMATION")
    print("=" * 64)
    print(f"Name       : {meta['name']}")
    print(f"Type       : {FILE_TYPES.get(path.suffix.lower(), 'Unknown')}")
    print(f"Size       : {meta['size_human']}")
    print(f"MIME       : {meta['mime']}")
    print(f"Signature  : {meta['signature']}")
    print(f"Modified   : {meta['modified']}")
    print(f"Entropy    : {ent}")

    print("\n" + "=" * 64)
    print("HASHES")
    print("=" * 64)

    for k, v in hashes.items():
        print(f"{k:<8}: {v}")

    print("\n" + "=" * 64)
    print("IOC EXTRACTION")
    print("=" * 64)

    if iocs:
        for kind, values in iocs.items():
            print(f"\n[{kind}]")
            for value in values[:100]:
                print(f"  {value}")
    else:
        print("[i] No IOCs detected.")

    print("\n" + "=" * 64)
    print("SUSPICIOUS INDICATORS")
    print("=" * 64)

    if suspicious:
        for item in suspicious:
            print(f"[!] {item}")
    else:
        print("[+] No suspicious keyword indicators found.")

    print("\n" + "=" * 64)
    print("SPECIALIZED ANALYSIS")
    print("=" * 64)

    specialized = {}

    suffix = path.suffix.lower()

    if suffix in [".apk", ".aab"]:
        print("[+] Android APK analysis")
        specialized = analyze_apk(path)

        print(f"    DEX files      : {len(specialized.get('dex', []))}")
        print(f"    Native .so     : {len(specialized.get('native', []))}")
        print(
            f"    Permissions    : "
            f"{len(specialized.get('permissions', []))}"
        )

    elif suffix in [".exe", ".dll", ".sys"]:
        print("[+] Windows PE analysis")
        specialized = analyze_pe(path)

        print(
            f"    Valid PE      : "
            f"{specialized.get('valid_pe_signature', False)}"
        )

        if specialized.get("indicators"):
            print("    PE indicators:")
            for x in specialized["indicators"][:30]:
                print(f"      {x}")

    elif suffix == ".pdf":
        print("[+] PDF forensic analysis")
        specialized = analyze_pdf(path)

        print(
            f"    JavaScript    : "
            f"{specialized.get('javascript')}"
        )

        print(
            f"    Embedded file : "
            f"{specialized.get('embedded_files')}"
        )

        print(
            f"    URLs          : "
            f"{len(specialized.get('urls', []))}"
        )

    elif suffix in [
        ".docx",
        ".pptx",
        ".xlsx",
        ".xlsm"
    ]:
        print("[+] Microsoft OOXML analysis")
        specialized = analyze_ooxml(path)

        print(
            f"    Macro/VBA indicators : "
            f"{len(specialized.get('macros', []))}"
        )

        print(
            f"    Relationship files   : "
            f"{len(specialized.get('relationships', []))}"
        )

        print(
            f"    External indicators : "
            f"{len(specialized.get('external_links', []))}"
        )

    elif suffix in [
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz"
    ]:
        print("[+] Archive forensic analysis")
        specialized = analyze_archive(path)

        print(
            f"    Suspicious members : "
            f"{len(specialized.get('suspicious', []))}"
        )

    elif suffix in [
        ".db",
        ".sqlite",
        ".sqlite3"
    ]:
        print("[+] SQLite database analysis")
        specialized = analyze_sqlite(path)

        print(
            f"    Tables : "
            f"{len(specialized.get('tables', []))}"
        )

        for table, count in specialized.get(
            "row_counts", {}
        ).items():
            print(f"      {table}: {count} rows")

    else:
        print("[+] Generic file forensic analysis")
        specialized = {
            "type": "GENERIC"
        }

    browser = browser_artifacts(path)

    if browser:
        print("\n[+] BROWSER ARTIFACT INDICATORS")
        for item in browser:
            print(f"    {item}")

    print("\n" + "=" * 64)
    print("YARA ANALYSIS")
    print("=" * 64)

    yara_result = yara_scan(path)

    if yara_result.get("available"):
        if yara_result.get("matches"):
            for m in yara_result["matches"]:
                print(f"[!] YARA MATCH: {m}")
        else:
            print("[+] No built-in YARA matches.")
    else:
        print("[i] YARA unavailable/skipped.")

    print("\n" + "=" * 64)
    print("STRINGS SUMMARY")
    print("=" * 64)
    print(f"Printable strings extracted : {len(strings)}")

    print("\nFirst 20 interesting strings:")

    interesting = [
        s for s in strings
        if (
            "http" in s.lower()
            or "powershell" in s.lower()
            or "cmd" in s.lower()
            or "password" in s.lower()
            or "token" in s.lower()
            or "socket" in s.lower()
        )
    ]

    for s in interesting[:20]:
        print(f"  {s[:200]}")

    report = {
        "timestamp": timestamp(),
        "target": str(path),
        "metadata": meta,
        "hashes": hashes,
        "entropy": ent,
        "iocs": iocs,
        "suspicious_indicators": suspicious,
        "specialized_analysis": specialized,
        "browser_indicators": browser,
        "yara": yara_result,
        "string_count": len(strings),
        "interesting_strings": interesting[:200],
    }

    save_report(report, path)

    print("\n" + "=" * 64)
    print("\033[92m[✓] DIGITAL FORENSIC ANALYSIS COMPLETE\033[0m")
    print("=" * 64)

# ============================================================
# REPORT
# ============================================================

def save_report(report, target):

    safe_name = re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        Path(target).name
    )

    filename = (
        datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
        + "_"
        + safe_name
        + "_forensic.json"
    )

    output = REPORT_DIR / filename

    try:
        with open(
            output,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                report,
                f,
                indent=2,
                ensure_ascii=False
            )

        print(f"\n[+] JSON forensic report:")
        print(f"    {output}")

    except Exception as e:
        print(f"[!] Could not save report: {e}")

# ============================================================
# MENU
# ============================================================

def menu():

    banner()

    while True:

        print("""
1. Analyze File
2. Analyze Directory
3. APK / Android Forensics
4. EXE / PE Forensics
5. PDF Forensics
6. Office Forensics (DOC/PPT/XLS)
7. Image / Generic Forensics
8. Archive Forensics
9. SQLite / Database Forensics
10. IOC Extraction
11. File Hashes
12. Strings + Entropy
13. Timeline Analysis
14. Full Automatic Analysis
0. Back
""")

        choice = input("Forensics > ").strip()

        if choice == "0":
            break

        elif choice in [
            "1","2","3","4","5","6","7","8","9","10","11","12","13","14"
        ]:
            path = ask_path()

            if not path.exists():
                print("[!] Target not found.")
                continue

            if choice == "10":
                strings = extract_strings(path)
                iocs = extract_iocs("\n".join(strings))

                print("\n=== IOC RESULTS ===")
                for k, values in iocs.items():
                    print(f"\n{k}:")
                    for v in values:
                        print(f"  {v}")

            elif choice == "11":
                print("\n=== FILE HASHES ===")
                for k, v in calculate_hashes(path).items():
                    print(f"{k}: {v}")

            elif choice == "12":
                print("\n=== STRINGS / ENTROPY ===")
                s = extract_strings(path)
                print(f"Strings : {len(s)}")
                print(f"Entropy : {entropy(path)}")

                for x in s[:30]:
                    print(x[:200])

            elif choice == "13":
                print("\n=== TIMELINE ===")
                timeline = build_timeline(path)

                for event in timeline[:100]:
                    print(
                        event["modified"],
                        event["path"]
                    )

            else:
                analyze(path)

        else:
            print("[!] Invalid option.")

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\n[i] Forensic analysis stopped.")
    except Exception as e:
        print(f"\n[!] Forensics error: {e}")
