#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SentinelSOC - ABOUT / COMMAND DOSSIER
-------------------------------------

A fictional Marvel-inspired terminal presentation for the
SentinelSOC defensive security toolkit.

Important:
    SentinelSOC is an independent educational/security project.
    It is NOT affiliated with Marvel, Disney, Marvel Entertainment,
    X-Men, SHIELD, Stark Industries, or any other Marvel property.

No sample telemetry is generated.
All runtime/system facts shown by the live sections come from the
current SentinelSOC installation and current environment.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
import time
from datetime import datetime
from pathlib import Path


# ============================================================
# SENTINELSOC IDENTITY
# ============================================================

PROJECT_NAME = "SentinelSOC"
VERSION = "1.0"

CREATOR = "Sayan Chowdhury"
COLLEGE = "VIT Vellore"
EMAIL = "sayanchowdhury702@gmail.com"
PHONE = "7278622784"

BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# MARVEL-INSPIRED ANSI PALETTE
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
BRIGHT_RED = "\033[31;1m"
ORANGE = "\033[38;5;208m"
GOLD = "\033[93m"
AMBER = "\033[38;5;214m"
WHITE = "\033[97m"
DARK = "\033[90m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"


def colour(text, code):
    return f"{code}{text}{RESET}"


def width():
    try:
        return max(
            70,
            min(
                shutil.get_terminal_size((100, 30)).columns,
                120,
            ),
        )
    except Exception:
        return 90


def clear():
    print("\033[2J\033[H", end="")


def pause():
    try:
        input(
            f"\n{colour('ENTER', ORANGE)} "
            f"{colour('to return to the SentinelSOC command deck...', DARK)}"
        )
    except (EOFError, KeyboardInterrupt):
        pass


def animate(text, delay=0.008):
    try:
        for char in text:
            print(char, end="", flush=True)
            time.sleep(delay)
        print()
    except KeyboardInterrupt:
        print()


# ============================================================
# DYNAMIC TERMINAL INFORMATION
# ============================================================

def runtime_info():
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"

    return {
        "HOSTNAME": hostname,
        "OS": platform.system() or "unknown",
        "OS RELEASE": platform.release() or "unknown",
        "ARCHITECTURE": platform.machine() or "unknown",
        "PYTHON": platform.python_version(),
        "TERMINAL": os.environ.get("TERM", "unknown"),
        "SENTINELSOC ROOT": str(BASE_DIR),
        "LOCAL TIME": datetime.now().astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
    }


# ============================================================
# DYNAMIC FILE / MODULE INVENTORY
# ============================================================

def module_inventory():
    modules_dir = BASE_DIR / "modules"

    if not modules_dir.exists():
        return []

    result = []

    try:
        for item in sorted(modules_dir.glob("*.py")):
            result.append(item.stem)
    except Exception:
        pass

    return result


# ============================================================
# HERO / MARVEL-INSPIRED OPENING
# ============================================================

def comic_frame(title):
    w = width()

    print(colour("╔" + "═" * (w - 2) + "╗", BRIGHT_RED))

    centered = f"  {title}  "
    left = max(0, (w - 2 - len(centered)) // 2)
    right = max(0, w - 2 - len(centered) - left)

    print(
        colour("║", BRIGHT_RED)
        + colour(" " * left + centered + " " * right, GOLD)
        + colour("║", BRIGHT_RED)
    )

    print(colour("╚" + "═" * (w - 2) + "╝", ORANGE))


def glowing_line(symbol="◆"):
    w = width()

    left = symbol * 3
    middle = "═" * max(10, w - 14)
    right = symbol * 3

    print(
        colour(
            left + middle + right,
            ORANGE,
        )
    )


def hero_animation():
    if os.environ.get("SENTINELSOC_NO_ANIMATION") == "1":
        return

    frames = [
        "[ SENTINELSOC ]",
        "[  S E N T I N E L S O C  ]",
        "[     S E N T I N E L     ]",
        "[  S E N T I N E L S O C  ]",
        "[ SENTINELSOC ]",
    ]

    try:
        for frame in frames:
            print(
                f"\r{colour(frame.center(width()), BRIGHT_RED)}",
                end="",
                flush=True,
            )
            time.sleep(0.07)
        print()
    except KeyboardInterrupt:
        print()


# ============================================================
# MISSION DOSSIER
# ============================================================

def mission():
    clear()

    comic_frame(
        "SENTINELSOC // COMMAND DOSSIER"
    )

    hero_animation()

    animate(
        colour(
            "THE BLUE TEAM'S DEFENCE SYSTEM AGAINST THE DIGITAL UNKNOWN.",
            GOLD,
        ),
        0.004,
    )

    print()

    print(
        colour(
            "⚡ MISSION",
            BRIGHT_RED,
        )
    )

    print(
        "SentinelSOC is a defensive cybersecurity and digital-forensics "
        "toolkit designed to bring live security telemetry, detection, "
        "correlation, incident-response workflow, evidence collection, "
        "threat intelligence and reporting into one operator-oriented "
        "command environment."
    )

    print()

    print(
        colour(
            "⚔ CORE PRINCIPLE",
            ORANGE,
        )
    )

    print(
        "Observe → Normalize → Detect → Correlate → Investigate → "
        "Respond → Preserve Evidence → Report."
    )

    print()

    print(
        colour(
            "🛡 DEFENSIVE PURPOSE",
            BRIGHT_RED,
        )
    )

    print(
        "The toolkit is intended for authorized defensive security work, "
        "security education, blue-team simulation, incident investigation, "
        "digital forensics workflows and SOC-style operational monitoring."
    )

    print()

    print(
        colour(
            "⚡ RUNTIME PHILOSOPHY",
            GOLD,
        )
    )

    print(
        "Live telemetry is preferred over static demonstrations. "
        "Where an operating system does not expose a collector, SentinelSOC "
        "reports the limitation instead of fabricating telemetry."
    )

    pause()


# ============================================================
# ARCHITECTURE DOSSIER
# ============================================================

def architecture():
    clear()

    comic_frame(
        "STARK-LEVEL DEFENSIVE ARCHITECTURE"
    )

    print()

    architecture_rows = [
        ("01", "TELEMETRY", "Android logcat / host telemetry"),
        ("02", "NORMALIZATION", "Raw events → normalized event schema"),
        ("03", "DETECTION", "Severity + risk scoring + IOC extraction"),
        ("04", "CORRELATION", "MITRE ATT&CK technique mapping"),
        ("05", "PERSISTENCE", "SQLite event / incident storage"),
        ("06", "DFIR", "Evidence, triage, cases and forensic collection"),
        ("07", "RESPONSE", "Incident triage and response workflow"),
        ("08", "REPORTING", "HTML / PDF / JSON / CSV / IAM"),
        ("09", "CONTROL", "Persistent Settings / operator configuration"),
        ("10", "CLI", "Single unified SOC operator interface"),
    ]

    print(
        colour(
            "┌────┬────────────────┬────────────────────────────────────────────┐",
            RED,
        )
    )

    print(
        colour(
            "│ ID │ LAYER          │ FUNCTION                                   │",
            GOLD,
        )
    )

    print(
        colour(
            "├────┼────────────────┼────────────────────────────────────────────┤",
            RED,
        )
    )

    for number, layer, function in architecture_rows:

        print(
            colour("│ ", RED)
            + colour(
                f"{number:<2} │ {layer:<14} │ {function:<42}",
                WHITE,
            )
            + colour("│", RED)
        )

    print(
        colour(
            "└────┴────────────────┴────────────────────────────────────────────┘",
            RED,
        )
    )

    print()

    print(
        colour(
            "DATA FLOW",
            ORANGE,
        )
    )

    print(
        colour(
            "RAW EVENTS",
            GOLD,
        )
        + "  →  "
        + colour("NORMALIZER", WHITE)
        + "  →  "
        + colour("RISK ENGINE", GOLD)
        + "  →  "
        + colour("IOC", ORANGE)
        + "  →  "
        + colour("MITRE", RED)
        + "  →  "
        + colour("CASE / DFIR", GOLD)
        + "  →  "
        + colour("REPORT", ORANGE)
    )

    pause()


# ============================================================
# MARVEL / THREAT ARCHETYPES
# ============================================================

def threat_universe():
    clear()

    comic_frame(
        "THE THREAT UNIVERSE"
    )

    print()

    print(
        colour(
            "THE FOLLOWING ARE FICTIONAL SECURITY ARCHETYPES "
            "INSPIRED BY COMIC-BOOK THEMES.",
            GOLD,
        )
    )

    print()

    threats = [
        (
            "DR. DOOM",
            "ADVANCED THREAT ACTOR",
            "Privilege escalation, command execution, persistence, "
            "credential abuse, lateral movement and infrastructure control.",
        ),
        (
            "ULTRON",
            "AUTOMATED ADVERSARY",
            "Self-propagating automation, autonomous process execution, "
            "botnet-style behavior and rapid event amplification.",
        ),
        (
            "THANOS",
            "IMPACT / DESTRUCTION ARCHETYPE",
            "High-impact disruption, destructive actions, service denial "
            "and broad operational blast radius.",
        ),
        (
            "LOKI",
            "DECEPTION / EVASION ARCHETYPE",
            "Masquerading, obfuscation, misleading process identity, "
            "defense evasion and social-engineering style deception.",
        ),
        (
            "HYDRA",
            "PERSISTENT THREAT NETWORK",
            "Distributed infrastructure, persistence mechanisms, command "
            "channels, coordinated intrusion activity and repeat compromise.",
        ),
    ]

    for name, role, technical in threats:

        print(
            f"{colour('╔', BRIGHT_RED)}"
            f"{colour(f' {name} ', GOLD)}"
            f"{colour('╗', BRIGHT_RED)}"
        )

        print(
            f"  {colour(role, ORANGE)}"
        )

        print(
            f"  {technical}"
        )

        print(
            colour(
                "  ------------------------------------------------------------",
                DARK,
            )
        )

    print()

    print(
        colour(
            "REAL-WORLD SECURITY TRANSLATION",
            RED,
        )
    )

    print(
        "Threat archetypes are mapped conceptually to real defensive "
        "security terminology such as IOC, TTP, persistence, privilege "
        "escalation, credential access, lateral movement, command-and-control, "
        "defense evasion and impact."
    )

    pause()


# ============================================================
# MARVEL REFERENCES / LEGACY
# ============================================================

def universe_references():
    clear()

    comic_frame(
        "THE SENTINEL // COMICBOOK LEGACY"
    )

    print()

    print(
        colour(
            "MARVEL-INSPIRED REFERENCES",
            GOLD,
        )
    )

    print()

    references = [
        (
            "SENTINELS",
            "X-Men",
            "The project's name evokes the classic Sentinel concept: "
            "continuous detection and threat observation.",
        ),
        (
            "S.H.I.E.L.D.",
            "Marvel",
            "Operational inspiration for centralized intelligence, "
            "monitoring and incident coordination.",
        ),
        (
            "STARK INDUSTRIES",
            "Marvel",
            "A thematic reference for engineering, telemetry, "
            "automation and systems intelligence.",
        ),
        (
            "DR. DOOM",
            "Marvel",
            "Used here as a fictional adversary archetype representing "
            "a technically sophisticated threat actor.",
        ),
        (
            "AVENGERS",
            "Marvel",
            "A metaphor for coordinating specialized security capabilities "
            "inside one defensive command environment.",
        ),
        (
            "WAKANDA",
            "Marvel",
            "A thematic metaphor for hardened engineering, resilient "
            "infrastructure and defensive technology.",
        ),
    ]

    for name, source, meaning in references:

        print(
            f"{colour('◆', RED)} "
            f"{colour(name, GOLD)} "
            f"{colour('— ' + source, ORANGE)}"
        )

        print(
            f"  {meaning}\n"
        )

    print(
        colour(
            "DISCLAIMER",
            RED,
        )
    )

    print(
        "SentinelSOC is an independent project and is not affiliated with, "
        "sponsored by, endorsed by, or operated by Marvel, Disney, or any "
        "Marvel property. Character and universe names are used solely "
        "as thematic references for this personal educational SOC interface."
    )

    pause()


# ============================================================
# LIVE PROJECT INVENTORY
# ============================================================

def live_project_status():
    clear()

    comic_frame(
        "LIVE SENTINELSOC PROJECT STATUS"
    )

    spinner = [
        "Scanning module architecture...",
        "Reading local project structure...",
        "Checking available defensive components...",
    ]

    for message in spinner:
        print(
            colour(
                f"[+] {message}",
                ORANGE,
            )
        )
        time.sleep(0.05)

    modules = module_inventory()

    print()

    print(
        colour(
            "PROJECT",
            GOLD,
        )
        + f": {PROJECT_NAME}"
    )

    print(
        colour(
            "VERSION",
            GOLD,
        )
        + f": {VERSION}"
    )

    print(
        colour(
            "MODULE COUNT",
            GOLD,
        )
        + f": {len(modules)}"
    )

    print()

    if modules:

        for index, module in enumerate(
            modules,
            start=1,
        ):

            print(
                f"{colour(f'{index:02}', ORANGE)} "
                f"{colour(module, WHITE)}"
            )

    else:

        print(
            colour(
                "[i] No module inventory available.",
                DARK,
            )
        )

    print()

    info = runtime_info()

    print(
        colour(
            "LIVE ENVIRONMENT",
            BRIGHT_RED,
        )
    )

    for key, value in info.items():

        print(
            f"  {colour(key, GOLD):<45} "
            f"{value}"
        )

    pause()


# ============================================================
# CREATOR DOSSIER
# ============================================================

def creator():
    clear()

    comic_frame(
        "THE CREATOR // ONE ABOVE ALL"
    )

    print()

    print(
        colour(
            "CREATOR PROFILE",
            GOLD,
        )
    )

    print()

    profile = [
        ("CREATOR", CREATOR),
        ("ROLE", "Creator / Architect / Defensive Security Builder"),
        ("INSTITUTION", COLLEGE),
        ("PROJECT", PROJECT_NAME),
        ("EMAIL", EMAIL),
        ("PHONE", PHONE),
    ]

    for key, value in profile:

        print(
            f"{colour(key, ORANGE):<24}"
            f": {colour(value, WHITE)}"
        )

    print()

    print(
        colour(
            "THE ONE ABOVE ALL",
            BRIGHT_RED,
        )
    )

    print(
        "Within this fictional comic-book framing, the creator is presented "
        "as the 'One Above All' of the SentinelSOC command deck: the person "
        "responsible for the vision, architecture, implementation and "
        "evolution of the project."
    )

    print()

    print(
        colour(
            "CREATOR'S NOTE",
            GOLD,
        )
    )

    print(
        "SentinelSOC was designed to turn cybersecurity concepts into a "
        "single operator experience where telemetry, detection, "
        "threat intelligence, DFIR, incident response and reporting "
        "work together instead of existing as isolated tools."
    )

    print()

    print(
        colour(
            "MISSION",
            ORANGE,
        )
    )

    print(
        "Build. Observe. Investigate. Defend."
    )

    pause()


# ============================================================
# ABOUT MAIN VIEW
# ============================================================

def about_menu():

    while True:

        clear()

        comic_frame(
            "SENTINELSOC // ABOUT"
        )

        print()

        print(
            colour(
                "◉ DEFENSIVE COMMAND INTERFACE",
                BRIGHT_RED,
            )
        )

        print(
            colour(
                "Inspired by the language of comic-book heroes, "
                "villains and command systems.",
                GOLD,
            )
        )

        print()

        menu_items = [
            ("1", "Mission & Philosophy"),
            ("2", "Architecture & Security Pipeline"),
            ("3", "Threat Universe / Dr. Doom Archetypes"),
            ("4", "Marvel Reference Dossier"),
            ("5", "Live Project Status"),
            ("6", "Creator / One Above All"),
            ("0", "Back"),
        ]

        print(
            colour(
                "┌───────┬───────────────────────────────────────────────┐",
                RED,
            )
        )

        print(
            colour(
                "│ OPTION│ DOSSIER                                       │",
                GOLD,
            )
        )

        print(
            colour(
                "├───────┼───────────────────────────────────────────────┤",
                RED,
            )
        )

        for number, label in menu_items:

            print(
                f"{colour('│', RED)}"
                f" {colour(number, ORANGE):<6}"
                f"{colour('│', WHITE)} "
                f"{label:<45}"
                f"{colour('│', RED)}"
            )

        print(
            colour(
                "└───────┴───────────────────────────────────────────────┘",
                RED,
            )
        )

        print()

        print(
            f"{colour('PROJECT', GOLD)} : {PROJECT_NAME}"
        )

        print(
            f"{colour('CREATOR', GOLD)} : {CREATOR}"
        )

        print(
            f"{colour('COLLEGE', GOLD)} : {COLLEGE}"
        )

        print()

        try:
            choice = input(
                colour(
                    "SentinelSOC About > ",
                    ORANGE,
                )
            ).strip()

        except (EOFError, KeyboardInterrupt):

            return

        if choice == "1":
            mission()

        elif choice == "2":
            architecture()

        elif choice == "3":
            threat_universe()

        elif choice == "4":
            universe_references()

        elif choice == "5":
            live_project_status()

        elif choice == "6":
            creator()

        elif choice == "0":
            return

        else:
            print(
                colour(
                    "[!] Invalid choice.",
                    RED,
                )
            )
            time.sleep(0.7)


# ============================================================
# ROUTER COMPATIBILITY
# ============================================================

def about():
    return about_menu()


def menu():
    return about_menu()


def run():
    return about_menu()


def main():
    return about_menu()


if __name__ == "__main__":
    about_menu()
