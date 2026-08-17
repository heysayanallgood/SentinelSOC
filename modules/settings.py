#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SentinelSOC Dynamic Settings / Control Center
---------------------------------------------
Pure Python standard library.
Termux/Kali compatible.
No sample data.
Persistent configuration.
Router-compatible exports:
    settings
    settings_menu
    menu
    run
    main
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sys
import time
from datetime import datetime
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = BASE_DIR / "assets"
CONFIG_DIR = ASSETS_DIR / "config"
CONFIG_FILE = CONFIG_DIR / "sentinelsoc_settings.json"

CONFIG_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# ANSI / THEMES
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CLEAR = "\033[2J\033[H"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

THEMES = {
    "cyan": {
        "primary": "\033[96m",
        "secondary": "\033[36m",
        "accent": "\033[92m",
        "warning": "\033[93m",
        "danger": "\033[91m",
        "muted": "\033[90m",
        "text": "\033[97m",
    },
    "green": {
        "primary": "\033[92m",
        "secondary": "\033[32m",
        "accent": "\033[96m",
        "warning": "\033[93m",
        "danger": "\033[91m",
        "muted": "\033[90m",
        "text": "\033[97m",
    },
    "amber": {
        "primary": "\033[93m",
        "secondary": "\033[33m",
        "accent": "\033[97m",
        "warning": "\033[91m",
        "danger": "\033[91m",
        "muted": "\033[90m",
        "text": "\033[97m",
    },
    "matrix": {
        "primary": "\033[92m",
        "secondary": "\033[32m",
        "accent": "\033[92m",
        "warning": "\033[93m",
        "danger": "\033[91m",
        "muted": "\033[90m",
        "text": "\033[97m",
    },
    "purple": {
        "primary": "\033[95m",
        "secondary": "\033[35m",
        "accent": "\033[96m",
        "warning": "\033[93m",
        "danger": "\033[91m",
        "muted": "\033[90m",
        "text": "\033[97m",
    },
}


DEFAULTS = {
    "theme": "cyan",
    "animations": True,
    "animation_speed": 0.025,
    "performance_mode": False,

    "show_banner": True,
    "show_timestamps": True,
    "show_status_bar": True,
    "compact_ui": False,

    "refresh_interval": 2,
    "collection_interval": 5,

    "default_report_format": "JSON",
    "auto_report": False,
    "report_timestamp": True,

    "logging_level": "INFO",
    "file_logging": True,
    "console_logging": True,

    "privacy_redaction": False,
    "redact_usernames": False,
    "redact_paths": False,

    "notifications": True,
    "terminal_bell": False,

    "safe_mode": False,
    "confirm_destructive_actions": True,

    "evidence_root": str(ASSETS_DIR / "incident_response"),
    "report_root": str(ASSETS_DIR / "reports"),

    "retention_days": 30,
}


# ============================================================
# CONFIGURATION ENGINE
# ============================================================

def _load_config() -> dict:
    data = dict(DEFAULTS)

    try:
        if CONFIG_FILE.exists():
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

            if isinstance(loaded, dict):
                for key in DEFAULTS:
                    if key in loaded:
                        data[key] = loaded[key]

    except Exception:
        # Never allow a corrupt settings file to crash SentinelSOC.
        data = dict(DEFAULTS)

    return data


CONFIG = _load_config()


def _save_config() -> bool:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        tmp = CONFIG_FILE.with_suffix(".tmp")

        tmp.write_text(
            json.dumps(CONFIG, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        tmp.replace(CONFIG_FILE)

        return True

    except Exception as exc:
        print(f"{C('danger')}[!] Could not save configuration: {exc}{RESET}")
        return False


def get_setting(name: str, default=None):
    return CONFIG.get(name, default)


def set_setting(name: str, value) -> bool:
    CONFIG[name] = value
    return _save_config()


def reset_settings() -> bool:
    CONFIG.clear()
    CONFIG.update(DEFAULTS)
    return _save_config()


# ============================================================
# COLOR HELPERS
# ============================================================

def C(name: str) -> str:
    theme = THEMES.get(CONFIG.get("theme", "cyan"), THEMES["cyan"])
    return theme.get(name, "")


# ============================================================
# TERMINAL HELPERS
# ============================================================

def terminal_width() -> int:
    try:
        return max(60, min(shutil.get_terminal_size((80, 24)).columns, 120))
    except Exception:
        return 80


def clear():
    if CONFIG.get("animations", True):
        print(CLEAR, end="")
    else:
        print("\033[2J\033[H", end="")


def pause(message="Press Enter to continue..."):
    try:
        input(f"\n{C('muted')}{message}{RESET}")
    except (EOFError, KeyboardInterrupt):
        pass


def ask(prompt: str, default: str = "") -> str:
    try:
        value = input(f"{C('primary')}{prompt}{RESET} ").strip()

        if value == "":
            return default

        return value

    except (EOFError, KeyboardInterrupt):
        return default


def yn(prompt: str, current: bool) -> bool:
    current_text = "ON" if current else "OFF"

    while True:
        answer = ask(
            f"{prompt} [{current_text}] (y/n/Enter=keep):",
            "",
        ).lower()

        if not answer:
            return current

        if answer in ("y", "yes", "1", "on"):
            return True

        if answer in ("n", "no", "0", "off"):
            return False

        print(f"{C('warning')}Enter y or n.{RESET}")


def choose(prompt: str, choices: list[str], current: str) -> str:
    print()

    for index, value in enumerate(choices, 1):
        marker = "●" if value == current else "○"
        print(
            f"  {C('accent')}{index}.{RESET} "
            f"{marker} {value}"
        )

    while True:
        answer = ask(
            f"{prompt} [current={current}]",
            "",
        )

        if not answer:
            return current

        try:
            index = int(answer)

            if 1 <= index <= len(choices):
                return choices[index - 1]

        except ValueError:
            pass

        if answer in choices:
            return answer

        print(f"{C('warning')}Invalid selection.{RESET}")


# ============================================================
# ANIMATION ENGINE
# ============================================================

def animate_text(text: str, delay: float | None = None):
    if not CONFIG.get("animations", True):
        print(text)
        return

    if CONFIG.get("performance_mode", False):
        print(text)
        return

    speed = (
        CONFIG.get("animation_speed", 0.025)
        if delay is None
        else delay
    )

    try:
        for character in text:
            print(character, end="", flush=True)
            time.sleep(speed)

        print()

    except KeyboardInterrupt:
        print(text)


def spinner(message="Initializing SentinelSOC"):
    if not CONFIG.get("animations", True):
        print(f"{C('accent')}[+] {message}{RESET}")
        return

    if CONFIG.get("performance_mode", False):
        print(f"{C('accent')}[+] {message}{RESET}")
        return

    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    try:
        for frame in frames:
            print(
                f"\r{C('primary')}{frame}{RESET} "
                f"{C('text')}{message}{RESET}",
                end="",
                flush=True,
            )
            time.sleep(0.045)

        print(
            f"\r{C('accent')}✓{RESET} "
            f"{C('text')}{message}{RESET}"
        )

    except KeyboardInterrupt:
        print()


def progress(label: str):
    if not CONFIG.get("animations", True):
        print(f"{C('accent')}[+] {label}{RESET}")
        return

    if CONFIG.get("performance_mode", False):
        print(f"{C('accent')}[+] {label}{RESET}")
        return

    width = min(30, terminal_width() - 30)

    try:
        for i in range(width + 1):
            filled = "█" * i
            empty = "░" * (width - i)
            percent = int((i / width) * 100)

            print(
                f"\r{C('primary')}{label:<20}{RESET} "
                f"[{filled}{empty}] "
                f"{percent:3d}%",
                end="",
                flush=True,
            )

            time.sleep(0.015)

        print()

    except KeyboardInterrupt:
        print()


# ============================================================
# HEADER / STATUS
# ============================================================

def header(title="SENTINELSOC | SETTINGS CONTROL CENTER"):
    width = terminal_width()

    print(f"{C('secondary')}{'═' * width}{RESET}")
    print(
        f"{C('primary')}"
        f"  ◈ SENTINELSOC  |  {title}"
        f"{RESET}"
    )
    print(f"{C('secondary')}{'═' * width}{RESET}")


def status_line():
    theme = CONFIG.get("theme", "cyan")
    animations = "ON" if CONFIG.get("animations") else "OFF"
    safe = "ON" if CONFIG.get("safe_mode") else "OFF"
    performance = "ON" if CONFIG.get("performance_mode") else "OFF"

    print(
        f"{C('muted')}"
        f"THEME:{theme.upper()}  "
        f"ANIMATION:{animations}  "
        f"SAFE:{safe}  "
        f"PERF:{performance}"
        f"{RESET}"
    )


def banner():
    if not CONFIG.get("show_banner", True):
        return

    lines = [
        " ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      ",
        " ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║      ",
        " ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ",
        " ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ",
        " ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ ",
        " ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ",
    ]

    print()

    for line in lines:
        print(f"{C('primary')}{line}{RESET}")

    print(
        f"{C('secondary')}"
        "              ◈ BLUE TEAM CONTROL CENTER ◈"
        f"{RESET}"
    )

    print()


# ============================================================
# SYSTEM INFORMATION
# ============================================================

def system_info() -> dict:
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"

    return {
        "OS": platform.system() or "unknown",
        "OS Release": platform.release() or "unknown",
        "Architecture": platform.machine() or "unknown",
        "Python": platform.python_version(),
        "Hostname": hostname,
        "Terminal": os.environ.get("TERM", "unknown"),
        "Shell": os.environ.get("SHELL", "unknown"),
        "Terminal Width": terminal_width(),
        "SentinelSOC Root": str(BASE_DIR),
        "Settings File": str(CONFIG_FILE),
    }


def system_information():
    clear()
    header("LIVE SYSTEM INFORMATION")
    banner()

    spinner("Collecting local runtime information")

    info = system_info()

    print()

    for key, value in info.items():
        print(
            f"{C('accent')}{key:<22}{RESET}: "
            f"{C('text')}{value}{RESET}"
        )

    print()
    status_line()
    pause()


# ============================================================
# SETTINGS SECTIONS
# ============================================================

def appearance_settings():
    clear()
    header("APPEARANCE & ANIMATION")

    print(
        f"{C('muted')}"
        "Dynamic terminal presentation controls"
        f"{RESET}\n"
    )

    CONFIG["theme"] = choose(
        "Select theme:",
        list(THEMES.keys()),
        CONFIG["theme"],
    )

    CONFIG["animations"] = yn(
        "Enable terminal animations?",
        CONFIG["animations"],
    )

    speed_choices = [
        ("FAST", 0.01),
        ("NORMAL", 0.025),
        ("CINEMATIC", 0.055),
        ("SLOW", 0.09),
    ]

    current_speed = CONFIG.get("animation_speed", 0.025)

    print("\nAnimation speed:")

    for index, (name, value) in enumerate(speed_choices, 1):
        marker = "●" if abs(current_speed - value) < 0.001 else "○"
        print(f"  {index}. {marker} {name}")

    answer = ask("Choose speed [Enter=keep]", "")

    if answer.isdigit():
        index = int(answer)

        if 1 <= index <= len(speed_choices):
            CONFIG["animation_speed"] = speed_choices[index - 1][1]

    CONFIG["show_banner"] = yn(
        "Show SentinelSOC banner?",
        CONFIG["show_banner"],
    )

    CONFIG["show_status_bar"] = yn(
        "Show status bar?",
        CONFIG["show_status_bar"],
    )

    CONFIG["compact_ui"] = yn(
        "Use compact UI?",
        CONFIG["compact_ui"],
    )

    _save_config()

    print(f"\n{C('accent')}✓ Appearance saved.{RESET}")
    pause()


def monitoring_settings():
    clear()
    header("MONITORING & COLLECTION")

    print(
        f"{C('muted')}"
        "Live collection timing and performance controls"
        f"{RESET}\n"
    )

    current = str(CONFIG.get("refresh_interval", 2))

    value = ask(
        f"UI refresh interval in seconds [{current}]:",
        current,
    )

    try:
        number = max(1, min(3600, int(value)))
        CONFIG["refresh_interval"] = number
    except ValueError:
        pass

    current = str(CONFIG.get("collection_interval", 5))

    value = ask(
        f"Collection interval in seconds [{current}]:",
        current,
    )

    try:
        number = max(1, min(3600, int(value)))
        CONFIG["collection_interval"] = number
    except ValueError:
        pass

    CONFIG["performance_mode"] = yn(
        "Enable performance mode?",
        CONFIG["performance_mode"],
    )

    CONFIG["show_timestamps"] = yn(
        "Show timestamps?",
        CONFIG["show_timestamps"],
    )

    _save_config()

    print(f"\n{C('accent')}✓ Monitoring settings saved.{RESET}")
    pause()


def reporting_settings():
    clear()
    header("REPORTING ENGINE")

    formats = ["JSON", "HTML", "PDF", "CSV"]

    CONFIG["default_report_format"] = choose(
        "Default report format:",
        formats,
        CONFIG["default_report_format"],
    )

    CONFIG["auto_report"] = yn(
        "Enable automatic report generation?",
        CONFIG["auto_report"],
    )

    CONFIG["report_timestamp"] = yn(
        "Include generation timestamps?",
        CONFIG["report_timestamp"],
    )

    current = str(CONFIG.get("report_root", ASSETS_DIR / "reports"))

    report_path = ask(
        f"Report output directory [{current}]:",
        current,
    )

    CONFIG["report_root"] = str(Path(report_path).expanduser())

    try:
        Path(CONFIG["report_root"]).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    _save_config()

    print(f"\n{C('accent')}✓ Reporting configuration saved.{RESET}")
    pause()


def logging_settings():
    clear()
    header("LOGGING & AUDIT")

    levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

    CONFIG["logging_level"] = choose(
        "Logging level:",
        levels,
        CONFIG["logging_level"],
    )

    CONFIG["file_logging"] = yn(
        "Enable file logging?",
        CONFIG["file_logging"],
    )

    CONFIG["console_logging"] = yn(
        "Enable console logging?",
        CONFIG["console_logging"],
    )

    _save_config()

    print(f"\n{C('accent')}✓ Logging configuration saved.{RESET}")
    pause()


def privacy_settings():
    clear()
    header("PRIVACY & DATA PROTECTION")

    print(
        f"{C('warning')}"
        "These controls affect presentation/storage policy."
        f"{RESET}\n"
    )

    CONFIG["privacy_redaction"] = yn(
        "Enable privacy redaction?",
        CONFIG["privacy_redaction"],
    )

    CONFIG["redact_usernames"] = yn(
        "Redact usernames in reports?",
        CONFIG["redact_usernames"],
    )

    CONFIG["redact_paths"] = yn(
        "Redact sensitive filesystem paths?",
        CONFIG["redact_paths"],
    )

    CONFIG["retention_days"] = max(
        1,
        min(
            3650,
            int(
                ask(
                    f"Evidence/report retention days "
                    f"[{CONFIG.get('retention_days', 30)}]:",
                    str(CONFIG.get("retention_days", 30)),
                )
            ),
        ),
    )

    _save_config()

    print(f"\n{C('accent')}✓ Privacy configuration saved.{RESET}")
    pause()


def security_settings():
    clear()
    header("SECURITY & SAFETY")

    CONFIG["safe_mode"] = yn(
        "Enable SentinelSOC safe mode?",
        CONFIG["safe_mode"],
    )

    CONFIG["confirm_destructive_actions"] = yn(
        "Confirm destructive actions?",
        CONFIG["confirm_destructive_actions"],
    )

    CONFIG["notifications"] = yn(
        "Enable notifications?",
        CONFIG["notifications"],
    )

    CONFIG["terminal_bell"] = yn(
        "Enable terminal bell?",
        CONFIG["terminal_bell"],
    )

    current = str(CONFIG.get("evidence_root"))

    evidence = ask(
        f"Evidence directory [{current}]:",
        current,
    )

    CONFIG["evidence_root"] = str(Path(evidence).expanduser())

    try:
        Path(CONFIG["evidence_root"]).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    _save_config()

    print(f"\n{C('accent')}✓ Security configuration saved.{RESET}")
    pause()


# ============================================================
# LIVE CONFIGURATION VIEW
# ============================================================

def configuration_overview():
    clear()
    header("LIVE CONFIGURATION")

    grouped = {
        "INTERFACE": [
            "theme",
            "animations",
            "animation_speed",
            "performance_mode",
            "show_banner",
            "show_timestamps",
            "show_status_bar",
            "compact_ui",
        ],
        "MONITORING": [
            "refresh_interval",
            "collection_interval",
        ],
        "REPORTING": [
            "default_report_format",
            "auto_report",
            "report_timestamp",
            "report_root",
        ],
        "LOGGING": [
            "logging_level",
            "file_logging",
            "console_logging",
        ],
        "PRIVACY": [
            "privacy_redaction",
            "redact_usernames",
            "redact_paths",
            "retention_days",
        ],
        "SECURITY": [
            "safe_mode",
            "confirm_destructive_actions",
            "notifications",
            "terminal_bell",
            "evidence_root",
        ],
    }

    for group, keys in grouped.items():
        print(
            f"\n{C('primary')}┌─ {group} "
            f"{'─' * max(3, 45 - len(group))}┐{RESET}"
        )

        for key in keys:
            value = CONFIG.get(key)

            if isinstance(value, bool):
                display = (
                    f"{C('accent')}ON{RESET}"
                    if value
                    else f"{C('danger')}OFF{RESET}"
                )
            else:
                display = f"{C('text')}{value}{RESET}"

            print(
                f"│ {C('secondary')}{key:<28}{RESET} "
                f"{display}"
            )

        print(
            f"{C('primary')}└{'─' * 48}┘{RESET}"
        )

    pause()


# ============================================================
# RESET
# ============================================================

def reset_configuration():
    clear()
    header("CONFIGURATION RESET")

    print(
        f"{C('danger')}"
        "This will restore SentinelSOC settings to their defaults."
        f"{RESET}\n"
    )

    if CONFIG.get("confirm_destructive_actions", True):
        answer = ask(
            "Type RESET to continue:",
            "",
        )

        if answer != "RESET":
            print(f"{C('warning')}Reset cancelled.{RESET}")
            pause()
            return

    if reset_settings():
        print(f"{C('accent')}✓ Configuration restored.{RESET}")
    else:
        print(f"{C('danger')}✗ Configuration reset failed.{RESET}")

    pause()


# ============================================================
# MAIN SETTINGS CONTROL CENTER
# ============================================================

def settings_menu():
    while True:
        clear()

        if CONFIG.get("show_banner", True):
            banner()

        header("SETTINGS CONTROL CENTER")

        print(
            f"{C('muted')}"
            "Dynamic SentinelSOC configuration — persistent and live"
            f"{RESET}\n"
        )

        status_line()

        print()

        menu_items = [
            ("1", "Appearance & Animation", appearance_settings),
            ("2", "Monitoring & Collection", monitoring_settings),
            ("3", "Reporting Engine", reporting_settings),
            ("4", "Logging & Audit", logging_settings),
            ("5", "Privacy & Data Protection", privacy_settings),
            ("6", "Security & Safety", security_settings),
            ("7", "Live Configuration", configuration_overview),
            ("8", "Live System Information", system_information),
            ("9", "Reset Configuration", reset_configuration),
            ("0", "Back", None),
        ]

        print(
            f"{C('primary')}┌───────┬────────────────────────────────────────────┐"
            f"{RESET}"
        )
        print(
            f"{C('primary')}│ OPTION│ CONTROL                                    │"
            f"{RESET}"
        )
        print(
            f"{C('primary')}├───────┼────────────────────────────────────────────┤"
            f"{RESET}"
        )

        for number, label, _ in menu_items:
            print(
                f"{C('secondary')}│   {number:<3} │{RESET} "
                f"{C('text')}{label:<43}{RESET}"
                f"{C('secondary')}│{RESET}"
            )

        print(
            f"{C('primary')}└───────┴────────────────────────────────────────────┘"
            f"{RESET}"
        )

        choice = ask(
            f"\n{C('primary')}SentinelSOC Settings >{RESET}",
            "",
        )

        selected = None

        for number, label, function in menu_items:
            if choice == number:
                selected = function
                break

        if choice == "0":
            return

        if selected is not None:
            try:
                selected()
            except KeyboardInterrupt:
                print(f"\n{C('warning')}Operation cancelled.{RESET}")
                pause()
            except Exception as exc:
                print(
                    f"\n{C('danger')}"
                    f"[!] Settings operation failed: {exc}"
                    f"{RESET}"
                )
                pause()
        else:
            print(f"{C('warning')}Invalid option.{RESET}")
            time.sleep(0.7)


# ============================================================
# ROUTER COMPATIBILITY
# ============================================================

def settings():
    return settings_menu()


def menu():
    return settings_menu()


def run():
    return settings_menu()


def main():
    return settings_menu()


# Router may import any of these names.
settings_menu = settings_menu


if __name__ == "__main__":
    try:
        settings_menu()
    finally:
        print(SHOW_CURSOR, end="")
