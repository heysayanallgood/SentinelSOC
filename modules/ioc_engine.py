#!/usr/bin/env python3

import re

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

DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+'
    r'(?:com|net|org|io|dev|app|in|co|uk|de|xyz)\b',
    re.IGNORECASE
)

HASH_RE = re.compile(
    r'\b[a-fA-F0-9]{32}\b|'
    r'\b[a-fA-F0-9]{40}\b|'
    r'\b[a-fA-F0-9]{64}\b'
)

PATH_RE = re.compile(
    r'(?<!\w)(/(?:data|system|vendor|sdcard|storage|tmp|proc|dev|etc|usr)'
    r'/[^\s,"\']+)'
)

PACKAGE_RE = re.compile(
    r'\b[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+){2,}\b'
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
        "domains": unique(DOMAIN_RE.findall(text)),
        "hashes": unique(HASH_RE.findall(text)),
        "paths": unique(PATH_RE.findall(text)),
        "packages": unique(PACKAGE_RE.findall(text)),
    }


def enrich_event(event):
    event = dict(event)
    event["iocs"] = extract_iocs(event)
    return event
