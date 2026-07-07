"""Checks a short, well-known list of paths that commonly get left
exposed by accident - backup files, version control metadata, environment
files, debug/management endpoints - the same kind of check covered by
basic security reviews and hardening guides. ZAP's own spider may also
surface some of these, but a direct, deterministic check catches things
that aren't linked from anywhere a crawler would find.

This is read-only black-box reconnaissance: a single GET request per
path, nothing more, with a short delay between requests. Every request
targets only the application you point this at.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import urljoin

import requests

from models import OwaspCategory, RawFinding

_COMMON_PATHS = [
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.local",
    ".env.production",
    "backup.zip",
    "backup.sql",
    "backup.tar.gz",
    "database.sql",
    "dump.sql",
    "wp-config.php.bak",
    "config.php.bak",
    "web.config.bak",
    ".svn/entries",
    ".DS_Store",
    "docker-compose.yml",
    "Dockerfile",
    ".aws/credentials",
    "id_rsa",
    "phpinfo.php",
    "server-status",
    "actuator/env",
    "actuator/heapdump",
    ".well-known/openid-configuration",
]


def check_exposed_paths(base_url: str, delay_seconds: float = 0.5) -> List[RawFinding]:
    findings: List[RawFinding] = []
    session = requests.Session()
    for path in _COMMON_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path)
        try:
            response = session.get(url, timeout=10, allow_redirects=False)
        except requests.RequestException:
            time.sleep(delay_seconds)
            continue

        if response.status_code == 200 and response.content:
            findings.append(
                RawFinding(
                    tool="exposure-check",
                    category=OwaspCategory.A02_MISCONFIGURATION,
                    title=f"Potentially exposed file or path: /{path}",
                    url=url,
                    raw_severity="medium",
                    description=(
                        f"A GET request to {url} returned HTTP 200 with content. "
                        "If this isn't meant to be public, remove it or block access."
                    ),
                    evidence=(
                        f"HTTP {response.status_code}, {len(response.content)} bytes, "
                        f"content-type: {response.headers.get('content-type', 'unknown')}"
                    ),
                )
            )
        time.sleep(delay_seconds)
    return findings
