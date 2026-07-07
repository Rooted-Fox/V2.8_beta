"""FFuf scanner: directory and file discovery, parameter fuzzing.

Finds hidden directories, admin panels, backup files, and API endpoints
that aren't linked from anywhere - these are prime candidates for access
control and misconfiguration findings. Uses SecLists wordlists if
available on Kali, falls back to a built-in short list.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from models import OwaspCategory, RawFinding
from scan_control import ScanControl, run_controlled_subprocess
from scanners.base import ScannerNotInstalled

_KALI_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

_BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "api", "api/v1", "api/v2",
    "backup", "config", "configuration", "debug", "dev", "development",
    "test", "staging", "old", "bak", ".git", ".env", "phpinfo.php",
    "robots.txt", "sitemap.xml", "swagger.json", "openapi.json", "graphql",
    "actuator", "actuator/env", "actuator/heapdump", "health", "metrics",
    "console", "shell", "upload", "uploads", "files", "images", "static",
]

_SENSITIVE_PATTERNS = [
    "admin", "backup", "config", ".git", ".env", "console",
    "actuator", "debug", "shell", "dashboard", "manage",
]


def _find_wordlist() -> str | None:
    for path in _KALI_WORDLISTS:
        if Path(path).exists():
            return path
    return None


def run_ffuf(target_url: str, control: Optional[ScanControl] = None) -> List[RawFinding]:
    if not shutil.which("ffuf"):
        raise ScannerNotInstalled("ffuf not found - install with: sudo apt install ffuf")

    base = target_url.rstrip("/")
    fuzz_url = f"{base}/FUZZ"

    wordlist = _find_wordlist()
    if wordlist:
        wordlist_arg = ["-w", wordlist]
    else:
        # write built-in wordlist to a temp file
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write("\n".join(_BUILTIN_WORDLIST))
        tmp.close()
        wordlist_arg = ["-w", tmp.name]

    args = [
        "ffuf",
        "-u", fuzz_url,
        *wordlist_arg,
        "-mc", "200,201,202,204,301,302,307,401,403",  # interesting status codes
        "-o", "/dev/stdout",
        "-of", "json",
        "-t", "30",          # 30 threads - fast but not abusive
        "-timeout", "10",
        "-s",                # silent mode
    ]

    try:
        result = run_controlled_subprocess(args, control=control, timeout=300)
        output = result.stdout
    except Exception:
        output = ""

    findings: List[RawFinding] = []
    try:
        data = json.loads(output)
        results = data.get("results", [])
    except json.JSONDecodeError:
        return findings

    for item in results:
        path = item.get("input", {}).get("FUZZ", "")
        status = item.get("status", 0)
        url = f"{base}/{path}"

        # raise severity for admin/sensitive-looking paths
        is_sensitive = any(pat in path.lower() for pat in _SENSITIVE_PATTERNS)
        if status == 200 and is_sensitive:
            severity = "high"
            category = OwaspCategory.A01_ACCESS_CONTROL
        elif status in (200, 201, 202, 204) and is_sensitive:
            severity = "high"
            category = OwaspCategory.A01_ACCESS_CONTROL
        elif status in (401, 403):
            severity = "info"
            category = OwaspCategory.A01_ACCESS_CONTROL
        else:
            severity = "low"
            category = OwaspCategory.A02_MISCONFIGURATION

        findings.append(
            RawFinding(
                tool="endpoint-discovery",
                category=category,
                title=f"Discovered path: /{path} (HTTP {status})",
                url=url,
                raw_severity=severity,
                description=(
                    f"ffuf discovered /{path} returning HTTP {status}. "
                    f"{'Sensitive-looking path accessible.' if is_sensitive else 'Path exists on server.'}"
                ),
                evidence=f"Status: {status} | Size: {item.get('length', 0)} bytes | Words: {item.get('words', 0)}",
            )
        )
    return findings
