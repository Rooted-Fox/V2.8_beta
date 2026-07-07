"""Nikto scanner: web server misconfiguration and outdated software detection.

Nikto checks 6700+ potentially dangerous files/programs, checks for outdated
versions of over 1250 servers, and finds version-specific problems. Strong
coverage for A02 (misconfiguration) and A03 (supply chain/outdated components).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from models import OwaspCategory, RawFinding
from scan_control import ScanControl, run_controlled_subprocess
from scanners.base import ScannerNotInstalled

_OSWAP_REFS = {
    "1": OwaspCategory.A02_MISCONFIGURATION,  # interesting files
    "2": OwaspCategory.A02_MISCONFIGURATION,  # misconfiguration
    "3": OwaspCategory.A03_SUPPLY_CHAIN,      # outdated
    "4": OwaspCategory.A02_MISCONFIGURATION,  # generic
    "6": OwaspCategory.A05_INJECTION,         # denial of service
    "7": OwaspCategory.A02_MISCONFIGURATION,  # remote file retrieval
    "8": OwaspCategory.A05_INJECTION,         # command execution
    "9": OwaspCategory.A07_AUTH_FAILURES,     # SQL injection
    "0": OwaspCategory.A02_MISCONFIGURATION,  # info disclosure
}


def run_nikto(target_url: str, control: Optional[ScanControl] = None) -> List[RawFinding]:
    if not shutil.which("nikto"):
        raise ScannerNotInstalled("nikto not found - install with: sudo apt install nikto")

    output_file = tempfile.mktemp(suffix=".json")
    args = [
        "nikto",
        "-h", target_url,
        "-Format", "json",
        "-output", output_file,
        "-nointeractive",
        "-Tuning", "0123456789abc",  # all scan types
        "-timeout", "10",
    ]

    run_controlled_subprocess(args, control=control, timeout=600)

    findings: List[RawFinding] = []
    try:
        data = json.loads(Path(output_file).read_text())
    except (OSError, json.JSONDecodeError):
        return findings

    for vuln in data.get("vulnerabilities", []):
        osvdb = str(vuln.get("OSVDBID", "0"))
        category = _OSWAP_REFS.get(osvdb[0] if osvdb else "0", OwaspCategory.A02_MISCONFIGURATION)
        findings.append(
            RawFinding(
                tool="server-analyser",
                category=category,
                title=vuln.get("msg", "nikto finding"),
                url=vuln.get("url", target_url),
                raw_severity="medium",
                description=vuln.get("msg", ""),
                evidence=f"OSVDB: {osvdb} | Method: {vuln.get('method', 'GET')}",
            )
        )
    return findings
