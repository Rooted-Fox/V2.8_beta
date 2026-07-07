"""Nuclei scanner: template-based CVE and vulnerability detection.

Nuclei runs 4000+ community templates covering CVEs from 2003 onwards,
misconfigurations, exposed panels, default credentials, and more - it's
the closest thing to "every known vulnerability class from OWASP history"
in a single tool. Maps findings across all 10 OWASP categories.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import List

from models import OwaspCategory, RawFinding
from scanners.base import ScannerNotInstalled

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "low",
}

_TAG_TO_CATEGORY = {
    "sqli": OwaspCategory.A05_INJECTION,
    "xss": OwaspCategory.A05_INJECTION,
    "ssti": OwaspCategory.A05_INJECTION,
    "injection": OwaspCategory.A05_INJECTION,
    "lfi": OwaspCategory.A01_ACCESS_CONTROL,
    "idor": OwaspCategory.A01_ACCESS_CONTROL,
    "path-traversal": OwaspCategory.A01_ACCESS_CONTROL,
    "auth-bypass": OwaspCategory.A07_AUTH_FAILURES,
    "default-login": OwaspCategory.A07_AUTH_FAILURES,
    "misconfig": OwaspCategory.A02_MISCONFIGURATION,
    "exposure": OwaspCategory.A02_MISCONFIGURATION,
    "config": OwaspCategory.A02_MISCONFIGURATION,
    "panel": OwaspCategory.A02_MISCONFIGURATION,
    "cve": OwaspCategory.A03_SUPPLY_CHAIN,
    "outdated": OwaspCategory.A03_SUPPLY_CHAIN,
    "crypto": OwaspCategory.A04_CRYPTO_FAILURES,
    "ssl": OwaspCategory.A04_CRYPTO_FAILURES,
    "tls": OwaspCategory.A04_CRYPTO_FAILURES,
    "rce": OwaspCategory.A05_INJECTION,
    "deserialization": OwaspCategory.A08_INTEGRITY_FAILURES,
    "ssrf": OwaspCategory.A10_EXCEPTIONAL,
    "dos": OwaspCategory.A10_EXCEPTIONAL,
    "redirect": OwaspCategory.A01_ACCESS_CONTROL,
    "xfo": OwaspCategory.A02_MISCONFIGURATION,
    "cors": OwaspCategory.A01_ACCESS_CONTROL,
}


def _infer_category(tags: list, template_id: str) -> OwaspCategory:
    for tag in tags:
        tag_lower = tag.lower()
        for key, category in _TAG_TO_CATEGORY.items():
            if key in tag_lower:
                return category
    # fallback by template ID prefix
    tid = template_id.lower()
    if "cve" in tid:
        return OwaspCategory.A03_SUPPLY_CHAIN
    if "sql" in tid or "xss" in tid or "inject" in tid:
        return OwaspCategory.A05_INJECTION
    return OwaspCategory.A02_MISCONFIGURATION


def run_nuclei(target_url: str) -> List[RawFinding]:
    if not shutil.which("nuclei"):
        raise ScannerNotInstalled(
            "nuclei not found - install with: sudo apt install nuclei  "
            "or: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )

    args = [
        "nuclei",
        "-u", target_url,
        "-jsonl",            # one JSON object per line
        "-severity", "critical,high,medium,low",
        "-tags", "cve,sqli,xss,ssti,lfi,ssrf,rce,auth-bypass,default-login,misconfig,exposure,cors,deserialization,panel",
        "-rate-limit", "50", # be respectful, not evasive
        "-silent",
        "-no-color",
        "-timeout", "10",
    ]

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=900)
        output = result.stdout
    except subprocess.TimeoutExpired:
        output = ""

    findings: List[RawFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        matched_at = item.get("matched-at") or item.get("host") or target_url
        evidence = item.get("request", "") + "\n" + item.get("response", "")

        findings.append(
            RawFinding(
                tool="template-scanner",
                category=_infer_category(tags, item.get("template-id", "")),
                title=f"[{item.get('template-id', 'nuclei')}] {info.get('name', 'finding')}",
                url=matched_at,
                raw_severity=_SEVERITY_MAP.get(info.get("severity", "low"), "low"),
                description=info.get("description", "")[:500],
                evidence=evidence[:1500],
            )
        )
    return findings
