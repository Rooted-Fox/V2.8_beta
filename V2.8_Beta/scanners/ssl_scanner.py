"""TLS/SSL scanner: cryptographic failure detection across all OWASP eras.

Tests for every known TLS weakness from SSLv2 (circa 1994) through modern
cipher suite issues — covering OWASP 2003-2026 A04 cryptographic failures
in one pass. Uses testssl.sh if available (Kali), otherwise sslscan.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from models import OwaspCategory, RawFinding
from scanners.base import ScannerNotInstalled

_SEVERITY_KEYWORDS = {
    "critical": ["sslv2", "poodle", "heartbleed", "drown", "beast", "crime", "breach",
                 "robot", "sweet32", "lucky13", "rce"],
    "high": ["sslv3", "tls10", "tls 1.0", "rc4", "des", "3des", "export",
             "null cipher", "anon cipher", "weak dh", "logjam", "freak",
             "certificate expired", "self-signed"],
    "medium": ["tls 1.1", "tls11", "sha1", "md5", "weak rsa", "short key",
               "revocation", "wildcard"],
    "low": ["hsts", "missing hsts", "secure flag", "httponly", "samesite",
            "forward secrecy partial"],
}


def _infer_severity(message: str) -> str:
    lowered = message.lower()
    for severity, keywords in _SEVERITY_KEYWORDS.items():
        if any(kw in lowered for kw in keywords):
            return severity
    return "info"


def run_ssl_scan(target_url: str) -> List[RawFinding]:
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return [
            RawFinding(
                tool="crypto-analyser",
                category=OwaspCategory.A04_CRYPTO_FAILURES,
                title="Site not served over HTTPS",
                url=target_url,
                raw_severity="high",
                description="The target URL uses HTTP not HTTPS. All traffic is transmitted unencrypted.",
                evidence=f"Scheme: {parsed.scheme}",
            )
        ]

    findings = []
    if shutil.which("testssl.sh") or shutil.which("testssl"):
        findings = _run_testssl(host, port, target_url)
    elif shutil.which("sslscan"):
        findings = _run_sslscan(host, port, target_url)
    else:
        raise ScannerNotInstalled(
            "No TLS scanner found. Install with: sudo apt install sslscan  "
            "or: git clone https://github.com/drwetter/testssl.sh"
        )

    return findings


def _run_testssl(host: str, port: int, target_url: str) -> List[RawFinding]:
    binary = shutil.which("testssl.sh") or shutil.which("testssl")
    output_file = tempfile.mktemp(suffix=".json")
    args = [
        binary,
        "--jsonfile", output_file,
        "--quiet",
        "--nodns", "min",
        f"{host}:{port}",
    ]
    try:
        subprocess.run(args, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        pass

    findings = []
    try:
        data = json.loads(Path(output_file).read_text())
    except (OSError, json.JSONDecodeError):
        return findings

    for item in data:
        if item.get("severity") in ("OK", "INFO"):
            continue
        severity = _infer_severity(item.get("finding", ""))
        if severity == "info":
            continue
        findings.append(
            RawFinding(
                tool="crypto-analyser",
                category=OwaspCategory.A04_CRYPTO_FAILURES,
                title=f"TLS issue: {item.get('id', 'unknown')}",
                url=target_url,
                raw_severity=severity,
                description=item.get("finding", ""),
                evidence=f"Severity: {item.get('severity')} | ID: {item.get('id')}",
            )
        )
    return findings


def _run_sslscan(host: str, port: int, target_url: str) -> List[RawFinding]:
    args = ["sslscan", "--no-colour", f"{host}:{port}"]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        output = result.stdout
    except subprocess.TimeoutExpired:
        return []

    findings = []
    issues = [
        ("SSLv2", "SSLv2 supported - critically weak, deprecated since 1996", "critical"),
        ("SSLv3", "SSLv3 supported - vulnerable to POODLE attack", "high"),
        ("TLSv1.0", "TLS 1.0 supported - deprecated, vulnerable to BEAST/POODLE", "high"),
        ("TLSv1.1", "TLS 1.1 supported - deprecated as of 2021", "medium"),
        ("RC4", "RC4 cipher supported - broken stream cipher", "high"),
        ("DES", "DES/3DES cipher supported - weak block cipher", "high"),
        ("MD5", "MD5 in cipher suite or certificate - cryptographically broken", "high"),
    ]

    for marker, description, severity in issues:
        if marker in output:
            findings.append(
                RawFinding(
                    tool="crypto-analyser",
                    category=OwaspCategory.A04_CRYPTO_FAILURES,
                    title=f"Weak TLS: {marker} detected",
                    url=target_url,
                    raw_severity=severity,
                    description=description,
                    evidence=f"sslscan detected {marker} on {host}:{port}",
                )
            )
    return findings
