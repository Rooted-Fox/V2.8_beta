"""Historic CVE enumeration via NIST NVD — speed-optimised.

Speed improvements:
- NVD API key drops rate limit from 6.1s → 0.6s between requests (~10x faster)
- Max 20 CVEs per technology (down from 50) — gets the most critical hits quickly
- Only query high/critical CVEs (cvssV3Severity=HIGH or CRITICAL) to cut volume
- Concurrent technology lookups via ThreadPoolExecutor
- Skip version-less technologies for CVE lookup (can't confirm applicability anyway)
"""
from __future__ import annotations

import concurrent.futures
import os
import time
from typing import List, Optional, Tuple

import requests

from models import OwaspCategory, RawFinding
from runtime_settings import get_settings
from scanners.tech_fingerprint import fingerprint

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_CVES_PER_TECH = 20
_MAX_WORKERS = 4  # parallel NVD queries

_CWE_TO_OWASP = {
    "CWE-89":  OwaspCategory.A05_INJECTION,
    "CWE-79":  OwaspCategory.A05_INJECTION,
    "CWE-78":  OwaspCategory.A05_INJECTION,
    "CWE-94":  OwaspCategory.A05_INJECTION,
    "CWE-77":  OwaspCategory.A05_INJECTION,
    "CWE-917": OwaspCategory.A05_INJECTION,
    "CWE-287": OwaspCategory.A07_AUTH_FAILURES,
    "CWE-384": OwaspCategory.A07_AUTH_FAILURES,
    "CWE-798": OwaspCategory.A07_AUTH_FAILURES,
    "CWE-284": OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-285": OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-639": OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-22":  OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-326": OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-327": OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-311": OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-319": OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-502": OwaspCategory.A08_INTEGRITY_FAILURES,
    "CWE-345": OwaspCategory.A08_INTEGRITY_FAILURES,
    "CWE-16":  OwaspCategory.A02_MISCONFIGURATION,
    "CWE-400": OwaspCategory.A10_EXCEPTIONAL,
    "CWE-703": OwaspCategory.A10_EXCEPTIONAL,
    "CWE-778": OwaspCategory.A09_LOGGING_FAILURES,
}

# Known CVE dates by vulnerability type — for the historical table on Dashboard
VULN_FIRST_KNOWN = {
    "SQL Injection":             1998,
    "Cross-Site Scripting":      1999,
    "Buffer Overflow":           1988,
    "Path Traversal":            1999,
    "Command Injection":         1994,
    "CSRF":                      2001,
    "XML Injection":             2002,
    "LDAP Injection":            2001,
    "XXE":                       2002,
    "Insecure Deserialization":  2015,
    "SSRF":                      2012,
    "Open Redirect":             2000,
    "Clickjacking":              2008,
    "HeartBleed":                2012,
    "Log4Shell":                 2021,
    "ShellShock":                2014,
}


def _owasp_from_cwes(cwes: List[str]) -> OwaspCategory:
    for cwe in cwes:
        if cwe in _CWE_TO_OWASP:
            return _CWE_TO_OWASP[cwe]
    return OwaspCategory.A03_SUPPLY_CHAIN


def _nvd_headers(api_key: str) -> dict:
    h = {"Accept": "application/json"}
    if api_key:
        h["apiKey"] = api_key
    return h


def _query_one_tech(tech: str, version: Optional[str],
                    api_key: str, delay: float) -> List[RawFinding]:
    """Query NVD for one technology and return RawFindings."""
    findings: List[RawFinding] = []

    params = {
        "keywordSearch": tech,
        "resultsPerPage": _MAX_CVES_PER_TECH,
        "startIndex": 0,
        "cvssV3Severity": "HIGH",   # only HIGH and CRITICAL — skip low/medium noise
    }
    try:
        resp = requests.get(NVD_API_BASE, params=params,
                            headers=_nvd_headers(api_key), timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return findings
    finally:
        time.sleep(delay)

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("vulnStatus") in ("Rejected", "Disputed"):
            continue

        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # CVSS extraction
        metrics = cve.get("metrics", {})
        score, vector, severity_str = None, None, "high"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                d = metrics[key][0].get("cvssData", {})
                score = d.get("baseScore")
                vector = d.get("vectorString")
                severity_str = str(d.get("baseSeverity") or "high").lower()
                break

        cwes = []
        for w in cve.get("weaknesses", []):
            for dd in w.get("description", []):
                v = dd.get("value", "")
                if v.startswith("CWE-"):
                    cwes.append(v)

        raw_sev = "critical" if (score or 0) >= 9.0 else "high"
        is_kev = bool(cve.get("cisaExploitAdd"))
        version_note = f" (detected: {version})" if version else ""
        kev_note = " [ACTIVELY EXPLOITED]" if is_kev else ""

        findings.append(RawFinding(
            tool="cve-intelligence",
            category=_owasp_from_cwes(cwes),
            title=f"{cve_id}: {tech}{version_note}{kev_note}",
            url="",
            raw_severity=raw_sev,
            description=description[:500],
            evidence=(
                f"CVE: {cve_id} | Tech: {tech}{version_note} | "
                f"CVSS: {score} | Vector: {vector} | CWEs: {','.join(cwes) or 'N/A'}"
            ),
        ))

    # Also query for CRITICAL separately (NVD doesn't support OR on severity)
    params["cvssV3Severity"] = "CRITICAL"
    try:
        resp = requests.get(NVD_API_BASE, params=params,
                            headers=_nvd_headers(api_key), timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return findings
    finally:
        time.sleep(delay)

    seen_ids = {f.title.split(":")[0] for f in findings}
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if cve_id in seen_ids or cve.get("vulnStatus") in ("Rejected", "Disputed"):
            continue
        descs = cve.get("descriptions", [])
        description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score, vector = None, None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics:
                d = metrics[key][0].get("cvssData", {})
                score = d.get("baseScore")
                vector = d.get("vectorString")
                break
        cwes = []
        for w in cve.get("weaknesses", []):
            for dd in w.get("description", []):
                v = dd.get("value", "")
                if v.startswith("CWE-"):
                    cwes.append(v)
        is_kev = bool(cve.get("cisaExploitAdd"))
        version_note = f" (detected: {version})" if version else ""
        kev_note = " [ACTIVELY EXPLOITED]" if is_kev else ""
        findings.append(RawFinding(
            tool="cve-intelligence",
            category=_owasp_from_cwes(cwes),
            title=f"{cve_id}: {tech}{version_note}{kev_note}",
            url="",
            raw_severity="critical",
            description=description[:500],
            evidence=(
                f"CVE: {cve_id} | Tech: {tech}{version_note} | "
                f"CVSS: {score} | Vector: {vector} | CWEs: {','.join(cwes) or 'N/A'}"
            ),
        ))

    return findings


def run_nvd_scan(target_url: str) -> List[RawFinding]:
    """Fingerprint the target then query NVD for HIGH/CRITICAL CVEs in parallel."""
    rt = get_settings()
    api_key = rt.get("nvd_api_key", "") or ""
    delay = 0.65 if api_key else 6.1

    technologies = fingerprint(target_url)
    # Only query techs where we know the version — unversioned lookups return too much noise
    versioned = [(t, v) for t, v in technologies
                 if v and t not in ("generator","powered_by","framework","CMS-detected")]
    # Also include unversioned for well-known products worth checking
    important = ["WordPress","Drupal","Apache Tomcat","JBoss","nginx","Apache HTTP Server",
                 "OpenSSL","PHP","Django","Ruby on Rails","jQuery","Laravel"]
    unversioned = [(t, v) for t, v in technologies
                   if not v and t in important]
    to_query = versioned + unversioned

    if not to_query:
        return []

    all_findings: List[RawFinding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {
            executor.submit(_query_one_tech, t, v, api_key, delay): (t, v)
            for t, v in to_query
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                all_findings.extend(future.result())
            except Exception:
                pass

    # Deduplicate by CVE ID
    seen: set = set()
    deduped: List[RawFinding] = []
    for f in all_findings:
        cve_id = f.title.split(":")[0].strip()
        if cve_id not in seen:
            seen.add(cve_id)
            deduped.append(f)

    return deduped
