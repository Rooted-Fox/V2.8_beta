"""Continuous learning pipeline for VulnIQ's triage agents.

Important honesty note: this does NOT fine-tune Claude. Opus cannot be
retrained by us. What this actually does — and what "learning" means in
this system — is pull real, current attacker techniques from trusted
sources and inject them into each agent's reasoning context before every
triage run. The agent reasons better because its prompt now contains
current technique knowledge, not because the model itself changed.

Sources:
  - PayloadsAllTheThings (GitHub) — categorized payloads with explanations
  - NIST NVD + CISA KEV — CVE ground truth (already used by nvd_scanner.py)
  - endoflife.date — EOL/SEOL component lifecycle data

HackTricks and PortSwigger are referenced as recommended reading for
methodology but are not scraped wholesale here — PortSwigger's academy
content is not freely redistributable, and HackTricks is a full book
better consulted directly than chunked automatically. Treat this module
as the automatable slice of the recommended resource list.
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

_STORE = Path(__file__).parent / "learned_knowledge.json"
_lock = threading.Lock()

# Each category maps to a PayloadsAllTheThings README we pull techniques from
_PATT_SOURCES = {
    "A05:injection": [
        "SQL%20Injection/README.md",
        "XSS%20Injection/README.md",
        "Server%20Side%20Template%20Injection/README.md",
        "Command%20Injection/README.md",
    ],
    "A01:broken_access_control": [
        "Insecure%20Direct%20Object%20References/README.md",
        "Server%20Side%20Request%20Forgery/README.md",
    ],
    "A07:authentication_failures": [
        "JSON%20Web%20Token/README.md",
        "Account%20Takeover/README.md",
    ],
    "A08:software_data_integrity_failures": [
        "Insecure%20Deserialization/README.md",
    ],
}

_BASE_RAW = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/"


def _load() -> dict:
    if _STORE.exists():
        try:
            return json.loads(_STORE.read_text())
        except Exception:
            pass
    return {"last_updated": None, "by_category": {}, "cve_summary": [],
            "eol_components": {}, "errors": []}


def _save(data: dict) -> None:
    with _lock:
        _STORE.write_text(json.dumps(data, indent=2, default=str))


def _extract_techniques(markdown: str, max_items: int = 8) -> List[str]:
    """Pull short, usable technique summaries out of a PayloadsAllTheThings
    README — headers (the technique name) paired with the first code block
    or explanation line that follows, so the agent gets 'what' and 'why'."""
    techniques = []
    # Split on ## or ### headers, which PayloadsAllTheThings uses per-technique
    sections = re.split(r'\n#{2,3}\s+', markdown)
    for section in sections[1:max_items + 1]:
        lines = section.strip().splitlines()
        if not lines:
            continue
        title = lines[0].strip()
        # Grab the first non-empty explanatory line after the title
        body_lines = [l.strip() for l in lines[1:6] if l.strip() and not l.strip().startswith("```")]
        summary = body_lines[0] if body_lines else ""
        # Grab first code/payload block if present
        code_match = re.search(r'```[^\n]*\n(.*?)```', section, re.DOTALL)
        payload_sample = code_match.group(1).strip().splitlines()[0] if code_match else ""
        entry = f"- {title}: {summary}"
        if payload_sample:
            entry += f" | Example: {payload_sample[:120]}"
        techniques.append(entry[:300])
    return techniques


def fetch_payloads_for_category(category: str) -> List[str]:
    """Pull and summarize current techniques for one OWASP category."""
    sources = _PATT_SOURCES.get(category, [])
    all_techniques = []
    for path in sources:
        try:
            resp = requests.get(_BASE_RAW + path, timeout=15)
            if resp.status_code == 200:
                all_techniques.extend(_extract_techniques(resp.text))
            time.sleep(0.3)  # be polite to GitHub's raw content servers
        except Exception:
            continue
    return all_techniques[:15]


def run_learning_cycle(nvd_api_key: str = "") -> dict:
    """Run one full learning cycle — call manually or on a schedule."""
    data = _load()
    errors = []

    # 1. Pull current techniques per category from PayloadsAllTheThings
    by_category = {}
    for category in _PATT_SOURCES:
        try:
            techniques = fetch_payloads_for_category(category)
            if techniques:
                by_category[category] = techniques
        except Exception as e:
            errors.append(f"PayloadsAllTheThings [{category}]: {e}")
    if by_category:
        data["by_category"] = by_category

    # 2. EOL component data (reuses the same endoflife.date source as before)
    try:
        products = ["php","nodejs","django","rails","wordpress","nginx",
                    "apache","jquery","react","angular","vue","bootstrap",
                    "tomcat","spring","laravel","drupal"]
        eol_data = {}
        for product in products:
            try:
                r = requests.get(f"https://endoflife.date/api/{product}.json", timeout=10)
                if r.status_code == 200:
                    cycles = r.json()
                    # keep only the 3 most recent cycles to stay compact
                    eol_data[product] = cycles[:3]
                time.sleep(0.2)
            except Exception:
                continue
        if eol_data:
            data["eol_components"] = eol_data
    except Exception as e:
        errors.append(f"EOL fetch: {e}")

    # 3. Recent critical CVEs (last 7 days) for situational awareness
    try:
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        headers = {"Accept": "application/json"}
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "pubStartDate": (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 20,
                "cvssV3Severity": "CRITICAL",
            },
            headers=headers, timeout=20,
        )
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            data["cve_summary"] = [
                {"id": v.get("cve", {}).get("id", ""),
                 "desc": (v.get("cve", {}).get("descriptions") or [{}])[0].get("value", "")[:150]}
                for v in vulns
            ]
    except Exception as e:
        errors.append(f"NVD recent CVE fetch: {e}")

    data["last_updated"] = datetime.now(timezone.utc).isoformat()
    data["errors"] = errors
    _save(data)
    return data


def get_knowledge() -> dict:
    """Return the current learned knowledge — used by the Settings UI."""
    return _load()


def context_for_category(category: str) -> str:
    """Build the prompt-injection string for one OWASP category. This is
    what actually makes the agent 'learned' — called from agents/agent.py
    when building the system prompt for each triage batch."""
    data = _load()
    techniques = data.get("by_category", {}).get(category, [])
    if not techniques:
        return ""
    lines = [
        "## Current attacker techniques (auto-updated from PayloadsAllTheThings)",
        "Use these as additional reasoning context when evaluating evidence — "
        "they reflect current real-world technique patterns, not just the base prompt's knowledge:",
    ]
    lines.extend(techniques)
    return "\n".join(lines)


def start_background_learning(api_key: str = "", interval_hours: int = 24) -> None:
    """Start a daemon thread that refreshes learned knowledge on a schedule."""
    def _loop():
        while True:
            try:
                run_learning_cycle(api_key)
            except Exception:
                pass
            time.sleep(interval_hours * 3600)
    threading.Thread(target=_loop, daemon=True).start()
