"""SQLMap scanner: dedicated SQL injection testing using sqlmap.

SQLMap is purpose-built for SQLi and goes far deeper than ZAP's injection
checks - it tests dozens of injection techniques (boolean-based, time-based,
error-based, UNION-based, stacked, out-of-band) and confirms exploitation
rather than just detecting it. This maps to A05:Injection at critical/high.

Only runs against the same target URL you authorize. Deliberately non-
destructive: --level 3 --risk 2 is thorough without causing data loss.
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


def run_sqlmap(target_url: str, scan_mode: str = "thorough",
               control: Optional[ScanControl] = None) -> List[RawFinding]:
    if not shutil.which("sqlmap"):
        raise ScannerNotInstalled("sqlmap not found - install with: sudo apt install sqlmap")

    output_dir = tempfile.mkdtemp(prefix="sqlmap_")
    if scan_mode == "fast":
        level, crawl, timeout_sec = "1", "1", 180   # boundary/error/UNION-based only — skips slow blind/time-based probing
    else:
        level, crawl, timeout_sec = "3", "2", 600   # full technique sweep including blind/time-based

    args = [
        "sqlmap",
        "-u", target_url,
        "--batch",            # non-interactive
        "--level", level,
        "--risk", "2",        # avoids destructive tests regardless of mode
        "--forms",            # also test forms on the page
        "--crawl", crawl,
        "--output-dir", output_dir,
        "--results-file", f"{output_dir}/results.json",
        "--format", "json",
        "--quiet",
    ]

    run_controlled_subprocess(args, control=control, timeout=timeout_sec)

    findings: List[RawFinding] = []
    results_path = Path(output_dir) / "results.json"
    if not results_path.exists():
        # sqlmap writes per-target files, scan for any JSON output
        for json_file in Path(output_dir).rglob("*.json"):
            findings.extend(_parse_sqlmap_json(json_file))
    else:
        findings.extend(_parse_sqlmap_json(results_path))

    # also check sqlmap's log for confirmed injections
    for log_file in Path(output_dir).rglob("*.log"):
        findings.extend(_parse_sqlmap_log(log_file, target_url))

    return findings


def _parse_sqlmap_json(path: Path) -> List[RawFinding]:
    findings = []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return findings

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [data]
    else:
        return findings

    for item in items:
        if not item.get("data"):
            continue
        for param, details in (item.get("data") or {}).items():
            technique = details.get("type", "SQL injection")
            findings.append(
                RawFinding(
                    tool="vulnerability-scanner",
                    category=OwaspCategory.A05_INJECTION,
                    title=f"SQL injection confirmed on parameter: {param}",
                    url=item.get("url", ""),
                    raw_severity="critical",
                    description=(
                        f"SQLMap confirmed SQL injection on parameter '{param}' "
                        f"using technique: {technique}. Database type: {item.get('dbms', 'unknown')}."
                    ),
                    evidence=json.dumps(details, indent=2)[:1500],
                )
            )
    return findings


def _parse_sqlmap_log(log_path: Path, target_url: str) -> List[RawFinding]:
    """Fallback: parse sqlmap's human-readable log for confirmed injections."""
    findings = []
    try:
        text = log_path.read_text(errors="ignore")
    except OSError:
        return findings

    if "sqlmap identified the following injection point" in text.lower():
        lines = [l for l in text.splitlines() if "injectable" in l.lower() or "parameter" in l.lower()]
        evidence = "\n".join(lines[:20])
        findings.append(
            RawFinding(
                tool="vulnerability-scanner",
                category=OwaspCategory.A05_INJECTION,
                title="SQL injection confirmed by sqlmap",
                url=target_url,
                raw_severity="critical",
                description="SQLMap confirmed one or more SQL injection points. See evidence for details.",
                evidence=evidence[:1500],
            )
        )
    return findings
