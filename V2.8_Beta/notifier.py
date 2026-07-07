"""Pushes a summary of new critical/high findings to Slack."""
from __future__ import annotations

from typing import List

import requests

from models import Severity, TriagedFinding
from runtime_settings import get_settings

_NOTIFY_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def notify_new_critical_findings(findings: List[TriagedFinding]) -> None:
    webhook_url = get_settings()["slack_webhook_url"]
    urgent = [f for f in findings if f.severity in _NOTIFY_SEVERITIES and f.exploitable]
    if not urgent or not webhook_url:
        return

    lines = [f"*{len(urgent)} new exploitable finding(s) need review:*"]
    for finding in urgent[:10]:
        lines.append(f"- [{finding.severity.value.upper()}] {finding.title} ({finding.url or 'n/a'})")

    requests.post(webhook_url, json={"text": "\n".join(lines)}, timeout=10)
