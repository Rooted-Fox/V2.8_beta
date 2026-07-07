"""Opus-powered API security triage agent.

Takes raw API findings and produces the same rich output as the web
scanner: CVSS score, CWE, OWASP API Top 10 mapping, root cause,
attack scenario, exploitation proof, and specific remediation.
"""
from __future__ import annotations

import json
from typing import List

from agents.agent import _build_client, _safe_float, TriageBatchError
from runtime_settings import get_settings

_API_SYSTEM = """You are a senior API penetration tester and security researcher.

You receive raw API security findings from automated testing against an authorized target.
Your job is to validate each finding, assess its real exploitability, and produce a
professional security report entry for each one.

Write like an experienced API security specialist writing for a client report:
- Be specific about which parameter, header, or field is vulnerable
- Explain exactly what an attacker gains from this specific finding
- Provide a working proof-of-concept request/response chain as evidence
- Give a specific, actionable fix — not "validate your inputs" but the exact middleware,
  header, or code pattern required

OWASP API Security Top 10 (2023) reference:
API1: BOLA (Broken Object Level Authorization) — CWE-284
API2: Broken Authentication — CWE-287, CWE-798
API3: Broken Object Property Level Authorization — CWE-213
API4: Unrestricted Resource Consumption — CWE-400
API5: Broken Function Level Authorization — CWE-285
API6: Unrestricted Access to Sensitive Business Flows — CWE-840
API7: Server Side Request Forgery — CWE-918
API8: Security Misconfiguration (Injection) — CWE-89, CWE-943
API9: Improper Inventory Management — CWE-1104
API10: Unsafe Consumption of APIs — CWE-346

Respond with a JSON array only. No prose. No markdown. One object per finding:
{
  "confirmed": true,
  "vulnerability_name": "Concise professional name",
  "owasp_api_category": "API1:2023 BOLA",
  "severity": "critical|high|medium|low",
  "cvss_score": 8.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
  "cwe_id": "CWE-284",
  "cwe_name": "Improper Access Control",
  "vulnerable_parameter": "exact parameter/field/header name",
  "root_cause": "exact technical root cause",
  "attack_scenario": "step-by-step: what the attacker does and what they gain",
  "proof_of_concept": "exact HTTP request that demonstrates the vulnerability",
  "business_impact": "specific business consequences",
  "remediation": "specific actionable fix with exact code pattern or middleware name",
  "false_positive_reason": null
}

If a finding is a false positive, set confirmed: false and explain in false_positive_reason.
"""


def triage_api_findings(raw_findings: List[dict]) -> List[dict]:
    """Send raw API findings to Opus for validation and enrichment."""
    if not raw_findings:
        return []

    rt = get_settings()
    if not rt.get("ai_enabled"):
        return raw_findings  # return unenriched if AI disabled

    client = _build_client(rt)
    model = rt["agent_model"]
    validated = []
    batch_size = 4

    for i in range(0, len(raw_findings), batch_size):
        batch = raw_findings[i:i + batch_size]
        user_msg = (
            f"Validate these {len(batch)} API security findings from authorized testing.\n\n"
            + json.dumps(batch, indent=2)
        )
        try:
            response = client.messages.create(
                model=model,
                max_tokens=min(800 + 1600 * len(batch), 8192),
                system=_API_SYSTEM,
                messages=[{"role": "user", "content": user_msg}],
            )
            text = "".join(b.text for b in response.content if b.type == "text")

            if getattr(response, "stop_reason", None) == "max_tokens":
                # truncated — keep raw findings for this batch
                validated.extend(batch)
                continue

            parsed = json.loads(text)
            for orig, enriched in zip(batch, parsed):
                if enriched.get("confirmed", True):
                    merged = {**orig, **enriched}
                    validated.append(merged)
        except Exception:
            # on any failure, keep the raw findings rather than lose them
            validated.extend(batch)

    return validated
