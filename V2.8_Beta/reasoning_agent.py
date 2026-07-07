"""Pre-scan reasoning agent — Opus reads the application map and produces
a targeted test plan before any active scanning begins.

This is what turns blind scanning into intelligent testing. Instead of
firing every test at every endpoint equally, Opus understands what the
application does, identifies the highest-risk areas, and directs the
scanners accordingly.

Also implements open reasoning mode — Opus reasons beyond OWASP Top 10
and flags anything suspicious regardless of category, going beyond
signature-based detection to true security reasoning.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from agents.agent import _build_client
from browser_agent import BrowserCrawlResult
from runtime_settings import get_settings

_REASONING_SYSTEM = """You are a principal security architect and penetration testing expert.

You have been given the results of an authenticated browser crawl of a web application.
Your job is to:

1. Understand what this application does — its purpose, the data it handles, the user roles,
   the sensitive operations, and the business logic it enforces.

2. Identify the highest-risk areas — which endpoints, parameters, and workflows are most
   likely to contain security vulnerabilities based on what you know about applications like this.

3. Go BEYOND OWASP Top 10 — reason about the full spectrum of web application security
   including business logic flaws, application-specific attack surfaces, emerging vulnerability
   classes, and anything unusual you observe in the endpoint map.

4. Produce a targeted test plan — specific instructions for what to test, where to focus,
   what vulnerability classes are most likely, and what evidence to look for.

Respond with a JSON object:
{
  "app_summary": "what this application does in 2-3 sentences",
  "app_type": "e-commerce|banking|cms|social|admin|api|other",
  "sensitive_areas": ["list of highest-risk endpoints or features"],
  "likely_vulnerabilities": [
    {
      "type": "vulnerability class name",
      "location": "specific endpoint or feature",
      "reason": "why this is likely here",
      "test_approach": "how to test for it",
      "beyond_owasp": true or false
    }
  ],
  "priority_endpoints": ["list of endpoints to test most thoroughly"],
  "business_logic_rules": ["inferred rules the application is supposed to enforce"],
  "attack_surface_notes": "anything unusual or high-risk observed",
  "open_reasoning_flags": ["anything suspicious that doesn't fit a standard category"]
}
"""


def generate_test_plan(crawl_result: BrowserCrawlResult,
                        target_url: str) -> Optional[Dict[str, Any]]:
    """Send the crawl results to Opus and get back a targeted test plan."""
    rt = get_settings()
    if not rt.get("ai_enabled"):
        return None

    try:
        client = _build_client(rt)
        model = rt["agent_model"]

        # Build the application map for Opus to reason about
        endpoints_summary = []
        for ep in crawl_result.endpoints[:100]:
            summary = f"{ep.get('method','GET')} {ep.get('path','/')}"
            if ep.get('post_data'):
                try:
                    body = json.loads(ep['post_data'])
                    summary += f" body_fields={list(body.keys())}"
                except Exception:
                    summary += f" body={ep['post_data'][:100]}"
            endpoints_summary.append(summary)

        forms_summary = []
        for form in crawl_result.forms[:20]:
            fields = [f.get('name','') for f in form.get('fields', [])]
            forms_summary.append(f"{form.get('method','GET')} {form.get('action','')} fields={fields}")

        user_content = f"""Target: {target_url}
Authentication: {"Successful" if crawl_result.authenticated else "Not authenticated"}
Application context: {crawl_result.app_context}
Page titles: {', '.join(set(crawl_result.page_titles[:10]))}

Discovered endpoints ({len(crawl_result.endpoints)} total, showing top 100):
{chr(10).join(endpoints_summary)}

Forms discovered:
{chr(10).join(forms_summary) if forms_summary else "None detected"}

JavaScript API calls ({len(crawl_result.js_api_calls)} total):
{chr(10).join(set(ep.get('path','') for ep in crawl_result.js_api_calls[:30]))}

Based on this application map, produce your security test plan."""

        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_REASONING_SYSTEM,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(b.text for b in response.content if b.type == "text")
        return json.loads(text)

    except Exception as e:
        return {"error": str(e), "app_summary": "Could not generate test plan",
                "likely_vulnerabilities": [], "priority_endpoints": [],
                "business_logic_rules": [], "open_reasoning_flags": []}


_OPEN_REASONING_SYSTEM = """You are a world-class penetration tester with expertise across
ALL domains of web application security — not limited to any framework, standard, or checklist.

You have raw HTTP request and response evidence from a security scan.

Your job is to reason about this evidence and identify ANY security issue you observe —
whether it appears in OWASP Top 10, CWE Top 25, SANS Top 25, or nowhere in any standard list.
Real vulnerabilities are not constrained by what lists were written years ago.

Look for:
- Standard vulnerability classes (injection, auth failures, access control, etc.)
- Business logic flaws specific to this application
- Emerging attack classes (prototype pollution, cache poisoning, HTTP smuggling, etc.)
- Novel patterns that look wrong even if you cannot name the category
- Chaining opportunities — how this finding connects to others
- Application-specific weaknesses based on what the application does

For each issue found, explain:
- What you observed
- Why it is a security concern
- What an attacker could do with it
- How to fix it

Respond with a JSON array of findings. Each finding:
{
  "vulnerability_name": "descriptive name",
  "category": "OWASP category if applicable, otherwise 'Beyond OWASP'",
  "severity": "critical|high|medium|low",
  "evidence": "what in the HTTP evidence indicates this",
  "attacker_impact": "what an attacker gains",
  "remediation": "specific fix",
  "novel": true or false
}

Return [] if nothing suspicious is found. Never invent findings not supported by evidence.
"""


def open_reason_finding(finding_evidence: str, app_context: str = "") -> List[dict]:
    """Apply open-ended security reasoning to raw evidence — goes beyond OWASP categories."""
    rt = get_settings()
    if not rt.get("ai_enabled"):
        return []
    try:
        client = _build_client(rt)
        model = rt["agent_model"]
        user_content = f"""Application context: {app_context}

Raw security evidence to reason about:
{finding_evidence}

Identify every security issue present in this evidence."""

        response = client.messages.create(
            model=model,
            max_tokens=2048,
            system=_OPEN_REASONING_SYSTEM,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(b.text for b in response.content if b.type == "text")
        return json.loads(text)
    except Exception:
        return []
