"""Business logic security agent — tests what no signature scanner can.

Infers the rules the application is supposed to enforce from the crawl
and test plan, then generates and executes tests specifically designed
to break those rules.

Finds: price manipulation, workflow bypass, privilege escalation through
application-specific paths, IDOR across related objects, multi-step
process abuse, and any other logic the application is supposed to prevent.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional

import requests

from agents.agent import _build_client
from runtime_settings import get_settings

_UA = "Mozilla/5.0 (compatible; VulnIQ-Security-Scanner/2.0)"

_BIZLOGIC_SYSTEM = """You are a business logic security specialist conducting an
authorized penetration test.

You have a map of the application — its purpose, its inferred business rules,
its endpoints, and what it is supposed to do.

Your job is to generate test cases that check whether the application's business
rules can be violated. Think like an attacker who understands what the application
is supposed to prevent and tries systematically to bypass those controls.

Test categories to consider:
- Price/value manipulation (negative prices, zero cost, overflow)
- Workflow bypass (skip required steps, jump to the end)
- Quantity manipulation (order more than available, negative quantities)
- Privilege/role bypass (access other users' resources, elevate own role)
- State manipulation (modify read-only fields, replay old states)
- Race conditions (concurrent requests to limited-use operations)
- Time-based bypass (expired tokens still working, future-dated operations)
- Referential bypass (reference objects from different accounts/contexts)
- Limit bypass (exceed rate limits, quotas, or usage caps)

For each test case produce:
{
  "test_name": "descriptive name",
  "rule_being_tested": "the business rule this should enforce",
  "attack_description": "what an attacker would do",
  "method": "GET|POST|PUT|DELETE|PATCH",
  "url": "exact URL",
  "headers": {},
  "body": null or {"field": "value"},
  "success_indicator": "what in the response would indicate the rule was bypassed",
  "severity_if_found": "critical|high|medium|low"
}

Return a JSON array of test cases. Be specific and targeted to this application.
"""

_ANALYSIS_SYSTEM = """You are a penetration tester analysing business logic test results.

For each test result, determine whether the business rule was bypassed.
A bypass means the application allowed something it should have prevented.

Return a JSON array of confirmed findings:
{
  "vulnerability_name": "specific name",
  "rule_violated": "what business rule was bypassed",
  "severity": "critical|high|medium|low",
  "url": "affected URL",
  "method": "HTTP method",
  "evidence": "exactly what in the response confirms the bypass",
  "business_impact": "what an attacker gains from this",
  "remediation": "specific fix",
  "tool": "business-logic-agent",
  "raw_severity": "high",
  "category": "Business Logic Flaw"
}

Return [] if no bypasses were confirmed.
"""


def run_business_logic_tests(
    test_plan: dict,
    session: requests.Session,
    base_headers: dict = None,
    push_callback: Optional[Callable[[dict], None]] = None,
) -> List[dict]:
    """Generate and execute business logic test cases based on the test plan."""
    rt = get_settings()
    if not rt.get("ai_enabled"):
        return []

    try:
        client = _build_client(rt)
        model = rt["agent_model"]
    except Exception:
        return []

    findings = []

    # Generate test cases
    try:
        user_content = f"""Application summary: {test_plan.get('app_summary', '')}
Application type: {test_plan.get('app_type', 'unknown')}

Inferred business rules:
{json.dumps(test_plan.get('business_logic_rules', []), indent=2)}

High-risk areas:
{json.dumps(test_plan.get('sensitive_areas', []), indent=2)}

Priority endpoints:
{json.dumps(test_plan.get('priority_endpoints', []), indent=2)}

Generate targeted business logic test cases for this specific application."""

        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_BIZLOGIC_SYSTEM,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(b.text for b in response.content if b.type == "text")
        test_cases = json.loads(text)

    except Exception:
        return findings

    if not test_cases:
        return findings

    # Execute test cases
    results = []
    headers = {**{"User-Agent": _UA}, **(base_headers or {})}

    for test in test_cases[:20]:  # cap at 20 test cases
        try:
            body = test.get("body")
            resp = session.request(
                method=test.get("method", "GET"),
                url=test["url"],
                headers={**headers, **(test.get("headers") or {})},
                json=body if body else None,
                timeout=10,
                allow_redirects=True,
            )
            results.append({
                "test_name": test.get("test_name", ""),
                "rule_being_tested": test.get("rule_being_tested", ""),
                "attack_description": test.get("attack_description", ""),
                "success_indicator": test.get("success_indicator", ""),
                "severity_if_found": test.get("severity_if_found", "medium"),
                "url": test["url"],
                "method": test.get("method", "GET"),
                "body_sent": body,
                "status_code": resp.status_code,
                "response_length": len(resp.text),
                "response_snippet": resp.text[:400],
            })
            time.sleep(0.3)
        except Exception:
            continue

    if not results:
        return findings

    # Analyse results with Opus
    try:
        analysis_response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_ANALYSIS_SYSTEM,
            messages=[{"role": "user", "content": f"""
Business logic test results from {len(results)} executed tests:
{json.dumps(results, indent=2)}

Which business rules were actually bypassed?"""}],
        )
        analysis_text = "".join(
            b.text for b in analysis_response.content if b.type == "text"
        )
        confirmed = json.loads(analysis_text)
        for f in confirmed:
            findings.append(f)
            if push_callback:
                push_callback(f)
    except Exception:
        pass

    return findings
