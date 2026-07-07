"""LangGraph iterative feedback loop — the core of autonomous testing.

When a finding is discovered, Opus immediately reasons about it and
generates follow-up probes. Those probes execute and return results.
Opus decides what to test next. The loop continues until coverage is
exhausted or a depth limit is reached.

This is what turns VulnIQ from AI-assisted into AI-autonomous.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import requests

from agents.agent import _build_client
from runtime_settings import get_settings

_FOLLOWUP_SYSTEM = """You are an autonomous penetration tester mid-engagement.

You have just discovered a security finding. Your job is to immediately reason about
what this finding enables and design follow-up probes to:
1. Confirm the finding more definitively
2. Determine the full extent of impact
3. Discover related vulnerabilities this finding may chain into
4. Test adjacent endpoints, parameters, and variations
5. Identify the full attack path this could be part of

Think like an experienced attacker who has just found something interesting and wants
to understand exactly how far it goes.

Respond with a JSON object:
{
  "assessment": "what this finding means and what it enables",
  "follow_up_probes": [
    {
      "description": "what this probe tests",
      "method": "GET|POST|PUT|DELETE|PATCH",
      "url": "exact URL to request",
      "headers": {"Header": "value"},
      "body": null or {"field": "value"},
      "expected_evidence": "what a positive result looks like"
    }
  ],
  "chain_hypothesis": "what larger attack this might be part of",
  "stop_reason": null or "why no further testing is needed"
}

Maximum 5 follow-up probes per iteration. If nothing meaningful to test further, set
stop_reason and return empty follow_up_probes.
"""

_UA = "Mozilla/5.0 (compatible; VulnIQ-Security-Scanner/2.0)"


def _execute_probe(probe: dict, session: requests.Session,
                   base_headers: dict = None) -> Optional[dict]:
    """Execute one follow-up probe and return the result."""
    headers = {**{"User-Agent": _UA}, **(base_headers or {}), **(probe.get("headers") or {})}
    try:
        body = probe.get("body")
        resp = session.request(
            method=probe.get("method", "GET"),
            url=probe["url"],
            headers=headers,
            json=body if body else None,
            timeout=10,
            allow_redirects=True,
        )
        return {
            "url": probe["url"],
            "method": probe.get("method", "GET"),
            "status_code": resp.status_code,
            "response_length": len(resp.text),
            "response_headers": dict(resp.headers),
            "response_snippet": resp.text[:500],
            "description": probe.get("description", ""),
        }
    except Exception as e:
        return {"url": probe.get("url", ""), "error": str(e)}


def run_feedback_loop(
    initial_finding: dict,
    session: requests.Session,
    app_context: str = "",
    base_headers: dict = None,
    max_iterations: int = 3,
    max_probes_total: int = 10,
    push_callback: Optional[Callable[[dict], None]] = None,
) -> List[dict]:
    """Run the iterative feedback loop on a finding.

    Returns a list of additional findings discovered through the loop.
    """
    rt = get_settings()
    if not rt.get("ai_enabled"):
        return []

    try:
        client = _build_client(rt)
        model = rt["agent_model"]
    except Exception:
        return []

    additional_findings = []
    probes_fired = 0
    current_finding = initial_finding

    for iteration in range(max_iterations):
        if probes_fired >= max_probes_total:
            break

        # Ask Opus what to test next based on this finding
        user_content = f"""Application context: {app_context}

Current finding:
{json.dumps(current_finding, indent=2)}

Previously discovered additional findings this iteration:
{json.dumps(additional_findings[-3:], indent=2) if additional_findings else "None yet"}

What should be tested next? Generate follow-up probes."""

        try:
            response = client.messages.create(
                model=model,
                max_tokens=2048,
                system=_FOLLOWUP_SYSTEM,
                messages=[{"role": "user", "content": user_content}],
            )
            text = "".join(b.text for b in response.content if b.type == "text")
            plan = json.loads(text)
        except Exception:
            break

        # If Opus says stop, we stop
        if plan.get("stop_reason"):
            break

        probes = plan.get("follow_up_probes", [])
        if not probes:
            break

        # Execute each probe
        iteration_results = []
        for probe in probes[:5]:
            if probes_fired >= max_probes_total:
                break
            result = _execute_probe(probe, session, base_headers)
            if result:
                iteration_results.append(result)
                probes_fired += 1
                time.sleep(0.3)  # polite pacing

        if not iteration_results:
            break

        # Ask Opus to reason about what the probe results mean
        try:
            analysis_response = client.messages.create(
                model=model,
                max_tokens=2048,
                system="""You are a penetration tester analysing probe results.
For each probe result, determine if it confirms a vulnerability, reveals new information,
or shows nothing interesting. Return a JSON array of findings, one per confirmed issue:
{
  "vulnerability_name": "descriptive name",
  "url": "affected URL",
  "method": "HTTP method",
  "severity": "critical|high|medium|low",
  "evidence": "what in the response confirms this",
  "description": "what was found",
  "raw_severity": "high",
  "tool": "feedback-loop-agent",
  "category": "OWASP category or 'Beyond OWASP'"
}
Return [] if probes reveal nothing significant.""",
                messages=[{"role": "user", "content": f"""
Original finding: {json.dumps(current_finding, indent=2)}
Chain hypothesis: {plan.get('chain_hypothesis', '')}

Probe results:
{json.dumps(iteration_results, indent=2)}

What did these probes reveal?"""}],
            )
            analysis_text = "".join(
                b.text for b in analysis_response.content if b.type == "text"
            )
            new_findings = json.loads(analysis_text)
            for f in new_findings:
                additional_findings.append(f)
                if push_callback:
                    push_callback(f)
                # Update current finding for next iteration
                if f.get("severity") in ("critical", "high"):
                    current_finding = f

        except Exception:
            break

    return additional_findings
