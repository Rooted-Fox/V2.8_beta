"""Attack Chain Detection Engine.

After AI triage completes, this engine reads all confirmed/likely findings
for an application and asks Claude to identify multi-step attack paths —
the kind of chains that let an attacker escalate from a low finding to a
full compromise.

Runs as a single Claude call against the full findings list, not per-
finding, so it can reason about relationships across the whole attack
surface in one pass.
"""
from __future__ import annotations

import json
from typing import List, Optional

import anthropic

from models import AttackChain, TriagedFinding
from runtime_settings import get_settings
from agents.agent import _build_client

_SYSTEM = """You are a senior penetration tester and threat modeler.

You will receive a list of validated security findings for a single application.
Your job is to identify multi-step attack chains — sequences of vulnerabilities
that an attacker could chain together to achieve a higher-impact outcome than
any single finding alone.

For each chain:
- Think like an attacker: what is the most damaging path through these findings?
- Be concrete about the steps, preconditions, and what each step enables.
- Focus on chains that lead to data exfiltration, account takeover, RCE,
  privilege escalation, or full system compromise.
- Do not invent vulnerabilities not in the list.
- Only include chains where at least 2 findings are directly linked.

Respond with a JSON array only, no prose, no markdown fences.
Each object in the array must match this schema exactly:
{
  "chain_name": "descriptive name, e.g. IDOR → Account Takeover",
  "risk_score": 9.5,
  "exploitation_difficulty": "easy|medium|hard",
  "preconditions": "what the attacker needs before starting",
  "attack_flow": "Step 1: ... Step 2: ... Step 3: ...",
  "business_impact": "what a successful attack achieves",
  "mitigations": "specific fixes that break this chain",
  "finding_ids": [1, 2, 3]
}

If no meaningful chains exist, return an empty array: []
"""


def _finding_summary(f: TriagedFinding) -> str:
    return (
        f"ID {f.id}: [{f.severity.value.upper()}] {f.vulnerability_name or f.rationale[:80]}\n"
        f"  URL: {f.url}\n"
        f"  CWE: {f.cwe_id} {f.cwe_name}\n"
        f"  CVSS: {f.cvss_score}\n"
        f"  Exploitable: {f.exploitable}\n"
        f"  Impact: {(f.technical_impact or '')[:150]}"
    )


def detect_chains(findings: List[TriagedFinding], app_name: str) -> List[AttackChain]:
    # Only correlate findings that have real exploitability evidence
    candidates = [f for f in findings if f.exploitable or f.confidence >= 60]
    if len(candidates) < 2:
        return []

    rt = get_settings()
    client = _build_client(rt)
    model = rt["agent_model"]

    summaries = "\n\n".join(_finding_summary(f) for f in candidates)
    user_message = (
        f"Application: {app_name}\n"
        f"Total findings provided: {len(candidates)}\n\n"
        f"Findings:\n{summaries}\n\n"
        f"Identify attack chains across these findings."
    )

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=_SYSTEM,
            messages=[{"role": "user", "content": user_message}],
        )
        text = "".join(b.text for b in response.content if b.type == "text")
        parsed = json.loads(text)
    except Exception:
        return []

    chains: List[AttackChain] = []
    for item in parsed:
        try:
            chains.append(AttackChain(
                app_name=app_name,
                chain_name=item.get("chain_name", "Unnamed chain"),
                risk_score=float(item.get("risk_score", 5.0)),
                exploitation_difficulty=item.get("exploitation_difficulty", "medium"),
                preconditions=item.get("preconditions", ""),
                attack_flow=item.get("attack_flow", ""),
                business_impact=item.get("business_impact", ""),
                mitigations=item.get("mitigations", ""),
                finding_ids=item.get("finding_ids", []),
            ))
        except Exception:
            continue
    return chains
