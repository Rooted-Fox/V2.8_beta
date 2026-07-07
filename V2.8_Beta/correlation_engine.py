"""Finding Correlation Engine.

Before any findings reach the AI triage queue, this engine:
  1. Groups raw findings that represent the same underlying vulnerability
     (same category + similar URL + similar title).
  2. Merges each group into a single consolidated finding with a confidence
     score derived from how many independent scanners agree.
  3. Assigns an initial ValidationStatus based on confidence.

Confidence formula:
  - 1 source  → 30%  → POTENTIAL
  - 2 sources → 60%  → LIKELY
  - 3 sources → 80%  → LIKELY
  - 4+ sources→ 95%  → CONFIRMED (pre-triage)

This dramatically reduces noise and false-positive volume reaching Opus,
and means a finding that sqlmap, ZAP, and nuclei all flag independently
arrives at the agent already marked CONFIRMED with high confidence,
rather than as three separate items.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import List, Tuple

from models import RawFinding, ValidationStatus


def _normalise_url(url: Optional[str]) -> str:
    if not url:
        return ""
    url = re.sub(r"\d+", "N", url)   # replace IDs: /orders/123 → /orders/N
    url = re.sub(r"\?.*", "", url)    # strip query string
    return url.lower().rstrip("/")


def _title_sim(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _confidence(source_count: int, tools: List[str]) -> Tuple[int, ValidationStatus]:
    score = min(95, 30 + (source_count - 1) * 22)
    # bonus for "heavyweight" confirmation from sqlmap or nuclei CVE match
    if any(t in ("sqlmap", "nuclei") for t in tools):
        score = min(98, score + 10)
    if score >= 80:
        status = ValidationStatus.CONFIRMED
    elif score >= 50:
        status = ValidationStatus.LIKELY
    else:
        status = ValidationStatus.POTENTIAL
    return score, status


def correlate(raw_findings: List[RawFinding]) -> List[RawFinding]:
    """Merge duplicates and annotate each survivor with confidence metadata.

    Returns a deduplicated list where each RawFinding has been augmented
    with two extra attributes:
      - _confidence (int 0-100)
      - _validation_status (ValidationStatus)
      - _source_count (int)
      - _tools (list of tool names that found it)

    The triage queue stores these; they survive into TriagedFinding.
    """
    if not raw_findings:
        return []

    groups: List[List[RawFinding]] = []

    for finding in raw_findings:
        placed = False
        for group in groups:
            rep = group[0]
            # same OWASP category is required
            if rep.category != finding.category:
                continue
            # similar URL (after normalisation)
            url_match = (_normalise_url(rep.url) == _normalise_url(finding.url))
            # similar title (>= 60% match OR one is a substring of the other)
            title_match = (_title_sim(rep.title, finding.title) >= 0.60 or
                           rep.title.lower() in finding.title.lower() or
                           finding.title.lower() in rep.title.lower())
            if url_match and title_match:
                group.append(finding)
                placed = True
                break
        if not placed:
            groups.append([finding])

    merged: List[RawFinding] = []
    for group in groups:
        # pick the finding with the most evidence as the representative
        rep = max(group, key=lambda f: len(f.evidence) + len(f.description))
        tools = list({f.tool for f in group})
        source_count = len(tools)

        # consolidate evidence from all sources
        extra_evidence = "\n\n".join(
            f"[{f.tool}] {f.evidence}" for f in group if f != rep and f.evidence
        )
        if extra_evidence:
            rep = rep.model_copy(update={"evidence": rep.evidence + "\n\n" + extra_evidence})

        confidence, vstatus = _confidence(source_count, tools)

        # attach metadata as dynamic attributes (picked up by triage_runner)
        rep._confidence = confidence
        rep._validation_status = vstatus
        rep._source_count = source_count
        rep._tools = tools
        # every pending-queue row id in this merged group, so the caller can
        # delete the whole group from the queue once - and only once - the
        # merged finding has actually been saved as a TriagedFinding
        rep._source_ids = [f.id for f in group if f.id is not None]
        merged.append(rep)

    return merged


# make Optional importable at module level (used in _normalise_url)
from typing import Optional
