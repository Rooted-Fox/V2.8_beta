"""Approval-gated AI triage: correlation → batched agent triage → attack chains.

Critical safety property: a finding is only ever removed from the pending
queue AFTER it has been successfully saved as a TriagedFinding. If an Opus
call fails partway through (bad key, network error, wrong endpoint), every
finding not yet successfully processed stays exactly where it was in the
pending queue - nothing is lost, and you can see exactly what failed.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable, Optional

from agents.agent import MAX_BATCH_SIZE, OwaspAgent, TriageBatchError
from attack_chain_engine import detect_chains
from correlation_engine import correlate
from models import RemediationStatus, TriagedFinding, ValidationStatus
from notifier import notify_new_critical_findings
from pending_store import PendingFindingsStore
from runtime_settings import get_settings
from store import FindingsStore
from token_store import TokenStore


class TokenBudgetExceeded(RuntimeError):
    pass


class AIIntegrationDisabled(RuntimeError):
    pass


def triage_app(app_name: Optional[str], token_limit: Optional[int],
               progress_callback: Optional[Callable[[int, int, str], None]] = None) -> dict:
    if not get_settings()["ai_enabled"]:
        raise AIIntegrationDisabled(
            "Opus/AI integration is off. Enable it on the Settings tab before approving triage."
        )

    pending_store = PendingFindingsStore()
    token_store = TokenStore()
    store = FindingsStore()

    if not token_store.has_budget(token_limit):
        raise TokenBudgetExceeded(
            f"Token budget ({token_limit}) already reached. Raise the limit or reset in Settings."
        )

    # Read pending findings WITHOUT deleting them yet.
    raw_findings = pending_store.peek_for_triage(app_name=app_name)
    correlated = correlate(raw_findings)

    by_category = defaultdict(list)
    for finding in correlated:
        by_category[finding.category].append(finding)

    total_batches = sum(
        -(-len(findings) // MAX_BATCH_SIZE) for findings in by_category.values()
    )
    batches_done = 0

    triaged: list[TriagedFinding] = []
    batch_errors: list[str] = []
    stopped_early = False

    for category, findings in by_category.items():
        if stopped_early:
            break
        try:
            agent = OwaspAgent(category)
        except Exception as exc:
            # Most likely cause: bad/missing API key or endpoint - this is
            # exactly the failure mode that used to silently wipe findings.
            batch_errors.append(f"{category.value}: could not start agent — {exc}")
            continue

        for i in range(0, len(findings), MAX_BATCH_SIZE):
            if not token_store.has_budget(token_limit):
                stopped_early = True
                break

            chunk = findings[i: i + MAX_BATCH_SIZE]
            if progress_callback:
                progress_callback(batches_done, total_batches, category.value)

            try:
                results, usage = agent.triage_batch(chunk)
                token_store.record(category.value, usage["input_tokens"], usage["output_tokens"])
            except TriageBatchError as exc:
                # The API call genuinely happened and was billed, even
                # though parsing failed afterward - record what was
                # actually spent so the token meter and budget stay accurate.
                token_store.record(category.value, exc.usage["input_tokens"], exc.usage["output_tokens"])
                batch_errors.append(f"{category.value} batch ({len(chunk)} findings): {exc}")
                batches_done += 1
                continue
            except Exception as exc:
                # This finding's batch failed. Its rows stay in the pending
                # queue exactly as they were - nothing is deleted, nothing
                # is lost. The error is surfaced so it's visible, not silent.
                batch_errors.append(f"{category.value} batch ({len(chunk)} findings): {exc}")
                batches_done += 1
                continue

            for finding, result in zip(chunk, results):
                finding_id = store.save(result)
                result.id = finding_id
                triaged.append(result)

            # Only now - after a confirmed successful save - remove these
            # specific rows from the pending queue.
            ids_to_delete = []
            for finding in chunk:
                ids_to_delete.extend(getattr(finding, "_source_ids", []) or
                                     ([finding.id] if finding.id else []))
            pending_store.delete_ids(ids_to_delete)

            batches_done += 1
            if progress_callback:
                progress_callback(batches_done, total_batches, category.value)

        if stopped_early:
            break

    # Attack chain detection - only runs over what was actually triaged
    chain_count = 0
    if triaged and not stopped_early:
        target_app = app_name or (triaged[0].app_name if triaged else "unspecified")
        try:
            store.delete_chains_for_app(target_app)
            chains = detect_chains(triaged, target_app)
            for chain in chains:
                store.save_chain(chain)
            chain_count = len(chains)
        except Exception as exc:
            batch_errors.append(f"Attack chain detection: {exc}")

    notify_new_critical_findings(triaged)

    return {
        "triaged_count": len(triaged),
        "correlated_from": len(raw_findings),
        "dedup_removed": len(raw_findings) - len(correlated),
        "chain_count": chain_count,
        "remaining_pending": len(pending_store.pending(app_name=app_name)),
        "stopped_early": stopped_early,
        "tokens_used_total": token_store.total_used(),
        "batch_errors": batch_errors,
    }
