"""Background-thread wrapper around triage_runner.triage_app() — exposes
live progress (X of Y batches done) so the UI can show real percentage
during AI triage instead of going silent until it's finished."""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

from triage_runner import AIIntegrationDisabled, TokenBudgetExceeded, triage_app

_state = {
    "running": False,
    "app_name": None,
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_result": None,
    "progress_pct": 0,
    "batches_done": 0,
    "batches_total": 0,
    "current_category": None,
}
_lock = threading.Lock()


def status() -> dict:
    with _lock:
        return dict(_state)


def start_triage(app_name: Optional[str], token_limit: Optional[int]) -> bool:
    with _lock:
        if _state["running"]:
            return False
        _state.update(
            running=True,
            app_name=app_name,
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            last_error=None,
            last_result=None,
            progress_pct=0,
            batches_done=0,
            batches_total=0,
            current_category=None,
        )

    def _on_progress(done: int, total: int, category: str) -> None:
        with _lock:
            _state["batches_done"] = done
            _state["batches_total"] = total
            _state["current_category"] = category
            _state["progress_pct"] = int((done / total) * 100) if total else 0

    def _run() -> None:
        try:
            result = triage_app(app_name=app_name, token_limit=token_limit,
                                progress_callback=_on_progress)
            with _lock:
                _state["last_result"] = result
                _state["progress_pct"] = 100
                # batch_errors is informational, not fatal - surface it
                # even on an otherwise-successful run
                if result.get("batch_errors"):
                    _state["last_error"] = (
                        f"{len(result['batch_errors'])} batch(es) had errors and were "
                        f"left in the pending queue for retry: " +
                        " | ".join(result["batch_errors"][:3])
                    )
        except (TokenBudgetExceeded, AIIntegrationDisabled) as exc:
            with _lock:
                _state["last_error"] = str(exc)
        except Exception as exc:
            with _lock:
                _state["last_error"] = (
                    f"Triage failed: {exc}. Findings remain safely in the pending "
                    f"queue — nothing was lost. Check Settings → Test Opus connection."
                )
        finally:
            with _lock:
                _state["running"] = False
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()

    threading.Thread(target=_run, daemon=True).start()
    return True
