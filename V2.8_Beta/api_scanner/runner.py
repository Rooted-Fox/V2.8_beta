"""API scan runner — orchestrates discovery, testing, and storage."""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Callable, List, Optional

from api_scanner.api_tester import scan_endpoints
from api_scanner.curl_parser import parse_curls
from api_scanner.domain_discovery import discover_apis
from api_scanner.file_parser import parse_file

_state = {
    "running": False,
    "mode": None,          # "curl" | "file" | "domain"
    "target": None,
    "started_at": None,
    "finished_at": None,
    "progress_pct": 0,
    "status_message": "idle",
    "last_error": None,
    "raw_findings": [],
    "validated_findings": [],
    "endpoints_found": 0,
    "discovery_log": [],
}
_lock = threading.Lock()
_raw_findings_store: List[dict] = []    # pre-triage
_validated_findings_store: List[dict] = []  # post-opus


def status() -> dict:
    with _lock:
        return {**_state,
                "raw_count": len(_raw_findings_store),
                "validated_count": len(_validated_findings_store)}


def get_raw_findings() -> List[dict]:
    return list(_raw_findings_store)


def get_validated_findings() -> List[dict]:
    return list(_validated_findings_store)


def clear_findings() -> None:
    _raw_findings_store.clear()
    _validated_findings_store.clear()


def start_api_scan(mode: str, payload: str, filename: str = "",
                   push_callback: Optional[Callable] = None) -> bool:
    """Start an API scan.
    mode: "curl" | "file" | "domain"
    payload: curl text / file content / domain or URL string
    """
    with _lock:
        if _state["running"]:
            return False
        _state.update(
            running=True,
            mode=mode,
            target=payload[:100],
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
            progress_pct=0,
            status_message="Starting API discovery...",
            last_error=None,
            discovery_log=[],
        )

    def _run():
        try:
            # Step 1: discovery / parsing
            with _lock:
                _state["status_message"] = "Discovering API endpoints..."
                _state["progress_pct"] = 10

            endpoints = []
            spec_content = None

            if mode == "curl":
                endpoints = parse_curls(payload)
                with _lock:
                    _state["discovery_log"].append(f"Parsed {len(endpoints)} curl commands")
            elif mode == "file":
                endpoints = parse_file(payload, filename)
                with _lock:
                    _state["discovery_log"].append(f"Parsed {len(endpoints)} endpoints from file")
            elif mode == "domain":
                result = discover_apis(payload)
                endpoints = result["endpoints"]
                with _lock:
                    _state["discovery_log"].extend(result["log"])
                    if result.get("spec_content"):
                        spec_content = result["spec_content"]

            with _lock:
                _state["endpoints_found"] = len(endpoints)
                _state["progress_pct"] = 25
                _state["status_message"] = f"Testing {len(endpoints)} endpoints..."

            # Step 2: security testing — findings pushed live via callback
            def _live_push(finding):
                _raw_findings_store.append(finding)
                if push_callback:
                    push_callback(finding)

            raw = scan_endpoints(endpoints, push_callback=_live_push)

            with _lock:
                _state["progress_pct"] = 85
                _state["status_message"] = f"Found {len(raw)} raw findings. Awaiting Opus approval."

        except Exception as exc:
            with _lock:
                _state["last_error"] = str(exc)
        finally:
            with _lock:
                _state["running"] = False
                _state["finished_at"] = datetime.now(timezone.utc).isoformat()
                _state["progress_pct"] = 100
                _state["status_message"] = "Scan complete — approve Opus analysis to validate findings"

    threading.Thread(target=_run, daemon=True).start()
    return True


def approve_api_triage() -> dict:
    """Run Opus triage on the current raw API findings."""
    from api_scanner.api_agent import triage_api_findings
    raw = get_raw_findings()
    if not raw:
        return {"error": "No raw API findings to triage"}
    validated = triage_api_findings(raw)
    _validated_findings_store.clear()
    _validated_findings_store.extend(validated)
    return {
        "raw_count": len(raw),
        "validated_count": len(validated),
        "false_positives_removed": len(raw) - len(validated),
    }
