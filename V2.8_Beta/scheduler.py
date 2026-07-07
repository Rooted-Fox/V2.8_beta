"""Cron-based scheduled scanning engine."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

_SCHEDULE_FILE = Path(__file__).parent / "scheduled_scans.json"
_lock = threading.Lock()


def _load() -> list:
    if _SCHEDULE_FILE.exists():
        try:
            return json.loads(_SCHEDULE_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return []


def _save(schedules: list) -> None:
    _SCHEDULE_FILE.write_text(json.dumps(schedules, indent=2))


def list_schedules() -> list:
    with _lock:
        return _load()


def add_schedule(target_url: str, app_name: Optional[str], cron_expr: str,
                 enabled: bool = True) -> dict:
    import uuid
    schedule = {
        "id": str(uuid.uuid4())[:8],
        "target_url": target_url,
        "app_name": app_name or "",
        "cron": cron_expr,
        "enabled": enabled,
        "last_run": None,
        "next_run": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        schedules = _load()
        schedules.append(schedule)
        _save(schedules)
    _start_scheduler()
    return schedule


def delete_schedule(schedule_id: str) -> bool:
    with _lock:
        schedules = _load()
        new = [s for s in schedules if s["id"] != schedule_id]
        if len(new) == len(schedules):
            return False
        _save(new)
        return True


def toggle_schedule(schedule_id: str, enabled: bool) -> bool:
    with _lock:
        schedules = _load()
        for s in schedules:
            if s["id"] == schedule_id:
                s["enabled"] = enabled
                _save(schedules)
                return True
        return False


_scheduler_thread: Optional[threading.Thread] = None
_scheduler_running = False


def _start_scheduler() -> None:
    global _scheduler_thread, _scheduler_running
    if _scheduler_running:
        return
    _scheduler_running = True

    def _run():
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
        except ImportError:
            return  # apscheduler not installed, skip

        scheduler = BackgroundScheduler()
        scheduler.start()
        _sync_jobs(scheduler)

        import time
        while _scheduler_running:
            _sync_jobs(scheduler)
            time.sleep(60)
        scheduler.shutdown()

    _scheduler_thread = threading.Thread(target=_run, daemon=True)
    _scheduler_thread.start()


def _sync_jobs(scheduler) -> None:
    """Remove all existing jobs and recreate from the current schedule file."""
    from apscheduler.triggers.cron import CronTrigger
    import scan_runner

    scheduler.remove_all_jobs()
    for s in _load():
        if not s.get("enabled"):
            continue
        try:
            trigger = CronTrigger.from_crontab(s["cron"])
            scheduler.add_job(
                scan_runner.start_scan,
                trigger=trigger,
                id=s["id"],
                kwargs={"target_url": s["target_url"], "app_name": s["app_name"] or None},
                replace_existing=True,
            )
        except Exception:
            continue
