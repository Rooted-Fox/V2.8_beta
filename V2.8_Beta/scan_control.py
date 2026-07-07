"""Shared control object for pausing, resuming, and stopping a running scan.

Pause/resume on subprocess-based scanners (sqlmap, nikto, ffuf) uses real
POSIX process signals (SIGSTOP/SIGCONT) on the actual child process - the
process genuinely freezes, not just "we stop polling it". ZAP gets paused
and resumed through its own native pause/resume API instead, since it's a
long-running daemon, not a child process we spawn per scan.

Stop terminates any running subprocess immediately and tells ZAP to stop
its current spider/active-scan job, then the orchestrator checks
should_stop() between every remaining stage so nothing new starts.
"""
from __future__ import annotations

import signal
import subprocess
import threading
import time
from typing import List


class ScanControl:
    def __init__(self):
        self.stop_requested = threading.Event()
        self.pause_requested = threading.Event()
        self._processes: List[subprocess.Popen] = []
        self._lock = threading.Lock()

    # ---- process registration (subprocess-based scanners) ----

    def register_process(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._processes.append(proc)
            # if a pause was already requested before this process started,
            # apply it immediately so nothing slips through unpaused
            if self.pause_requested.is_set():
                try:
                    proc.send_signal(signal.SIGSTOP)
                except Exception:
                    pass

    def unregister_process(self, proc: subprocess.Popen) -> None:
        with self._lock:
            if proc in self._processes:
                self._processes.remove(proc)

    # ---- control actions, called from the API/scan_runner ----

    def request_pause(self) -> None:
        self.pause_requested.set()
        with self._lock:
            for p in self._processes:
                if p.poll() is None:  # still running
                    try:
                        p.send_signal(signal.SIGSTOP)
                    except Exception:
                        pass

    def request_resume(self) -> None:
        self.pause_requested.clear()
        with self._lock:
            for p in self._processes:
                if p.poll() is None:
                    try:
                        p.send_signal(signal.SIGCONT)
                    except Exception:
                        pass

    def request_stop(self) -> None:
        self.stop_requested.set()
        self.pause_requested.clear()  # don't leave anything frozen on the way out
        with self._lock:
            for p in self._processes:
                if p.poll() is None:
                    try:
                        p.terminate()
                    except Exception:
                        pass

    # ---- checks used inside scanner loops ----

    def should_stop(self) -> bool:
        return self.stop_requested.is_set()

    def wait_while_paused(self, poll_interval: float = 1.0) -> bool:
        """Blocks while a pause is active. Returns False if a stop came in
        while waiting, True if it's fine to continue."""
        while self.pause_requested.is_set() and not self.stop_requested.is_set():
            time.sleep(poll_interval)
        return not self.stop_requested.is_set()


def run_controlled_subprocess(args: list, control=None, timeout: int = 600,
                              poll_interval: float = 0.5) -> subprocess.CompletedProcess:
    """Runs a subprocess the same way subprocess.run() would, but registers
    it with ScanControl so pause (SIGSTOP/SIGCONT) and stop (terminate)
    actually reach the real child process - not just a "we'll stop polling
    it" simulation. Always returns a CompletedProcess-like result, even if
    the process was stopped or timed out, so callers can keep their
    existing partial-output parsing logic unchanged.
    """
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if control:
        control.register_process(proc)

    start = time.time()
    try:
        while True:
            if proc.poll() is not None:
                break
            if control and control.stop_requested.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            if time.time() - start > timeout:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            time.sleep(poll_interval)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, Exception):
            stdout, stderr = "", ""
    except Exception:
        stdout, stderr = "", ""
    finally:
        if control:
            control.unregister_process(proc)

    return subprocess.CompletedProcess(args, proc.returncode if proc.returncode is not None else 0,
                                       stdout or "", stderr or "")
