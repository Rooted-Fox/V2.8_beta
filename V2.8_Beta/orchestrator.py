"""VulnIQ Enhanced Scan Pipeline — The complete 8-phase autonomous testing engine.

Phase 0: Browser authentication + authenticated crawl (Playwright)
Phase 1: Pre-scan reasoning — Opus understands the application
Phase 2: Active scanning — 8 engines against authenticated endpoints
Phase 3: Iterative feedback loop — findings trigger follow-up probes
Phase 4: Business logic testing — inferred rule violation testing
Phase 5: Correlation — dedup + confidence scoring
Phase 6: Human approval gate
Phase 7: Opus full triage — CVSS, CWE, chains, remediation
Phase 8: Evaluated findings + reports

Progress weights (sum to 100):
  Browser crawl:      8%
  Reasoning agent:    5%
  ZAP spider:         7%
  ZAP active:        25%
  SQLMap:             8%
  Nuclei:             8%
  Nikto:              6%
  SSL:                4%
  FFuf:               5%
  Exposed paths:      3%
  NVD:                8%
  Feedback loop:      8%
  Business logic:     5%
"""
from __future__ import annotations

import concurrent.futures
import functools
import threading
from typing import Callable, List, Optional
from urllib.parse import urlparse

from models import RawFinding
from pending_store import PendingFindingsStore
from runtime_settings import get_settings
from scan_control import ScanControl
from scanners.base import ScannerNotInstalled
from scanners.exposed_paths import check_exposed_paths
from scanners.ffuf_scanner import run_ffuf
from scanners.nikto_scanner import run_nikto
from scanners.nuclei_scanner import run_nuclei
from scanners.nvd_scanner import run_nvd_scan
from scanners.sqlmap_scanner import run_sqlmap
from scanners.ssl_scanner import run_ssl_scan
from scanners.zap_scanner import ZapScanner

# New advanced scanners
from scanners.js_library_scanner import run_js_library_scan
from scanners.injection_scanner import run_injection_scan
from scanners.auth_scanner import run_auth_scan
from scanners.infrastructure_scanner import run_infrastructure_scan

_WEIGHTS = {
    "browser":      8,
    "reasoning":    4,
    "zap_spider":   6,
    "zap_active":  20,
    "sqlmap":       6,
    "nuclei":       6,
    "nikto":        4,
    "ssl":          3,
    "ffuf":         4,
    "exposed":      2,
    "nvd":          6,
    "js_library":   5,
    "injection":    5,
    "auth":         5,
    "infra":        5,
    "feedback":     6,
    "bizlogic":     5,
}


def _default_app_name(url: str) -> str:
    return urlparse(url).hostname or url


class Orchestrator:
    def __init__(self, target_urls: List[str], app_names: Optional[List[str]] = None,
                 scan_mode: str = "thorough",
                 credentials: Optional[dict] = None):
        """
        credentials: {"username": "...", "password": "...", "login_url": "..."}
        """
        self.target_urls = target_urls if isinstance(target_urls, list) else [target_urls]
        self.app_names = app_names or []
        self.scan_mode = scan_mode if scan_mode in ("fast", "thorough") else "thorough"
        self.credentials = credentials or {}
        self.pending_store = PendingFindingsStore()
        self.scanner_log: List[str] = []
        self.control = ScanControl()
        self._progress = 0
        self._progress_lock = threading.Lock()
        self._status_message = "Initialising..."
        self._current_app_name = ""
        self._test_plan = None
        self._crawl_result = None

    # ── control ─────────────────────────────────────────────
    def pause(self):
        self.control.request_pause()
        with self._progress_lock:
            self._status_message = "Paused"

    def resume(self):
        self.control.request_resume()
        with self._progress_lock:
            self._status_message = "Resuming..."

    def stop(self):
        self.control.request_stop()
        with self._progress_lock:
            self._status_message = "Stopping..."

    @property
    def is_paused(self):
        return self.control.pause_requested.is_set()

    # ── progress ─────────────────────────────────────────────
    @property
    def progress(self):
        with self._progress_lock:
            return self._progress

    @property
    def status_message(self):
        with self._progress_lock:
            return self._status_message

    def _advance(self, stage: str, message: str):
        weight = _WEIGHTS.get(stage, 0)
        with self._progress_lock:
            if message not in ("Paused", "Resuming..."):
                self._progress = min(100, self._progress + weight)
            self._status_message = message

    # ── live findings ─────────────────────────────────────────
    def _push_live(self, findings, fallback_url: str = ""):
        if not findings:
            return
        if isinstance(findings, dict):
            findings = [findings]
        processed = []
        for f in findings:
            if isinstance(f, RawFinding):
                f.app_name = self._current_app_name
                if not f.url and fallback_url:
                    f.url = fallback_url
                processed.append(f)
            elif isinstance(f, dict):
                # Convert dict findings from feedback loop / business logic
                raw = RawFinding(
                    tool=f.get("tool", "ai-agent"),
                    category=_infer_category_from_dict(f),
                    title=f.get("vulnerability_name", f.get("description", "Finding")),
                    url=f.get("url", fallback_url),
                    app_name=self._current_app_name,
                    raw_severity=f.get("raw_severity", f.get("severity", "medium")),
                    description=f.get("description", f.get("vulnerability_name", "")),
                    evidence=f.get("evidence", ""),
                )
                processed.append(raw)
        if get_settings()["skip_info_findings"]:
            processed = [f for f in processed
                         if (f.raw_severity or "").lower() != "info"]
        if processed:
            self.pending_store.save_many(processed)

    def _safe_run(self, fn, *args, stage: str, label: str) -> List[RawFinding]:
        if self.control.should_stop():
            return []
        try:
            return fn(*args)
        except ScannerNotInstalled as exc:
            self.scanner_log.append(f"[skip] {label}: {exc}")
            return []
        except Exception as exc:
            self.scanner_log.append(f"[error] {label}: {exc}")
            return []

    def _scan_one(self, target_url: str, app_name: str) -> List[RawFinding]:
        self._current_app_name = app_name
        all_findings: List[RawFinding] = []
        rt = get_settings()
        ai_enabled = rt.get("ai_enabled", False)

        # ── PHASE 0: Browser authentication + crawl ─────────
        crawl_result = None
        session_headers = {}
        if self.credentials.get("username") and self.credentials.get("password"):
            self._advance("browser", "Authenticating and crawling application...")
            try:
                from browser_agent import crawl_authenticated
                crawl_result = crawl_authenticated(
                    target_url=target_url,
                    username=self.credentials.get("username"),
                    password=self.credentials.get("password"),
                    login_url=self.credentials.get("login_url"),
                )
                self._crawl_result = crawl_result
                session_headers = crawl_result.session_headers or {}
                for log_line in crawl_result.log:
                    self.scanner_log.append(f"[browser] {log_line}")
                self.scanner_log.append(
                    f"[browser] Captured {len(crawl_result.endpoints)} authenticated endpoints"
                )
            except Exception as exc:
                self.scanner_log.append(f"[error] browser: {exc}")
                self._advance("browser", "Browser crawl skipped")
        else:
            self._advance("browser", "Scanning without authentication (no credentials provided)")

        if self.control.should_stop():
            return all_findings

        # ── PHASE 1: Pre-scan reasoning ─────────────────────
        test_plan = None
        if ai_enabled and crawl_result and crawl_result.endpoints:
            self._advance("reasoning", "Opus is analysing the application structure...")
            try:
                from reasoning_agent import generate_test_plan
                test_plan = generate_test_plan(crawl_result, target_url)
                self._test_plan = test_plan
                if test_plan and not test_plan.get("error"):
                    self.scanner_log.append(
                        f"[reasoning] Application identified as: {test_plan.get('app_type','unknown')}"
                    )
                    self.scanner_log.append(
                        f"[reasoning] {len(test_plan.get('likely_vulnerabilities',[]))} "
                        f"targeted vulnerability hypotheses generated"
                    )
                    if test_plan.get("open_reasoning_flags"):
                        self.scanner_log.append(
                            f"[reasoning] Open reasoning flags: "
                            f"{len(test_plan['open_reasoning_flags'])} unusual observations"
                        )
            except Exception as exc:
                self.scanner_log.append(f"[error] reasoning: {exc}")
        else:
            self._advance("reasoning", "Pre-scan reasoning skipped (requires AI + authenticated crawl)")

        if self.control.should_stop():
            return all_findings

        # ── PHASE 2: Active scanning ─────────────────────────
        self._advance("zap_spider", "Crawling application structure...")
        zap = ZapScanner(target_url, scan_mode=self.scan_mode)
        try:
            zap_findings = zap.scan(
                progress_callback=self._zap_cb,
                control=self.control,
                findings_callback=lambda fs: self._push_live(fs, fallback_url=target_url),
            )
            all_findings.extend(zap_findings)
        except ScannerNotInstalled as exc:
            self.scanner_log.append(f"[skip] zap: {exc}")
        except Exception as exc:
            self.scanner_log.append(f"[error] zap: {exc}")

        if self.control.should_stop():
            return all_findings

        sqlmap_fn = functools.partial(run_sqlmap, scan_mode=self.scan_mode,
                                      control=self.control)
        nikto_fn  = functools.partial(run_nikto,  control=self.control)
        ffuf_fn   = functools.partial(run_ffuf,   control=self.control)

        # Wrap new scanners to pass crawl context when available
        crawl_endpoints = [ep.get("url","") for ep in
                           (crawl_result.endpoints if crawl_result else [])]
        crawl_forms = (crawl_result.forms if crawl_result else [])
        auth_headers = (crawl_result.session_headers if crawl_result else {})

        inject_fn = functools.partial(run_injection_scan,
                                      endpoints=crawl_endpoints,
                                      forms=crawl_forms)
        auth_fn   = functools.partial(run_auth_scan, auth_headers=auth_headers)

        parallel  = [
            ("sqlmap",     sqlmap_fn,           target_url, "sqlmap",     "Deep SQL injection testing..."),
            ("nuclei",     run_nuclei,           target_url, "nuclei",     "CVE template scanning..."),
            ("nikto",      nikto_fn,             target_url, "nikto",      "Server analysis..."),
            ("ssl",        run_ssl_scan,         target_url, "ssl",        "Cryptographic analysis..."),
            ("ffuf",       ffuf_fn,              target_url, "ffuf",       "Endpoint discovery..."),
            ("exposed",    check_exposed_paths,  target_url, "exposed",    "Sensitive file detection..."),
            ("nvd",        run_nvd_scan,         target_url, "nvd",        "Historic CVE lookup..."),
            ("js_library", run_js_library_scan,  target_url, "js_library", "JavaScript library CVE scan..."),
            ("injection",  inject_fn,            target_url, "injection",  "SSTI, NoSQL, XXE, secret detection..."),
            ("auth",       auth_fn,              target_url, "auth",       "JWT, session, auth flaw testing..."),
            ("infra",      run_infrastructure_scan, target_url, "infra",   "Cache poisoning, SSRF, GraphQL, CORS..."),
        ]

        def _run_parallel(item):
            stage, fn, url, label, msg = item
            if self.control.pause_requested.is_set():
                self.control.wait_while_paused()
            results = self._safe_run(fn, url, stage=stage, label=label)
            self._push_live(results, fallback_url=url)
            self._advance(stage, msg)
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=11) as executor:
            futures = {executor.submit(_run_parallel, item): item for item in parallel}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    all_findings.extend(fut.result())
                except Exception:
                    pass

        if self.control.should_stop():
            return all_findings

        # ── PHASE 3: Iterative feedback loop ─────────────────
        if ai_enabled and all_findings:
            self._advance("feedback", "Running iterative AI feedback loop...")
            try:
                import requests as _requests
                from feedback_loop import run_feedback_loop
                loop_session = _requests.Session()
                if session_headers:
                    loop_session.headers.update(session_headers)

                # Run feedback loop on top high-severity findings
                high_sev = [f for f in all_findings
                            if (f.raw_severity or "").lower() in ("critical", "high")][:5]
                for finding in high_sev:
                    if self.control.should_stop():
                        break
                    extra = run_feedback_loop(
                        initial_finding={
                            "vulnerability_name": finding.title,
                            "url": finding.url,
                            "description": finding.description,
                            "evidence": finding.evidence,
                            "severity": finding.raw_severity,
                        },
                        session=loop_session,
                        app_context=crawl_result.app_context if crawl_result else "",
                        base_headers=session_headers,
                        max_iterations=2,
                        max_probes_total=6,
                        push_callback=lambda f: self._push_live(f, fallback_url=target_url),
                    )
                    all_findings.extend([
                        RawFinding(
                            tool=f.get("tool","feedback-loop"),
                            category=_infer_category_from_dict(f),
                            title=f.get("vulnerability_name","Finding"),
                            url=f.get("url", target_url),
                            app_name=app_name,
                            raw_severity=f.get("raw_severity", f.get("severity","medium")),
                            description=f.get("description",""),
                            evidence=f.get("evidence",""),
                        ) for f in extra
                    ])
                self.scanner_log.append(f"[feedback] Feedback loop complete")
            except Exception as exc:
                self.scanner_log.append(f"[error] feedback loop: {exc}")
        else:
            self._advance("feedback", "Feedback loop skipped (requires AI enabled)")

        # ── PHASE 4: Business logic testing ──────────────────
        if ai_enabled and test_plan and not test_plan.get("error"):
            self._advance("bizlogic", "Testing business logic rules...")
            try:
                import requests as _requests
                from business_logic_agent import run_business_logic_tests
                biz_session = _requests.Session()
                if session_headers:
                    biz_session.headers.update(session_headers)
                biz_findings = run_business_logic_tests(
                    test_plan=test_plan,
                    session=biz_session,
                    base_headers=session_headers,
                    push_callback=lambda f: self._push_live(f, fallback_url=target_url),
                )
                for f in biz_findings:
                    all_findings.append(RawFinding(
                        tool=f.get("tool","business-logic"),
                        category=_infer_category_from_dict(f),
                        title=f.get("vulnerability_name","Business Logic Finding"),
                        url=f.get("url", target_url),
                        app_name=app_name,
                        raw_severity=f.get("raw_severity", f.get("severity","high")),
                        description=f.get("description",""),
                        evidence=f.get("evidence",""),
                    ))
                self.scanner_log.append(
                    f"[bizlogic] {len(biz_findings)} business logic findings"
                )
            except Exception as exc:
                self.scanner_log.append(f"[error] business logic: {exc}")
        else:
            self._advance("bizlogic", "Business logic testing skipped (requires AI + test plan)")

        return all_findings

    def _zap_cb(self, stage: str):
        if stage == "spider_done":
            self._advance("zap_spider", "Crawl complete — active scanning...")
        elif stage == "active_done":
            self._advance("zap_active", "Active scan complete...")
        elif stage == "paused":
            with self._progress_lock:
                self._status_message = "Paused"
        elif stage == "resumed":
            with self._progress_lock:
                self._status_message = "Resuming..."

    def scan(self) -> List[RawFinding]:
        all_findings: List[RawFinding] = []
        for i, url in enumerate(self.target_urls):
            if self.control.should_stop():
                break
            app_name = (
                self.app_names[i] if i < len(self.app_names) else None
            ) or _default_app_name(url)
            with self._progress_lock:
                self._progress = 0
                self._status_message = f"Starting assessment of {app_name}..."
            findings = self._scan_one(url, app_name)
            all_findings.extend(findings)

        with self._progress_lock:
            self._progress = 100
            self._status_message = "Stopped" if self.control.should_stop() else "Assessment complete"
        return all_findings


def _infer_category_from_dict(f: dict):
    """Map a finding dict to the nearest OWASP category."""
    from models import OwaspCategory
    cat_str = (f.get("category") or f.get("owasp_api") or "").lower()
    mapping = {
        "business logic": OwaspCategory.A06_INSECURE_DESIGN,
        "bola": OwaspCategory.A01_ACCESS_CONTROL,
        "idor": OwaspCategory.A01_ACCESS_CONTROL,
        "injection": OwaspCategory.A05_INJECTION,
        "auth": OwaspCategory.A07_AUTH_FAILURES,
        "crypto": OwaspCategory.A04_CRYPTO_FAILURES,
        "misconfig": OwaspCategory.A02_MISCONFIGURATION,
        "supply": OwaspCategory.A03_SUPPLY_CHAIN,
        "integrity": OwaspCategory.A08_INTEGRITY_FAILURES,
        "logging": OwaspCategory.A09_LOGGING_FAILURES,
    }
    for keyword, category in mapping.items():
        if keyword in cat_str:
            return category
    return OwaspCategory.A06_INSECURE_DESIGN
