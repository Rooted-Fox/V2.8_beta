"""OWASP ZAP DAST scanner — pause/resume/stop via ZAP's native API,
and live alert streaming so findings appear during the scan, not after."""
from __future__ import annotations

import time
from typing import Callable, List, Optional

import requests

from models import OwaspCategory, RawFinding
from runtime_settings import get_settings
from scan_control import ScanControl
from scanners.base import BaseScanner

_RISK_TO_SEV = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
_AJAX_MAX_SEC = 120
_ACTIVE_SCAN_MAX_SEC = {"fast": 480, "thorough": 1800}
_ALERT_POLL_SEC = 8  # how often we check for new alerts during active scan, for live streaming

_ALERT_KEYWORDS = {
    OwaspCategory.A01_ACCESS_CONTROL: ["access control","path traversal","directory traversal","idor","privilege"],
    OwaspCategory.A02_MISCONFIGURATION: ["misconfiguration","default credential","server leaks","x-content-type","x-frame-options","content security policy","hsts","clickjacking","information disclosure","directory listing","debug"],
    OwaspCategory.A03_SUPPLY_CHAIN: ["vulnerable js library","retire.js","outdated library","sri","subresource integrity"],
    OwaspCategory.A04_CRYPTO_FAILURES: ["tls","ssl","certificate","weak cipher","plaintext","secure flag","mixed content","rc4","des","md5","sha1"],
    OwaspCategory.A05_INJECTION: ["sql injection","cross site scripting","xss","command injection","ldap injection","nosql injection","template injection","ssti","code injection"],
    OwaspCategory.A06_INSECURE_DESIGN: ["business logic","rate limit","brute force","account enumeration"],
    OwaspCategory.A07_AUTH_FAILURES: ["authentication","session fixation","session","jwt","credential","login","password"],
    OwaspCategory.A08_INTEGRITY_FAILURES: ["deserialization","integrity","unsigned","object injection"],
    OwaspCategory.A09_LOGGING_FAILURES: ["logging","monitoring","audit"],
    OwaspCategory.A10_EXCEPTIONAL: ["denial of service","dos","resource exhaustion","stack trace","exception","error handling","crash","redos","server side request forgery","ssrf"],
}


def _infer_category(alert_name: str) -> OwaspCategory:
    lowered = alert_name.lower()
    for category, keywords in _ALERT_KEYWORDS.items():
        if any(kw in lowered for kw in keywords):
            return category
    return OwaspCategory.A02_MISCONFIGURATION


def _alert_to_finding(alert: dict, evidence: str) -> RawFinding:
    return RawFinding(
        tool="dast",
        category=_infer_category(alert.get("alert", "")),
        title=alert.get("alert", "security finding"),
        url=alert.get("url"),
        raw_severity=_RISK_TO_SEV.get(alert.get("risk"), "low"),
        description=alert.get("description", ""),
        evidence=evidence,
    )


class ZapScanner(BaseScanner):
    def __init__(self, target_url: str, scan_mode: str = "thorough"):
        self.target_url = target_url
        self.scan_mode = scan_mode if scan_mode in _ACTIVE_SCAN_MAX_SEC else "thorough"
        rt = get_settings()
        self.base = rt["zap_api_url"]
        self.params = {"apikey": rt["zap_api_key"]}
        self._seen_alert_ids: set = set()

    def _get(self, path: str, timeout: int = 30, _retries: int = 3, **extra):
        """ZAP occasionally drops a connection mid-request when it's busy
        running an active scan while also fielding our status/alert polls -
        that's a transient hiccup, not a real failure, so retry a couple of
        times with a short backoff before actually giving up."""
        last_exc = None
        for attempt in range(_retries):
            try:
                r = requests.get(f"{self.base}{path}", params={**self.params, **extra},
                                 timeout=timeout)
                r.raise_for_status()
                return r.json()
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.ChunkedEncodingError) as exc:
                last_exc = exc
                if attempt < _retries - 1:
                    time.sleep(1.5 * (attempt + 1))  # 1.5s, 3s
                    continue
                raise
        raise last_exc  # pragma: no cover — defensive, loop always returns or raises above

    def _get_lenient(self, path: str, timeout: int = 30, **extra) -> Optional[dict]:
        """Same as _get, but for non-critical calls (e.g. a single alert
        poll tick) where a failure shouldn't abort the whole scan - it
        just skips that one poll and the next one will catch up."""
        try:
            return self._get(path, timeout=timeout, **extra)
        except requests.RequestException:
            return None

    def _message_context(self, msg_id: Optional[str]) -> str:
        if not msg_id:
            return ""
        try:
            msg = self._get("/JSON/core/view/message/", id=msg_id, timeout=10).get("message", {})
        except requests.RequestException:
            return ""
        req = f"{msg.get('requestHeader','')}\n{msg.get('requestBody','')}"
        res = f"{msg.get('responseHeader','')}\n{msg.get('responseBody','')}"
        return f"--- request ---\n{req}\n--- response ---\n{res}"[:3000]

    def _maximize_thoroughness(self) -> None:
        strength = "HIGH" if self.scan_mode == "thorough" else "MEDIUM"
        try:
            self._get("/JSON/ascan/action/setPolicyAttackStrength/",
                      scanPolicyName="Default Policy", attackStrength=strength)
            self._get("/JSON/ascan/action/setPolicyAlertThreshold/",
                      scanPolicyName="Default Policy", alertThreshold="LOW")
        except requests.RequestException:
            pass

    def _fetch_new_alerts(self, findings_callback: Optional[Callable[[List[RawFinding]], None]]) -> None:
        """Pulls current alerts from ZAP and pushes only the ones we haven't
        seen yet through findings_callback - this is what makes findings
        show up live during the active scan instead of only at the end."""
        if not findings_callback:
            return
        try:
            alerts = self._get("/JSON/core/view/alerts/", baseurl=self.target_url,
                               timeout=20).get("alerts", [])
        except requests.RequestException:
            return
        new_findings = []
        for alert in alerts:
            alert_id = alert.get("id") or f"{alert.get('alert')}|{alert.get('url')}"
            if alert_id in self._seen_alert_ids:
                continue
            self._seen_alert_ids.add(alert_id)
            evidence = self._message_context(alert.get("messageId")) or alert.get("evidence", "")
            new_findings.append(_alert_to_finding(alert, evidence))
        if new_findings:
            findings_callback(new_findings)

    def _ajax_spider(self, control: Optional[ScanControl]) -> None:
        try:
            self._get("/JSON/ajaxSpider/action/scan/", url=self.target_url)
        except requests.RequestException:
            return
        deadline = time.time() + _AJAX_MAX_SEC
        while True:
            if control and control.should_stop():
                try: self._get("/JSON/ajaxSpider/action/stop/")
                except requests.RequestException: pass
                return
            if control and control.pause_requested.is_set():
                if not control.wait_while_paused():
                    try: self._get("/JSON/ajaxSpider/action/stop/")
                    except requests.RequestException: pass
                    return
            try:
                status = self._get("/JSON/ajaxSpider/view/status/", timeout=10).get("status")
            except requests.RequestException:
                return
            if status != "running":
                return
            if time.time() > deadline:
                try: self._get("/JSON/ajaxSpider/action/stop/")
                except requests.RequestException: pass
                return
            time.sleep(2)

    def scan(self, progress_callback: Optional[Callable[[str], None]] = None,
             control: Optional[ScanControl] = None,
             findings_callback: Optional[Callable[[List[RawFinding]], None]] = None) -> List[RawFinding]:
        """findings_callback, if given, is called with newly-discovered
        alerts AS THEY APPEAR during the scan (live), not just once at the
        end. The full return value still contains everything found, for
        callers that don't need live updates."""
        self._maximize_thoroughness()

        # Classic spider
        self._get("/JSON/spider/action/scan/", url=self.target_url, timeout=30)
        while int(self._get("/JSON/spider/view/status/", timeout=10)["status"]) < 100:
            if control and control.should_stop():
                try: self._get("/JSON/spider/action/stop/")
                except requests.RequestException: pass
                break
            if control and control.pause_requested.is_set():
                try: self._get("/JSON/spider/action/pause/")
                except requests.RequestException: pass
                if not control.wait_while_paused():
                    try: self._get("/JSON/spider/action/stop/")
                    except requests.RequestException: pass
                    break
                try: self._get("/JSON/spider/action/resume/")
                except requests.RequestException: pass
            time.sleep(2)

        if not (control and control.should_stop()):
            self._ajax_spider(control)

        if progress_callback:
            progress_callback("spider_done")

        if control and control.should_stop():
            self._fetch_new_alerts(findings_callback)
            return self._collect_all_alerts()

        # Active scan — bounded, pausable, stoppable, with live alert polling
        scan_id = self._get("/JSON/ascan/action/scan/", url=self.target_url, timeout=30)["scan"]
        deadline = time.time() + _ACTIVE_SCAN_MAX_SEC[self.scan_mode]
        last_alert_check = time.time()

        while int(self._get("/JSON/ascan/view/status/", scanId=scan_id, timeout=10)["status"]) < 100:
            if control and control.should_stop():
                try: self._get("/JSON/ascan/action/stop/", scanId=scan_id)
                except requests.RequestException: pass
                break
            if control and control.pause_requested.is_set():
                try: self._get("/JSON/ascan/action/pause/", scanId=scan_id)
                except requests.RequestException: pass
                if progress_callback:
                    progress_callback("paused")
                if not control.wait_while_paused():
                    try: self._get("/JSON/ascan/action/stop/", scanId=scan_id)
                    except requests.RequestException: pass
                    break
                try: self._get("/JSON/ascan/action/resume/", scanId=scan_id)
                except requests.RequestException: pass
                if progress_callback:
                    progress_callback("resumed")
            if time.time() > deadline:
                try: self._get("/JSON/ascan/action/stop/", scanId=scan_id)
                except requests.RequestException: pass
                break
            if time.time() - last_alert_check > _ALERT_POLL_SEC:
                self._fetch_new_alerts(findings_callback)
                last_alert_check = time.time()
            time.sleep(4)

        if progress_callback:
            progress_callback("active_done")

        # Final sweep — catches anything found in the last poll window
        self._fetch_new_alerts(findings_callback)
        return self._collect_all_alerts()

    def _collect_all_alerts(self) -> List[RawFinding]:
        alerts = self._get("/JSON/core/view/alerts/", baseurl=self.target_url,
                           timeout=30).get("alerts", [])
        findings: List[RawFinding] = []
        for alert in alerts:
            evidence = self._message_context(alert.get("messageId")) or alert.get("evidence", "")
            findings.append(_alert_to_finding(alert, evidence))
        return findings
