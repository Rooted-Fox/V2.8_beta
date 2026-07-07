"""OWASP API Top 10 security tests.

Each test function takes an ApiEndpoint and a requests.Session and returns
a list of raw API findings. All tests are evidence-based — they don't flag
theoretical risks, they flag actual observable HTTP response behaviours.
"""
from __future__ import annotations

import copy
import json
import random
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from api_scanner.curl_parser import ApiEndpoint

_UA = "Mozilla/5.0 (compatible; VulnIQ-API-Scanner/1.0)"
_TIMEOUT = 10


def _req(session: requests.Session, method: str, url: str,
         headers: dict = None, body: Any = None, **kwargs) -> Optional[requests.Response]:
    try:
        h = {**{"User-Agent": _UA}, **(headers or {})}
        if body is not None:
            return session.request(method, url, json=body, headers=h,
                                   timeout=_TIMEOUT, allow_redirects=True, **kwargs)
        return session.request(method, url, headers=h,
                               timeout=_TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException:
        return None


def _finding(ep: ApiEndpoint, vuln_type: str, owasp_cat: str,
             severity: str, evidence: str, parameter: str = "N/A",
             request_repr: str = "", response_repr: str = "") -> dict:
    return {
        "tool": "api-security-scanner",
        "owasp_api": owasp_cat,
        "vulnerability_name": vuln_type,
        "url": ep.url,
        "method": ep.method,
        "raw_severity": severity,
        "parameter": parameter,
        "evidence": evidence,
        "request": request_repr[:1000],
        "response": response_repr[:1000],
        "description": f"{vuln_type} detected on {ep.method} {ep.path}",
    }


# ─── API1: BOLA (Broken Object Level Authorization) ─────────────────────────

def test_bola(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    if not ep.path_params and not any(
        re.search(r'/\d+', ep.path) for _ in [1]
    ):
        return findings

    # Try substituting different numeric IDs
    test_ids = ["1", "2", "999999", "0", "-1"]
    for test_id in test_ids:
        # Replace first numeric segment in path
        test_path = re.sub(r'/\d+', f'/{test_id}', ep.url, count=1)
        if test_path == ep.url:
            continue
        resp = _req(session, "GET", test_path, headers=ep.headers)
        if resp and resp.status_code == 200 and len(resp.text) > 50:
            if test_id != re.search(r'/(\d+)', ep.url).group(1):
                findings.append(_finding(
                    ep, "BOLA — Broken Object Level Authorization",
                    "API1:2023 BOLA", "high",
                    f"GET {test_path} returned HTTP 200 with {len(resp.text)} bytes. "
                    f"Object ID substitution was not rejected, suggesting authorization "
                    f"checks are not validating object ownership.",
                    parameter="id (path parameter)",
                    request_repr=f"GET {test_path}",
                    response_repr=resp.text[:300],
                ))
            break
    return findings


# ─── API2: Broken Authentication ─────────────────────────────────────────────

_JWT_NONE_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none","typ":"JWT"}

def test_broken_auth(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    auth_val = ep.headers.get("Authorization", ep.headers.get("authorization", ""))

    # Test 1: no auth at all
    headers_no_auth = {k: v for k, v in ep.headers.items()
                       if k.lower() != "authorization"}
    resp_no_auth = _req(session, ep.method, ep.url, headers=headers_no_auth, body=ep.body)
    if resp_no_auth and resp_no_auth.status_code == 200 and len(resp_no_auth.text) > 50:
        findings.append(_finding(
            ep, "Missing Authentication — endpoint accessible without credentials",
            "API2:2023 Broken Authentication", "critical",
            f"Request to {ep.method} {ep.url} without any Authorization header "
            f"returned HTTP 200 with {len(resp_no_auth.text)} bytes of content.",
            parameter="Authorization header",
            request_repr=f"{ep.method} {ep.url} (no auth header)",
            response_repr=resp_no_auth.text[:300],
        ))

    # Test 2: JWT algorithm confusion (none algorithm)
    if auth_val.lower().startswith("bearer ") and auth_val.count(".") >= 2:
        parts = auth_val[7:].split(".")
        if len(parts) == 3:
            # Build a JWT with alg:none — just header.payload. (no signature)
            none_jwt = f"{_JWT_NONE_HEADER}.{parts[1]}."
            headers_none = {**ep.headers, "Authorization": f"Bearer {none_jwt}"}
            resp_none = _req(session, ep.method, ep.url, headers=headers_none, body=ep.body)
            if resp_none and resp_none.status_code == 200:
                findings.append(_finding(
                    ep, "JWT Algorithm Confusion — 'none' algorithm accepted",
                    "API2:2023 Broken Authentication", "critical",
                    "Server accepted a JWT with alg:none (no signature verification). "
                    "An attacker can forge tokens without knowing the secret key.",
                    parameter="Authorization: Bearer (JWT)",
                    request_repr=f"{ep.method} {ep.url} with alg:none JWT",
                    response_repr=resp_none.text[:300],
                ))

    return findings


# ─── API3: Excessive Data Exposure ───────────────────────────────────────────

_SENSITIVE_PATTERNS = [
    (r'(?i)"password"\s*:\s*"[^"]+"', "password field"),
    (r'(?i)"passwd"\s*:\s*"[^"]+"', "passwd field"),
    (r'(?i)"secret"\s*:\s*"[^"]+"', "secret field"),
    (r'(?i)"token"\s*:\s*"[^"]+"', "token field"),
    (r'(?i)"api_key"\s*:\s*"[^"]+"', "api_key field"),
    (r'(?i)"ssn"\s*:\s*"[^"]+"', "SSN field"),
    (r'(?i)"credit_card"\s*:\s*"[^"]+"', "credit card field"),
    (r'(?i)"cvv"\s*:\s*"[^"]+"', "CVV field"),
    (r'(?i)"private_key"\s*:\s*"[^"]+"', "private key"),
    (r'\b[0-9]{16}\b', "possible credit card number"),
    (r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b', "possible SSN"),
]

def test_excessive_data_exposure(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    resp = _req(session, ep.method, ep.url, headers=ep.headers, body=ep.body)
    if not resp or resp.status_code != 200:
        return findings
    body = resp.text
    for pattern, label in _SENSITIVE_PATTERNS:
        m = re.search(pattern, body)
        if m:
            findings.append(_finding(
                ep, f"Excessive Data Exposure — {label} in API response",
                "API3:2023 Excessive Data Exposure", "high",
                f"API response contains a {label} field that should not be returned "
                f"to clients. Matched pattern: {m.group()[:80]}",
                parameter="response body",
                request_repr=f"{ep.method} {ep.url}",
                response_repr=body[:300],
            ))
    return findings


# ─── API4: Lack of Resource & Rate Limiting ───────────────────────────────────

def test_rate_limiting(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    # Only test endpoints that look like auth or sensitive operations
    sensitive_paths = ["login","auth","token","password","register","signup","forgot"]
    if not any(s in ep.path.lower() for s in sensitive_paths):
        return findings

    # Send 15 rapid requests and check if any throttling kicks in
    results = []
    for _ in range(15):
        resp = _req(session, ep.method, ep.url, headers=ep.headers, body=ep.body)
        if resp:
            results.append(resp.status_code)

    throttled = any(s in [429, 503, 403] for s in results)
    if not throttled and len(results) >= 10:
        findings.append(_finding(
            ep, "Lack of Rate Limiting on sensitive endpoint",
            "API4:2023 Lack of Resource & Rate Limiting", "high",
            f"Sent 15 rapid requests to {ep.method} {ep.path}. "
            f"All returned: {set(results)}. No 429 Too Many Requests or "
            f"throttling response observed — brute force and credential stuffing are possible.",
            parameter="N/A — endpoint-level",
            request_repr=f"{ep.method} {ep.url} × 15",
            response_repr=f"Status codes: {results}",
        ))
    return findings


# ─── API5: Function Level Authorization ──────────────────────────────────────

_ADMIN_PATTERNS = ["admin","manage","management","superuser","root",
                   "internal","config","configuration","settings","system"]
_HTTP_METHODS = ["GET","POST","PUT","PATCH","DELETE"]

def test_function_level_auth(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []

    # Test 1: admin path access
    if any(p in ep.path.lower() for p in _ADMIN_PATTERNS):
        resp = _req(session, ep.method, ep.url, headers=ep.headers, body=ep.body)
        if resp and resp.status_code == 200 and len(resp.text) > 50:
            findings.append(_finding(
                ep, "Broken Function Level Authorization — admin endpoint accessible",
                "API5:2023 Function Level Authorization", "critical",
                f"Admin/privileged endpoint {ep.method} {ep.path} returned HTTP 200. "
                f"If this is accessible with regular user credentials, it constitutes "
                f"a function-level authorization bypass.",
                parameter="endpoint path",
                request_repr=f"{ep.method} {ep.url}",
                response_repr=resp.text[:300],
            ))

    # Test 2: HTTP method switching (e.g. GET works → try DELETE)
    if ep.method == "GET":
        for method in ["DELETE", "PUT"]:
            resp = _req(session, method, ep.url, headers=ep.headers)
            if resp and resp.status_code not in [405, 404, 403]:
                findings.append(_finding(
                    ep, f"HTTP Method Switching — {method} not rejected on GET endpoint",
                    "API5:2023 Function Level Authorization", "medium",
                    f"{method} {ep.url} returned HTTP {resp.status_code} instead of 405 Method Not Allowed. "
                    f"Unintended methods may expose destructive operations.",
                    parameter=f"HTTP method",
                    request_repr=f"{method} {ep.url}",
                    response_repr=resp.text[:200],
                ))
    return findings


# ─── API6: Mass Assignment ───────────────────────────────────────────────────

_PRIVILEGED_FIELDS = ["isAdmin","is_admin","admin","role","roles","permissions",
                       "price","cost","amount","discount","balance","credit",
                       "verified","active","enabled","confirmed","approved",
                       "user_id","userId","owner_id","account_type","plan"]

def test_mass_assignment(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    if ep.method not in ("POST", "PUT", "PATCH") or not ep.body:
        return findings

    # Get baseline response
    baseline = _req(session, ep.method, ep.url, headers=ep.headers, body=ep.body)
    if not baseline:
        return findings

    # Inject privileged fields into the body
    evil_body = {**ep.body}
    for field in _PRIVILEGED_FIELDS:
        evil_body[field] = True if "admin" in field.lower() or "is_" in field else 0

    resp = _req(session, ep.method, ep.url, headers=ep.headers, body=evil_body)
    if not resp:
        return findings

    # If extra fields don't cause an error (400 Bad Request), server may accept them
    if resp.status_code == baseline.status_code and resp.status_code in [200, 201, 204]:
        # Check if any injected fields appear in response (confirms acceptance)
        accepted = [f for f in _PRIVILEGED_FIELDS if f in resp.text or f in (resp.json() or {}) if hasattr(resp, "json")]
        findings.append(_finding(
            ep, "Mass Assignment — privileged fields not filtered from request body",
            "API6:2023 Mass Assignment", "high",
            f"Adding fields {_PRIVILEGED_FIELDS[:5]} to the request body did not cause "
            f"a 400 error (got HTTP {resp.status_code}). Server may silently accept "
            f"and apply privileged field modifications.",
            parameter="request body (extra fields)",
            request_repr=f"{ep.method} {ep.url} body: {json.dumps(evil_body)[:200]}",
            response_repr=resp.text[:200],
        ))
    return findings


# ─── API7: SSRF ──────────────────────────────────────────────────────────────

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://127.0.0.1:80",
    "http://localhost",
    "http://[::1]",
]

def test_ssrf(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    url_params = {k for k, v in (ep.body or {}).items()
                  if isinstance(v, str) and ("url" in k.lower() or "uri" in k.lower()
                                             or "link" in k.lower() or "href" in k.lower()
                                             or "callback" in k.lower())}
    url_params |= {k for k in ep.query_params
                   if "url" in k.lower() or "uri" in k.lower()}
    if not url_params:
        return findings

    for param in list(url_params)[:3]:
        for payload in _SSRF_PAYLOADS[:2]:
            if ep.body and param in ep.body:
                test_body = {**ep.body, param: payload}
                resp = _req(session, ep.method, ep.url, headers=ep.headers, body=test_body)
            else:
                from urllib.parse import urlencode
                test_url = f"{ep.url}?{param}={payload}"
                resp = _req(session, ep.method, test_url, headers=ep.headers)
            if resp and resp.status_code not in [400, 422] and (
                "169.254" in resp.text or "ami-id" in resp.text or
                "instance-id" in resp.text or resp.status_code == 200
            ):
                findings.append(_finding(
                    ep, "SSRF — Server-Side Request Forgery via URL parameter",
                    "API7:2023 SSRF", "critical",
                    f"Parameter '{param}' accepted URL payload '{payload}'. "
                    f"Response was HTTP {resp.status_code} — server may have "
                    f"fetched the internal URL.",
                    parameter=param,
                    request_repr=f"{ep.method} {ep.url} with {param}={payload}",
                    response_repr=resp.text[:300],
                ))
    return findings


# ─── API8: Injection via JSON body ───────────────────────────────────────────

_NOSQL_PAYLOADS = [{"$gt": ""}, {"$where": "1==1"}, {"$regex": ".*"}]
_SQLI_PAYLOADS  = ["'", "' OR '1'='1", "'; DROP TABLE users--", "1 AND 1=1"]
_SQL_ERRORS = ["sql syntax","mysql_fetch","ORA-","SQLSTATE","sqlite3","pg_query"]

def test_injection(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    if not ep.body or not isinstance(ep.body, dict):
        return findings

    string_fields = [k for k, v in ep.body.items() if isinstance(v, str)]
    for field in string_fields[:5]:
        # NoSQL injection
        for payload in _NOSQL_PAYLOADS:
            test_body = {**ep.body, field: payload}
            resp = _req(session, ep.method, ep.url, headers=ep.headers, body=test_body)
            if resp and resp.status_code in [200, 201] and len(resp.text) > 100:
                findings.append(_finding(
                    ep, f"NoSQL Injection in '{field}' field",
                    "API8:2023 Security Misconfiguration (Injection)", "critical",
                    f"NoSQL operator payload {payload} in field '{field}' returned "
                    f"HTTP {resp.status_code} with {len(resp.text)} bytes — query "
                    f"may have been manipulated.",
                    parameter=field,
                    request_repr=f"{ep.method} {ep.url} body: {json.dumps(test_body)[:200]}",
                    response_repr=resp.text[:200],
                ))
                break  # one finding per field is enough

        # SQLi in JSON body
        for payload in _SQLI_PAYLOADS[:2]:
            test_body = {**ep.body, field: payload}
            resp = _req(session, ep.method, ep.url, headers=ep.headers, body=test_body)
            if resp:
                if any(err in resp.text.lower() for err in _SQL_ERRORS):
                    findings.append(_finding(
                        ep, f"SQL Injection in '{field}' field (JSON body)",
                        "API8:2023 Security Misconfiguration (Injection)", "critical",
                        f"SQL error in response after injecting payload '{payload}' "
                        f"into JSON field '{field}'.",
                        parameter=field,
                        request_repr=f"{ep.method} {ep.url} body: {json.dumps(test_body)[:200]}",
                        response_repr=resp.text[:300],
                    ))
                    break

    return findings


# ─── API9: Improper Assets Management ────────────────────────────────────────

def test_improper_assets(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    findings = []
    base = ep.base_url

    # Check for older API versions
    version_match = re.search(r'/v(\d+)/', ep.path or ep.url)
    if not version_match:
        return findings
    current_ver = int(version_match.group(1))

    for old_ver in range(max(1, current_ver - 3), current_ver):
        old_path = ep.path.replace(f"/v{current_ver}/", f"/v{old_ver}/")
        old_url = f"{base}{old_path}"
        resp = _req(session, ep.method, old_url, headers=ep.headers, body=ep.body)
        if resp and resp.status_code == 200 and len(resp.text) > 50:
            findings.append(_finding(
                ep, f"Improper Assets Management — deprecated API v{old_ver} still active",
                "API9:2023 Improper Assets Management", "high",
                f"Older API version endpoint {ep.method} {old_url} returned "
                f"HTTP 200 with {len(resp.text)} bytes. Deprecated API versions "
                f"often lack current security controls and patches.",
                parameter="API version in path",
                request_repr=f"{ep.method} {old_url}",
                response_repr=resp.text[:200],
            ))
    return findings


# ─── API10: Unsafe API Consumption (Third-party) ─────────────────────────────

def test_unsafe_consumption(ep: ApiEndpoint, session: requests.Session) -> List[dict]:
    """Checks for security headers and CORS misconfiguration."""
    findings = []
    resp = _req(session, ep.method, ep.url, headers={
        **ep.headers,
        "Origin": "https://evil.com",
    }, body=ep.body)
    if not resp:
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append(_finding(
            ep, "CORS Misconfiguration — wildcard origin with credentials",
            "API10:2023 Unsafe API Consumption", "high",
            "API returns Access-Control-Allow-Origin: * combined with "
            "Access-Control-Allow-Credentials: true. Any website can make "
            "credentialed requests to this API on behalf of a user.",
            parameter="CORS headers",
            request_repr=f"{ep.method} {ep.url} with Origin: https://evil.com",
            response_repr=f"ACAO: {acao}, ACAC: {acac}",
        ))

    if acao == "https://evil.com":
        findings.append(_finding(
            ep, "CORS Misconfiguration — arbitrary origin reflected",
            "API10:2023 Unsafe API Consumption", "high",
            "API reflects the attacker-controlled Origin header value back in "
            "Access-Control-Allow-Origin. Any domain can read the API response.",
            parameter="CORS headers",
            request_repr=f"{ep.method} {ep.url} with Origin: https://evil.com",
            response_repr=f"ACAO: {acao}",
        ))
    return findings


# ─── Main: run all tests on a list of endpoints ──────────────────────────────

_ALL_TESTS = [
    test_bola,
    test_broken_auth,
    test_excessive_data_exposure,
    test_rate_limiting,
    test_function_level_auth,
    test_mass_assignment,
    test_ssrf,
    test_injection,
    test_improper_assets,
    test_unsafe_consumption,
]


def scan_endpoints(endpoints: list, push_callback=None) -> List[dict]:
    """Run all OWASP API Top 10 tests against a list of ApiEndpoint objects.
    push_callback, if given, is called with each new finding immediately
    as it's discovered — this is what makes findings appear live."""
    session = requests.Session()
    session.headers["User-Agent"] = _UA
    all_findings = []

    for ep in endpoints:
        for test_fn in _ALL_TESTS:
            try:
                results = test_fn(ep, session)
                for f in results:
                    all_findings.append(f)
                    if push_callback:
                        push_callback(f)
            except Exception:
                continue
            time.sleep(0.2)  # polite pacing between tests

    return all_findings
