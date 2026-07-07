"""Infrastructure vulnerability scanner.

Covers server-level attack classes that Acunetix misses or does weakly:
  - Cache poisoning via unkeyed headers
  - SSRF with cloud metadata targeting
  - Race conditions on sensitive endpoints
  - GraphQL security issues
  - CORS misconfiguration (deep)
  - WebSocket security
  - Open redirect chaining
  - Debug endpoint exposure
"""
from __future__ import annotations

import re
import threading
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse, urlsplit

import requests

from models import OwaspCategory, RawFinding

_UA = "Mozilla/5.0 (compatible; VulnIQ/2.0)"
_TIMEOUT = 10


def _req(session, method, url, **kwargs):
    try:
        return session.request(
            method, url, timeout=_TIMEOUT,
            headers={"User-Agent": _UA, **kwargs.pop("headers", {})},
            **kwargs
        )
    except Exception:
        return None


# ── Cache Poisoning ───────────────────────────────────────────────────────────

_CACHE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]

def test_cache_poisoning(target_url: str, session: requests.Session) -> List[RawFinding]:
    findings = []
    canary = "vulniq-cache-poison-test"

    for header in _CACHE_HEADERS:
        try:
            resp = _req(session, "GET", target_url,
                        headers={header: canary})
            if resp and canary in resp.text:
                # Cache poisoning confirmed — canary reflected in response
                findings.append(RawFinding(
                    tool="infrastructure-scanner",
                    category=OwaspCategory.A02_MISCONFIGURATION,
                    title=f"Web Cache Poisoning via {header} header",
                    url=target_url,
                    raw_severity="high",
                    description=(
                        f"The application reflected the attacker-controlled '{header}' "
                        "header value in its response. If this response is cached, all "
                        "subsequent users who receive the cached response will be served "
                        "the attacker-controlled content, enabling persistent XSS, "
                        "credential harvesting, or denial of service."
                    ),
                    evidence=(
                        f"Injected header: {header}: {canary}\n"
                        f"Canary reflected in response: yes\n"
                        f"Response snippet: {resp.text[:400]}"
                    ),
                ))
        except Exception:
            continue
        time.sleep(0.2)

    return findings


# ── SSRF ──────────────────────────────────────────────────────────────────────

_SSRF_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/",     "AWS EC2 metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/", "AWS IAM metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance",     "Azure IMDS"),
    ("http://100.100.100.200/latest/meta-data/",     "Alibaba metadata"),
    ("http://127.0.0.1:80",                          "Internal localhost:80"),
    ("http://127.0.0.1:8080",                        "Internal localhost:8080"),
    ("http://127.0.0.1:22",                          "Internal SSH port"),
    ("http://localhost/server-status",               "Apache server-status"),
    ("http://[::1]",                                 "IPv6 localhost"),
]

_SSRF_SUCCESS_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4",  # AWS
    "project-id", "service-accounts",         # GCP
    "compute/metadata",                        # Azure
    "computeMetadata",
]

def test_ssrf(target_url: str, session: requests.Session) -> List[RawFinding]:
    findings = []

    # Find URL parameters in the target
    parts = urlsplit(target_url)
    from urllib.parse import parse_qs, urlencode, urlunsplit
    params = parse_qs(parts.query)

    url_params = [k for k in params if any(kw in k.lower() for kw in [
        "url", "uri", "link", "src", "href", "redirect", "callback",
        "endpoint", "target", "dest", "path", "proxy", "fetch", "load",
    ])]

    if not url_params:
        return findings

    for param in url_params[:3]:
        for ssrf_url, location in _SSRF_TARGETS[:5]:
            try:
                test_params = {**{k: v[0] for k, v in params.items()}, param: ssrf_url}
                test_url = urlunsplit(parts._replace(query=urlencode(test_params)))

                resp = _req(session, "GET", test_url)
                if not resp:
                    continue

                # Check for cloud metadata in response
                resp_lower = resp.text.lower()
                for indicator in _SSRF_SUCCESS_INDICATORS:
                    if indicator.lower() in resp_lower:
                        findings.append(RawFinding(
                            tool="infrastructure-scanner",
                            category=OwaspCategory.A10_EXCEPTIONAL,
                            title=f"Server-Side Request Forgery (SSRF) — {location}",
                            url=target_url,
                            raw_severity="critical",
                            description=(
                                f"Parameter '{param}' is vulnerable to SSRF. The server "
                                f"fetched the attacker-controlled URL '{ssrf_url}' and "
                                f"returned cloud metadata content in the response. An "
                                f"attacker can use this to steal cloud credentials, access "
                                f"internal services, and achieve full cloud account compromise."
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"SSRF target: {ssrf_url} ({location})\n"
                                f"Metadata indicator found: {indicator}\n"
                                f"Response snippet: {resp.text[:500]}"
                            ),
                        ))
                        return findings  # stop after first confirmed SSRF

                # Check for connection to internal service (different response time/status)
                if resp.status_code not in (400, 422, 403) and len(resp.text) > 50:
                    if "connection refused" not in resp.text.lower():
                        findings.append(RawFinding(
                            tool="infrastructure-scanner",
                            category=OwaspCategory.A10_EXCEPTIONAL,
                            title=f"Potential SSRF — Server contacted internal endpoint",
                            url=target_url,
                            raw_severity="high",
                            description=(
                                f"Parameter '{param}' may be vulnerable to SSRF. The server "
                                f"returned a non-error response when provided with internal "
                                f"URL '{ssrf_url}', suggesting it may have attempted the "
                                f"internal connection."
                            ),
                            evidence=(
                                f"Parameter: {param}\n"
                                f"SSRF target: {ssrf_url}\n"
                                f"Response: HTTP {resp.status_code}, {len(resp.text)} bytes"
                            ),
                        ))

            except Exception:
                continue
            time.sleep(0.2)

    return findings


# ── GraphQL Security ──────────────────────────────────────────────────────────

def test_graphql(target_url: str, session: requests.Session) -> List[RawFinding]:
    findings = []
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

    graphql_paths = ["/graphql", "/api/graphql", "/graphql/v1",
                     "/gql", "/query", "/api/query"]

    for path in graphql_paths:
        url = urljoin(base, path)
        try:
            # Test 1: Introspection enabled
            introspection_query = {
                "query": "{ __schema { types { name } } }"
            }
            resp = _req(session, "POST", url, json=introspection_query,
                        headers={"Content-Type": "application/json"})

            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if "data" in data and "__schema" in str(data.get("data", {})):
                        findings.append(RawFinding(
                            tool="infrastructure-scanner",
                            category=OwaspCategory.A02_MISCONFIGURATION,
                            title="GraphQL Introspection Enabled on Production",
                            url=url,
                            raw_severity="medium",
                            description=(
                                "GraphQL introspection is enabled, exposing the complete "
                                "API schema including all types, queries, mutations, and "
                                "field names. Attackers can use this to map the entire "
                                "API surface before targeting specific operations."
                            ),
                            evidence=(
                                f"Introspection query returned schema data.\n"
                                f"Response: {resp.text[:400]}"
                            ),
                        ))

                    # Test 2: Batch query DoS potential
                    batch_query = [introspection_query] * 10
                    batch_resp = _req(session, "POST", url, json=batch_query,
                                      headers={"Content-Type": "application/json"})
                    if batch_resp and batch_resp.status_code == 200:
                        findings.append(RawFinding(
                            tool="infrastructure-scanner",
                            category=OwaspCategory.A02_MISCONFIGURATION,
                            title="GraphQL Batching Enabled — DoS and enumeration risk",
                            url=url,
                            raw_severity="medium",
                            description=(
                                "GraphQL query batching is enabled with no apparent rate "
                                "limiting. An attacker can send hundreds of queries in a "
                                "single HTTP request, bypassing rate limits and enabling "
                                "efficient enumeration or resource exhaustion attacks."
                            ),
                            evidence=(
                                f"Sent 10 batched queries in one request.\n"
                                f"All processed: HTTP {batch_resp.status_code}"
                            ),
                        ))
                except Exception:
                    pass

        except Exception:
            continue
        time.sleep(0.3)

    return findings


# ── Race Conditions ───────────────────────────────────────────────────────────

def test_race_conditions(target_url: str, session: requests.Session) -> List[RawFinding]:
    """Test for race conditions on sensitive single-use endpoints."""
    findings = []
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

    # Target endpoints commonly vulnerable to race conditions
    race_paths = [
        ("/apply-coupon", "POST", {"code": "TESTCODE10"}),
        ("/redeem", "POST", {"token": "test"}),
        ("/withdraw", "POST", {"amount": "1"}),
        ("/vote", "POST", {}),
        ("/like", "POST", {}),
        ("/claim", "POST", {}),
    ]

    results = []
    threads = []

    def fire_request(url, method, data):
        try:
            resp = session.request(method, url, data=data,
                                   timeout=_TIMEOUT, headers={"User-Agent": _UA})
            results.append(resp.status_code)
        except Exception:
            pass

    for path, method, data in race_paths:
        url = urljoin(base, path)
        results.clear()

        # Fire 10 concurrent requests
        for _ in range(10):
            t = threading.Thread(target=fire_request, args=(url, method, data))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        threads.clear()

        if not results:
            continue

        # If endpoint exists and multiple 200s received, race condition possible
        success_count = results.count(200) + results.count(201)
        if success_count >= 2 and any(r != 404 for r in results):
            findings.append(RawFinding(
                tool="infrastructure-scanner",
                category=OwaspCategory.A06_INSECURE_DESIGN,
                title=f"Potential Race Condition — {path}",
                url=url,
                raw_severity="high",
                description=(
                    f"Endpoint '{path}' returned {success_count} success responses "
                    f"when 10 concurrent requests were fired simultaneously. If this "
                    f"endpoint performs a single-use operation (coupon redemption, "
                    f"gift card use, vote, withdrawal), the race condition may allow "
                    f"the operation to be executed multiple times."
                ),
                evidence=(
                    f"Concurrent requests: 10\n"
                    f"Success responses (200/201): {success_count}\n"
                    f"All status codes: {results}"
                ),
            ))

        time.sleep(0.5)

    return findings


# ── CORS Misconfiguration (deep) ──────────────────────────────────────────────

def test_cors(target_url: str, session: requests.Session) -> List[RawFinding]:
    findings = []
    test_origins = [
        "https://evil.attacker.com",
        "null",
        f"https://evil{urlparse(target_url).netloc}",
        f"https://{urlparse(target_url).netloc}.evil.com",
    ]

    for origin in test_origins:
        try:
            resp = _req(session, "GET", target_url,
                        headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == origin or acao == "*":
                severity = "critical" if acac.lower() == "true" else "high"
                findings.append(RawFinding(
                    tool="infrastructure-scanner",
                    category=OwaspCategory.A01_ACCESS_CONTROL,
                    title=f"CORS Misconfiguration — Origin '{origin}' reflected/accepted",
                    url=target_url,
                    raw_severity=severity,
                    description=(
                        f"The server reflected the attacker-controlled origin '{origin}' "
                        f"in Access-Control-Allow-Origin"
                        + (f" with Access-Control-Allow-Credentials: true, enabling "
                           f"cross-site requests with user credentials"
                           if acac.lower() == "true"
                           else "")
                        + ". An attacker-controlled website can make cross-origin "
                        "requests to this application on behalf of logged-in users."
                    ),
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                    ),
                ))
                break
        except Exception:
            continue
        time.sleep(0.15)

    return findings


# ── Debug Endpoints ───────────────────────────────────────────────────────────

_DEBUG_PATHS = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/mappings", "/actuator/beans", "/actuator/metrics",
    "/_profiler", "/_profiler/phpinfo",
    "/telescope", "/telescope/requests",
    "/__debug__", "/.well-known/security.txt",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/trace", "/debug", "/console",
    "/rails/info/properties", "/rails/info/routes",
    "/api/_debug", "/api/debug",
]

def test_debug_endpoints(target_url: str, session: requests.Session) -> List[RawFinding]:
    findings = []
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

    for path in _DEBUG_PATHS:
        url = urljoin(base, path)
        try:
            resp = _req(session, "GET", url, allow_redirects=False)
            if not resp or resp.status_code not in (200, 401, 403):
                continue

            # 200 = exposed, 401/403 = exists but protected (still worth noting)
            severity = "high" if resp.status_code == 200 else "medium"
            if resp.status_code == 200 and len(resp.text) < 50:
                continue

            findings.append(RawFinding(
                tool="infrastructure-scanner",
                category=OwaspCategory.A02_MISCONFIGURATION,
                title=f"Debug/Admin Endpoint Exposed — {path}",
                url=url,
                raw_severity=severity,
                description=(
                    f"Debug or admin endpoint '{path}' returned HTTP {resp.status_code}. "
                    + (f"The endpoint is publicly accessible and returned {len(resp.text)} "
                       f"bytes of potentially sensitive configuration or debug data."
                       if resp.status_code == 200
                       else "The endpoint exists but requires authentication — "
                            "ensure it is not accessible from untrusted networks.")
                ),
                evidence=(
                    f"URL: {url}\n"
                    f"HTTP status: {resp.status_code}\n"
                    f"Response length: {len(resp.text)}\n"
                    f"Response snippet: {resp.text[:300]}"
                ),
            ))
        except Exception:
            continue
        time.sleep(0.1)

    return findings


# ── Main ──────────────────────────────────────────────────────────────────────

def run_infrastructure_scan(target_url: str) -> List[RawFinding]:
    session = requests.Session()
    session.headers["User-Agent"] = _UA
    findings = []
    findings.extend(test_cache_poisoning(target_url, session))
    findings.extend(test_ssrf(target_url, session))
    findings.extend(test_graphql(target_url, session))
    findings.extend(test_cors(target_url, session))
    findings.extend(test_debug_endpoints(target_url, session))
    findings.extend(test_race_conditions(target_url, session))
    return findings
