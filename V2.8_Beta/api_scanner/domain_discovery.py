"""Domain-based API endpoint discovery.

Discovers API endpoints for a domain using multiple techniques:
1. Common API path probing (fast, always works)
2. Exposed API documentation detection
3. Wayback Machine / Common Crawl (passive recon, network-dependent)
4. Subdomain enumeration for API subdomains
5. JavaScript file analysis for endpoint extraction
"""
from __future__ import annotations

import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

from api_scanner.curl_parser import ApiEndpoint

_UA = "Mozilla/5.0 (compatible; VulnIQ-API-Discovery/1.0)"
_TIMEOUT = 8

_COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/graphiql", "/gql",
    "/service", "/services",
    "/ws", "/webservice", "/webservices",
    "/rpc", "/jsonrpc", "/xmlrpc",
]

_DOC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs/", "/api/docs",
    "/docs", "/documentation",
    "/swagger-ui", "/swagger-ui.html", "/swagger-ui/",
    "/.well-known/openapi",
    "/api/swagger", "/api/openapi",
]

_API_SUBDOMAIN_PREFIXES = [
    "api", "gateway", "dev-api", "staging-api", "api-v1",
    "api-v2", "rest", "graphql", "services", "backend",
]


def _get(url: str, session: requests.Session) -> Optional[requests.Response]:
    try:
        resp = session.get(url, timeout=_TIMEOUT, allow_redirects=True,
                           headers={"User-Agent": _UA})
        return resp
    except requests.RequestException:
        return None


def _looks_like_api_response(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return ("json" in ct or "xml" in ct) and resp.status_code < 400


def _probe_common_paths(base_url: str, session: requests.Session) -> List[str]:
    """Check common API paths and return the ones that respond."""
    found = []
    for path in _COMMON_API_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        resp = _get(url, session)
        if resp and resp.status_code < 404:
            found.append(url)
    return found


def _probe_doc_paths(base_url: str, session: requests.Session) -> List[dict]:
    """Check for exposed API documentation and return {url, content, type}."""
    found = []
    for path in _DOC_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        resp = _get(url, session)
        if resp and resp.status_code == 200 and len(resp.text) > 100:
            ct = resp.headers.get("Content-Type", "")
            found.append({
                "url": url,
                "content": resp.text,
                "type": "openapi" if "swagger" in ct or "openapi" in resp.text[:200].lower() else "html",
            })
    return found


def _extract_endpoints_from_js(js_url: str, base_url: str,
                                session: requests.Session) -> List[str]:
    """Pull API endpoint paths from a JavaScript file."""
    resp = _get(js_url, session)
    if not resp or resp.status_code != 200:
        return []
    patterns = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'\.get\(["\']([^"\']+)["\']',
        r'\.post\(["\']([^"\']+)["\']',
        r'baseURL:\s*["\']([^"\']+)["\']',
        r'endpoint:\s*["\']([^"\']+)["\']',
    ]
    endpoints = set()
    for pat in patterns:
        for match in re.findall(pat, resp.text):
            if match.startswith("/"):
                endpoints.add(f"{base_url.rstrip('/')}{match}")
            elif match.startswith("http"):
                endpoints.add(match)
    return list(endpoints)


def _wayback_lookup(domain: str) -> List[str]:
    """Query Wayback Machine CDX API for known API URLs for this domain."""
    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/api/*",
                "output": "text",
                "fl": "original",
                "limit": 200,
                "filter": "statuscode:200",
                "collapse": "urlkey",
            },
            timeout=15, headers={"User-Agent": _UA}
        )
        if resp.status_code == 200:
            return [u.strip() for u in resp.text.splitlines() if u.strip().startswith("http")]
    except requests.RequestException:
        pass
    return []


def _api_subdomains(domain: str, session: requests.Session) -> List[str]:
    """Check common API subdomain patterns."""
    # Extract the root domain (strip www or subdomains)
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    found = []
    for prefix in _API_SUBDOMAIN_PREFIXES:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{prefix}.{root}"
            resp = _get(url, session)
            if resp and resp.status_code < 404:
                found.append(url)
                break  # found on https, don't also check http
    return found


def _endpoint_from_url(url: str, method: str = "GET") -> ApiEndpoint:
    ep = ApiEndpoint()
    ep.method = method
    ep.url = url
    parsed = urlparse(url)
    ep.base_url = f"{parsed.scheme}://{parsed.netloc}"
    ep.path = parsed.path
    from api_scanner.curl_parser import _extract_path_params
    ep.path_params = _extract_path_params(parsed.path)
    return ep


def discover_apis(domain_or_url: str) -> dict:
    """Full API discovery pipeline for a domain or base URL.

    Returns:
        {
            "base_urls": [...],
            "endpoints": [ApiEndpoint, ...],
            "spec_content": "...",   # OpenAPI/Swagger content if found
            "spec_url": "...",
            "wayback_urls": [...],
            "log": [...]             # discovery log messages
        }
    """
    log = []
    session = requests.Session()
    session.headers["User-Agent"] = _UA

    # Normalise input — accept bare domain or full URL
    if not domain_or_url.startswith("http"):
        domain_or_url = f"https://{domain_or_url}"
    parsed = urlparse(domain_or_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc

    result = {
        "base_urls": [base_url],
        "endpoints": [],
        "spec_content": None,
        "spec_url": None,
        "wayback_urls": [],
        "log": log,
    }

    # 1. Probe common API paths
    log.append("Probing common API paths...")
    api_paths = _probe_common_paths(base_url, session)
    log.append(f"Found {len(api_paths)} responding API base paths")

    # 2. Look for exposed API documentation
    log.append("Checking for exposed API documentation (Swagger/OpenAPI)...")
    docs = _probe_doc_paths(base_url, session)
    for doc in docs:
        if doc["type"] == "openapi":
            result["spec_content"] = doc["content"]
            result["spec_url"] = doc["url"]
            log.append(f"Found API spec at: {doc['url']}")
            break

    # 3. Parse spec if found — gives us the richest endpoint list
    if result["spec_content"]:
        from api_scanner.file_parser import parse_openapi
        spec_endpoints = parse_openapi(result["spec_content"])
        result["endpoints"].extend(spec_endpoints)
        log.append(f"Parsed {len(spec_endpoints)} endpoints from spec")

    # 4. Extract endpoints from JS files on the main page
    log.append("Scanning JavaScript files for API endpoint references...")
    try:
        resp = _get(base_url, session)
        if resp:
            js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
            js_endpoints = []
            for js_path in js_urls[:10]:  # cap at 10 JS files
                js_url = urljoin(base_url, js_path)
                js_endpoints.extend(_extract_endpoints_from_js(js_url, base_url, session))
            for url in set(js_endpoints):
                result["endpoints"].append(_endpoint_from_url(url))
            log.append(f"Found {len(js_endpoints)} endpoint references in JavaScript files")
    except Exception as e:
        log.append(f"JS extraction error: {e}")

    # 5. Add discovered API paths as generic endpoints
    for path_url in api_paths:
        result["endpoints"].append(_endpoint_from_url(path_url))

    # 6. API subdomain discovery
    log.append("Checking API subdomains...")
    api_subs = _api_subdomains(domain, session)
    for sub_url in api_subs:
        result["base_urls"].append(sub_url)
        result["endpoints"].append(_endpoint_from_url(sub_url))
        log.append(f"Found API subdomain: {sub_url}")

    # 7. Wayback Machine passive recon (network-dependent, graceful fail)
    log.append("Querying Wayback Machine for historical API endpoints...")
    try:
        wb_urls = _wayback_lookup(domain)
        result["wayback_urls"] = wb_urls
        for url in wb_urls[:50]:
            result["endpoints"].append(_endpoint_from_url(url))
        log.append(f"Found {len(wb_urls)} historical API URLs from Wayback Machine")
    except Exception:
        log.append("Wayback Machine query skipped (network unavailable)")

    # Deduplicate endpoints by URL+method
    seen = set()
    deduped = []
    for ep in result["endpoints"]:
        key = f"{ep.method}:{ep.url}"
        if key not in seen:
            seen.add(key)
            deduped.append(ep)
    result["endpoints"] = deduped

    log.append(f"Discovery complete: {len(result['endpoints'])} unique API endpoints found")
    return result
