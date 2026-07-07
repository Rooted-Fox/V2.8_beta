"""Technology fingerprinting: identify what software and versions are running
on the target from black-box HTTP responses only.

Checks response headers, HTML meta tags, JS file paths, favicon hash,
error page signatures, and common framework indicators. Returns a list
of (technology, version) tuples for the CVE lookup engine to use.
"""
from __future__ import annotations

import hashlib
import re
from typing import List, Optional, Tuple
from urllib.parse import urljoin

import requests

# (pattern, technology_name, version_group_index or None)
_HEADER_PATTERNS: List[Tuple[re.Pattern, str, Optional[int]]] = [
    (re.compile(r"Apache/([\d.]+)", re.I),        "Apache HTTP Server",    1),
    (re.compile(r"nginx/([\d.]+)", re.I),          "nginx",                 1),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I),  "Microsoft IIS",         1),
    (re.compile(r"PHP/([\d.]+)", re.I),             "PHP",                   1),
    (re.compile(r"Express",        re.I),           "Express.js",            None),
    (re.compile(r"Django/([\d.]+)", re.I),          "Django",                1),
    (re.compile(r"Laravel",        re.I),           "Laravel",               None),
    (re.compile(r"Rails/([\d.]+)", re.I),           "Ruby on Rails",         1),
    (re.compile(r"Tomcat/([\d.]+)", re.I),          "Apache Tomcat",         1),
    (re.compile(r"JBoss",          re.I),           "JBoss",                 None),
    (re.compile(r"Jetty/([\d.]+)", re.I),           "Jetty",                 1),
    (re.compile(r"OpenSSL/([\d.]+)", re.I),         "OpenSSL",               1),
    (re.compile(r"WordPress/([\d.]+)", re.I),       "WordPress",             1),
    (re.compile(r"Drupal/([\d.]+)", re.I),          "Drupal",                1),
]

_HTML_PATTERNS: List[Tuple[re.Pattern, str, Optional[int]]] = [
    (re.compile(r'meta name=["\']generator["\'][^>]*content=["\']([^"\']+)', re.I), "generator", 1),
    (re.compile(r'jquery[/-]([\d.]+)(?:\.min)?\.js', re.I),   "jQuery",    1),
    (re.compile(r'react[/@]([\d.]+)', re.I),                    "React",     1),
    (re.compile(r'vue[/@]([\d.]+)', re.I),                      "Vue.js",    1),
    (re.compile(r'angular[/@]([\d.]+)', re.I),                  "Angular",   1),
    (re.compile(r'bootstrap[/-]([\d.]+)', re.I),                "Bootstrap", 1),
    (re.compile(r'lodash[/-]([\d.]+)', re.I),                   "Lodash",    1),
    (re.compile(r'moment[/-]([\d.]+)', re.I),                   "Moment.js", 1),
    (re.compile(r'wp-content', re.I),                           "WordPress", None),
    (re.compile(r'Powered by ([A-Za-z]+\s?[\d.]*)', re.I),     "powered_by", 1),
    (re.compile(r'<meta name=["\']framework["\'][^>]*content=["\']([^"\']+)', re.I), "framework", 1),
]

_ERROR_SIGNATURES = {
    "MySQL": ["mysql", "You have an error in your SQL syntax"],
    "PostgreSQL": ["postgresql", "pg_query()", "PSQLException"],
    "Oracle": ["ORA-", "oracle.jdbc"],
    "MSSQL": ["[Microsoft][ODBC SQL Server Driver]", "System.Data.SqlClient"],
    "MongoDB": ["MongoError", "mongo"],
    "PHP": ["Fatal error", "Uncaught exception", "Call to undefined function"],
    "Java": ["java.lang", "Exception in thread", "NullPointerException", "javax.servlet"],
    "Python": ["Traceback (most recent call last)", "AttributeError:", "ImportError:"],
    "Ruby": ["ActionView::Template::Error", "ActiveRecord"],
    "ASP.NET": ["ASP.NET", "System.Web", "__VIEWSTATE"],
}


def fingerprint(target_url: str, timeout: int = 10) -> List[Tuple[str, Optional[str]]]:
    """Return list of (technology, version_or_None) tuples."""
    results: List[Tuple[str, Optional[str]]] = []
    seen: set = set()

    def add(tech: str, version: Optional[str]) -> None:
        key = (tech.lower(), version)
        if key not in seen:
            seen.add(key)
            results.append((tech, version))

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; security-scanner/1.0)"

    # --- main page ---
    try:
        resp = session.get(target_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return results

    # headers
    all_headers = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
    for pat, tech, grp in _HEADER_PATTERNS:
        m = pat.search(all_headers)
        if m:
            add(tech, m.group(grp) if grp else None)

    # html body
    body = resp.text[:80000]
    for pat, tech, grp in _HTML_PATTERNS:
        for m in pat.finditer(body):
            val = m.group(grp) if grp else None
            if tech in ("generator", "powered_by", "framework") and val:
                # extract product name from value like "WordPress 6.2"
                parts = val.strip().split()
                product = parts[0]
                version = parts[1] if len(parts) > 1 else None
                add(product, version)
            else:
                add(tech, val)

    # --- probe /robots.txt for tech hints ---
    try:
        robots = session.get(urljoin(target_url, "/robots.txt"), timeout=5)
        if "wp-" in robots.text:
            add("WordPress", None)
        if "Disallow: /admin" in robots.text or "Disallow: /administrator" in robots.text:
            add("CMS-detected", None)
    except requests.RequestException:
        pass

    # --- probe error page for technology signatures ---
    try:
        err_resp = session.get(
            urljoin(target_url, "/____nonexistent____xyz"), timeout=5
        )
        err_body = err_resp.text
        for tech, sigs in _ERROR_SIGNATURES.items():
            if any(sig in err_body for sig in sigs):
                add(tech, None)
    except requests.RequestException:
        pass

    # --- check X-Powered-By header ---
    xpb = resp.headers.get("X-Powered-By", "")
    if xpb:
        parts = xpb.strip().split("/")
        product = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else None
        add(product, version)

    # --- check Server header ---
    server = resp.headers.get("Server", "")
    if server and not any(t.lower() in server.lower() for t, _ in results):
        parts = server.strip().split("/")
        add(parts[0].strip(), parts[1].strip() if len(parts) > 1 else None)

    return results
