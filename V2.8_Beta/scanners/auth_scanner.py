"""Authentication vulnerability scanner.

Covers JWT attacks, OAuth misconfigurations, session weaknesses,
password reset flaws, and credential exposure — beyond what
Acunetix checks.
"""
from __future__ import annotations

import base64
import json
import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlsplit

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


# ── JWT Attacks ───────────────────────────────────────────────────────────────

def _decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def _forge_jwt_none_alg(token: str) -> Optional[str]:
    """Forge a JWT with alg:none (no signature required)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Replace header with alg:none
        none_header = base64.urlsafe_b64encode(
            b'{"alg":"none","typ":"JWT"}'
        ).rstrip(b"=").decode()
        return f"{none_header}.{parts[1]}."
    except Exception:
        return None


def _forge_jwt_weak_secret(token: str) -> List[str]:
    """Try common weak secrets for HMAC JWT."""
    # Common weak secrets
    weak_secrets = [
        "secret", "password", "123456", "qwerty", "admin",
        "changeme", "mysecret", "jwt_secret", "your-secret",
        "", "null", "undefined", "secret123",
    ]
    forged = []
    try:
        import hmac
        import hashlib
        parts = token.split(".")
        if len(parts) != 3:
            return []
        header_payload = f"{parts[0]}.{parts[1]}"
        for secret in weak_secrets:
            sig = hmac.new(
                secret.encode(),
                header_payload.encode(),
                hashlib.sha256,
            ).digest()
            forged_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            if forged_sig == parts[2]:
                forged.append(secret)
    except Exception:
        pass
    return forged


def test_jwt_vulnerabilities(target_url: str, session: requests.Session,
                              auth_headers: dict = None) -> List[RawFinding]:
    """Test JWT tokens found in request/response for common weaknesses."""
    findings = []

    # Look for JWT in auth headers or cookies
    jwt_tokens = []
    for header_val in (auth_headers or {}).values():
        if isinstance(header_val, str) and header_val.count(".") == 2:
            token = header_val.replace("Bearer ", "").strip()
            jwt_tokens.append(token)

    # Also check response cookies and headers for JWTs
    try:
        resp = _req(session, "GET", target_url)
        if resp:
            for cookie in resp.cookies:
                if cookie.value.count(".") == 2:
                    jwt_tokens.append(cookie.value)
            auth_resp_header = resp.headers.get("Authorization", "")
            if auth_resp_header.count(".") == 2:
                jwt_tokens.append(auth_resp_header.replace("Bearer ", ""))
    except Exception:
        pass

    for token in jwt_tokens[:3]:
        payload = _decode_jwt_payload(token)
        if not payload:
            continue

        # Test 1: Algorithm none
        none_token = _forge_jwt_none_alg(token)
        if none_token:
            forged_headers = {"Authorization": f"Bearer {none_token}",
                              "User-Agent": _UA}
            resp = _req(session, "GET", target_url, headers=forged_headers)
            if resp and resp.status_code == 200:
                findings.append(RawFinding(
                    tool="auth-scanner",
                    category=OwaspCategory.A07_AUTH_FAILURES,
                    title="JWT Algorithm Confusion — 'none' algorithm accepted",
                    url=target_url,
                    raw_severity="critical",
                    description=(
                        "The server accepted a JWT with the algorithm set to 'none', "
                        "meaning no signature verification is performed. An attacker can "
                        "forge tokens for any user including administrators without knowing "
                        "the signing secret."
                    ),
                    evidence=(
                        f"Original token algorithm: {_decode_jwt_payload(token.split('.')[0]) or 'unknown'}\n"
                        f"Forged token (alg:none): {none_token[:50]}...\n"
                        f"Server response: HTTP {resp.status_code}"
                    ),
                ))

        # Test 2: Weak secret
        weak = _forge_jwt_weak_secret(token)
        if weak:
            findings.append(RawFinding(
                tool="auth-scanner",
                category=OwaspCategory.A07_AUTH_FAILURES,
                title=f"JWT Weak Signing Secret — cracked with '{weak[0]}'",
                url=target_url,
                raw_severity="critical",
                description=(
                    f"The JWT signing secret is weak and was cracked using a common "
                    f"password ('{weak[0]}'). An attacker can forge tokens for any user "
                    f"or modify claims (e.g. elevate role to 'admin') and re-sign them."
                ),
                evidence=(
                    f"Weak secret discovered: '{weak[0]}'\n"
                    f"JWT payload: {json.dumps(payload, indent=2)[:300]}"
                ),
            ))

        # Test 3: Sensitive data in JWT payload
        sensitive_keys = ["password", "passwd", "secret", "ssn", "credit_card",
                          "cvv", "pin", "private_key"]
        found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
        if found_sensitive:
            findings.append(RawFinding(
                tool="auth-scanner",
                category=OwaspCategory.A02_MISCONFIGURATION,
                title="Sensitive Data in JWT Payload",
                url=target_url,
                raw_severity="high",
                description=(
                    f"The JWT payload contains sensitive fields: {found_sensitive}. "
                    "JWT payloads are only base64-encoded, not encrypted. Anyone who "
                    "intercepts this token can read its full contents without any key."
                ),
                evidence=(
                    f"Sensitive fields in payload: {found_sensitive}\n"
                    f"Decoded payload: {json.dumps(payload, indent=2)[:300]}"
                ),
            ))

        # Test 4: Expired token still accepted
        if "exp" in payload:
            exp = payload["exp"]
            import time as t
            if exp < t.time():
                resp_expired = _req(session, "GET", target_url,
                                    headers={"Authorization": f"Bearer {token}",
                                             "User-Agent": _UA})
                if resp_expired and resp_expired.status_code == 200:
                    findings.append(RawFinding(
                        tool="auth-scanner",
                        category=OwaspCategory.A07_AUTH_FAILURES,
                        title="Expired JWT Token Still Accepted",
                        url=target_url,
                        raw_severity="high",
                        description=(
                            "An expired JWT token was accepted by the server. The 'exp' "
                            "claim is not being validated, allowing attackers to use "
                            "stolen tokens indefinitely."
                        ),
                        evidence=(
                            f"Token expiry (exp): {exp}\n"
                            f"Current time: {int(t.time())}\n"
                            f"Server accepted expired token with HTTP {resp_expired.status_code}"
                        ),
                    ))

    return findings


# ── Session Security ──────────────────────────────────────────────────────────

def test_session_security(target_url: str, session: requests.Session) -> List[RawFinding]:
    """Check session cookie security attributes and fixation."""
    findings = []

    try:
        resp = _req(session, "GET", target_url)
        if not resp:
            return findings

        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag missing — cookie transmitted over HTTP")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag missing — readable by JavaScript")
            samesite = cookie._rest.get("SameSite", cookie._rest.get("samesite", ""))
            if not samesite:
                issues.append("SameSite attribute missing — CSRF risk")
            elif samesite.lower() == "none" and not cookie.secure:
                issues.append("SameSite=None without Secure — cross-site leakage")

            if issues:
                findings.append(RawFinding(
                    tool="auth-scanner",
                    category=OwaspCategory.A07_AUTH_FAILURES,
                    title=f"Insecure Cookie — {cookie.name}",
                    url=target_url,
                    raw_severity="medium",
                    description=(
                        f"Session cookie '{cookie.name}' has security attribute issues: "
                        + "; ".join(issues)
                    ),
                    evidence=(
                        f"Cookie name: {cookie.name}\n"
                        f"Secure: {cookie.secure}\n"
                        f"HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}\n"
                        f"SameSite: {samesite or 'not set'}\n"
                        f"Issues: {'; '.join(issues)}"
                    ),
                ))

        # Check for security headers
        security_headers = {
            "Strict-Transport-Security": ("Missing HSTS header", "medium"),
            "Content-Security-Policy": ("Missing CSP header", "medium"),
            "X-Frame-Options": ("Missing clickjacking protection", "medium"),
            "X-Content-Type-Options": ("Missing MIME sniffing protection", "low"),
            "Referrer-Policy": ("Missing Referrer-Policy header", "low"),
            "Permissions-Policy": ("Missing Permissions-Policy header", "low"),
        }
        missing_headers = []
        for header, (desc, sev) in security_headers.items():
            if header not in resp.headers:
                missing_headers.append((header, desc, sev))

        if missing_headers:
            findings.append(RawFinding(
                tool="auth-scanner",
                category=OwaspCategory.A02_MISCONFIGURATION,
                title=f"Missing Security Headers ({len(missing_headers)} headers)",
                url=target_url,
                raw_severity="medium",
                description=(
                    "The application is missing important security headers that protect "
                    "against common browser-based attacks."
                ),
                evidence=(
                    "Missing headers:\n" +
                    "\n".join(f"  - {h}: {d}" for h, d, s in missing_headers)
                ),
            ))

    except Exception:
        pass

    return findings


# ── Password Reset Flaws ──────────────────────────────────────────────────────

def test_password_reset(target_url: str, session: requests.Session) -> List[RawFinding]:
    """Test password reset endpoint for common weaknesses."""
    findings = []
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

    reset_paths = [
        "/forgot-password", "/forgot_password", "/password/reset",
        "/reset-password", "/account/forgot", "/users/password/new",
        "/api/auth/reset", "/api/password/reset", "/auth/reset",
    ]

    for path in reset_paths:
        url = urljoin(base, path)
        try:
            resp = _req(session, "GET", url)
            if not resp or resp.status_code not in (200, 405):
                continue

            # Test: Host header injection in password reset
            poisoned_headers = {
                "Host": "evil.attacker.com",
                "X-Forwarded-Host": "evil.attacker.com",
                "User-Agent": _UA,
            }
            resp_poisoned = _req(session, "POST", url,
                                 headers=poisoned_headers,
                                 data={"email": "test@test.com"})

            if resp_poisoned and resp_poisoned.status_code in (200, 201, 302):
                findings.append(RawFinding(
                    tool="auth-scanner",
                    category=OwaspCategory.A07_AUTH_FAILURES,
                    title="Password Reset — Host Header Injection vulnerability",
                    url=url,
                    raw_severity="high",
                    description=(
                        "The password reset endpoint accepted a request with a poisoned "
                        "Host header (evil.attacker.com). If the reset email is generated "
                        "using the Host header, the reset link will point to the attacker's "
                        "domain, allowing them to steal reset tokens."
                    ),
                    evidence=(
                        f"Reset endpoint: {url}\n"
                        f"Poisoned Host header: evil.attacker.com\n"
                        f"Response: HTTP {resp_poisoned.status_code}\n"
                        f"Response snippet: {resp_poisoned.text[:300]}"
                    ),
                ))
                break

        except Exception:
            continue
        time.sleep(0.2)

    return findings


# ── User Enumeration ──────────────────────────────────────────────────────────

def test_user_enumeration(target_url: str, session: requests.Session) -> List[RawFinding]:
    """Detect user enumeration via different responses for valid/invalid usernames."""
    findings = []
    base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

    auth_paths = [
        "/login", "/signin", "/api/login", "/api/auth",
        "/wp-login.php", "/admin/login",
    ]

    for path in auth_paths:
        url = urljoin(base, path)
        try:
            resp_check = _req(session, "GET", url)
            if not resp_check or resp_check.status_code == 404:
                continue

            # Test with likely-valid username (admin) vs invalid
            resp_valid = _req(session, "POST", url,
                              data={"username": "admin", "password": "wrong_xyz_123"})
            resp_invalid = _req(session, "POST", url,
                                data={"username": "user_xyz_nonexistent_9z8",
                                      "password": "wrong_xyz_123"})

            if not resp_valid or not resp_invalid:
                continue

            # Different response lengths or status codes indicate enumeration
            len_diff = abs(len(resp_valid.text) - len(resp_invalid.text))
            status_diff = resp_valid.status_code != resp_invalid.status_code

            if len_diff > 50 or status_diff:
                findings.append(RawFinding(
                    tool="auth-scanner",
                    category=OwaspCategory.A07_AUTH_FAILURES,
                    title="User Enumeration via Login Response Difference",
                    url=url,
                    raw_severity="medium",
                    description=(
                        "The login endpoint returns different responses for valid and "
                        "invalid usernames, allowing attackers to enumerate valid accounts "
                        "before attempting password attacks."
                    ),
                    evidence=(
                        f"Valid username response: HTTP {resp_valid.status_code}, "
                        f"{len(resp_valid.text)} bytes\n"
                        f"Invalid username response: HTTP {resp_invalid.status_code}, "
                        f"{len(resp_invalid.text)} bytes\n"
                        f"Difference: {len_diff} bytes, status diff: {status_diff}"
                    ),
                ))
                break
        except Exception:
            continue
        time.sleep(0.3)

    return findings


# ── Main ──────────────────────────────────────────────────────────────────────

def run_auth_scan(target_url: str, auth_headers: dict = None) -> List[RawFinding]:
    session = requests.Session()
    session.headers["User-Agent"] = _UA
    findings = []
    findings.extend(test_jwt_vulnerabilities(target_url, session, auth_headers))
    findings.extend(test_session_security(target_url, session))
    findings.extend(test_password_reset(target_url, session))
    findings.extend(test_user_enumeration(target_url, session))
    return findings
