"""Parse curl commands into a structured API endpoint map.

Handles:
  - Single or multiple curl commands (one per block, separated by blank lines)
  - -X METHOD, --request METHOD
  - -H 'Header: value', --header 'Header: value'
  - -d 'body', --data 'body', --data-raw 'body', --data-binary 'body'
  - JSON and form-encoded bodies
  - Bearer tokens, API keys, Basic auth extracted from headers
  - URL path parameter detection (/users/{id}, /orders/123)
  - Query string parameter extraction
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


class ApiEndpoint:
    """A single API endpoint parsed from a curl command."""

    def __init__(self):
        self.method: str = "GET"
        self.url: str = ""
        self.path: str = ""
        self.base_url: str = ""
        self.headers: Dict[str, str] = {}
        self.body: Optional[Dict[str, Any]] = None
        self.body_raw: str = ""
        self.query_params: Dict[str, List[str]] = {}
        self.path_params: List[str] = []
        self.auth_type: str = "none"   # bearer, apikey, basic, none
        self.auth_value: str = ""
        self.content_type: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "path": self.path,
            "base_url": self.base_url,
            "headers": self.headers,
            "body": self.body,
            "body_raw": self.body_raw,
            "query_params": self.query_params,
            "path_params": self.path_params,
            "auth_type": self.auth_type,
            "auth_value": self.auth_value[:20] + "..." if len(self.auth_value) > 20 else self.auth_value,
            "content_type": self.content_type,
        }


def _extract_path_params(path: str) -> List[str]:
    """Detect path parameters — both {id} style and numeric literals."""
    template_params = re.findall(r'\{([^}]+)\}', path)
    numeric_params = re.findall(r'/(\d+)(?:/|$|\?)', path)
    return template_params + [f"id:{n}" for n in numeric_params]


def _detect_auth(headers: Dict[str, str]) -> tuple[str, str]:
    auth_header = headers.get("Authorization", headers.get("authorization", ""))
    if auth_header.lower().startswith("bearer "):
        return "bearer", auth_header[7:]
    if auth_header.lower().startswith("basic "):
        return "basic", auth_header[6:]
    # Check for API key patterns in any header
    for k, v in headers.items():
        if any(kw in k.lower() for kw in ["api-key","apikey","x-api-key","token","api_key"]):
            return "apikey", v
    return "none", ""


def parse_curl(curl_text: str) -> Optional[ApiEndpoint]:
    """Parse a single curl command string into an ApiEndpoint."""
    text = curl_text.strip()
    if not text.startswith("curl"):
        return None

    # Normalize line continuations
    text = re.sub(r'\\\s*\n', ' ', text)

    try:
        tokens = shlex.split(text)
    except ValueError:
        # shlex fails on unbalanced quotes — try simpler split
        tokens = text.split()

    ep = ApiEndpoint()
    i = 1  # skip "curl"
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-X", "--request") and i + 1 < len(tokens):
            ep.method = tokens[i + 1].upper()
            i += 2
        elif tok in ("-H", "--header") and i + 1 < len(tokens):
            header = tokens[i + 1]
            if ":" in header:
                k, v = header.split(":", 1)
                ep.headers[k.strip()] = v.strip()
            i += 2
        elif tok in ("-d", "--data", "--data-raw", "--data-binary",
                     "--data-urlencode") and i + 1 < len(tokens):
            ep.body_raw = tokens[i + 1]
            try:
                ep.body = json.loads(ep.body_raw)
            except (json.JSONDecodeError, ValueError):
                # Try form-encoded
                pairs = parse_qs(ep.body_raw)
                ep.body = {k: v[0] if len(v) == 1 else v for k, v in pairs.items()} or None
            if ep.method == "GET":
                ep.method = "POST"
            i += 2
        elif tok in ("-u", "--user") and i + 1 < len(tokens):
            ep.auth_type = "basic"
            ep.auth_value = tokens[i + 1]
            i += 2
        elif not tok.startswith("-") and tok.startswith("http"):
            ep.url = tok
            i += 1
        else:
            i += 1

    if not ep.url:
        return None

    parsed = urlparse(ep.url)
    ep.base_url = f"{parsed.scheme}://{parsed.netloc}"
    ep.path = parsed.path
    ep.query_params = parse_qs(parsed.query)
    ep.path_params = _extract_path_params(parsed.path)
    ep.content_type = ep.headers.get("Content-Type",
                                      ep.headers.get("content-type", ""))
    ep.auth_type, ep.auth_value = _detect_auth(ep.headers)

    return ep


def parse_curls(text: str) -> List[ApiEndpoint]:
    """Parse multiple curl commands from a text block."""
    # Split on 'curl' at the start of a new command
    blocks = re.split(r'(?=\bcurl\s)', text.strip())
    endpoints = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        ep = parse_curl(block)
        if ep:
            endpoints.append(ep)
    return endpoints
