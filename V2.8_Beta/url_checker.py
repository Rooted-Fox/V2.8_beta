"""URL reachability checker with redirect following — standalone utility,
no dependency on any scan job manager."""
from __future__ import annotations

import requests


def check_url(url: str, timeout: int = 8) -> dict:
    if not url.startswith(("http://", "https://")):
        return {"reachable": False, "error": "URL must start with http:// or https://",
                "final_url": url, "redirects": []}
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; VulnIQ/1.0)"})
        redirects = [r.url for r in resp.history]
        return {
            "reachable": True,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirects": redirects,
            "redirect_count": len(redirects),
        }
    except requests.exceptions.ConnectionError:
        return {"reachable": False, "error": "Connection refused or DNS resolution failed",
                "final_url": url, "redirects": []}
    except requests.exceptions.Timeout:
        return {"reachable": False, "error": f"Timed out after {timeout}s",
                "final_url": url, "redirects": []}
    except Exception as exc:
        return {"reachable": False, "error": str(exc), "final_url": url, "redirects": []}
