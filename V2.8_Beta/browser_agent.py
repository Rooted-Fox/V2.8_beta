"""Playwright browser agent — Phase 0 of the enhanced scan pipeline.

Logs into an application as a real authenticated user, navigates through
it, captures every network request made during the session, and returns
a rich endpoint map for the scanners and reasoning agent to work from.

This is what opens up authenticated testing — everything behind a login
that unauthenticated scanners completely miss.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class BrowserCrawlResult:
    def __init__(self):
        self.authenticated: bool = False
        self.session_cookies: List[dict] = []
        self.session_headers: Dict[str, str] = {}
        self.endpoints: List[Dict[str, Any]] = []
        self.page_titles: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.js_api_calls: List[Dict[str, Any]] = []
        self.app_context: str = ""   # what the app appears to do
        self.log: List[str] = []

    def to_dict(self) -> dict:
        return {
            "authenticated": self.authenticated,
            "endpoint_count": len(self.endpoints),
            "form_count": len(self.forms),
            "js_api_calls": len(self.js_api_calls),
            "app_context": self.app_context,
            "log": self.log,
        }


def crawl_authenticated(
    target_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    login_url: Optional[str] = None,
    max_pages: int = 30,
    timeout_ms: int = 10000,
) -> BrowserCrawlResult:
    """Navigate the application as an authenticated user and capture everything."""

    result = BrowserCrawlResult()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result.log.append("[skip] Playwright not installed — run: pip install playwright && playwright install chromium")
        return result

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-dev-shm-usage", "--disable-gpu"]
            )
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
            )
            page = context.new_page()

            # Capture all network requests
            def on_request(request):
                parsed = urlparse(request.url)
                target_parsed = urlparse(target_url)
                if parsed.netloc == target_parsed.netloc:
                    endpoint = {
                        "method": request.method,
                        "url": request.url,
                        "path": parsed.path,
                        "headers": dict(request.headers),
                        "post_data": request.post_data,
                        "resource_type": request.resource_type,
                    }
                    if request.resource_type in ("xhr", "fetch", "document"):
                        result.endpoints.append(endpoint)
                        if request.resource_type in ("xhr", "fetch"):
                            result.js_api_calls.append(endpoint)

            page.on("request", on_request)

            # Step 1: navigate to the target
            try:
                page.goto(target_url, timeout=timeout_ms, wait_until="networkidle")
                result.log.append(f"Loaded: {target_url}")
            except Exception as e:
                result.log.append(f"[warn] Initial load timeout (continuing): {e}")

            # Step 2: attempt login if credentials provided
            if username and password:
                login_target = login_url or target_url
                try:
                    if login_url and login_url != target_url:
                        page.goto(login_url, timeout=timeout_ms, wait_until="networkidle")

                    # Detect and fill login form
                    _attempt_login(page, username, password, timeout_ms)

                    # Wait for post-login navigation
                    try:
                        page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass

                    # Check if login succeeded
                    current_url = page.url
                    page_text = page.content().lower()
                    login_indicators = ["logout", "log out", "sign out", "dashboard",
                                       "welcome", "profile", "account", "home"]
                    if any(ind in page_text for ind in login_indicators):
                        result.authenticated = True
                        result.log.append(f"Login successful — authenticated as {username}")
                    else:
                        result.log.append(f"[warn] Login may not have succeeded — verify credentials")

                    # Capture session cookies and headers
                    result.session_cookies = context.cookies()
                    result.session_headers = {
                        "Cookie": "; ".join(
                            f"{c['name']}={c['value']}" for c in result.session_cookies
                        )
                    }

                except Exception as e:
                    result.log.append(f"[warn] Login attempt error: {e}")

            # Step 3: crawl authenticated pages
            visited = {page.url}
            queue = [page.url]
            pages_visited = 0

            while queue and pages_visited < max_pages:
                url = queue.pop(0)
                if url in visited and url != queue[0:1]:
                    pass

                try:
                    if url != page.url:
                        page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                        visited.add(url)
                        pages_visited += 1
                        time.sleep(0.3)

                    # Collect page title
                    try:
                        title = page.title()
                        if title:
                            result.page_titles.append(title)
                    except Exception:
                        pass

                    # Collect forms
                    try:
                        forms = page.evaluate("""() => {
                            return Array.from(document.forms).map(f => ({
                                action: f.action,
                                method: f.method || 'GET',
                                fields: Array.from(f.elements)
                                    .filter(e => e.name)
                                    .map(e => ({name: e.name, type: e.type, value: e.value}))
                            }));
                        }""")
                        result.forms.extend(forms)
                    except Exception:
                        pass

                    # Find more links to crawl
                    try:
                        links = page.evaluate("""() => {
                            return Array.from(document.querySelectorAll('a[href]'))
                                .map(a => a.href)
                                .filter(h => h.startsWith('http'));
                        }""")
                        target_parsed = urlparse(target_url)
                        for link in links:
                            link_parsed = urlparse(link)
                            if (link_parsed.netloc == target_parsed.netloc
                                    and link not in visited
                                    and link not in queue):
                                queue.append(link)
                    except Exception:
                        pass

                    # Click navigation items to discover JS-rendered content
                    try:
                        nav_items = page.query_selector_all("nav a, .nav a, .menu a, .sidebar a")
                        for item in nav_items[:5]:
                            try:
                                href = item.get_attribute("href")
                                if href and not href.startswith("#"):
                                    full = urljoin(target_url, href) if href.startswith("/") else href
                                    if full not in visited:
                                        queue.append(full)
                            except Exception:
                                pass
                    except Exception:
                        pass

                except Exception as e:
                    result.log.append(f"[warn] Page error on {url}: {e}")
                    continue

            result.log.append(f"Crawl complete: {pages_visited} pages, "
                              f"{len(result.endpoints)} endpoints, "
                              f"{len(result.js_api_calls)} API calls captured")

            # Build app context summary
            result.app_context = _infer_app_context(result)
            browser.close()

    except Exception as e:
        result.log.append(f"[error] Browser agent failed: {e}")

    return result


def _attempt_login(page, username: str, password: str, timeout_ms: int) -> None:
    """Detect and fill a login form on the current page."""
    from urllib.parse import urljoin

    # Common username field selectors
    user_selectors = [
        'input[name="username"]', 'input[name="user"]',
        'input[name="email"]', 'input[name="login"]',
        'input[type="email"]', 'input[id="username"]',
        'input[id="user"]', 'input[id="email"]',
        'input[name="uname"]', 'input[name="userid"]',
        'input[autocomplete="username"]',
    ]
    pwd_selectors = [
        'input[type="password"]',
        'input[name="password"]', 'input[name="passwd"]',
        'input[name="pass"]', 'input[id="password"]',
    ]
    submit_selectors = [
        'button[type="submit"]', 'input[type="submit"]',
        'button:text("Login")', 'button:text("Sign in")',
        'button:text("Log in")', 'button:text("Submit")',
        '[value="Login"]', '[value="Sign In"]',
    ]

    user_field = None
    for sel in user_selectors:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                user_field = el
                break
        except Exception:
            pass

    pwd_field = None
    for sel in pwd_selectors:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                pwd_field = el
                break
        except Exception:
            pass

    if not user_field or not pwd_field:
        return

    user_field.fill(username)
    pwd_field.fill(password)

    # Try to submit
    for sel in submit_selectors:
        try:
            btn = page.query_selector(sel)
            if btn and btn.is_visible():
                btn.click()
                return
        except Exception:
            pass

    # Fallback: press Enter in the password field
    pwd_field.press("Enter")


def _infer_app_context(result: BrowserCrawlResult) -> str:
    """Build a short description of what the application appears to do."""
    titles = list(set(result.page_titles))
    paths = list(set(ep.get("path", "") for ep in result.endpoints))
    api_paths = list(set(ep.get("path", "") for ep in result.js_api_calls))

    context_parts = []
    if titles:
        context_parts.append(f"Page titles: {', '.join(titles[:5])}")
    if paths:
        context_parts.append(f"Discovered {len(paths)} unique paths including: {', '.join(paths[:10])}")
    if api_paths:
        context_parts.append(f"API calls observed: {', '.join(api_paths[:10])}")

    # Infer app type from paths
    app_type_hints = {
        "e-commerce": ["cart", "shop", "product", "order", "checkout", "payment"],
        "banking/finance": ["account", "transfer", "balance", "transaction", "payment"],
        "CMS/blog": ["post", "article", "category", "tag", "admin", "wp-"],
        "social": ["profile", "friend", "message", "feed", "follow", "like"],
        "admin panel": ["admin", "manage", "dashboard", "config", "user", "setting"],
        "API gateway": ["api", "v1", "v2", "graphql", "rest"],
    }
    all_paths = " ".join(paths).lower()
    detected_types = [t for t, keywords in app_type_hints.items()
                     if any(k in all_paths for k in keywords)]
    if detected_types:
        context_parts.append(f"Application type appears to be: {', '.join(detected_types)}")

    return " | ".join(context_parts) if context_parts else "Web application (context not determined)"


# Fix missing import
from urllib.parse import urljoin
