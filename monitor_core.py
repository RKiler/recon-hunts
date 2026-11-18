from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import aiohttp

from js_analysis import extract_js_signals, extract_script_urls_from_html, looks_like_js_url


GRAPHQL_OPERATION_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
FEATURE_FLAG_RE = re.compile(r"\b(?:feature|flag|experiment|variant|gate)[A-Za-z0-9_.:-]{2,80}", re.I)
ROUTE_LITERAL_RE = re.compile(r"[\"'`](/(?:app|dashboard|settings|admin|account|org|project|billing|integrations?|connectors?|sources?|destinations?|cohort|chart|report|export|import|mcp)[^\"'`]{0,180})[\"'`]", re.I)
CACHE_PARAM_RE = re.compile(r"^(?:v|ver|version|cache|cb|t|ts|timestamp|dpl|hash|_=)$", re.I)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def normalize_url(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    if not parsed.scheme:
        return value
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if not CACHE_PARAM_RE.match(k)]
    path = re.sub(r"/+", "/", parsed.path or "/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, urlencode(query, doseq=True), ""))


def risk_for_item(item_type: str, value: str) -> str:
    text = f"{item_type} {value}".lower()
    if item_type in {"secret_like", "graphql_mutation"}:
        return "high"
    if any(token in text for token in ("admin", "role", "permission", "billing", "invite", "token", "export", "import", "mcp", "sso", "oauth")):
        return "high"
    if item_type in {"api_endpoint", "graphql_query", "frontend_route", "feature_flag"}:
        return "medium"
    return "info"


def parse_cookie_header(cookie_header: str, url: str) -> list[dict[str, Any]]:
    cookie_header = str(cookie_header or "").strip()
    if cookie_header.lower().startswith("cookie:"):
        cookie_header = cookie_header.split(":", 1)[1].strip()
    parsed = urlsplit(url)
    cookies: list[dict[str, Any]] = []
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if not name or not value:
            continue
        cookies.append({"name": name.strip(), "value": value.strip(), "url": f"{parsed.scheme}://{parsed.netloc}/", "path": "/"})
    return cookies


def resolve_secret_ref(secret_ref: str | None) -> str:
    if not secret_ref:
        return ""
    secret_ref = str(secret_ref).strip()
    if secret_ref.startswith("env:"):
        return os.getenv(secret_ref[4:].strip(), "")
    if secret_ref.startswith("file:"):
        path = Path(secret_ref[5:].strip())
        try:
            return path.read_text(encoding="utf-8", errors="ignore").strip() if path.is_file() else ""
        except OSError:
            return ""
    return secret_ref


def classify_request(url: str, method: str = "GET", post_data: str | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    path = parsed.path or "/"
    if re.search(r"/(?:api|graphql|gql|oauth|auth|sso|admin|invite|export|import|webhook|token|billing|mcp)(?:/|$)", path, re.I):
        item_type = "graphql_endpoint" if "graphql" in path.lower() or "gql" in path.lower() else "api_endpoint"
        items.append({"item_type": item_type, "value": normalized, "metadata": {"method": method}})
    if post_data and ("graphql" in normalized.lower() or GRAPHQL_OPERATION_RE.search(post_data)):
        for op in GRAPHQL_OPERATION_RE.finditer(post_data):
            op_kind = post_data[max(0, op.start() - 20):op.start()].lower()
            item_type = "graphql_mutation" if "mutation" in op_kind else "graphql_query"
            items.append({"item_type": item_type, "value": op.group(1), "metadata": {"url": normalized, "method": method}})
    return items


def classify_js_text(asset_url: str, text: str) -> list[dict[str, Any]]:
    signals = extract_js_signals(text)
    items: list[dict[str, Any]] = []
    for key in ("api_urls", "endpoint_paths"):
        for value in signals.get(key, [])[:300]:
            item_type = "graphql_endpoint" if "graphql" in value.lower() or "gql" in value.lower() else "api_endpoint"
            items.append({"item_type": item_type, "value": normalize_url(urljoin(asset_url, value)), "source_url": asset_url, "metadata": {"source": key}})
    for op in GRAPHQL_OPERATION_RE.finditer(text):
        prefix = text[max(0, op.start() - 25):op.start()].lower()
        item_type = "graphql_mutation" if "mutation" in prefix else "graphql_query"
        items.append({"item_type": item_type, "value": op.group(1), "source_url": asset_url, "metadata": {"source": "graphql_operation"}})
    for match in FEATURE_FLAG_RE.finditer(text):
        items.append({"item_type": "feature_flag", "value": match.group(0), "source_url": asset_url, "metadata": {"source": "feature_flag"}})
    for match in ROUTE_LITERAL_RE.finditer(text):
        items.append({"item_type": "frontend_route", "value": match.group(1), "source_url": asset_url, "metadata": {"source": "route_literal"}})
    for value in signals.get("tokens_or_secret_like_strings", [])[:80]:
        digest = hashlib.sha256(value.encode()).hexdigest()
        items.append({"item_type": "secret_like", "value": digest, "source_url": asset_url, "metadata": {"redacted": True, "prefix": value[:24]}})
    for value in signals.get("sensitive_terms", [])[:120]:
        items.append({"item_type": "sensitive_keyword", "value": value.lower(), "source_url": asset_url, "metadata": {"source": "keyword"}})
    return items


class CdpClient:
    def __init__(self, ws_url: str) -> None:
        self.ws_url = ws_url
        self.session: aiohttp.ClientSession | None = None
        self.ws: aiohttp.ClientWebSocketResponse | None = None
        self.next_id = 0
        self.pending: dict[int, asyncio.Future] = {}
        self.events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.reader_task: asyncio.Task | None = None

    async def __aenter__(self) -> "CdpClient":
        self.session = aiohttp.ClientSession()
        self.ws = await self.session.ws_connect(self.ws_url, timeout=15)
        self.reader_task = asyncio.create_task(self._reader())
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self.reader_task:
            self.reader_task.cancel()
        if self.ws:
            await self.ws.close()
        if self.session:
            await self.session.close()

    async def _reader(self) -> None:
        assert self.ws is not None
        async for msg in self.ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            payload = json.loads(msg.data)
            if "id" in payload and payload["id"] in self.pending:
                future = self.pending.pop(payload["id"])
                if not future.done():
                    future.set_result(payload)
            elif "method" in payload:
                await self.events.put(payload)

    async def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = 10) -> dict[str, Any]:
        self.next_id += 1
        msg_id = self.next_id
        future = asyncio.get_running_loop().create_future()
        self.pending[msg_id] = future
        assert self.ws is not None
        await self.ws.send_json({"id": msg_id, "method": method, "params": params or {}})
        try:
            payload = await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self.pending.pop(msg_id, None)
            return {}
        return payload.get("result") or {}


async def wait_for_json(url: str, timeout: float = 12) -> Any:
    deadline = asyncio.get_running_loop().time() + timeout
    async with aiohttp.ClientSession() as session:
        while asyncio.get_running_loop().time() < deadline:
            try:
                async with session.get(url, timeout=2) as resp:
                    if resp.status == 200:
                        return await resp.json(content_type=None)
            except Exception:
                pass
            await asyncio.sleep(0.25)
    raise TimeoutError(url)


async def create_page(port: int) -> str:
    # Start without target traffic so authentication can be installed before the
    # first request. An unauthenticated navigation can otherwise race with CDP
    # cookie injection and replace a valid session with logged-out cookies.
    encoded = "about:blank"
    async with aiohttp.ClientSession() as session:
        endpoint = f"http://127.0.0.1:{port}/json/new?{encoded}"
        for method in ("put", "get"):
            request = getattr(session, method)
            try:
                async with request(endpoint, timeout=5) as resp:
                    if resp.status >= 400:
                        continue
                    payload = await resp.json(content_type=None)
                    if payload.get("webSocketDebuggerUrl"):
                        return payload["webSocketDebuggerUrl"]
            except Exception:
                continue
        pages = await wait_for_json(f"http://127.0.0.1:{port}/json/list", timeout=5)
        if pages:
            return pages[0]["webSocketDebuggerUrl"]
    raise RuntimeError("unable to create chromium devtools page")


async def run_browser_monitor(config: dict[str, Any]) -> dict[str, Any]:
    start_url = str(config.get("start_url") or "").strip()
    if not start_url:
        raise ValueError("start_url is required")
    auth_type = str(config.get("auth_type") or "none").lower()
    extra_routes = config.get("extra_routes") or []
    if isinstance(extra_routes, str):
        extra_routes = [line.strip() for line in extra_routes.splitlines() if line.strip()]
    max_seconds = max(10, min(int(config.get("max_seconds") or 45), 180))
    chrome = os.getenv("CHROME_PATH", "/usr/bin/chromium")
    port = find_free_port()
    user_data_dir = tempfile.mkdtemp(prefix="recon-monitor-chrome-")
    args = [
        chrome,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "about:blank",
    ]
    process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    scripts: dict[str, dict[str, Any]] = {}
    requests: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    auth_report: dict[str, Any] = {"status": "not_required" if auth_type == "none" else "unchecked", "evidence": {}}
    try:
        await wait_for_json(f"http://127.0.0.1:{port}/json/version")
        ws_url = await create_page(port)
        async with CdpClient(ws_url) as cdp:
            await cdp.call("Network.enable", {"maxResourceBufferSize": 20_000_000, "maxTotalBufferSize": 100_000_000})
            await cdp.call("Page.enable")
            await cdp.call("Runtime.enable")
            if auth_type == "cookie":
                cookie_value = resolve_secret_ref(config.get("cookie_secret_ref"))
                cookies = parse_cookie_header(cookie_value, start_url)
                if cookies:
                    await cdp.call("Network.setCookies", {"cookies": cookies})

            async def consume_events() -> None:
                request_meta: dict[str, dict[str, Any]] = {}
                while True:
                    event = await cdp.events.get()
                    method = event.get("method")
                    params = event.get("params") or {}
                    if method == "Network.requestWillBeSent":
                        req = params.get("request") or {}
                        request_id = params.get("requestId")
                        request_meta[request_id] = {"url": req.get("url"), "method": req.get("method"), "postData": req.get("postData")}
                        requests.append({"url": req.get("url"), "method": req.get("method"), "resource_type": params.get("type"), "post_data": req.get("postData")})
                        items.extend(classify_request(req.get("url") or "", req.get("method") or "GET", req.get("postData")))
                    elif method == "Network.responseReceived":
                        response = params.get("response") or {}
                        request_id = params.get("requestId")
                        meta = request_meta.get(request_id, {})
                        url = response.get("url") or meta.get("url") or ""
                        if looks_like_js_url(url) or params.get("type") == "Script":
                            scripts.setdefault(url, {}).update({"url": url, "status": response.get("status"), "mime_type": response.get("mimeType"), "request_id": request_id})
                    elif method == "Network.loadingFinished":
                        request_id = params.get("requestId")
                        target = next((value for value in scripts.values() if value.get("request_id") == request_id), None)
                        if not target:
                            continue
                        body_payload = await cdp.call("Network.getResponseBody", {"requestId": request_id}, timeout=5)
                        body = body_payload.get("body") or ""
                        if body_payload.get("base64Encoded"):
                            body = base64.b64decode(body).decode("utf-8", errors="ignore")
                        target["sha256"] = hashlib.sha256(body.encode()).hexdigest()
                        target["size_bytes"] = len(body.encode())
                        target["body"] = body
                        items.extend(classify_js_text(target["url"], body))
                        for script_url in extract_script_urls_from_html(start_url, body):
                            items.append({"item_type": "js_reference", "value": normalize_url(script_url), "source_url": target["url"], "metadata": {"source": "script_url"}})

            consumer = asyncio.create_task(consume_events())
            urls = [start_url, *[urljoin(start_url, item) for item in extra_routes]]
            if auth_type == "login":
                login_url = str(config.get("login_url") or start_url)
                urls = [login_url, *urls]
            for index, url in enumerate(urls):
                await cdp.call("Page.navigate", {"url": url}, timeout=15)
                await asyncio.sleep(min(5, max_seconds / max(1, len(urls))))
                if index == 0 and auth_type == "login":
                    email = str(config.get("login_email") or "")
                    password = resolve_secret_ref(config.get("password_secret_ref"))
                    user_sel = str(config.get("username_selector") or "input[type=email],input[name=email],input[name=username],input#email")
                    pass_sel = str(config.get("password_selector") or "input[type=password],input[name=password],input#password")
                    submit_sel = str(config.get("submit_selector") or "button[type=submit],input[type=submit]")
                    script = f"""
                    (() => {{
                      const user = document.querySelector({json.dumps(user_sel)});
                      const pass = document.querySelector({json.dumps(pass_sel)});
                      if (user) {{ user.focus(); user.value = {json.dumps(email)}; user.dispatchEvent(new Event('input', {{bubbles:true}})); }}
                      if (pass) {{ pass.focus(); pass.value = {json.dumps(password)}; pass.dispatchEvent(new Event('input', {{bubbles:true}})); }}
                      const btn = document.querySelector({json.dumps(submit_sel)});
                      if (btn) btn.click();
                      return {{user: !!user, pass: !!pass, submit: !!btn}};
                    }})()
                    """
                    await cdp.call("Runtime.evaluate", {"expression": script, "awaitPromise": False}, timeout=5)
                    await asyncio.sleep(8)
            await asyncio.sleep(max(3, min(12, max_seconds / 3)))
            check_url = str(config.get("auth_check_url") or "").strip()
            check_selector = str(config.get("auth_check_selector") or "").strip()
            check_text = str(config.get("auth_check_text") or "").strip()
            failure_text = str(config.get("auth_failure_text") or "").strip()
            if check_url:
                await cdp.call("Page.navigate", {"url": urljoin(start_url, check_url)}, timeout=15)
                await asyncio.sleep(4)
            if auth_type != "none" or check_selector or check_text or failure_text:
                expression = f"""
                (() => {{
                  const selector = {json.dumps(check_selector)};
                  const successText = {json.dumps(check_text)};
                  const failureText = {json.dumps(failure_text)};
                  const body = document.body ? document.body.innerText || "" : "";
                  const href = location.href;
                  const selectorMatched = selector ? !!document.querySelector(selector) : false;
                  const successTextMatched = successText ? body.includes(successText) : false;
                  const failureTextMatched = failureText ? body.includes(failureText) : false;
                  const looksLogin = /login|signin|sign-in|auth/.test(href.toLowerCase());
                  return {{href, selectorMatched, successTextMatched, failureTextMatched, looksLogin}};
                }})()
                """
                eval_payload = await cdp.call(
                    "Runtime.evaluate",
                    {"expression": expression, "returnByValue": True},
                    timeout=5,
                )
                evidence = ((eval_payload.get("result") or {}).get("value") or {}) if eval_payload else {}
                status = "unchecked"
                if failure_text and evidence.get("failureTextMatched"):
                    status = "failed"
                elif check_selector and not evidence.get("selectorMatched"):
                    status = "failed"
                elif check_text and not evidence.get("successTextMatched"):
                    status = "failed"
                elif evidence.get("looksLogin") and auth_type != "none" and not (check_selector or check_text):
                    status = "likely_expired"
                elif check_selector or check_text or failure_text:
                    status = "ok"
                elif auth_type != "none":
                    status = "ok"
                auth_report = {"status": status, "evidence": evidence}
            consumer.cancel()
    finally:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
        shutil.rmtree(user_data_dir, ignore_errors=True)

    deduped_items: dict[str, dict[str, Any]] = {}
    for item in items:
        value = normalize_url(str(item.get("value") or "").strip()) if str(item.get("value") or "").startswith(("http://", "https://")) else str(item.get("value") or "").strip()
        if not value:
            continue
        item_type = str(item.get("item_type") or "unknown")
        key = hashlib.sha256(f"{item_type}|{value}".encode()).hexdigest()
        deduped_items[key] = {**item, "item_type": item_type, "value": value, "item_key": key, "risk": risk_for_item(item_type, value)}
    return {
        "start_url": start_url,
        "scripts": [{k: v for k, v in script.items() if k != "body"} for script in scripts.values()],
        "requests": requests[:1000],
        "items": list(deduped_items.values()),
        "auth": auth_report,
    }
