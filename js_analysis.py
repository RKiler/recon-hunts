from __future__ import annotations

import re
import json
from html import unescape
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse


ABSOLUTE_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
PATH_CHARS = r"A-Za-z0-9._~:%@${}\[\]-"
QUERY_CHARS = r"A-Za-z0-9=&_.~:%@${}\[\],-"
PATH_RE = re.compile(rf"(?<![:A-Za-z0-9])/(?:[{PATH_CHARS}]+/){{0,12}}[{PATH_CHARS}]*(?:\?[{QUERY_CHARS}]+)?")
RELATIVE_ROUTE_RE = re.compile(rf"\b(?:api|v[0-9]+|graphql|auth|oauth|admin|users?|accounts?|orgs?|teams?|billing|webhooks?|callbacks?|sessions?)(?:/[{PATH_CHARS}]+){{1,12}}(?:\?[{QUERY_CHARS}]+)?", re.I)
QUOTED_ENDPOINT_RE = re.compile(r'''(?:"([^"\r\n]{1,240})"|'([^'\r\n]{1,240})'|`([^`\r\n]{1,240})`)''')
GRAPHQL_RE = re.compile(r"\b(?:graphql|gql|query|mutation|subscription|fragment|__schema|__typename)\b", re.I)
AUTH_RE = re.compile(
    r"\b(?:auth|authorization|bearer|login|logout|signup|signin|oauth|sso|jwt|token|refresh[_-]?token|access[_-]?token|password|passwd|apikey|api[_-]?key|secret)\b",
    re.I,
)
SECRET_RE = re.compile(
    r"(?:"
    r"(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|refresh[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{8,}['\"]"
    r"|AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_\-]{20,}"
    r"|sk_(?:live|test)_[0-9A-Za-z]{16,}"
    r"|gh[pousr]_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_\-]{20,}"
    r"|hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"
    r"|discord(?:app)?\.com/api/webhooks/[0-9]{15,}/[A-Za-z0-9._-]{20,}"
    r"|https://[^\"'\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\"'\s]*"
    r"|-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
    r"|Bearer\s+[A-Za-z0-9._\-+/=]{12,}"
    r")",
    re.I,
)
DOM_SINK_RE = re.compile(
    r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|eval|new\s+Function|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"])\b",
    re.I,
)
POSTMESSAGE_RE = re.compile(r"\b(?:postMessage|addEventListener\s*\(\s*['\"]message['\"]|onmessage\b)\b", re.I)
MESSAGE_RECEIVER_RE = re.compile(
    r"(?:addEventListener\s*\(\s*['\"]message['\"]|\bonmessage\s*=)",
    re.I,
)
MESSAGE_DATA_RE = re.compile(
    r"\b(?:event|evt|message|msg|e)\s*\.\s*data\b|\bdata\s*\[\s*['\"](?:url|html|content|payload|command|action)['\"]\s*\]",
    re.I,
)
STORAGE_RE = re.compile(r"\b(?:localStorage|sessionStorage|indexedDB|document\.cookie)\b", re.I)
FETCH_XHR_RE = re.compile(
    r"\b(?:fetch\s*\(|XMLHttpRequest|axios(?:\.[a-z]+)?\s*\(|\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH)|\$.ajax\s*\()",
    re.I,
)
LOCATION_SOURCE_RE = re.compile(
    r"\b(?:location(?:\.href|\.search|\.hash|\.pathname)?|document\.URL|documentURI|window\.name)\b",
    re.I,
)
SENSITIVE_TERM_RE = re.compile(
    r"\b(?:webhook|admin|invite|invitation|export|role|roles|permission|permissions|impersonat(?:e|ion)|tenant|organization|org|billing|user[_-]?management)\b",
    re.I,
)
GRAPHQL_ENDPOINT_RE = re.compile(r"/graphql\b|graphql", re.I)
API_HINT_RE = re.compile(rf"/api(?:/[{PATH_CHARS}]+)*|/v[0-9]+(?:/[{PATH_CHARS}]+)*", re.I)
API_SUBSTRING_RE = re.compile(rf"/(?:api|graphql|oauth|auth|login|logout|signup|signin|admin|invite|role|permission|export|import|webhook|callback|token|session|profile|account|user|member|org|team|billing|payment|checkout|order|search|report|setting|notification|upload|download|file|attachment)(?:/[{PATH_CHARS}]+){{0,12}}(?:\?[{QUERY_CHARS}]+)?", re.I)
ROUTE_HINT_RE = re.compile(
    r"(?:^|/)(?:api|graphql|rest|rpc|service|services|auth|oauth|login|logout|signup|signin|admin|user|users|account|accounts|invite|invites|role|roles|permission|permissions|export|imports?|webhook|hooks|callback|callbacks|token|tokens|session|sessions|profile|profiles|org|organization|organizations|team|teams|member|members|billing|payments?|checkout|cart|orders?|search|reports?|settings|notifications?|upload|download|files?|attachments?)(?:/|$)",
    re.I,
)
EXTENSION_NOISE_RE = re.compile(r"\.(?:m?js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|html?)$", re.I)
PATH_KEYWORD_RE = re.compile(
    r"(?:^|[_/\-.])(?:api|graphql|auth|oauth|login|logout|signup|signin|admin|invite|role|permission|export|import|webhook|callback|token|session|profile|account|user|member|org|team|billing|payment|checkout|order|search|report|setting|notification|upload|download|file|attachment)(?:s)?(?:$|[_/\-.])",
    re.I,
)
REGEX_LIKE_RE = re.compile(r"[()^|*+]|/[gimsuy]{1,6}$")
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
INLINE_JS_URL_RE = re.compile(r"https?://[^\s\"']+\.m?js(?:[?#][^\s\"']*)?|(?<![A-Za-z0-9._~:%-])/[^\"'\s]+\.m?js(?:[?#][^\s\"']*)?", re.I)
RELATIVE_JS_IMPORT_RE = re.compile(
    r"""
    (?:
        \bimport\s*\(\s*["'](?P<dynamic>\.{1,2}/[^"']+\.m?js(?:[?#][^"']*)?)["']
      | \bfrom\s*["'](?P<from>\.{1,2}/[^"']+\.m?js(?:[?#][^"']*)?)["']
      | \bimport\s*["'](?P<side_effect>\.{1,2}/[^"']+\.m?js(?:[?#][^"']*)?)["']
    )
    """,
    re.I | re.X,
)
SOURCE_MAPPING_URL_RE = re.compile(r"sourceMappingURL=([^\s*]+)", re.I)
JS_MAP_URL_RE = re.compile(r"https?://[^\s\"']+\.m?js\.map(?:[?#][^\s\"']*)?|/[^\"'\s]+\.m?js\.map(?:[?#][^\s\"']*)?", re.I)
NEXT_ROUTE_RE = re.compile(r"(?:(?:page|route|path|href|as)\s*:\s*)[\"'`]([^\"'`]{1,240})[\"'`]", re.I)
CONCAT_PATH_RE = re.compile(r"[\"'`]((?:/|https?://)[^\"'`]{1,160})[\"'`]\s*\+", re.I)
ROUTE_OBJECT_RE = re.compile(r"(?:route|pathname|endpoint|url|uri|baseURL|baseUrl|apiUrl|api_url)\s*[:=]\s*[\"'`]([^\"'`]{1,240})[\"'`]", re.I)
FETCH_LITERAL_RE = re.compile(r"\b(?:fetch|axios(?:\.[a-z]+)?|request|get|post|put|patch|delete)\s*\(\s*[\"'`]([^\"'`]{1,240})[\"'`]", re.I)
URL_CONSTRUCTOR_RE = re.compile(r"\bnew\s+URL\s*\(\s*[\"'`]([^\"'`]{1,240})[\"'`]", re.I)
HTTP_CLIENT_CONFIG_RE = re.compile(r"(?:url|path|pathname|route|endpoint|href)\s*:\s*[\"'`]([^\"'`]{1,240})[\"'`]", re.I)
OPENAPI_LITERAL_RE = re.compile(r"[\"'`]((?:/|https?://)[^\"'`]*(?:swagger|openapi|api-docs)[^\"'`]*)[\"'`]", re.I)
GRAPHQL_LITERAL_RE = re.compile(r"[\"'`]((?:/|https?://)[^\"'`]*(?:graphql|gql)[^\"'`]*)[\"'`]", re.I)
GRAPHQL_OPERATION_RE = re.compile(
    r"\b(query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)\b",
    re.I,
)
GRAPHQL_ANONYMOUS_OPERATION_RE = re.compile(r"\b(query|mutation|subscription)\s*(?:\([^)]*\))?\s*\{", re.I)
GRAPHQL_PERSISTED_QUERY_RE = re.compile(
    r"(?:sha256Hash|persistedQuery|operationId)\s*[:=]\s*[\"'`]([A-Fa-f0-9]{32,128})[\"'`]",
    re.I,
)
GRAPHQL_CLIENT_ENDPOINT_RE = re.compile(
    r"(?:ApolloClient|HttpLink|BatchHttpLink|createHttpLink|GraphQLClient|graphqlRequest)[\s\S]{0,500}?"
    r"(?:uri|url|endpoint)\s*:\s*[\"'`]([^\"'`]{1,240})[\"'`]",
    re.I,
)
GRAPHQL_WEBSOCKET_RE = re.compile(
    r"[\"'`](wss?://[^\"'`]*(?:graphql|gql|subscriptions?)[^\"'`]*)[\"'`]",
    re.I,
)
NEXT_DATA_ROUTE_RE = re.compile(r"[\"'`]((?:/_next/data/)[^\"'`]+\.json(?:\?[^\"'`]*)?)[\"'`]", re.I)

XSS_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:q|query|search|keyword|term|name|title|message|comment|content|body|text|html|template|view|return|next|redirect|redirect_uri|callback)(?:$|[_-])",
    re.I,
)
IDOR_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:id|user|user_id|account|account_id|org|org_id|tenant|tenant_id|project|project_id|workspace|workspace_id|team|team_id|group|group_id|member|member_id|file|file_id|doc|doc_id|document|document_id|order|order_id|invoice|invoice_id|ticket|ticket_id)(?:$|[_-])",
    re.I,
)
SSRF_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:url|uri|dest|destination|redirect|redirect_uri|return|return_to|next|continue|callback|callback_url|endpoint|feed|image|image_url|avatar|link|target|proxy|webhook)(?:$|[_-])",
    re.I,
)


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def normalize_candidate(value: str) -> str:
    value = unescape(value.strip())
    value = value.replace("\\/", "/")
    value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)
    value = value.replace("\\/", "/")
    value = re.sub(r"\s+", "", value)
    return value.rstrip(";,.)]}\"'")


def normalize_contextual_route(value: str) -> str:
    value = normalize_candidate(value)
    if value.startswith(("http://", "https://", "ws://", "wss://", "/")):
        return value
    if RELATIVE_ROUTE_RE.fullmatch(value) or ROUTE_HINT_RE.search(value):
        return f"/{value.lstrip('/')}"
    return value


def is_graphql_candidate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except (TypeError, ValueError):
        return False
    lowered = f"{parsed.path}?{parsed.query}".lower()
    if any(token in lowered for token in ("graphql", "graphiql", "/gql", "playground")):
        return True
    query_names = {name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    return bool(query_names & {"query", "operationname", "extensions"})


def classify_graphql_response(status: int, content_type: str, body: str) -> dict[str, Any]:
    lowered_type = (content_type or "").lower()
    lowered_body = (body or "").lower()
    try:
        payload: Any = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        payload = None

    if isinstance(payload, dict):
        data = payload.get("data")
        errors = payload.get("errors")
        typename = data.get("__typename") if isinstance(data, dict) else None
        if isinstance(typename, str) and typename:
            return {"confidence": "confirmed", "graphql_response": True, "typename": typename}
        if isinstance(errors, list):
            messages = [
                str(item.get("message") or "")
                for item in errors[:5]
                if isinstance(item, dict)
            ]
            marker_text = " ".join(messages).lower()
            if messages and any(
                marker in marker_text
                for marker in (
                    "graphql",
                    "cannot query field",
                    "syntax error",
                    "must provide query",
                    "operation",
                    "validation",
                    "__typename",
                )
            ):
                return {
                    "confidence": "probable",
                    "graphql_response": True,
                    "error_messages": messages[:3],
                }
            if "graphql-response+json" in lowered_type:
                return {"confidence": "probable", "graphql_response": True}

    if status in {401, 403}:
        return {"confidence": "candidate", "graphql_response": False, "auth_gated": True}
    if status == 404:
        return {"confidence": "rejected", "graphql_response": False, "reason": "not_found"}
    if "text/html" in lowered_type and "<html" in lowered_body:
        return {"confidence": "rejected", "graphql_response": False, "reason": "generic_html"}
    if status == 405:
        return {"confidence": "candidate", "graphql_response": False, "reason": "method_not_allowed"}
    return {"confidence": "candidate", "graphql_response": False}


def looks_like_endpoint_candidate(value: str) -> bool:
    if not value or len(value) < 4 or len(value) > 240:
        return False
    if " " in value or value.startswith("//"):
        return False
    if not (value.startswith("/") or value.startswith("http://") or value.startswith("https://")):
        return False
    if value in {"/", "//"}:
        return False
    if value.startswith(("http://", "https://")):
        try:
            path_part = urlparse(value).path
        except (TypeError, ValueError):
            return False
    else:
        path_part = value
    if EXTENSION_NOISE_RE.search(path_part):
        return False
    if any(ch in value for ch in ("<", ">", "|")):
        return False
    if REGEX_LIKE_RE.search(value):
        return False
    if API_HINT_RE.search(value) or GRAPHQL_ENDPOINT_RE.search(value) or ROUTE_HINT_RE.search(value):
        return True
    segments = [segment for segment in value.split("/") if segment]
    if len(segments) >= 2:
        return True
    return bool(PATH_KEYWORD_RE.search(value))


def extract_endpoint_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for regex in (ABSOLUTE_URL_RE, PATH_RE, API_SUBSTRING_RE):
        for match in regex.finditer(text):
            candidate = normalize_candidate(match.group(0))
            if looks_like_endpoint_candidate(candidate):
                candidates.append(candidate)

    for match in QUOTED_ENDPOINT_RE.finditer(text):
        candidate = normalize_contextual_route(next(group for group in match.groups() if group is not None))
        if looks_like_endpoint_candidate(candidate):
            candidates.append(candidate)

    for regex in (
        NEXT_ROUTE_RE,
        CONCAT_PATH_RE,
        ROUTE_OBJECT_RE,
        FETCH_LITERAL_RE,
        URL_CONSTRUCTOR_RE,
        HTTP_CLIENT_CONFIG_RE,
        OPENAPI_LITERAL_RE,
        GRAPHQL_LITERAL_RE,
        NEXT_DATA_ROUTE_RE,
    ):
        for match in regex.finditer(text):
            candidate = normalize_contextual_route(match.group(1))
            if looks_like_endpoint_candidate(candidate):
                candidates.append(candidate)

    return dedupe_keep_order(candidates)


def unique_matches(regex: re.Pattern[str], text: str, limit: int = 200) -> list[str]:
    return dedupe_keep_order([match.group(0) for match in regex.finditer(text)])[:limit]


def safe_urljoin(base_url: str, candidate: str) -> str | None:
    """Resolve a discovered URL without letting malformed JS text abort a scan."""
    try:
        return urljoin(base_url, candidate)
    except (TypeError, ValueError):
        return None


def proximity_count(left: re.Pattern[str], right: re.Pattern[str], text: str, distance: int = 2500) -> int:
    """Count bounded lexical flows without treating file-wide keyword co-occurrence as data flow."""
    left_positions = [match.start() for match in left.finditer(text)]
    right_positions = [match.start() for match in right.finditer(text)]
    if not left_positions or not right_positions:
        return 0
    return sum(
        1
        for position in left_positions
        if any(abs(position - candidate) <= distance for candidate in right_positions)
    )


def extract_js_signals(text: str) -> dict[str, Any]:
    absolute_urls = unique_matches(ABSOLUTE_URL_RE, text)
    endpoint_candidates = extract_endpoint_candidates(text)
    api_urls = [value for value in endpoint_candidates if value.startswith(("http://", "https://"))]
    endpoint_paths = [value for value in endpoint_candidates if value.startswith("/")]
    graphql_operations = [
        {"type": match.group(1).lower(), "name": match.group(2)}
        for match in GRAPHQL_OPERATION_RE.finditer(text)
    ]
    graphql_anonymous_operations = unique_matches(GRAPHQL_ANONYMOUS_OPERATION_RE, text)
    graphql_client_endpoints = dedupe_keep_order(
        normalize_contextual_route(match.group(1))
        for match in GRAPHQL_CLIENT_ENDPOINT_RE.finditer(text)
    )
    graphql_websocket_urls = dedupe_keep_order(
        normalize_contextual_route(match.group(1))
        for match in GRAPHQL_WEBSOCKET_RE.finditer(text)
    )
    dom_source_sink_proximity_count = proximity_count(LOCATION_SOURCE_RE, DOM_SINK_RE, text)
    message_receiver_count = len(list(MESSAGE_RECEIVER_RE.finditer(text)))
    message_data_flow_count = proximity_count(MESSAGE_RECEIVER_RE, MESSAGE_DATA_RE, text)
    message_sensitive_effect_count = sum(
        proximity_count(MESSAGE_RECEIVER_RE, pattern, text)
        for pattern in (DOM_SINK_RE, FETCH_XHR_RE, STORAGE_RE, AUTH_RE)
    )
    return {
        "absolute_urls": absolute_urls,
        "api_urls": api_urls,
        "endpoint_paths": endpoint_paths,
        "graphql_hints": unique_matches(GRAPHQL_RE, text),
        "graphql_operations": graphql_operations[:200],
        "graphql_anonymous_operations": graphql_anonymous_operations[:50],
        "graphql_persisted_query_hashes": dedupe_keep_order(
            match.group(1) for match in GRAPHQL_PERSISTED_QUERY_RE.finditer(text)
        )[:200],
        "graphql_client_endpoints": graphql_client_endpoints[:50],
        "graphql_websocket_urls": graphql_websocket_urls[:50],
        "auth_related_keywords": unique_matches(AUTH_RE, text),
        "tokens_or_secret_like_strings": unique_matches(SECRET_RE, text),
        "dangerous_dom_sinks": unique_matches(DOM_SINK_RE, text),
        "location_sources": unique_matches(LOCATION_SOURCE_RE, text),
        "postmessage_usage": unique_matches(POSTMESSAGE_RE, text),
        "dom_source_sink_proximity_count": dom_source_sink_proximity_count,
        "postmessage_receiver_count": message_receiver_count,
        "postmessage_data_flow_count": message_data_flow_count,
        "postmessage_sensitive_effect_count": message_sensitive_effect_count,
        "storage_usage": unique_matches(STORAGE_RE, text),
        "fetch_xhr_usage": unique_matches(FETCH_XHR_RE, text),
        "sensitive_terms": unique_matches(SENSITIVE_TERM_RE, text),
    }


def extract_script_urls_from_html(base_url: str, html: str) -> list[str]:
    results: list[str] = []
    for match in SCRIPT_SRC_RE.finditer(html):
        joined = safe_urljoin(base_url, match.group(1))
        if joined:
            results.append(joined)
    for match in INLINE_JS_URL_RE.finditer(html):
        joined = safe_urljoin(base_url, match.group(0))
        if joined:
            results.append(joined)
    return dedupe_keep_order([url for url in results if looks_like_js_url(url)])


def extract_js_urls_from_text(base_url: str, text: str) -> list[str]:
    results: list[str] = []
    for match in INLINE_JS_URL_RE.finditer(text):
        joined = safe_urljoin(base_url, match.group(0))
        if joined:
            results.append(joined)
    for match in RELATIVE_JS_IMPORT_RE.finditer(text):
        relative = next((group for group in match.groups() if group), "")
        if relative:
            joined = safe_urljoin(base_url, relative)
            if joined:
                results.append(joined)
    return dedupe_keep_order([url for url in results if looks_like_js_url(url)])


def extract_source_map_urls_from_js(asset_url: str, text: str) -> list[str]:
    results: list[str] = []
    for match in SOURCE_MAPPING_URL_RE.finditer(text):
        value = match.group(1).strip().strip("'\"")
        if value and not value.startswith("data:"):
            joined = safe_urljoin(asset_url, value)
            if joined:
                results.append(joined)
    for match in JS_MAP_URL_RE.finditer(text):
        joined = safe_urljoin(asset_url, match.group(0))
        if joined:
            results.append(joined)
    if not results:
        try:
            parsed = urlparse(asset_url)
        except (TypeError, ValueError):
            return []
        path = parsed.path.lower()
        if path.endswith((".js", ".mjs")):
            results.append(asset_url.split("?", 1)[0].split("#", 1)[0] + ".map")
    return dedupe_keep_order(results)


def extract_text_from_source_map(source_map_text: str) -> str:
    try:
        payload = json.loads(source_map_text)
    except json.JSONDecodeError:
        return ""
    parts: list[str] = []
    sources_content = payload.get("sourcesContent")
    if isinstance(sources_content, list):
        parts.extend(str(item) for item in sources_content if item)
    sources = payload.get("sources")
    if isinstance(sources, list):
        parts.extend(str(item) for item in sources if item)
    names = payload.get("names")
    if isinstance(names, list):
        parts.extend(str(item) for item in names if isinstance(item, str) and "/" in item)
    return "\n".join(parts)


def looks_like_js_url(url: str) -> bool:
    if not isinstance(url, str) or not url or len(url) > 4096:
        return False
    if "\\" in url or any(ord(char) < 32 for char in url):
        return False
    if any(char in url for char in ('"', "'", "`", "<", ">", "{", "}", "(", ")")):
        return False
    try:
        parsed = urlparse(url)
    except (TypeError, ValueError):
        return False
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return False
    if parsed.scheme and not parsed.hostname:
        return False
    if parsed.username or parsed.password:
        return False
    return parsed.path.lower().endswith((".js", ".mjs", ".cjs"))


def classify_parameter_risks(name: str, value: str = "") -> list[str]:
    tags: list[str] = []
    lowered_value = value.lower()
    if XSS_PARAM_RE.search(name):
        tags.append("xss")
    if IDOR_PARAM_RE.search(name):
        tags.append("idor")
    if SSRF_PARAM_RE.search(name):
        tags.append("ssrf")
    if lowered_value.startswith(("http://", "https://")) and "ssrf" not in tags and XSS_PARAM_RE.search(name):
        tags.append("ssrf")
    return tags


def extract_query_parameters(url: str) -> list[dict[str, Any]]:
    try:
        parsed = urlparse(url)
    except (TypeError, ValueError):
        return []
    params = []
    seen = set()
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        params.append(
            {
                "name": name,
                "example_value": value,
                "risk_tags": classify_parameter_risks(name, value),
            }
        )
    return params


def severity_for_param_tags(tags: list[str], name: str = "", value: str = "", path: str = "") -> str:
    tag_set = set(tags)
    lowered_name = name.lower()
    lowered_value = value.lower()
    lowered_path = path.lower()
    if "ssrf" in tag_set and lowered_value.startswith(("http://", "https://")):
        return "high"
    if "ssrf" in tag_set:
        return "high"
    if "idor" in tag_set and any(marker in lowered_path for marker in ("/admin", "/api/", "/users", "/accounts", "/members")):
        return "high"
    if "xss" in tag_set and ("idor" in tag_set or lowered_name in {"html", "template", "redirect", "callback"}):
        return "high"
    if "xss" in tag_set and any(marker in lowered_value for marker in ("<", "%3c", "javascript:")):
        return "high"
    if "xss" in tag_set or "idor" in tag_set:
        return "medium"
    return "info"


def severity_for_js_signals(signals: dict[str, list[str]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if signals["tokens_or_secret_like_strings"]:
        findings.append(
            {
                "finding_type": "js_secret_like_strings",
                "severity": "high",
                "details": {"matches": signals["tokens_or_secret_like_strings"][:20]},
            }
        )
    if signals["dangerous_dom_sinks"]:
        findings.append(
            {
                "finding_type": "js_dom_xss_sinks",
                "severity": "medium",
                "details": {"matches": signals["dangerous_dom_sinks"][:20]},
            }
        )
    if signals["dangerous_dom_sinks"] and signals["location_sources"]:
        findings.append(
            {
                "finding_type": "js_dom_xss_candidate",
                "severity": "high",
                "details": {
                    "sinks": signals["dangerous_dom_sinks"][:20],
                    "sources": signals["location_sources"][:20],
                },
            }
        )
    if signals["sensitive_terms"] and (signals["api_urls"] or signals["endpoint_paths"]):
        findings.append(
            {
                "finding_type": "js_sensitive_admin_surface",
                "severity": "medium",
                "details": {
                    "sensitive_terms": signals["sensitive_terms"][:20],
                    "sample_endpoints": (signals["api_urls"] + signals["endpoint_paths"])[:20],
                },
            }
        )
    return findings
