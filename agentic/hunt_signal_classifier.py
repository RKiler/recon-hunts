"""Rank recon routes as test candidates, never as verified vulnerabilities."""

from __future__ import annotations

import re
from urllib.parse import urlsplit


PATH_TOKEN = re.compile(r"[a-z0-9]+", re.I)
LONG_SEGMENT = re.compile(r"(?<=/)[A-Za-z0-9_-]{33,}(?=/|$)")
OBJECT_PATH = {"user", "users", "account", "accounts", "org", "orgs", "team", "teams",
               "project", "projects", "member", "members", "file", "files", "document",
               "documents", "report", "reports", "export", "exports", "invoice", "invoices",
               "workspace", "workspaces", "bot", "bots", "space", "spaces"}
URL_PARAMS = {"url", "uri", "target", "destination", "sourceurl", "imageurl", "webhookurl",
              "callbackurl", "feedurl", "remoteurl", "endpointurl"}
FILE_PARAMS = {"file", "filename", "filepath", "path", "document", "template", "resource",
               "log", "folder", "directory", "attachment"}
IDENTITY_PARAMS = {"userid", "accountid", "orgid", "organizationid", "tenantid", "teamid",
                   "projectid", "workspaceid", "memberid", "ownerid"}
REDIRECT_PARAMS = {"redirect", "redirecturi", "returnto", "returnurl", "next", "continue",
                   "callback", "destination"}
SEARCH_PARAMS = {"query", "filter", "sort", "orderby", "search", "where", "criteria"}
HTML_PARAMS = {"html", "markdown", "content", "message", "comment", "template"}


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def route_hint(value: str) -> str | None:
    """Keep only bounded relative paths; discard URLs and query values."""
    value = str(value).strip()
    if not value.startswith("/") or value.startswith("//") or any(ord(char) < 32 for char in value):
        return None
    try:
        path = urlsplit(value).path
    except ValueError:
        return None
    if not path or len(path) > 240:
        return None
    return LONG_SEGMENT.sub("{id}", path)


def classify_route(path: str, params: list[str] | tuple[str, ...] = (),
                   method: str = "") -> list[tuple[str, int, str]]:
    """Return hypothesis classes with conservative scores and concrete reasons."""
    try:
        path = urlsplit(str(path or "")).path.lower()
    except ValueError:
        return []
    segments = set(PATH_TOKEN.findall(path))
    names = {normalize_name(name) for name in params if name}
    write = str(method).upper() in {"POST", "PUT", "PATCH", "DELETE"}
    matches: list[tuple[str, int, str]] = []

    def add(family: str, score: int, reason: str) -> None:
        matches.append((family, score, reason))

    if names & URL_PARAMS and segments & {"fetch", "import", "preview", "render", "proxy", "webhook", "image", "connect", "url"}:
        add("ssrf", 9, "URL-like input on server-fetching workflow")
    elif names & URL_PARAMS:
        add("ssrf", 5, "URL-like parameter; server-side fetch unproven")
    if names & FILE_PARAMS and segments & {"read", "download", "view", "preview", "template", "render", "file", "files", "logs", "export", "resource"}:
        add("lfi_path_traversal", 9, "File/path input on read or render workflow")
    elif names & FILE_PARAMS:
        add("lfi_path_traversal", 5, "File/path parameter; filesystem use unproven")
    if segments & {"template", "render", "compile", "email", "pdf"} and names & {"template", "html", "content", "view"}:
        add("ssti", 8, "Template-like input on rendering workflow")
    if segments & {"exec", "execute", "command", "shell", "build", "deploy", "script", "runner"}:
        add("rce_command_injection", 6, "Execution-capable workflow; input control unproven")
    if segments & {"oauth", "authorize", "sso", "saml", "callback", "token", "identity"}:
        add("oauth_sso", 7 if names & (REDIRECT_PARAMS | {"state", "code", "clientid"}) else 5,
            "Identity flow with callback/state boundary")
    if segments & {"reset", "recover", "recovery", "invite", "verify", "link", "session", "sessions"}:
        add("account_takeover", 6, "Account-lifecycle or session transition")
    if names & REDIRECT_PARAMS:
        add("open_redirect", 5, "Client-supplied redirect destination")
    if names & HTML_PARAMS and segments & {"render", "preview", "comment", "message", "editor", "content", "markdown"}:
        add("xss", 7, "User content on an HTML-rendering workflow")
    if names & SEARCH_PARAMS and segments & {"search", "query", "filter", "report", "export"}:
        add("injection", 5, "Search/filter input reaching a query workflow")
    if names & IDENTITY_PARAMS or segments & OBJECT_PATH and any(
        token in segments for token in {"admin", "permission", "permissions", "member", "members", "export", "download"}
    ):
        add("authorization", 7 if write else 6, "Object or tenant selector on sensitive workflow")
    if "graphql" in segments or "gql" in segments:
        add("graphql", 5, "GraphQL route; operation and authorization unknown")
    if segments & {"upload", "uploads", "import", "imports"}:
        add("upload_import", 5, "Upload/import processing boundary")
    return sorted(matches, key=lambda item: item[1], reverse=True)
