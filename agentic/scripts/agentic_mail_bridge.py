#!/usr/bin/env python3
"""Small, read-only Gmail IMAP bridge for owned signup verification."""

from __future__ import annotations

import email
import html
import imaplib
import json
import os
import re
import secrets
import socketserver
import subprocess
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit


SOCKET = Path(os.environ.get("AGENTIC_MAIL_SOCKET", "/run/agentic-mail/mail.sock"))
PASSWORD_FILE = Path(os.environ.get("AGENTIC_MAIL_PASSWORD_FILE", "/run/secrets/gmail_app_password"))
ADDRESS = os.environ.get("AGENTIC_MAIL_ADDRESS", "atesting586@gmail.com")
OPEN_SCRIPT = "/app/scripts/agentic_mail_open.cjs"
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$", re.I)
URL_RE = re.compile(r"https://[^\s<>\"']+", re.I)
VERIFY_RE = re.compile(r"(?:verify|verification|confirm|confirmation|activate|activation|register|signup|sign-up|email)", re.I)
UNSAFE_RE = re.compile(r"(?:logout|signout|unsubscribe|delete|remove|cancel|billing|payment|password|reset)", re.I)
LINK_TTL = 600
MAX_EMAILS = 25
MAX_EMAIL_BYTES = 300_000
HANDLES: dict[str, tuple[str, str, float]] = {}


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(html.unescape(value))


def valid_host(host: str) -> bool:
    return bool(HOST_RE.fullmatch(host) and ".." not in host and "." in host)


def matching_link(raw: str, host: str) -> bool:
    try:
        parsed = urlsplit(html.unescape(raw).rstrip(".,;)>"))
        purpose = parsed.path + "?" + parsed.query
        return (parsed.scheme == "https" and parsed.hostname == host and
                not parsed.username and not parsed.password and parsed.port in (None, 443)
                and bool(VERIFY_RE.search(purpose)) and not UNSAFE_RE.search(purpose))
    except ValueError:
        return False


def extract_links(message: email.message.Message, host: str) -> list[str]:
    links = []
    for part in message.walk():
        if part.get_content_maintype() != "text" or part.get_content_type() not in ("text/plain", "text/html"):
            continue
        if part.get_content_disposition() == "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        text = payload[:MAX_EMAIL_BYTES].decode(part.get_content_charset() or "utf-8", errors="replace")
        candidates = URL_RE.findall(text)
        if part.get_content_type() == "text/html":
            parser = LinkParser()
            parser.feed(text)
            candidates.extend(parser.links)
        for candidate in candidates:
            candidate = html.unescape(candidate).rstrip(".,;)>")
            if matching_link(candidate, host) and candidate not in links:
                links.append(candidate)
    return links[:5]


def mailbox():
    password = "".join(PASSWORD_FILE.read_text(encoding="utf-8").split())
    if not re.fullmatch(r"[a-z]{16}", password):
        raise ValueError("App-password file is not in the expected format")
    connection = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=15)
    try:
        connection.login(ADDRESS, password)
        return connection
    except Exception:
        connection.logout()
        raise


def find_messages(host: str, after: datetime) -> list[dict]:
    if not valid_host(host):
        raise ValueError("Invalid exact host")
    now = datetime.now(timezone.utc)
    if after < now - timedelta(hours=1) or after > now + timedelta(minutes=2):
        raise ValueError("Search must start within the past hour")
    connection = mailbox()
    try:
        status, _ = connection.select("INBOX", readonly=True)
        if status != "OK":
            raise RuntimeError("Inbox is unavailable")
        since = after.strftime("%d-%b-%Y")
        status, data = connection.search(None, "SINCE", since)
        if status != "OK":
            raise RuntimeError("Mailbox search failed")
        ids = (data[0] or b"").split()[-MAX_EMAILS:]
        matches = []
        for message_id in reversed(ids):
            status, size_data = connection.fetch(message_id, "(RFC822.SIZE)")
            if status != "OK" or not size_data:
                continue
            match = re.search(rb"RFC822\.SIZE (\d+)", size_data[0] or b"")
            if not match or int(match.group(1)) > MAX_EMAIL_BYTES:
                continue
            status, fetched = connection.fetch(message_id, "(BODY.PEEK[])")
            if status != "OK":
                continue
            chunks = [item for item in fetched if isinstance(item, tuple) and len(item) > 1]
            if not chunks or len(chunks[0][1]) > MAX_EMAIL_BYTES:
                continue
            message = email.message_from_bytes(chunks[0][1])
            try:
                received = parsedate_to_datetime(message.get("Date", ""))
                if received.tzinfo is None:
                    received = received.replace(tzinfo=timezone.utc)
                if received < after or received > now + timedelta(minutes=2):
                    continue
            except (TypeError, ValueError, OverflowError):
                continue
            links = extract_links(message, host)
            if not links:
                continue
            for link in links:
                handle = secrets.token_urlsafe(24)
                HANDLES[handle] = (link, host, time.monotonic() + LINK_TTL)
                matches.append({"handle": handle, "host": host})
            if len(matches) >= 5:
                break
        return matches[:5]
    finally:
        try:
            connection.logout()
        except imaplib.IMAP4.error:
            pass


def handle(request: dict) -> dict:
    action = request.get("action")
    if action == "health":
        return {"ok": True, "mailbox_configured": PASSWORD_FILE.is_file()}
    if action == "check":
        connection = mailbox()
        connection.logout()
        return {"ok": True, "mailbox": ADDRESS}
    if action == "find":
        after = datetime.fromisoformat(str(request.get("after", "")).replace("Z", "+00:00"))
        if after.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        matches = find_messages(str(request.get("host", "")).lower(), after.astimezone(timezone.utc))
        return {"ok": True, "matches": matches}
    if action == "open":
        if request.get("confirm_owned_signup") is not True:
            raise ValueError("Owned signup confirmation is required")
        handle_id = str(request.get("handle", ""))
        host = str(request.get("host", "")).lower()
        item = HANDLES.pop(handle_id, None)
        if not item or item[1] != host or item[2] < time.monotonic():
            raise ValueError("Verification handle is missing or expired")
        link = item[0]
        if not matching_link(link, host):
            raise ValueError("Verification link left the exact host")
        result = subprocess.run(["node", OPEN_SCRIPT], input=json.dumps({"url": link, "host": host}),
                                text=True, capture_output=True, timeout=35, check=False)
        if result.returncode != 0:
            raise RuntimeError("Visible-browser verification could not complete")
        return json.loads(result.stdout)
    raise ValueError("Unsupported action")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline(4097)
        if len(raw) > 4096:
            response = {"ok": False, "error": "Request too large"}
        else:
            try:
                response = handle(json.loads(raw))
            except (ValueError, OSError, imaplib.IMAP4.error, RuntimeError, subprocess.TimeoutExpired) as exc:
                response = {"ok": False, "error": type(exc).__name__}
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


class Server(socketserver.UnixStreamServer):
    allow_reuse_address = True


if __name__ == "__main__":
    SOCKET.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if SOCKET.exists():
        SOCKET.unlink()
    with Server(str(SOCKET), Handler) as server:
        SOCKET.chmod(0o600)
        server.serve_forever()
