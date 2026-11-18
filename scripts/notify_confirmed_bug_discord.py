#!/usr/bin/env python3
"""Send one redacted Discord alert for a confirmed, unique bug finding."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml


DEFAULT_CONFIG = Path("/root/enhanced_recon_framework/config.yaml")
DEFAULT_LEDGER = Path(
    "/root/enhanced_recon_framework/exports/notifications/discord_confirmed_bug_alerts.jsonl"
)


def clean(value: Any, limit: int) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    text = re.sub(r"(?i)(authorization\s*:\s*)([^\s,;]+)", r"\1[redacted]", text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[redacted]", text)
    text = re.sub(
        r"(?i)((?:cookie|set-cookie|password|passwd|secret|api[_-]?key|token)\s*[=:]\s*)([^\s,;]+)",
        r"\1[redacted]",
        text,
    )
    text = re.sub(
        r"https://(?:discord(?:app)?\.com)/api/webhooks/[^\s)]+",
        "[redacted Discord webhook]",
        text,
        flags=re.IGNORECASE,
    )
    return text[:limit] or "Not provided"


def read_env_value(env_path: Path, name: str) -> str:
    if not env_path.exists():
        return ""
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() != name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        return value.strip()
    return ""


def load_webhook(config_path: Path) -> tuple[str, str]:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    scan = raw.get("scan") or {}
    alerts = raw.get("alerts") or {}
    discord = alerts.get("discord") or {}

    candidates = (
        ("scan.codex_worker_discord_alert_webhook_url", scan.get("codex_worker_discord_alert_webhook_url")),
        ("alerts.discord.webhook_url", discord.get("webhook_url")),
        ("DISCORD_WEBHOOK_URL", os.getenv("DISCORD_WEBHOOK_URL")),
        (".env.DISCORD_WEBHOOK_URL", read_env_value(config_path.parent / ".env", "DISCORD_WEBHOOK_URL")),
    )
    for source, value in candidates:
        webhook = str(value or "").strip()
        if webhook:
            parsed = urlparse(webhook)
            host = (parsed.hostname or "").lower()
            if parsed.scheme != "https" or host not in {"discord.com", "discordapp.com"}:
                raise ValueError(f"Discord webhook from {source} has an unexpected origin")
            if not parsed.path.startswith("/api/webhooks/"):
                raise ValueError(f"Discord webhook from {source} has an unexpected path")
            return webhook, source
    raise ValueError("No Discord webhook is configured")


def build_key(args: argparse.Namespace) -> str:
    if args.dedupe_key:
        material = clean(args.dedupe_key, 1000).lower()
    else:
        material = "\n".join(
            clean(value, 1000).lower()
            for value in (
                args.program,
                args.target,
                args.title,
                args.vulnerability_class,
                args.endpoint,
            )
        )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def already_sent_and_lock(ledger_path: Path, finding_key: str):
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    handle = ledger_path.open("a+", encoding="utf-8")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    handle.seek(0)
    for line in handle:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("finding_key") == finding_key and row.get("status") == "sent":
            return handle, True
    return handle, False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", default="Unspecified program")
    parser.add_argument("--target", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--severity", default="Unrated")
    parser.add_argument("--vulnerability-class", default="Unspecified")
    parser.add_argument("--endpoint", default="Not provided")
    parser.add_argument("--summary", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--dedupe-key")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        webhook, source = load_webhook(args.config)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Discord alert configuration error: {exc}", file=sys.stderr)
        return 2

    finding_key = build_key(args)
    if args.dry_run:
        print(
            json.dumps(
                {
                    "configured": True,
                    "config_source": source,
                    "finding_key": finding_key[:12],
                    "would_send": True,
                },
                sort_keys=True,
            )
        )
        return 0

    ledger, duplicate = already_sent_and_lock(args.ledger, finding_key)
    try:
        if duplicate:
            print(json.dumps({"status": "duplicate_skipped", "finding_key": finding_key[:12]}))
            return 0

        fields = [
            {"name": "Program", "value": clean(args.program, 1024), "inline": True},
            {"name": "Target", "value": clean(args.target, 1024), "inline": True},
            {"name": "Severity", "value": clean(args.severity, 1024), "inline": True},
            {
                "name": "Class",
                "value": clean(args.vulnerability_class, 1024),
                "inline": True,
            },
            {"name": "Endpoint", "value": clean(args.endpoint, 1024), "inline": False},
            {"name": "Verified impact", "value": clean(args.summary, 1024), "inline": False},
            {"name": "Evidence", "value": clean(args.evidence, 1024), "inline": False},
        ]
        payload = {
            "username": "Recon Codex",
            "allowed_mentions": {"parse": []},
            "embeds": [
                {
                    "title": clean(f"Confirmed bug: {args.title}", 256),
                    "description": "A finding passed the confirmed-finding gate. The hunt is continuing.",
                    "color": 0xD93636,
                    "fields": fields,
                    "footer": {"text": f"Unique finding {finding_key[:12]}"},
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
            ],
        }
        separator = "&" if "?" in webhook else "?"
        request = Request(
            f"{webhook}{separator}wait=true",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Recon-Codex-Finding-Alert/1.0"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=15) as response:
                status = response.status
            if not 200 <= status < 300:
                raise RuntimeError(f"Discord returned HTTP {status}")
        except HTTPError as exc:
            print(f"Discord alert failed with HTTP {exc.code}", file=sys.stderr)
            return 3
        except (URLError, TimeoutError, RuntimeError) as exc:
            print(f"Discord alert failed: {type(exc).__name__}", file=sys.stderr)
            return 3

        ledger.seek(0, os.SEEK_END)
        ledger.write(
            json.dumps(
                {
                    "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "finding_key": finding_key,
                    "status": "sent",
                    "program": clean(args.program, 200),
                    "target": clean(args.target, 300),
                    "title": clean(args.title, 300),
                    "evidence": clean(args.evidence, 500),
                },
                sort_keys=True,
            )
            + "\n"
        )
        ledger.flush()
        os.fsync(ledger.fileno())
        print(json.dumps({"status": "sent", "finding_key": finding_key[:12]}))
        return 0
    finally:
        fcntl.flock(ledger.fileno(), fcntl.LOCK_UN)
        ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
