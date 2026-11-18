#!/usr/bin/env python3
"""Send a redacted Discord alert when Codex needs human login action."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

import yaml

from notify_confirmed_bug_discord import clean, load_webhook


DEFAULT_CONFIG = Path("/root/enhanced_recon_framework/config.yaml")
DEFAULT_LEDGER = Path(
    "/root/enhanced_recon_framework/exports/notifications/discord_captcha_alerts.jsonl"
)
NOVNC_URL = "http://127.0.0.1:6080/vnc.html?autoconnect=true&resize=scale"


def recent_duplicate(handle, key: str, window_minutes: int) -> bool:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=window_minutes)
    handle.seek(0)
    for line in handle:
        try:
            row = json.loads(line)
            when = dt.datetime.fromisoformat(row["sent_at"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        if row.get("dedupe_key") == key and row.get("status") == "sent" and when >= cutoff:
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--account-alias", required=True)
    parser.add_argument("--tmux-session", default="unknown")
    parser.add_argument("--reason", default="CAPTCHA or manual login challenge detected")
    parser.add_argument("--wait-minutes", type=int, default=45)
    parser.add_argument("--title", default=None)
    parser.add_argument("--description", default=None)
    parser.add_argument("--footer-prefix", default="CAPTCHA request")
    parser.add_argument("--hide-tunnel", action="store_true")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        webhook, source = load_webhook(args.config)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"Discord CAPTCHA alert configuration error: {error}", file=sys.stderr)
        return 2

    program = clean(args.program, 120)
    target = clean(args.target, 200)
    account = clean(args.account_alias, 80)
    tmux_session = clean(args.tmux_session, 80)
    reason = clean(args.reason, 500)
    title = clean(
        args.title or f"Human login required: {program}", 256,
    )
    description = clean(
        args.description or (
            "Codex paused at a CAPTCHA, MFA, consent, or manual login challenge. "
            "Use the existing SSH tunnel; do not send credentials in Discord."
        ),
        500,
    )
    footer_prefix = clean(args.footer_prefix, 80)
    wait_minutes = 0 if args.wait_minutes == 0 else max(5, min(args.wait_minutes, 120))
    dedupe_key = hashlib.sha256(
        f"{program}|{target}|{account}|{tmux_session}".encode("utf-8")
    ).hexdigest()

    if args.dry_run:
        print(
            json.dumps(
                {
                    "configured": True,
                    "config_source": source,
                    "dedupe_key": dedupe_key[:12],
                    "would_send": True,
                },
                sort_keys=True,
            )
        )
        return 0

    args.ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger = args.ledger.open("a+", encoding="utf-8")
    fcntl.flock(ledger.fileno(), fcntl.LOCK_EX)
    try:
        if not args.force and recent_duplicate(ledger, dedupe_key, 15):
            print(json.dumps({"status": "duplicate_skipped", "dedupe_key": dedupe_key[:12]}))
            return 0

        payload = {
            "username": "Recon Codex",
            "allowed_mentions": {"parse": []},
            "embeds": [
                {
                    "title": title,
                    "description": description,
                    "color": 0xF2A900,
                    "fields": [
                        {"name": "Target", "value": target, "inline": False},
                        {"name": "Account alias", "value": account, "inline": True},
                        {"name": "tmux session", "value": tmux_session, "inline": True},
                        {"name": "Wait window", "value": "Pending until completed" if wait_minutes == 0 else f"{wait_minutes} minutes", "inline": True},
                        {"name": "Reason", "value": reason, "inline": False},
                        *([] if args.hide_tunnel else [
                            {"name": "Open through SSH tunnel", "value": NOVNC_URL, "inline": False},
                        ]),
                    ],
                    "footer": {"text": f"{footer_prefix} {dedupe_key[:12]}"},
                    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                }
            ],
        }
        separator = "&" if "?" in webhook else "?"
        request = urllib.request.Request(
            f"{webhook}{separator}wait=true",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Recon-Codex-CAPTCHA-Alert/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            print(f"Discord CAPTCHA alert failed with HTTP {error.code}", file=sys.stderr)
            return 3
        except (urllib.error.URLError, TimeoutError) as error:
            print(f"Discord CAPTCHA alert failed: {type(error).__name__}", file=sys.stderr)
            return 3

        if not 200 <= status < 300:
            print(f"Discord CAPTCHA alert returned HTTP {status}", file=sys.stderr)
            return 3

        ledger.seek(0, os.SEEK_END)
        ledger.write(
            json.dumps(
                {
                    "sent_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
                    "dedupe_key": dedupe_key,
                    "status": "sent",
                    "program": program,
                    "target": target,
                    "account_alias": account,
                    "tmux_session": tmux_session,
                },
                sort_keys=True,
            )
            + "\n"
        )
        ledger.flush()
        os.fsync(ledger.fileno())
        os.chmod(args.ledger, 0o600)
        print(json.dumps({"status": "sent", "dedupe_key": dedupe_key[:12]}))
        return 0
    finally:
        fcntl.flock(ledger.fileno(), fcntl.LOCK_UN)
        ledger.close()


if __name__ == "__main__":
    raise SystemExit(main())
