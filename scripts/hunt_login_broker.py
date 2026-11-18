#!/usr/bin/env python3
"""Prepare isolated visible sessions for owned hunt login files."""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright


ROOT = Path("/root/codex_artifacts/domain_hunts")
SIGNALS = Path("/root/codex_artifacts/hunt_login_signals")
SECRET_ROOT = Path("/root/codex_artifacts/hunt_credentials")
CDP = "http://127.0.0.1:9222"
VPN_LOGIN_DOMAINS = {domain.strip().lower() for domain in os.getenv("HUNT_LOGIN_VPN_DOMAINS", "betfair.com").split(",") if domain.strip()}
VPN_LOGIN_PROXY = os.getenv("HUNT_LOGIN_VPN_PROXY", "http://127.0.0.1:8888")
LOGIN_REQUEST_MAX_AGE_SECONDS = max(900, int(os.getenv("HUNT_LOGIN_REQUEST_MAX_AGE_SECONDS", "7200")))
SAFE_SECRET = re.compile(r"[0-9a-f]{32}\.secret\Z")
LOGIN_PATHS = {"zapier.com": "/app/login"}
SIDEKICK = "https://sidekick.zapier.com"
SIDEKICK_SELF = "/api/bridge/sidekick/v0/me"


def load_owned_secret(name: str) -> dict[str, str]:
    if not SAFE_SECRET.fullmatch(name):
        raise ValueError("Invalid owned credential reference")
    path = SECRET_ROOT / name
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Owned credential file permissions are invalid")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"email", "password"}:
        raise ValueError("Owned login file must contain email and password")
    if not all(isinstance(data[key], str) and data[key] for key in ("email", "password")):
        raise ValueError("Owned login fields are invalid")
    return data


def save_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    path.chmod(0o600)


def alert(run_id: int, domain: str, account: dict, reason: str, force: bool = False) -> None:
    command = [
        "/usr/bin/python3", "/root/enhanced_recon_framework/scripts/notify_captcha_required.py",
        "--program", domain, "--target", account["exact_host"],
        "--account-alias", account["alias"], "--tmux-session", account.get("run_label", f"hunt-run-{run_id}"),
        "--reason", reason, "--wait-minutes", "0",
    ]
    if force:
        command.append("--force")
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25, check=False)
    if result.returncode:
        print(f"Human-login alert delivery failed for run {run_id}: exit {result.returncode}", flush=True)


async def try_normal_login(page, credentials: dict[str, str]) -> None:
    email = page.locator('input[type="email"], input[name="email"]').first
    password = page.locator('input[type="password"]').first
    if await email.count() and await email.is_visible():
        await email.fill(credentials["email"])
    if not await password.count() or not await password.is_visible():
        submit = page.locator('button[type="submit"]').first
        if await submit.count() and await submit.is_visible():
            await submit.click(timeout=10000)
            await page.wait_for_timeout(1500)
    password = page.locator('input[type="password"]').first
    if await password.count() and await password.is_visible():
        await password.fill(credentials["password"])
        submit = page.locator('button[type="submit"]').first
        if await submit.count() and await submit.is_visible():
            await submit.click(timeout=10000)


def host_in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def login_context_options(domain: str) -> dict:
    return {"proxy": {"server": VPN_LOGIN_PROXY}} if domain in VPN_LOGIN_DOMAINS else {}


def login_left_page(url: str, host: str) -> bool:
    parsed = urlsplit(url)
    if not host_in_scope((parsed.hostname or "").lower(), host):
        return False
    return host == "zapier.com" and parsed.path.startswith("/app") and not parsed.path.startswith("/app/login")


def quarantine_stale_login_request(request_path: Path) -> bool:
    """Keep abandoned login handoffs from being reopened and alerting forever."""
    try:
        stale = time.time() - request_path.stat().st_mtime > LOGIN_REQUEST_MAX_AGE_SECONDS
    except OSError:
        return True
    if not stale:
        return False
    stale_path = request_path.with_name(request_path.name + ".stale")
    try:
        os.replace(request_path, stale_path)
    except OSError:
        return True
    return True


async def serve_request(browser, request_path: Path, active: dict, forced_alerts: set) -> None:
    request = json.loads(request_path.read_text(encoding="utf-8"))
    run_id = int(request["run_id"])
    domain = str(request["domain"]).lower()
    if request_path != ROOT / f"run_{run_id}" / "login_request.json":
        raise ValueError("Invalid login request path")
    session_dir = request_path.parent / "sessions"
    session_dir.mkdir(mode=0o700, exist_ok=True)
    session_dir.chmod(0o700)
    to_prepare = []
    for index, account in enumerate(request["accounts"]):
        account_id = int(account["id"])
        key = (run_id, account_id)
        state_path = session_dir / f"account_{account_id}.json"
        if state_path.exists() or key in active:
            continue
        host = str(account["exact_host"]).lower()
        if not host_in_scope(host, domain):
            save_json(session_dir / f"account_{account_id}.status.json", {"status": "blocked_host"})
            continue
        credentials = None
        if host in LOGIN_PATHS and account.get("credential_type") != "manual_login":
            try:
                credentials = load_owned_secret(account["secret_file"])
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"Owned credential unavailable for run {run_id}, account {account_id}: {type(exc).__name__}", flush=True)
        context = await browser.new_context(**login_context_options(domain))
        page = await context.new_page()
        cdp = await context.new_cdp_session(page)
        try:
            window = await cdp.send("Browser.getWindowForTarget")
            await cdp.send("Browser.setWindowBounds", {"windowId": window["windowId"],
                            "bounds": {"left": (index % 3) * 480, "top": 0,
                                       "width": 480, "height": 900, "windowState": "normal"}})
        except Exception:
            pass

        async def scope_navigation(route, navigation_request, *, allowed=domain, owned_page=page):
            target = urlsplit(navigation_request.url).hostname or ""
            is_top_navigation = navigation_request.is_navigation_request() and navigation_request.frame == owned_page.main_frame
            if is_top_navigation and target != allowed and not target.endswith("." + allowed):
                await route.abort()
            else:
                await route.continue_()

        await page.route("**/*", scope_navigation)
        active[key] = (context, page, account, host)
        to_prepare.append((key, page, account, credentials))
    for key, page, account, credentials in to_prepare:
        status_path = session_dir / f"account_{key[1]}.status.json"
        try:
            host = str(account["exact_host"]).lower()
            await page.goto(f"https://{host}{LOGIN_PATHS.get(host, '/')}", wait_until="domcontentloaded", timeout=30000)
            if credentials is not None and (urlsplit(page.url).hostname or "").lower() == host:
                await try_normal_login(page, credentials)
            await page.wait_for_timeout(2500)
            if login_left_page(page.url, host):
                await save_session(active[key][0], session_dir / f"account_{key[1]}.json")
                save_json(status_path, {"status": "ready_for_identity_verification"})
            else:
                save_json(status_path, {"status": "manual_login_pending"})
                alert(run_id, domain, account, "Complete login or CAPTCHA in this account's isolated VNC window, then select Login complete in Hunts", key in forced_alerts)
        except Exception as exc:
            print(f"Owned login did not complete for run {run_id}, account {key[1]}: {type(exc).__name__}", flush=True)
            save_json(status_path, {"status": "manual_login_pending"})
            alert(run_id, domain, account, "Automatic login did not complete; inspect this account's VNC window, then select Login complete in Hunts", key in forced_alerts)
        forced_alerts.discard(key)


async def save_session(context, path: Path) -> None:
    temp = path.with_suffix(".tmp")
    await context.storage_state(path=str(temp))
    temp.chmod(0o600)
    os.replace(temp, path)


async def sidekick_authenticated(page, expected_email: str) -> bool:
    if (urlsplit(page.url).hostname or "").lower() != "sidekick.zapier.com":
        return False
    try:
        identity = await page.evaluate("""async path => {
            const response = await fetch(path, {credentials: 'include'});
            if (response.status !== 200) return null;
            const data = await response.json();
            return {id: data.id, email: data.email, account_id: data.account_id};
        }""", SIDEKICK_SELF)
        return bool(identity and identity.get("id") and identity.get("account_id") and
                    str(identity.get("email") or "").casefold() == expected_email)
    except Exception:
        return False


async def serve_sidekick(browser, request_path: Path, active: dict) -> None:
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if request.get("domain") != "zapier.com":
        return
    run_id = int(request["run_id"])
    session_dir = request_path.parent / "sessions"
    for index, account in enumerate(request.get("accounts", [])):
        if account.get("exact_host") != "zapier.com":
            continue
        account_id = int(account["id"])
        key = (run_id, account_id)
        base = session_dir / f"account_{account_id}.json"
        destination = session_dir / f"account_{account_id}_sidekick.json"
        status_path = session_dir / f"account_{account_id}_sidekick.status.json"
        if key in active or destination.exists() or not base.is_file():
            continue
        try:
            expected_email = load_owned_secret(account["secret_file"])["email"].casefold()
        except (KeyError, OSError, ValueError, json.JSONDecodeError):
            save_json(status_path, {"status": "blocked_owned_identity"})
            continue
        context = await browser.new_context(storage_state=str(base))
        page = await context.new_page()

        async def guard(route, navigation, *, owned_page=page):
            host = (urlsplit(navigation.url).hostname or "").lower()
            if navigation.is_navigation_request() and navigation.frame == owned_page.main_frame and not host_in_scope(host, "zapier.com"):
                await route.abort()
            else:
                await route.continue_()

        await page.route("**/*", guard)
        try:
            cdp = await context.new_cdp_session(page)
            window = await cdp.send("Browser.getWindowForTarget")
            await cdp.send("Browser.setWindowBounds", {"windowId": window["windowId"],
                           "bounds": {"left": (index % 3) * 480, "top": 0,
                                      "width": 480, "height": 900, "windowState": "normal"}})
        except Exception:
            pass
        try:
            await page.goto(SIDEKICK + "/", wait_until="domcontentloaded", timeout=30000)
            if await sidekick_authenticated(page, expected_email):
                await save_session(context, destination)
                save_json(status_path, {"status": "ready_for_identity_verification"})
                await context.close()
                continue
            active[key] = (context, page, account, expected_email, time.monotonic() + 30)
            save_json(status_path, {"status": "manual_login_pending"})
            alert(run_id, "zapier.com", {**account, "exact_host": "sidekick.zapier.com"},
                  "Complete Sidekick Sign in with Zapier in this isolated VNC window; the broker will verify the session automatically")
        except Exception as exc:
            await context.close()
            print(f"Sidekick login window unavailable for run {run_id}, account {account_id}: {type(exc).__name__}", flush=True)
            save_json(status_path, {"status": "manual_login_pending"})


async def main() -> None:
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    SIGNALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    active = {}
    sidekick_active = {}
    forced_alerts = set()
    async with async_playwright() as playwright:
        browser = await playwright.chromium.connect_over_cdp(CDP)
        while True:
            for marker in SIGNALS.glob("run_*_account_*.retry"):
                match = re.fullmatch(r"run_(\d+)_account_(\d+)\.retry", marker.name)
                if not match:
                    continue
                run_id, account_id = map(int, match.groups())
                key = (run_id, account_id)
                request_path = ROOT / f"run_{run_id}" / "login_request.json"
                try:
                    request = json.loads(request_path.read_text(encoding="utf-8"))
                    valid = request.get("run_id") == run_id and any(
                        item.get("id") == account_id for item in request.get("accounts", [])
                    )
                except (OSError, ValueError, TypeError):
                    valid = False
                if not valid:
                    marker.unlink(missing_ok=True)
                    continue
                if key in active:
                    context = active.pop(key)[0]
                    await context.close()
                session_dir = ROOT / f"run_{run_id}" / "sessions"
                (session_dir / f"account_{account_id}.json").unlink(missing_ok=True)
                (session_dir / f"account_{account_id}.status.json").unlink(missing_ok=True)
                (SIGNALS / f"run_{run_id}_account_{account_id}.complete").unlink(missing_ok=True)
                marker.unlink(missing_ok=True)
                forced_alerts.add(key)
            for request_path in ROOT.glob("run_*/login_request.json"):
                if quarantine_stale_login_request(request_path):
                    continue
                try:
                    await serve_request(browser, request_path, active, forced_alerts)
                except Exception:
                    continue
                try:
                    await serve_sidekick(browser, request_path, sidekick_active)
                except Exception:
                    continue
            for store in (active, sidekick_active):
                for key, value in list(store.items()):
                    if not (ROOT / f"run_{key[0]}" / "login_request.json").is_file():
                        await value[0].close()
                        del store[key]
            for (run_id, account_id), (context, page, account, host) in list(active.items()):
                state_path = ROOT / f"run_{run_id}" / "sessions" / f"account_{account_id}.json"
                marker = SIGNALS / f"run_{run_id}_account_{account_id}.complete"
                if not state_path.exists() and marker.is_file():
                    marker.unlink()
                    if host_in_scope((urlsplit(page.url).hostname or "").lower(), host):
                        await save_session(context, state_path)
                        save_json(state_path.with_suffix(".status.json"), {"status": "ready_for_identity_verification"})
                    else:
                        save_json(state_path.with_suffix(".status.json"), {"status": "blocked_host"})
                elif not state_path.exists() and login_left_page(page.url, host):
                    await save_session(context, state_path)
                    save_json(state_path.with_suffix(".status.json"), {"status": "ready_for_identity_verification"})
            for (run_id, account_id), (context, page, account, expected_email, next_check) in list(sidekick_active.items()):
                if time.monotonic() < next_check:
                    continue
                sidekick_active[(run_id, account_id)] = (context, page, account, expected_email, time.monotonic() + 30)
                if await sidekick_authenticated(page, expected_email):
                    session_dir = ROOT / f"run_{run_id}" / "sessions"
                    destination = session_dir / f"account_{account_id}_sidekick.json"
                    await save_session(context, destination)
                    save_json(session_dir / f"account_{account_id}_sidekick.status.json",
                              {"status": "ready_for_identity_verification"})
                    await context.close()
                    del sidekick_active[(run_id, account_id)]
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
