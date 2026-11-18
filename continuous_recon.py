#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import errno
import fnmatch
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import shutil
import socket
import smtplib
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import aiohttp
import asyncpg
import redis
import yaml
from prometheus_client import Counter, Gauge, start_http_server

from bug_job_taxonomy import job_category
from js_analysis import (
    classify_graphql_response,
    extract_js_signals,
    extract_query_parameters,
    extract_js_urls_from_text,
    extract_script_urls_from_html,
    extract_source_map_urls_from_js,
    extract_text_from_source_map,
    is_graphql_candidate_url,
    looks_like_js_url,
    severity_for_js_signals,
    severity_for_param_tags,
)
from monitor_core import run_browser_monitor


LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOT_ROOT = Path("/app/screenshots")
SCREENSHOT_ROOT.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "recon_framework.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("recon-framework")

MAX_INDEXED_PARAMETER_NAME_BYTES = 2048


def storage_parameter_name(value: Any) -> str:
    """Bound pathological query keys while preserving normal names verbatim.

    The complete parsed parameter payload remains in endpoints.parameters. This
    representation is only for the separately indexed url_parameters table.
    """
    name = strip_postgres_nuls(value) or ""
    encoded = name.encode("utf-8")
    if len(encoded) <= MAX_INDEXED_PARAMETER_NAME_BYTES:
        return name
    digest = hashlib.sha256(encoded).hexdigest()
    suffix = f"...[sha256:{digest}]"
    prefix_budget = MAX_INDEXED_PARAMETER_NAME_BYTES - len(suffix.encode("ascii"))
    prefix = encoded[:prefix_budget].decode("utf-8", errors="ignore")
    return f"{prefix}{suffix}"

SUBDOMAINS_FOUND = Counter("subdomains_found_total", "Total subdomains discovered")
LIVE_HOSTS_FOUND = Counter("live_hosts_found_total", "Total live hosts discovered")
ENDPOINTS_FOUND = Counter("endpoints_found_total", "Total endpoints discovered")
JS_ASSETS_FOUND = Counter("js_assets_found_total", "Total JS assets discovered")
SCREENSHOTS_CAPTURED = Counter("screenshots_captured_total", "Total screenshots captured")
RISKY_PARAMS_FOUND = Counter("risky_params_found_total", "Total risky URL parameters discovered")
FINDINGS_FOUND = Counter("findings_found_total", "Total findings discovered")
SCAN_DURATION = Gauge("scan_duration_seconds", "Most recent domain scan duration")

DEFAULT_SUMMARY_PREVIEW_LIMIT = 20
GRAPHQL_TYPENAME_QUERY = "query ReconTypename { __typename }"
GRAPHQL_INTROSPECTION_QUERY = "query ReconSchema { __schema { queryType { name } } }"


@dataclass
class AppConfig:
    data: dict[str, Any]

    @property
    def scan(self) -> dict[str, Any]:
        return self.data["scan"]

    @property
    def database(self) -> dict[str, Any]:
        return self.data["database"]

    @property
    def redis(self) -> dict[str, Any]:
        return self.data["redis"]

    @property
    def alerts(self) -> dict[str, Any]:
        return self.data["alerts"]

    @property
    def tools(self) -> dict[str, Any]:
        return self.data["tools"]

    @property
    def retention(self) -> dict[str, Any]:
        return self.data.get("retention", {})

    @property
    def shodan(self) -> dict[str, Any]:
        return self.data.get("shodan", {})


@dataclass
class ToolRunResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False


def load_config() -> AppConfig:
    config_path = Path("/app/config.yaml")
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if os.getenv("RECON_DB_PASSWORD"):
        data["database"]["password"] = os.getenv("RECON_DB_PASSWORD")

    discord = data["alerts"].get("discord", {})
    if os.getenv("DISCORD_WEBHOOK_URL"):
        discord["webhook_url"] = os.getenv("DISCORD_WEBHOOK_URL")
    data["alerts"]["discord"] = discord
    shodan_discord = data["alerts"].get("shodan_discord", {})
    if os.getenv("SHODAN_DISCORD_WEBHOOK_URL"):
        shodan_discord["webhook_url"] = os.getenv("SHODAN_DISCORD_WEBHOOK_URL")
    data["alerts"]["shodan_discord"] = shodan_discord
    shodan = data.setdefault("shodan", {})
    if os.getenv("SHODAN_API_KEY"):
        shodan["api_key"] = os.getenv("SHODAN_API_KEY")
    search_intelligence = data.setdefault("search_intelligence", {})
    for env_name, config_name in (
        ("GOOGLE_CSE_API_KEY", "google_api_key"),
        ("GOOGLE_CSE_ENGINE_ID", "google_engine_id"),
        ("SERPER_API_KEY", "serper_api_key"),
        ("SERPAPI_API_KEY", "serpapi_api_key"),
    ):
        if os.getenv(env_name):
            search_intelligence[config_name] = os.getenv(env_name)
    return AppConfig(data)


def domain_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value)


def screenshot_filename(target_url: str, captured_at: datetime | None = None) -> str:
    """Return a unique screenshot filename that stays below filesystem limits."""
    hostname = urlsplit(target_url).hostname or "host"
    host_slug = domain_slug(hostname) or "host"
    max_host_bytes = 180
    encoded = host_slug.encode("utf-8")
    if len(encoded) > max_host_bytes:
        digest = hashlib.sha256(encoded).hexdigest()[:12]
        prefix_budget = max_host_bytes - len(digest) - 1
        prefix = encoded[:prefix_budget].decode("utf-8", errors="ignore")
        host_slug = f"{prefix}-{digest}"
    timestamp = (captured_at or datetime.utcnow()).strftime("%Y%m%d%H%M%S%f")
    return f"{timestamp}_{host_slug}.png"


def chunk_message(message: str, limit: int = 3500) -> list[str]:
    if len(message) <= limit:
        return [message]
    lines = message.splitlines()
    parts: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in lines:
        projected = current_len + len(line) + 1
        if current and projected > limit:
            parts.append("\n".join(current))
            current = [line]
            current_len = len(line) + 1
        else:
            current.append(line)
            current_len = projected
    if current:
        parts.append("\n".join(current))
    return parts


DISCORD_COLORS = {
    "info": 0x3498DB,
    "success": 0x2ECC71,
    "warning": 0xF39C12,
    "danger": 0xE74C3C,
    "change": 0x9B59B6,
}


def discord_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 18)].rstrip()}... [truncated]"


def discord_duration(seconds: Any) -> str:
    try:
        total = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return "unknown"
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def discord_field(name: str, value: Any, inline: bool = True) -> dict[str, Any]:
    return {
        "name": discord_text(name, 256) or "Details",
        "value": discord_text(value, 1024) or "None",
        "inline": inline,
    }


def discord_embed(
    title: str,
    *,
    description: str = "",
    color: int = DISCORD_COLORS["info"],
    fields: list[dict[str, Any]] | None = None,
    timestamp: str | None = None,
    footer: str = "Recon Framework",
) -> dict[str, Any]:
    embed: dict[str, Any] = {
        "title": discord_text(title, 256),
        "color": color,
        "footer": {"text": discord_text(footer, 2048)},
    }
    if description:
        embed["description"] = discord_text(description, 4000)
    if fields:
        embed["fields"] = fields[:25]
    if timestamp:
        embed["timestamp"] = timestamp
    return embed


def select_discord_alert_config(
    alerts: dict[str, Any],
    alert_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    dedicated_sources = {"shodan", "infrastructure", "port_scan"}
    use_infrastructure_channel = (
        alert_type.startswith(("shodan_", "infrastructure_"))
        or payload.get("source") in dedicated_sources
    )
    if use_infrastructure_channel:
        shodan_discord = alerts.get("shodan_discord", {})
        if shodan_discord.get("enabled") and shodan_discord.get("webhook_url"):
            return shodan_discord
    return alerts.get("discord", {})


def discord_list_pages(
    sections: list[tuple[str, list[str], int]],
    page_limit: int = 3600,
) -> list[str]:
    pages: list[str] = []
    current = ""
    for title, items, total in sections:
        if not items:
            continue
        lines = [f"### {title} ({total})", *items]
        if total > len(items):
            lines.append(f"*... {total - len(items)} more stored in the dashboard*")
        section = "\n".join(lines)
        if current and len(current) + len(section) + 2 > page_limit:
            pages.append(current)
            current = ""
        if len(section) > page_limit:
            for part in chunk_message(section, page_limit):
                if current:
                    pages.append(current)
                    current = ""
                pages.append(part)
            continue
        current = f"{current}\n\n{section}".strip()
    if current:
        pages.append(current)
    return pages


def build_discord_alert_embeds(
    alert_type: str,
    message: str,
    payload: dict[str, Any],
    max_messages: int = 6,
) -> list[dict[str, Any]]:
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    domain = str(payload.get("domain") or "").strip()
    title_domain = f" • {domain}" if domain else ""
    embeds: list[dict[str, Any]] = []

    if alert_type == "scan_started":
        embeds.append(
            discord_embed(
                f"Scan Started{title_domain}",
                description="Initial reconnaissance has started.",
                color=DISCORD_COLORS["info"],
                fields=[
                    discord_field("Domain", domain or "Unknown"),
                    discord_field("Scan type", "First run"),
                    discord_field("Status", "Running"),
                ],
                timestamp=str(payload.get("started_at") or now),
                footer="Recon Framework • scan_started",
            )
        )
    elif alert_type == "scan_summary":
        first_run = bool(payload.get("first_run"))
        counts = [
            ("Subdomains", len(payload.get("new_subdomains") or [])),
            ("Live hosts", len(payload.get("new_live_hosts") or [])),
            ("URLs", len(payload.get("new_urls") or [])),
            ("JS files", len(payload.get("new_js_assets") or [])),
            ("Changed JS", len(payload.get("changed_js_assets") or [])),
            ("Screenshots", len(payload.get("new_screenshots") or [])),
            ("Findings", len(payload.get("findings") or [])),
            ("AI triage", len(payload.get("ai_triage") or [])),
            ("Cloud assets", len(payload.get("cloud_assets") or [])),
            ("Changes", len(payload.get("asset_events") or [])),
        ]
        count_lines = "\n".join(f"**{name}:** {count}" for name, count in counts)
        has_changes = any(count for _, count in counts)
        severity_values = {
            str(item.get("severity") or "").lower()
            for item in (payload.get("findings") or [])
            if isinstance(item, dict)
        }
        priority_values = {
            str(item.get("priority") or "").lower()
            for item in (payload.get("ai_triage") or [])
            if isinstance(item, dict)
        }
        if "critical" in severity_values or "critical" in priority_values:
            summary_color = DISCORD_COLORS["danger"]
            summary_description = "Critical-priority reconnaissance data requires review."
        elif "high" in severity_values or "high" in priority_values:
            summary_color = DISCORD_COLORS["warning"]
            summary_description = "High-priority reconnaissance data requires review."
        elif has_changes:
            summary_color = DISCORD_COLORS["success"]
            summary_description = "New reconnaissance data was discovered."
        else:
            summary_color = DISCORD_COLORS["info"]
            summary_description = "Scan completed with no new discoveries."
        embeds.append(
            discord_embed(
                f"Scan Complete{title_domain}",
                description=summary_description,
                color=summary_color,
                fields=[
                    discord_field("Scan type", "First run" if first_run else "Delta scan"),
                    discord_field("Lane", payload.get("scan_lane") or "fast_delta"),
                    discord_field("Deep scan", "Yes" if payload.get("deep_scan") else "No"),
                    discord_field("Duration", discord_duration(payload.get("duration_seconds"))),
                    discord_field("New data", count_lines, inline=False),
                    discord_field(
                        "Scanner activity",
                        (
                            f"**Nuclei hosts:** {len(payload.get('nuclei_scanned_hosts') or [])}\n"
                            f"**Nuclei DAST URLs:** {len(payload.get('nuclei_dast_scanned_urls') or [])}\n"
                            f"**Permutation subs:** {len(payload.get('permutation_subdomains') or [])}\n"
                            f"**Hidden param probes:** {len(payload.get('hidden_parameter_probes') or [])}"
                        ),
                        inline=False,
                    ),
                ],
                timestamp=now,
                footer="Recon Framework • scan_summary • details follow",
            )
        )
        preview_limit = max(1, int(payload.get("_discord_preview_limit") or (25 if first_run else 20)))
        sections: list[tuple[str, list[str], int]] = []

        def add_section(name: str, values: list[Any], formatter) -> None:
            sections.append(
                (
                    name,
                    [discord_text(f"• {formatter(item)}", 450) for item in values[:preview_limit]],
                    len(values),
                )
            )

        add_section("Findings", payload.get("findings") or [], lambda item: f"**{str(item.get('severity') or 'info').upper()}** `{item.get('finding_type')}`\n  {item.get('location')}")
        add_section("AI triage", payload.get("ai_triage") or [], lambda item: f"**{str(item.get('priority') or 'info').upper()}** score `{item.get('score', 0)}`\n  {item.get('location')}")
        add_section("Monitor changes", payload.get("monitor_events") or [], lambda item: f"**{str(item.get('severity') or 'info').upper()}** `{item.get('item_type', 'item')}` {item.get('value', '')}")
        add_section("New live hosts", payload.get("new_live_hosts") or [], lambda item: item)
        add_section("Changed fingerprints", payload.get("changed_fingerprints") or [], lambda item: f"`{item.get('status_code')}` {item.get('url')} • {item.get('webserver') or 'unknown server'}")
        add_section("New URLs", payload.get("new_urls") or [], lambda item: f"{item.get('url')} • `{item.get('source')}`")
        add_section("New JS files", payload.get("new_js_assets") or [], lambda item: f"{item.get('asset_url')} • `{item.get('source')}`")
        add_section("Changed JS files", payload.get("changed_js_assets") or [], lambda item: item.get("asset_url"))
        add_section("New subdomains", payload.get("new_subdomains") or [], lambda item: item)
        add_section("Cloud assets", payload.get("cloud_assets") or [], lambda item: f"`{item.get('provider')}:{item.get('asset_type')}` {item.get('identifier')}")

        detail_pages = discord_list_pages(sections)
        allowed_details = max(0, max_messages - 1)
        shown_pages = min(len(detail_pages), allowed_details)
        for index, page in enumerate(detail_pages[:allowed_details], start=1):
            embeds.append(
                discord_embed(
                    f"Scan Details{title_domain} • {index}/{shown_pages}",
                    description=page,
                    color=DISCORD_COLORS["change"],
                    timestamp=now,
                    footer="Recon Framework • open dashboard for complete results",
                )
            )
    elif alert_type == "monitor_changes":
        events = payload.get("events") or []
        event_severities = {
            str(event.get("severity") or "").lower()
            for event in events
            if isinstance(event, dict)
        }
        monitor_color = (
            DISCORD_COLORS["danger"]
            if event_severities & {"critical", "high"}
            else DISCORD_COLORS["warning"]
            if "medium" in event_severities
            else DISCORD_COLORS["change"]
        )
        target = next((line.split(":", 1)[1].strip() for line in message.splitlines() if line.startswith("Target:")), "")
        description = "\n".join(
            discord_text(
                f"• **{str(event.get('severity') or 'info').upper()}** `{event.get('item_type') or 'item'}`\n  {event.get('value')}",
                600,
            )
            for event in events[:15]
        )
        if len(events) > 15:
            description += f"\n*... {len(events) - 15} more stored in the dashboard*"
        embeds.append(
            discord_embed(
                "Monitor Changes Detected",
                description=description or discord_text(message, 3500),
                color=monitor_color,
                fields=[
                    discord_field("Target", target or "See dashboard", inline=False),
                    discord_field("New items", len(events)),
                    discord_field("Run ID", payload.get("run_id") or "Unknown"),
                ],
                timestamp=now,
                footer="Recon Framework • monitor_changes",
            )
        )
    elif alert_type in {"scan_error", "monitor_error", "monitor_auth_warning"}:
        is_warning = alert_type == "monitor_auth_warning"
        embeds.append(
            discord_embed(
                {
                    "scan_error": f"Scan Failed{title_domain}",
                    "monitor_error": "Monitor Failed",
                    "monitor_auth_warning": "Monitor Authentication Warning",
                }[alert_type],
                description=discord_text(message, 3000),
                color=DISCORD_COLORS["warning"] if is_warning else DISCORD_COLORS["danger"],
                fields=[
                    discord_field("Domain ID", payload.get("domain_id") or "Unknown"),
                    discord_field("Run ID", payload.get("run_id") or "N/A"),
                    *([discord_field("Error", payload.get("error"), inline=False)] if payload.get("error") else []),
                ],
                timestamp=now,
                footer=f"Recon Framework • {alert_type}",
            )
        )
    else:
        scalar_fields = [
            discord_field(str(key).replace("_", " ").title(), value)
            for key, value in payload.items()
            if isinstance(value, (str, int, float, bool)) and key != "message"
        ][:8]
        embeds.append(
            discord_embed(
                alert_type.replace("_", " ").title(),
                description=discord_text(message, 3500),
                color=DISCORD_COLORS["info"],
                fields=scalar_fields,
                timestamp=now,
                footer=f"Recon Framework • {alert_type}",
            )
        )

    return embeds[:max_messages]


def dedupe_list(items: list[str]) -> list[str]:
    seen = set()
    results: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            results.append(item)
    return results


def extract_katana_urls(output: str, base_url: str = "") -> list[str]:
    """Extract crawl targets from Katana JSONL or legacy plain URL output."""
    urls: list[str] = []

    def add_url(value: Any) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        candidate = urljoin(base_url, value.strip()) if base_url else value.strip()
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            return
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            urls.append(candidate)

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(("http://", "https://")):
            add_url(line)
            continue
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue

        request = payload.get("request")
        if isinstance(request, dict):
            add_url(request.get("endpoint") or request.get("url"))

        response = payload.get("response")
        if not isinstance(response, dict):
            continue
        forms = response.get("forms")
        if not isinstance(forms, list):
            continue
        for form in forms:
            if isinstance(form, dict):
                add_url(form.get("action") or form.get("url"))

    return dedupe_list(urls)


def strip_postgres_nuls(value: str | None) -> str | None:
    if value is None:
        return None
    return value.replace("\x00", "")


def sanitize_postgres_value(value: Any) -> Any:
    if isinstance(value, str):
        return strip_postgres_nuls(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [sanitize_postgres_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_postgres_value(item) for item in value]
    if isinstance(value, dict):
        return {strip_postgres_nuls(str(key)): sanitize_postgres_value(item) for key, item in value.items()}
    return value


def postgres_json(value: Any) -> str:
    return json.dumps(sanitize_postgres_value(value))


def redact_secret(value: str | None, keep: int = 4) -> str | None:
    if not value:
        return None
    value = strip_postgres_nuls(str(value)) or ""
    if len(value) <= keep * 2:
        return "<redacted>"
    return f"{value[:keep]}...{value[-keep:]}"


def normalize_json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def new_scan_summary(domain: str, first_run: bool) -> dict[str, Any]:
    return {
        "domain": domain,
        "first_run": first_run,
        "deep_scan": False,
        "new_subdomains": [],
        "new_live_hosts": [],
        "new_urls": [],
        "new_js_assets": [],
        "changed_js_assets": [],
        "changed_fingerprints": [],
        "new_screenshots": [],
        "findings": [],
        "nuclei_scanned_hosts": [],
        "nuclei_skipped_hosts": [],
        "nuclei_batch": [],
        "permutation_subdomains": [],
        "nuclei_dast_scanned_urls": [],
        "hidden_parameter_probes": [],
        "ffuf_scanned_hosts": [],
        "ffuf_skipped_hosts": [],
        "passive_sources": {},
        "passive_recursion": {},
        "httpx_probe": {},
        "dnsx_probe": {},
        "ai_triage": [],
        "asset_events": [],
        "cloud_assets": [],
        "monitor_events": [],
        "new_ips": [],
        "new_ports": [],
        "scan_lane": "fast_delta",
    }


class ContinuousReconFramework:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.db_pool: asyncpg.Pool | None = None
        self.redis_client: redis.Redis | None = None
        self.scan_semaphore = asyncio.Semaphore(int(self.config.scan["max_concurrent_domains"]))
        self.live_host_semaphore = asyncio.Semaphore(int(self.config.scan.get("max_concurrent_live_hosts", 5)))
        self.amass_semaphore = asyncio.Semaphore(1)
        self.archive_semaphore = asyncio.Semaphore(
            max(1, int(self.config.scan.get("archive_provider_max_concurrency", 4)))
        )
        passive_concurrency = max(1, int(self.config.scan.get("passive_source_max_concurrency", 1)))
        self.passive_source_semaphores: dict[str, asyncio.Semaphore] = {
            source: asyncio.Semaphore(passive_concurrency)
            for source in ("crtsh", "crtname", "certspotter", "alienvault")
        }
        recursive_dns_concurrency = max(
            1,
            int(self.config.scan.get("recursive_passive_dns_concurrency", 5)),
        )
        self.recursive_dns_semaphore = asyncio.Semaphore(recursive_dns_concurrency)
        self.passive_source_last_request: dict[str, float] = {}
        self.passive_source_circuit_until: dict[str, float] = {}
        self.last_maintenance_run: datetime | None = None
        self.subdomain_sources_by_domain: dict[int, dict[str, set[str]]] = {}

    @staticmethod
    def append_summary(summary: dict[str, Any] | None, key: str, item: Any) -> None:
        if summary is None:
            return
        items = summary.setdefault(key, [])
        if item not in items:
            items.append(item)

    @staticmethod
    def summary_has_changes(summary: dict[str, Any]) -> bool:
        return any(
            summary.get(key)
            for key in (
                "new_subdomains",
                "new_live_hosts",
                "new_urls",
                "new_js_assets",
                "changed_js_assets",
                "changed_fingerprints",
                "new_screenshots",
                "findings",
                "ai_triage",
                "asset_events",
                "cloud_assets",
                "monitor_events",
                "new_ips",
                "new_ports",
            )
        )

    def build_scan_start_message(self, domain_info: dict[str, Any]) -> str:
        lines = [
            f"Recon Scan Started: {domain_info['domain']}",
            "Scan type: first run",
            f"Started: {datetime.utcnow().isoformat(timespec='seconds')} UTC",
        ]
        if domain_info.get("organization"):
            lines.append(f"Organization: {domain_info['organization']}")
        return "\n".join(lines)

    def domain_bool(self, domain_info: dict[str, Any], key: str, default: bool) -> bool:
        value = domain_info.get(key)
        return default if value is None else bool(value)

    def domain_int(self, domain_info: dict[str, Any], key: str, default: int) -> int:
        value = domain_info.get(key)
        return default if value is None else int(value)

    def render_summary_section(self, title: str, items: list[Any], formatter, first_run: bool) -> list[str]:
        if not items:
            return []
        if first_run:
            limit = int(self.config.alerts.get("first_run_summary_preview_limit", 0))
        else:
            limit = int(self.config.alerts.get("summary_preview_limit", DEFAULT_SUMMARY_PREVIEW_LIMIT))
        if limit <= 0:
            limit = len(items)
        lines = [f"{title} ({len(items)}):"]
        for item in items[:limit]:
            lines.append(f"- {formatter(item)}")
        if len(items) > limit:
            lines.append(f"- ... and {len(items) - limit} more")
        return lines

    def build_scan_summary_message(self, summary: dict[str, Any], duration: float) -> str:
        lines = [
            f"Recon Summary: {summary['domain']}",
            f"Scan type: {'first run' if summary['first_run'] else 'delta scan'}",
            f"Scan lane: {summary.get('scan_lane', 'fast_delta')}",
            f"Deep scan: {'yes' if summary.get('deep_scan') else 'no'}",
            f"Duration: {duration:.1f}s",
            (
                "New counts: "
                f"subdomains={len(summary['new_subdomains'])}, "
                f"live_hosts={len(summary['new_live_hosts'])}, "
                f"urls={len(summary['new_urls'])}, "
                f"js_assets={len(summary['new_js_assets'])}, "
                f"changed_js_assets={len(summary['changed_js_assets'])}, "
                f"screenshots={len(summary['new_screenshots'])}, "
                f"findings={len(summary['findings'])}, "
                f"ai_triage={len(summary.get('ai_triage', []))}, "
                f"cloud_assets={len(summary.get('cloud_assets', []))}, "
                f"events={len(summary.get('asset_events', []))}"
            ),
            (
                "Nuclei: "
                f"scanned_hosts={len(summary.get('nuclei_scanned_hosts', []))}, "
                f"skipped_hosts={len(summary.get('nuclei_skipped_hosts', []))}, "
                f"dast_urls={len(summary.get('nuclei_dast_scanned_urls', []))}"
            ),
            (
                "Deep discoveries: "
                f"permutation_subdomains={len(summary.get('permutation_subdomains', []))}, "
                f"hidden_parameter_probes={len(summary.get('hidden_parameter_probes', []))}, "
                f"recursive_zones={len(summary.get('passive_recursion', {}).get('zones_queried', []))}, "
                f"recursive_names={summary.get('passive_recursion', {}).get('new_names', 0)}"
            ),
            (
                "HTTPX coverage: "
                f"status={summary.get('httpx_probe', {}).get('status', 'not_run')}, "
                f"inputs={summary.get('httpx_probe', {}).get('total_inputs', 0)}, "
                f"outputs={summary.get('httpx_probe', {}).get('output_records', 0)}, "
                f"timeouts={summary.get('httpx_probe', {}).get('timed_out_batches', 0)}, "
                f"incomplete_inputs={summary.get('httpx_probe', {}).get('incomplete_inputs', 0)}"
            ),
            (
                "DNSX coverage: "
                f"status={summary.get('dnsx_probe', {}).get('status', 'not_run')}, "
                f"inputs={summary.get('dnsx_probe', {}).get('total_inputs', 0)}, "
                f"outputs={summary.get('dnsx_probe', {}).get('output_records', 0)}, "
                f"timeouts={summary.get('dnsx_probe', {}).get('timed_out_batches', 0)}, "
                f"incomplete_inputs={summary.get('dnsx_probe', {}).get('incomplete_inputs', 0)}"
            ),
        ]
        first_run = summary["first_run"]
        lines.extend(self.render_summary_section("New subdomains", summary["new_subdomains"], lambda item: item, first_run))
        lines.extend(self.render_summary_section("New live hosts", summary["new_live_hosts"], lambda item: item, first_run))
        lines.extend(
            self.render_summary_section(
                "New infrastructure IPs",
                summary.get("new_ips", []),
                lambda item: f"{item['ip']} <- {item['hostname']} ({item['classification']})",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "New URLs",
                summary["new_urls"],
                lambda item: f"{item['url']} [{item['source']}]",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "New JS assets",
                summary["new_js_assets"],
                lambda item: f"{item['asset_url']} [{item['source']}]",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Changed JS assets",
                summary["changed_js_assets"],
                lambda item: f"{item['asset_url']} sha256={item['sha256'] or 'unknown'}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Changed HTTP fingerprints",
                summary["changed_fingerprints"],
                lambda item: f"{item['url']} [{item['status_code']}] server={item['webserver'] or 'unknown'}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "New screenshots",
                summary["new_screenshots"],
                lambda item: f"{item['url']} -> {item['screenshot_path']}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Findings",
                summary["findings"],
                lambda item: f"[{item['severity'].upper()}] {item['finding_type']} @ {item['location']}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "AI triage",
                summary.get("ai_triage", []),
                lambda item: f"[{item['priority'].upper()} score={item['score']}] {item['location']} ({', '.join(item.get('reasons', [])[:3])})",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Cloud assets",
                summary.get("cloud_assets", []),
                lambda item: f"{item['provider']}:{item['asset_type']} {item['identifier']}",
                first_run,
            )
        )
        lines.extend(
            self.render_summary_section(
                "Monitor changes",
                summary.get("monitor_events", []),
                lambda item: f"[{item.get('severity', 'info').upper()}] {item.get('item_type', 'item')} {item.get('value', '')}",
                first_run,
            )
        )
        if not self.summary_has_changes(summary):
            lines.append("No new discoveries in this scan.")
        return "\n".join(lines)

    async def init(self) -> None:
        self.db_pool = await asyncpg.create_pool(
            host=self.config.database["host"],
            port=self.config.database["port"],
            database=self.config.database["name"],
            user=self.config.database["user"],
            password=self.config.database["password"],
            min_size=1,
            max_size=20,
        )
        if self.config.redis.get("enabled", False):
            try:
                self.redis_client = redis.Redis(
                    host=self.config.redis["host"],
                    port=self.config.redis["port"],
                    decode_responses=True,
                )
                self.redis_client.ping()
            except redis.RedisError as exc:
                logger.warning("Redis unavailable, continuing without it: %s", exc)
                self.redis_client = None
        await self.ensure_runtime_schema()
        await self.seed_existing_triage()
        await self.seed_existing_operational_queues()

    async def ensure_runtime_schema(self) -> None:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            await conn.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS enable_port_scan BOOLEAN")
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS infrastructure_ips (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    ip_address INET NOT NULL,
                    ip_version SMALLINT NOT NULL,
                    ptr_name TEXT,
                    asn TEXT,
                    asn_org TEXT,
                    provider TEXT,
                    classification VARCHAR(30) NOT NULL DEFAULT 'unknown',
                    scan_eligible BOOLEAN NOT NULL DEFAULT TRUE,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, ip_address)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS infrastructure_ip_subdomains (
                    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
                    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(ip_asset_id, subdomain_id)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_records (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    subdomain_id INTEGER NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
                    record_type VARCHAR(12) NOT NULL,
                    value TEXT NOT NULL,
                    ttl INTEGER,
                    is_current BOOLEAN NOT NULL DEFAULT TRUE,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(subdomain_id, record_type, value)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS port_scan_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
                    profile VARCHAR(30) NOT NULL,
                    schedule_bucket DATE NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'queued',
                    priority INTEGER NOT NULL DEFAULT 50,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 2,
                    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    lease_owner TEXT,
                    lease_expires_at TIMESTAMP,
                    heartbeat_at TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error TEXT,
                    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_asset_id, profile, schedule_bucket)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS network_services (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    protocol VARCHAR(8) NOT NULL DEFAULT 'tcp',
                    state VARCHAR(20) NOT NULL DEFAULT 'open',
                    service TEXT,
                    product TEXT,
                    version TEXT,
                    extra_info TEXT,
                    banner TEXT,
                    tls JSONB NOT NULL DEFAULT '{}'::jsonb,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    closed_at TIMESTAMP,
                    UNIQUE(ip_asset_id, port, protocol)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shodan_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    ip_asset_id BIGINT REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
                    job_type VARCHAR(20) NOT NULL CHECK (job_type IN ('domain', 'host')),
                    dedupe_key TEXT NOT NULL UNIQUE,
                    status VARCHAR(20) NOT NULL DEFAULT 'queued',
                    priority INTEGER NOT NULL DEFAULT 50,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    lease_owner TEXT,
                    lease_expires_at TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error TEXT,
                    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shodan_domain_snapshots (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    fetched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    response_hash VARCHAR(64) NOT NULL,
                    record_count INTEGER NOT NULL DEFAULT 0,
                    subdomain_count INTEGER NOT NULL DEFAULT 0,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shodan_host_snapshots (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    ip_asset_id BIGINT NOT NULL REFERENCES infrastructure_ips(id) ON DELETE CASCADE,
                    fetched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    shodan_last_update TIMESTAMP,
                    fingerprint_hash VARCHAR(64) NOT NULL,
                    ports INTEGER[] NOT NULL DEFAULT '{}',
                    hostnames TEXT[] NOT NULL DEFAULT '{}',
                    tags TEXT[] NOT NULL DEFAULT '{}',
                    vulnerabilities TEXT[] NOT NULL DEFAULT '{}',
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_leaks (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE SET NULL,
                    js_asset_id INTEGER REFERENCES js_assets(id) ON DELETE SET NULL,
                    detector_name TEXT NOT NULL,
                    detector_type TEXT,
                    decoder_name TEXT,
                    source_type TEXT NOT NULL DEFAULT 'js_asset',
                    source_url TEXT NOT NULL,
                    source_file TEXT,
                    line_number INTEGER,
                    verified BOOLEAN NOT NULL DEFAULT FALSE,
                    redacted_secret TEXT,
                    fingerprint VARCHAR(64) NOT NULL,
                    raw_sha256 VARCHAR(64),
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_new BOOLEAN NOT NULL DEFAULT TRUE,
                    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
                    UNIQUE(domain_id, source_url, detector_name, fingerprint)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_leak_scan_status (
                    js_asset_id INTEGER PRIMARY KEY REFERENCES js_assets(id) ON DELETE CASCADE,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE SET NULL,
                    asset_url TEXT NOT NULL,
                    sha256 VARCHAR(64),
                    status VARCHAR(30) NOT NULL DEFAULT 'queued',
                    http_status INTEGER,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    started_at TIMESTAMP,
                    scanned_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_credential_leaks_domain_seen ON credential_leaks(domain_id, last_seen DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_credential_leaks_detector_seen ON credential_leaks(detector_name, last_seen DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_credential_leaks_verified_seen ON credential_leaks(verified, last_seen DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_credential_leak_scan_status_domain_status ON credential_leak_scan_status(domain_id, status, updated_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_credential_leak_scan_status_scanned ON credential_leak_scan_status(scanned_at DESC)")
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ffuf_runs (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE CASCADE,
                    host_url TEXT NOT NULL,
                    scan_lane VARCHAR(50) NOT NULL,
                    wordlist_path TEXT NOT NULL,
                    wordlist_sha256 VARCHAR(64) NOT NULL,
                    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    status VARCHAR(20) NOT NULL DEFAULT 'running',
                    hits_count INTEGER NOT NULL DEFAULT 0,
                    options JSONB NOT NULL DEFAULT '{}'::jsonb,
                    error TEXT,
                    UNIQUE(live_host_id, scan_lane, wordlist_sha256)
                )
                """
            )
            await conn.execute("ALTER TABLE ffuf_runs ADD COLUMN IF NOT EXISTS options JSONB NOT NULL DEFAULT '{}'::jsonb")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_ffuf_runs_domain ON ffuf_runs(domain_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_ffuf_runs_live_host ON ffuf_runs(live_host_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_ffuf_runs_status ON ffuf_runs(status)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_ffuf_runs_queue_worker_status ON ffuf_runs(status, (options->>'queue_worker'), started_at)")
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analyst_annotations (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    entity_type VARCHAR(60) NOT NULL,
                    entity_id INTEGER,
                    entity_key VARCHAR(128) NOT NULL,
                    location TEXT,
                    status VARCHAR(40) NOT NULL DEFAULT 'new',
                    severity_override VARCHAR(20),
                    tags TEXT[] NOT NULL DEFAULT '{}',
                    bookmarked BOOLEAN NOT NULL DEFAULT FALSE,
                    notes TEXT,
                    assigned_to VARCHAR(120),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(entity_type, entity_key)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS asset_events (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    event_key VARCHAR(128) NOT NULL UNIQUE,
                    event_type VARCHAR(80) NOT NULL,
                    entity_type VARCHAR(60) NOT NULL,
                    entity_id INTEGER,
                    location TEXT NOT NULL,
                    severity VARCHAR(20) NOT NULL DEFAULT 'info',
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS asset_risk_scores (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    entity_type VARCHAR(60) NOT NULL,
                    entity_id INTEGER,
                    entity_key VARCHAR(128) NOT NULL,
                    location TEXT NOT NULL,
                    score INTEGER NOT NULL DEFAULT 0,
                    priority VARCHAR(20) NOT NULL DEFAULT 'low',
                    reasons TEXT[] NOT NULL DEFAULT '{}',
                    recommended_actions TEXT[] NOT NULL DEFAULT '{}',
                    run_profiles TEXT[] NOT NULL DEFAULT '{}',
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(entity_type, entity_key)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_assets (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    provider VARCHAR(80) NOT NULL,
                    asset_type VARCHAR(80) NOT NULL,
                    identifier TEXT NOT NULL,
                    location TEXT NOT NULL,
                    source VARCHAR(80) NOT NULL DEFAULT 'recon',
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, provider, asset_type, identifier)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scope_rules (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    rule_type VARCHAR(30) NOT NULL DEFAULT 'exclude',
                    pattern TEXT NOT NULL,
                    reason TEXT,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, rule_type, pattern)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_profiles (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    name VARCHAR(120) NOT NULL,
                    profile_type VARCHAR(40) NOT NULL DEFAULT 'cookie',
                    host_pattern TEXT NOT NULL DEFAULT '*',
                    header_name VARCHAR(120),
                    secret_ref TEXT,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, name)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_targets (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    name VARCHAR(160) NOT NULL,
                    start_url TEXT NOT NULL,
                    auth_type VARCHAR(30) NOT NULL DEFAULT 'none',
                    cookie_secret_ref TEXT,
                    login_url TEXT,
                    login_email TEXT,
                    password_secret_ref TEXT,
                    username_selector TEXT,
                    password_selector TEXT,
                    submit_selector TEXT,
                    auth_check_url TEXT,
                    auth_check_selector TEXT,
                    auth_check_text TEXT,
                    auth_failure_text TEXT,
                    auth_status VARCHAR(30),
                    auth_last_checked_at TIMESTAMP,
                    auth_last_error TEXT,
                    extra_routes JSONB NOT NULL DEFAULT '[]'::jsonb,
                    interval_hours INTEGER NOT NULL DEFAULT 24,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    alert_min_risk VARCHAR(20) NOT NULL DEFAULT 'medium',
                    last_run_at TIMESTAMP,
                    last_error TEXT,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, start_url)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_runs (
                    id SERIAL PRIMARY KEY,
                    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    status VARCHAR(30) NOT NULL DEFAULT 'running',
                    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP,
                    duration_seconds DOUBLE PRECISION,
                    auth_status VARCHAR(30),
                    new_items_count INTEGER NOT NULL DEFAULT 0,
                    new_events_count INTEGER NOT NULL DEFAULT 0,
                    scripts_count INTEGER NOT NULL DEFAULT 0,
                    requests_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    summary JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_intel_items (
                    id SERIAL PRIMARY KEY,
                    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    item_type VARCHAR(80) NOT NULL,
                    item_key VARCHAR(128) NOT NULL,
                    value TEXT NOT NULL,
                    risk VARCHAR(20) NOT NULL DEFAULT 'info',
                    source_url TEXT,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(monitor_id, item_type, item_key)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_events (
                    id SERIAL PRIMARY KEY,
                    run_id INTEGER REFERENCES monitor_runs(id) ON DELETE SET NULL,
                    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    event_type VARCHAR(80) NOT NULL,
                    item_type VARCHAR(80) NOT NULL,
                    item_key VARCHAR(128) NOT NULL,
                    value TEXT NOT NULL,
                    severity VARCHAR(20) NOT NULL DEFAULT 'info',
                    summary TEXT,
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    alerted_at TIMESTAMP,
                    UNIQUE(monitor_id, event_type, item_key)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_packs (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    source_table VARCHAR(60) NOT NULL,
                    source_id INTEGER,
                    evidence_key VARCHAR(128) NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    location TEXT NOT NULL,
                    severity VARCHAR(20) NOT NULL DEFAULT 'info',
                    summary TEXT,
                    request JSONB NOT NULL DEFAULT '{}'::jsonb,
                    response JSONB NOT NULL DEFAULT '{}'::jsonb,
                    artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
                    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS validation_queue (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
                    evidence_pack_id INTEGER REFERENCES evidence_packs(id) ON DELETE SET NULL,
                    source_table VARCHAR(60) NOT NULL,
                    source_id INTEGER,
                    queue_key VARCHAR(128) UNIQUE,
                    status VARCHAR(40) NOT NULL DEFAULT 'needs_validation',
                    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
                    location TEXT NOT NULL,
                    validation_steps TEXT[] NOT NULL DEFAULT '{}',
                    notes TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_playbooks (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    source_table VARCHAR(60) NOT NULL,
                    source_id INTEGER,
                    playbook_key VARCHAR(128) NOT NULL UNIQUE,
                    target_url TEXT NOT NULL,
                    owasp_category VARCHAR(100) NOT NULL,
                    check_type VARCHAR(80) NOT NULL,
                    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
                    confidence VARCHAR(30) NOT NULL DEFAULT 'candidate',
                    reasons TEXT[] NOT NULL DEFAULT '{}',
                    validation_steps TEXT[] NOT NULL DEFAULT '{}',
                    stop_conditions TEXT[] NOT NULL DEFAULT '{}',
                    safety_notes TEXT[] NOT NULL DEFAULT '{}',
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    status VARCHAR(40) NOT NULL DEFAULT 'queued',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bug_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    target TEXT NOT NULL,
                    asset_type VARCHAR(60) NOT NULL,
                    asset_value TEXT NOT NULL,
                    job_type VARCHAR(80) NOT NULL,
                    job_category VARCHAR(50) NOT NULL DEFAULT 'input_workflow',
                    priority INTEGER NOT NULL DEFAULT 50,
                    status VARCHAR(30) NOT NULL DEFAULT 'queued',
                    scope_ok BOOLEAN NOT NULL DEFAULT TRUE,
                    source_table VARCHAR(60),
                    source_id INTEGER,
                    source_observed_at TIMESTAMP,
                    job_key VARCHAR(128) NOT NULL UNIQUE,
                    hypothesis TEXT,
                    safety_notes TEXT[] NOT NULL DEFAULT '{}',
                    required_context JSONB NOT NULL DEFAULT '{}'::jsonb,
                    prompt_path TEXT,
                    codex_output_path TEXT,
                    result_summary TEXT,
                    finding_status VARCHAR(30),
                    confidence INTEGER,
                    outcome_class VARCHAR(40),
                    vulnerability_class VARCHAR(160),
                    manual_review_priority VARCHAR(20),
                    alert_signals TEXT[] NOT NULL DEFAULT '{}',
                    codex_alerted_at TIMESTAMP,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 2,
                    error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS authz_observations (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    bug_job_id BIGINT REFERENCES bug_jobs(id) ON DELETE SET NULL,
                    endpoint TEXT NOT NULL,
                    method VARCHAR(12) NOT NULL DEFAULT 'GET',
                    actor TEXT NOT NULL,
                    object_owner TEXT,
                    status_code INTEGER,
                    response_hash VARCHAR(64),
                    content_length INTEGER,
                    sensitive_keywords TEXT[] NOT NULL DEFAULT '{}',
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bug_job_curation_runs (
                    id BIGSERIAL PRIMARY KEY,
                    status VARCHAR(30) NOT NULL DEFAULT 'running',
                    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
                    candidates_considered INTEGER NOT NULL DEFAULT 0,
                    jobs_approved INTEGER NOT NULL DEFAULT 0,
                    jobs_deferred INTEGER NOT NULL DEFAULT 0,
                    jobs_pending_ai INTEGER NOT NULL DEFAULT 0,
                    ai_candidates_reviewed INTEGER NOT NULL DEFAULT 0,
                    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bug_job_curation_decisions (
                    bug_job_id BIGINT PRIMARY KEY REFERENCES bug_jobs(id) ON DELETE CASCADE,
                    run_id BIGINT REFERENCES bug_job_curation_runs(id) ON DELETE SET NULL,
                    decision VARCHAR(30) NOT NULL,
                    score INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    decided_by VARCHAR(30) NOT NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    decided_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_surfaces (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE CASCADE,
                    surface_type VARCHAR(40) NOT NULL,
                    location TEXT NOT NULL,
                    source VARCHAR(80) NOT NULL DEFAULT 'recon',
                    status_code INTEGER,
                    auth_required BOOLEAN,
                    schema_url TEXT,
                    methods TEXT[] NOT NULL DEFAULT '{}',
                    operations_count INTEGER NOT NULL DEFAULT 0,
                    risk_flags TEXT[] NOT NULL DEFAULT '{}',
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, surface_type, location)
                )
                """
            )
            for ddl in (
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_check_url TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_check_selector TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_check_text TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_failure_text TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_status VARCHAR(30)",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_last_checked_at TIMESTAMP",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_last_error TEXT",
                "ALTER TABLE monitor_events ADD COLUMN IF NOT EXISTS run_id INTEGER REFERENCES monitor_runs(id) ON DELETE SET NULL",
                "ALTER TABLE validation_queue ADD COLUMN IF NOT EXISTS queue_key VARCHAR(128)",
                "ALTER TABLE validation_queue DROP CONSTRAINT IF EXISTS validation_queue_source_table_source_id_location_key",
                "ALTER TABLE attack_playbooks DROP CONSTRAINT IF EXISTS attack_playbooks_source_table_source_id_check_type_target_u_key",
                "ALTER TABLE analyst_annotations ADD COLUMN IF NOT EXISTS location TEXT",
                "CREATE INDEX IF NOT EXISTS idx_annotations_domain_status ON analyst_annotations(domain_id, status, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_annotations_tags ON analyst_annotations USING GIN (tags)",
                "CREATE INDEX IF NOT EXISTS idx_asset_events_domain_seen ON asset_events(domain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_asset_events_type ON asset_events(event_type, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_risk_scores_domain_priority ON asset_risk_scores(domain_id, priority, score DESC, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_cloud_assets_domain_provider ON cloud_assets(domain_id, provider, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_scope_rules_domain ON scope_rules(domain_id, enabled)",
                "CREATE INDEX IF NOT EXISTS idx_auth_profiles_domain ON auth_profiles(domain_id, enabled)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_targets_due ON monitor_targets(enabled, last_run_at, interval_hours)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_targets_domain ON monitor_targets(domain_id, enabled)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_runs_monitor_started ON monitor_runs(monitor_id, started_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_runs_domain_started ON monitor_runs(domain_id, started_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_intel_domain_type ON monitor_intel_items(domain_id, item_type, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_domain_seen ON monitor_events(domain_id, severity, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_run_seen ON monitor_events(run_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_monitor_seen ON monitor_events(monitor_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_evidence_packs_domain ON evidence_packs(domain_id, severity, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_validation_queue_domain_status ON validation_queue(domain_id, status, priority, updated_at DESC)",
                "CREATE UNIQUE INDEX IF NOT EXISTS validation_queue_queue_key_uq ON validation_queue(queue_key)",
                "CREATE INDEX IF NOT EXISTS idx_attack_playbooks_domain_priority ON attack_playbooks(domain_id, status, priority, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_attack_playbooks_check_type ON attack_playbooks(check_type, updated_at DESC)",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 2",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS source_observed_at TIMESTAMP",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS job_category VARCHAR(50) NOT NULL DEFAULT 'input_workflow'",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS outcome_class VARCHAR(40)",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS vulnerability_class VARCHAR(160)",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS manual_review_priority VARCHAR(20)",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS alert_signals TEXT[] NOT NULL DEFAULT '{}'",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS model_tokens_used BIGINT",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS model_run_count INTEGER",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS model_name VARCHAR(120)",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS model_provider VARCHAR(80)",
                "ALTER TABLE bug_jobs ADD COLUMN IF NOT EXISTS model_result_alert_eligible BOOLEAN NOT NULL DEFAULT FALSE",
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_claim ON bug_jobs(status, scope_ok, priority DESC, created_at ASC)",
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_domain_status ON bug_jobs(domain_id, status, priority DESC, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_type_status ON bug_jobs(job_type, status, priority DESC, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_category_claim ON bug_jobs(job_category, status, source_observed_at DESC, priority DESC)",
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_roi ON bug_jobs(finished_at DESC, job_category, outcome_class) WHERE status = 'done'",
                "CREATE INDEX IF NOT EXISTS idx_bug_job_curation_decision ON bug_job_curation_decisions(decision, score DESC, decided_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_authz_observations_domain_endpoint ON authz_observations(domain_id, endpoint, method, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_authz_observations_job ON authz_observations(bug_job_id, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_api_surfaces_domain_type ON api_surfaces(domain_id, surface_type, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_api_surfaces_risk_flags ON api_surfaces USING GIN (risk_flags)",
                "CREATE INDEX IF NOT EXISTS idx_api_surfaces_confidence ON api_surfaces((metadata->>'confidence'), last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_infrastructure_ips_domain ON infrastructure_ips(domain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_infrastructure_ips_classification ON infrastructure_ips(classification, scan_eligible)",
                "CREATE INDEX IF NOT EXISTS idx_infrastructure_ip_subdomains_subdomain ON infrastructure_ip_subdomains(subdomain_id)",
                "CREATE INDEX IF NOT EXISTS idx_dns_records_domain_current ON dns_records(domain_id, is_current, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_dns_records_subdomain_type ON dns_records(subdomain_id, record_type, is_current)",
                "CREATE INDEX IF NOT EXISTS idx_port_scan_jobs_claim ON port_scan_jobs(status, available_at, priority DESC, created_at)",
                "CREATE INDEX IF NOT EXISTS idx_port_scan_jobs_lease ON port_scan_jobs(status, lease_expires_at)",
                "CREATE INDEX IF NOT EXISTS idx_port_scan_jobs_domain ON port_scan_jobs(domain_id, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_network_services_domain_state ON network_services(domain_id, state, port)",
                "CREATE INDEX IF NOT EXISTS idx_network_services_ip_state ON network_services(ip_asset_id, state, port)",
                "CREATE INDEX IF NOT EXISTS idx_shodan_jobs_claim ON shodan_jobs(status, available_at, priority DESC, created_at)",
                "CREATE INDEX IF NOT EXISTS idx_shodan_jobs_domain ON shodan_jobs(domain_id, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_shodan_domain_snapshots_domain ON shodan_domain_snapshots(domain_id, fetched_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_shodan_host_snapshots_ip ON shodan_host_snapshots(ip_asset_id, fetched_at DESC)",
            ):
                await conn.execute(ddl)
            parameter_name_limit = await conn.fetchval(
                """
                SELECT character_maximum_length
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'url_parameters'
                  AND column_name = 'param_name'
                """
            )
            if parameter_name_limit is not None:
                async with conn.transaction():
                    await conn.execute("DROP VIEW IF EXISTS parameter_risk_clusters")
                    await conn.execute("ALTER TABLE url_parameters ALTER COLUMN param_name TYPE TEXT")
                    await conn.execute(
                        """
                        CREATE VIEW parameter_risk_clusters AS
                        SELECT
                            up.param_name,
                            ARRAY_REMOVE(ARRAY_AGG(DISTINCT tag), NULL) AS risk_tags,
                            COUNT(*) AS occurrence_count,
                            COUNT(DISTINCT d.id) AS domain_count,
                            ARRAY_AGG(DISTINCT d.domain) AS domains,
                            MAX(up.last_seen) AS last_seen
                        FROM url_parameters up
                        JOIN endpoints e ON e.id = up.endpoint_id
                        JOIN live_hosts lh ON lh.id = e.live_host_id
                        JOIN subdomains s ON s.id = lh.subdomain_id
                        JOIN domains d ON d.id = s.domain_id
                        LEFT JOIN LATERAL UNNEST(up.risk_tags) AS tag ON TRUE
                        GROUP BY up.param_name
                        HAVING COUNT(*) > 0
                        """
                    )
            await conn.execute("ALTER TABLE active_hunt_results ALTER COLUMN parameter_name TYPE TEXT")
            await conn.execute(
                """
                UPDATE port_scan_jobs
                SET status = CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'failed' END,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    available_at = CASE
                      WHEN attempts < max_attempts THEN NOW()
                      ELSE available_at
                    END,
                    updated_at = NOW(),
                    error = COALESCE(error, 'worker lease expired')
                WHERE status = 'running'
                  AND lease_expires_at < NOW()
                """
            )
            await conn.execute(
                """
                UPDATE shodan_jobs
                SET status = CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'failed' END,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    available_at = CASE
                      WHEN attempts < max_attempts THEN NOW()
                      ELSE available_at
                    END,
                    updated_at = NOW(),
                    error = COALESCE(error, 'worker lease expired')
                WHERE status = 'running'
                  AND lease_expires_at < NOW()
                """
            )
            await conn.execute(
                """
                UPDATE api_surfaces
                SET metadata = metadata || jsonb_build_object(
                      'confidence', CASE WHEN status_code = 404 THEN 'rejected' ELSE 'candidate' END,
                      'verified', FALSE
                    ),
                    risk_flags = CASE
                      WHEN status_code = 404 THEN ARRAY['graphql_candidate', 'rejected']::text[]
                      ELSE ARRAY['graphql_candidate', 'candidate']::text[]
                    END
                WHERE surface_type = 'graphql'
                  AND NOT (metadata ? 'confidence')
                """
            )

    @staticmethod
    def entity_key(entity_type: str, entity_id: int | None, location: str) -> str:
        if entity_id is not None:
            return f"{entity_type}:{entity_id}"
        return hashlib.sha256(f"{entity_type}|{location}".encode()).hexdigest()

    async def load_scope_rules(self, domain_id: int) -> list[dict[str, Any]]:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT rule_type, pattern, reason
                FROM scope_rules
                WHERE enabled = TRUE
                  AND (domain_id = $1 OR domain_id IS NULL)
                ORDER BY domain_id NULLS LAST, id
                """,
                domain_id,
            )
            return [dict(row) for row in rows]

    async def load_auth_profiles(self, domain_id: int) -> list[dict[str, Any]]:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT name, profile_type, host_pattern, header_name, secret_ref, metadata
                FROM auth_profiles
                WHERE enabled = TRUE
                  AND (domain_id = $1 OR domain_id IS NULL)
                ORDER BY domain_id NULLS LAST, id
                """,
                domain_id,
            )
            return [dict(row) for row in rows]

    def pattern_matches(self, pattern: str, value: str) -> bool:
        pattern = str(pattern or "").strip()
        value = str(value or "")
        if not pattern:
            return False
        if pattern.startswith("regex:"):
            try:
                return re.search(pattern[6:], value, re.IGNORECASE) is not None
            except re.error:
                return False
        if any(ch in pattern for ch in "*?[]"):
            return fnmatch.fnmatch(value.lower(), pattern.lower())
        return pattern.lower() in value.lower()

    def is_scope_allowed(self, domain_info: dict[str, Any], value: str) -> bool:
        configured = self.config.scan.get("out_of_scope_patterns", []) or []
        rules = list(domain_info.get("_scope_rules") or [])
        rules.extend({"rule_type": "exclude", "pattern": item, "reason": "config"} for item in configured)
        for rule in rules:
            rule_type = str(rule.get("rule_type") or "exclude").lower()
            if rule_type in {"exclude", "deny", "out_of_scope"} and self.pattern_matches(str(rule.get("pattern") or ""), value):
                logger.info("Skipping out-of-scope target: %s matched %s", value, rule.get("pattern"))
                return False
        return True

    def is_explicitly_scope_included(self, domain_info: dict[str, Any], value: str) -> bool:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        for rule in domain_info.get("_scope_rules") or []:
            rule_type = str(rule.get("rule_type") or "").lower()
            if rule_type not in {"include", "allow", "in_scope", "allowlist"}:
                continue
            pattern = str(rule.get("pattern") or "").strip()
            if not pattern:
                continue
            lowered_pattern = pattern.lower().rstrip(".")
            if lowered_pattern.startswith("regex:"):
                matched = self.pattern_matches(pattern, value) or (
                    bool(hostname) and self.pattern_matches(pattern, hostname)
                )
            elif "://" in lowered_pattern or "/" in lowered_pattern:
                matched = (
                    fnmatch.fnmatch(value.lower(), lowered_pattern)
                    if any(char in lowered_pattern for char in "*?[]")
                    else value.lower().startswith(lowered_pattern)
                )
            elif any(char in lowered_pattern for char in "*?[]"):
                matched = bool(hostname) and fnmatch.fnmatch(hostname, lowered_pattern)
            else:
                matched = hostname == lowered_pattern
            if matched:
                return True
        return False

    def is_target_or_explicitly_allowed_url(self, domain_info: dict[str, Any], value: str) -> bool:
        return self.is_scope_allowed(domain_info, value) and (
            self.is_target_domain_url(domain_info, value)
            or self.is_explicitly_scope_included(domain_info, value)
        )

    @staticmethod
    def is_target_domain_url(domain_info: dict[str, Any], value: str) -> bool:
        root_domain = str(domain_info.get("domain") or "").lower().strip().lstrip(".")
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        return bool(root_domain and (hostname == root_domain or hostname.endswith(f".{root_domain}")))

    def resolve_secret_ref(self, secret_ref: str | None) -> str | None:
        if not secret_ref:
            return None
        secret_ref = str(secret_ref).strip()
        if secret_ref.startswith("env:"):
            return os.getenv(secret_ref[4:].strip()) or None
        if secret_ref.startswith("file:"):
            path = Path(secret_ref[5:].strip())
            try:
                if path.is_file():
                    return path.read_text(encoding="utf-8", errors="ignore").strip()
            except OSError as exc:
                logger.warning("Unable to read auth profile secret %s: %s", path, exc)
            return None
        return secret_ref

    def auth_profile_matches(self, profile: dict[str, Any], url_or_host: str) -> bool:
        pattern = str(profile.get("host_pattern") or "*").strip()
        parsed = urlsplit(url_or_host if "://" in url_or_host else f"https://{url_or_host}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        candidate = url_or_host.lower()
        if pattern == "*":
            return True
        return self.pattern_matches(pattern, hostname) or self.pattern_matches(pattern, candidate)

    def auth_profile_headers(self, domain_info: dict[str, Any], url_or_host: str | None = None) -> dict[str, str]:
        if not url_or_host:
            return {}
        profiles = list(domain_info.get("_auth_profiles") or [])
        headers: dict[str, str] = {}
        for profile in profiles:
            if not self.auth_profile_matches(profile, url_or_host):
                continue
            metadata = normalize_json_value(profile.get("metadata"))
            if not isinstance(metadata, dict):
                metadata = {}
            value = self.resolve_secret_ref(profile.get("secret_ref")) or str(metadata.get("value") or "").strip()
            profile_type = str(profile.get("profile_type") or "cookie").lower()
            if profile_type == "cookie":
                if value.lower().startswith("cookie:"):
                    _, _, value = value.partition(":")
                if value.strip():
                    headers.setdefault("Cookie", value.strip())
            if profile_type == "bearer" and value.strip():
                headers.setdefault("Authorization", f"Bearer {value.strip()}")
            if profile_type == "header":
                header_name = str(profile.get("header_name") or metadata.get("header_name") or "").strip()
                if header_name and value.strip():
                    if not any(existing.lower() == header_name.lower() for existing in headers):
                        headers[header_name] = value.strip()
        return headers

    def authenticated_header_lines(self, domain_info: dict[str, Any], url_or_host: str | None = None) -> list[str]:
        headers = self.authenticated_headers(url_or_host, domain_info)
        return [f"{name}: {value}" for name, value in headers.items()]

    async def record_asset_event(
        self,
        domain_id: int | None,
        event_type: str,
        entity_type: str,
        entity_id: int | None,
        location: str,
        severity: str = "info",
        payload: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        location = strip_postgres_nuls(location) or ""
        event_type = strip_postgres_nuls(event_type) or ""
        entity_type = strip_postgres_nuls(entity_type) or ""
        severity = strip_postgres_nuls(severity) or "info"
        payload = sanitize_postgres_value(payload or {})
        event_key = hashlib.sha256(f"{domain_id}|{event_type}|{entity_type}|{entity_id}|{location}".encode()).hexdigest()
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO asset_events (domain_id, event_key, event_type, entity_type, entity_id, location, severity, payload)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                ON CONFLICT (event_key)
                DO UPDATE SET last_seen = NOW(), payload = EXCLUDED.payload, severity = EXCLUDED.severity
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                event_key,
                event_type,
                entity_type,
                entity_id,
                location,
                severity,
                postgres_json(payload),
            )
        if row and row["inserted"]:
            self.append_summary(
                summary,
                "asset_events",
                {"event_type": event_type, "entity_type": entity_type, "location": location, "severity": severity},
            )

    async def get_due_monitor_targets(self, domain_id: int | None = None) -> list[dict[str, Any]]:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT mt.*, d.domain
                FROM monitor_targets mt
                JOIN domains d ON d.id = mt.domain_id
                WHERE mt.enabled = TRUE
                  AND d.active = TRUE
                  AND ($1::int IS NULL OR mt.domain_id = $1)
                  AND (
                    mt.last_run_at IS NULL
                    OR mt.last_run_at < NOW() - make_interval(hours => mt.interval_hours)
                  )
                ORDER BY mt.last_run_at NULLS FIRST, mt.id
                LIMIT 20
                """,
                domain_id,
            )
            return [dict(row) for row in rows]

    def monitor_item_alertable(self, risk: str, min_risk: str) -> bool:
        ranks = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return ranks.get(str(risk or "info").lower(), 0) >= ranks.get(str(min_risk or "medium").lower(), 2)

    async def record_monitor_item(
        self,
        monitor: dict[str, Any],
        item: dict[str, Any],
        summary: dict[str, Any] | None = None,
        run_id: int | None = None,
    ) -> dict[str, Any] | None:
        assert self.db_pool is not None
        domain_id = int(monitor["domain_id"])
        monitor_id = int(monitor["id"])
        item_type = strip_postgres_nuls(str(item.get("item_type") or "unknown")) or "unknown"
        value = strip_postgres_nuls(str(item.get("value") or "")) or ""
        if not value:
            return None
        item_key = strip_postgres_nuls(str(item.get("item_key") or hashlib.sha256(f"{item_type}|{value}".encode()).hexdigest())) or ""
        risk = strip_postgres_nuls(str(item.get("risk") or "info")) or "info"
        source_url = strip_postgres_nuls(str(item.get("source_url") or "")) or None
        metadata = sanitize_postgres_value(item.get("metadata") or {})
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO monitor_intel_items (monitor_id, domain_id, item_type, item_key, value, risk, source_url, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                ON CONFLICT (monitor_id, item_type, item_key)
                DO UPDATE SET last_seen = NOW(), value = EXCLUDED.value, risk = EXCLUDED.risk, source_url = EXCLUDED.source_url, metadata = EXCLUDED.metadata
                RETURNING id, (xmax = 0) AS inserted
                """,
                monitor_id,
                domain_id,
                item_type,
                item_key,
                value,
                risk,
                source_url,
                postgres_json(metadata),
            )
            if not row or not row["inserted"]:
                return None
            event = await conn.fetchrow(
                """
                INSERT INTO monitor_events (run_id, monitor_id, domain_id, event_type, item_type, item_key, value, severity, summary, payload)
                VALUES ($1, $2, $3, 'new_monitor_intel', $4, $5, $6, $7, $8, $9::jsonb)
                ON CONFLICT (monitor_id, event_type, item_key)
                DO UPDATE SET last_seen = NOW(), severity = EXCLUDED.severity, payload = EXCLUDED.payload
                RETURNING id, run_id, monitor_id, domain_id, event_type, item_type, item_key, value, severity, summary, payload, first_seen, last_seen
                """,
                run_id,
                monitor_id,
                domain_id,
                item_type,
                item_key,
                value,
                risk,
                f"New {item_type}: {value}",
                postgres_json({"source_url": source_url, "metadata": metadata, "monitor": monitor.get("name")}),
            )
        event_dict = dict(event) if event else None
        if event_dict:
            self.append_summary(
                summary,
                "monitor_events",
                {
                    "monitor": monitor.get("name"),
                    "item_type": item_type,
                    "value": value,
                    "severity": risk,
                    "source_url": source_url,
                },
            )
        return event_dict

    async def start_monitor_run(self, monitor: dict[str, Any]) -> int:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            return int(await conn.fetchval(
                """
                INSERT INTO monitor_runs (monitor_id, domain_id, status)
                VALUES ($1, $2, 'running')
                RETURNING id
                """,
                int(monitor["id"]),
                int(monitor["domain_id"]),
            ))

    async def finish_monitor_run(
        self,
        monitor: dict[str, Any],
        run_id: int,
        status: str,
        result: dict[str, Any] | None = None,
        events: list[dict[str, Any]] | None = None,
        error: str | None = None,
    ) -> None:
        assert self.db_pool is not None
        result = result or {}
        events = events or []
        auth = result.get("auth") or {}
        auth_status = str(auth.get("status") or ("error" if error else "unchecked"))
        auth_error = error if error else (None if auth_status in {"ok", "unchecked", "not_required"} else auth_status)
        js_sha256 = ""
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE monitor_runs
                SET status = $2,
                    finished_at = NOW(),
                    duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at)),
                    auth_status = $3,
                    new_items_count = $4,
                    new_events_count = $5,
                    scripts_count = $6,
                    requests_count = $7,
                    error = $8,
                    summary = $9::jsonb
                WHERE id = $1
                """,
                run_id,
                status,
                auth_status,
                len(events),
                len(events),
                len(result.get("scripts") or []),
                len(result.get("requests") or []),
                error,
                postgres_json({"auth": auth, "start_url": result.get("start_url")}),
            )
            await conn.execute(
                """
                UPDATE monitor_targets
                SET last_run_at = NOW(),
                    last_error = $2,
                    auth_status = $3,
                    auth_last_checked_at = NOW(),
                    auth_last_error = $4,
                    updated_at = NOW()
                WHERE id = $1
                """,
                int(monitor["id"]),
                error,
                auth_status,
                auth_error,
            )

    async def run_monitor_target(self, monitor: dict[str, Any], summary: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        assert self.db_pool is not None
        monitor_id = int(monitor["id"])
        lock_conn = await self.db_pool.acquire()
        lock_acquired = False
        try:
            lock_acquired = bool(await lock_conn.fetchval("SELECT pg_try_advisory_lock($1, $2)", 817263546, monitor_id))
            if not lock_acquired:
                logger.info("Monitor %s is already running; skipping duplicate run", monitor_id)
                return []
        finally:
            if not lock_acquired:
                await self.db_pool.release(lock_conn)
        logger.info("Running monitor %s for %s", monitor.get("name"), monitor.get("start_url"))
        run_id = await self.start_monitor_run(monitor)
        metadata = normalize_json_value(monitor.get("metadata"))
        if not isinstance(metadata, dict):
            metadata = {}
        extra_routes = normalize_json_value(monitor.get("extra_routes"))
        config = {
            "start_url": monitor.get("start_url"),
            "auth_type": monitor.get("auth_type"),
            "cookie_secret_ref": monitor.get("cookie_secret_ref"),
            "login_url": monitor.get("login_url"),
            "login_email": monitor.get("login_email"),
            "password_secret_ref": monitor.get("password_secret_ref"),
            "username_selector": monitor.get("username_selector"),
            "password_selector": monitor.get("password_selector"),
            "submit_selector": monitor.get("submit_selector"),
            "auth_check_url": monitor.get("auth_check_url"),
            "auth_check_selector": monitor.get("auth_check_selector"),
            "auth_check_text": monitor.get("auth_check_text"),
            "auth_failure_text": monitor.get("auth_failure_text"),
            "extra_routes": extra_routes if isinstance(extra_routes, list) else [],
            "max_seconds": metadata.get("max_seconds", 45),
        }
        try:
            result = await run_browser_monitor(config)
            events: list[dict[str, Any]] = []
            for script in result.get("scripts") or []:
                if script.get("sha256"):
                    event = await self.record_monitor_item(
                        monitor,
                        {
                            "item_type": "js_content_hash",
                            "value": str(script.get("sha256")),
                            "risk": "info",
                            "source_url": script.get("url"),
                            "metadata": {"url": script.get("url"), "status": script.get("status"), "size_bytes": script.get("size_bytes")},
                        },
                        summary,
                        run_id,
                    )
                    if event:
                        events.append(event)
            for item in result.get("items") or []:
                event = await self.record_monitor_item(monitor, item, summary, run_id)
                if event:
                    events.append(event)
            await self.finish_monitor_run(monitor, run_id, "success", result, events)
            alertable = [
                event for event in events
                if self.monitor_item_alertable(str(event.get("severity") or "info"), str(monitor.get("alert_min_risk") or "medium"))
            ]
            auth_status = str((result.get("auth") or {}).get("status") or "unchecked")
            if auth_status not in {"ok", "unchecked", "not_required"}:
                await self.send_alert(
                    "monitor_auth_warning",
                    f"Monitor auth warning: {monitor.get('name') or monitor.get('start_url')}\nTarget: {monitor.get('start_url')}\nAuth status: {auth_status}",
                    {
                        "monitor_id": monitor["id"],
                        "domain_id": monitor["domain_id"],
                        "run_id": run_id,
                        "auth": sanitize_postgres_value(result.get("auth") or {}),
                    },
                )
            if alertable:
                lines = [
                    f"Monitor changes: {monitor.get('name') or monitor.get('start_url')}",
                    f"Target: {monitor.get('start_url')}",
                    f"New alertable items: {len(alertable)}",
                ]
                for event in alertable[:8]:
                    lines.append(f"- [{str(event.get('severity')).upper()}] {event.get('item_type')}: {event.get('value')}")
                await self.send_alert(
                    "monitor_changes",
                    "\n".join(lines),
                    {"monitor_id": monitor["id"], "domain_id": monitor["domain_id"], "run_id": run_id, "events": sanitize_postgres_value(alertable[:25])},
                )
            return events
        except Exception as exc:
            logger.exception("Monitor failed for %s: %s", monitor.get("start_url"), exc)
            await self.finish_monitor_run(monitor, run_id, "failed", error=repr(exc))
            await self.send_alert(
                "monitor_error",
                f"Monitor failed: {monitor.get('name') or monitor.get('start_url')}\nTarget: {monitor.get('start_url')}\nError: {repr(exc)}",
                {"monitor_id": monitor["id"], "domain_id": monitor["domain_id"], "run_id": run_id, "error": repr(exc)},
            )
            return []
        finally:
            if lock_acquired:
                try:
                    await lock_conn.execute("SELECT pg_advisory_unlock($1, $2)", 817263546, monitor_id)
                finally:
                    await self.db_pool.release(lock_conn)

    async def run_due_monitors(self, domain_id: int | None = None, summary: dict[str, Any] | None = None) -> None:
        if not bool(self.config.scan.get("change_monitors_enabled", True)):
            return
        monitors = await self.get_due_monitor_targets(domain_id)
        if not monitors:
            return
        max_concurrent = max(1, min(int(self.config.scan.get("change_monitor_concurrency", 1)), 3))
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_one(monitor: dict[str, Any]) -> None:
            async with semaphore:
                await self.run_monitor_target(monitor, summary)

        await asyncio.gather(*(run_one(monitor) for monitor in monitors))

    async def upsert_asset_risk(
        self,
        domain_id: int | None,
        entity_type: str,
        entity_id: int | None,
        location: str,
        decision: dict[str, Any],
    ) -> None:
        assert self.db_pool is not None
        entity_key = self.entity_key(entity_type, entity_id, location)
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO asset_risk_scores (
                  domain_id, entity_type, entity_id, entity_key, location, score, priority, reasons, recommended_actions, run_profiles
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (entity_type, entity_key)
                DO UPDATE SET
                  domain_id = EXCLUDED.domain_id,
                  location = EXCLUDED.location,
                  score = EXCLUDED.score,
                  priority = EXCLUDED.priority,
                  reasons = EXCLUDED.reasons,
                  recommended_actions = EXCLUDED.recommended_actions,
                  run_profiles = EXCLUDED.run_profiles,
                  updated_at = NOW()
                """,
                domain_id,
                strip_postgres_nuls(entity_type) or "",
                entity_id,
                entity_key,
                strip_postgres_nuls(location) or "",
                int(decision.get("score") or 0),
                strip_postgres_nuls(str(decision.get("priority") or "low")) or "low",
                sanitize_postgres_value(decision.get("reasons") or []),
                sanitize_postgres_value(decision.get("recommended_actions") or []),
                sanitize_postgres_value(decision.get("run_profiles") or []),
            )
        await self.record_attack_playbooks(
            domain_id,
            entity_type,
            entity_id,
            location,
            decision,
            {
                "entity_type": entity_type,
                "location": location,
                "score": decision.get("score"),
                "priority": decision.get("priority"),
                "reasons": decision.get("reasons") or [],
                "recommended_actions": decision.get("recommended_actions") or [],
                "run_profiles": decision.get("run_profiles") or [],
            },
        )

    async def save_cloud_asset(
        self,
        domain_id: int | None,
        provider: str,
        asset_type: str,
        identifier: str,
        location: str,
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        if not provider or not identifier:
            return False
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO cloud_assets (domain_id, provider, asset_type, identifier, location, source, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
                ON CONFLICT (domain_id, provider, asset_type, identifier)
                DO UPDATE SET last_seen = NOW(), location = EXCLUDED.location, source = EXCLUDED.source, metadata = EXCLUDED.metadata
                RETURNING (xmax = 0) AS inserted
                """,
                domain_id,
                provider,
                asset_type,
                identifier,
                location,
                source,
                postgres_json(sanitize_postgres_value(metadata or {})),
            )
            return bool(row and row["inserted"])

    def cloud_inventory_items(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("assets", "resources", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                defaults = {name: payload.get(name) for name in ("provider", "source", "domain", "domains") if payload.get(name)}
                return [{**defaults, **item} for item in value if isinstance(item, dict)]
        if payload.get("identifier") or payload.get("location") or payload.get("arn"):
            return [payload]
        return []

    def cloud_inventory_matches_domain(self, item: dict[str, Any], domain: str) -> bool:
        domain = domain.lower().strip().lstrip(".")
        explicit_domains = item.get("domains") or item.get("domain") or []
        if isinstance(explicit_domains, str):
            explicit_domains = [explicit_domains]
        for value in explicit_domains:
            marker = str(value).lower().strip().lstrip(".")
            if marker == domain or marker.endswith(f".{domain}"):
                return True

        hostnames = item.get("hostnames") or item.get("hosts") or item.get("dns_names") or []
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        for value in hostnames:
            host = str(value).lower().strip().lstrip(".")
            if host == domain or host.endswith(f".{domain}"):
                return True

        haystacks = [
            item.get("identifier"),
            item.get("location"),
            item.get("url"),
            item.get("name"),
            item.get("arn"),
        ]
        return any(domain in str(value).lower() for value in haystacks if value)

    async def ingest_cloud_inventory(self, domain_info: dict[str, Any], summary: dict[str, Any] | None = None) -> int:
        config = self.config.data.get("cloud_inventory", {}) or {}
        if not bool(config.get("enabled", True)):
            return 0
        directory = Path(str(config.get("directory") or "/app/cloud_inventory"))
        if not directory.is_dir():
            return 0

        imported = 0
        domain = str(domain_info["domain"]).lower()
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Skipping cloud inventory %s: %s", path, exc)
                continue
            for item in self.cloud_inventory_items(payload):
                if not self.cloud_inventory_matches_domain(item, domain):
                    continue
                provider = str(item.get("provider") or "unknown").strip().lower()
                asset_type = str(item.get("asset_type") or item.get("type") or "resource").strip().lower()
                identifier = str(item.get("identifier") or item.get("name") or item.get("arn") or "").strip()
                location = str(item.get("location") or item.get("url") or identifier).strip()
                if not identifier:
                    continue
                metadata = {key: value for key, value in item.items() if key not in {"provider", "asset_type", "type", "identifier", "location", "url", "source"}}
                metadata["inventory_file"] = path.name
                source = str(item.get("source") or config.get("source") or "cloud_inventory").strip()
                inserted = await self.save_cloud_asset(domain_info["id"], provider, asset_type, identifier, location, source, metadata)
                await self.record_asset_event(
                    domain_info["id"],
                    "cloud_inventory_asset",
                    "cloud_asset",
                    None,
                    location,
                    "info",
                    {"provider": provider, "asset_type": asset_type, "identifier": identifier, "source": source},
                    summary,
                )
                if inserted:
                    self.append_summary(
                        summary,
                        "cloud_assets",
                        {"provider": provider, "asset_type": asset_type, "identifier": identifier, "location": location},
                    )
                imported += 1
        if imported:
            logger.info("Imported %s cloud inventory assets for %s", imported, domain)
        return imported

    async def detect_cloud_asset(self, domain_id: int | None, location: str, source: str) -> None:
        text = str(location or "").lower()
        parsed = urlsplit(location if "://" in location else f"https://{location}")
        host = (parsed.hostname or text).lower()
        rules = [
            ("aws", "cdn", "cloudfront.net"),
            ("aws", "storage", "s3.amazonaws.com"),
            ("aws", "storage", ".s3."),
            ("azure", "app", "azurewebsites.net"),
            ("azure", "storage", "blob.core.windows.net"),
            ("gcp", "storage", "storage.googleapis.com"),
            ("gcp", "app", "appspot.com"),
            ("vercel", "app", "vercel.app"),
            ("netlify", "app", "netlify.app"),
            ("heroku", "app", "herokuapp.com"),
            ("firebase", "app", "firebaseapp.com"),
            ("cloudflare", "edge", "pages.dev"),
            ("fastly", "edge", "fastly.net"),
        ]
        for provider, asset_type, needle in rules:
            if needle in host or (not parsed.hostname and needle in text):
                await self.save_cloud_asset(
                    domain_id,
                    provider,
                    asset_type,
                    host,
                    location,
                    source,
                    {"matched": needle},
                )
                return

    async def save_api_surface(
        self,
        domain_id: int,
        live_host_id: int | None,
        surface_type: str,
        location: str,
        source: str,
        status_code: int | None = None,
        auth_required: bool | None = None,
        schema_url: str | None = None,
        methods: list[str] | None = None,
        operations_count: int = 0,
        risk_flags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        risk_flags = sorted({str(item).lower() for item in (risk_flags or []) if str(item)})
        methods = sorted({str(item).upper() for item in (methods or []) if str(item)})
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO api_surfaces (
                  domain_id, live_host_id, surface_type, location, source, status_code, auth_required, schema_url, methods, operations_count, risk_flags, metadata
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)
                ON CONFLICT (domain_id, surface_type, location)
                DO UPDATE SET
                  live_host_id = COALESCE(EXCLUDED.live_host_id, api_surfaces.live_host_id),
                  source = EXCLUDED.source,
                  status_code = COALESCE(EXCLUDED.status_code, api_surfaces.status_code),
                  auth_required = COALESCE(EXCLUDED.auth_required, api_surfaces.auth_required),
                  schema_url = COALESCE(EXCLUDED.schema_url, api_surfaces.schema_url),
                  methods = EXCLUDED.methods,
                  operations_count = GREATEST(api_surfaces.operations_count, EXCLUDED.operations_count),
                  risk_flags = EXCLUDED.risk_flags,
                  metadata = EXCLUDED.metadata,
                  last_seen = NOW()
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                live_host_id,
                surface_type,
                location,
                source,
                status_code,
                auth_required,
                schema_url,
                methods,
                int(operations_count or 0),
                risk_flags,
                postgres_json(sanitize_postgres_value(metadata or {})),
            )
        if row and row["inserted"]:
            await self.record_asset_event(
                domain_id,
                "api_surface_discovered",
                "api_surface",
                int(row["id"]),
                location,
                "medium" if risk_flags else "info",
                {
                    "surface_type": surface_type,
                    "source": source,
                    "status_code": status_code,
                    "risk_flags": risk_flags,
                    "operations_count": operations_count,
                },
                summary,
            )
            decision = self.analyze_triage_payload(
                "api_surface",
                location,
                {
                    "source": source,
                    "status_code": status_code,
                    "risk_tags": risk_flags,
                    "parameters": [{"name": "api_surface"}] if surface_type in {"openapi", "graphql"} else [],
                    "details": metadata or {},
                },
            )
            await self.upsert_asset_risk(domain_id, "api_surface", int(row["id"]), location, decision)

    async def verify_graphql_endpoint(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        target: str,
        source: str,
        initial_status: int | None = None,
        summary: dict[str, Any] | None = None,
        discovery_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.is_target_domain_url(domain_info, target) or not self.is_scope_allowed(domain_info, target):
            result = {
                "confidence": "candidate",
                "verified": False,
                "verification_skipped": "out_of_scope_host",
                "discovery": discovery_metadata or {},
            }
            await self.save_api_surface(
                int(domain_info["id"]),
                live_host_id,
                "graphql",
                target,
                source,
                initial_status,
                auth_required=initial_status in {401, 403},
                risk_flags=["graphql_candidate", "candidate"],
                metadata=result,
                summary=summary,
            )
            return result

        if not self.config.scan.get("graphql_verification_enabled", True):
            result = {
                "confidence": "candidate",
                "verified": False,
                "discovery": discovery_metadata or {},
            }
            await self.save_api_surface(
                int(domain_info["id"]),
                live_host_id,
                "graphql",
                target,
                source,
                initial_status,
                auth_required=initial_status in {401, 403},
                risk_flags=["graphql_candidate"],
                metadata=result,
                summary=summary,
            )
            return result

        timeout = aiohttp.ClientTimeout(
            total=float(self.config.scan.get("graphql_verification_timeout_seconds", 10))
        )
        max_bytes = int(self.config.scan.get("graphql_verification_max_response_bytes", 262144))
        base_headers = self.authenticated_headers(target, domain_info)
        headers = {
            **base_headers,
            "Accept": "application/graphql-response+json, application/json",
        }
        probes: list[dict[str, Any]] = []

        async def record_response(method: str, response: aiohttp.ClientResponse) -> None:
            body_bytes = await response.content.read(max_bytes + 1)
            truncated = len(body_bytes) > max_bytes
            body = body_bytes[:max_bytes].decode("utf-8", errors="ignore")
            classification = classify_graphql_response(
                response.status,
                response.headers.get("content-type", ""),
                body,
            )
            probes.append(
                {
                    "method": method,
                    "status_code": response.status,
                    "content_type": response.headers.get("content-type", "")[:160],
                    "truncated": truncated,
                    **classification,
                }
            )

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    async with session.post(
                        target,
                        json={"query": GRAPHQL_TYPENAME_QUERY},
                        allow_redirects=True,
                        headers={**headers, "Content-Type": "application/json"},
                    ) as response:
                        await record_response("POST", response)
                except Exception as exc:
                    probes.append({"method": "POST", "confidence": "candidate", "error": type(exc).__name__})

                try:
                    async with session.get(
                        target,
                        params={"query": GRAPHQL_TYPENAME_QUERY},
                        allow_redirects=True,
                        headers=headers,
                    ) as response:
                        await record_response("GET", response)
                except Exception as exc:
                    probes.append({"method": "GET", "confidence": "candidate", "error": type(exc).__name__})

                confirmed = any(probe.get("confidence") == "confirmed" for probe in probes)
                if confirmed and self.config.scan.get("graphql_introspection_enabled", False):
                    try:
                        async with session.post(
                            target,
                            json={"query": GRAPHQL_INTROSPECTION_QUERY},
                            allow_redirects=True,
                            headers={**headers, "Content-Type": "application/json"},
                        ) as response:
                            body = (await response.content.read(max_bytes + 1))[:max_bytes].decode(
                                "utf-8", errors="ignore"
                            )
                            payload = json.loads(body)
                            schema = payload.get("data", {}).get("__schema") if isinstance(payload, dict) else None
                            probes.append(
                                {
                                    "method": "POST_INTROSPECTION",
                                    "status_code": response.status,
                                    "introspection_enabled": isinstance(schema, dict),
                                }
                            )
                    except Exception:
                        pass
        except Exception as exc:
            probes.append({"method": "SESSION", "confidence": "candidate", "error": type(exc).__name__})

        confidence_rank = {"rejected": 0, "candidate": 1, "probable": 2, "confirmed": 3}
        confidence = max(
            (str(probe.get("confidence") or "candidate") for probe in probes),
            key=lambda value: confidence_rank.get(value, 1),
            default="candidate",
        )
        if probes and all(probe.get("confidence") == "rejected" for probe in probes):
            confidence = "rejected"
        methods = [
            str(probe["method"])
            for probe in probes
            if probe.get("method") in {"GET", "POST"}
            and (
                probe.get("graphql_response")
                or probe.get("status_code") in {401, 403}
            )
        ]
        auth_required = any(probe.get("status_code") in {401, 403} for probe in probes)
        representative = max(
            probes,
            key=lambda probe: confidence_rank.get(str(probe.get("confidence") or "candidate"), 1),
            default={},
        )
        metadata = {
            "confidence": confidence,
            "verified": True,
            "probes": probes,
            "discovery": discovery_metadata or {},
        }
        risk_flags = ["graphql", confidence] if confidence in {"confirmed", "probable"} else ["graphql_candidate", confidence]
        if auth_required:
            risk_flags.append("auth_required")
        await self.save_api_surface(
            int(domain_info["id"]),
            live_host_id,
            "graphql",
            target,
            source,
            representative.get("status_code", initial_status),
            auth_required=auth_required,
            methods=methods,
            operations_count=int((discovery_metadata or {}).get("operations_count") or 0),
            risk_flags=risk_flags,
            metadata=metadata,
            summary=summary,
        )
        return metadata

    def summarize_openapi_spec(self, spec_text: str) -> dict[str, Any]:
        try:
            payload = json.loads(spec_text)
        except json.JSONDecodeError:
            try:
                payload = yaml.safe_load(spec_text)
            except yaml.YAMLError:
                payload = None
        if not isinstance(payload, dict):
            return {"methods": [], "operations_count": 0, "risk_flags": ["unparsed_spec"], "metadata": {}}
        paths = payload.get("paths") if isinstance(payload.get("paths"), dict) else {}
        methods: set[str] = set()
        operations_count = 0
        risk_flags: set[str] = set()
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            lowered_path = str(path).lower()
            if any(token in lowered_path for token in ("admin", "internal", "debug", "config", "token", "secret")):
                risk_flags.add("sensitive_path")
            for method, operation in item.items():
                method_lower = str(method).lower()
                if method_lower not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                methods.add(method_lower.upper())
                operations_count += 1
                operation_text = json.dumps(operation, default=str).lower()
                if any(token in operation_text for token in ("admin", "internal", "debug", "token", "password", "secret", "upload", "import", "export")):
                    risk_flags.add("sensitive_operation")
        components = payload.get("components") if isinstance(payload.get("components"), dict) else {}
        security = payload.get("security") or components.get("securitySchemes")
        if not security:
            risk_flags.add("no_global_security")
        return {
            "methods": sorted(methods),
            "operations_count": operations_count,
            "risk_flags": sorted(risk_flags),
            "metadata": {
                "title": (payload.get("info") or {}).get("title") if isinstance(payload.get("info"), dict) else None,
                "version": (payload.get("info") or {}).get("version") if isinstance(payload.get("info"), dict) else None,
            },
        }

    async def create_evidence_pack(
        self,
        domain_id: int | None,
        source_table: str,
        source_id: int | None,
        title: str,
        location: str,
        severity: str,
        raw: dict[str, Any],
        summary: str | None = None,
    ) -> int | None:
        assert self.db_pool is not None
        evidence_key = hashlib.sha256(f"{source_table}|{source_id}|{location}|{title}".encode()).hexdigest()
        request = {"url": location, "method": "GET"} if location.startswith(("http://", "https://")) else {}
        response = {}
        if isinstance(raw, dict):
            status = raw.get("status_code") or raw.get("severity")
            if status is None and isinstance(raw.get("details"), dict):
                status = raw["details"].get("status_code")
            if status is not None:
                response["observed"] = status
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO evidence_packs (
                  domain_id, source_table, source_id, evidence_key, title, location, severity, summary, request, response, raw
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11::jsonb)
                ON CONFLICT (evidence_key)
                DO UPDATE SET
                  severity = EXCLUDED.severity,
                  summary = EXCLUDED.summary,
                  request = EXCLUDED.request,
                  response = EXCLUDED.response,
                  raw = EXCLUDED.raw,
                  updated_at = NOW()
                RETURNING id
                """,
                domain_id,
                source_table,
                source_id,
                evidence_key,
                title,
                location,
                severity,
                summary or title,
                postgres_json(request),
                postgres_json(response),
                postgres_json(sanitize_postgres_value(raw)),
            )
            return int(row["id"]) if row else None

    async def enqueue_validation(
        self,
        domain_id: int | None,
        finding_id: int | None,
        evidence_pack_id: int | None,
        source_table: str,
        source_id: int | None,
        priority: str,
        location: str,
        steps: list[str],
    ) -> None:
        assert self.db_pool is not None
        clean_source_table = strip_postgres_nuls(source_table) or "unknown"
        clean_location = strip_postgres_nuls(location) or ""
        queue_key = hashlib.sha256(f"{clean_source_table}|{source_id}|{clean_location}".encode()).hexdigest()
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO validation_queue (
                  domain_id, finding_id, evidence_pack_id, source_table, source_id, queue_key, priority, location, validation_steps
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (queue_key)
                DO UPDATE SET
                  finding_id = EXCLUDED.finding_id,
                  evidence_pack_id = EXCLUDED.evidence_pack_id,
                  priority = EXCLUDED.priority,
                  location = EXCLUDED.location,
                  validation_steps = EXCLUDED.validation_steps,
                  updated_at = NOW()
                """,
                domain_id,
                finding_id,
                evidence_pack_id,
                clean_source_table,
                source_id,
                queue_key,
                priority,
                clean_location,
                steps,
            )

    def build_attack_playbooks(
        self,
        source_table: str,
        source_id: int | None,
        location: str,
        decision: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        text = f"{source_table} {location} {json.dumps(payload or {}, default=str)} {' '.join(decision.get('reasons') or [])} {' '.join(decision.get('recommended_actions') or [])}".lower()
        priority = str(decision.get("priority") or "medium")
        reasons = dedupe_list([str(item) for item in (decision.get("reasons") or []) if str(item)])[:12]
        common_stop = [
            "stop before destructive state changes, billing changes, mass emails, or data deletion",
            "stop on repeated 5xx responses or rate-limit signals",
            "stay inside the configured scope and authorization boundaries",
        ]
        common_safety = [
            "use only accounts and cookies authorized for this target",
            "keep request rate within the program limit",
            "capture minimal proof and avoid accessing other users' sensitive data",
        ]

        def playbook(
            check_type: str,
            owasp_category: str,
            steps: list[str],
            extra_reasons: list[str] | None = None,
            confidence: str = "candidate",
        ) -> dict[str, Any]:
            key = hashlib.sha256(f"{source_table}|{source_id}|{location}|{check_type}".encode()).hexdigest()
            return {
                "playbook_key": key,
                "target_url": location,
                "owasp_category": owasp_category,
                "check_type": check_type,
                "priority": priority,
                "confidence": confidence,
                "reasons": dedupe_list([*(reasons or []), *(extra_reasons or [])])[:12],
                "validation_steps": dedupe_list([
                    "confirm the host and path are in scope",
                    "reproduce the baseline response with a fresh request",
                    *steps,
                    "record status, response length, relevant headers, and a minimal response snippet",
                ])[:16],
                "stop_conditions": common_stop,
                "safety_notes": common_safety,
                "payload": sanitize_postgres_value(payload or {}),
            }

        candidates: list[dict[str, Any]] = []
        if "graphql" in text or "graphiql" in text or "/gql" in text:
            candidates.append(
                playbook(
                    "graphql_api_authz",
                    "API5:2023 Broken Function Level Authorization",
                    [
                        "check whether introspection or schema hints are exposed without authentication",
                        "compare the same safe query across unauthenticated, low-privilege, and owner cookies",
                        "test field-level authorization with object IDs owned by another authorized test account",
                        "try aliases and batching only with read-only operations first",
                    ],
                    ["graphql surface"],
                    "high" if priority in {"critical", "high"} else "candidate",
                )
            )
        if any(token in text for token in ("parameter", " id", "_id", "uuid", "tenant", "org", "workspace", "project", "account")):
            candidates.append(
                playbook(
                    "bac_idor_bola",
                    "A01:2021 Broken Access Control",
                    [
                        "identify object IDs in the request path, query string, JSON body, and response",
                        "create fresh objects as User A and User B before replaying cross-user access checks",
                        "test GET, POST, PUT, PATCH, and DELETE only where the action is non-destructive or reversible",
                        "compare owner, member, viewer, and unauthenticated responses for authorization bypass",
                    ],
                    ["object or tenant identifier"],
                )
            )
        if any(token in text for token in ("redirect", "callback", "return_to", "next=", "url=", "uri=", "webhook", "fetch", "import")):
            candidates.append(
                playbook(
                    "ssrf_open_redirect_callback",
                    "A10:2021 Server-Side Request Forgery",
                    [
                        "test harmless external callback and redirect targets with allowlist-bypass encodings",
                        "check whether redirects preserve tokens, codes, state, or sensitive query parameters",
                        "for URL fetchers, use a controlled collaborator endpoint and avoid internal IP probing unless explicitly allowed",
                        "verify whether webhook/import previews leak headers, metadata, or fetched content",
                    ],
                    ["URL-like sink"],
                )
            )
        if any(token in text for token in ("upload", "file", "path", "download", "export", "import", "xml", "archive")):
            candidates.append(
                playbook(
                    "file_upload_traversal_xxe",
                    "A05:2021 Security Misconfiguration",
                    [
                        "check content-type, extension, archive, and parser behavior with inert test files",
                        "test path traversal only against owned files or safe sentinel paths",
                        "check whether exports/downloads enforce ownership on generated file IDs",
                        "look for XML parser behavior without using external entity callbacks unless allowed",
                    ],
                    ["file or parser workflow"],
                )
            )
        if any(token in text for token in ("login", "auth", "oauth", "sso", "saml", "session", "token", "jwt", "invite")):
            candidates.append(
                playbook(
                    "auth_oauth_session",
                    "A07:2021 Identification and Authentication Failures",
                    [
                        "check state, nonce, redirect_uri, RelayState, and callback binding",
                        "compare invite, role, and session behavior across owned test users",
                        "verify logout, token rotation, and session invalidation expectations",
                        "look for role downgrade/upgrade inconsistencies in JSON bodies and hidden client-side controls",
                    ],
                    ["auth-sensitive route"],
                )
            )
        if any(token in text for token in ("xss", "dom", "postmessage", "html", "markdown", "template", "reflected")):
            candidates.append(
                playbook(
                    "xss_dom_reflection",
                    "A03:2021 Injection",
                    [
                        "identify the exact reflection or DOM sink context before adding payloads",
                        "start with inert markers and encoding probes, then move to safe proof payloads if context allows",
                        "check CSP, sanitizer behavior, postMessage origin validation, and stored rendering paths",
                        "avoid payloads that trigger actions outside the owned test account",
                    ],
                    ["client-side injection signal"],
                )
            )
        if any(token in text for token in ("admin", "internal", "debug", "actuator", "swagger", "openapi", "config", "backup", ".env", "secret")):
            candidates.append(
                playbook(
                    "exposure_misconfig_secrets",
                    "A05:2021 Security Misconfiguration",
                    [
                        "verify whether the exposed surface is accessible unauthenticated and from a low-privilege session",
                        "check for sensitive keys, tokens, internal hostnames, stack traces, and environment data",
                        "for API docs, identify high-risk operations and test authorization separately",
                        "capture only the minimum sensitive snippet needed to prove impact",
                    ],
                    ["exposure keyword"],
                )
            )
        if any(token in text for token in ("cors", "csrf", "origin", "referer", "frame", "clickjack")):
            candidates.append(
                playbook(
                    "cors_csrf_browser_boundary",
                    "A01:2021 Broken Access Control",
                    [
                        "test Origin reflection, null origin, trusted-subdomain origin, and credential behavior",
                        "check state-changing requests for CSRF tokens and SameSite protections",
                        "verify frame-ancestors and X-Frame-Options on sensitive pages",
                        "use harmless owned-account changes for browser-boundary tests",
                    ],
                    ["browser security boundary"],
                )
            )
        if any(token in text for token in ("s3", "bucket", "blob", "storage", "cloudfront", "azure", "gcp", "aws")):
            candidates.append(
                playbook(
                    "cloud_storage_takeover",
                    "A05:2021 Security Misconfiguration",
                    [
                        "check public listing, object read, write, and delete permissions with non-destructive probes only",
                        "verify dangling DNS or takeover indicators before attempting a claim",
                        "look for signed URL leakage, overly broad cache behavior, and exposed bucket metadata",
                        "avoid modifying existing production objects",
                    ],
                    ["cloud asset signal"],
                )
            )
        return candidates[:5]

    def should_enqueue_playbook_bug_job(
        self,
        item: dict[str, Any],
        source_table: str,
        location: str,
        decision: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> bool:
        if not self.config.scan.get("bug_jobs_enqueue_playbooks", True):
            return False
        priority_score = self.bug_job_priority(item.get("priority"), int(decision.get("score") or 0))
        min_priority = int(self.config.scan.get("bug_jobs_playbook_min_priority", 85) or 85)
        if priority_score < min_priority:
            return False
        check_type = str(item.get("check_type") or "")
        text = f"{source_table} {location} {json.dumps(payload or {}, default=str)} {' '.join(item.get('reasons') or [])}".lower()
        high_signal_terms = {
            "graphql_api_authz": ("graphql", "gql", "mutation", "query"),
            "bac_idor_bola": ("user_id", "userid", "account_id", "org_id", "organization_id", "tenant_id", "workspace_id", "project_id", "member_id", "role_id", "uuid"),
            "ssrf_open_redirect_callback": ("redirect=", "redirect_uri", "callback=", "callback_url", "return_to", "next=", "url=", "uri=", "webhook", "fetch", "import_url"),
            "file_upload_traversal_xxe": ("filename=", "file=", "filepath=", "path=", "download", "export", "import", "upload", "preview", "attachment", "document", "web-inf", "application.properties"),
            "auth_oauth_session": ("oauth", "sso", "saml", "jwt", "magic", "invite", "invitation", "reset", "mfa", "session"),
            "xss_dom_reflection": ("xss", "postmessage", "innerhtml", "outerhtml", "document.write", "markdown", "html=", "q=", "query=", "search="),
            "exposure_misconfig_secrets": ("debug", "actuator", "swagger", "openapi", "config", "backup", ".env", "secret", "token"),
            "cors_csrf_browser_boundary": ("cors", "csrf", "origin", "frame-ancestors", "x-frame-options"),
            "cloud_storage_takeover": ("s3", "bucket", "blob", "storage", "cloudfront", "azure", "gcp", "aws"),
        }
        if not any(term in text for term in high_signal_terms.get(check_type, ())):
            return False
        if source_table in {"finding", "findings"} and priority_score < 95:
            return False
        return True

    async def record_attack_playbooks(
        self,
        domain_id: int | None,
        source_table: str,
        source_id: int | None,
        location: str,
        decision: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> None:
        if not self.config.scan.get("attack_playbooks_enabled", True):
            return
        assert self.db_pool is not None
        playbooks = self.build_attack_playbooks(source_table, source_id, location, decision, payload)
        if not playbooks:
            return
        async with self.db_pool.acquire() as conn:
            for item in playbooks:
                await conn.execute(
                    """
                    INSERT INTO attack_playbooks (
                      domain_id, source_table, source_id, playbook_key, target_url, owasp_category, check_type,
                      priority, confidence, reasons, validation_steps, stop_conditions, safety_notes, payload
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
                    ON CONFLICT (playbook_key) DO UPDATE
                    SET
                      domain_id = EXCLUDED.domain_id,
                      source_table = EXCLUDED.source_table,
                      source_id = EXCLUDED.source_id,
                      target_url = EXCLUDED.target_url,
                      owasp_category = EXCLUDED.owasp_category,
                      check_type = EXCLUDED.check_type,
                      priority = EXCLUDED.priority,
                      confidence = EXCLUDED.confidence,
                      reasons = EXCLUDED.reasons,
                      validation_steps = EXCLUDED.validation_steps,
                      stop_conditions = EXCLUDED.stop_conditions,
                      safety_notes = EXCLUDED.safety_notes,
                      payload = EXCLUDED.payload,
                      updated_at = NOW()
                    """,
                    domain_id,
                    strip_postgres_nuls(source_table) or "unknown",
                    source_id,
                    item["playbook_key"],
                    strip_postgres_nuls(item["target_url"]) or "",
                    item["owasp_category"],
                    item["check_type"],
                    item["priority"],
                    item["confidence"],
                    item["reasons"],
                    item["validation_steps"],
                    item["stop_conditions"],
                    item["safety_notes"],
                    postgres_json(item["payload"]),
                )
        for item in playbooks:
            if not self.should_enqueue_playbook_bug_job(item, source_table, location, decision, payload):
                continue
            await self.enqueue_bug_job(
                domain_id=domain_id,
                source_table=source_table,
                source_id=source_id,
                asset_type="playbook",
                asset_value=location,
                job_type=self.job_type_for_playbook(item["check_type"]),
                priority=self.bug_job_priority(item["priority"], int(decision.get("score") or 0)),
                hypothesis=f"{item['check_type']} on {location}",
                required_context={
                    "playbook_key": item["playbook_key"],
                    "owasp_category": item["owasp_category"],
                    "check_type": item["check_type"],
                    "confidence": item["confidence"],
                    "reasons": item["reasons"],
                    "validation_steps": item["validation_steps"],
                    "payload": item["payload"],
                },
                safety_notes=item["safety_notes"],
            )

    def bug_job_priority(self, priority: str | int | None, score: int = 0) -> int:
        if isinstance(priority, int):
            base = priority
        else:
            base = {
                "critical": 95,
                "high": 80,
                "medium": 60,
                "low": 40,
                "info": 25,
            }.get(str(priority or "").lower(), 50)
        if score:
            base = max(base, min(100, int(score)))
        return max(1, min(100, int(base)))

    def job_type_for_playbook(self, check_type: str) -> str:
        mapping = {
            "graphql_api_authz": "graphql_authz_test",
            "bac_idor_bola": "idor_bac_test",
            "ssrf_open_redirect_callback": "ssrf_candidate_test",
            "file_upload_traversal_xxe": "upload_attack_surface",
            "auth_oauth_session": "auth_session_review",
            "xss_dom_reflection": "xss_reflection_test",
            "exposure_misconfig_secrets": "new_admin_route_review",
            "cors_csrf_browser_boundary": "cors_misconfig_test",
            "cloud_storage_takeover": "cloud_storage_review",
        }
        return mapping.get(check_type, check_type.replace("-", "_") or "manual_review")

    @staticmethod
    def canonical_bug_job_asset_key(asset_type: str, asset_value: str) -> str:
        value = strip_postgres_nuls(asset_value) or ""
        if not value:
            return ""

        def normalize_endpoint_path(path: str) -> str:
            path = re.sub(r"/+", "/", path or "/").rstrip("/") or "/"
            parts = []
            uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
            for part in path.split("/"):
                if uuid_re.match(part):
                    parts.append("{uuid}")
                elif re.fullmatch(r"\d{4,}", part):
                    parts.append("{int}")
                elif re.fullmatch(r"[A-Za-z0-9_-]{20,}", part):
                    parts.append("{opaque}")
                else:
                    normalized = re.sub(r"[0-9a-f]{20,}", "{hex}", part, flags=re.IGNORECASE)
                    normalized = re.sub(r"([._-])[A-Za-z0-9_-]{8,}(?=\.(?:js|mjs|cjs|css|map|json)$)", r"\1{hash}", normalized, flags=re.IGNORECASE)
                    normalized = re.sub(r"[A-Za-z0-9_-]{32,}", "{opaque}", normalized)
                    parts.append(normalized)
            return "/".join(parts) or "/"

        def normalize_endpoint_query(query: str) -> str:
            if not query:
                return ""
            names = sorted({name for name, _ in parse_qsl(query, keep_blank_values=True) if name})
            return urlencode([(name, "{value}") for name in names])

        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            scheme = parsed.scheme.lower()
            hostname = (parsed.hostname or "").lower().rstrip(".")
            netloc = hostname
            if parsed.port and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
                netloc = f"{hostname}:{parsed.port}"
            path = parsed.path or "/"
            if asset_type in {"endpoint", "url", "live_host"} and path != "/":
                path = normalize_endpoint_path(path)
            query = normalize_endpoint_query(parsed.query) if asset_type in {"endpoint", "url"} else parsed.query
            return urlunsplit((scheme, netloc, path, query, ""))
        if asset_type in {"endpoint", "path"}:
            path = value.split("#", 1)[0]
            if "?" in path:
                base, query = path.split("?", 1)
                query = normalize_endpoint_query(query)
                return f"{normalize_endpoint_path(base)}?{query}" if query else normalize_endpoint_path(base)
            return normalize_endpoint_path(path)
        return value

    @staticmethod
    def canonical_js_dom_review_asset_key(asset_value: str, context: dict[str, Any] | None) -> str:
        payload = context or {}
        nested_payload = payload.get("payload")
        if not isinstance(nested_payload, dict):
            nested_payload = {}
        js_sha256 = str(
            payload.get("javascript_sha256")
            or nested_payload.get("sha256")
            or ""
        ).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", js_sha256):
            return f"sha256:{js_sha256}"
        return ContinuousReconFramework.canonical_bug_job_asset_key("js_asset", asset_value)

    @staticmethod
    def text_has_high_risk_identifier(text: str) -> bool:
        uuid_re = r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
        long_numeric_path_re = r"/\d{4,}(?:[/?#]|$)"
        if re.search(uuid_re, text, re.IGNORECASE) or re.search(long_numeric_path_re, text):
            return True
        # Long route names such as __lcp_index_meta__ are not object IDs. A
        # generic opaque identifier must contain both letters and digits.
        opaque_segments = re.findall(r"/([a-z0-9_-]{16,})(?:[/?#]|$)", text, re.IGNORECASE)
        return any(any(ch.isalpha() for ch in value) and any(ch.isdigit() for ch in value) for value in opaque_segments)

    @staticmethod
    def truthy_payload_flag(payload: dict[str, Any], *keys: str) -> bool:
        for key in keys:
            value = payload.get(key)
            if value is True:
                return True
            if isinstance(value, str) and value.lower() in {"1", "true", "yes", "changed", "new"}:
                return True
        return False

    def classify_bug_jobs(
        self,
        source_table: str,
        source_id: int | None,
        item_type: str,
        location: str,
        payload: dict[str, Any] | None,
        decision: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        if not self.config.scan.get("bug_jobs_enabled", True):
            return []
        payload = payload or {}
        decision = decision or {}
        text = f"{source_table} {item_type} {location} {json.dumps(payload, default=str)} {' '.join(decision.get('reasons') or [])} {' '.join(decision.get('recommended_actions') or [])}".lower()
        base_priority = self.bug_job_priority(decision.get("priority"), int(decision.get("score") or 0))
        configured_max_jobs = max(1, int(self.config.scan.get("bug_jobs_max_per_asset", 2)))
        high_signal_only = bool(self.config.scan.get("bug_jobs_high_signal_only", True))
        collapse_endpoint_jobs = bool(self.config.scan.get("bug_jobs_collapse_endpoint_jobs", True))
        common_safety = [
            "stay inside confirmed scope",
            "prefer read-only checks and operator-owned accounts",
            "do not print cookies, tokens, secrets, or Authorization headers",
            "do not perform destructive actions unless a disposable object is explicitly identified",
        ]
        jobs: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add(job_type: str, priority: int, hypothesis: str, extra_context: dict[str, Any] | None = None) -> None:
            if job_type in seen:
                return
            seen.add(job_type)
            jobs.append(
                {
                    "job_type": job_type,
                    "priority": max(1, min(100, priority)),
                    "hypothesis": hypothesis,
                    "required_context": {
                        "source_table": source_table,
                        "source_id": source_id,
                        "item_type": item_type,
                        "location": location,
                        "triage_decision": decision,
                        "payload": payload,
                        **(extra_context or {}),
                    },
                    "safety_notes": common_safety,
                }
            )

        object_tokens = (
            "user_id", "userid", "account_id", "org_id", "organization_id", "tenant_id", "team_id",
            "workspace_id", "project_id", "member_id", "role_id", "file_id", "report_id", "export_id",
            "/users/", "/accounts/", "/orgs/", "/organizations/", "/teams/", "/workspaces/", "/projects/",
            "/members/", "/roles/", "/permissions/", "/files/", "/reports/", "/exports/",
        )
        admin_tokens = (
            "/admin", "/internal", "/settings", "/roles", "/permissions", "/invite", "/invitation",
            "/members", "/users", "/audit", "/billing", "/sso", "/scim", "/webhook", "/api-key",
            "admin.", "internal.", "staff.", "support.", "console.", "dashboard.", "portal.",
        )
        authz_admin_tokens = (
            "/settings", "/roles", "/permissions", "/invite", "/invitation", "/members", "/users",
            "/audit", "/billing", "/sso", "/scim", "/webhook", "/api-key", "api_key",
            "tenant", "workspace", "organization", "account_id", "org_id", "user_id", "role_id",
            "member_id", "permission", "owner", "admin_id",
        )
        upload_tokens = ("/upload", "/import", "/export", "/report", "/preview", "/download", "/files", "multipart", "filename")
        lfi_tokens = (
            "filename=", "file=", "filepath=", "path=", "dir=", "folder=", "template=", "document=",
            "resource=", "asset=", "log=", "/download", "/read", "/view", "/preview", "/export",
            "/logs", "/backup", "/attachment", "/document", "/template", "web-inf", "application.properties",
        )
        url_sink_tokens = ("url=", "uri=", "redirect=", "redirect_uri", "next=", "return_to", "callback=", "callback_url", "webhook", "fetch", "import_url")
        xss_tokens = (
            "comment", "message", "description", "markdown", "html", "note", "title=", "name=",
            "q=", "query=", "search=", "callback=", "return=", "fragment", "hash", "postmessage",
            "innerhtml", "outerhtml", "insertadjacenthtml", "document.write",
        )
        injection_tokens = (
            "sql", "query=", "search=", "filter=", "sort=", "order=", "where=", "select=", "id=",
            "ids=", "json", "nosql", "mongo", "template=", "ssti", "expression", "cmd=", "command=",
            "exec=", "shell", "xpath", "ldap", "report", "export", "import",
        )
        auth_tokens = (
            "/login", "/signin", "/logout", "/register", "/signup", "/forgot", "/reset", "/recover",
            "/verify", "/magic", "/mfa", "/2fa", "/oauth", "/oidc", "/sso", "/saml", "/session",
            "/refresh", "/invite", "/activation", "pkce", "remember_me",
        )
        crypto_tokens = (
            "jwt", "jws", "jwks", "bearer", "signed_url", "signed-url", "signature", "hmac", "nonce",
            "private_key", "signing_key", "encryption_key", "encrypt", "decrypt", "reset_token",
            "magic_link", "recovery_code", "code_challenge", "code_verifier",
        )
        supply_chain_tokens = (
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock", "composer.lock", "gemfile.lock",
            "requirements.txt", "pom.xml", "build.gradle", "webpack", "vite", "rollup", "artifact",
            "registry", "dependency", "dependencies", "ci/cd", "pipeline", "runner", "build hook",
        )
        integrity_tokens = (
            "idempotency", "webhook-signature", "x-signature", "event_id", "event-id", "checksum",
            "serialized", "deserial", "pickle", "plugin", "update_manifest", "update-manifest",
            "callback_signature", "callback-signature", "trusted_field", "provenance",
        )
        logging_tokens = (
            "/audit", "/activity", "/security-events", "/security/events", "/event-log", "/event_log",
            "/logs", "/logfile", "/notifications/security", "/alerts", "audit_log", "audit-log",
        )
        exceptional_tokens = (
            "stack trace", "traceback", "unhandled exception", "internal server error", "panic:",
            "sqlstate", "nullpointerexception", "fatal error", "debug traceback",
        )
        secret_tokens = ("secret", "token", "api_key", "client_secret", "private_key", "access_key", "auth_token", "webhook")
        staging_tokens = ("staging", "stage", ".stg", "-stg", "dev.", ".dev", "-dev", "test.", ".test", "-test", "uat", "qa.", ".qa", "beta")
        source_map_tokens = ("sourcemappingurl", "source_map", "sourcemap")
        js_dom_tokens = ("innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "postmessage", "addeventlistener(\"message", "addeventlistener('message", "location.hash", "location.search", "searchparams", "dangerouslysetinnerhtml")
        api_doc_tokens = ("/swagger", "/openapi", "/api-docs", "/redoc")
        exposure_path_names = {
            "admin", "administrator", "manage", "management", "manager", "console", "dashboard",
            "portal", "backoffice", "internal", "staff", "support", "ops", "secure", "debug",
            "actuator", "metrics", "prometheus", "grafana", "kibana", "swagger", "swagger-ui",
            "api-docs", "openapi", "redoc", "config", "configuration", "backup", "backups",
            "logs", "logfile", ".env", ".git", "server-status", "phpinfo.php",
        }

        is_endpoint = item_type == "endpoint" or source_table == "endpoints"
        is_live_host = item_type == "live_host" or source_table == "live_hosts"
        is_js_asset = item_type in {"js_asset", "js_file"} or source_table == "js_assets" or bool(re.search(r"\.(?:mjs|cjs|js)(?:[?#]|$)", text))
        is_new_asset = self.truthy_payload_flag(payload, "is_new", "new", "inserted", "is_new_live_host")
        is_changed_asset = self.truthy_payload_flag(payload, "changed", "is_changed", "fingerprint_changed", "hash_changed", "js_changed")
        asset_url = str(payload.get("url") or payload.get("asset_url") or location or "")
        parsed_asset = urlsplit(asset_url)
        asset_sha256 = str(payload.get("sha256") or "").strip().lower()
        has_downloaded_body = bool(re.fullmatch(r"[0-9a-f]{64}", asset_sha256))
        try:
            has_successful_body = int(payload.get("http_status") or payload.get("status_code") or 0) == 200
        except (TypeError, ValueError):
            has_successful_body = False
        is_source_map_asset = bool(re.search(r"\.map(?:[?#]|$)", parsed_asset.path, re.IGNORECASE))
        review_all_new_js = bool(self.config.scan.get("bug_jobs_dom_review_all_new_js", False))
        review_all_delta_js = bool(self.config.scan.get("bug_jobs_dom_review_all_delta_js", False))
        scan_lane = str(payload.get("scan_lane") or "").strip().lower()
        is_delta_scan = bool(
            payload.get("is_delta_scan") is True
            and payload.get("first_run") is False
            and scan_lane in {"fast_delta", "deep_scan"}
        )
        mandatory_delta_dom_review = bool(
            review_all_delta_js
            and is_delta_scan
            and (is_new_asset or is_changed_asset)
        )
        force_dom_review = bool(
            (review_all_new_js or mandatory_delta_dom_review)
            and is_js_asset
            and not is_source_map_asset
            and has_downloaded_body
            and has_successful_body
            and (is_new_asset or is_changed_asset)
        )
        path_segments = {segment.lower() for segment in parsed_asset.path.split("/") if segment}
        parameter_names = {name.lower() for name, _ in parse_qsl(parsed_asset.query, keep_blank_values=True)}
        for parameter in payload.get("parameters") or []:
            if isinstance(parameter, dict) and parameter.get("name"):
                parameter_names.add(str(parameter["name"]).lower())
            elif isinstance(parameter, str):
                parameter_names.add(parameter.lower())

        object_parameter_names = {
            "id", "user_id", "userid", "account_id", "accountid", "org_id", "organization_id",
            "tenant_id", "team_id", "workspace_id", "project_id", "member_id", "role_id", "file_id",
            "report_id", "export_id", "job_id", "result_id", "download_id", "attachment_id",
        }
        object_path_names = {
            "users", "accounts", "orgs", "organizations", "teams", "workspaces", "projects", "members",
            "roles", "permissions", "files", "reports", "exports",
        }
        admin_path_names = {
            "admin", "internal", "settings", "roles", "permissions", "invite", "invitation", "members",
            "users", "audit", "billing", "sso", "scim", "webhook", "api-key",
        }
        custom_role_parameter_names = {
            "role", "role_id", "permission", "permissions", "scope", "scopes", "capability",
            "capabilities", "entitlement", "entitlements", "access_level", "policy_id", "member_id",
            "target_user_id", "targetuserid",
        }
        custom_role_path_names = {
            "roles", "permissions", "policies", "capabilities", "entitlements", "members", "assignments",
        }
        secondary_operation_path_names = {
            "jobs", "status", "result", "results", "download", "downloads", "export", "exports",
            "preview", "previews", "thumbnail", "thumbnails", "history", "audit", "retry", "cancel",
            "restore", "clone", "transfer", "bulk",
        }
        authz_path_names = admin_path_names - {"admin", "internal"}
        upload_path_names = {"upload", "import", "export", "report", "preview", "download", "files"}
        lfi_parameter_names = {
            "filename", "file", "filepath", "path", "dir", "folder", "template", "document", "resource",
            "asset", "log",
        }
        url_parameter_names = {
            "url", "uri", "redirect", "redirect_uri", "next", "return_to", "callback", "callback_url",
            "webhook", "import_url",
        }
        xss_parameter_names = {
            "comment", "message", "description", "markdown", "html", "note", "title", "name", "q", "query",
            "search", "callback", "return", "fragment", "hash",
        }
        injection_parameter_names = {
            "query", "search", "filter", "sort", "order", "where", "select", "json", "template",
            "expression", "cmd", "command", "exec", "xpath", "ldap",
        }
        endpoint_object_path = bool(
            re.search(
                r"/(?:users|accounts|orgs|organizations|teams|workspaces|projects|members|roles|permissions|files|reports|exports)/[^/?#]+(?:[/?.#]|$)",
                parsed_asset.path.lower(),
            )
        )

        if is_endpoint:
            has_object_signal = bool(parameter_names & object_parameter_names) or endpoint_object_path or self.text_has_high_risk_identifier(asset_url)
            has_admin_signal = bool(path_segments & admin_path_names)
            has_authz_admin_signal = bool(path_segments & authz_path_names) or bool(parameter_names & object_parameter_names)
            has_custom_role_signal = bool(path_segments & custom_role_path_names) or bool(
                parameter_names & custom_role_parameter_names
            )
            has_secondary_operation_signal = bool(path_segments & secondary_operation_path_names) and bool(
                parameter_names & object_parameter_names or endpoint_object_path or self.text_has_high_risk_identifier(asset_url)
            )
            has_upload_signal = bool(path_segments & upload_path_names) or "multipart" in text
            # A download/log route is a workflow lead, not evidence that user
            # input reaches a filesystem path. Require an actual path-like
            # parameter before assigning traversal/LFI priority.
            has_lfi_signal = bool(parameter_names & lfi_parameter_names)
            has_url_sink_signal = bool(parameter_names & url_parameter_names) or "webhook" in path_segments
            has_xss_signal = bool(parameter_names & xss_parameter_names)
            has_injection_signal = bool(parameter_names & injection_parameter_names)
        else:
            has_object_signal = any(token in text for token in object_tokens) or self.text_has_high_risk_identifier(location)
            has_admin_signal = any(token in text for token in admin_tokens)
            has_authz_admin_signal = any(token in text for token in authz_admin_tokens)
            has_upload_signal = any(token in text for token in upload_tokens)
            has_lfi_signal = any(token in text for token in lfi_tokens)
            has_url_sink_signal = any(token in text for token in url_sink_tokens)
            has_xss_signal = any(token in text for token in xss_tokens)
            has_injection_signal = any(token in text for token in injection_tokens)
            has_custom_role_signal = any(
                token in text
                for token in ("custom role", "permission", "capability", "entitlement", "access_level", "policy_id")
            )
            has_secondary_operation_signal = any(
                token in text
                for token in ("job_id", "result_id", "export_id", "download_id", "/jobs/", "/results/", "/history/")
            )
        has_secret_signal = any(token in text for token in secret_tokens)
        has_source_map_signal = any(token in text for token in source_map_tokens) or bool(
            re.search(r"\.(?:js\.)?map(?:[?#]|$)", asset_url, re.IGNORECASE)
        )
        graphql_operation_count = payload.get("operations_count") or payload.get("graphql_operations_count") or 0
        graphql_operations = payload.get("graphql_operations") or payload.get("operations") or []
        has_graphql_operation_signal = bool(graphql_operations) or bool(
            isinstance(graphql_operation_count, int) and graphql_operation_count > 0
        ) or bool(payload.get("operation_name"))
        has_graphql_signal = "graphql" in text or "/gql" in text or "graphiql" in text or has_graphql_operation_signal
        has_js_dom_signal = any(token in text for token in js_dom_tokens)
        has_auth_signal = any(token in text for token in auth_tokens)
        has_crypto_signal = any(token in text for token in crypto_tokens)
        has_supply_chain_signal = any(token in text for token in supply_chain_tokens)
        has_integrity_signal = any(token in text for token in integrity_tokens)
        has_logging_signal = any(token in text for token in logging_tokens)
        status_code = payload.get("status_code") or payload.get("http_status") or payload.get("status")
        try:
            has_exceptional_signal = int(status_code) >= 500
        except (TypeError, ValueError):
            has_exceptional_signal = False
        try:
            status_int = int(status_code)
        except (TypeError, ValueError):
            status_int = None
        source_name = str(payload.get("source") or "").lower()
        has_ffuf_exposure_signal = bool(
            is_endpoint
            and source_name == "ffuf"
            and status_int in {200, 204, 301, 302, 307, 308, 401, 403, 405, 500}
            and path_segments.intersection(exposure_path_names)
        )
        if (
            is_endpoint
            and source_name == "common_path_probe"
            and not parameter_names
            and (
                status_int in {404, 405}
                or (status_int in {401, 403} and not has_graphql_signal)
            )
        ):
            return []
        has_exceptional_signal = has_exceptional_signal or any(token in text for token in exceptional_tokens)
        has_high_risk_host_signal = is_live_host and (has_admin_signal or any(token in text for token in staging_tokens))
        has_api_doc_signal = any(token in text for token in api_doc_tokens)
        finding_type = str(payload.get("finding_type") or "").lower()
        is_authz_finding = item_type == "finding" and bool(
            re.search(r"(?:idor|bola|bfla|broken[_ -]?access|authz|authorization|tenant[_ -]?(?:escape|isolation))", finding_type)
        )
        high_signal_reasons = [
            name
            for name, present in (
                ("object-id-or-tenant-signal", has_object_signal),
                ("auth-admin-signal", has_authz_admin_signal),
                ("custom-role-permission-signal", has_custom_role_signal),
                ("async-secondary-operation-signal", has_secondary_operation_signal),
                ("upload-export-file-signal", has_upload_signal),
                ("lfi-path-traversal-signal", has_lfi_signal),
                ("webhook-url-redirect-signal", has_url_sink_signal),
                ("xss-signal", has_xss_signal),
                ("injection-signal", has_injection_signal),
                ("changed-asset", is_changed_asset),
                ("graphql-operation-signal" if has_graphql_operation_signal else "graphql-signal", has_graphql_signal),
                ("source-map-signal", has_source_map_signal),
                ("high-risk-staging-admin-host", has_high_risk_host_signal),
                ("api-docs-signal", has_api_doc_signal),
                ("ffuf-exposed-panel-or-sensitive-path", has_ffuf_exposure_signal),
                (
                    "delta-new-or-changed-javascript-body"
                    if mandatory_delta_dom_review
                    else "new-or-changed-javascript-body",
                    force_dom_review,
                ),
                ("js-dom-sink-signal", is_js_asset and has_js_dom_signal),
                ("secret-signal", is_js_asset and has_secret_signal),
                ("authentication-lifecycle-signal", has_auth_signal),
                ("cryptographic-token-signal", has_crypto_signal),
                ("software-supply-chain-signal", has_supply_chain_signal),
                ("software-data-integrity-signal", has_integrity_signal),
                ("security-logging-alerting-signal", has_logging_signal),
                ("exceptional-condition-signal", has_exceptional_signal),
            )
            if present
        ]
        high_signal = bool(high_signal_reasons)
        if high_signal_only and not high_signal:
            return []
        if collapse_endpoint_jobs and (is_endpoint or is_live_host):
            max_jobs = 1
        elif is_js_asset:
            max_jobs = min(configured_max_jobs, 2 if high_signal_only else configured_max_jobs)
        else:
            max_jobs = min(configured_max_jobs, 2 if high_signal_only else configured_max_jobs)

        if has_graphql_signal:
            add("graphql_authz_test", max(base_priority, 94), "GraphQL surface may expose query, mutation, or field-level authorization issues")
        if (has_object_signal or has_authz_admin_signal or has_custom_role_signal or has_secondary_operation_signal) and (item_type != "finding" or is_authz_finding):
            authz_priority = 96 if has_custom_role_signal or has_secondary_operation_signal else (90 if has_authz_admin_signal else 86)
            add(
                "idor_bac_test",
                max(base_priority, authz_priority),
                "Endpoint contains object, tenant, custom-role, or secondary-operation indicators suitable for BAC/IDOR testing",
                {
                    "custom_role_permission_review": has_custom_role_signal,
                    "secondary_operation_review": has_secondary_operation_signal,
                    "sibling_operations_to_check": [
                        "list/detail", "create/status/result/download", "preview/export", "retry/cancel", "archive/restore"
                    ] if has_secondary_operation_signal else ["list/detail", "read/write", "single/bulk", "web/mobile/legacy"],
                },
            )
        if has_upload_signal or has_lfi_signal:
            add("upload_attack_surface", max(base_priority, 99 if has_lfi_signal else 93), "Upload, import, export, preview, download, or file/path workflow may expose parser, LFI, traversal, or file-authorization bugs")
        if has_url_sink_signal:
            add("ssrf_candidate_test", max(base_priority, 97), "URL, redirect, callback, webhook, or fetch-like parameter may be SSRF/open-redirect relevant")
        if has_xss_signal and (is_endpoint or is_changed_asset):
            add("xss_reflection_test", max(base_priority, 96), "User-controlled text-like parameter may reflect, store, or flow into HTML/JavaScript")
        if has_injection_signal and (is_endpoint or has_upload_signal or has_lfi_signal):
            add("injection_review", max(base_priority, 98), "Search, filter, report, template, command, or query-like input may expose SQL/NoSQL/SSTI/command injection behavior")
        if has_integrity_signal:
            add("integrity_review", max(base_priority, 97), "Signature, idempotency, webhook, serialized state, update, or provenance handling may trust attacker-controlled data")
        if has_crypto_signal:
            add("crypto_token_review", max(base_priority, 95), "Token, signature, signed URL, nonce, key, or cryptographic lifecycle signal requires binding and integrity review")
        if has_auth_signal:
            add("auth_session_review", max(base_priority, 94), "Authentication, reset, invite, MFA, OAuth, SSO, or session lifecycle may contain a bypass or stale-access flaw")
        if has_supply_chain_signal:
            add("component_supply_chain_review", max(base_priority, 94), "Package, build, registry, dependency, CI/CD, or artifact evidence may expose a reachable supply-chain failure")
        if has_logging_signal:
            add("logging_audit_review", max(base_priority, 93), "Audit, activity, security-event, log, or alert surface may expose cross-tenant data or integrity gaps")
        if has_exceptional_signal:
            add("exceptional_condition_review", max(base_priority, 92), "Observed server error or exception evidence may reveal fail-open, partial-state, or sensitive error behavior")
        if any(token in text for token in ("cors", "origin", "csrf", "cache-control", "vary:", "frame-ancestors")):
            add("cors_misconfig_test", max(base_priority, 68), "Browser trust boundary signal may need CORS, CSRF, cache, or clickjacking validation")
        if is_js_asset and (is_new_asset or is_changed_asset or has_graphql_signal or has_source_map_signal or has_admin_signal or has_url_sink_signal or has_upload_signal):
            add("js_endpoint_extraction", max(base_priority, 78 if is_changed_asset else 72), "JavaScript asset may reveal routes, params, GraphQL operations, or client-side auth assumptions")
        if is_js_asset and (has_js_dom_signal or force_dom_review):
            dom_priority = 96 if has_js_dom_signal else int(
                self.config.scan.get("bug_jobs_dom_review_new_js_priority", 90) or 90
            )
            add(
                "js_dom_xss_review",
                max(base_priority, dom_priority),
                (
                    "JavaScript contains DOM, postMessage, location, or HTML sink signals that need DOM-XSS review"
                    if has_js_dom_signal
                    else "New or changed JavaScript body requires the focused DOM-XSS and postMessage review"
                ),
                {
                    "mandatory_new_js_dom_review": force_dom_review,
                    "mandatory_delta_js_dom_review": mandatory_delta_dom_review,
                    "javascript_sha256": asset_sha256,
                    "scan_lane": scan_lane or None,
                    "is_delta_scan": is_delta_scan,
                },
            )
        if is_js_asset and has_secret_signal:
            add("js_secret_review", max(base_priority, 88), "Asset contains source-map, secret, token, environment, or config indicators")
        if has_source_map_signal:
            add("source_map_review", max(base_priority, 93), "Source map signal should be reviewed for sensitive original sources")
        if has_ffuf_exposure_signal or any(token in text for token in ("/debug", "/actuator", "/config", "/backup", "/console", "/staging", "/stage", "/dev", "/beta")) or has_api_doc_signal or has_high_risk_host_signal:
            route_priority = 99 if has_ffuf_exposure_signal else 94
            add(
                "new_admin_route_review",
                max(base_priority, route_priority),
                "Discovered admin, panel, debug, API-docs, config, backup, or internal route may expose functionality without the intended authorization",
                {
                    "forced_browsing_review": True,
                    "discovery_source": source_name or source_table,
                    "observed_status": status_int,
                },
            )

        for job in jobs:
            context = job.setdefault("required_context", {})
            context["bug_job_high_signal_reasons"] = high_signal_reasons
            context["job_category"] = job_category(job["job_type"])
            context["feature_chain_signals"] = {
                "custom_role_permission": has_custom_role_signal,
                "secondary_operation": has_secondary_operation_signal,
                "graphql_operation": has_graphql_operation_signal,
                "changed_javascript": is_changed_asset,
                "source_map": has_source_map_signal,
            }

        ranked_jobs = sorted(jobs, key=lambda item: item["priority"], reverse=True)
        selected_jobs = ranked_jobs[:max_jobs]
        if force_dom_review and not any(item["job_type"] == "js_dom_xss_review" for item in selected_jobs):
            dom_job = next(item for item in ranked_jobs if item["job_type"] == "js_dom_xss_review")
            selected_jobs.append(dom_job)
        return selected_jobs

    async def enqueue_bug_job(
        self,
        domain_id: int | None,
        source_table: str,
        source_id: int | None,
        asset_type: str,
        asset_value: str,
        job_type: str,
        priority: int,
        hypothesis: str,
        required_context: dict[str, Any] | None = None,
        safety_notes: list[str] | None = None,
        scope_ok: bool = True,
    ) -> None:
        if not self.config.scan.get("bug_jobs_enabled", True) or not self.config.scan.get("bug_jobs_auto_enqueue", True):
            return
        assert self.db_pool is not None
        clean_source_table = strip_postgres_nuls(source_table) or "unknown"
        clean_asset_type = strip_postgres_nuls(asset_type) or "unknown"
        clean_asset_value = strip_postgres_nuls(asset_value) or ""
        clean_job_type = strip_postgres_nuls(job_type) or "manual_review"
        clean_job_category = job_category(clean_job_type)
        clean_hypothesis = strip_postgres_nuls(hypothesis) or ""
        canonical_asset_value = self.canonical_bug_job_asset_key(clean_asset_type, clean_asset_value)
        context_payload = (required_context or {}).get("payload")
        if not isinstance(context_payload, dict):
            context_payload = {}
        if (
            clean_job_type == "graphql_authz_test"
            and str(context_payload.get("source") or "").lower() == "common_path_probe"
        ):
            parsed_graphql = urlsplit(clean_asset_value)
            if parsed_graphql.path.lower().rstrip("/") in {"/graphql", "/api/graphql", "/graphql/console"}:
                canonical_asset_value = urlunsplit(
                    (parsed_graphql.scheme.lower(), parsed_graphql.netloc.lower(), "/graphql", "", "")
                )
        mandatory_dom_review = bool(
            clean_job_type == "js_dom_xss_review"
            and isinstance(required_context, dict)
            and (
                required_context.get("mandatory_new_js_dom_review") is True
                or required_context.get("mandatory_delta_js_dom_review") is True
            )
        )
        deterministic_dom_review = bool(
            clean_job_type == "js_dom_xss_review"
            and isinstance(required_context, dict)
            and required_context.get("deterministic_js_flow") is True
            and required_context.get("javascript_sha256")
        )
        if mandatory_dom_review or deterministic_dom_review:
            # One focused review per unique body and root domain. Mirrored URLs
            # remain in required_context without multiplying work.
            canonical_asset_value = self.canonical_js_dom_review_asset_key(
                clean_asset_value,
                required_context,
            )
        dedupe_source_id = source_id
        dedupe_source_table = clean_source_table
        if clean_asset_type in {"endpoint", "url", "live_host", "js_asset", "js_file", "finding"}:
            dedupe_source_id = None
            dedupe_source_table = clean_asset_type
        job_key = hashlib.sha256(
            f"{domain_id}|{dedupe_source_table}|{dedupe_source_id}|{clean_asset_type}|{canonical_asset_value}|{clean_job_type}".encode()
        ).hexdigest()
        async with self.db_pool.acquire() as conn:
            target = await conn.fetchval("SELECT domain FROM domains WHERE id = $1", domain_id) if domain_id else None
            source_observed_at = await self.bug_job_source_observed_at(
                conn,
                clean_source_table,
                source_id,
                required_context or {},
            )
            recent_window_days = max(
                1,
                int(self.config.scan.get("bug_jobs_recent_window_days", 30) or 30),
            )
            if source_observed_at is None or source_observed_at < datetime.utcnow() - timedelta(days=recent_window_days):
                return
            effective_scope_ok = bool(scope_ok)
            if target and re.match(r"^https?://", clean_asset_value, re.IGNORECASE):
                host = (urlsplit(clean_asset_value).hostname or "").lower().rstrip(".")
                target_host = str(target).lower().rstrip(".")
                if host and host != target_host and not host.endswith(f".{target_host}"):
                    effective_scope_ok = False
            if not effective_scope_ok:
                return
            if clean_asset_type == "endpoint":
                try:
                    endpoint_status = int(
                        context_payload.get("status_code")
                        or context_payload.get("http_status")
                        or context_payload.get("status")
                    )
                except (TypeError, ValueError):
                    endpoint_status = None
                if endpoint_status in {404, 405}:
                    return
                endpoint_source = str(context_payload.get("source") or "").lower()
                parsed_endpoint = urlsplit(clean_asset_value)
                first_segment = next(
                    (segment.lower() for segment in parsed_endpoint.path.split("/") if segment),
                    "",
                )
                query_names = {
                    name.lower() for name, _value in parse_qsl(parsed_endpoint.query, keep_blank_values=True)
                }
                if endpoint_source == "js_analysis" and (
                    re.fullmatch(r"(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}", first_segment)
                    or (parsed_endpoint.path.lower().endswith("/issues/new") and {"labels", "template"} <= query_names)
                ):
                    return
            min_enqueue_priority = max(
                0,
                int(self.config.scan.get("bug_jobs_enqueue_min_priority", 90) or 0),
            )
            if int(priority) < min_enqueue_priority:
                return
            existing = await conn.fetchval("SELECT id FROM bug_jobs WHERE job_key = $1", job_key)
            if existing is None:
                max_domain = max(
                    0,
                    int(self.config.scan.get("bug_jobs_max_queued_per_domain", 150) or 0),
                )
                max_domain_type = max(
                    0,
                    int(self.config.scan.get("bug_jobs_max_queued_per_domain_job_type", 40) or 0),
                )
                ignore_queue_caps = bool(
                    mandatory_dom_review
                    and self.config.scan.get("bug_jobs_dom_review_ignore_queue_caps", True)
                )
                if max_domain and domain_id is not None and not ignore_queue_caps:
                    queue_full = await conn.fetchval(
                        """
                        SELECT COUNT(*) >= $2
                        FROM (
                            SELECT 1 FROM bug_jobs
                            WHERE domain_id = $1 AND status IN ('queued', 'curation_pending')
                            LIMIT $2
                        ) AS bounded
                        """,
                        domain_id,
                        max_domain,
                    )
                    if bool(queue_full):
                        return
                if max_domain_type and domain_id is not None and not ignore_queue_caps:
                    type_full = await conn.fetchval(
                        """
                        SELECT COUNT(*) >= $3
                        FROM (
                            SELECT 1 FROM bug_jobs
                            WHERE domain_id = $1 AND job_type = $2 AND status IN ('queued', 'curation_pending')
                            LIMIT $3
                        ) AS bounded
                        """,
                        domain_id,
                        clean_job_type,
                        max_domain_type,
                    )
                    if bool(type_full):
                        return
            initial_status = (
                "curation_pending"
                if self.config.scan.get("bug_job_curator_enabled", True)
                and self.config.scan.get("bug_job_curator_gate_new_jobs", True)
                else "queued"
            )
            await conn.execute(
                """
                INSERT INTO bug_jobs (
                  domain_id, target, asset_type, asset_value, job_type, job_category, priority, status, scope_ok, source_table,
                  source_id, source_observed_at, job_key, hypothesis, safety_notes, required_context
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb)
                ON CONFLICT (job_key) DO UPDATE SET
                  priority = GREATEST(bug_jobs.priority, EXCLUDED.priority),
                  job_category = EXCLUDED.job_category,
                  scope_ok = bug_jobs.scope_ok AND EXCLUDED.scope_ok,
                  source_observed_at = GREATEST(bug_jobs.source_observed_at, EXCLUDED.source_observed_at),
                  hypothesis = EXCLUDED.hypothesis,
                  safety_notes = EXCLUDED.safety_notes,
                  required_context = CASE
                    WHEN EXCLUDED.required_context ->> 'mandatory_new_js_dom_review' = 'true'
                      OR EXCLUDED.required_context ->> 'mandatory_delta_js_dom_review' = 'true'
                    THEN bug_jobs.required_context
                    ELSE bug_jobs.required_context || EXCLUDED.required_context
                  END,
                  updated_at = NOW()
                """,
                domain_id,
                strip_postgres_nuls(target or "unknown"),
                clean_asset_type,
                clean_asset_value,
                clean_job_type,
                clean_job_category,
                int(priority),
                initial_status,
                effective_scope_ok,
                clean_source_table,
                source_id,
                source_observed_at,
                job_key,
                clean_hypothesis,
                safety_notes or [],
                postgres_json(sanitize_postgres_value(required_context or {})),
            )

    @staticmethod
    async def bug_job_source_observed_at(
        conn: asyncpg.Connection,
        source_table: str,
        source_id: int | None,
        context: dict[str, Any],
    ) -> datetime | None:
        payload = context.get("payload") if isinstance(context.get("payload"), dict) else context
        for key in ("first_seen", "discovered_at", "source_observed_at", "created_at"):
            raw = payload.get(key) if isinstance(payload, dict) else None
            if isinstance(raw, datetime):
                return raw.replace(tzinfo=None)
            if isinstance(raw, str) and raw.strip():
                try:
                    parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
                except ValueError:
                    continue
                if parsed.tzinfo is not None:
                    parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
                return parsed
        source_tables = {
            "endpoints": "endpoints",
            "live_hosts": "live_hosts",
            "js_assets": "js_assets",
            "findings": "findings",
            "api_surfaces": "api_surfaces",
            "asset_events": "asset_events",
        }
        table = source_tables.get(source_table)
        if table and source_id is not None:
            return await conn.fetchval(f"SELECT first_seen FROM {table} WHERE id = $1", source_id)
        return None

    async def enqueue_bug_jobs_for_asset(
        self,
        domain_id: int | None,
        source_table: str,
        source_id: int | None,
        item_type: str,
        location: str,
        payload: dict[str, Any] | None,
        decision: dict[str, Any] | None = None,
    ) -> None:
        for job in self.classify_bug_jobs(source_table, source_id, item_type, location, payload, decision):
            await self.enqueue_bug_job(
                domain_id=domain_id,
                source_table=source_table,
                source_id=source_id,
                asset_type=item_type,
                asset_value=location,
                job_type=job["job_type"],
                priority=job["priority"],
                hypothesis=job["hypothesis"],
                required_context=job["required_context"],
                safety_notes=job["safety_notes"],
            )

    def validation_steps_for_finding(self, finding_type: str, severity: str, details: dict[str, Any]) -> list[str]:
        text = f"{finding_type} {json.dumps(details, default=str)}".lower()
        steps = ["confirm the asset is in scope", "reproduce the scanner observation with a fresh request"]
        if "nuclei" in finding_type:
            steps.append("review the matched template, matcher, and affected endpoint")
        if "dalfox" in finding_type or "xss" in text:
            steps.append("manually verify payload execution in a controlled browser session")
        if "graphql" in text:
            steps.append("check introspection, batching, unauthenticated queries, and authorization boundaries")
        if "openapi" in text or "swagger" in text:
            steps.append("review unauthenticated API documentation and test high-risk operations")
        if "bucket" in text or "s3" in text or "azure" in text or "gcp" in text:
            steps.append("validate cloud object permissions without modifying data")
        if severity in {"critical", "high"}:
            steps.append("capture minimal evidence and impact for a report draft")
        return dedupe_list(steps)

    async def seed_existing_triage(self) -> None:
        if not self.config.scan.get("ai_triage_enabled", True):
            return
        assert self.db_pool is not None
        limit = int(self.config.scan.get("ai_triage_startup_backfill_limit", 250))
        async with self.db_pool.acquire() as conn:
            endpoints = await conn.fetch(
                """
                SELECT
                  d.id AS domain_id,
                  e.id AS endpoint_id,
                  e.path,
                  (lh.url || e.path) AS full_url,
                  e.source,
                  e.status_code,
                  e.parameters,
                  e.risk_tags
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE cardinality(e.risk_tags) > 0
                   OR jsonb_array_length(e.parameters) > 0
                   OR e.source = 'js_analysis'
                   OR (lh.url || e.path) ~* '(admin|internal|debug|graphql|api|swagger|openapi|actuator|config|backup|token|auth|login|redirect|callback|upload)'
                ORDER BY e.last_seen DESC
                LIMIT $1
                """,
                limit,
            )
            findings = await conn.fetch(
                """
                SELECT id, domain_id, finding_type, severity, location, details
                FROM findings
                WHERE severity IN ('critical', 'high', 'medium') OR finding_type LIKE 'nuclei_%'
                ORDER BY last_seen DESC
                LIMIT $1
                """,
                max(50, limit // 4),
            )
        for row in endpoints:
            await self.triage_item(
                row["domain_id"],
                "endpoints",
                row["endpoint_id"],
                "endpoint",
                row["path"],
                row["full_url"],
                {
                    "url": row["full_url"],
                    "path": row["path"],
                    "source": row["source"],
                    "status_code": row["status_code"],
                    "parameters": row["parameters"],
                    "risk_tags": row["risk_tags"],
                },
            )
        for row in findings:
            await self.triage_item(
                row["domain_id"],
                "findings",
                row["id"],
                "finding",
                row["finding_type"],
                row["location"],
                {
                    "severity": row["severity"],
                    "finding_type": row["finding_type"],
                    "location": row["location"],
                    "details": row["details"],
                },
            )

    async def seed_existing_operational_queues(self) -> None:
        assert self.db_pool is not None
        limit = int(self.config.scan.get("operational_backfill_limit", 500))
        async with self.db_pool.acquire() as conn:
            findings = await conn.fetch(
                """
                SELECT id, domain_id, finding_type, severity, location, details
                FROM findings
                WHERE severity IN ('critical', 'high', 'medium')
                   OR finding_type LIKE 'nuclei_%'
                   OR finding_type LIKE 'dalfox_%'
                ORDER BY last_seen DESC
                LIMIT $1
                """,
                limit,
            )
            recent_live_hosts = await conn.fetch(
                """
                SELECT
                  d.id AS domain_id,
                  d.domain,
                  d.enable_ffuf,
                  lh.id AS live_host_id,
                  lh.url,
                  lh.status_code,
                  lh.title,
                  lh.webserver,
                  COALESCE(lhf.technologies, '[]'::jsonb) AS technologies,
                  lh.first_seen,
                  lh.last_seen
                FROM live_hosts lh
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                LEFT JOIN live_host_fingerprints lhf ON lhf.live_host_id = lh.id AND lhf.is_current = TRUE
                WHERE lh.first_seen > NOW() - INTERVAL '14 days'
                   OR lh.last_seen > NOW() - INTERVAL '14 days'
                ORDER BY lh.last_seen DESC NULLS LAST, lh.first_seen DESC
                LIMIT $1
                """,
                limit,
            )
            recent_assets = await conn.fetch(
                """
                SELECT d.id AS domain_id, 'subdomain' AS entity_type, s.id AS entity_id, s.subdomain AS location, 'new_subdomain' AS event_type, s.first_seen, jsonb_build_object('resolved', s.is_resolved, 'ip_addresses', s.ip_addresses) AS payload
                FROM subdomains s JOIN domains d ON d.id = s.domain_id
                WHERE s.first_seen > NOW() - INTERVAL '14 days'
                UNION ALL
                SELECT d.id AS domain_id, 'live_host' AS entity_type, lh.id AS entity_id, lh.url AS location, 'new_live_host' AS event_type, lh.first_seen, jsonb_build_object('status_code', lh.status_code, 'title', lh.title, 'webserver', lh.webserver) AS payload
                FROM live_hosts lh JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                WHERE lh.first_seen > NOW() - INTERVAL '14 days'
                UNION ALL
                SELECT d.id AS domain_id, 'endpoint' AS entity_type, e.id AS entity_id, (lh.url || e.path) AS location, 'new_endpoint' AS event_type, e.first_seen, jsonb_build_object('source', e.source, 'status_code', e.status_code, 'risk_tags', e.risk_tags) AS payload
                FROM endpoints e JOIN live_hosts lh ON lh.id = e.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                WHERE e.first_seen > NOW() - INTERVAL '14 days'
                UNION ALL
                SELECT d.id AS domain_id, 'js_asset' AS entity_type, ja.id AS entity_id, ja.asset_url AS location, 'new_js_asset' AS event_type, ja.first_seen, jsonb_build_object('source', ja.source, 'http_status', ja.http_status, 'sha256', ja.sha256) AS payload
                FROM js_assets ja JOIN live_hosts lh ON lh.id = ja.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                WHERE ja.first_seen > NOW() - INTERVAL '14 days'
                ORDER BY first_seen DESC
                LIMIT $1
                """,
                limit,
            )
            cloud_locations = await conn.fetch(
                """
                SELECT domain_id, location, source
                FROM (
                  SELECT d.id AS domain_id, lh.url AS location, 'live_host' AS source
                  FROM live_hosts lh JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE lh.url ~* '(s3|bucket|blob|storage|cloudfront|amazonaws|azure|gcp|googleapis|vercel|netlify|heroku|firebase|pages\\.dev|fastly)'
                  UNION ALL
                  SELECT d.id AS domain_id, ja.asset_url AS location, 'js_asset' AS source
                  FROM js_assets ja JOIN live_hosts lh ON lh.id = ja.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE ja.asset_url ~* '(s3|bucket|blob|storage|cloudfront|amazonaws|azure|gcp|googleapis|vercel|netlify|heroku|firebase|pages\\.dev|fastly)'
                  UNION ALL
                  SELECT d.id AS domain_id, (lh.url || e.path) AS location, 'endpoint' AS source
                  FROM endpoints e JOIN live_hosts lh ON lh.id = e.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE (lh.url || e.path) ~* '(s3|bucket|blob|storage|cloudfront|amazonaws|azure|gcp|googleapis|vercel|netlify|heroku|firebase|pages\\.dev|fastly)'
                ) cloud_candidates
                LIMIT $1
                """,
                max(limit, 2000),
            )
            api_candidates = await conn.fetch(
                """
                SELECT d.id AS domain_id, lh.id AS live_host_id, (lh.url || e.path) AS location, e.source, e.status_code
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE (lh.url || e.path) ~* '(graphql|graphiql|swagger|openapi|api-docs|redoc)'
                ORDER BY e.last_seen DESC
                LIMIT $1
                """,
                limit,
            )

        for row in recent_live_hosts:
            technologies = normalize_json_value(row["technologies"])
            if not isinstance(technologies, list):
                technologies = []
            payload = {
                "live_host_id": int(row["live_host_id"]),
                "url": row["url"],
                "status_code": row["status_code"],
                "title": row["title"],
                "webserver": row["webserver"],
                "tech": technologies,
                "technologies": technologies,
                "is_new_live_host": True,
                "fingerprint_changed": False,
                "backfilled": True,
            }
            decision = self.analyze_triage_payload("live_host", row["url"], payload)
            decision["score"] = int(decision.get("score") or 0) + self.host_priority_score(payload)
            decision["priority"] = self.priority_from_score(int(decision["score"]))
            await self.record_attack_playbooks(row["domain_id"], "live_hosts", int(row["live_host_id"]), row["url"], decision, payload)
            await self.enqueue_bug_jobs_for_asset(row["domain_id"], "live_hosts", int(row["live_host_id"]), "live_host", row["url"], payload, decision)
            await self.maybe_enqueue_bug_job_ffuf(dict(row), payload, decision)

        for row in findings:
            details = normalize_json_value(row["details"])
            if not isinstance(details, dict):
                details = {"details": details}
            evidence_id = await self.create_evidence_pack(
                row["domain_id"],
                "findings",
                int(row["id"]),
                row["finding_type"],
                row["location"],
                row["severity"],
                {"severity": row["severity"], "finding_type": row["finding_type"], "location": row["location"], "details": details},
                f"{str(row['severity']).upper()} {row['finding_type']} at {row['location']}",
            )
            await self.enqueue_validation(
                row["domain_id"],
                int(row["id"]),
                evidence_id,
                "findings",
                int(row["id"]),
                row["severity"] if row["severity"] in {"critical", "high", "medium"} else "medium",
                row["location"],
                self.validation_steps_for_finding(row["finding_type"], row["severity"], details),
            )
        for row in recent_assets:
            await self.record_asset_event(
                row["domain_id"],
                row["event_type"],
                row["entity_type"],
                int(row["entity_id"]),
                row["location"],
                "info",
                normalize_json_value(row["payload"]) if isinstance(normalize_json_value(row["payload"]), dict) else {},
            )
        for row in cloud_locations:
            await self.detect_cloud_asset(row["domain_id"], row["location"], row["source"])
        for row in api_candidates:
            lowered = str(row["location"]).lower()
            if "graphql" in lowered or "graphiql" in lowered:
                await self.save_api_surface(
                    row["domain_id"],
                    row["live_host_id"],
                    "graphql",
                    row["location"],
                    row["source"],
                    row["status_code"],
                    auth_required=row["status_code"] in {401, 403},
                    risk_flags=["graphql", "auth_required"] if row["status_code"] in {401, 403} else ["graphql"],
                    metadata={"backfilled": True},
                )
            else:
                await self.save_api_surface(
                    row["domain_id"],
                    row["live_host_id"],
                    "api_docs",
                    row["location"],
                    row["source"],
                    row["status_code"],
                    auth_required=row["status_code"] in {401, 403},
                    risk_flags=["api_docs"],
                    metadata={"backfilled": True},
                )

    async def get_domains_to_scan(
        self,
        limit: int | None = None,
        excluded_domain_ids: set[int] | None = None,
    ) -> list[dict[str, Any]]:
        assert self.db_pool is not None
        scan_limit = max(1, int(limit or self.config.scan["max_concurrent_domains"]))
        excluded_ids = sorted(excluded_domain_ids or set())
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  id,
                  domain,
                  organization,
                  scan_interval_hours,
                  last_scan,
                  include_subdomains,
                  max_live_hosts,
                  max_wayback_urls,
                  max_js_assets,
                  enable_gau,
                  enable_katana,
                  enable_hakrawler,
                  enable_js_analysis,
                  enable_ffuf,
                  enable_nuclei,
                  enable_screenshots,
                  enable_port_scan
                FROM domains
                WHERE active = TRUE
                  AND (
                    last_scan IS NULL OR
                    last_scan < NOW() - make_interval(hours => scan_interval_hours)
                  )
                  AND NOT (id = ANY($2::int[]))
                ORDER BY last_scan NULLS FIRST
                LIMIT $1
                """,
                scan_limit,
                excluded_ids,
            )
            return [dict(row) for row in rows]

    async def update_domain_last_scan(self, domain_id: int, retry_after_minutes: int | None = None) -> None:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            if retry_after_minutes is None:
                await conn.execute("UPDATE domains SET last_scan = NOW() WHERE id = $1", domain_id)
                return
            await conn.execute(
                """
                UPDATE domains
                SET last_scan = NOW()
                  - make_interval(hours => scan_interval_hours)
                  + make_interval(mins => $2)
                WHERE id = $1
                """,
                domain_id,
                max(1, int(retry_after_minutes)),
            )

    async def should_run_deep_scan(self, domain_info: dict[str, Any], first_run: bool) -> bool:
        if not self.config.scan.get("deep_scan_enabled", False):
            return False
        if first_run:
            return True

        interval_hours = int(self.config.scan.get("deep_scan_interval_hours", 168))
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            last_deep_scan = await conn.fetchval(
                """
                SELECT MAX(scan_finished_at)
                FROM scan_snapshots
                WHERE domain_id = $1
                  AND COALESCE((metadata->>'deep_scan')::boolean, FALSE) = TRUE
                """,
                domain_info["id"],
            )
        if last_deep_scan is None:
            return True
        return last_deep_scan < datetime.utcnow() - timedelta(hours=interval_hours)

    @staticmethod
    async def terminate_process_group(proc: asyncio.subprocess.Process, grace_seconds: float = 2.0) -> None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
            return
        except asyncio.TimeoutError:
            pass

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
        except asyncio.TimeoutError:
            logger.warning("Process group did not exit after SIGKILL: pid=%s", proc.pid)

    async def run_tool_result(
        self,
        *args: str,
        stdin_text: str | None = None,
        log_args: list[str] | None = None,
        capture_output_files: bool = False,
        timeout_seconds: float | None = None,
    ) -> ToolRunResult:
        binary = args[0]
        display_args = log_args if log_args is not None else list(args)
        if shutil.which(binary) is None:
            logger.info("Skipping missing tool: %s", binary)
            return ToolRunResult()

        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
                    stdout=stdout_file if capture_output_files else asyncio.subprocess.PIPE,
                    stderr=stderr_file if capture_output_files else asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
            except OSError as exc:
                if exc.errno == errno.EMFILE:
                    logger.warning("Too many open files while starting tool %s; skipping this run", binary)
                    return ToolRunResult(stderr=repr(exc))
                logger.warning("Failed to start tool %s: %r", binary, exc)
                return ToolRunResult(stderr=repr(exc))

            timed_out = False
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(stdin_text.encode() if stdin_text is not None else None),
                    timeout=timeout_seconds or self.config.scan["tool_timeout_seconds"],
                )
            except asyncio.TimeoutError:
                timed_out = True
                await self.terminate_process_group(proc)
                logger.warning("Tool timed out: %s", " ".join(display_args))
                stdout = b""
                stderr = b""
            except asyncio.CancelledError:
                await self.terminate_process_group(proc)
                raise

            if capture_output_files:
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout = stdout_file.read()
                stderr = stderr_file.read()

            if not timed_out and proc.returncode not in (0, 1):
                logger.warning("Tool returned %s: %s %s", proc.returncode, binary, stderr.decode(errors="ignore"))
            return ToolRunResult(
                stdout=stdout.decode(errors="ignore"),
                stderr=stderr.decode(errors="ignore"),
                returncode=proc.returncode,
                timed_out=timed_out,
            )

    async def run_tool(
        self,
        *args: str,
        stdin_text: str | None = None,
        log_args: list[str] | None = None,
        capture_output_files: bool = False,
        timeout_seconds: float | None = None,
    ) -> str:
        result = await self.run_tool_result(
            *args,
            stdin_text=stdin_text,
            log_args=log_args,
            capture_output_files=capture_output_files,
            timeout_seconds=timeout_seconds,
        )
        return result.stdout

    async def run_port_command(self, args: list[str], timeout_seconds: float) -> tuple[int, str, str]:
        if shutil.which(args[0]) is None:
            raise RuntimeError(f"missing port scan tool: {args[0]}")
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            await self.terminate_process_group(proc)
            raise RuntimeError(f"tool timed out after {timeout_seconds:.0f}s: {args[0]}")
        except asyncio.CancelledError:
            await self.terminate_process_group(proc)
            raise
        return proc.returncode or 0, stdout.decode(errors="ignore"), stderr.decode(errors="ignore")

    async def claim_port_scan_job(self, worker_id: str) -> dict[str, Any] | None:
        assert self.db_pool is not None
        lease_seconds = max(60, int(self.config.scan.get("port_scan_lease_seconds", 600)))
        async with self.db_pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT psj.id
                    FROM port_scan_jobs psj
                    JOIN infrastructure_ips ii ON ii.id = psj.ip_asset_id
                    WHERE psj.status = 'queued'
                      AND psj.available_at <= NOW()
                      AND psj.attempts < psj.max_attempts
                      AND ii.scan_eligible = TRUE
                    ORDER BY psj.priority DESC, psj.created_at
                    FOR UPDATE OF psj SKIP LOCKED
                    LIMIT 1
                    """
                )
                if not row:
                    return None
                return dict(
                    await conn.fetchrow(
                        """
                        UPDATE port_scan_jobs
                        SET status = 'running',
                            attempts = attempts + 1,
                            lease_owner = $2,
                            lease_expires_at = NOW() + make_interval(secs => $3),
                            heartbeat_at = NOW(),
                            started_at = COALESCE(started_at, NOW()),
                            updated_at = NOW(),
                            error = NULL
                        WHERE id = $1
                        RETURNING *
                        """,
                        row["id"],
                        worker_id,
                        lease_seconds,
                    )
                )

    async def heartbeat_port_scan_job(self, job_id: int, worker_id: str) -> None:
        assert self.db_pool is not None
        lease_seconds = max(60, int(self.config.scan.get("port_scan_lease_seconds", 600)))
        interval = max(10, int(self.config.scan.get("port_scan_heartbeat_seconds", 30)))
        while True:
            await asyncio.sleep(interval)
            async with self.db_pool.acquire() as conn:
                updated = await conn.execute(
                    """
                    UPDATE port_scan_jobs
                    SET heartbeat_at = NOW(),
                        lease_expires_at = NOW() + make_interval(secs => $3),
                        updated_at = NOW()
                    WHERE id = $1 AND status = 'running' AND lease_owner = $2
                    """,
                    job_id,
                    worker_id,
                    lease_seconds,
                )
            if updated.endswith(" 0"):
                return

    async def load_port_scan_context(self, job: dict[str, Any]) -> dict[str, Any]:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT psj.id, psj.domain_id, psj.ip_asset_id, psj.profile,
                       host(ii.ip_address) AS ip_address, ii.classification,
                       ii.provider, ii.asn, ii.asn_org, d.domain,
                       COALESCE(ARRAY_AGG(DISTINCT s.subdomain)
                         FILTER (WHERE s.subdomain IS NOT NULL), ARRAY[]::text[]) AS subdomains
                FROM port_scan_jobs psj
                JOIN infrastructure_ips ii ON ii.id = psj.ip_asset_id
                JOIN domains d ON d.id = psj.domain_id
                LEFT JOIN infrastructure_ip_subdomains iis ON iis.ip_asset_id = ii.id
                LEFT JOIN subdomains s ON s.id = iis.subdomain_id
                WHERE psj.id = $1
                GROUP BY psj.id, ii.id, d.id
                """,
                job["id"],
            )
            existing = await conn.fetch(
                """
                SELECT id, port, protocol, state, service, product, version
                FROM network_services
                WHERE ip_asset_id = $1
                """,
                job["ip_asset_id"],
            )
        if not row:
            raise RuntimeError("port scan job context disappeared")
        context = dict(row)
        context["existing_services"] = [dict(item) for item in existing]
        return context

    def port_scan_arguments(self, context: dict[str, Any]) -> tuple[list[str], set[int] | None]:
        profile = str(context["profile"])
        naabu = self.config.tools.get("naabu", "naabu")
        rate_key = f"port_scan_{profile}_rate"
        scan_rate = int(self.config.scan.get(rate_key, self.config.scan.get("port_scan_rate", 1000)))
        args = [
            naabu,
            "-host",
            str(context["ip_address"]),
            "-json",
            "-silent",
            "-Pn",
            "-scan-type",
            "c",
            "-rate",
            str(max(1, scan_rate)),
            "-retries",
            str(max(1, int(self.config.scan.get("port_scan_retries", 1)))),
            "-timeout",
            str(max(100, int(self.config.scan.get("port_scan_connect_timeout_ms", 1000)))),
            "-verify",
            "-no-stdin",
        ]
        scanned_ports: set[int] | None = None
        if (
            profile == "deep"
            and self.config.scan.get("port_scan_full_enabled", False)
            and context.get("classification") == "origin"
        ):
            args.extend(["-top-ports", "full"])
        elif profile in {"first", "deep"}:
            args.extend(["-top-ports", "1000"])
        else:
            configured = self.config.scan.get("port_scan_quick_ports", [])
            quick_ports = {int(port) for port in configured if str(port).isdigit()}
            quick_ports.update(
                int(item["port"])
                for item in context["existing_services"]
                if item["state"] == "open"
                or (profile == "shodan" and item["state"] == "passive_unverified")
            )
            scanned_ports = {port for port in quick_ports if 1 <= port <= 65535}
            args.extend(["-port", ",".join(str(port) for port in sorted(scanned_ports))])
        return args, scanned_ports

    def port_scan_naabu_timeout(self, profile: str, per_ip_budget: int) -> int:
        timeout_key = f"port_scan_{profile}_naabu_timeout_seconds"
        configured = int(
            self.config.scan.get(
                timeout_key,
                self.config.scan.get("port_scan_naabu_timeout_seconds", 300),
            )
        )
        return max(30, min(per_ip_budget - 20, configured))

    @staticmethod
    def parse_naabu_ports(output: str) -> set[int]:
        ports: set[int] = set()
        for line in output.splitlines():
            try:
                payload = json.loads(line)
                port = int(payload.get("port"))
            except (json.JSONDecodeError, TypeError, ValueError):
                match = re.search(r":(\d{1,5})$", line.strip())
                if not match:
                    continue
                port = int(match.group(1))
            if 1 <= port <= 65535:
                ports.add(port)
        return ports

    @staticmethod
    def parse_nmap_services(output: str) -> dict[int, dict[str, Any]]:
        services: dict[int, dict[str, Any]] = {}
        if not output.strip():
            return services
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return services
        for port_node in root.findall(".//port"):
            state = port_node.find("state")
            service = port_node.find("service")
            try:
                port = int(port_node.attrib["portid"])
            except (KeyError, ValueError):
                continue
            if state is None or state.attrib.get("state") != "open":
                continue
            attrs = service.attrib if service is not None else {}
            services[port] = {
                "service": attrs.get("name"),
                "product": attrs.get("product"),
                "version": attrs.get("version"),
                "extra_info": attrs.get("extrainfo"),
                "metadata": {
                    "method": attrs.get("method"),
                    "confidence": attrs.get("conf"),
                    "tunnel": attrs.get("tunnel"),
                },
            }
        return services

    @staticmethod
    def port_severity(port: int, service: str | None) -> str:
        if port in {2375, 2376, 6443, 10250, 9200, 9300, 27017, 6379, 11211}:
            return "high"
        if port in {21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5672, 9092, 15672}:
            return "medium"
        if service and service.lower() in {"mongodb", "redis", "elasticsearch", "docker", "kubernetes"}:
            return "high"
        return "info"

    @staticmethod
    def classify_open_port_transition(previous_state: str | None) -> str:
        if previous_state == "passive_unverified":
            return "verified"
        if previous_state in {"closed", "not_observed"}:
            return "reopened"
        if previous_state is None:
            return "new"
        return "unchanged"

    async def current_dns_hosts_for_ip(
        self,
        ip_address: str,
        hostnames: list[str],
    ) -> list[str]:
        timeout_seconds = max(
            1.0,
            float(self.config.scan.get("port_scan_dns_validation_timeout_seconds", 5)),
        )
        max_hosts = max(
            1,
            int(self.config.scan.get("port_scan_dns_validation_max_hosts", 25)),
        )
        expected_ip = ipaddress.ip_address(ip_address)

        async def resolves_to_ip(hostname: str) -> bool:
            try:
                results = await asyncio.wait_for(
                    asyncio.get_running_loop().getaddrinfo(
                        hostname,
                        None,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=timeout_seconds,
                )
            except (OSError, asyncio.TimeoutError):
                return False
            for result in results:
                try:
                    if ipaddress.ip_address(result[4][0]) == expected_ip:
                        return True
                except (IndexError, ValueError):
                    continue
            return False

        candidates = dedupe_list(
            [str(hostname).strip().rstrip(".").lower() for hostname in hostnames if hostname]
        )[:max_hosts]
        matches = await asyncio.gather(*(resolves_to_ip(hostname) for hostname in candidates))
        return [hostname for hostname, matched in zip(candidates, matches) if matched]

    async def execute_port_scan_job(self, job: dict[str, Any], worker_id: str) -> dict[str, Any]:
        context = await self.load_port_scan_context(job)
        ip_text = str(context["ip_address"])
        current_dns_hosts = await self.current_dns_hosts_for_ip(
            ip_text,
            list(context.get("subdomains") or []),
        )
        if (
            self.config.scan.get("port_scan_require_current_dns", True)
            and context.get("subdomains")
            and not current_dns_hosts
        ):
            logger.info(
                "Skipping stale infrastructure IP %s for %s; no associated hostname currently resolves to it",
                ip_text,
                context["domain"],
            )
            return {
                "ip": ip_text,
                "profile": context["profile"],
                "status": "skipped_stale_dns",
                "open_ports": [],
                "new_ports": [],
                "reopened_ports": [],
                "verified_ports": [],
                "closed_ports": [],
                "subdomains": context["subdomains"],
                "current_dns_hosts": [],
            }
        args, scanned_ports = self.port_scan_arguments(context)
        per_ip_budget = max(60, int(self.config.scan.get("port_scan_per_ip_timeout_seconds", 480)))
        naabu_timeout = self.port_scan_naabu_timeout(str(context["profile"]), per_ip_budget)
        rc, output, stderr = await self.run_port_command(args, naabu_timeout)
        if rc not in {0, 1}:
            raise RuntimeError(f"naabu failed with exit {rc}: {stderr[-500:]}")
        open_ports = self.parse_naabu_ports(output)

        service_details: dict[int, dict[str, Any]] = {}
        if open_ports:
            nmap_args = [
                self.config.tools.get("nmap", "nmap"),
                "-Pn",
                "-n",
                "-sV",
                "--version-light",
                "--host-timeout",
                f"{max(30, int(self.config.scan.get('port_scan_nmap_host_timeout_seconds', 240)))}s",
                "--max-retries",
                "1",
                "-p",
                ",".join(str(port) for port in sorted(open_ports)),
                "-oX",
                "-",
                ip_text,
            ]
            nmap_timeout = max(30, min(per_ip_budget - naabu_timeout, int(self.config.scan.get("port_scan_nmap_timeout_seconds", 240))))
            rc, nmap_output, nmap_stderr = await self.run_port_command(nmap_args, nmap_timeout)
            if rc not in {0, 1}:
                logger.warning("Nmap enrichment failed for %s: %s", ip_text, nmap_stderr[-500:])
            else:
                service_details = self.parse_nmap_services(nmap_output)

        new_ports: list[dict[str, Any]] = []
        closed_ports: list[int] = []
        reopened_ports: list[int] = []
        verified_ports: list[int] = []
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            product_text = " ".join(
                str(detail.get("product") or "").lower()
                for detail in service_details.values()
            )
            detected_cdn = next(
                (
                    provider
                    for provider in ("cloudflare", "akamai", "fastly", "imperva", "incapsula")
                    if provider in product_text
                ),
                None,
            )
            if detected_cdn:
                await conn.execute(
                    """
                    UPDATE infrastructure_ips
                    SET classification = 'cdn',
                        provider = COALESCE(provider, $2),
                        scan_eligible = FALSE,
                        last_seen = NOW()
                    WHERE id = $1
                    """,
                    context["ip_asset_id"],
                    detected_cdn,
                )
            try:
                ptr_name = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip_text), timeout=2)
                ptr_value = ptr_name[0]
            except (OSError, asyncio.TimeoutError):
                ptr_value = None
            if ptr_value:
                await conn.execute(
                    "UPDATE infrastructure_ips SET ptr_name = $2 WHERE id = $1",
                    context["ip_asset_id"],
                    ptr_value,
                )

            existing_by_port = {int(item["port"]): item for item in context["existing_services"]}
            for port in sorted(open_ports):
                detail = service_details.get(port, {})
                previous = existing_by_port.get(port)
                row = await conn.fetchrow(
                    """
                    INSERT INTO network_services (
                      domain_id, ip_asset_id, port, protocol, state, service,
                      product, version, extra_info, metadata
                    )
                    VALUES ($1, $2, $3, 'tcp', 'open', $4, $5, $6, $7, $8::jsonb)
                    ON CONFLICT (ip_asset_id, port, protocol)
                    DO UPDATE SET
                      state = 'open',
                      service = COALESCE(EXCLUDED.service, network_services.service),
                      product = COALESCE(EXCLUDED.product, network_services.product),
                      version = COALESCE(EXCLUDED.version, network_services.version),
                      extra_info = COALESCE(EXCLUDED.extra_info, network_services.extra_info),
                      metadata = network_services.metadata || EXCLUDED.metadata,
                      last_seen = NOW(),
                      last_scanned_at = NOW(),
                      closed_at = NULL
                    RETURNING id, (xmax = 0) AS inserted
                    """,
                    context["domain_id"],
                    context["ip_asset_id"],
                    port,
                    detail.get("service"),
                    detail.get("product"),
                    detail.get("version"),
                    detail.get("extra_info"),
                    postgres_json(detail.get("metadata", {})),
                )
                if row["inserted"]:
                    new_ports.append({"id": int(row["id"]), "port": port, **detail})
                elif self.classify_open_port_transition(
                    str(previous["state"]) if previous else None
                ) == "verified":
                    verified_ports.append(port)
                elif self.classify_open_port_transition(
                    str(previous["state"]) if previous else None
                ) == "reopened":
                    reopened_ports.append(port)

            if scanned_ports is not None:
                closed_ports = sorted(
                    port
                    for port, item in existing_by_port.items()
                    if item["state"] in {"open", "passive_unverified"}
                    and port in scanned_ports
                    and port not in open_ports
                )
                if closed_ports:
                    await conn.execute(
                        """
                        UPDATE network_services
                        SET state = CASE
                              WHEN state = 'passive_unverified' THEN 'not_observed'
                              ELSE 'closed'
                            END,
                            closed_at = NOW(),
                            last_scanned_at = NOW()
                        WHERE ip_asset_id = $1 AND port = ANY($2::int[]) AND protocol = 'tcp'
                        """,
                        context["ip_asset_id"],
                        closed_ports,
                    )

        for item in new_ports:
            port = int(item["port"])
            severity = self.port_severity(port, item.get("service"))
            location = f"{ip_text}:{port}"
            payload = {
                "domain": context["domain"],
                "subdomains": context["subdomains"],
                "service": item.get("service"),
                "product": item.get("product"),
                "version": item.get("version"),
                "profile": context["profile"],
            }
            await self.record_asset_event(
                context["domain_id"],
                "new_open_port",
                "network_service",
                item["id"],
                location,
                severity,
                payload,
            )
            if severity in {"high", "medium"}:
                await self.save_finding(
                    context["domain_id"],
                    "interesting_open_port",
                    severity,
                    location,
                    payload,
                )

        result = {
            "ip": ip_text,
            "profile": context["profile"],
            "open_ports": sorted(open_ports),
            "new_ports": [item["port"] for item in new_ports],
            "reopened_ports": reopened_ports,
            "verified_ports": verified_ports,
            "closed_ports": closed_ports,
            "subdomains": context["subdomains"],
            "current_dns_hosts": current_dns_hosts,
        }
        if new_ports or reopened_ports:
            await self.send_alert(
                "infrastructure_change",
                (
                    f"Infrastructure change: {context['domain']}\n"
                    f"IP: {ip_text}\n"
                    f"New ports: {', '.join(map(str, result['new_ports'])) or 'none'}\n"
                    f"Reopened ports: {', '.join(map(str, reopened_ports)) or 'none'}\n"
                    f"Associated hosts: {', '.join(context['subdomains'][:5]) or 'none'}"
                ),
                {
                    "domain_id": context["domain_id"],
                    "source": "port_scan",
                    "direct_ip_note": "HTTP/TLS may require the associated hostname for Host and SNI",
                    **result,
                },
            )
        return result

    async def run_port_worker_once(self, worker_id: str) -> bool:
        job = await self.claim_port_scan_job(worker_id)
        if not job:
            return False
        heartbeat = asyncio.create_task(self.heartbeat_port_scan_job(int(job["id"]), worker_id))
        timeout = max(60, int(self.config.scan.get("port_scan_per_ip_timeout_seconds", 480)))
        try:
            result = await asyncio.wait_for(self.execute_port_scan_job(job, worker_id), timeout=timeout)
        except Exception as exc:
            logger.warning("Port scan job %s failed: %s", job["id"], exc)
            error_text = repr(exc)[:2000]
            exhausted_timeout_status = (
                "incomplete_timeout"
                if "tool timed out" in error_text and int(job["attempts"]) >= int(job["max_attempts"])
                else "failed"
            )
            assert self.db_pool is not None
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE port_scan_jobs
                    SET status = CASE
                          WHEN attempts < max_attempts THEN 'queued'
                          ELSE $3
                        END,
                        available_at = CASE
                          WHEN attempts < max_attempts THEN NOW() + INTERVAL '2 minutes'
                          ELSE available_at
                        END,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        heartbeat_at = NULL,
                        error = $2,
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    job["id"],
                    error_text,
                    exhausted_timeout_status,
                )
        else:
            assert self.db_pool is not None
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE port_scan_jobs
                    SET status = 'completed',
                        completed_at = NOW(),
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        heartbeat_at = NULL,
                        result_summary = $2::jsonb,
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    job["id"],
                    postgres_json(result),
                )
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
        return True

    def shodan_enabled(self) -> bool:
        return bool(self.config.shodan.get("enabled", False) and self.config.shodan.get("api_key"))

    async def queue_shodan_domain_job(
        self,
        domain_id: int,
        priority: int = 80,
        conn: asyncpg.Connection | None = None,
    ) -> bool:
        if not self.shodan_enabled() or not self.config.shodan.get("domain_lookup_enabled", True):
            return False
        interval_hours = max(1, int(self.config.shodan.get("domain_lookup_interval_hours", 24)))
        query = """
            INSERT INTO shodan_jobs (
              domain_id, job_type, dedupe_key, priority, max_attempts
            )
            VALUES ($1, 'domain', $2, $3, $4)
            ON CONFLICT (dedupe_key)
            DO UPDATE SET
              status = 'queued',
              priority = GREATEST(shodan_jobs.priority, EXCLUDED.priority),
              attempts = 0,
              available_at = NOW(),
              lease_owner = NULL,
              lease_expires_at = NULL,
              error = NULL,
              updated_at = NOW()
            WHERE shodan_jobs.status IN ('completed', 'failed')
              AND shodan_jobs.updated_at <= NOW() - ($5 * INTERVAL '1 hour')
            RETURNING id
        """
        params = (
            domain_id,
            f"domain:{domain_id}",
            priority,
            max(1, int(self.config.shodan.get("max_attempts", 3))),
            interval_hours,
        )
        if conn is not None:
            return bool(await conn.fetchval(query, *params))
        assert self.db_pool is not None
        async with self.db_pool.acquire() as db_conn:
            return bool(await db_conn.fetchval(query, *params))

    async def queue_shodan_host_job(
        self,
        domain_id: int,
        ip_asset_id: int,
        priority: int = 60,
        conn: asyncpg.Connection | None = None,
    ) -> bool:
        if not self.shodan_enabled():
            return False
        interval_hours = max(1, int(self.config.shodan.get("host_lookup_interval_hours", 72)))
        query = """
            INSERT INTO shodan_jobs (
              domain_id, ip_asset_id, job_type, dedupe_key, priority, max_attempts
            )
            VALUES ($1, $2, 'host', $3, $4, $5)
            ON CONFLICT (dedupe_key)
            DO UPDATE SET
              status = 'queued',
              priority = GREATEST(shodan_jobs.priority, EXCLUDED.priority),
              attempts = 0,
              available_at = NOW(),
              lease_owner = NULL,
              lease_expires_at = NULL,
              error = NULL,
              updated_at = NOW()
            WHERE shodan_jobs.status IN ('completed', 'failed')
              AND shodan_jobs.updated_at <= NOW() - ($6 * INTERVAL '1 hour')
            RETURNING id
        """
        params = (
            domain_id,
            ip_asset_id,
            f"host:{ip_asset_id}",
            priority,
            max(1, int(self.config.shodan.get("max_attempts", 3))),
            interval_hours,
        )
        if conn is not None:
            return bool(await conn.fetchval(query, *params))
        assert self.db_pool is not None
        async with self.db_pool.acquire() as db_conn:
            return bool(await db_conn.fetchval(query, *params))

    async def seed_shodan_jobs(self) -> None:
        if not self.shodan_enabled() or self.db_pool is None:
            return
        max_ips = max(1, int(self.config.shodan.get("max_ip_lookups_per_domain", 100)))
        skip_cdn = bool(self.config.shodan.get("skip_cdn_ips", True))
        domain_interval = max(1, int(self.config.shodan.get("domain_lookup_interval_hours", 168)))
        host_interval = max(1, int(self.config.shodan.get("host_lookup_interval_hours", 72)))
        max_attempts = max(1, int(self.config.shodan.get("max_attempts", 3)))
        async with self.db_pool.acquire() as conn:
            domain_status = await conn.execute(
                """
                INSERT INTO shodan_jobs (
                  domain_id, job_type, dedupe_key, priority, max_attempts
                )
                SELECT id, 'domain', 'domain:' || id::text, 80, $1
                FROM domains
                WHERE active = TRUE
                ON CONFLICT (dedupe_key)
                DO UPDATE SET
                  status = 'queued',
                  priority = GREATEST(shodan_jobs.priority, EXCLUDED.priority),
                  attempts = 0,
                  available_at = NOW(),
                  lease_owner = NULL,
                  lease_expires_at = NULL,
                  error = NULL,
                  updated_at = NOW()
                WHERE shodan_jobs.status IN ('completed', 'failed')
                  AND shodan_jobs.updated_at <= NOW() - ($2 * INTERVAL '1 hour')
                """,
                max_attempts,
                domain_interval,
            )
            host_status = await conn.execute(
                """
                WITH ranked AS (
                  SELECT ii.domain_id, ii.id,
                         ROW_NUMBER() OVER (
                           PARTITION BY ii.domain_id
                           ORDER BY
                             CASE ii.classification WHEN 'origin' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,
                             ii.last_seen DESC
                         ) AS position
                  FROM infrastructure_ips ii
                  JOIN domains d ON d.id = ii.domain_id
                  WHERE d.active = TRUE
                    AND ii.scan_eligible = TRUE
                    AND ($1::boolean = FALSE OR ii.classification <> 'cdn')
                )
                INSERT INTO shodan_jobs (
                  domain_id, ip_asset_id, job_type, dedupe_key, priority, max_attempts
                )
                SELECT domain_id, id, 'host', 'host:' || id::text, 60, $2
                FROM ranked
                WHERE position <= $3
                ON CONFLICT (dedupe_key)
                DO UPDATE SET
                  status = 'queued',
                  priority = GREATEST(shodan_jobs.priority, EXCLUDED.priority),
                  attempts = 0,
                  available_at = NOW(),
                  lease_owner = NULL,
                  lease_expires_at = NULL,
                  error = NULL,
                  updated_at = NOW()
                WHERE shodan_jobs.status IN ('completed', 'failed')
                  AND shodan_jobs.updated_at <= NOW() - ($4 * INTERVAL '1 hour')
                """,
                skip_cdn,
                max_attempts,
                max_ips,
                host_interval,
            )
        logger.info("Shodan queue seed complete: %s, %s", domain_status, host_status)

    async def claim_shodan_job(self, worker_id: str) -> dict[str, Any] | None:
        assert self.db_pool is not None
        lease_seconds = max(60, int(self.config.shodan.get("lease_seconds", 120)))
        async with self.db_pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT sj.id, sj.domain_id, sj.ip_asset_id, sj.job_type,
                           d.domain, host(ii.ip_address) AS ip_address
                    FROM shodan_jobs sj
                    JOIN domains d ON d.id = sj.domain_id
                    LEFT JOIN infrastructure_ips ii ON ii.id = sj.ip_asset_id
                    WHERE sj.status = 'queued'
                      AND sj.available_at <= NOW()
                    ORDER BY sj.priority DESC, sj.created_at
                    FOR UPDATE OF sj SKIP LOCKED
                    LIMIT 1
                    """
                )
                if not row:
                    return None
                updated = await conn.fetchrow(
                    """
                    UPDATE shodan_jobs
                    SET status = 'running',
                        attempts = attempts + 1,
                        lease_owner = $2,
                        lease_expires_at = NOW() + ($3 * INTERVAL '1 second'),
                        started_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $1
                    RETURNING attempts, max_attempts
                    """,
                    row["id"],
                    worker_id,
                    lease_seconds,
                )
        result = dict(row)
        result.update(dict(updated))
        return result

    async def fetch_shodan_json(self, path: str) -> dict[str, Any]:
        api_key = str(self.config.shodan.get("api_key") or "")
        if not api_key:
            raise RuntimeError("SHODAN_API_KEY is not configured")
        base_url = str(self.config.shodan.get("api_base_url") or "https://api.shodan.io").rstrip("/")
        timeout = aiohttp.ClientTimeout(
            total=max(5, int(self.config.shodan.get("request_timeout_seconds", 30)))
        )
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"{base_url}{path}", params={"key": api_key}) as response:
                if response.status == 404:
                    return {"_not_found": True}
                payload = await response.json(content_type=None)
                if response.status != 200:
                    message = payload.get("error") if isinstance(payload, dict) else str(payload)
                    raise RuntimeError(f"Shodan API returned HTTP {response.status}: {message}")
                if not isinstance(payload, dict):
                    raise RuntimeError("Shodan API returned an unexpected response")
                return payload

    @staticmethod
    def parse_shodan_domain_payload(
        domain: str,
        payload: dict[str, Any],
    ) -> tuple[set[str], list[dict[str, Any]]]:
        payload = sanitize_postgres_value(payload)
        names: set[str] = set()
        records: list[dict[str, Any]] = []

        def normalize(label: Any) -> str | None:
            value = str(label or "").lower().strip().rstrip(".").lstrip("*.")
            if not value:
                return domain
            candidate = value if value == domain or value.endswith(f".{domain}") else f"{value}.{domain}"
            if len(candidate) > 255 or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", candidate):
                return None
            return candidate

        for label in payload.get("subdomains") or []:
            candidate = normalize(label)
            if candidate:
                names.add(candidate)
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            candidate = normalize(item.get("subdomain"))
            if not candidate:
                continue
            names.add(candidate)
            record_type = str(item.get("type") or "").upper()
            value = str(item.get("value") or "").strip().rstrip(".")
            if record_type in {"A", "AAAA", "CNAME", "MX", "NS", "TXT"} and value:
                records.append(
                    {
                        "hostname": candidate,
                        "type": record_type,
                        "value": value,
                        "last_seen": item.get("last_seen"),
                    }
                )
        return names, records

    @staticmethod
    def parse_shodan_host_payload(payload: dict[str, Any]) -> dict[str, Any]:
        payload = sanitize_postgres_value(payload)
        services: dict[tuple[int, str], dict[str, Any]] = {}
        vulnerabilities: set[str] = set()
        top_vulns = payload.get("vulns") or {}
        if isinstance(top_vulns, dict):
            vulnerabilities.update(str(item) for item in top_vulns)
        elif isinstance(top_vulns, list):
            vulnerabilities.update(str(item) for item in top_vulns)

        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                continue
            if not 1 <= port <= 65535:
                continue
            protocol = str(item.get("transport") or "tcp").lower()
            if protocol not in {"tcp", "udp"}:
                protocol = "tcp"
            item_vulns = item.get("vulns") or {}
            if isinstance(item_vulns, dict):
                vulnerabilities.update(str(value) for value in item_vulns)
            elif isinstance(item_vulns, list):
                vulnerabilities.update(str(value) for value in item_vulns)
            module = item.get("_shodan") if isinstance(item.get("_shodan"), dict) else {}
            service = {
                "port": port,
                "protocol": protocol,
                "service": item.get("product") or module.get("module"),
                "product": item.get("product"),
                "version": item.get("version"),
                "extra_info": item.get("info"),
                "banner": str(item.get("data") or "")[:4096] or None,
                "timestamp": item.get("timestamp"),
                "module": module.get("module"),
                "cves": sorted(vulnerabilities),
                "tls": item.get("ssl") if isinstance(item.get("ssl"), dict) else {},
            }
            key = (port, protocol)
            previous = services.get(key)
            if previous is None or str(service.get("timestamp") or "") > str(previous.get("timestamp") or ""):
                services[key] = service

        ports = {
            int(port)
            for port in (payload.get("ports") or [])
            if str(port).isdigit() and 1 <= int(port) <= 65535
        }
        ports.update(port for port, _ in services)
        normalized = {
            "ip": payload.get("ip_str"),
            "last_update": payload.get("last_update"),
            "hostnames": sorted({str(item).lower().rstrip(".") for item in payload.get("hostnames") or [] if item}),
            "domains": sorted({str(item).lower().rstrip(".") for item in payload.get("domains") or [] if item}),
            "ports": sorted(ports),
            "tags": sorted({str(item) for item in payload.get("tags") or [] if item}),
            "vulnerabilities": sorted(vulnerabilities),
            "asn": payload.get("asn"),
            "org": payload.get("org"),
            "isp": payload.get("isp"),
            "os": payload.get("os"),
            "country_code": (payload.get("country_code") or payload.get("location", {}).get("country_code"))
            if isinstance(payload.get("location", {}), dict)
            else payload.get("country_code"),
            "services": [services[key] for key in sorted(services)],
        }
        return normalized

    @staticmethod
    def classify_shodan_host(parsed: dict[str, Any]) -> tuple[str | None, str | None]:
        provider_text = " ".join(
            str(parsed.get(key) or "").lower()
            for key in ("org", "isp")
        )
        hostnames = [str(item).lower() for item in parsed.get("hostnames") or []]
        providers = {
            "cloudflare": ("cloudflare", ("cloudflare.net",)),
            "akamai": ("akamai", ("akamai.net", "akamaiedge.net", "edgekey.net", "edgesuite.net")),
            "fastly": ("fastly", ("fastly.net", "fastlylb.net")),
            "imperva": ("imperva", ("incapdns.net", "impervadns.net")),
        }
        for provider, (keyword, suffixes) in providers.items():
            if keyword in provider_text or any(
                hostname.endswith(suffixes) for hostname in hostnames
            ):
                return "cdn", provider
        return None, None

    async def ingest_shodan_domain_result(
        self,
        job: dict[str, Any],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if payload.get("_not_found"):
            return {"domain": job["domain"], "subdomains": 0, "records": 0, "not_found": True}
        names, records = self.parse_shodan_domain_payload(job["domain"], payload)
        existing_names: set[str] = set()
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT subdomain FROM subdomains WHERE domain_id = $1 AND subdomain = ANY($2::text[])",
                job["domain_id"],
                sorted(names),
            )
            existing_names = {str(row["subdomain"]) for row in rows}

        self.subdomain_sources_by_domain.setdefault(job["domain_id"], {})
        subdomain_ids: dict[str, int] = {}
        for name in sorted(names):
            self.subdomain_sources_by_domain[job["domain_id"]].setdefault(name, set()).add("shodan")
            subdomain_ids[name] = await self.save_subdomain(job["domain_id"], name)

        async with self.db_pool.acquire() as conn:
            if self.config.shodan.get("include_historical_dns", True):
                for record in records:
                    await conn.execute(
                        """
                        INSERT INTO dns_records (
                          domain_id, subdomain_id, record_type, value, is_current
                        )
                        VALUES ($1, $2, $3, $4, FALSE)
                        ON CONFLICT (subdomain_id, record_type, value)
                        DO UPDATE SET last_seen = NOW()
                        """,
                        job["domain_id"],
                        subdomain_ids[record["hostname"]],
                        record["type"],
                        record["value"],
                    )
            stable = {"names": sorted(names), "records": records}
            response_hash = hashlib.sha256(
                json.dumps(stable, sort_keys=True, default=str).encode()
            ).hexdigest()
            await conn.execute(
                """
                INSERT INTO shodan_domain_snapshots (
                  domain_id, response_hash, record_count, subdomain_count, metadata
                )
                VALUES ($1, $2, $3, $4, $5::jsonb)
                """,
                job["domain_id"],
                response_hash,
                len(records),
                len(names),
                postgres_json(
                    {
                        "source": "shodan",
                        "records_sample": records[:500],
                        "more_records": max(0, len(records) - 500),
                    }
                ),
            )
        new_names = sorted(names - existing_names)
        if new_names:
            await self.send_alert(
                "shodan_change",
                f"Shodan discovered {len(new_names)} new subdomains for {job['domain']}",
                {
                    "domain_id": job["domain_id"],
                    "domain": job["domain"],
                    "new_subdomains": new_names[:100],
                    "source": "shodan",
                },
            )
        return {
            "domain": job["domain"],
            "subdomains": len(names),
            "new_subdomains": len(new_names),
            "records": len(records),
        }

    async def ingest_shodan_host_result(
        self,
        job: dict[str, Any],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if payload.get("_not_found"):
            return {"ip": job["ip_address"], "ports": [], "not_found": True}
        parsed = self.parse_shodan_host_payload(payload)
        shodan_classification, shodan_provider = self.classify_shodan_host(parsed)
        stable = {
            "ports": parsed["ports"],
            "hostnames": parsed["hostnames"],
            "tags": parsed["tags"],
            "vulnerabilities": parsed["vulnerabilities"],
            "services": parsed["services"],
        }
        fingerprint = hashlib.sha256(
            json.dumps(stable, sort_keys=True, default=str).encode()
        ).hexdigest()
        new_ports: list[int] = []
        assert self.db_pool is not None

        for hostname in parsed["hostnames"]:
            candidate = self.normalize_subdomain_candidate(hostname, job["domain"])
            if not candidate:
                continue
            self.subdomain_sources_by_domain.setdefault(job["domain_id"], {}).setdefault(candidate, set()).add("shodan")
            subdomain_id = await self.save_subdomain(job["domain_id"], candidate)
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO infrastructure_ip_subdomains (ip_asset_id, subdomain_id)
                    VALUES ($1, $2)
                    ON CONFLICT (ip_asset_id, subdomain_id)
                    DO UPDATE SET last_seen = NOW()
                    """,
                    job["ip_asset_id"],
                    subdomain_id,
                )

        async with self.db_pool.acquire() as conn:
            previous_fingerprint = await conn.fetchval(
                """
                SELECT fingerprint_hash
                FROM shodan_host_snapshots
                WHERE ip_asset_id = $1
                ORDER BY fetched_at DESC
                LIMIT 1
                """,
                job["ip_asset_id"],
            )
            await conn.execute(
                """
                UPDATE infrastructure_ips
                SET ptr_name = COALESCE(ptr_name, $2),
                    asn = COALESCE($3, asn),
                    asn_org = COALESCE($4, asn_org),
                    provider = COALESCE($5, provider),
                    classification = CASE
                      WHEN $7 = 'cdn' THEN 'cdn'
                      ELSE classification
                    END,
                    scan_eligible = CASE
                      WHEN $7 = 'cdn' THEN FALSE
                      ELSE scan_eligible
                    END,
                    metadata = metadata || $6::jsonb,
                    last_seen = NOW()
                WHERE id = $1
                """,
                job["ip_asset_id"],
                parsed["hostnames"][0] if parsed["hostnames"] else None,
                parsed["asn"],
                parsed["org"],
                shodan_provider or parsed["isp"],
                postgres_json(
                    {
                        "shodan": {
                            "last_update": parsed["last_update"],
                            "tags": parsed["tags"],
                            "vulnerabilities": parsed["vulnerabilities"],
                            "country_code": parsed["country_code"],
                            "os": parsed["os"],
                        }
                    }
                ),
                shodan_classification,
            )
            await conn.execute(
                """
                INSERT INTO shodan_host_snapshots (
                  domain_id, ip_asset_id, shodan_last_update, fingerprint_hash,
                  ports, hostnames, tags, vulnerabilities, metadata
                )
                VALUES ($1, $2, $3::text::timestamptz, $4, $5::int[], $6::text[], $7::text[], $8::text[], $9::jsonb)
                """,
                job["domain_id"],
                job["ip_asset_id"],
                parsed["last_update"],
                fingerprint,
                parsed["ports"],
                parsed["hostnames"],
                parsed["tags"],
                parsed["vulnerabilities"],
                postgres_json(
                    {
                        "source": "shodan",
                        "asn": parsed["asn"],
                        "org": parsed["org"],
                        "isp": parsed["isp"],
                        "country_code": parsed["country_code"],
                        "os": parsed["os"],
                    }
                ),
            )
            for service in parsed["services"]:
                existed = await conn.fetchval(
                    """
                    SELECT TRUE
                    FROM network_services
                    WHERE ip_asset_id = $1 AND port = $2 AND protocol = $3
                    """,
                    job["ip_asset_id"],
                    service["port"],
                    service["protocol"],
                )
                await conn.execute(
                    """
                    INSERT INTO network_services (
                      domain_id, ip_asset_id, port, protocol, state, service,
                      product, version, extra_info, banner, tls, metadata
                    )
                    VALUES (
                      $1, $2, $3, $4, 'passive_unverified', $5,
                      $6, $7, $8, $9, $10::jsonb, $11::jsonb
                    )
                    ON CONFLICT (ip_asset_id, port, protocol)
                    DO UPDATE SET
                      state = CASE
                        WHEN network_services.state = 'open' THEN 'open'
                        ELSE 'passive_unverified'
                      END,
                      service = COALESCE(network_services.service, EXCLUDED.service),
                      product = COALESCE(network_services.product, EXCLUDED.product),
                      version = COALESCE(network_services.version, EXCLUDED.version),
                      extra_info = COALESCE(network_services.extra_info, EXCLUDED.extra_info),
                      banner = COALESCE(network_services.banner, EXCLUDED.banner),
                      tls = CASE
                        WHEN network_services.tls = '{}'::jsonb THEN EXCLUDED.tls
                        ELSE network_services.tls
                      END,
                      metadata = network_services.metadata || EXCLUDED.metadata,
                      last_seen = NOW()
                    """,
                    job["domain_id"],
                    job["ip_asset_id"],
                    service["port"],
                    service["protocol"],
                    service["service"],
                    service["product"],
                    service["version"],
                    service["extra_info"],
                    service["banner"],
                    postgres_json(service["tls"]),
                    postgres_json(
                        {
                            "shodan": {
                                "timestamp": service["timestamp"],
                                "module": service["module"],
                                "cves": service["cves"],
                            }
                        }
                    ),
                )
                if not existed:
                    new_ports.append(int(service["port"]))

            changed = previous_fingerprint is not None and previous_fingerprint != fingerprint
            if (
                self.config.shodan.get("verify_new_ports", True)
                and parsed["ports"]
                and shodan_classification != "cdn"
                and (new_ports or changed or previous_fingerprint is None)
            ):
                await conn.execute(
                    """
                    INSERT INTO port_scan_jobs (
                      domain_id, ip_asset_id, profile, schedule_bucket, priority
                    )
                    VALUES ($1, $2, 'shodan', CURRENT_DATE, $3)
                    ON CONFLICT (ip_asset_id, profile, schedule_bucket) DO NOTHING
                    """,
                    job["domain_id"],
                    job["ip_asset_id"],
                    95 if new_ports else 75,
                )
            elif shodan_classification == "cdn":
                await conn.execute(
                    """
                    UPDATE port_scan_jobs
                    SET status = 'cancelled',
                        error = 'shared CDN identified by Shodan',
                        updated_at = NOW()
                    WHERE ip_asset_id = $1
                      AND profile = 'shodan'
                      AND status = 'queued'
                    """,
                    job["ip_asset_id"],
                )

        for port in new_ports:
            await self.record_asset_event(
                job["domain_id"],
                "new_shodan_port",
                "infrastructure_ip",
                job["ip_asset_id"],
                f"{job['ip_address']}:{port}",
                self.port_severity(port, None),
                {"source": "shodan", "verified": False},
            )
        if new_ports:
            await self.send_alert(
                "shodan_change",
                f"Shodan reported new ports for {job['domain']}: {job['ip_address']}",
                {
                    "domain_id": job["domain_id"],
                    "domain": job["domain"],
                    "ip": job["ip_address"],
                    "new_ports": sorted(new_ports),
                    "verified": False,
                    "verification_queued": bool(self.config.shodan.get("verify_new_ports", True)),
                },
            )
        return {
            "ip": job["ip_address"],
            "ports": parsed["ports"],
            "new_ports": sorted(new_ports),
            "vulnerabilities": len(parsed["vulnerabilities"]),
            "changed": previous_fingerprint is not None and previous_fingerprint != fingerprint,
            "classification": shodan_classification,
        }

    async def execute_shodan_job(self, job: dict[str, Any]) -> dict[str, Any]:
        if job["job_type"] == "domain":
            payload = await self.fetch_shodan_json(f"/dns/domain/{job['domain']}")
            return await self.ingest_shodan_domain_result(job, payload)
        if not job.get("ip_address"):
            raise RuntimeError("Shodan host job has no IP address")
        payload = await self.fetch_shodan_json(f"/shodan/host/{job['ip_address']}")
        return await self.ingest_shodan_host_result(job, payload)

    async def run_shodan_worker_once(self, worker_id: str) -> bool:
        job = await self.claim_shodan_job(worker_id)
        if not job:
            return False
        try:
            result = await self.execute_shodan_job(job)
        except Exception as exc:
            logger.warning("Shodan job %s failed: %s", job["id"], exc)
            assert self.db_pool is not None
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE shodan_jobs
                    SET status = CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'failed' END,
                        available_at = CASE
                          WHEN attempts < max_attempts THEN NOW() + INTERVAL '5 minutes'
                          ELSE available_at
                        END,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        error = $2,
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    job["id"],
                    repr(exc)[:2000],
                )
        else:
            assert self.db_pool is not None
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE shodan_jobs
                    SET status = 'completed',
                        completed_at = NOW(),
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        error = NULL,
                        result_summary = $2::jsonb,
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    job["id"],
                    postgres_json(result),
                )
            logger.info("Completed Shodan %s job for %s", job["job_type"], job["domain"])
        return True

    async def run_amass(self, domain: str) -> str:
        binary = self.config.tools.get("amass", "amass")
        timeout_minutes = int(
            self.config.scan.get(
                "amass_timeout_minutes",
                max(1, int(self.config.scan["tool_timeout_seconds"]) // 60),
            )
        )
        async with self.amass_semaphore:
            try:
                return await self.run_tool(
                    binary,
                    "enum",
                    "-passive",
                    "-norecursive",
                    "-nocolor",
                    "-timeout",
                    str(timeout_minutes),
                    "-d",
                    domain,
                    capture_output_files=True,
                )
            finally:
                await self.cleanup_orphaned_amass_engines()

    @staticmethod
    async def cleanup_orphaned_amass_engines() -> None:
        orphaned: list[int] = []
        for process_dir in Path("/proc").iterdir():
            if not process_dir.name.isdigit():
                continue
            try:
                command = (process_dir / "cmdline").read_bytes().split(b"\0")
                status = (process_dir / "status").read_text(encoding="utf-8")
            except (OSError, PermissionError):
                continue
            if len(command) < 2 or Path(command[0].decode(errors="ignore")).name != "amass":
                continue
            if command[1] != b"engine":
                continue
            parent_line = next((line for line in status.splitlines() if line.startswith("PPid:")), "")
            if parent_line.split()[-1:] != ["1"]:
                continue
            orphaned.append(int(process_dir.name))

        for pid in orphaned:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
        if orphaned:
            await asyncio.sleep(0.5)
        for pid in orphaned:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
        if orphaned:
            logger.info("Cleaned up %d orphaned Amass engine process(es)", len(orphaned))

    @staticmethod
    def redact_cli_headers(args: list[str]) -> list[str]:
        redacted: list[str] = []
        redact_next = False
        for arg in args:
            if redact_next:
                redacted.append("<redacted-header>")
                redact_next = False
                continue
            redacted.append(arg)
            if arg in {"-H", "--header", "-h", "--chrome-header", "-C", "--cookie"}:
                redact_next = True
        return redacted

    @staticmethod
    def create_header_file(header_lines: list[str]) -> str:
        if not header_lines:
            return ""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            os.chmod(handle.name, 0o600)
            handle.write("\n".join(header_lines))
            handle.write("\n")
            return handle.name

    def cookie_header_file(self) -> Path | None:
        value = str(self.config.scan.get("cookie_header_file") or "").strip()
        if not value:
            return None
        path = Path(value)
        return path if path.is_file() else None

    def cookie_header_value(self) -> str | None:
        path = self.cookie_header_file()
        if path is None:
            return None
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    if stripped.lower().startswith("cookie:"):
                        return stripped
                    return f"Cookie: {stripped}"
        except OSError as exc:
            logger.warning("Unable to read cookie header file %s: %s", path, exc)
        return None

    def cookie_header_allowed(self, url_or_host: str) -> bool:
        allowed = [str(item).strip().lower().lstrip(".") for item in self.config.scan.get("cookie_header_domains", []) if str(item).strip()]
        if not allowed:
            return True
        parsed = urlsplit(url_or_host if "://" in url_or_host else f"https://{url_or_host}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        return any(hostname == domain or hostname.endswith(f".{domain}") for domain in allowed)

    def authenticated_headers(self, url_or_host: str | None = None, domain_info: dict[str, Any] | None = None) -> dict[str, str]:
        if domain_info is not None and url_or_host:
            profile_headers = self.auth_profile_headers(domain_info, url_or_host)
            if profile_headers:
                return profile_headers
        if url_or_host and not self.cookie_header_allowed(url_or_host):
            return {}
        header = self.cookie_header_value()
        if not header:
            return {}
        name, _, value = header.partition(":")
        if name.lower() != "cookie" or not value.strip():
            return {}
        return {"Cookie": value.strip()}

    def passive_source_timeout(self, source: str) -> aiohttp.ClientTimeout:
        configured = self.config.scan.get("passive_source_timeouts", {})
        default_timeout = int(self.config.scan.get("passive_source_timeout_seconds", 25))
        if isinstance(configured, dict):
            timeout_seconds = int(configured.get(source, default_timeout))
        else:
            timeout_seconds = default_timeout
        return aiohttp.ClientTimeout(total=max(1, timeout_seconds))

    def passive_source_headers(self) -> dict[str, str]:
        user_agent = str(
            self.config.scan.get(
                "passive_source_user_agent",
                "enhanced-recon-framework/1.0",
            )
        )
        return {
            "Accept": "application/json,text/plain,*/*",
            "User-Agent": user_agent,
        }

    def passive_source_retries(self, source: str) -> int:
        configured = self.config.scan.get("passive_source_retries", {})
        if isinstance(configured, dict):
            return max(1, int(configured.get(source, 1)))
        return 1

    def passive_source_delay(self, source: str) -> float:
        configured = self.config.scan.get("passive_source_request_delays", {})
        default_delay = float(self.config.scan.get("passive_source_request_delay_seconds", 1.0))
        if isinstance(configured, dict):
            return max(0.0, float(configured.get(source, default_delay)))
        return max(0.0, default_delay)

    async def wait_for_passive_source_slot(self, source: str) -> None:
        loop = asyncio.get_running_loop()
        delay = self.passive_source_delay(source)
        last_request = self.passive_source_last_request.get(source)
        if last_request is not None:
            await asyncio.sleep(max(0.0, last_request + delay - loop.time()))
        self.passive_source_last_request[source] = loop.time()

    async def fetch_passive_json(self, source: str, domain: str, url: str) -> Any | None:
        retry_statuses = {429, 500, 502, 503, 504}
        permanent_request_statuses = {400, 404}
        max_backoff = max(1.0, float(self.config.scan.get("passive_source_max_backoff_seconds", 60)))
        attempts = self.passive_source_retries(source)
        semaphore = self.passive_source_semaphores.setdefault(source, asyncio.Semaphore(1))
        loop = asyncio.get_running_loop()

        if self.passive_source_circuit_until.get(source, 0.0) > loop.time():
            logger.info("Skipping %s for %s while provider cooldown is active", source, domain)
            return None

        async with semaphore:
            if self.passive_source_circuit_until.get(source, 0.0) > loop.time():
                logger.info("Skipping %s for %s while provider cooldown is active", source, domain)
                return None
            async with aiohttp.ClientSession(
                timeout=self.passive_source_timeout(source),
                headers=self.passive_source_headers(),
            ) as session:
                for attempt in range(1, attempts + 1):
                    try:
                        await self.wait_for_passive_source_slot(source)
                        async with session.get(url) as response:
                            if response.status == 200:
                                self.passive_source_circuit_until.pop(source, None)
                                return await response.json(content_type=None)
                            if response.status in permanent_request_statuses:
                                logger.warning("%s returned HTTP %s for %s", source, response.status, domain)
                                return None
                            if response.status not in retry_statuses or attempt >= attempts:
                                logger.warning("%s returned HTTP %s for %s", source, response.status, domain)
                                cooldown_key = "passive_source_rate_limit_cooldown_seconds" if response.status == 429 else "passive_source_error_cooldown_seconds"
                                cooldown = max(0.0, float(self.config.scan.get(cooldown_key, 900 if response.status == 429 else 300)))
                                if cooldown:
                                    self.passive_source_circuit_until[source] = loop.time() + cooldown
                                return None
                            retry_after = response.headers.get("Retry-After", "").strip()
                            try:
                                retry_delay = float(retry_after)
                            except ValueError:
                                retry_delay = 0.0
                            backoff = min(max_backoff, max(retry_delay, float(2 ** (attempt - 1))))
                            logger.info(
                                "%s returned HTTP %s for %s; retrying in %.1fs (%s/%s)",
                                source,
                                response.status,
                                domain,
                                backoff,
                                attempt,
                                attempts,
                            )
                    except Exception as exc:
                        if attempt >= attempts:
                            self.log_passive_source_failure(source, domain, exc)
                            cooldown = max(0.0, float(self.config.scan.get("passive_source_timeout_cooldown_seconds", 120)))
                            if cooldown:
                                self.passive_source_circuit_until[source] = loop.time() + cooldown
                            return None
                        backoff = min(max_backoff, float(2 ** (attempt - 1)))
                        logger.info(
                            "%s attempt %s/%s failed for %s; retrying in %.1fs",
                            source,
                            attempt,
                            attempts,
                            domain,
                            backoff,
                        )
                    await asyncio.sleep(backoff)
        return None

    def log_passive_source_failure(self, source: str, domain: str, exc: Exception) -> None:
        if isinstance(exc, asyncio.TimeoutError):
            timeout = self.passive_source_timeout(source).total
            logger.warning("%s timed out for %s after %ss", source, domain, timeout)
            return
        logger.warning("%s failed for %s: %s: %s", source, domain, type(exc).__name__, exc)

    async def run_crtsh(self, domain: str) -> set[str]:
        results: set[str] = set()
        payload = await self.fetch_passive_json(
            "crtsh",
            domain,
            f"https://crt.sh/?q=%25.{domain}&output=json",
        )
        if not isinstance(payload, list):
            return results

        for entry in payload:
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.lower().strip().lstrip("*.")
                if name.endswith(domain):
                    results.add(name)
        return results

    def normalize_subdomain_candidate(self, value: str, domain: str) -> str | None:
        domain = domain.lower().strip().rstrip(".")
        candidate = value.lower().strip().strip(".,;:'\"()[]{}<>").lstrip("*.")
        if not candidate:
            return None
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        candidate = candidate.rstrip(".")
        if candidate != domain and not candidate.endswith(f".{domain}"):
            return None
        if len(candidate) > 255:
            return None
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", candidate):
            return None
        return candidate

    async def run_crtname(self, domain: str) -> set[str]:
        results: set[str] = set()
        query = urlencode({"apex": domain})
        payload = await self.fetch_passive_json(
            "crtname",
            domain,
            f"https://crt.name/v1/search?{query}",
        )
        if not isinstance(payload, list):
            return results
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            candidate = self.normalize_subdomain_candidate(str(entry.get("sub", "")), domain)
            if candidate:
                results.add(candidate)
        return results

    async def run_certspotter(self, domain: str) -> set[str]:
        results: set[str] = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        payload = await self.fetch_passive_json("certspotter", domain, url)
        if not isinstance(payload, list):
            return results
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            for name in entry.get("dns_names") or []:
                candidate = self.normalize_subdomain_candidate(str(name), domain)
                if candidate:
                    results.add(candidate)
        return results

    async def run_alienvault(self, domain: str) -> set[str]:
        results: set[str] = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        payload = await self.fetch_passive_json("alienvault", domain, url)
        if not isinstance(payload, dict):
            return results
        for entry in payload.get("passive_dns", []):
            candidate = self.normalize_subdomain_candidate(str(entry.get("hostname", "")), domain)
            if candidate:
                results.add(candidate)
        return results

    async def run_hackertarget(self, domain: str) -> set[str]:
        results: set[str] = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        status, body = await self.fetch_text_url(url, max_bytes=2_000_000)
        if status != 200 or not body:
            return results
        for line in body.splitlines():
            name = line.split(",", 1)[0]
            candidate = self.normalize_subdomain_candidate(name, domain)
            if candidate:
                results.add(candidate)
        return results

    async def run_rapiddns(self, domain: str) -> set[str]:
        results: set[str] = set()
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        status, body = await self.fetch_text_url(url, max_bytes=3_000_000)
        if status != 200 or not body:
            return results
        pattern = re.compile(rf"([a-zA-Z0-9_.-]+\.){re.escape(domain)}")
        for match in pattern.finditer(body):
            candidate = self.normalize_subdomain_candidate(match.group(0), domain)
            if candidate:
                results.add(candidate)
        return results

    def passive_source_runner(self, source: str, domain: str) -> Any | None:
        runners = {
            "crtsh": self.run_crtsh,
            "crtname": self.run_crtname,
            "certspotter": self.run_certspotter,
            "alienvault": self.run_alienvault,
            "hackertarget": self.run_hackertarget,
            "rapiddns": self.run_rapiddns,
        }
        runner = runners.get(source)
        return runner(domain) if runner else None

    async def run_recursive_subdomain_tool(self, source: str, zone: str) -> set[str]:
        if source == "amass":
            stdout = await self.run_amass(zone)
        else:
            tool_specs = {
                "assetfinder": (
                    self.config.tools.get("assetfinder", "assetfinder"),
                    [zone],
                ),
                "subfinder": (
                    self.config.tools.get("subfinder", "subfinder"),
                    ["-d", zone, "-silent"],
                ),
                "findomain": (
                    self.config.tools.get("findomain", "findomain"),
                    ["-t", zone, "-q"],
                ),
                "sublist3r": (
                    self.config.tools.get("sublist3r", "sublist3r"),
                    ["-d", zone, "-n", "-t", "10"],
                ),
            }
            spec = tool_specs.get(source)
            if spec is None:
                return set()
            binary, args = spec
            stdout = await self.run_tool(binary, *args, capture_output_files=True)

        results: set[str] = set()
        for line in stdout.splitlines():
            candidate = self.normalize_subdomain_candidate(line, zone)
            if candidate:
                results.add(candidate)
        return results

    async def enumerate_passive_subdomains(self, domain: str) -> dict[str, set[str]]:
        if not self.config.scan.get("passive_subdomain_sources_enabled", True):
            return {}
        source_names = list(dict.fromkeys(
            str(item).lower() for item in self.config.scan.get("passive_sources", [])
        ))
        tasks: list[tuple[str, Any]] = []
        for source in source_names:
            task = self.passive_source_runner(source, domain)
            if task is not None:
                tasks.append((source, task))
        if not tasks:
            return {}
        max_per_source = int(self.config.scan.get("max_passive_subdomains_per_source", 10000))
        outputs = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
        results: dict[str, set[str]] = {}
        for (source, _), output in zip(tasks, outputs):
            if isinstance(output, Exception):
                logger.warning("Passive source failed: %s: %s", source, output)
                continue
            results[source] = set(sorted(output)[:max_per_source])
        return results

    def select_recursive_zone_candidates(
        self,
        domain: str,
        discovered_names: set[str],
        excluded: set[str],
        limit: int,
    ) -> list[str]:
        domain_labels = domain.lower().strip(".").split(".")
        max_zone_labels = max(
            1,
            int(self.config.scan.get("recursive_passive_max_zone_labels", 3)),
        )
        keywords = {
            str(item).strip().lower()
            for item in self.config.scan.get(
                "recursive_passive_priority_keywords",
                self.config.scan.get("host_priority_keywords", []),
            )
            if str(item).strip()
        }
        descendant_counts: dict[str, int] = {}
        for value in discovered_names:
            candidate = self.normalize_subdomain_candidate(value, domain)
            if not candidate or candidate == domain:
                continue
            labels = candidate.split(".")
            relative = labels[: -len(domain_labels)]
            for depth in range(1, min(len(relative), max_zone_labels) + 1):
                zone = ".".join([*relative[-depth:], *domain_labels])
                if zone == domain or zone in excluded:
                    continue
                descendant_counts[zone] = descendant_counts.get(zone, 0) + 1

        def score(zone: str) -> tuple[int, int, int, str]:
            relative = zone[: -(len(domain) + 1)].split(".")
            keyword_hit = int(any(label in keywords for label in relative))
            return (
                -keyword_hit,
                -descendant_counts[zone],
                len(relative),
                zone,
            )

        return sorted(descendant_counts, key=score)[: max(0, limit)]

    @staticmethod
    def dns_answer_has_exact_record(output: str, zone: str, record_type: str) -> bool:
        expected_zone = zone.lower().rstrip(".")
        expected_type = record_type.upper()
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue
            owner = fields[0].lower().rstrip(".")
            try:
                class_index = fields.index("IN")
            except ValueError:
                continue
            if (
                owner == expected_zone
                and class_index + 1 < len(fields)
                and fields[class_index + 1].upper() == expected_type
            ):
                return True
        return False

    async def is_delegated_zone(self, zone: str) -> bool:
        dig_binary = self.config.tools.get("dig", "dig")
        timeout = max(
            2.0,
            float(self.config.scan.get("recursive_passive_dns_timeout_seconds", 8)),
        )
        async with self.recursive_dns_semaphore:
            for record_type in ("NS", "SOA"):
                result = await self.run_tool_result(
                    dig_binary,
                    "+time=2",
                    "+tries=1",
                    "+noall",
                    "+answer",
                    zone,
                    record_type,
                    capture_output_files=True,
                    timeout_seconds=timeout,
                )
                if self.dns_answer_has_exact_record(result.stdout, zone, record_type):
                    return True
        return False

    async def enumerate_recursive_passive_subdomains(
        self,
        domain: str,
        initial_names: set[str],
        summary: dict[str, Any] | None = None,
    ) -> dict[str, set[str]]:
        if not self.config.scan.get("recursive_passive_discovery_enabled", False):
            return {}
        max_depth = max(1, int(self.config.scan.get("recursive_passive_max_depth", 2)))
        max_candidates = max(
            1,
            int(self.config.scan.get("recursive_passive_max_candidates", 50)),
        )
        per_round = max(
            1,
            int(self.config.scan.get("recursive_passive_candidates_per_round", 25)),
        )
        supported_sources = {
            "crtsh",
            "crtname",
            "certspotter",
            "alienvault",
            "hackertarget",
            "rapiddns",
        }
        configured_sources = list(dict.fromkeys(
            str(item).lower()
            for item in self.config.scan.get("recursive_passive_sources", ["crtname"])
        ))
        sources = [source for source in configured_sources if source in supported_sources]
        supported_tools = {"assetfinder", "subfinder", "findomain", "sublist3r", "amass"}
        configured_tools = list(dict.fromkeys(
            str(item).lower()
            for item in self.config.scan.get("recursive_subdomain_tools", [])
        ))
        recursive_tools = [source for source in configured_tools if source in supported_tools]
        max_zones = max(
            1,
            int(self.config.scan.get("recursive_passive_max_zones", 10)),
        )
        if not sources and not recursive_tools:
            return {}

        all_names = set(initial_names)
        frontier_names = set(initial_names)
        checked_zones: set[str] = {domain}
        queried_zones: set[str] = {domain}
        results: dict[str, set[str]] = {}
        recursive_stats: dict[str, Any] = {
            "enabled": True,
            "candidate_budget": max_candidates,
            "candidates_checked": 0,
            "delegated_zones": [],
            "zones_queried": [],
            "passive_sources": sources,
            "subdomain_tools": recursive_tools,
            "new_names": 0,
            "depth_completed": 0,
        }

        for depth in range(1, max_depth + 1):
            remaining = max_candidates - int(recursive_stats["candidates_checked"])
            if remaining <= 0 or not frontier_names:
                break
            candidates = self.select_recursive_zone_candidates(
                domain,
                frontier_names,
                checked_zones,
                min(per_round, remaining),
            )
            if not candidates:
                break
            checked_zones.update(candidates)
            recursive_stats["candidates_checked"] += len(candidates)
            delegated_flags = await asyncio.gather(
                *(self.is_delegated_zone(zone) for zone in candidates),
                return_exceptions=True,
            )
            delegated = [
                zone
                for zone, is_delegated in zip(candidates, delegated_flags)
                if is_delegated is True and zone not in queried_zones
            ]
            remaining_zones = max_zones - len(queried_zones - {domain})
            delegated = delegated[: max(0, remaining_zones)]
            recursive_stats["delegated_zones"].extend(delegated)
            if not delegated:
                recursive_stats["depth_completed"] = depth
                break

            queried_zones.update(delegated)
            recursive_stats["zones_queried"].extend(delegated)
            jobs: list[tuple[str, str, Any]] = []
            for zone in delegated:
                for source in sources:
                    task = self.passive_source_runner(source, zone)
                    if task is not None:
                        jobs.append((source, zone, task))
                for source in recursive_tools:
                    jobs.append((source, zone, self.run_recursive_subdomain_tool(source, zone)))
            outputs = await asyncio.gather(
                *(task for _, _, task in jobs),
                return_exceptions=True,
            )
            next_frontier: set[str] = set()
            for (source, zone, _), output in zip(jobs, outputs):
                if isinstance(output, Exception):
                    logger.warning(
                        "Recursive passive source failed: %s for %s: %s",
                        source,
                        zone,
                        output,
                    )
                    continue
                source_key = f"{source}_recursive"
                for value in output:
                    candidate = self.normalize_subdomain_candidate(str(value), domain)
                    if not candidate:
                        continue
                    results.setdefault(source_key, set()).add(candidate)
                    if candidate not in all_names:
                        all_names.add(candidate)
                        next_frontier.add(candidate)
            recursive_stats["depth_completed"] = depth
            recursive_stats["new_names"] += len(next_frontier)
            frontier_names = next_frontier

        recursive_stats["delegated_zones"] = sorted(set(recursive_stats["delegated_zones"]))
        recursive_stats["zones_queried"] = sorted(set(recursive_stats["zones_queried"]))
        if summary is not None:
            summary["passive_recursion"] = recursive_stats
        logger.info(
            "Recursive passive discovery for %s: checked=%s delegated=%s queried=%s new=%s depth=%s",
            domain,
            recursive_stats["candidates_checked"],
            len(recursive_stats["delegated_zones"]),
            len(recursive_stats["zones_queried"]),
            recursive_stats["new_names"],
            recursive_stats["depth_completed"],
        )
        return results

    async def enumerate_subdomains(
        self,
        domain_info: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> set[str]:
        domain = domain_info["domain"]
        if not self.domain_bool(domain_info, "include_subdomains", True):
            return {domain}

        tool_map = [
            (self.config.tools.get("assetfinder", "assetfinder"), [domain]),
            (self.config.tools.get("subfinder", "subfinder"), ["-d", domain, "-silent"]),
            (self.config.tools.get("findomain", "findomain"), ["-t", domain, "-q"]),
            (self.config.tools.get("sublist3r", "sublist3r"), ["-d", domain, "-n", "-t", "10"]),
        ]
        tool_names = ["assetfinder", "subfinder", "findomain", "sublist3r", "amass"]
        tasks = [
            self.run_tool(binary, *args, capture_output_files=True)
            for binary, args in tool_map
        ]
        tasks.append(self.run_amass(domain))
        passive_task = self.enumerate_passive_subdomains(domain)
        tasks.append(passive_task)
        outputs = await asyncio.gather(*tasks, return_exceptions=True)

        subdomains: set[str] = {domain}
        source_map: dict[str, set[str]] = {domain: {"root"}}
        for name, item in zip(tool_names + ["passive"], outputs):
            if isinstance(item, Exception):
                continue
            if isinstance(item, dict):
                for source, discovered in item.items():
                    for discovered_name in discovered:
                        candidate = self.normalize_subdomain_candidate(discovered_name, domain)
                        if not candidate:
                            continue
                        subdomains.add(candidate)
                        source_map.setdefault(candidate, set()).add(source)
                continue
            for line in str(item).splitlines():
                candidate = self.normalize_subdomain_candidate(line, domain)
                if candidate:
                    subdomains.add(candidate)
                    source_map.setdefault(candidate, set()).add(name)
        recursive_results = await self.enumerate_recursive_passive_subdomains(
            domain,
            subdomains,
            summary,
        )
        for source, discovered in recursive_results.items():
            for discovered_name in discovered:
                candidate = self.normalize_subdomain_candidate(discovered_name, domain)
                if not candidate:
                    continue
                subdomains.add(candidate)
                source_map.setdefault(candidate, set()).add(source)
        self.subdomain_sources_by_domain[domain_info["id"]] = source_map
        return subdomains

    async def load_known_subdomains(self, domain_id: int, domain: str) -> set[str]:
        if not self.config.scan.get("httpx_include_known_subdomains", True):
            return set()
        limit = max(1, int(self.config.scan.get("httpx_max_known_subdomains_per_scan", 20000)))
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT subdomain
                FROM subdomains
                WHERE domain_id = $1
                  AND (subdomain = $2 OR subdomain LIKE ('%.' || $2))
                ORDER BY last_seen DESC, subdomain
                LIMIT $3
                """,
                domain_id,
                domain,
                limit,
            )
        return {str(row["subdomain"]).lower().rstrip(".") for row in rows}

    def generate_permutation_candidates(self, domain: str, subdomains: set[str]) -> list[str]:
        words = [str(item).strip().lower() for item in self.config.scan.get("permutation_words", []) if str(item).strip()]
        if not words:
            return []

        max_candidates = int(self.config.scan.get("max_permutation_candidates", 500))
        labels: set[str] = set()
        for subdomain in subdomains:
            if subdomain == domain or not subdomain.endswith(f".{domain}"):
                continue
            relative = subdomain[: -(len(domain) + 1)]
            if not relative:
                continue
            leftmost = relative.split(".", 1)[0].lower()
            if 1 < len(leftmost) <= 40 and leftmost.replace("-", "").isalnum():
                labels.add(leftmost)

        candidates: list[str] = []
        seen = set(subdomains)

        def add(candidate: str) -> None:
            if len(candidates) >= max_candidates:
                return
            candidate = candidate.strip(".").lower()
            if candidate and candidate.endswith(domain) and candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)

        for word in words:
            add(f"{word}.{domain}")
        for label in sorted(labels):
            for word in words:
                add(f"{word}-{label}.{domain}")
                add(f"{label}-{word}.{domain}")
                add(f"{word}.{label}.{domain}")
        return candidates

    async def discover_permutation_subdomains(
        self,
        domain_info: dict[str, Any],
        subdomains: set[str],
        summary: dict[str, Any] | None = None,
    ) -> set[str]:
        if not self.config.scan.get("permutation_discovery_enabled", False):
            return set()

        candidates = self.generate_permutation_candidates(domain_info["domain"], subdomains)
        if not candidates:
            return set()

        dnsx_binary = self.config.tools.get("dnsx", "dnsx")
        stdout = await self.run_tool(
            dnsx_binary,
            "-silent",
            "-a",
            stdin_text="\n".join(candidates),
            capture_output_files=True,
        )
        resolved: set[str] = set()
        for line in stdout.splitlines():
            name = line.strip().lower().split()[0].rstrip(".")
            if name.endswith(domain_info["domain"]):
                resolved.add(name)
        for item in sorted(resolved):
            self.append_summary(summary, "permutation_subdomains", item)
            self.subdomain_sources_by_domain.setdefault(domain_info["id"], {}).setdefault(item, set()).add("permutation_dnsx")
        return resolved

    async def save_subdomain(self, domain_id: int, subdomain: str, summary: dict[str, Any] | None = None) -> int:
        assert self.db_pool is not None
        sources = sorted(self.subdomain_sources_by_domain.get(domain_id, {}).get(subdomain, {"unknown"}))
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO subdomains (domain_id, subdomain)
                VALUES ($1, $2)
                ON CONFLICT (domain_id, subdomain)
                DO UPDATE SET last_seen = NOW()
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                subdomain,
            )
            for source in sources:
                await conn.execute(
                    """
                    INSERT INTO subdomain_sources (subdomain_id, source)
                    VALUES ($1, $2)
                    ON CONFLICT (subdomain_id, source)
                    DO UPDATE SET last_seen = NOW()
                    """,
                    row["id"],
                    source,
                )
        if row and row["inserted"]:
            SUBDOMAINS_FOUND.inc()
            self.append_summary(summary, "new_subdomains", subdomain)
            await self.record_asset_event(
                domain_id,
                "new_subdomain",
                "subdomain",
                int(row["id"]),
                subdomain,
                "info",
                {"sources": sources},
                summary,
            )
        if summary is not None:
            source_counts = summary.setdefault("passive_sources", {})
            for source in sources:
                source_counts[source] = int(source_counts.get(source, 0)) + 1
        return int(row["id"])

    @staticmethod
    def classify_ip_asset(payload: dict[str, Any]) -> tuple[str, str | None]:
        cdn_value = payload.get("cdn")
        provider = payload.get("cdn_name") or payload.get("cdn")
        cnames = [str(item).lower().rstrip(".") for item in (payload.get("cname") or [])]
        cdn_suffixes = (
            "akamai.net",
            "akamaiedge.net",
            "akamaitechnologies.com",
            "cloudflare.net",
            "cloudfront.net",
            "edgesuite.net",
            "edgekey.net",
            "fastly.net",
            "fastlylb.net",
            "azureedge.net",
            "trafficmanager.net",
            "googlehosted.com",
            "gslb.googlehosted.com",
            "incapdns.net",
            "impervadns.net",
        )
        if cdn_value or any(cname.endswith(cdn_suffixes) for cname in cnames):
            return "cdn", str(provider or next(iter(cnames), "cdn"))
        return "unknown", str(provider) if provider else None

    async def collect_dnsx_payloads(
        self,
        domain: str,
        subdomains: list[str],
        summary: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        dnsx_binary = self.config.tools.get("dnsx", "dnsx")
        dns_timeout = max(1, int(self.config.scan.get("infrastructure_dns_timeout_seconds", 3)))
        threads = max(1, int(self.config.scan.get("infrastructure_dns_threads", 50)))
        rate_limit = max(1, int(self.config.scan.get("infrastructure_dns_rate_limit", 200)))
        batch_size = max(1, int(self.config.scan.get("dnsx_batch_size", 500)))
        minimum_batch_size = max(1, int(self.config.scan.get("dnsx_fallback_min_batch_size", 50)))
        max_split_depth = max(0, int(self.config.scan.get("dnsx_max_split_depth", 4)))
        batch_timeout = max(10.0, float(self.config.scan.get("dnsx_batch_timeout_seconds", 180)))
        stats: dict[str, Any] = {
            "status": "complete",
            "total_inputs": len(subdomains),
            "batch_size": batch_size,
            "attempted_batches": 0,
            "completed_batches": 0,
            "timed_out_batches": 0,
            "split_retries": 0,
            "incomplete_inputs": 0,
            "output_records": 0,
            "malformed_records": 0,
        }
        collected: dict[str, dict[str, Any]] = {}

        async def run_batch(batch: list[str], depth: int) -> None:
            if not batch:
                return
            stats["attempted_batches"] += 1
            result = await self.run_tool_result(
                dnsx_binary,
                "-json",
                "-silent",
                "-a",
                "-aaaa",
                "-cname",
                "-cdn",
                "-asn",
                "-retry",
                "1",
                "-timeout",
                f"{dns_timeout}s",
                "-threads",
                str(min(threads, len(batch))),
                "-rate-limit",
                str(rate_limit),
                "-omit-raw",
                stdin_text="\n".join(batch),
                capture_output_files=True,
                timeout_seconds=batch_timeout,
            )
            for line in result.stdout.splitlines():
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed_records"] += 1
                    continue
                hostname = str(payload.get("host") or "").lower().rstrip(".") if isinstance(payload, dict) else ""
                if hostname:
                    collected[hostname] = payload
                else:
                    stats["malformed_records"] += 1

            if not result.timed_out:
                stats["completed_batches"] += 1
                return
            stats["timed_out_batches"] += 1
            if len(batch) > minimum_batch_size and depth < max_split_depth:
                stats["split_retries"] += 1
                midpoint = max(1, len(batch) // 2)
                await run_batch(batch[:midpoint], depth + 1)
                await run_batch(batch[midpoint:], depth + 1)
                return
            stats["status"] = "incomplete"
            stats["incomplete_inputs"] += len(batch)
            logger.error(
                "DNSX coverage incomplete for %s: %s input(s) still timed out at fallback depth %s",
                domain,
                len(batch),
                depth,
            )

        for offset in range(0, len(subdomains), batch_size):
            await run_batch(subdomains[offset : offset + batch_size], 0)

        stats["output_records"] = len(collected)
        if summary is not None:
            summary["dnsx_probe"] = stats
        logger.info(
            "DNSX coverage for %s: status=%s inputs=%s outputs=%s batches=%s timeouts=%s split_retries=%s incomplete_inputs=%s",
            domain,
            stats["status"],
            stats["total_inputs"],
            stats["output_records"],
            stats["attempted_batches"],
            stats["timed_out_batches"],
            stats["split_retries"],
            stats["incomplete_inputs"],
        )
        return list(collected.values())

    async def discover_infrastructure(
        self,
        domain_info: dict[str, Any],
        subdomains: list[str],
        first_run: bool,
        deep_scan: bool,
        summary: dict[str, Any] | None = None,
    ) -> int:
        if not self.domain_bool(domain_info, "enable_port_scan", self.config.scan.get("port_scan_enabled", True)):
            return 0
        if not subdomains:
            return 0

        payloads = await self.collect_dnsx_payloads(domain_info["domain"], subdomains, summary)
        if not payloads:
            return 0

        profile = "first" if first_run else ("deep" if deep_scan else "quick")
        max_ips = max(1, int(self.config.scan.get("port_scan_max_ips_per_domain", 500)))
        skip_cdn = bool(self.config.scan.get("port_scan_skip_cdn_ips", True))
        queued = 0
        seen_ips: set[str] = set()

        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            for payload in payloads:
                hostname = str(payload.get("host") or "").lower().rstrip(".")
                if not hostname or not hostname.endswith(domain_info["domain"]):
                    continue
                subdomain_id = await self.save_subdomain(domain_info["id"], hostname, summary)
                addresses = []
                for record_type, key in (("A", "a"), ("AAAA", "aaaa")):
                    for value in payload.get(key) or []:
                        try:
                            ip_text = str(ipaddress.ip_address(str(value)))
                        except ValueError:
                            continue
                        addresses.append((record_type, ip_text))
                cnames = [str(item).lower().rstrip(".") for item in (payload.get("cname") or []) if item]
                ttl = payload.get("ttl")

                await conn.execute(
                    "UPDATE dns_records SET is_current = FALSE WHERE subdomain_id = $1 AND is_current = TRUE",
                    subdomain_id,
                )
                for record_type, value in [*addresses, *(("CNAME", item) for item in cnames)]:
                    await conn.execute(
                        """
                        INSERT INTO dns_records (domain_id, subdomain_id, record_type, value, ttl)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (subdomain_id, record_type, value)
                        DO UPDATE SET last_seen = NOW(), ttl = EXCLUDED.ttl, is_current = TRUE
                        """,
                        domain_info["id"],
                        subdomain_id,
                        record_type,
                        value,
                        int(ttl) if isinstance(ttl, (int, float)) else None,
                    )

                ip_values = sorted({value for _, value in addresses})
                await conn.execute(
                    """
                    UPDATE subdomains
                    SET is_resolved = $2,
                        ip_addresses = $3::text[],
                        last_seen = NOW()
                    WHERE id = $1
                    """,
                    subdomain_id,
                    bool(ip_values),
                    ip_values,
                )
                classification, provider = self.classify_ip_asset(payload)
                asn_data = payload.get("asn")
                asn = None
                asn_org = None
                if isinstance(asn_data, dict):
                    asn = str(asn_data.get("as_number") or asn_data.get("asn") or "") or None
                    asn_org = str(asn_data.get("as_name") or asn_data.get("org") or "") or None
                elif asn_data:
                    asn = str(asn_data)

                for ip_text in ip_values:
                    if ip_text not in seen_ips and len(seen_ips) >= max_ips:
                        continue
                    seen_ips.add(ip_text)
                    row = await conn.fetchrow(
                        """
                        INSERT INTO infrastructure_ips (
                          domain_id, ip_address, ip_version, asn, asn_org, provider,
                          classification, scan_eligible, metadata
                        )
                        VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9::jsonb)
                        ON CONFLICT (domain_id, ip_address)
                        DO UPDATE SET
                          last_seen = NOW(),
                          asn = COALESCE(EXCLUDED.asn, infrastructure_ips.asn),
                          asn_org = COALESCE(EXCLUDED.asn_org, infrastructure_ips.asn_org),
                          provider = COALESCE(EXCLUDED.provider, infrastructure_ips.provider),
                          classification = CASE
                            WHEN EXCLUDED.classification <> 'unknown' THEN EXCLUDED.classification
                            ELSE infrastructure_ips.classification
                          END,
                          scan_eligible = CASE
                            WHEN EXCLUDED.classification = 'cdn' THEN EXCLUDED.scan_eligible
                            ELSE infrastructure_ips.scan_eligible
                          END,
                          metadata = infrastructure_ips.metadata || EXCLUDED.metadata
                        RETURNING id, (xmax = 0) AS inserted, scan_eligible
                        """,
                        domain_info["id"],
                        ip_text,
                        ipaddress.ip_address(ip_text).version,
                        asn,
                        asn_org,
                        provider,
                        classification,
                        not (skip_cdn and classification == "cdn"),
                        postgres_json({"cnames": cnames, "dns_host": hostname}),
                    )
                    await conn.execute(
                        """
                        INSERT INTO infrastructure_ip_subdomains (ip_asset_id, subdomain_id)
                        VALUES ($1, $2)
                        ON CONFLICT (ip_asset_id, subdomain_id)
                        DO UPDATE SET last_seen = NOW()
                        """,
                        row["id"],
                        subdomain_id,
                    )
                    if row["inserted"]:
                        self.append_summary(
                            summary,
                            "new_ips",
                            {"ip": ip_text, "hostname": hostname, "classification": classification},
                        )
                        await self.record_asset_event(
                            domain_info["id"],
                            "new_ip",
                            "infrastructure_ip",
                            int(row["id"]),
                            ip_text,
                            "info",
                            {"hostname": hostname, "classification": classification, "provider": provider},
                            summary,
                        )
                    if not row["scan_eligible"]:
                        continue
                    inserted = await conn.fetchval(
                        """
                        INSERT INTO port_scan_jobs (
                          domain_id, ip_asset_id, profile, schedule_bucket, priority
                        )
                        VALUES ($1, $2, $3, CURRENT_DATE, $4)
                        ON CONFLICT (ip_asset_id, profile, schedule_bucket) DO NOTHING
                        RETURNING id
                        """,
                        domain_info["id"],
                        row["id"],
                        profile,
                        100 if row["inserted"] else (70 if deep_scan else 50),
                    )
                    if inserted:
                        queued += 1
                    if row["scan_eligible"]:
                        await self.queue_shodan_host_job(
                            domain_info["id"],
                            int(row["id"]),
                            90 if row["inserted"] else 60,
                            conn=conn,
                        )
        logger.info(
            "Infrastructure discovery for %s found %s unique IPs and queued %s %s port jobs",
            domain_info["domain"],
            len(seen_ips),
            queued,
            profile,
        )
        return queued

    async def save_live_host(
        self,
        subdomain_id: int,
        payload: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> tuple[int, bool]:
        assert self.db_pool is not None
        url = payload["url"]
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        title = payload.get("title") or None
        status_code = payload.get("status_code")
        webserver = payload.get("webserver") or None
        content_length = payload.get("content_length")
        ip_values = self.httpx_payload_ip_addresses(payload)

        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO live_hosts (subdomain_id, url, port, protocol, status_code, title, webserver, content_length)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (url)
                DO UPDATE SET
                  last_seen = NOW(),
                  status_code = EXCLUDED.status_code,
                  title = EXCLUDED.title,
                  webserver = EXCLUDED.webserver,
                  content_length = EXCLUDED.content_length
                RETURNING id, (xmax = 0) AS inserted
                """,
                subdomain_id,
                url,
                port,
                parsed.scheme,
                status_code,
                title,
                webserver,
                content_length,
            )

            for tech in payload.get("tech", []) or []:
                await conn.execute(
                    """
                    INSERT INTO technologies (live_host_id, technology, version)
                    VALUES ($1, $2, NULL)
                    ON CONFLICT (live_host_id, technology, version)
                    DO UPDATE SET last_seen = NOW()
                    """,
                    row["id"],
                    str(tech),
                )

            if ip_values:
                domain_id = await conn.fetchval(
                    "SELECT domain_id FROM subdomains WHERE id = $1",
                    subdomain_id,
                )
                await conn.execute(
                    """
                    UPDATE subdomains
                    SET is_resolved = TRUE,
                        ip_addresses = $2::text[],
                        last_seen = NOW()
                    WHERE id = $1
                    """,
                    subdomain_id,
                    ip_values,
                )
                await conn.execute(
                    """
                    UPDATE dns_records
                    SET is_current = FALSE
                    WHERE subdomain_id = $1
                      AND record_type IN ('A', 'AAAA')
                      AND is_current = TRUE
                    """,
                    subdomain_id,
                )
                for ip_text in ip_values:
                    record_type = "AAAA" if ipaddress.ip_address(ip_text).version == 6 else "A"
                    await conn.execute(
                        """
                        INSERT INTO dns_records (domain_id, subdomain_id, record_type, value)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT (subdomain_id, record_type, value)
                        DO UPDATE SET last_seen = NOW(), is_current = TRUE
                        """,
                        domain_id,
                        subdomain_id,
                        record_type,
                        ip_text,
                    )

        if row and row["inserted"]:
            LIVE_HOSTS_FOUND.inc()
            self.append_summary(summary, "new_live_hosts", url)
        return int(row["id"]), bool(row["inserted"])

    @staticmethod
    def httpx_payload_ip_addresses(payload: dict[str, Any]) -> list[str]:
        candidates: list[Any] = []
        for key in ("a", "aaaa"):
            value = payload.get(key) or []
            candidates.extend(value if isinstance(value, list) else [value])
        if payload.get("host_ip"):
            candidates.append(payload["host_ip"])

        addresses: set[str] = set()
        for value in candidates:
            try:
                addresses.add(str(ipaddress.ip_address(str(value))))
            except ValueError:
                continue
        return sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item))

    @staticmethod
    def parse_httpx_jsonl(output: str) -> tuple[list[dict[str, Any]], int]:
        payloads: list[dict[str, Any]] = []
        malformed = 0
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(payload, dict) and payload.get("url"):
                payloads.append(payload)
            else:
                malformed += 1
        return payloads, malformed

    async def collect_httpx_payloads(
        self,
        domain: str,
        subdomains: list[str],
        summary: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        httpx_binary = self.config.tools.get("httpx", "httpx")
        batch_size = max(1, int(self.config.scan.get("httpx_batch_size", 200)))
        minimum_batch_size = max(1, int(self.config.scan.get("httpx_fallback_min_batch_size", 25)))
        max_split_depth = max(0, int(self.config.scan.get("httpx_max_split_depth", 4)))
        batch_timeout = max(10.0, float(self.config.scan.get("httpx_batch_timeout_seconds", 300)))
        request_timeout = max(1, int(self.config.scan.get("httpx_request_timeout_seconds", 10)))
        retries = max(0, int(self.config.scan.get("httpx_retries", 1)))
        threads = max(1, int(self.config.scan.get("httpx_threads", 50)))
        rate_limit = max(1, int(self.config.scan.get("httpx_rate_limit", 100)))

        existing_stats = dict((summary or {}).get("httpx_probe") or {})
        stats: dict[str, Any] = {
            "status": "complete",
            "total_inputs": len(subdomains),
            "known_subdomains_reused": int(existing_stats.get("known_subdomains_reused", 0)),
            "batch_size": batch_size,
            "attempted_batches": 0,
            "completed_batches": 0,
            "timed_out_batches": 0,
            "split_retries": 0,
            "incomplete_inputs": 0,
            "output_records": 0,
            "malformed_records": 0,
        }
        collected: dict[str, dict[str, Any]] = {}

        async def run_batch(batch: list[str], depth: int) -> None:
            if not batch:
                return
            stats["attempted_batches"] += 1
            result = await self.run_tool_result(
                httpx_binary,
                "-json",
                "-silent",
                "-threads",
                str(min(threads, len(batch))),
                "-rate-limit",
                str(rate_limit),
                "-timeout",
                str(request_timeout),
                "-retries",
                str(retries),
                "-tech-detect",
                "-status-code",
                "-content-length",
                stdin_text="\n".join(batch),
                capture_output_files=True,
                timeout_seconds=batch_timeout,
            )
            payloads, malformed = self.parse_httpx_jsonl(result.stdout)
            stats["malformed_records"] += malformed
            for payload in payloads:
                collected[str(payload["url"])] = payload

            if not result.timed_out:
                stats["completed_batches"] += 1
                return

            stats["timed_out_batches"] += 1
            if len(batch) > minimum_batch_size and depth < max_split_depth:
                stats["split_retries"] += 1
                midpoint = max(1, len(batch) // 2)
                await run_batch(batch[:midpoint], depth + 1)
                await run_batch(batch[midpoint:], depth + 1)
                return

            stats["status"] = "incomplete"
            stats["incomplete_inputs"] += len(batch)
            logger.error(
                "HTTPX coverage incomplete for %s: %s input(s) still timed out at fallback depth %s",
                domain,
                len(batch),
                depth,
            )

        for offset in range(0, len(subdomains), batch_size):
            await run_batch(subdomains[offset : offset + batch_size], 0)

        stats["output_records"] = len(collected)
        if summary is not None:
            summary["httpx_probe"] = stats
        logger.info(
            "HTTPX coverage for %s: status=%s inputs=%s outputs=%s batches=%s timeouts=%s split_retries=%s incomplete_inputs=%s",
            domain,
            stats["status"],
            stats["total_inputs"],
            stats["output_records"],
            stats["attempted_batches"],
            stats["timed_out_batches"],
            stats["split_retries"],
            stats["incomplete_inputs"],
        )
        return list(collected.values())

    async def probe_live_hosts(
        self,
        domain_info: dict[str, Any],
        subdomains: list[str],
        summary: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        payloads = await self.collect_httpx_payloads(domain_info["domain"], subdomains, summary)
        if not payloads:
            return []

        results: list[dict[str, Any]] = []
        subdomain_ids = {sub: await self.save_subdomain(domain_info["id"], sub, summary) for sub in subdomains}
        for payload in payloads:
            host = (urlsplit(payload["url"]).hostname or "").lower().rstrip(".")
            if not host or host not in subdomain_ids:
                continue
            live_host_id, is_new_live_host = await self.save_live_host(subdomain_ids[host], payload, summary)
            fingerprint_changed = await self.record_host_fingerprint(domain_info["id"], live_host_id, payload, summary)
            payload["live_host_id"] = live_host_id
            payload["is_new_live_host"] = is_new_live_host
            payload["fingerprint_changed"] = fingerprint_changed
            await self.detect_cloud_asset(domain_info["id"], payload["url"], "live_host")
            live_host_decision = self.analyze_triage_payload(
                "live_host",
                payload["url"],
                {
                    "url": payload["url"],
                    "status_code": payload.get("status_code"),
                    "title": payload.get("title"),
                    "webserver": payload.get("webserver"),
                    "technologies": payload.get("tech", []),
                    "new": is_new_live_host,
                    "fingerprint_changed": fingerprint_changed,
                },
            )
            live_host_decision["score"] = int(live_host_decision.get("score") or 0) + self.host_priority_score(payload)
            live_host_decision["priority"] = self.priority_from_score(int(live_host_decision["score"]))
            await self.upsert_asset_risk(domain_info["id"], "live_host", live_host_id, payload["url"], live_host_decision)
            if (
                is_new_live_host
                or fingerprint_changed
                or self.priority_rank(str(live_host_decision.get("priority") or "low"))
                >= self.priority_rank(str(self.config.scan.get("bug_jobs_live_host_min_priority", "high")))
            ):
                await self.record_attack_playbooks(
                    domain_info["id"],
                    "live_hosts",
                    live_host_id,
                    payload["url"],
                    live_host_decision,
                    {
                        "url": payload["url"],
                        "status_code": payload.get("status_code"),
                        "title": payload.get("title"),
                        "webserver": payload.get("webserver"),
                        "technologies": payload.get("tech", []),
                        "new": is_new_live_host,
                        "fingerprint_changed": fingerprint_changed,
                    },
                )
                await self.enqueue_bug_jobs_for_asset(
                    domain_info["id"],
                    "live_hosts",
                    live_host_id,
                    "live_host",
                    payload["url"],
                    {
                        "url": payload["url"],
                        "status_code": payload.get("status_code"),
                        "title": payload.get("title"),
                        "webserver": payload.get("webserver"),
                        "technologies": payload.get("tech", []),
                        "new": is_new_live_host,
                        "fingerprint_changed": fingerprint_changed,
                    },
                    live_host_decision,
                )
                await self.maybe_enqueue_bug_job_ffuf(domain_info, payload, live_host_decision, summary)
            if is_new_live_host:
                await self.record_asset_event(
                    domain_info["id"],
                    "new_live_host",
                    "live_host",
                    live_host_id,
                    payload["url"],
                    "info",
                    {
                        "status_code": payload.get("status_code"),
                        "title": payload.get("title"),
                        "webserver": payload.get("webserver"),
                        "technologies": payload.get("tech", []),
                    },
                    summary,
                )
            results.append(payload)

        max_live_hosts = domain_info.get("max_live_hosts")
        if max_live_hosts:
            results = results[: int(max_live_hosts)]
        return results

    def host_priority_score(self, host: dict[str, Any]) -> int:
        url = str(host.get("url") or "").lower()
        hostname = urlsplit(url).hostname or url
        title = str(host.get("title") or "").lower()
        webserver = str(host.get("webserver") or "").lower()
        status_code = int(host.get("status_code") or 0)
        keywords = [str(item).lower() for item in self.config.scan.get("host_priority_keywords", [])]

        score = 0
        for keyword in keywords:
            if keyword and keyword in hostname:
                score += 20
            if keyword and keyword in title:
                score += 8
        if status_code in {200, 401, 403}:
            score += 12
        elif 300 <= status_code < 400:
            score += 6
        elif status_code >= 500:
            score -= 10
        if any(token in webserver for token in ("api", "gateway", "nginx", "envoy")):
            score += 4
        if host.get("is_new_live_host"):
            score += 3
        if host.get("fingerprint_changed"):
            score += 5
        return score

    def rank_live_hosts(self, live_hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            live_hosts,
            key=lambda host: (
                self.host_priority_score(host),
                int(host.get("status_code") or 0) in {200, 401, 403},
                str(host.get("url") or ""),
            ),
            reverse=True,
        )

    async def record_host_fingerprint(
        self,
        domain_id: int,
        live_host_id: int,
        payload: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> bool:
        assert self.db_pool is not None
        techs = sorted(str(item) for item in (payload.get("tech", []) or []))
        fingerprint_material = {
            "status_code": payload.get("status_code"),
            "title": payload.get("title"),
            "webserver": payload.get("webserver"),
            "content_length": payload.get("content_length"),
            "tech": techs,
        }
        fingerprint_hash = hashlib.sha256(json.dumps(fingerprint_material, sort_keys=True).encode()).hexdigest()
        changed = False

        async with self.db_pool.acquire() as conn:
            current = await conn.fetchrow(
                "SELECT id, fingerprint_hash FROM live_host_fingerprints WHERE live_host_id = $1 AND is_current = TRUE",
                live_host_id,
            )

            await conn.execute(
                """
                UPDATE live_hosts
                SET fingerprint_hash = $2,
                    status_code = $3,
                    title = $4,
                    webserver = $5,
                    content_length = $6,
                    last_seen = NOW()
                WHERE id = $1
                """,
                live_host_id,
                fingerprint_hash,
                payload.get("status_code"),
                payload.get("title"),
                payload.get("webserver"),
                payload.get("content_length"),
            )

            if current and current["fingerprint_hash"] == fingerprint_hash:
                await conn.execute(
                    """
                    UPDATE live_host_fingerprints
                    SET last_seen = NOW()
                    WHERE live_host_id = $1 AND fingerprint_hash = $2
                    """,
                    live_host_id,
                    fingerprint_hash,
                )
                return False

            if current:
                changed = True
                await conn.execute(
                    "UPDATE live_host_fingerprints SET is_current = FALSE, last_seen = NOW() WHERE live_host_id = $1 AND is_current = TRUE",
                    live_host_id,
                )

            await conn.execute(
                """
                INSERT INTO live_host_fingerprints (
                  live_host_id,
                  fingerprint_hash,
                  status_code,
                  title,
                  webserver,
                  content_length,
                  technologies,
                  metadata,
                  is_current
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, TRUE)
                ON CONFLICT (live_host_id, fingerprint_hash)
                DO UPDATE SET last_seen = NOW(), is_current = TRUE
                """,
                live_host_id,
                fingerprint_hash,
                payload.get("status_code"),
                payload.get("title"),
                payload.get("webserver"),
                payload.get("content_length"),
                json.dumps(techs),
                json.dumps(fingerprint_material),
            )

        if changed:
            location = payload.get("url") or f"live_host:{live_host_id}"
            self.append_summary(
                summary,
                "changed_fingerprints",
                {
                    "url": location,
                    "status_code": payload.get("status_code"),
                    "webserver": payload.get("webserver"),
                },
            )
            await self.save_finding(
                domain_id,
                "host_fingerprint_changed",
                "info",
                location,
                fingerprint_material,
                summary,
            )
            await self.record_asset_event(
                domain_id,
                "host_fingerprint_changed",
                "live_host",
                live_host_id,
                location,
                "info",
                fingerprint_material,
                summary,
            )
        return changed

    async def save_finding(
        self,
        domain_id: int | None,
        finding_type: str,
        severity: str,
        location: str,
        details: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> int | None:
        assert self.db_pool is not None
        finding_type = strip_postgres_nuls(finding_type) or ""
        severity = strip_postgres_nuls(severity) or ""
        location = strip_postgres_nuls(location) or ""
        details = sanitize_postgres_value(details)
        finding_key = hashlib.sha256(
            f"{domain_id}|{finding_type}|{location}|{json.dumps(details, sort_keys=True)}".encode()
        ).hexdigest()
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO findings (domain_id, finding_key, finding_type, severity, location, details)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                ON CONFLICT (finding_key)
                DO UPDATE SET last_seen = NOW(), is_resolved = FALSE
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                finding_key,
                finding_type,
                severity,
                location,
                postgres_json(details),
            )

        if row and row["inserted"]:
            FINDINGS_FOUND.inc()
            finding_id = int(row["id"])
            self.append_summary(
                summary,
                "findings",
                {"finding_type": finding_type, "severity": severity, "location": location, "details": details},
            )
            await self.record_asset_event(
                domain_id,
                "new_finding",
                "finding",
                finding_id,
                location,
                severity,
                {"finding_type": finding_type, "details": details},
                summary,
            )
            await self.triage_item(
                domain_id,
                "findings",
                finding_id,
                "finding",
                finding_type,
                location,
                {"severity": severity, "finding_type": finding_type, "location": location, "details": details},
                summary,
            )
            evidence_id = await self.create_evidence_pack(
                domain_id,
                "findings",
                finding_id,
                finding_type,
                location,
                severity,
                {"severity": severity, "finding_type": finding_type, "location": location, "details": details},
                f"{severity.upper()} {finding_type} at {location}",
            )
            if severity in {"critical", "high", "medium"} or finding_type.startswith(("nuclei_", "dalfox_")):
                await self.enqueue_validation(
                    domain_id,
                    finding_id,
                    evidence_id,
                    "findings",
                    finding_id,
                    severity if severity in {"critical", "high", "medium"} else "medium",
                    location,
                    self.validation_steps_for_finding(finding_type, severity, details),
                )
            return finding_id
        return None

    def priority_from_score(self, score: int) -> str:
        if score >= 90:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    def priority_rank(self, priority: str) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(priority, 0)

    def analyze_triage_payload(self, item_type: str, location: str, payload: dict[str, Any]) -> dict[str, Any]:
        text = f"{item_type} {location} {json.dumps(payload, default=str)}".lower()
        high_signal_keywords = [str(item).lower() for item in self.config.scan.get("ai_triage_high_signal_keywords", [])]
        noise_finding_types = {
            "api_surface_discovered", "host_fingerprint_changed", "interesting_bruteforce_hit",
            "interesting_exposed_path", "interesting_open_port", "js_asset_changed",
            "js_dom_xss_candidate", "js_dom_xss_sinks", "js_secret_like_strings",
            "js_sensitive_admin_surface", "risky_url_parameter",
        }
        reasons: list[str] = []
        actions: list[str] = []
        profiles: set[str] = {"baseline"}
        score = 0

        severity = str(payload.get("severity") or "").lower()
        finding_type = str(payload.get("finding_type") or item_type or "").lower()
        static_candidate = finding_type in noise_finding_types
        if severity in {"critical", "high", "medium"} and not static_candidate:
            add = {"critical": 90, "high": 70, "medium": 45}[severity]
            score += add
            reasons.append(f"{severity} severity")
            actions.append("validate scanner evidence and impact")
        elif severity in {"critical", "high", "medium"}:
            score += {"critical": 18, "high": 14, "medium": 10}[severity]
            reasons.append("static candidate; impact not validated")

        status_code = payload.get("status_code")
        if status_code in {200, "200"}:
            reasons.append("HTTP 200 observed; not risk by itself")
        elif status_code in {401, 403, "401", "403"}:
            reasons.append("auth-gated surface; not risk by itself")
            profiles.add("auth")

        matched_keywords: list[str] = []
        for keyword in high_signal_keywords:
            if keyword and keyword in text:
                matched_keywords.append(keyword)
                if keyword in {"graphql", "swagger", "openapi", "api"}:
                    profiles.add("api")
                if keyword in {"auth", "login", "sso", "token", "callback", "redirect"}:
                    profiles.add("auth")
                if keyword in {"admin", "internal", "debug", "actuator", "config", "backup"}:
                    actions.append("test authorization and exposure controls")
        if matched_keywords:
            score += min(12, len(matched_keywords) * 3)
            reasons.append("signals:" + ",".join(matched_keywords[:5]))

        risk_tags = payload.get("risk_tags") or []
        if risk_tags:
            score += min(10, 2 + len(risk_tags) * 2)
            reasons.append("risk tags present")
            actions.append("test parameter handling")

        parameters = payload.get("parameters") or []
        if parameters:
            score += 6
            reasons.append("parameters present")
            actions.append("check IDOR, redirect, SSRF, injection, and authz paths")

        source = str(payload.get("source") or "")
        if source == "js_analysis":
            score += 4
            reasons.append("extracted from JavaScript")
            actions.append("trace frontend auth assumptions and hidden API routes")
            profiles.add("api")

        details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
        confidence = str(payload.get("confidence") or details.get("confidence") or "").lower()
        if item_type == "api_surface":
            if confidence == "rejected":
                score = 0
                reasons.append("API surface rejected by protocol verification")
            elif confidence not in {"confirmed", "probable"}:
                score = min(score, 24)
                reasons.append("API surface is candidate-only")
            else:
                score = max(score, 38 if confidence == "confirmed" else 32)
                reasons.append(f"{confidence} API surface")

        if static_candidate:
            score = min(score, 29)

        if "graphql" in text:
            actions.append("check introspection, batching, authz, and mutation access")
            profiles.add("api")
        if any(token in text for token in ("s3", "bucket", "aws", "azure", "gcp")):
            profiles.add("cloud")
            actions.append("check cloud storage permissions and object exposure")

        priority = self.priority_from_score(score)
        return {
            "priority": priority,
            "score": score,
            "reasons": dedupe_list(reasons)[:12],
            "recommended_actions": dedupe_list(actions)[:12],
            "run_profiles": sorted(profiles),
            "alert": self.priority_rank(priority) >= self.priority_rank(str(self.config.scan.get("ai_triage_alert_min_priority", "high"))),
        }

    async def triage_item(
        self,
        domain_id: int | None,
        source_table: str,
        source_id: int,
        item_type: str,
        title: str,
        location: str,
        payload: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.config.scan.get("ai_triage_enabled", True):
            return
        assert self.db_pool is not None
        source_table = strip_postgres_nuls(source_table) or ""
        item_type = strip_postgres_nuls(item_type) or ""
        title = strip_postgres_nuls(title) or ""
        location = strip_postgres_nuls(location) or ""
        payload = sanitize_postgres_value(payload)
        decision = self.analyze_triage_payload(item_type, location, payload)
        item_key = hashlib.sha256(f"{source_table}|{source_id}|{location}".encode()).hexdigest()
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO ai_triage_items (
                  domain_id,
                  source_table,
                  source_id,
                  item_key,
                  item_type,
                  title,
                  location,
                  priority,
                  score,
                  reasons,
                  recommended_actions,
                  run_profiles,
                  alert,
                  payload
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
                ON CONFLICT (item_key)
                DO UPDATE SET
                  last_seen = NOW(),
                  priority = EXCLUDED.priority,
                  score = EXCLUDED.score,
                  reasons = EXCLUDED.reasons,
                  recommended_actions = EXCLUDED.recommended_actions,
                  run_profiles = EXCLUDED.run_profiles,
                  alert = EXCLUDED.alert,
                  payload = EXCLUDED.payload,
                  resolved = FALSE
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                source_table,
                source_id,
                item_key,
                item_type,
                title,
                location,
                decision["priority"],
                int(decision["score"]),
                decision["reasons"],
                decision["recommended_actions"],
                decision["run_profiles"],
                bool(decision["alert"]),
                postgres_json(payload),
            )
        if row and row["inserted"]:
            self.append_summary(
                summary,
                "ai_triage",
                {
                    "priority": decision["priority"],
                    "score": decision["score"],
                    "title": title,
                    "location": location,
                    "reasons": decision["reasons"],
                    "recommended_actions": decision["recommended_actions"],
                },
            )
        if row:
            await self.upsert_asset_risk(domain_id, item_type, int(row["id"]), location, decision)
            await self.enqueue_bug_jobs_for_asset(domain_id, source_table, source_id, item_type, location, payload, decision)

    async def send_alert(
        self,
        alert_type: str,
        message: str,
        payload: dict[str, Any],
        finding_id: int | None = None,
    ) -> None:
        assert self.db_pool is not None
        alert_type = strip_postgres_nuls(alert_type) or ""
        message = strip_postgres_nuls(message) or ""
        payload = sanitize_postgres_value(payload)

        if self.redis_client is not None:
            key = f"alert:{hashlib.sha1(message.encode()).hexdigest()}"
            if self.redis_client.get(key):
                return
            self.redis_client.setex(key, 1800, "1")

        async with self.db_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO alerts (finding_id, alert_type, message, payload) VALUES ($1, $2, $3, $4::jsonb)",
                finding_id,
                alert_type,
                message,
                postgres_json(payload),
            )

        for url in self.config.alerts.get("webhook_urls", []):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    await session.post(url, json={"type": alert_type, "message": message, "payload": payload})
            except Exception as exc:
                logger.warning("Webhook alert failed: %s", exc)

        discord = select_discord_alert_config(
            self.config.alerts,
            alert_type,
            payload,
        )
        if discord.get("enabled") and discord.get("webhook_url"):
            try:
                max_parts = max(1, min(int(discord.get("max_message_parts", 6)), 10))
                delay_seconds = max(0.0, float(discord.get("message_delay_seconds", 1.0)))
                username = str(discord.get("username") or "Recon Framework")[:80]
                discord_payload = dict(payload)
                discord_payload["_discord_preview_limit"] = int(
                    self.config.alerts.get(
                        "first_run_summary_preview_limit" if payload.get("first_run") else "summary_preview_limit",
                        20,
                    )
                )
                embeds = build_discord_alert_embeds(
                    alert_type,
                    message,
                    discord_payload,
                    max_messages=max_parts,
                )
                webhook_url = str(discord["webhook_url"])
                webhook_url = f"{webhook_url}{'&' if '?' in webhook_url else '?'}wait=true"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    for index, embed in enumerate(embeds):
                        async with session.post(
                            webhook_url,
                            json={
                                "embeds": [embed],
                                "username": username,
                                "allowed_mentions": {"parse": []},
                            },
                        ) as response:
                            if response.status >= 400:
                                body = await response.text()
                                logger.warning("Discord alert failed: status=%s body=%s", response.status, body[:300])
                            if index < len(embeds) - 1 and delay_seconds > 0:
                                await asyncio.sleep(delay_seconds)
            except Exception as exc:
                logger.warning("Discord alert failed: %r", exc)

        smtp_cfg = self.config.alerts.get("smtp", {})
        if smtp_cfg.get("enabled"):
            try:
                msg = EmailMessage()
                msg["Subject"] = f"Recon alert: {alert_type}"
                msg["From"] = smtp_cfg["from_email"]
                msg["To"] = ", ".join(smtp_cfg["to_emails"])
                msg.set_content(f"{message}\n\n{json.dumps(payload, indent=2)}")
                with smtplib.SMTP(smtp_cfg["server"], smtp_cfg["port"]) as server:
                    server.starttls()
                    server.login(smtp_cfg["username"], smtp_cfg["password"])
                    server.send_message(msg)
            except Exception as exc:
                logger.warning("SMTP alert failed: %s", exc)

    async def save_url_parameters(
        self,
        domain_id: int,
        endpoint_id: int,
        full_url: str,
        source: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        full_url = strip_postgres_nuls(full_url) or ""
        source = strip_postgres_nuls(source) or ""
        parsed = urlsplit(full_url)
        path = parsed.path or "/"
        parameters = sanitize_postgres_value(extract_query_parameters(full_url))
        if not parameters:
            return

        for item in parameters:
            stored_name = storage_parameter_name(item["name"])
            if stored_name != item["name"]:
                logger.warning(
                    "Bounded oversized query parameter name for endpoint_id=%s: bytes=%s",
                    endpoint_id,
                    len(str(item["name"]).encode("utf-8")),
                )
            async with self.db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO url_parameters (endpoint_id, param_name, example_value, risk_tags)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (endpoint_id, param_name)
                    DO UPDATE SET last_seen = NOW(), example_value = EXCLUDED.example_value, risk_tags = EXCLUDED.risk_tags
                    RETURNING id, (xmax = 0) AS inserted
                    """,
                    endpoint_id,
                    stored_name,
                    strip_postgres_nuls(item["example_value"]) or "",
                    sanitize_postgres_value(item["risk_tags"]),
                )

            if row and row["inserted"] and item["risk_tags"]:
                RISKY_PARAMS_FOUND.inc()
                severity = severity_for_param_tags(item["risk_tags"], item["name"], item["example_value"], path)
                await self.save_finding(
                    domain_id,
                    "risky_url_parameter",
                    severity,
                    full_url,
                    {
                        "parameter": item["name"],
                        "example_value": item["example_value"],
                        "risk_tags": item["risk_tags"],
                        "source": source,
                    },
                    summary,
                )

    async def save_endpoint(
        self,
        domain_id: int,
        live_host_id: int,
        full_url: str,
        source: str,
        summary: dict[str, Any] | None = None,
        status_code: int | None = None,
    ) -> int:
        assert self.db_pool is not None
        full_url = strip_postgres_nuls(full_url) or ""
        source = strip_postgres_nuls(source) or ""
        parsed = urlsplit(full_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        path_hash = hashlib.sha256(path.encode()).hexdigest()
        parameter_payload = sanitize_postgres_value(extract_query_parameters(full_url))
        risk_tags = sorted({tag for item in parameter_payload for tag in item["risk_tags"]})
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO endpoints (live_host_id, path, path_hash, method, status_code, probed_at, parameters, risk_tags, source)
                VALUES ($1, $2, $3, 'GET', $4, CASE WHEN $4::int IS NULL THEN NULL ELSE NOW() END, $5::jsonb, $6, $7)
                ON CONFLICT (live_host_id, path_hash, method, source)
                DO UPDATE SET
                  last_seen = NOW(),
                  status_code = COALESCE(EXCLUDED.status_code, endpoints.status_code),
                  probed_at = COALESCE(EXCLUDED.probed_at, endpoints.probed_at),
                  parameters = EXCLUDED.parameters,
                  risk_tags = EXCLUDED.risk_tags
                RETURNING id, (xmax = 0) AS inserted
                """,
                live_host_id,
                path,
                path_hash,
                status_code,
                postgres_json(parameter_payload),
                risk_tags,
                source,
            )

        endpoint_id = int(row["id"])
        await self.detect_cloud_asset(domain_id, full_url, source)
        await self.save_url_parameters(domain_id, endpoint_id, full_url, source, summary)

        if row and row["inserted"]:
            ENDPOINTS_FOUND.inc()
            self.append_summary(summary, "new_urls", {"url": full_url, "source": source, "risk_tags": risk_tags})
            event_severity = "info"
            lowered = full_url.lower()
            if any(token in lowered for token in ("graphql", "swagger", "openapi", "graphiql")):
                event_severity = "medium" if status_code in {200, 401, 403} else "info"
            if any(token in lowered for token in ("graphql", "graphiql")):
                graphql_confidence = "rejected" if status_code == 404 else "candidate"
                graphql_flags = ["graphql_candidate", graphql_confidence]
                if status_code in {401, 403}:
                    graphql_flags.append("auth_required")
                await self.save_api_surface(
                    domain_id,
                    live_host_id,
                    "graphql",
                    full_url,
                    source,
                    status_code,
                    auth_required=status_code in {401, 403},
                    risk_flags=graphql_flags,
                    metadata={"endpoint_id": endpoint_id, "confidence": graphql_confidence, "verified": False},
                    summary=summary,
                )
            elif any(token in lowered for token in ("swagger", "openapi", "api-docs", "redoc")):
                await self.save_api_surface(
                    domain_id,
                    live_host_id,
                    "api_docs",
                    full_url,
                    source,
                    status_code,
                    auth_required=status_code in {401, 403},
                    risk_flags=["api_docs"],
                    metadata={"endpoint_id": endpoint_id},
                    summary=summary,
                )
            await self.record_asset_event(
                domain_id,
                "new_endpoint",
                "endpoint",
                endpoint_id,
                full_url,
                event_severity,
                {"source": source, "status_code": status_code, "risk_tags": risk_tags},
                summary,
            )
            await self.triage_item(
                domain_id,
                "endpoints",
                endpoint_id,
                "endpoint",
                path,
                full_url,
                {
                    "url": full_url,
                    "path": path,
                    "source": source,
                    "status_code": status_code,
                    "parameters": parameter_payload,
                    "risk_tags": risk_tags,
                },
                summary,
            )
            if event_severity == "medium":
                await self.save_finding(
                    domain_id,
                    "api_surface_discovered",
                    "info",
                    full_url,
                    {"source": source, "status_code": status_code, "risk_tags": risk_tags},
                    summary,
                )
        return endpoint_id

    async def save_endpoint_js_reference(self, endpoint_id: int, js_asset_id: int, found_value: str) -> None:
        assert self.db_pool is not None
        found_value = strip_postgres_nuls(found_value) or ""
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO endpoint_js_references (endpoint_id, js_asset_id, found_value)
                VALUES ($1, $2, $3)
                ON CONFLICT (endpoint_id, js_asset_id)
                DO UPDATE SET last_seen = NOW(), found_value = EXCLUDED.found_value
                """,
                endpoint_id,
                js_asset_id,
                found_value,
            )

    async def probe_url_status(self, session: aiohttp.ClientSession, url: str, domain_info: dict[str, Any] | None = None) -> int | None:
        try:
            async with session.head(url, allow_redirects=True, headers=self.authenticated_headers(url, domain_info)) as response:
                if response.status not in {405, 501}:
                    return response.status
        except Exception:
            pass
        try:
            async with session.get(url, allow_redirects=True, headers=self.authenticated_headers(url, domain_info)) as response:
                return response.status
        except Exception:
            return None

    async def probe_url_statuses(self, urls: list[str], domain_info: dict[str, Any] | None = None) -> dict[str, int | None]:
        if not urls:
            return {}
        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        concurrency = int(self.config.scan.get("url_status_probe_concurrency", 10))
        semaphore = asyncio.Semaphore(max(1, concurrency))
        results: dict[str, int | None] = {}

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async def worker(url: str) -> None:
                async with semaphore:
                    results[url] = await self.probe_url_status(session, url, domain_info)

            await asyncio.gather(*(worker(url) for url in urls))
        return results

    async def discover_wayback_urls(self, hostname: str, limit: int) -> list[str]:
        wayback_binary = self.config.tools.get("waybackurls", "waybackurls")
        timeout_seconds = max(10.0, float(self.config.scan.get("wayback_timeout_seconds", 45)))
        async with self.archive_semaphore:
            result = await self.run_tool_result(
                wayback_binary,
                stdin_text=f"{hostname}\n",
                capture_output_files=True,
                timeout_seconds=timeout_seconds,
            )
        if result.timed_out:
            logger.info("Wayback URL discovery timed out for %s after %.0fs", hostname, timeout_seconds)
            return []
        urls: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)
        return urls[:limit]

    async def discover_gau_urls(self, hostname: str, limit: int) -> list[str]:
        gau_binary = self.config.tools.get("gau", "gau")
        configured = self.config.scan.get("gau_providers", ["urlscan", "otx", "commoncrawl"])
        if isinstance(configured, str):
            providers = [item.strip() for item in configured.split(",") if item.strip()]
        else:
            providers = [str(item).strip() for item in configured if str(item).strip()]
        providers = dedupe_list(providers) or ["urlscan"]
        timeout_seconds = max(10.0, float(self.config.scan.get("gau_provider_timeout_seconds", 45)))
        client_timeout = max(5, int(self.config.scan.get("gau_http_timeout_seconds", 25)))

        async def fetch_provider(provider: str) -> tuple[str, ToolRunResult]:
            async with self.archive_semaphore:
                result = await self.run_tool_result(
                    gau_binary,
                    "--threads",
                    "1",
                    "--timeout",
                    str(client_timeout),
                    "--providers",
                    provider,
                    hostname,
                    capture_output_files=True,
                    timeout_seconds=timeout_seconds,
                )
            return provider, result

        provider_results = await asyncio.gather(*(fetch_provider(provider) for provider in providers))
        urls: list[str] = []
        for provider, result in provider_results:
            provider_urls = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip().startswith(("http://", "https://"))
            ]
            if result.timed_out:
                logger.info("GAU provider %s timed out for %s after %.0fs", provider, hostname, timeout_seconds)
            elif result.returncode not in (0, 1, None):
                logger.info("GAU provider %s failed for %s with code %s", provider, hostname, result.returncode)
            elif provider_urls:
                logger.info("GAU provider %s returned %s URL(s) for %s", provider, len(provider_urls), hostname)
            urls.extend(provider_urls)
        return dedupe_list(urls)[:limit]

    async def discover_katana_urls(self, domain_info: dict[str, Any], url: str, limit: int) -> list[str]:
        katana_binary = self.config.tools.get("katana", "katana")
        args = [
            katana_binary,
            "-u",
            url,
            "-d",
            str(self.config.scan.get("katana_depth", 1)),
            "-fs",
            "fqdn",
            "-c",
            str(max(1, int(self.config.scan.get("katana_concurrency", 2)))),
            "-p",
            "1",
            "-rl",
            str(max(1, int(self.config.scan.get("katana_rate_limit", 2)))),
            "-ct",
            str(self.config.scan.get("katana_crawl_duration", "45s")),
            "-timeout",
            str(max(1, int(self.config.scan.get("http_timeout_seconds", 15)))),
            "-silent",
        ]
        if self.config.scan.get("katana_js_crawl", True):
            args.append("-jc")
        if self.config.scan.get("katana_jsonl", True):
            args.extend(["-j", "-or", "-ob"])
            if self.config.scan.get("katana_form_extraction", True):
                args.append("-fx")
        header_path = self.create_header_file(self.authenticated_header_lines(domain_info, url))
        if header_path:
            args.extend(["-H", header_path])
        try:
            stdout = await self.run_tool(*args, capture_output_files=True)
        finally:
            if header_path:
                Path(header_path).unlink(missing_ok=True)
        return extract_katana_urls(stdout, url)[:limit]

    async def discover_hakrawler_urls(self, domain_info: dict[str, Any], url: str, limit: int) -> list[str]:
        hakrawler_binary = self.config.tools.get("hakrawler", "hakrawler")
        args = [
            hakrawler_binary,
            "-d",
            "1",
            "-u",
            "-t",
            str(max(1, int(self.config.scan.get("hakrawler_threads", 1)))),
            "-timeout",
            str(max(5, int(self.config.scan.get("hakrawler_timeout_seconds", 45)))),
            "-size",
            str(max(1, int(self.config.scan.get("hakrawler_max_page_size_kb", 2048)))),
        ]
        stdout = await self.run_tool(
            *args,
            stdin_text=f"{url}\n",
            capture_output_files=True,
        )
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)
        return urls[:limit]

    async def fetch_text_url(self, url: str, max_bytes: int = 2_000_000, domain_info: dict[str, Any] | None = None) -> tuple[int | None, str]:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True, headers=self.authenticated_headers(url, domain_info)) as response:
                    body = await response.content.read(max_bytes + 1)
                    if len(body) > max_bytes:
                        return response.status, ""
                    return response.status, body.decode("utf-8", errors="ignore")
        except Exception:
            return None, ""

    def parse_sitemap_urls(self, base_url: str, text: str) -> tuple[list[str], list[str]]:
        urls: list[str] = []
        sitemap_urls: list[str] = []
        try:
            root = ET.fromstring(text.strip())
        except ET.ParseError:
            return urls, sitemap_urls

        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1].lower() != "loc" or not element.text:
                continue
            loc = urljoin(base_url, element.text.strip())
            if loc.lower().endswith(".xml") or "sitemap" in loc.lower():
                sitemap_urls.append(loc)
            elif loc.startswith(("http://", "https://")):
                urls.append(loc)
        return urls, sitemap_urls

    async def discover_robots_sitemap_urls(self, domain_info: dict[str, Any], base_url: str) -> list[str]:
        if not self.config.scan.get("robots_sitemap_discovery_enabled", True):
            return []

        max_sitemap_urls = int(self.config.scan.get("max_sitemap_urls_per_host", 200))
        max_sitemap_files = int(self.config.scan.get("max_sitemap_files_per_host", 5))
        discovered: list[str] = []
        sitemap_queue: list[str] = [urljoin(base_url.rstrip("/") + "/", "sitemap.xml")]

        robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
        status, robots_text = await self.fetch_text_url(robots_url, max_bytes=500_000, domain_info=domain_info)
        if status and status < 500 and robots_text:
            for raw_line in robots_text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                if not value:
                    continue
                if key == "sitemap":
                    sitemap_queue.append(urljoin(base_url, value))
                elif key in {"allow", "disallow"} and value != "/" and not any(ch in value for ch in "*$"):
                    discovered.append(urljoin(base_url.rstrip("/") + "/", value.lstrip("/")))

        seen_sitemaps: set[str] = set()
        while sitemap_queue and len(seen_sitemaps) < max_sitemap_files and len(discovered) < max_sitemap_urls:
            sitemap_url = sitemap_queue.pop(0)
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)
            status, sitemap_text = await self.fetch_text_url(sitemap_url, max_bytes=2_000_000, domain_info=domain_info)
            if not status or status >= 500 or not sitemap_text:
                continue
            urls, nested_sitemaps = self.parse_sitemap_urls(base_url, sitemap_text)
            discovered.extend(urls)
            for nested in nested_sitemaps:
                if nested not in seen_sitemaps and len(sitemap_queue) < max_sitemap_files:
                    sitemap_queue.append(nested)

        return [url for url in dedupe_list(discovered) if url.startswith(("http://", "https://"))][:max_sitemap_urls]

    async def discover_urls_for_host(self, domain_info: dict[str, Any], live_host: dict[str, Any]) -> list[str]:
        hostname = urlsplit(live_host["url"]).hostname or live_host["url"]
        max_wayback = self.domain_int(domain_info, "max_wayback_urls", int(self.config.scan["max_wayback_urls_per_host"]))
        max_urls = int(self.config.scan.get("max_discovered_urls_per_host", 500))
        tasks = [self.discover_wayback_urls(hostname, max_wayback)]
        if self.domain_bool(domain_info, "enable_gau", self.config.scan.get("enable_gau", True)):
            tasks.append(self.discover_gau_urls(hostname, int(self.config.scan.get("gau_max_urls_per_host", 200))))
        if self.domain_bool(domain_info, "enable_katana", self.config.scan.get("enable_katana", True)):
            tasks.append(self.discover_katana_urls(domain_info, live_host["url"], int(self.config.scan.get("katana_max_urls_per_host", 100))))
        if self.domain_bool(domain_info, "enable_hakrawler", self.config.scan.get("enable_hakrawler", True)):
            tasks.append(self.discover_hakrawler_urls(domain_info, live_host["url"], int(self.config.scan.get("hakrawler_max_urls_per_host", 100))))
        if self.config.scan.get("robots_sitemap_discovery_enabled", True):
            tasks.append(self.discover_robots_sitemap_urls(domain_info, live_host["url"]))

        discovered: list[str] = []
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, Exception):
                continue
            discovered.extend(result)

        deduped: list[str] = []
        seen = set()
        for item in discovered:
            if not self.is_target_or_explicitly_allowed_url(domain_info, item):
                continue
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped[:max_urls]

    async def fetch_html(self, url: str, domain_info: dict[str, Any] | None = None) -> str:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True, headers=self.authenticated_headers(url, domain_info)) as response:
                    content_type = response.headers.get("content-type", "").lower()
                    if response.status >= 400 or "html" not in content_type:
                        return ""
                    return await response.text(errors="ignore")
        except Exception:
            return ""

    async def download_js(self, asset_url: str, domain_info: dict[str, Any] | None = None) -> tuple[int | None, bytes | None]:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["js_download_timeout_seconds"])
        max_bytes = int(self.config.scan["js_max_download_bytes"])
        max_redirects = max(0, int(self.config.scan.get("js_redirect_limit", 3)))
        current_url = asset_url
        if domain_info and not self.is_target_or_explicitly_allowed_url(domain_info, current_url):
            return None, None
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for redirect_count in range(max_redirects + 1):
                    async with session.get(
                        current_url,
                        allow_redirects=False,
                        headers=self.authenticated_headers(current_url, domain_info),
                    ) as response:
                        if response.status in {301, 302, 303, 307, 308} and response.headers.get("location"):
                            if redirect_count >= max_redirects:
                                logger.info("Skipping JS asset after redirect limit: %s", asset_url)
                                return response.status, None
                            next_url = urljoin(current_url, response.headers["location"])
                            if urlsplit(current_url).scheme == "https" and urlsplit(next_url).scheme == "http":
                                logger.info("Blocking HTTPS downgrade while fetching JS asset: %s", asset_url)
                                return response.status, None
                            if domain_info and not self.is_target_or_explicitly_allowed_url(domain_info, next_url):
                                logger.info("Blocking out-of-scope JS redirect: %s", asset_url)
                                return response.status, None
                            current_url = next_url
                            continue

                        body = await response.content.read(max_bytes + 1)
                        if len(body) > max_bytes:
                            logger.info("Skipping oversized JS asset: %s", asset_url)
                            return response.status, None
                        return response.status, body
                return None, None
        except Exception:
            return None, None

    async def store_js_analysis(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        js_asset_id: int,
        asset_url: str,
        source_text: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        domain_id = int(domain_info["id"])
        signals = extract_js_signals(source_text)
        risk_summary = {
            "api_url_count": len(signals["api_urls"]),
            "endpoint_path_count": len(signals["endpoint_paths"]),
            "graphql_hint_count": len(signals["graphql_hints"]),
            "graphql_operation_count": len(signals["graphql_operations"]),
            "graphql_persisted_query_count": len(signals["graphql_persisted_query_hashes"]),
            "graphql_websocket_count": len(signals["graphql_websocket_urls"]),
            "auth_keyword_count": len(signals["auth_related_keywords"]),
            "dom_sink_count": len(signals["dangerous_dom_sinks"]),
            "location_source_count": len(signals["location_sources"]),
            "postmessage_count": len(signals["postmessage_usage"]),
            "dom_source_sink_proximity_count": int(signals["dom_source_sink_proximity_count"]),
            "postmessage_receiver_count": int(signals["postmessage_receiver_count"]),
            "postmessage_data_flow_count": int(signals["postmessage_data_flow_count"]),
            "postmessage_sensitive_effect_count": int(signals["postmessage_sensitive_effect_count"]),
            "storage_count": len(signals["storage_usage"]),
            "fetch_xhr_count": len(signals["fetch_xhr_usage"]),
        }
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO js_analysis_results (js_asset_id, extraction, risk_summary, analyzed_at)
                VALUES ($1, $2::jsonb, $3::jsonb, NOW())
                ON CONFLICT (js_asset_id)
                DO UPDATE SET extraction = EXCLUDED.extraction, risk_summary = EXCLUDED.risk_summary, analyzed_at = NOW()
                """,
                js_asset_id,
                json.dumps(signals),
                json.dumps(risk_summary),
            )
            js_sha256 = str(
                await conn.fetchval("SELECT sha256 FROM js_assets WHERE id = $1", js_asset_id) or ""
            )

        has_dom_flow = bool(risk_summary["dom_source_sink_proximity_count"])
        has_message_flow = bool(
            risk_summary["postmessage_data_flow_count"]
            and risk_summary["postmessage_sensitive_effect_count"]
        )
        scan_lane = str((summary or {}).get("scan_lane") or "").strip().lower()
        is_delta_scan = bool(
            summary
            and summary.get("first_run") is False
            and scan_lane in {"fast_delta", "deep_scan"}
        )
        if is_delta_scan and (has_dom_flow or has_message_flow):
            await self.enqueue_bug_job(
                domain_id=domain_id,
                source_table="js_assets",
                source_id=js_asset_id,
                asset_type="js_asset",
                asset_value=asset_url,
                job_type="js_dom_xss_review",
                priority=99 if has_dom_flow else 98,
                hypothesis=(
                    "Bounded location-source to executable DOM-sink relationship requires runtime validation"
                    if has_dom_flow
                    else "Bounded message-data to security-sensitive-effect relationship requires origin and impact validation"
                ),
                required_context={
                    "payload": {"asset_url": asset_url, "http_status": 200, "sha256": js_sha256, "source": "js_analysis_dataflow"},
                    "javascript_sha256": js_sha256,
                    "deterministic_js_flow": True,
                    "bug_job_high_signal_reasons": [
                        "bounded-dom-source-sink" if has_dom_flow else "bounded-postmessage-sensitive-effect"
                    ],
                },
                safety_notes=[
                    "validate only the exact current JavaScript body and owning first-party route",
                    "static proximity is a lead, not proof of exploitability",
                ],
            )

        raw_endpoints = dedupe_list(
            signals["api_urls"]
            + signals["endpoint_paths"]
            + signals["graphql_client_endpoints"]
        )
        endpoint_pairs = []
        for endpoint in raw_endpoints:
            target = endpoint if endpoint.startswith(("http://", "https://")) else urljoin(asset_url, endpoint)
            if self.is_target_or_explicitly_allowed_url(domain_info, target):
                endpoint_pairs.append((endpoint, target))
        endpoint_targets = [target for _, target in endpoint_pairs]
        endpoint_statuses: dict[str, int | None] = {}
        if self.config.scan.get("probe_discovered_url_status", True):
            endpoint_statuses = await self.probe_url_statuses(endpoint_targets, domain_info)
        graphql_client_targets = {
            endpoint if endpoint.startswith(("http://", "https://")) else urljoin(asset_url, endpoint)
            for endpoint in signals["graphql_client_endpoints"]
            if self.is_target_or_explicitly_allowed_url(
                domain_info,
                endpoint if endpoint.startswith(("http://", "https://")) else urljoin(asset_url, endpoint),
            )
        }
        graphql_metadata = {
            "js_asset_id": js_asset_id,
            "js_asset_url": asset_url,
            "operations": signals["graphql_operations"][:100],
            "operations_count": len(signals["graphql_operations"]),
            "anonymous_operation_count": len(signals["graphql_anonymous_operations"]),
            "persisted_query_hashes": signals["graphql_persisted_query_hashes"][:50],
        }
        max_graphql_verifications = int(
            self.config.scan.get("graphql_max_verifications_per_js_asset", 10)
        )
        graphql_verifications = 0
        for raw_endpoint, target in endpoint_pairs:
            endpoint_id = await self.save_endpoint(domain_id, live_host_id, target, "js_analysis", summary, endpoint_statuses.get(target))
            await self.save_endpoint_js_reference(endpoint_id, js_asset_id, raw_endpoint)
            if (
                graphql_verifications < max_graphql_verifications
                and (is_graphql_candidate_url(target) or target in graphql_client_targets)
            ):
                await self.verify_graphql_endpoint(
                    domain_info,
                    live_host_id,
                    target,
                    "js_analysis",
                    endpoint_statuses.get(target),
                    summary,
                    graphql_metadata,
                )
                graphql_verifications += 1

        for websocket_url in signals["graphql_websocket_urls"]:
            target = urljoin(asset_url, websocket_url)
            if not self.is_target_or_explicitly_allowed_url(domain_info, target):
                continue
            await self.save_api_surface(
                domain_id,
                live_host_id,
                "graphql",
                target,
                "js_analysis",
                methods=["WEBSOCKET"],
                operations_count=len(signals["graphql_operations"]),
                risk_flags=["graphql", "probable", "subscription"],
                metadata={
                    **graphql_metadata,
                    "confidence": "probable",
                    "verified": False,
                    "transport": "websocket",
                },
                summary=summary,
            )

        for finding in severity_for_js_signals(signals):
            await self.save_finding(
                domain_id,
                finding["finding_type"],
                finding["severity"],
                asset_url,
                finding["details"],
                summary,
            )

    def sanitize_trufflehog_result(self, finding: dict[str, Any]) -> dict[str, Any]:
        cleaned = sanitize_postgres_value(finding)
        if not isinstance(cleaned, dict):
            return {}
        for key in ("Raw", "RawV2"):
            cleaned.pop(key, None)
        if cleaned.get("Redacted"):
            cleaned["Redacted"] = redact_secret(str(cleaned["Redacted"]))
        return cleaned

    @staticmethod
    def trufflehog_source_location(finding: dict[str, Any]) -> tuple[str | None, int | None]:
        data = (((finding.get("SourceMetadata") or {}).get("Data") or {}))
        for value in data.values():
            if not isinstance(value, dict):
                continue
            source_file = value.get("file") or value.get("File") or value.get("path") or value.get("Path")
            line = value.get("line") or value.get("Line")
            try:
                return str(source_file) if source_file else None, int(line) if line is not None else None
            except (TypeError, ValueError):
                return str(source_file) if source_file else None, None
        return None, None

    async def store_credential_leak(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        js_asset_id: int,
        asset_url: str,
        finding: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        domain_id = int(domain_info["id"])
        detector_name = str(finding.get("DetectorName") or finding.get("DetectorType") or "unknown")
        detector_type = str(finding.get("DetectorType") or "") or None
        decoder_name = str(finding.get("DecoderName") or "") or None
        raw_value = str(finding.get("Raw") or finding.get("RawV2") or "")
        redacted = redact_secret(str(finding.get("Redacted") or raw_value or ""))
        fingerprint_material = raw_value or json.dumps(finding, sort_keys=True, default=str)
        fingerprint = hashlib.sha256(fingerprint_material.encode()).hexdigest()
        raw_sha256 = hashlib.sha256(raw_value.encode()).hexdigest() if raw_value else None
        source_file, line_number = self.trufflehog_source_location(finding)
        clean_result = self.sanitize_trufflehog_result(finding)
        verified = bool(finding.get("Verified"))

        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO credential_leaks (
                  domain_id, live_host_id, js_asset_id, detector_name, detector_type, decoder_name,
                  source_type, source_url, source_file, line_number, verified, redacted_secret,
                  fingerprint, raw_sha256, result
                )
                VALUES ($1, $2, $3, $4, $5, $6, 'js_asset', $7, $8, $9, $10, $11, $12, $13, $14::jsonb)
                ON CONFLICT (domain_id, source_url, detector_name, fingerprint)
                DO UPDATE SET
                  live_host_id = EXCLUDED.live_host_id,
                  js_asset_id = EXCLUDED.js_asset_id,
                  detector_type = EXCLUDED.detector_type,
                  decoder_name = EXCLUDED.decoder_name,
                  source_file = EXCLUDED.source_file,
                  line_number = EXCLUDED.line_number,
                  verified = EXCLUDED.verified,
                  redacted_secret = EXCLUDED.redacted_secret,
                  raw_sha256 = EXCLUDED.raw_sha256,
                  result = EXCLUDED.result,
                  last_seen = NOW(),
                  is_resolved = FALSE
                RETURNING id, (xmax = 0) AS inserted
                """,
                domain_id,
                live_host_id,
                js_asset_id,
                detector_name,
                detector_type,
                decoder_name,
                asset_url,
                source_file,
                line_number,
                verified,
                redacted,
                fingerprint,
                raw_sha256,
                postgres_json(clean_result),
            )

        if row and row["inserted"]:
            severity = "high" if verified else "medium"
            self.append_summary(
                summary,
                "credential_leaks",
                {
                    "detector_name": detector_name,
                    "verified": verified,
                    "source_url": asset_url,
                    "redacted_secret": redacted,
                },
            )
            await self.record_asset_event(
                domain_id,
                "credential_leak_candidate",
                "credential_leak",
                int(row["id"]),
                asset_url,
                severity,
                {
                    "detector_name": detector_name,
                    "verified": verified,
                    "source_file": source_file,
                    "line_number": line_number,
                },
                summary,
            )
            await self.triage_item(
                domain_id,
                "credential_leaks",
                int(row["id"]),
                "credential_leak",
                detector_name,
                asset_url,
                {
                    "detector_name": detector_name,
                    "verified": verified,
                    "redacted_secret": redacted,
                    "source_file": source_file,
                    "line_number": line_number,
                },
                summary,
            )
            if verified:
                await self.save_finding(
                    domain_id,
                    "trufflehog_verified_credential_leak",
                    "high",
                    asset_url,
                    {
                        "detector_name": detector_name,
                        "redacted_secret": redacted,
                        "source_file": source_file,
                        "line_number": line_number,
                        "raw_sha256": raw_sha256,
                    },
                    summary,
                )

    async def scan_js_with_trufflehog(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        js_asset_id: int,
        asset_url: str,
        body: bytes,
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.domain_bool(domain_info, "trufflehog_enabled", self.config.scan.get("trufflehog_enabled", True)):
            return
        trufflehog_binary = self.config.tools.get("trufflehog", "trufflehog")
        if shutil.which(trufflehog_binary) is None:
            logger.info("Skipping missing tool: %s", trufflehog_binary)
            return

        suffix = ".js"
        parsed_path = urlsplit(asset_url).path.lower()
        if parsed_path.endswith(".map"):
            suffix = ".map"
        elif parsed_path.endswith(".json"):
            suffix = ".json"

        with tempfile.TemporaryDirectory(prefix="recon-trufflehog-") as tmpdir:
            tmp_path = Path(tmpdir) / f"asset-{hashlib.sha256(asset_url.encode()).hexdigest()[:16]}{suffix}"
            tmp_path.write_bytes(body)
            args = [
                trufflehog_binary,
                "filesystem",
                "--json",
                f"--results={self.config.scan.get('trufflehog_results', 'verified,unknown')}",
            ]
            if not self.config.scan.get("trufflehog_verify", False):
                args.append("--no-verification")
            args.append(str(tmp_path))
            stdout = await self.run_tool(
                *args,
                log_args=[trufflehog_binary, "filesystem", "--json", "--results=<configured>", "--no-verification", "<js-asset>"],
                capture_output_files=True,
                timeout_seconds=float(self.config.scan.get("trufflehog_timeout_seconds", 90)),
            )

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(finding, dict):
                continue
            await self.store_credential_leak(domain_info, live_host_id, js_asset_id, asset_url, finding, summary)

    async def save_js_asset(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        asset_url: str,
        source: str,
        summary: dict[str, Any] | None = None,
        recursion_depth: int = 0,
        seen_js_urls: set[str] | None = None,
    ) -> int | None:
        assert self.db_pool is not None
        if seen_js_urls is None:
            seen_js_urls = set()
        if asset_url in seen_js_urls:
            return None
        seen_js_urls.add(asset_url)
        if not self.is_target_or_explicitly_allowed_url(domain_info, asset_url):
            return None

        http_status, body = await self.download_js(asset_url, domain_info)
        sha256 = hashlib.sha256(body).hexdigest() if body is not None else None
        size_bytes = len(body) if body is not None else None

        async with self.db_pool.acquire() as conn:
            existing = await conn.fetchrow(
                """
                SELECT ja.id, ja.sha256, jar.id AS analysis_id
                FROM js_assets ja
                LEFT JOIN js_analysis_results jar ON jar.js_asset_id = ja.id
                WHERE ja.live_host_id = $1 AND ja.asset_url = $2
                """,
                live_host_id,
                asset_url,
            )
            row = await conn.fetchrow(
                """
                INSERT INTO js_assets (live_host_id, asset_url, source, sha256, size_bytes, http_status)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (live_host_id, asset_url)
                DO UPDATE SET last_seen = NOW(), sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes, http_status = EXCLUDED.http_status
                RETURNING id, (xmax = 0) AS inserted
                """,
                live_host_id,
                asset_url,
                source,
                sha256,
                size_bytes,
                http_status,
            )

        is_new = bool(row and row["inserted"])
        is_changed = bool(body is not None and existing is not None and existing["sha256"] not in (None, sha256) and sha256 is not None)
        scan_lane = str((summary or {}).get("scan_lane") or "").strip().lower()
        first_run = (summary or {}).get("first_run")
        is_delta_scan = bool(
            first_run is False and scan_lane in {"fast_delta", "deep_scan"}
        )

        if is_new:
            JS_ASSETS_FOUND.inc()
            self.append_summary(summary, "new_js_assets", {"asset_url": asset_url, "source": source, "sha256": sha256})
            await self.detect_cloud_asset(domain_info["id"], asset_url, "js_asset")
            await self.record_asset_event(
                domain_info["id"],
                "new_js_asset",
                "js_asset",
                int(row["id"]),
                asset_url,
                "info",
                {"source": source, "sha256": sha256, "http_status": http_status, "size_bytes": size_bytes},
                summary,
            )
            await self.triage_item(
                domain_info["id"],
                "js_assets",
                int(row["id"]),
                "js_asset",
                asset_url.rsplit("/", 1)[-1] or asset_url,
                asset_url,
                {
                    "asset_url": asset_url,
                    "source": source,
                    "sha256": sha256,
                    "http_status": http_status,
                    "size_bytes": size_bytes,
                    "is_new": True,
                    "is_changed": False,
                    "first_run": first_run,
                    "scan_lane": scan_lane,
                    "is_delta_scan": is_delta_scan,
                    "source_observed_at": datetime.now(timezone.utc).isoformat(),
                },
                summary,
            )
        elif is_changed:
            self.append_summary(summary, "changed_js_assets", {"asset_url": asset_url, "source": source, "sha256": sha256})
            await self.record_asset_event(
                domain_info["id"],
                "js_asset_changed",
                "js_asset",
                int(row["id"]),
                asset_url,
                "info",
                {"source": source, "sha256": sha256, "http_status": http_status, "size_bytes": size_bytes},
                summary,
            )
            await self.save_finding(
                domain_info["id"],
                "js_asset_changed",
                "info",
                asset_url,
                {"source": source, "sha256": sha256},
                summary,
            )
            await self.triage_item(
                domain_info["id"],
                "js_assets",
                int(row["id"]),
                "js_asset",
                asset_url.rsplit("/", 1)[-1] or asset_url,
                asset_url,
                {
                    "asset_url": asset_url,
                    "source": source,
                    "sha256": sha256,
                    "http_status": http_status,
                    "size_bytes": size_bytes,
                    "is_new": False,
                    "is_changed": True,
                    "first_run": first_run,
                    "scan_lane": scan_lane,
                    "is_delta_scan": is_delta_scan,
                    "source_observed_at": datetime.now(timezone.utc).isoformat(),
                },
                summary,
            )

        should_analyze = bool(
            body is not None
            and self.domain_bool(domain_info, "enable_js_analysis", self.config.scan.get("analyze_js_assets", True))
            and (is_new or is_changed or existing is None or existing["analysis_id"] is None)
        )
        if should_analyze:
            try:
                source_text = body.decode("utf-8", errors="ignore")
                if self.config.scan.get("js_source_maps_enabled", True):
                    source_text = await self.build_js_analysis_text(domain_info, asset_url, source_text)
                await self.store_js_analysis(
                    domain_info,
                    live_host_id,
                    int(row["id"]),
                    asset_url,
                    source_text,
                    summary,
                )
            except Exception as exc:
                logger.warning("JS analysis failed for %s: %s", asset_url, exc)

        if body is not None and (is_new or is_changed):
            try:
                await self.scan_js_with_trufflehog(
                    domain_info,
                    live_host_id,
                    int(row["id"]),
                    asset_url,
                    body,
                    summary,
                )
            except Exception as exc:
                logger.warning("TruffleHog scan failed for %s: %s", asset_url, exc)

        if body is not None and self.config.scan.get("js_recursive_discovery_enabled", True):
            max_depth = int(self.config.scan.get("js_recursive_depth", 1))
            if recursion_depth < max_depth:
                source_text = body.decode("utf-8", errors="ignore")
                try:
                    nested_urls = extract_js_urls_from_text(asset_url, source_text)
                except (TypeError, ValueError) as exc:
                    logger.warning("Skipping malformed nested JS URL in %s: %s", asset_url, exc)
                    nested_urls = []
                for nested_url in nested_urls:
                    await self.save_js_asset(
                        domain_info,
                        live_host_id,
                        nested_url,
                        "js_recursive",
                        summary,
                        recursion_depth + 1,
                        seen_js_urls,
                    )

        return int(row["id"]) if row else None

    async def build_js_analysis_text(self, domain_info: dict[str, Any], asset_url: str, source_text: str) -> str:
        source_map_texts: list[str] = []
        max_maps = int(self.config.scan.get("js_source_map_max_per_asset", 3))
        for source_map_url in extract_source_map_urls_from_js(asset_url, source_text)[:max_maps]:
            if not self.is_target_or_explicitly_allowed_url(domain_info, source_map_url):
                continue
            status, body = await self.download_js(source_map_url, domain_info)
            if status and status >= 400:
                continue
            if body is None:
                continue
            extracted = extract_text_from_source_map(body.decode("utf-8", errors="ignore"))
            if extracted:
                source_map_texts.append(extracted)
        if not source_map_texts:
            return source_text
        return source_text + "\n" + "\n".join(source_map_texts)

    async def save_screenshot_record(
        self,
        domain_info: dict[str, Any],
        live_host_id: int,
        url: str,
        screenshot_path: Path,
        capture_reason: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        assert self.db_pool is not None
        try:
            if not screenshot_path.is_file():
                return
            data = screenshot_path.read_bytes()
        except OSError as exc:
            logger.warning("Screenshot disappeared before persistence for %s: %s", url, exc)
            return
        sha256 = hashlib.sha256(data).hexdigest()
        relative_path = str(screenshot_path.relative_to(SCREENSHOT_ROOT))
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO screenshots (live_host_id, screenshot_path, sha256, file_size, capture_reason)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (live_host_id, screenshot_path)
                DO UPDATE SET last_seen = NOW(), sha256 = EXCLUDED.sha256, file_size = EXCLUDED.file_size, capture_reason = EXCLUDED.capture_reason
                RETURNING id, (xmax = 0) AS inserted
                """,
                live_host_id,
                relative_path,
                sha256,
                len(data),
                capture_reason,
            )
        if row and row["inserted"]:
            SCREENSHOTS_CAPTURED.inc()
            self.append_summary(summary, "new_screenshots", {"url": url, "screenshot_path": relative_path})
            await self.record_asset_event(
                domain_info["id"],
                "new_screenshot",
                "screenshot",
                int(row["id"]),
                url,
                "info",
                {"screenshot_path": relative_path, "sha256": sha256, "capture_reason": capture_reason},
                summary,
            )

    async def capture_screenshot(
        self,
        domain_info: dict[str, Any],
        live_host: dict[str, Any],
        capture_reason: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.domain_bool(domain_info, "enable_screenshots", self.config.scan.get("screenshots_enabled", True)):
            return

        gowitness_binary = self.config.tools.get("gowitness", "gowitness")
        target_url = live_host["url"]
        destination = SCREENSHOT_ROOT / domain_slug(domain_info["domain"])
        destination.mkdir(parents=True, exist_ok=True)
        filename = screenshot_filename(target_url)
        final_path = destination / filename
        try:
            with tempfile.TemporaryDirectory(prefix=".capture-", dir=destination) as capture_dir_text:
                capture_dir = Path(capture_dir_text)
                args = [
                    gowitness_binary,
                    "scan",
                    "single",
                    "--url",
                    target_url,
                    "--screenshot-path",
                    str(capture_dir),
                    "--screenshot-format",
                    "png",
                    "--write-none",
                    "--driver",
                    "gorod",
                    "--timeout",
                    str(self.config.scan.get("http_timeout_seconds", 15)),
                    "--chrome-path",
                    os.getenv("CHROME_PATH", "/usr/bin/chromium"),
                ]
                await self.run_tool(*args)
                newest = max(
                    capture_dir.glob("*.png"),
                    key=lambda item: item.stat().st_mtime,
                    default=None,
                )
                if newest is None:
                    logger.info("Screenshot tool produced no PNG for %s", target_url)
                    return
                newest.replace(final_path)
        except OSError as exc:
            logger.warning("Screenshot file handling failed for %s: %s", target_url, exc)
            return
        await self.save_screenshot_record(domain_info, live_host["live_host_id"], target_url, final_path, capture_reason, summary)

    def extract_openapi_urls(self, base_url: str, spec_text: str) -> list[str]:
        if not self.config.scan.get("openapi_discovery_enabled", True):
            return []
        try:
            payload = json.loads(spec_text)
        except json.JSONDecodeError:
            try:
                payload = yaml.safe_load(spec_text)
            except yaml.YAMLError:
                return []
        if not isinstance(payload, dict):
            return []

        paths = payload.get("paths")
        if not isinstance(paths, dict):
            return []

        base_candidates = [base_url.rstrip("/")]
        servers = payload.get("servers")
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict) and isinstance(server.get("url"), str):
                    base_candidates.append(urljoin(base_url.rstrip("/") + "/", server["url"].rstrip("/")))
        elif isinstance(payload.get("host"), str):
            scheme = "https"
            schemes = payload.get("schemes")
            if isinstance(schemes, list) and schemes:
                scheme = str(schemes[0])
            base_path = str(payload.get("basePath") or "").strip("/")
            base_candidates.append(f"{scheme}://{payload['host']}/{base_path}".rstrip("/"))

        urls: list[str] = []
        for path in paths:
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            for candidate_base in base_candidates:
                urls.append(urljoin(candidate_base.rstrip("/") + "/", path.lstrip("/")))
        return dedupe_list(urls)[: int(self.config.scan.get("max_openapi_paths_per_host", 300))]

    async def probe_common_paths(
        self,
        domain_info: dict[str, Any],
        live_host: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for path in self.config.scan["common_paths"]:
                target = live_host["url"].rstrip("/") + path
                if not self.is_scope_allowed(domain_info, target):
                    continue
                try:
                    async with session.get(target, allow_redirects=True, headers=self.authenticated_headers(target, domain_info)) as response:
                        if response.status < 500:
                            await self.save_endpoint(domain_info["id"], live_host["live_host_id"], target, "common_path_probe", summary, response.status)
                            if (
                                self.config.scan.get("openapi_discovery_enabled", True)
                                and response.status == 200
                                and path in {"/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs"}
                            ):
                                body = await response.content.read(2_000_001)
                                if len(body) <= 2_000_000:
                                    spec_text = body.decode("utf-8", errors="ignore")
                                    spec_summary = self.summarize_openapi_spec(spec_text)
                                    await self.save_api_surface(
                                        domain_info["id"],
                                        live_host["live_host_id"],
                                        "openapi",
                                        target,
                                        "openapi_spec",
                                        response.status,
                                        auth_required=False,
                                        schema_url=target,
                                        methods=spec_summary["methods"],
                                        operations_count=spec_summary["operations_count"],
                                        risk_flags=spec_summary["risk_flags"],
                                        metadata=spec_summary["metadata"],
                                        summary=summary,
                                    )
                                    for spec_url in self.extract_openapi_urls(live_host["url"], spec_text):
                                        await self.save_endpoint(domain_info["id"], live_host["live_host_id"], spec_url, "openapi_spec", summary)
                            if (
                                path in {"/graphql", "/api/graphql", "/gql", "/graphiql", "/graphql/console", "/playground", "/api/playground"}
                                and response.status in {200, 400, 401, 403, 405}
                            ):
                                await self.verify_graphql_endpoint(
                                    domain_info,
                                    live_host["live_host_id"],
                                    target,
                                    "common_path_probe",
                                    response.status,
                                    summary,
                                    {"path": path},
                                )
                            if path in {"/.env", "/.git/HEAD", "/swagger", "/swagger.json", "/v2/api-docs"} and response.status == 200:
                                await self.save_finding(
                                    domain_info["id"],
                                    "interesting_exposed_path",
                                    "medium",
                                    target,
                                    {"status_code": response.status, "source": "common_path_probe"},
                                    summary,
                                )
                except Exception:
                    continue

    async def run_directory_bruteforce(
        self,
        domain_info: dict[str, Any],
        domain_id: int,
        live_host: dict[str, Any],
        summary: dict[str, Any] | None = None,
        scan_lane: str = "fast_delta",
    ) -> None:
        if not self.domain_bool(domain_info, "enable_ffuf", self.config.scan.get("directory_bruteforce_enabled", False)):
            return

        wordlist = self.select_ffuf_wordlist(scan_lane)
        if not wordlist.is_file():
            logger.info("Skipping ffuf for %s, wordlist not found: %s", live_host["url"], wordlist)
            self.append_summary(
                summary,
                "ffuf_skipped_hosts",
                {"url": live_host["url"], "reason": "missing_wordlist", "wordlist": str(wordlist), "scan_lane": scan_lane},
            )
            return
        wordlist_sha256 = self.file_sha256(wordlist)
        run_id = await self.start_ffuf_run(domain_id, live_host, scan_lane, str(wordlist), wordlist_sha256, summary)
        if run_id is None:
            return

        ffuf_binary = self.config.tools.get("ffuf", "ffuf")
        hits_count = 0
        try:
            stdout = await self.run_tool(
                ffuf_binary,
                "-w",
                str(wordlist),
                "-u",
                f"{live_host['url'].rstrip('/')}/FUZZ",
                "-mc",
                ",".join(str(status) for status in self.config.scan.get("ffuf_match_status", [200, 204, 301, 302, 307, 308, 401, 403])),
                "-t",
                str(self.config.scan.get("ffuf_threads", 10)),
                "-rate",
                str(self.config.scan.get("ffuf_rate", 30)),
                "-timeout",
                str(self.config.scan.get("ffuf_timeout_seconds", 10)),
                "-noninteractive",
                "-json",
                capture_output_files=True,
            )
            if stdout:
                for line in stdout.splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    url = payload.get("url")
                    status = payload.get("status")
                    if not url or status is None:
                        continue
                    hits_count += 1
                    await self.save_endpoint(domain_id, live_host["live_host_id"], url, "ffuf", summary, int(status))
                    if is_graphql_candidate_url(url):
                        await self.verify_graphql_endpoint(
                            domain_info,
                            live_host["live_host_id"],
                            url,
                            "ffuf",
                            int(status),
                            summary,
                            {"scan_lane": scan_lane, "wordlist": str(wordlist)},
                        )
                    if int(status) in {401, 403}:
                        await self.save_finding(
                            domain_id,
                            "interesting_bruteforce_hit",
                            "info",
                            url,
                            {"status_code": status, "source": "ffuf", "scan_lane": scan_lane, "wordlist": str(wordlist)},
                            summary,
                        )
            await self.finish_ffuf_run(run_id, "completed", hits_count)
            self.append_summary(
                summary,
                "ffuf_scanned_hosts",
                {"url": live_host["url"], "hits": hits_count, "wordlist": str(wordlist), "scan_lane": scan_lane},
            )
        except Exception as exc:
            await self.finish_ffuf_run(run_id, "failed", hits_count, repr(exc))
            raise

    def select_ffuf_wordlist(self, scan_lane: str) -> Path:
        if self.config.scan.get("ffuf_aggressive_enabled", False):
            value = self.config.scan.get("ffuf_wordlist_aggressive")
        elif scan_lane == "deep_scan" or scan_lane == "first_run":
            value = self.config.scan.get("ffuf_wordlist_deep")
        else:
            value = self.config.scan.get("ffuf_wordlist_default")
        return Path(value or self.config.scan.get("ffuf_wordlist", "/app/wordlists/commons.txt"))

    @staticmethod
    def file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def select_bug_job_ffuf_wordlist(self, live_host: dict[str, Any], decision: dict[str, Any]) -> Path:
        text = " ".join(
            [
                str(live_host.get("url") or ""),
                str(live_host.get("title") or ""),
                str(live_host.get("webserver") or ""),
                " ".join(str(item) for item in (live_host.get("tech") or live_host.get("technologies") or [])),
                " ".join(str(item) for item in decision.get("reasons") or []),
                " ".join(str(item) for item in decision.get("recommended_actions") or []),
            ]
        ).lower()
        explicit = self.config.scan.get("bug_jobs_auto_ffuf_wordlist")
        if explicit:
            return Path(str(explicit))
        if any(token in text for token in ("api", "graphql", "swagger", "openapi", "gateway")):
            return Path(str(self.config.scan.get("ffuf_wordlist_deep") or self.config.scan.get("ffuf_wordlist_default") or self.config.scan.get("ffuf_wordlist")))
        return self.select_ffuf_wordlist(str(self.config.scan.get("bug_jobs_auto_ffuf_lane", "bug_jobs_fast")))

    async def enqueue_ffuf_worker_run(
        self,
        domain_id: int,
        live_host: dict[str, Any],
        scan_lane: str,
        wordlist: Path,
        options: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> int | None:
        assert self.db_pool is not None
        if not wordlist.is_file():
            self.append_summary(
                summary,
                "ffuf_queue_errors",
                {"url": live_host.get("url"), "reason": "wordlist_missing", "wordlist": str(wordlist), "scan_lane": scan_lane},
            )
            return None
        wordlist_sha256 = self.file_sha256(wordlist)
        async with self.db_pool.acquire() as conn:
            existing = await conn.fetchrow(
                """
                SELECT id, status, completed_at
                FROM ffuf_runs
                WHERE live_host_id = $1
                  AND scan_lane = $2
                  AND wordlist_sha256 = $3
                """,
                live_host["live_host_id"],
                scan_lane,
                wordlist_sha256,
            )
            if existing:
                if existing["status"] in {"queued", "running"}:
                    self.append_summary(
                        summary,
                        "ffuf_skipped_hosts",
                        {"url": live_host["url"], "reason": f"already_{existing['status']}", "wordlist": str(wordlist), "scan_lane": scan_lane},
                    )
                    return int(existing["id"])
                if existing["status"] == "completed" and self.config.scan.get("ffuf_skip_completed", True):
                    self.append_summary(
                        summary,
                        "ffuf_skipped_hosts",
                        {"url": live_host["url"], "reason": "already_completed", "wordlist": str(wordlist), "scan_lane": scan_lane},
                    )
                    return int(existing["id"])
            row = await conn.fetchrow(
                """
                INSERT INTO ffuf_runs (
                  domain_id, live_host_id, host_url, scan_lane, wordlist_path,
                  wordlist_sha256, status, options
                )
                VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7::jsonb)
                ON CONFLICT (live_host_id, scan_lane, wordlist_sha256)
                DO UPDATE SET
                  status = CASE
                    WHEN ffuf_runs.status IN ('queued', 'running', 'completed') THEN ffuf_runs.status
                    ELSE 'queued'
                  END,
                  error = NULL,
                  host_url = EXCLUDED.host_url,
                  wordlist_path = EXCLUDED.wordlist_path,
                  options = ffuf_runs.options || EXCLUDED.options
                RETURNING id
                """,
                domain_id,
                live_host["live_host_id"],
                live_host["url"],
                scan_lane,
                str(wordlist),
                wordlist_sha256,
                postgres_json(sanitize_postgres_value(options)),
            )
        run_id = int(row["id"]) if row else None
        if run_id:
            self.append_summary(
                summary,
                "ffuf_queued_hosts",
                {"url": live_host["url"], "run_id": run_id, "wordlist": str(wordlist), "scan_lane": scan_lane},
            )
        return run_id

    async def maybe_enqueue_bug_job_ffuf(
        self,
        domain_info: dict[str, Any],
        live_host: dict[str, Any],
        decision: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.config.scan.get("bug_jobs_auto_ffuf_enabled", True):
            return
        if not self.config.scan.get("directory_bruteforce_enabled", False):
            return
        if self.config.scan.get("bug_jobs_auto_ffuf_respect_domain_enable", False) and not self.domain_bool(
            domain_info,
            "enable_ffuf",
            True,
        ):
            return
        is_new = bool(live_host.get("is_new_live_host"))
        fingerprint_changed = bool(live_host.get("fingerprint_changed"))
        min_priority = str(self.config.scan.get("bug_jobs_auto_ffuf_min_priority", "high"))
        high_signal = self.priority_rank(str(decision.get("priority") or "low")) >= self.priority_rank(min_priority)
        require_high_signal = bool(
            self.config.scan.get("bug_jobs_auto_ffuf_new_live_host_requires_high_signal", True)
        )
        if is_new and (
            not self.config.scan.get("bug_jobs_auto_ffuf_on_new_live_hosts", True)
            or (require_high_signal and not high_signal)
        ):
            is_new = False
        if fingerprint_changed and not self.config.scan.get("bug_jobs_auto_ffuf_on_fingerprint_change", True):
            fingerprint_changed = False
        if high_signal and not self.config.scan.get("bug_jobs_auto_ffuf_on_high_signal_hosts", True):
            high_signal = False
        if not (is_new or fingerprint_changed or high_signal):
            return
        max_per_scan = max(0, int(self.config.scan.get("bug_jobs_auto_ffuf_max_per_domain_per_scan", 25) or 0))
        counter_key = "_bug_jobs_auto_ffuf_queued"
        if summary is not None and max_per_scan:
            queued_count = int(summary.get(counter_key) or 0)
            if queued_count >= max_per_scan:
                return
            summary[counter_key] = queued_count + 1
        scan_lane = str(self.config.scan.get("bug_jobs_auto_ffuf_lane", "bug_jobs_fast"))
        wordlist = self.select_bug_job_ffuf_wordlist(live_host, decision)
        domain_id = int(domain_info.get("id") or domain_info.get("domain_id"))
        await self.enqueue_ffuf_worker_run(
            domain_id,
            live_host,
            scan_lane,
            wordlist,
            {
                "queue_worker": "ffuf",
                "source": "bug_jobs_live_host_watcher",
                "reason": {
                    "new_live_host": is_new,
                    "fingerprint_changed": fingerprint_changed,
                    "high_signal": high_signal,
                    "priority": decision.get("priority"),
                    "score": decision.get("score"),
                    "reasons": decision.get("reasons", []),
                },
                "profile": "bug_jobs_auto",
                "match_status": [200, 204, 301, 302, 307, 308, 401, 403, 405, 500],
            },
            summary,
        )

    async def start_ffuf_run(
        self,
        domain_id: int,
        live_host: dict[str, Any],
        scan_lane: str,
        wordlist_path: str,
        wordlist_sha256: str,
        summary: dict[str, Any] | None,
    ) -> int | None:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            existing = await conn.fetchrow(
                """
                SELECT id, status, completed_at
                FROM ffuf_runs
                WHERE live_host_id = $1
                  AND scan_lane = $2
                  AND wordlist_sha256 = $3
                """,
                live_host["live_host_id"],
                scan_lane,
                wordlist_sha256,
            )
            if existing and existing["status"] == "completed" and self.config.scan.get("ffuf_skip_completed", True):
                self.append_summary(
                    summary,
                    "ffuf_skipped_hosts",
                    {"url": live_host["url"], "reason": "already_completed", "wordlist": wordlist_path, "scan_lane": scan_lane},
                )
                return None
            row = await conn.fetchrow(
                """
                INSERT INTO ffuf_runs (domain_id, live_host_id, host_url, scan_lane, wordlist_path, wordlist_sha256)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (live_host_id, scan_lane, wordlist_sha256)
                DO UPDATE SET
                  started_at = NOW(),
                  completed_at = NULL,
                  status = 'running',
                  hits_count = 0,
                  error = NULL,
                  host_url = EXCLUDED.host_url,
                  wordlist_path = EXCLUDED.wordlist_path
                RETURNING id
                """,
                domain_id,
                live_host["live_host_id"],
                live_host["url"],
                scan_lane,
                wordlist_path,
                wordlist_sha256,
            )
            return int(row["id"]) if row else None

    async def finish_ffuf_run(self, run_id: int, status: str, hits_count: int, error: str | None = None) -> None:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE ffuf_runs
                SET completed_at = NOW(), status = $2, hits_count = $3, error = $4
                WHERE id = $1
                """,
                run_id,
                status,
                hits_count,
                error,
            )

    def host_nuclei_profiles(self, live_host: dict[str, Any]) -> list[str]:
        text = " ".join(
            [
                str(live_host.get("url") or ""),
                str(live_host.get("title") or ""),
                str(live_host.get("webserver") or ""),
                " ".join(str(item) for item in live_host.get("tech", []) or []),
            ]
        ).lower()
        profiles = ["baseline"]
        if any(token in text for token in ("api", "graphql", "swagger", "openapi", "graphiql")):
            profiles.append("api")
        if any(token in text for token in ("auth", "login", "sso", "oauth", "jwt", "token")):
            profiles.append("auth")
        if any(token in text for token in ("s3", "bucket", "aws", "azure", "gcp", "cloudfront")):
            profiles.append("cloud")
        if live_host.get("tech"):
            profiles.append("tech")
        return dedupe_list(profiles)

    def should_run_nuclei_for_host(self, live_host: dict[str, Any]) -> bool:
        if live_host.get("is_new_live_host") or live_host.get("fingerprint_changed"):
            return True
        if self.config.scan.get("nuclei_only_on_new_live_hosts", False):
            return False
        if not self.config.scan.get("nuclei_only_on_interesting_hosts", True):
            return True
        score = self.host_priority_score(live_host)
        status_code = int(live_host.get("status_code") or 0)
        return score >= 20 or status_code in {401, 403}

    def nuclei_batch_status(self, domain_info: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        if not self.config.scan.get("nuclei_batching_enabled", True):
            return {"enabled": True, "reason": "batching_disabled"}
        batch_count = max(1, int(self.config.scan.get("nuclei_batch_count", 3)))
        window_hours = max(1, int(self.config.scan.get("nuclei_batch_window_hours", 72)))
        if batch_count <= 1:
            return {"enabled": True, "reason": "single_batch", "batch_count": batch_count}

        now = now or datetime.utcnow()
        window_index = int(now.timestamp() // (window_hours * 3600))
        active_batch = window_index % batch_count
        domain_id = int(domain_info.get("id") or 0)
        domain_batch = domain_id % batch_count
        return {
            "enabled": domain_batch == active_batch,
            "reason": "active_batch" if domain_batch == active_batch else "inactive_batch",
            "active_batch": active_batch,
            "domain_batch": domain_batch,
            "batch_count": batch_count,
            "window_hours": window_hours,
            "window_index": window_index,
        }

    def select_nuclei_hosts(
        self,
        domain_info: dict[str, Any],
        live_hosts: list[dict[str, Any]],
        first_run: bool,
        deep_scan: bool,
        summary: dict[str, Any] | None = None,
    ) -> set[int]:
        if not self.domain_bool(domain_info, "enable_nuclei", self.config.scan.get("nuclei_enabled", False)):
            return set()
        if self.config.scan.get("nuclei_only_on_deep_scan", True) and not (first_run or deep_scan):
            self.append_summary(summary, "nuclei_batch", {"enabled": False, "reason": "not_deep_scan"})
            return set()
        batch = self.nuclei_batch_status(domain_info)
        self.append_summary(summary, "nuclei_batch", batch)
        if not batch.get("enabled", True):
            for host in live_hosts:
                self.append_summary(summary, "nuclei_skipped_hosts", {**batch, "url": host["url"], "reason": "inactive_nuclei_batch"})
            return set()

        max_hosts = max(0, int(self.config.scan.get("nuclei_max_hosts_per_domain", 25)))
        if max_hosts <= 0:
            return set()
        candidates = [host for host in live_hosts if self.should_run_nuclei_for_host(host)]
        candidates = self.rank_live_hosts(candidates)
        selected = candidates[:max_hosts]
        selected_ids = {int(host["live_host_id"]) for host in selected}
        for host in live_hosts:
            if int(host["live_host_id"]) not in selected_ids:
                self.append_summary(summary, "nuclei_skipped_hosts", {"url": host["url"], "reason": "not_selected_for_nuclei"})
        return selected_ids

    async def run_nuclei_scan(
        self,
        domain_info: dict[str, Any],
        domain_id: int,
        live_host: dict[str, Any],
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.domain_bool(domain_info, "enable_nuclei", self.config.scan.get("nuclei_enabled", False)):
            return
        if not self.should_run_nuclei_for_host(live_host):
            self.append_summary(summary, "nuclei_skipped_hosts", live_host["url"])
            return
        self.append_summary(summary, "nuclei_scanned_hosts", live_host["url"])

        nuclei_binary = self.config.tools.get("nuclei", "nuclei")
        severities = self.config.scan.get("nuclei_severities", ["critical", "high", "medium"])
        profile_tags = self.config.scan.get("nuclei_profile_tags", {}) or {}
        selected_tags: set[str] = set()
        for profile in self.host_nuclei_profiles(live_host):
            selected_tags.update(str(tag) for tag in profile_tags.get(profile, []) if str(tag))
        args = [
            nuclei_binary,
            "-target",
            live_host["url"],
            "-jsonl",
            "-duc",
            "-rl",
            str(self.config.scan.get("nuclei_rate_limit", 20)),
            "-c",
            str(self.config.scan.get("nuclei_concurrency", 5)),
            "-bulk-size",
            str(self.config.scan.get("nuclei_bulk_size", 25)),
            "-timeout",
            str(self.config.scan.get("nuclei_timeout_seconds", 10)),
            "-retries",
            str(self.config.scan.get("nuclei_retries", 1)),
        ]
        if severities:
            args.extend(["-severity", ",".join(str(item) for item in severities)])
        if selected_tags:
            args.extend(["-tags", ",".join(sorted(selected_tags))])
        templates_dir = self.config.scan.get("nuclei_templates_dir", "")
        if templates_dir:
            args.extend(["-t", templates_dir])
        header_path = self.create_header_file(self.authenticated_header_lines(domain_info, live_host["url"]))
        if header_path:
            args.extend(["-H", header_path])
        try:
            stdout = await self.run_tool(
                *args,
                capture_output_files=True,
                timeout_seconds=float(self.config.scan.get("nuclei_wall_timeout_seconds", 180)),
            )
        finally:
            if header_path:
                Path(header_path).unlink(missing_ok=True)
        if not stdout:
            return

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = payload.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            matched_at = payload.get("matched-at") or payload.get("host") or live_host["url"]
            template_id = payload.get("template-id") or "unknown"
            await self.save_finding(
                domain_id,
                f"nuclei_{template_id}",
                severity,
                matched_at,
                {
                    "template_id": template_id,
                    "template_name": info.get("name"),
                    "severity": severity,
                    "matcher_name": payload.get("matcher-name"),
                    "matched_at": matched_at,
                    "type": payload.get("type"),
                    "tags": info.get("tags") or [],
                    "description": info.get("description"),
                },
                summary,
            )

    async def run_nuclei_dast_scan(
        self,
        domain_info: dict[str, Any],
        domain_id: int,
        urls: list[str],
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.config.scan.get("nuclei_dast_enabled", False):
            return

        max_urls = int(self.config.scan.get("nuclei_dast_max_urls_per_domain", 50))
        selected = dedupe_list(
            [
                item["url"] if isinstance(item, dict) else str(item)
                for item in urls
                if (item["url"] if isinstance(item, dict) else str(item)).startswith(("http://", "https://"))
            ]
        )[:max_urls]
        if not selected:
            return

        nuclei_binary = self.config.tools.get("nuclei", "nuclei")
        severities = self.config.scan.get("nuclei_dast_severities", self.config.scan.get("nuclei_severities", ["critical", "high", "medium"]))
        templates_dir = self.config.scan.get("nuclei_templates_dir", "")

        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
                temp_path = handle.name
                handle.write("\n".join(selected))
                handle.write("\n")

            args = [
                nuclei_binary,
                "-list",
                temp_path,
                "-jsonl",
                "-dast",
                "-duc",
                "-rl",
                str(self.config.scan.get("nuclei_dast_rate_limit", self.config.scan.get("nuclei_rate_limit", 20))),
                "-c",
                str(self.config.scan.get("nuclei_dast_concurrency", self.config.scan.get("nuclei_concurrency", 5))),
                "-bulk-size",
                str(self.config.scan.get("nuclei_bulk_size", 25)),
                "-timeout",
                str(self.config.scan.get("nuclei_timeout_seconds", 10)),
                "-retries",
                str(self.config.scan.get("nuclei_retries", 1)),
            ]
            if severities:
                args.extend(["-severity", ",".join(str(item) for item in severities)])
            if templates_dir:
                args.extend(["-t", templates_dir])

            for url in selected:
                self.append_summary(summary, "nuclei_dast_scanned_urls", url)

            stdout = await self.run_tool(
                *args,
                capture_output_files=True,
                timeout_seconds=float(self.config.scan.get("nuclei_dast_wall_timeout_seconds", self.config.scan.get("nuclei_wall_timeout_seconds", 180))),
            )
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except OSError:
                    pass

        if not stdout:
            return

        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = payload.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            matched_at = payload.get("matched-at") or payload.get("host") or payload.get("url") or domain_info["domain"]
            template_id = payload.get("template-id") or "unknown"
            await self.save_finding(
                domain_id,
                f"nuclei_dast_{template_id}",
                severity,
                matched_at,
                {
                    "template_id": template_id,
                    "template_name": info.get("name"),
                    "severity": severity,
                    "matcher_name": payload.get("matcher-name"),
                    "matched_at": matched_at,
                    "type": payload.get("type"),
                    "tags": info.get("tags") or [],
                    "description": info.get("description"),
                    "source": "nuclei_dast",
                },
                summary,
            )

    def build_hidden_param_url(self, url: str, param_name: str, value: str = "test") -> str:
        parsed = urlsplit(url)
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        if any(name.lower() == param_name.lower() for name, _ in query_items):
            return url
        query_items.append((param_name, value))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query_items), parsed.fragment))

    def select_targeted_urls(self, urls: list[Any]) -> list[str]:
        max_urls = int(self.config.scan.get("targeted_triage_max_urls", 75))
        keywords = [str(item).lower() for item in self.config.scan.get("ai_triage_high_signal_keywords", [])]
        candidates: list[tuple[int, str]] = []
        for item in urls:
            if isinstance(item, dict):
                url = str(item.get("url") or "")
                risk_tags = item.get("risk_tags") or []
                source = str(item.get("source") or "")
            else:
                url = str(item)
                risk_tags = []
                source = ""
            if not url.startswith(("http://", "https://")):
                continue
            lowered = url.lower()
            score = 0
            if "?" in url:
                score += 20
            if source == "js_analysis":
                score += 15
            if risk_tags:
                score += 15
            for keyword in keywords:
                if keyword and keyword in lowered:
                    score += 8
            if score > 0:
                candidates.append((score, url))
        candidates.sort(reverse=True)
        return dedupe_list([url for _, url in candidates])[:max_urls]

    def select_dalfox_urls(self, urls: list[Any]) -> list[str]:
        max_urls = int(self.config.scan.get("dalfox_max_urls_per_domain", 40))
        candidates: list[tuple[int, str]] = []
        keywords = [str(item).lower() for item in self.config.scan.get("host_priority_keywords", [])]
        for item in urls:
            if isinstance(item, dict):
                url = str(item.get("url") or "")
                risk_tags = [str(tag).lower() for tag in item.get("risk_tags") or []]
                source = str(item.get("source") or "")
            else:
                url = str(item)
                risk_tags = []
                source = ""
            if not url.startswith(("http://", "https://")) or "?" not in url:
                continue
            parsed = urlsplit(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            lowered = url.lower()
            score = 10
            if "xss" in risk_tags:
                score += 40
            if source == "js_analysis":
                score += 15
            if any(name.lower() in {"q", "query", "search", "keyword", "term", "name", "title", "message", "comment", "content", "body", "text", "html", "template", "redirect", "callback"} for name, _ in params):
                score += 20
            for keyword in keywords:
                if keyword and keyword in lowered:
                    score += 5
            candidates.append((score, url))
        candidates.sort(reverse=True)
        return dedupe_list([url for _, url in candidates])[:max_urls]

    async def run_dalfox_scan(
        self,
        domain_info: dict[str, Any],
        domain_id: int,
        urls: list[Any],
        summary: dict[str, Any] | None = None,
        deep_scan: bool = False,
    ) -> None:
        if not self.config.scan.get("dalfox_enabled", False):
            return
        if self.config.scan.get("dalfox_only_on_deep_scan", False) and not deep_scan:
            return

        selected = self.select_dalfox_urls(urls)
        if not selected:
            return

        dalfox_binary = self.config.tools.get("dalfox", "dalfox")
        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
                temp_path = handle.name
                handle.write("\n".join(selected))
                handle.write("\n")

            args = [
                dalfox_binary,
                "file",
                temp_path,
                "--silence",
                "--format",
                "json",
                "--worker",
                str(self.config.scan.get("dalfox_worker", 3)),
                "--delay",
                str(self.config.scan.get("dalfox_delay_ms", 200)),
                "--timeout",
                str(self.config.scan.get("dalfox_timeout_seconds", 10)),
            ]
            if self.config.scan.get("dalfox_skip_bav", True):
                args.append("--skip-bav")

            for url in selected:
                self.append_summary(summary, "dalfox_scanned_urls", url)

            stdout = await self.run_tool(*args, capture_output_files=True)
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except OSError:
                    pass

        if not stdout:
            return

        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding_type = str(payload.get("type") or payload.get("poc_type") or payload.get("evidence") or "xss").lower()
            matched_at = str(payload.get("url") or payload.get("target") or payload.get("data") or domain_info["domain"])
            if not matched_at.startswith(("http://", "https://")):
                matched_at = str(payload.get("target") or domain_info["domain"])
            severity = "high" if "verified" in finding_type or payload.get("poc") else "medium"
            await self.save_finding(
                domain_id,
                "dalfox_xss",
                severity,
                matched_at,
                {
                    "source": "dalfox",
                    "tool": "dalfox",
                    "type": payload.get("type"),
                    "param": payload.get("param") or payload.get("parameter"),
                    "payload": payload.get("payload"),
                    "evidence": payload.get("evidence"),
                    "poc": payload.get("poc"),
                    "raw": payload,
                },
                summary,
            )

    async def probe_hidden_parameters(
        self,
        domain_info: dict[str, Any],
        domain_id: int,
        live_hosts: list[dict[str, Any]],
        urls: list[str],
        summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.config.scan.get("hidden_param_discovery_enabled", False):
            return

        param_names = [str(item).strip() for item in self.config.scan.get("hidden_param_words", []) if str(item).strip()]
        if not param_names:
            return

        max_urls = int(self.config.scan.get("hidden_param_max_urls_per_domain", 25))
        max_params = int(self.config.scan.get("hidden_param_max_params_per_url", 8))
        selected_urls = dedupe_list(
            [
                item["url"] if isinstance(item, dict) else str(item)
                for item in urls
                if (item["url"] if isinstance(item, dict) else str(item)).startswith(("http://", "https://"))
            ]
        )[:max_urls]
        if not selected_urls:
            return

        host_ids = {
            str(item.get("url", "")).rstrip("/"): int(item["live_host_id"])
            for item in live_hosts
            if item.get("url") and item.get("live_host_id")
        }

        timeout = aiohttp.ClientTimeout(total=self.config.scan["http_timeout_seconds"])
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for base_url in selected_urls:
                split = urlsplit(base_url)
                live_host_url = f"{split.scheme}://{split.netloc}".rstrip("/")
                live_host_id = host_ids.get(live_host_url)
                if not live_host_id:
                    continue
                for param_name in param_names[:max_params]:
                    target = self.build_hidden_param_url(base_url, param_name)
                    if target == base_url:
                        continue
                    try:
                        async with session.get(target, allow_redirects=True, headers=self.authenticated_headers(target, domain_info)) as response:
                            if response.status >= 500:
                                continue
                            await self.save_endpoint(domain_id, live_host_id, target, "hidden_param_probe", summary, response.status)
                            self.append_summary(summary, "hidden_parameter_probes", {"url": target, "status_code": response.status})
                    except Exception:
                        continue

    async def collect_js_assets_for_host(
        self,
        domain_info: dict[str, Any],
        host: dict[str, Any],
        summary: dict[str, Any] | None = None,
        discovered_urls: list[str] | None = None,
    ) -> None:
        if not self.domain_bool(domain_info, "enable_js_analysis", self.config.scan.get("analyze_js_assets", True)):
            return

        js_urls = [url for url in (discovered_urls or []) if looks_like_js_url(url)]
        html = await self.fetch_html(host["url"], domain_info)
        if html:
            js_urls.extend(extract_script_urls_from_html(host["url"], html))

        unique_js_urls: list[str] = []
        seen: set[str] = set()
        for item in js_urls:
            if item not in seen:
                seen.add(item)
                unique_js_urls.append(item)

        max_js_assets = self.domain_int(domain_info, "max_js_assets", int(self.config.scan["max_js_assets_per_host"]))
        for asset_url in unique_js_urls[:max_js_assets]:
            await self.save_js_asset(domain_info, host["live_host_id"], asset_url, "html_or_historical", summary)

    async def process_live_host(
        self,
        domain_info: dict[str, Any],
        host: dict[str, Any],
        summary: dict[str, Any] | None = None,
        run_ffuf: bool = False,
        full_discovery: bool = True,
        run_nuclei: bool = False,
    ) -> None:
        async with self.live_host_semaphore:
            if host.get("is_new_live_host"):
                await self.capture_screenshot(domain_info, host, "new_live_host", summary)
            elif host.get("fingerprint_changed") and self.config.scan.get("screenshots_on_fingerprint_change", True):
                await self.capture_screenshot(domain_info, host, "fingerprint_change", summary)

            discovered_urls: list[str] = []
            if full_discovery:
                discovered_urls = await self.discover_urls_for_host(domain_info, host)
                url_statuses: dict[str, int | None] = {}
                if self.config.scan.get("probe_discovered_url_status", True):
                    url_statuses = await self.probe_url_statuses(discovered_urls, domain_info)
                for endpoint in discovered_urls:
                    await self.save_endpoint(
                        domain_info["id"],
                        host["live_host_id"],
                        endpoint,
                        "historical_or_crawl",
                        summary,
                        url_statuses.get(endpoint),
                    )
                    if is_graphql_candidate_url(endpoint):
                        await self.verify_graphql_endpoint(
                            domain_info,
                            host["live_host_id"],
                            endpoint,
                            "historical_or_crawl",
                            url_statuses.get(endpoint),
                            summary,
                            {"discovery": "historical_or_crawl"},
                        )

            if full_discovery or self.config.scan.get("js_collect_all_live_hosts", True):
                await self.collect_js_assets_for_host(domain_info, host, summary, discovered_urls)

            await self.probe_common_paths(domain_info, host, summary)
            if full_discovery and run_ffuf and self.domain_bool(domain_info, "enable_ffuf", False):
                await self.run_directory_bruteforce(
                    domain_info,
                    domain_info["id"],
                    host,
                    summary,
                    str(summary.get("scan_lane", "fast_delta")) if summary else "fast_delta",
                )
            if run_nuclei:
                await self.run_nuclei_scan(domain_info, domain_info["id"], host, summary)

    async def collect_domain_totals(self, domain_id: int) -> dict[str, int]:
        assert self.db_pool is not None
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                  (SELECT COUNT(*) FROM subdomains s WHERE s.domain_id = $1) AS subdomains,
                  (SELECT COUNT(*)
                   FROM live_hosts lh
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS live_hosts,
                  (SELECT COUNT(*)
                   FROM endpoints e
                   JOIN live_hosts lh ON lh.id = e.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS endpoints,
                  (SELECT COUNT(*)
                   FROM js_assets ja
                   JOIN live_hosts lh ON lh.id = ja.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS js_assets,
                  (SELECT COUNT(*)
                   FROM url_parameters up
                   JOIN endpoints e ON e.id = up.endpoint_id
                   JOIN live_hosts lh ON lh.id = e.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1 AND cardinality(up.risk_tags) > 0) AS risky_params,
                  (SELECT COUNT(*)
                   FROM findings f
                   WHERE f.domain_id = $1) AS findings,
                  (SELECT COUNT(*)
                   FROM findings f
                   WHERE f.domain_id = $1 AND f.finding_type LIKE 'nuclei_%') AS nuclei_hits,
                  (SELECT COUNT(*) FROM infrastructure_ips ii WHERE ii.domain_id = $1) AS ip_assets,
                  (SELECT COUNT(*) FROM network_services ns WHERE ns.domain_id = $1 AND ns.state = 'open') AS open_ports,
                  (SELECT COUNT(*)
                   FROM screenshots sc
                   JOIN live_hosts lh ON lh.id = sc.live_host_id
                   JOIN subdomains s ON s.id = lh.subdomain_id
                   WHERE s.domain_id = $1) AS screenshots
                """,
                domain_id,
            )
            return {key: int(value or 0) for key, value in dict(row).items()}

    async def record_scan_snapshot(
        self,
        domain_info: dict[str, Any],
        scan_started_at: datetime,
        scan_finished_at: datetime,
        duration_seconds: float,
        summary: dict[str, Any],
    ) -> None:
        assert self.db_pool is not None
        totals = await self.collect_domain_totals(domain_info["id"])
        new_counts = {
            "new_subdomains": len(summary["new_subdomains"]),
            "new_live_hosts": len(summary["new_live_hosts"]),
            "new_urls": len(summary["new_urls"]),
            "new_js_assets": len(summary["new_js_assets"]),
            "changed_js_assets": len(summary["changed_js_assets"]),
            "changed_fingerprints": len(summary["changed_fingerprints"]),
            "new_screenshots": len(summary["new_screenshots"]),
            "new_findings": len(summary["findings"]),
            "nuclei_scanned_hosts": len(summary.get("nuclei_scanned_hosts", [])),
            "nuclei_skipped_hosts": len(summary.get("nuclei_skipped_hosts", [])),
            "permutation_subdomains": len(summary.get("permutation_subdomains", [])),
            "nuclei_dast_scanned_urls": len(summary.get("nuclei_dast_scanned_urls", [])),
            "hidden_parameter_probes": len(summary.get("hidden_parameter_probes", [])),
            "ffuf_scanned_hosts": len(summary.get("ffuf_scanned_hosts", [])),
            "ffuf_skipped_hosts": len(summary.get("ffuf_skipped_hosts", [])),
            "ai_triage": len(summary.get("ai_triage", [])),
            "asset_events": len(summary.get("asset_events", [])),
            "new_ips": len(summary.get("new_ips", [])),
            "new_ports": len(summary.get("new_ports", [])),
        }
        metadata = {
            "organization": domain_info.get("organization"),
            "include_subdomains": domain_info.get("include_subdomains"),
            "deep_scan": bool(summary.get("deep_scan")),
            "scan_lane": summary.get("scan_lane"),
            "passive_sources": summary.get("passive_sources", {}),
            "passive_recursion": summary.get("passive_recursion", {}),
            "httpx_probe": summary.get("httpx_probe", {}),
            "dnsx_probe": summary.get("dnsx_probe", {}),
        }
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scan_snapshots (
                  domain_id,
                  scan_started_at,
                  scan_finished_at,
                  duration_seconds,
                  first_run,
                  totals,
                  new_counts,
                  metadata
                )
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb)
                """,
                domain_info["id"],
                scan_started_at,
                scan_finished_at,
                duration_seconds,
                bool(summary["first_run"]),
                json.dumps(totals),
                json.dumps(new_counts),
                json.dumps(metadata),
            )

    async def prune_old_data(self) -> None:
        assert self.db_pool is not None
        retention = self.config.retention
        alerts_days = int(retention.get("alerts_days", 30))
        snapshots_days = int(retention.get("snapshots_days", 120))
        screenshots_days = int(retention.get("screenshots_days", 60))
        fingerprints_days = int(retention.get("fingerprints_days", 120))

        cutoff_alerts = datetime.utcnow() - timedelta(days=alerts_days)
        cutoff_snapshots = datetime.utcnow() - timedelta(days=snapshots_days)
        cutoff_screenshots = datetime.utcnow() - timedelta(days=screenshots_days)
        cutoff_fingerprints = datetime.utcnow() - timedelta(days=fingerprints_days)

        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                "DELETE FROM screenshots WHERE captured_at < $1 RETURNING screenshot_path",
                cutoff_screenshots,
            )
            await conn.execute("DELETE FROM alerts WHERE sent_at < $1", cutoff_alerts)
            await conn.execute("DELETE FROM scan_snapshots WHERE scan_finished_at < $1", cutoff_snapshots)
            await conn.execute(
                "DELETE FROM live_host_fingerprints WHERE is_current = FALSE AND last_seen < $1",
                cutoff_fingerprints,
            )

        for row in rows:
            try:
                path = SCREENSHOT_ROOT / str(row["screenshot_path"])
                if path.is_file():
                    path.unlink()
            except OSError:
                continue

    async def maybe_run_maintenance(self) -> None:
        interval_minutes = int(self.config.retention.get("maintenance_interval_minutes", 60))
        now = datetime.utcnow()
        if self.last_maintenance_run and now - self.last_maintenance_run < timedelta(minutes=interval_minutes):
            return
        await self.prune_old_data()
        self.last_maintenance_run = now

    async def run_domain_scan(self, domain_info: dict[str, Any]) -> None:
        async with self.scan_semaphore:
            domain = domain_info["domain"]
            first_run = domain_info["last_scan"] is None
            domain_info["_scope_rules"] = await self.load_scope_rules(domain_info["id"])
            domain_info["_auth_profiles"] = await self.load_auth_profiles(domain_info["id"])
            summary = new_scan_summary(domain, first_run)
            deep_scan = await self.should_run_deep_scan(domain_info, first_run)
            summary["deep_scan"] = deep_scan
            summary["scan_lane"] = "first_run" if first_run else ("deep_scan" if deep_scan else "fast_delta")
            started_at = datetime.utcnow()
            logger.info("Scanning %s", domain)
            if first_run:
                await self.send_alert(
                    "scan_started",
                    self.build_scan_start_message(domain_info),
                    {"domain_id": domain_info["id"], "domain": domain, "first_run": True, "started_at": started_at.isoformat()},
                )

            try:
                await self.queue_shodan_domain_job(domain_info["id"], priority=90)
                await self.ingest_cloud_inventory(domain_info, summary)
                discovered_subdomains = set(await self.enumerate_subdomains(domain_info, summary))
                known_subdomains = await self.load_known_subdomains(domain_info["id"], domain)
                discovered_subdomains.update(known_subdomains)
                summary["httpx_probe"] = {"known_subdomains_reused": len(known_subdomains)}
                subdomains = sorted(discovered_subdomains)
                if deep_scan:
                    subdomain_set = set(subdomains)
                    subdomain_set.update(await self.discover_permutation_subdomains(domain_info, subdomain_set, summary))
                    subdomains = sorted(subdomain_set)
                if not subdomains:
                    await self.update_domain_last_scan(domain_info["id"])
                    finished_at = datetime.utcnow()
                    duration = (finished_at - started_at).total_seconds()
                    await self.record_scan_snapshot(domain_info, started_at, finished_at, duration, summary)
                    if first_run:
                        await self.send_alert(
                            "scan_summary",
                            self.build_scan_summary_message(summary, duration),
                            {"domain_id": domain_info["id"], **summary, "duration_seconds": duration},
                        )
                    return

                await self.discover_infrastructure(
                    domain_info,
                    subdomains,
                    first_run,
                    deep_scan,
                    summary,
                )
                live_hosts = await self.probe_live_hosts(domain_info, subdomains, summary)
                if live_hosts:
                    live_hosts = self.rank_live_hosts(live_hosts)
                    max_full_hosts = int(self.config.scan.get("max_full_scan_hosts_per_domain", 25))
                    fast_top_hosts = int(self.config.scan.get("scan_lane_fast_top_hosts", 5))
                    fast_changed_only = bool(self.config.scan.get("scan_lane_fast_changed_only", True))
                    max_ffuf_hosts = int(self.config.scan.get("ffuf_max_hosts_per_domain", 3))
                    nuclei_host_ids = self.select_nuclei_hosts(domain_info, live_hosts, first_run, deep_scan, summary)

                    async def process_indexed_host(index: int, host: dict[str, Any]) -> None:
                        changed = bool(host.get("is_new_live_host") or host.get("fingerprint_changed"))
                        if deep_scan or first_run:
                            full_discovery = index < max_full_hosts
                        elif fast_changed_only:
                            full_discovery = changed or index < fast_top_hosts
                        else:
                            full_discovery = index < fast_top_hosts
                        await self.process_live_host(
                            domain_info,
                            host,
                            summary,
                            run_ffuf=(deep_scan or changed) and index < max_ffuf_hosts,
                            full_discovery=full_discovery,
                            run_nuclei=int(host["live_host_id"]) in nuclei_host_ids,
                        )

                    await asyncio.gather(*(process_indexed_host(index, host) for index, host in enumerate(live_hosts)))

                    if deep_scan or self.config.scan.get("targeted_triage_enabled", True):
                        new_urls = self.select_targeted_urls(summary["new_urls"])
                        await self.run_nuclei_dast_scan(domain_info, domain_info["id"], new_urls, summary)
                        dalfox_source_urls = summary["new_urls"] if self.config.scan.get("dalfox_only_new_urls", True) else new_urls
                        await self.run_dalfox_scan(domain_info, domain_info["id"], dalfox_source_urls, summary, deep_scan)
                        if deep_scan:
                            await self.probe_hidden_parameters(domain_info, domain_info["id"], live_hosts, new_urls, summary)

                await self.run_due_monitors(domain_info["id"], summary)
                probe_incomplete = any(
                    summary.get(key, {}).get("status") == "incomplete"
                    for key in ("httpx_probe", "dnsx_probe")
                )
                retry_minutes = int(self.config.scan.get("incomplete_probe_retry_minutes", 30)) if probe_incomplete else None
                await self.update_domain_last_scan(domain_info["id"], retry_minutes)
                finished_at = datetime.utcnow()
                duration = (finished_at - started_at).total_seconds()
                SCAN_DURATION.set(duration)
                await self.record_scan_snapshot(domain_info, started_at, finished_at, duration, summary)
                if first_run or self.summary_has_changes(summary):
                    await self.send_alert(
                        "scan_summary",
                        self.build_scan_summary_message(summary, duration),
                        {"domain_id": domain_info["id"], **summary, "duration_seconds": duration},
                    )
                logger.info("Finished %s in %.2fs", domain, duration)
            except Exception as exc:
                logger.exception("Scan failed for %s: %s", domain, exc)
                await self.send_alert(
                    "scan_error",
                    f"Recon scan failed: {domain}",
                    {"domain_id": domain_info["id"], "domain": domain, "error": repr(exc)},
                )

    async def fill_domain_scan_slots(
        self,
        active_tasks: dict[int, asyncio.Task[None]],
    ) -> int:
        max_concurrent = max(1, int(self.config.scan["max_concurrent_domains"]))
        available_slots = max_concurrent - len(active_tasks)
        if available_slots <= 0:
            return 0

        domains = await self.get_domains_to_scan(
            limit=available_slots,
            excluded_domain_ids=set(active_tasks),
        )
        started = 0
        for domain in domains:
            domain_id = int(domain["id"])
            if domain_id in active_tasks:
                continue
            active_tasks[domain_id] = asyncio.create_task(
                self.run_domain_scan(domain),
                name=f"domain-scan:{domain['domain']}",
            )
            started += 1
        return started

    @staticmethod
    async def reap_domain_scan_tasks(
        active_tasks: dict[int, asyncio.Task[None]],
        timeout_seconds: float,
    ) -> int:
        if not active_tasks:
            return 0
        done, _ = await asyncio.wait(
            active_tasks.values(),
            timeout=max(0.1, timeout_seconds),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not done:
            return 0

        completed_ids = [
            domain_id
            for domain_id, task in active_tasks.items()
            if task in done
        ]
        for domain_id in completed_ids:
            task = active_tasks.pop(domain_id)
            try:
                task.result()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Unhandled domain scan task failure: domain_id=%s", domain_id)
        return len(completed_ids)

    async def continuous_loop(self) -> None:
        active_tasks: dict[int, asyncio.Task[None]] = {}
        poll_seconds = max(1.0, float(self.config.scan.get("scheduler_poll_seconds", 5)))
        idle_sleep = max(poll_seconds, float(self.config.scan["idle_sleep_seconds"]))
        try:
            while True:
                await self.maybe_run_maintenance()
                await self.run_due_monitors()
                started = await self.fill_domain_scan_slots(active_tasks)
                if active_tasks:
                    await self.reap_domain_scan_tasks(active_tasks, poll_seconds)
                    continue
                await asyncio.sleep(poll_seconds if started else idle_sleep)
        finally:
            for task in active_tasks.values():
                task.cancel()
            if active_tasks:
                await asyncio.gather(*active_tasks.values(), return_exceptions=True)


async def main() -> None:
    config = load_config()
    start_http_server(config.scan["metrics_port"])
    framework = ContinuousReconFramework(config)
    await framework.init()
    await framework.continuous_loop()


if __name__ == "__main__":
    asyncio.run(main())
