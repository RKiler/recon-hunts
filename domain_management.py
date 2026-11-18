"""Validation and option handling for dashboard-managed recon domains."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable
from urllib.parse import urlsplit


class DomainValidationError(ValueError):
    """Raised when dashboard domain input is not a valid DNS hostname."""


DOMAIN_OPTION_KEYS = (
    "scan_interval_hours",
    "include_subdomains",
    "max_live_hosts",
    "max_wayback_urls",
    "max_js_assets",
    "enable_gau",
    "enable_katana",
    "enable_hakrawler",
    "enable_js_analysis",
    "enable_ffuf",
    "enable_nuclei",
    "enable_screenshots",
    "enable_port_scan",
    "enable_search_intelligence",
)

BOOLEAN_OPTION_KEYS = {
    "include_subdomains",
    "enable_gau",
    "enable_katana",
    "enable_hakrawler",
    "enable_js_analysis",
    "enable_ffuf",
    "enable_nuclei",
    "enable_screenshots",
    "enable_port_scan",
    "enable_search_intelligence",
}

OPTION_LIMITS = {
    "scan_interval_hours": (1, 8760),
    "max_live_hosts": (1, 100000),
    "max_wayback_urls": (1, 100000),
    "max_js_assets": (1, 100000),
}

DOMAIN_PRESETS: dict[str, dict[str, Any]] = {
    "standard": {
        "scan_interval_hours": 48,
        "include_subdomains": True,
        "max_live_hosts": None,
        "max_wayback_urls": None,
        "max_js_assets": None,
        "enable_gau": True,
        "enable_katana": True,
        "enable_hakrawler": True,
        "enable_js_analysis": True,
        "enable_ffuf": False,
        "enable_nuclei": False,
        "enable_screenshots": True,
        "enable_port_scan": False,
        "enable_search_intelligence": True,
    },
    "light": {
        "scan_interval_hours": 72,
        "include_subdomains": True,
        "max_live_hosts": None,
        "max_wayback_urls": None,
        "max_js_assets": None,
        "enable_gau": True,
        "enable_katana": False,
        "enable_hakrawler": False,
        "enable_js_analysis": True,
        "enable_ffuf": False,
        "enable_nuclei": False,
        "enable_screenshots": True,
        "enable_port_scan": False,
        "enable_search_intelligence": True,
    },
    "expanded": {
        "scan_interval_hours": 48,
        "include_subdomains": True,
        "max_live_hosts": None,
        "max_wayback_urls": None,
        "max_js_assets": None,
        "enable_gau": True,
        "enable_katana": True,
        "enable_hakrawler": True,
        "enable_js_analysis": True,
        "enable_ffuf": True,
        "enable_nuclei": True,
        "enable_screenshots": True,
        "enable_port_scan": True,
        "enable_search_intelligence": True,
    },
}


def normalize_domain(value: Any) -> str:
    """Normalize a URL, wildcard, or hostname into a lowercase ASCII hostname."""
    raw = str(value or "").strip()
    if not raw:
        raise DomainValidationError("domain is required")
    if raw.startswith("*."):
        raw = raw[2:]

    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise DomainValidationError("domain contains an invalid host or port") from exc
    if not hostname or port is not None:
        raise DomainValidationError("enter a hostname without a port")

    hostname = hostname.rstrip(".").lower()
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainValidationError("domain contains invalid international characters") from exc
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise DomainValidationError("root domains must be DNS names, not IP addresses")

    if len(hostname) > 253 or "." not in hostname:
        raise DomainValidationError("enter a root domain such as example.com")
    labels = hostname.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise DomainValidationError("domain contains an invalid DNS label")
    return hostname


def parse_domain_values(value: Any) -> list[str]:
    """Parse a list or comma/newline-separated value and preserve first-seen order."""
    if isinstance(value, str):
        raw_values: Iterable[Any] = re.split(r"[\s,]+", value)
    elif isinstance(value, (list, tuple, set)):
        raw_values = value
    else:
        raise DomainValidationError("domains must be a list or comma/newline-separated text")

    domains: list[str] = []
    seen: set[str] = set()
    for item in raw_values:
        if not str(item or "").strip():
            continue
        domain = normalize_domain(item)
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    if not domains:
        raise DomainValidationError("at least one domain is required")
    if len(domains) > 100:
        raise DomainValidationError("add at most 100 domains in one request")
    return domains


def _coerce_bool(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "1", "yes", "on"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "0", "no", "off"}:
        return False
    raise DomainValidationError(f"{key} must be true or false")


def _coerce_bounded_int(value: Any, key: str, allow_none: bool) -> int | None:
    if value in (None, "") and allow_none:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DomainValidationError(f"{key} must be an integer") from exc
    minimum, maximum = OPTION_LIMITS[key]
    if not minimum <= parsed <= maximum:
        raise DomainValidationError(f"{key} must be between {minimum} and {maximum}")
    return parsed


def domain_options_from_payload(payload: dict[str, Any], *, preset_default: str = "standard") -> dict[str, Any]:
    """Apply a named preset and validated per-field overrides."""
    preset = str(payload.get("preset") or preset_default).strip().lower()
    if preset not in DOMAIN_PRESETS:
        raise DomainValidationError(f"unknown scan preset: {preset}")
    options = dict(DOMAIN_PRESETS[preset])
    supplied = payload.get("options")
    if supplied is None:
        supplied = {key: payload[key] for key in DOMAIN_OPTION_KEYS if key in payload}
    if not isinstance(supplied, dict):
        raise DomainValidationError("options must be an object")

    for key, value in supplied.items():
        if key not in DOMAIN_OPTION_KEYS:
            continue
        if key in BOOLEAN_OPTION_KEYS:
            options[key] = _coerce_bool(value, key)
        elif key == "scan_interval_hours":
            options[key] = _coerce_bounded_int(value, key, allow_none=False)
        else:
            options[key] = _coerce_bounded_int(value, key, allow_none=True)
    return options
