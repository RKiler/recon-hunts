#!/usr/bin/env python3
"""Dedicated, resumable domain-hunt worker over recon data packets."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import signal
from datetime import datetime
from pathlib import Path

import asyncpg
import yaml

from hunt_coordinator import excluded, root_host_allowed, safe_asset_display
from independent_hunt import IndependentHuntCoordinator, json_object
from hunt_signal_classifier import classify_route, route_hint


LOG = logging.getLogger("independent-hunt-worker")
OUT_ROOT = Path("/root/codex_artifacts/domain_hunts")
TABLES = {
    "subdomains": ("subdomains t", "t.domain_id = $1", "t.subdomain AS asset, t.is_resolved, t.ip_addresses"),
    "live_hosts": ("live_hosts t JOIN subdomains s ON s.id = t.subdomain_id", "s.domain_id = $1",
                   "t.url AS asset, t.status_code, t.title, t.webserver, t.port"),
    "endpoints": ("endpoints t JOIN live_hosts h ON h.id = t.live_host_id JOIN subdomains s ON s.id = h.subdomain_id",
                  "s.domain_id = $1", "h.url AS host, t.path AS asset, t.method, t.status_code, t.risk_tags, "
                  "jsonb_path_query_array(t.parameters, '$[0 to 15].name') AS param_names"),
    "url_parameters": ("url_parameters t JOIN endpoints e ON e.id = t.endpoint_id JOIN live_hosts h ON h.id = e.live_host_id JOIN subdomains s ON s.id = h.subdomain_id",
                       "s.domain_id = $1", "h.url AS host, e.path AS path, t.param_name AS asset, t.risk_tags"),
    "js_assets": ("js_assets t JOIN live_hosts h ON h.id = t.live_host_id JOIN subdomains s ON s.id = h.subdomain_id "
                  "LEFT JOIN LATERAL (SELECT id, risk_summary, extraction FROM js_analysis_results "
                  "WHERE js_asset_id = t.id ORDER BY id DESC LIMIT 1) ja ON TRUE",
                  "s.domain_id = $1", "h.url AS host, t.asset_url AS asset, t.http_status, t.sha256, t.size_bytes, "
                  "ja.id AS analysis_id, ja.risk_summary AS analysis_summary, "
                  "jsonb_path_query_array(ja.extraction, '$.endpoint_paths[0 to 19]') AS route_hints, "
                  "CASE WHEN jsonb_typeof(ja.extraction->'tokens_or_secret_like_strings') = 'array' "
                  "THEN jsonb_array_length(ja.extraction->'tokens_or_secret_like_strings') "
                  "ELSE 0 END AS secret_pattern_count"),
    "api_surfaces": ("api_surfaces t", "t.domain_id = $1",
                     "t.location AS asset, t.surface_type, t.status_code, t.auth_required, t.operations_count, t.risk_flags"),
    "technologies": ("technologies t JOIN live_hosts h ON h.id = t.live_host_id JOIN subdomains s ON s.id = h.subdomain_id",
                     "s.domain_id = $1", "h.url AS host, t.technology AS asset, t.version"),
    "screenshots": ("screenshots t JOIN live_hosts h ON h.id = t.live_host_id JOIN subdomains s ON s.id = h.subdomain_id",
                    "s.domain_id = $1", "h.url AS host, t.screenshot_path AS asset, t.capture_reason"),
    "findings": ("findings t", "t.domain_id = $1",
                 "t.location AS asset, t.finding_type, t.severity, t.is_resolved"),
    "ffuf_run_hits": ("ffuf_run_hits t JOIN ffuf_runs r ON r.id = t.ffuf_run_id", "r.domain_id = $1",
                      "r.host_url AS host, t.url AS asset, t.status_code, t.content_length"),
    "cloud_assets": ("cloud_assets t", "t.domain_id = $1",
                     "t.location AS asset, t.provider, t.asset_type, t.identifier"),
    "network_services": ("network_services t", "t.domain_id = $1",
                         "t.port AS asset, t.protocol, t.state, t.service, t.product, t.version"),
    "credential_leaks": ("credential_leaks t", "t.domain_id = $1",
                         "t.source_url AS asset, t.detector_name, t.detector_type, t.verified, t.is_resolved"),
    "asset_events": ("asset_events t", "t.domain_id = $1",
                     "t.location AS asset, t.event_type, t.entity_type, t.severity"),
    "scan_snapshots": ("scan_snapshots t", "t.domain_id = $1",
                       "t.scan_finished_at AS observed_at, t.first_run, t.new_counts"),
    "dns_records": ("dns_records t JOIN subdomains s ON s.id = t.subdomain_id", "t.domain_id = $1",
                    "s.subdomain AS host, t.value AS asset, t.record_type, t.is_current"),
    "subdomain_sources": ("subdomain_sources t JOIN subdomains s ON s.id = t.subdomain_id", "s.domain_id = $1",
                          "s.subdomain AS host, s.subdomain AS asset, t.source"),
    "infrastructure_ips": ("infrastructure_ips t", "t.domain_id = $1",
                           "t.ip_address AS asset, t.provider, t.asn_org, t.classification, t.scan_eligible"),
    "live_host_fingerprints": ("live_host_fingerprints t JOIN live_hosts h ON h.id = t.live_host_id "
                               "JOIN subdomains s ON s.id = h.subdomain_id", "s.domain_id = $1",
                               "h.url AS host, h.url AS asset, t.status_code, t.title, t.webserver, t.is_current"),
    "authz_observations": ("authz_observations t", "t.domain_id = $1",
                           "t.endpoint AS asset, t.method, t.actor, t.object_owner, t.status_code, t.response_hash"),
    "evidence_packs": ("evidence_packs t", "t.domain_id = $1",
                       "t.location AS asset, t.title, t.summary, t.severity, t.source_table AS origin_table, t.source_id"),
    "validation_queue": ("validation_queue t", "t.domain_id = $1",
                         "t.location AS asset, t.priority, t.status, t.source_table AS origin_table, t.source_id"),
    "asset_risk_scores": ("asset_risk_scores t", "t.domain_id = $1",
                          "t.location AS asset, t.score, t.priority, t.reasons, t.entity_type"),
    "monitor_intel_items": ("monitor_intel_items t", "t.domain_id = $1",
                            "t.source_url AS asset, t.item_type, t.risk, t.value"),
    "search_intel_results": ("search_intel_results t", "t.domain_id = $1 AND t.is_in_scope = TRUE",
                             "t.url AS asset, t.category, t.risk_tags, t.status_code, t.title"),
    "shodan_host_snapshots": ("shodan_host_snapshots t JOIN infrastructure_ips i ON i.id = t.ip_asset_id",
                              "t.domain_id = $1", "i.ip_address AS asset, t.ports, t.vulnerabilities, t.tags"),
}
DELTA_TIMESTAMPS = {
    "subdomains": "t.first_seen", "live_hosts": "t.first_seen", "endpoints": "t.first_seen",
    "url_parameters": "t.first_seen", "js_assets": "t.first_seen", "api_surfaces": "t.first_seen",
    "technologies": "t.first_seen", "screenshots": "t.captured_at", "findings": "t.first_seen",
    "ffuf_run_hits": "t.created_at", "cloud_assets": "t.first_seen",
    "network_services": "t.first_seen", "credential_leaks": "t.first_seen",
    "asset_events": "t.first_seen", "dns_records": "t.first_seen",
    "subdomain_sources": "t.first_seen", "infrastructure_ips": "t.first_seen",
    "live_host_fingerprints": "t.first_seen", "monitor_intel_items": "t.first_seen",
    "search_intel_results": "t.first_seen", "shodan_host_snapshots": "t.fetched_at",
}
SIGNAL = re.compile(
    r"(?i)(admin|internal|debug|swagger|graphql|oauth|sso|callback|redirect|webhook|upload|import|export|"
    r"report|download|file|token|secret|password|auth|login|invite|role|member|permission|billing|"
    r"checkout|payment|preview|search|query|filter|url|uri|source.?map|staging|dev|403|401)"
)
CONTEXT_STOP = {"about", "again", "application", "assets", "data", "domain", "find", "from", "have",
                "hunt", "look", "only", "please", "recon", "site", "test", "that", "this", "using", "with",
                "www", "http", "https", "api", "app", "web", "com", "net", "org", "io"}
CLIENT_FINDINGS = {"js_dom_xss_candidate", "js_dom_xss_sinks", "js_secret_like_strings",
                   "js_sensitive_admin_surface", "js_asset_changed"}
DOM_LEAD_RE = re.compile(r"\b(?:dom[ -]?xss|dom[ -]?based[ -]?xss)\b", re.I)
MESSAGE_LEAD_RE = re.compile(r"\b(?:postmessage|messageport|messagechannel|cross[ -]?origin messaging)\b", re.I)
SECRET_LEAD_RE = re.compile(
    r"\b(?:hardcoded (?:credential|secret|token|api key)s?|"
    r"(?:credential|secret|api key|token)(?:s)? (?:leak|exposure) in (?:js|javascript|bundle|source map)|"
    r"(?:js|javascript|bundle|source map) (?:credential|secret|api key|token)(?:s)? (?:leak|exposure))\b", re.I)


def json_safe(value):
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    return value


def json_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def context_terms(context: str, domain: str = "") -> list[str]:
    ignored = CONTEXT_STOP | set(domain.lower().split("."))
    return [term for term in dict.fromkeys(re.findall(r"[a-z][a-z0-9_-]{2,24}", context.lower()))
            if term not in ignored][:24]


def scoped_row(row: dict, domain: str, include_subdomains: bool, exclusions: list[str]) -> bool:
    host = str(row.get("host") or "")
    asset = str(row.get("asset") or "")
    if host and (not root_host_allowed(host, domain, include_subdomains) or excluded(host, exclusions)):
        return False
    if asset.startswith(("http://", "https://")) and (
        not root_host_allowed(asset, domain, include_subdomains) or excluded(asset, exclusions)
    ):
        return False
    if row.get("source_table") == "subdomains" and not root_host_allowed(asset, domain, include_subdomains):
        return False
    return not excluded(asset, exclusions)


def rank_row(row: dict, terms: list[str]) -> tuple[int, bool]:
    text = " ".join(str(row.get(key) or "") for key in
                    ("asset", "host", "path", "finding_type", "detector_name", "surface_type")).lower()
    if row.get("source_table") == "js_assets":
        text += " " + " ".join(str(hint) for hint in json_list(row.get("route_hints"))).lower()
    matched = any(term in text for term in terms) if terms else False
    if row.get("source_table") == "js_assets":
        if row.get("http_status") != 200 or not row.get("sha256"):
            return 0, matched
        risk = json_object(row.get("analysis_summary"))
        dom = int(risk.get("dom_source_sink_proximity_count") or 0)
        receiver = int(risk.get("postmessage_receiver_count") or 0)
        flow = int(risk.get("postmessage_data_flow_count") or 0)
        effect = int(risk.get("postmessage_sensitive_effect_count") or 0)
        secret = int(row.get("secret_pattern_count") or 0)
        routes = [classify_route(hint) for hint in json_list(row.get("route_hints"))]
        route_score = max((signal[1] for family in routes for signal in family), default=0)
        score = max(8 if dom else 0, 9 if receiver and flow and effect else 0,
                    4 if secret else 0, min(route_score, 6))
        return score + (2 if score and matched else 0), matched
    if row.get("source_table") in {"endpoints", "url_parameters"}:
        params = json_list(row.get("param_names")) if row["source_table"] == "endpoints" else [row.get("asset")]
        path = row.get("asset") if row["source_table"] == "endpoints" else row.get("path")
        route_score = max((signal[1] for signal in classify_route(path, params, row.get("method"))), default=0)
        if route_score:
            return route_score + (2 if matched else 0), matched
    if row.get("source_table") == "findings" and row.get("finding_type") in CLIENT_FINDINGS:
        return 0, matched
    if row.get("source_table") == "credential_leaks":
        score = 12 if row.get("verified") is True else 3
        return score + (2 if matched else 0), matched
    if (row.get("source_table") == "api_surfaces" and row.get("surface_type") == "graphql"
            and row.get("status_code") in {401, 403} and not row.get("operations_count")):
        return 0, matched
    score = 2 if SIGNAL.search(text) else 0
    if matched:
        score += 5
    if row.get("source_table") in {"findings", "credential_leaks", "api_surfaces"}:
        score += 2
    if row.get("status_code") in {401, 403, 500}:
        score += 1
    return score, matched


def candidate_classes(row: dict) -> list[str]:
    classes = []
    table = row.get("source_table")
    if table == "js_assets":
        risk = json_object(row.get("analysis_summary"))
        if int(risk.get("dom_source_sink_proximity_count") or 0):
            classes.append("dom_xss_static_hint")
        if all(int(risk.get(key) or 0) for key in (
            "postmessage_receiver_count", "postmessage_data_flow_count",
            "postmessage_sensitive_effect_count"
        )):
            classes.append("postmessage_static_hint")
        if int(row.get("secret_pattern_count") or 0):
            classes.append("credential_pattern_unverified")
        for path in json_list(row.get("route_hints")):
            classes.extend(item[0] for item in classify_route(path))
    elif table in {"endpoints", "url_parameters"}:
        path = row.get("asset") if table == "endpoints" else row.get("path")
        params = json_list(row.get("param_names")) if table == "endpoints" else [row.get("asset")]
        classes.extend(item[0] for item in classify_route(path, params, row.get("method")))
    return list(dict.fromkeys(classes))[:8]


async def enrich_top_endpoints(conn, top_signals: list[dict], domain: str,
                               include_subdomains: bool, exclusions: list[str]) -> None:
    endpoint_ids = [int(row["id"]) for row in top_signals
                    if row["source_table"] == "endpoints"][:24]
    if not endpoint_ids:
        return
    references = await conn.fetch("""
        SELECT selected.id AS endpoint_id, j.id AS js_asset_id, j.asset_url,
               j.sha256, j.http_status
        FROM unnest($1::integer[]) AS selected(id)
        JOIN LATERAL (
            SELECT js_asset_id FROM endpoint_js_references
            WHERE endpoint_id = selected.id ORDER BY id DESC LIMIT 3
        ) reference ON TRUE
        JOIN js_assets j ON j.id = reference.js_asset_id
    """, endpoint_ids)
    by_endpoint: dict[int, list[dict]] = {}
    for reference in references:
        url = str(reference["asset_url"] or "")
        if not root_host_allowed(url, domain, include_subdomains) or excluded(url, exclusions):
            continue
        by_endpoint.setdefault(reference["endpoint_id"], []).append({
            "js_asset_id": reference["js_asset_id"], "asset_url": safe_asset_display(url),
            "sha256": reference["sha256"], "http_status": reference["http_status"],
        })
    for row in top_signals:
        if row["source_table"] == "endpoints":
            row["related_js"] = by_endpoint.get(row["id"], [])


def client_proof_gap(item: dict, evidence_root: Path | None = None,
                     confirmed: bool = False) -> str | None:
    label = " ".join(str(item.get(key) or "") for key in ("title", "bug_class"))
    if DOM_LEAD_RE.search(label):
        required = ("current_asset_sha256", "reachable_route", "attacker_controlled_source",
                    "source_to_sink_trace", "sink")
    elif MESSAGE_LEAD_RE.search(label):
        required = ("current_asset_sha256", "receiver", "sender_control", "trust_check",
                    "protected_effect")
    elif SECRET_LEAD_RE.search(label):
        required = ("current_asset_sha256", "credential_class", "redacted_fingerprint",
                    "non_public_reason")
    else:
        return None
    proof = item.get("client_proof")
    missing = [key for key in required if not isinstance(proof, dict) or not proof.get(key)]
    if SECRET_LEAD_RE.search(label) and isinstance(proof, dict) and not re.fullmatch(
        r"sha256:[0-9a-fA-F]{64}", str(proof.get("redacted_fingerprint") or "")
    ):
        missing.append("SHA-256-only redacted_fingerprint")
    if confirmed and isinstance(proof, dict):
        if DOM_LEAD_RE.search(label) and proof.get("browser_execution") != "observed":
            missing.append("observed browser_execution")
        if MESSAGE_LEAD_RE.search(label) and proof.get("protected_effect_observed") is not True:
            missing.append("observed protected effect")
    if not missing and not re.fullmatch(r"[0-9a-fA-F]{64}", str(proof["current_asset_sha256"])):
        missing.append("valid current_asset_sha256")
    if evidence_root is not None:
        evidence = Path(str(item.get("evidence_path") or ""))
        if not item.get("evidence_path") or not (evidence if evidence.is_absolute() else evidence_root / evidence).is_file():
            missing.append("existing evidence_path")
        body_name = proof.get("asset_body_path") if isinstance(proof, dict) else None
        if not body_name:
            missing.append("asset_body_path")
        else:
            body = Path(str(body_name))
            body = (body if body.is_absolute() else evidence_root / body).resolve()
            if not body.is_relative_to(evidence_root.resolve()) or not body.is_file() or body.stat().st_size > 50 * 1024 * 1024:
                missing.append("saved current JS body under this pass")
            elif re.fullmatch(r"[0-9a-fA-F]{64}", str(proof.get("current_asset_sha256") or "")):
                digest = hashlib.sha256()
                with body.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != proof["current_asset_sha256"].lower():
                    missing.append("matching current JS body SHA-256")
    return "Missing current client-side proof: " + ", ".join(missing) if missing else None


def unverified_client_record(item: dict, reason: str) -> dict:
    return {"title": item.get("title", "Unverified client-side signal"), "reason": reason,
            "affected_asset": item.get("affected_asset"), "evidence_path": item.get("evidence_path"),
            "next_test": item.get("next_test")}


def general_proof_gap(item: dict, evidence_root: Path | None = None,
                      confirmed: bool = False) -> str | None:
    label = " ".join(str(item.get(key) or "") for key in ("title", "bug_class"))
    if any(pattern.search(label) for pattern in (DOM_LEAD_RE, MESSAGE_LEAD_RE, SECRET_LEAD_RE)):
        return None
    proof = item.get("hypothesis_proof")
    required = ("current_surface", "controlled_input", "trust_boundary",
                "observed_behavior", "decisive_next_test")
    missing = [key for key in required if not isinstance(proof, dict) or not proof.get(key)]
    if evidence_root is not None:
        evidence = Path(str(item.get("evidence_path") or ""))
        evidence = (evidence if evidence.is_absolute() else evidence_root / evidence).resolve()
        if not evidence.is_relative_to(evidence_root.resolve()) or not evidence.is_file():
            missing.append("existing evidence_path under this pass")
    if confirmed and not all(item.get(key) for key in ("baseline", "negative_control", "impact", "reproduction")):
        missing.append("baseline/control/impact/reproduction")
    return "Missing current hypothesis proof: " + ", ".join(missing) if missing else None


def normalize_result(result: dict, evidence_root: Path | None = None) -> dict:
    for field in ("leads", "confirmed_findings", "killed", "blocked", "evidence_files"):
        if not isinstance(result.get(field), list):
            result[field] = []
    result["summary"] = str(result.get("summary") or "")[:2000]
    leads = []
    for item in result["leads"]:
        if not isinstance(item, dict):
            continue
        gap = client_proof_gap(item, evidence_root) or general_proof_gap(item, evidence_root)
        if gap:
            result["blocked"].append(unverified_client_record(item, gap))
        else:
            leads.append(item)
    confirmed = []
    for item in result["confirmed_findings"]:
        if not isinstance(item, dict):
            continue
        required = ("title", "bug_class", "affected_asset", "evidence_path", "baseline",
                    "negative_control", "impact", "reproduction")
        gap = client_proof_gap(item, evidence_root, confirmed=True) or general_proof_gap(
            item, evidence_root, confirmed=True)
        if gap:
            result["blocked"].append(unverified_client_record(item, gap))
        elif not all(item.get(key) for key in required):
            item["review_reason"] = "Confirmation record lacks baseline, control, impact, reproduction, or evidence"
            leads.append(item)
        else:
            confirmed.append(item)
    result["leads"] = leads
    result["confirmed_findings"] = confirmed
    skills = result.get("skills_used")
    if not isinstance(skills, list):
        skills = []
    result["skills_used"] = list(dict.fromkeys(
        str(skill).strip()[:160] for skill in skills if str(skill).strip()
    ))[:8]
    try:
        result["active_request_count"] = max(0, int(result.get("active_request_count") or 0))
    except (TypeError, ValueError):
        result["active_request_count"] = 0
    return result


def source_filter(run: dict, table: str, predicate: str) -> tuple[str, list]:
    params = [run["domain_id"]]
    if run.get("data_source") != "delta":
        return predicate, params
    scans = run.get("delta_scans") or []
    if not scans:
        raise ValueError("Selected delta scans are unavailable")
    if table == "scan_snapshots":
        return predicate + " AND t.id = ANY($2::bigint[])", [run["domain_id"], [scan["id"] for scan in scans]]
    timestamp = DELTA_TIMESTAMPS[table]
    windows = []
    for scan in scans:
        start = len(params) + 1
        params.extend((scan["scan_started_at"], scan["scan_finished_at"]))
        windows.append(f"({timestamp} >= ${start} AND {timestamp} <= ${start + 1})")
    return predicate + " AND (" + " OR ".join(windows) + ")", params


async def build_packet(conn, run: dict, exclusions: list[str]) -> tuple[dict, dict, bool]:
    """Walk every selected table by stable descending ID, never via bug_jobs."""
    cursor = json_object(run.get("cursor"))
    floors = dict(cursor.get("floors") or {})
    uppers = dict(cursor.get("uppers") or {})
    next_lt = dict(cursor.get("next_lt") or {})
    tables = {name: spec for name, spec in TABLES.items()
              if run.get("data_source") != "delta" or name in DELTA_TIMESTAMPS or name == "scan_snapshots"}
    if not uppers:
        for table, (source, predicate, _) in tables.items():
            filtered, params = source_filter(run, table, predicate)
            uppers[table] = int(await conn.fetchval(
                f"WITH scoped AS MATERIALIZED (SELECT t.id FROM {source} WHERE {filtered}) "
                "SELECT COALESCE(MAX(id), 0) FROM scoped", *params,
            ) or 0)
            next_lt[table] = uppers[table] + 1
            floors.setdefault(table, 0)
    active_tables = sum(int(next_lt.get(table, 0)) > int(floors.get(table, 0)) + 1 for table in tables)
    quota = max(1, (int(run["records_per_pass"]) + max(active_tables, 1) - 1) // max(active_tables, 1))
    all_rows = []
    processed = {}
    for table, (source, predicate, fields) in tables.items():
        floor = int(floors.get(table, 0))
        upper = int(uppers.get(table, 0))
        before = int(next_lt.get(table, upper + 1))
        if before <= floor + 1:
            processed[table] = 0
            continue
        filtered, params = source_filter(run, table, predicate)
        first = len(params) + 1
        rows = await conn.fetch(
            f"WITH scoped AS MATERIALIZED (SELECT t.id, {fields} FROM {source} WHERE {filtered} "
            f"AND t.id > ${first} AND t.id < ${first + 1} AND t.id <= ${first + 2}) "
            f"SELECT * FROM scoped ORDER BY id DESC LIMIT ${first + 3}",
            *params, floor, before, upper, quota,
        )
        processed[table] = len(rows)
        if rows:
            next_lt[table] = int(rows[-1]["id"])
        if len(rows) < quota:
            next_lt[table] = floor + 1
        for raw in rows:
            row = {"source_table": table, **json_safe(dict(raw))}
            if run.get("data_source") == "delta":
                row["delta_basis"] = "selected_snapshot_id" if table == "scan_snapshots" else DELTA_TIMESTAMPS[table]
            row["asset"] = safe_asset_display(row.get("asset")) if str(row.get("asset") or "").startswith(("http://", "https://")) else str(row.get("asset") or "")[:350]
            if table == "js_assets":
                row["route_hints"] = list(dict.fromkeys(filter(None, (
                    route_hint(value) for value in json_list(row.get("route_hints"))
                ))))
            if table == "endpoints":
                row["param_names"] = [str(value)[:80] for value in json_list(row.get("param_names"))]
            if scoped_row(row, run["domain"], run["include_subdomains"], exclusions):
                all_rows.append(row)
    complete = all(int(next_lt.get(table, 0)) <= int(floors.get(table, 0)) + 1 for table in tables)
    terms = context_terms(str(run.get("application_context") or ""), run["domain"])
    ranked = []
    for row in all_rows:
        score, matched = rank_row(row, terms)
        if row["source_table"] == "findings" and row.get("finding_type") in CLIENT_FINDINGS:
            continue
        if run["data_scope"] == "context" and terms and not matched:
            continue
        if run["data_scope"] == "all" and score == 0:
            continue
        ranked.append((score, row))
    ranked.sort(key=lambda pair: (pair[0], pair[1]["id"]), reverse=True)
    source_limits = {"endpoints": 24, "url_parameters": 14, "js_assets": 18}
    source_rows: dict[str, list[dict]] = {}
    seen_top = set()
    for _, row in ranked:
        if row["source_table"] == "js_assets" and row.get("sha256"):
            key = ("js_body", row["sha256"])
        else:
            key = (row["source_table"], row.get("host"), row.get("asset"),
                   row.get("method"), row.get("finding_type"))
        if key in seen_top:
            continue
        seen_top.add(key)
        table = row["source_table"]
        bucket = source_rows.setdefault(table, [])
        if len(bucket) < source_limits.get(table, 5):
            bucket.append({**row, "candidate_classes": candidate_classes(row)})
    top_signals = []
    while len(top_signals) < 80 and any(source_rows.values()):
        for table in list(source_rows):
            if source_rows[table]:
                top_signals.append(source_rows[table].pop(0))
                if len(top_signals) == 80:
                    break
    await enrich_top_endpoints(conn, top_signals, run["domain"],
                               run["include_subdomains"], exclusions)
    packet = {
        "run_id": run["id"], "domain": run["domain"], "data_scope": run["data_scope"],
        "data_source": run.get("data_source", "all"),
        "delta_scans": json_safe(run.get("delta_scans") or []),
        "application_context": run["application_context"], "records_examined": sum(processed.values()),
        "processed_counts": processed, "context_terms": terms,
        "selected_count": len(ranked), "top_signals": top_signals,
        "rows": all_rows, "scope_exclusions": exclusions,
    }
    next_cursor = {"floors": floors, "uppers": uppers, "next_lt": next_lt,
                   "cycle": int(cursor.get("cycle") or 1)}
    return packet, next_cursor, complete


async def build_action_packet(conn, run: dict, action_id: int,
                              exclusions: list[str]) -> tuple[dict, dict, bool]:
    """Build one bounded validation packet from a durable research action."""
    action = await conn.fetchrow("""
        SELECT a.id, a.hypothesis_id, a.state, a.purpose, a.baseline_ref,
               a.negative_control_ref, a.mutation_dimension, a.stop_conditions,
               a.cleanup_plan, h.bug_family, h.title, h.affected_asset, h.feature,
               h.controlled_input, h.boundary_class, h.actor_context,
               h.state AS hypothesis_state, h.evidence_level, h.next_action,
               h.missing_proof, h.latest_summary
        FROM hunt_actions a JOIN hunt_hypotheses h ON h.id=a.hypothesis_id
        WHERE a.id=$1 AND a.run_id=$2 AND h.run_id=$2
    """, action_id, run["id"])
    if not action:
        raise ValueError("Research action is unavailable for this hunt")
    events = await conn.fetch("""
        SELECT p.sequence, e.event_type, e.from_state, e.to_state,
               e.evidence_level, e.created_at
        FROM hunt_hypothesis_events e
        LEFT JOIN hunt_passes p ON p.id=e.pass_id
        WHERE e.hypothesis_id=$1 ORDER BY e.created_at DESC LIMIT 12
    """, action["hypothesis_id"])
    evidence_paths = await conn.fetchval("""
        SELECT COALESCE(array_agg(evidence_path ORDER BY created_at DESC), ARRAY[]::text[])
        FROM hunt_evidence_refs WHERE hypothesis_id=$1
    """, action["hypothesis_id"])
    action_data = json_safe(dict(action))
    action_data["prior_events"] = [json_safe(dict(item)) for item in events]
    action_data["evidence_paths"] = list(evidence_paths or [])[:20]
    packet = {
        "run_id": run["id"], "domain": run["domain"],
        "work_type": "research_action", "research_action": action_data,
        "data_scope": run["data_scope"], "data_source": run.get("data_source", "all"),
        "application_context": run["application_context"], "records_examined": 0,
        "processed_counts": {}, "selected_count": 1,
        "top_signals": [{
            "source_table": "hunt_actions", "id": int(action["id"]),
            "asset": safe_asset_display(action["affected_asset"]),
            "candidate_classes": [action["bug_family"]],
            "title": action["title"], "purpose": action["purpose"],
        }],
        "rows": [], "scope_exclusions": exclusions,
    }
    cursor = json_object(run.get("cursor"))
    return packet, cursor, bool(json_object(run.get("coverage")).get("last_packet_exhausted"))


def build_prompt(run: dict, pass_id: int, packet_path: Path, packet: dict,
                 artifact_dir: Path, accounts: list[dict]) -> str:
    signup_instructions = (
        "Target signup is enabled for this campaign by the operator. The existing restricted Gmail bridge is at "
        "/app/scripts/agentic_mail_client.py; use `health` first and stop if unavailable. It can check the operator's "
        "mailbox, find recent HTTPS verification messages for one exact host, and open a one-time same-host handle. "
        "It cannot create Gmail accounts or bypass CAPTCHA/MFA. Before submitting any target registration, verify that "
        "the exact program rules explicitly allow owned test-account registration and that the signup host is in scope. "
        "If either is unclear, do not submit. Use a unique plus-address only if the program permits multiple owned "
        "accounts and the target accepts it; do not assume aliases create a distinct identity. After a permitted signup, "
        "record its UTC submission time, use `find --host <exact-host> --after <UTC-ISO-time>`, then open only the "
        "returned handle with `open --host <exact-host> --handle <opaque-handle> --confirm-owned-signup`. The helper "
        "does not reveal message bodies or verification URLs and blocks off-host navigation. Verify the new identity and "
        "tenant with a harmless self/profile GET before tests. Never include mailbox address, alias, message details, or "
        "verification handles in evidence. Stop for operator VNC on CAPTCHA/MFA or unexpected consent."
        if run.get("target_signup_enabled") else
        "Target application signup is disabled for this campaign. Do not submit a registration form or open a verification email."
    )
    if packet.get("work_type") == "research_action":
        focus = (
            "This is a durable research-action pass. Work only the research_action in the packet. "
            "Re-read its prior dispositions and evidence, select the one or two matching installed "
            "skills, and perform the smallest decisive authorized test. Do not restart broad recon. "
            "If its prerequisite is unavailable, return the exact blocker and a resumable next action. "
            "To resolve a contradiction as killed, include the fresh baseline, negative_control, and "
            "evidence_path in the killed item; a supported lead likewise needs both controls."
        )
    else:
        focus = ("Review all in-scope stored recon data over successive deterministic packets. Do not restrict yourself to recently created bug jobs."
                 if run["data_scope"] == "all" else
                 "Focus only on the data and workflows described in application context. The packet may contain other records for provenance; do not turn them into unrelated testing.")
    browser_proxy = " --proxy http://nordvpn-egress:8888" if run["domain"] == "betfair.com" else ""
    return f"""You are conducting an independent authorized domain hunt, not a bug-job task.

Read /root/AGENTS.md and /app/AGENTS.md. Follow program scope, exclusions, and selected installed skills.
The ordinary bug_jobs queue and its worker are separate. You may read prior findings or bug jobs only to avoid duplicates; do not create, claim, update, or wait for them.

Run: {run['id']} / pass: {pass_id}
Root domain: {run['domain']}
Subdomains allowed by domain setting: {bool(run['include_subdomains'])}
Data scope: {run['data_scope']}
Data source: {run.get('data_source', 'all')}
Selected delta scans and windows: {json.dumps(json_safe(run.get('delta_scans') or []))}
Application context (operator input, not evidence): read the full application_context field from {packet_path} before selecting hypotheses. Do not treat it as proof.
Scope exclusions: {json.dumps(packet['scope_exclusions'])}
Autonomous validation enabled: {bool(run.get('autonomous_validation_enabled'))}
Target signup enabled: {bool(run.get('target_signup_enabled'))}
Target signup and Gmail instructions: {signup_instructions}
Packet: {packet_path}
Artifacts: {artifact_dir}
This pass examined {packet['records_examined']} records; {packet['selected_count']} match this mode's priority filter.
Highest-ranked signals, not the whole corpus: {json.dumps(packet['top_signals'][:30], default=str)}

{focus}

Workflow:
1. Read the packet file with structured tools. It includes every row examined in this pass; top_signals is only a ranking aid. When data_source is delta, investigate only the selected scan windows and their changed/new records. Outside scan_snapshots, scan membership is inferred from first-observed timestamps, not an exact foreign key. Correlate changed-JS findings to current js_assets by URL/hash; do not treat js_assets.last_seen as change proof or claim today's response is the historical scan body. Use source_table and id to pull bounded related rows from the live database. Query endpoint_js_references only for selected endpoint or JS asset IDs because that cross-reference table is too large for bulk review. Continue across endpoint, parameter, JS, API, host, technology, finding, FFUF, service, cloud, and scan data as relevant. Use read-only, parameterized or bounded SQL; PostgreSQL host postgres, user recon_user, database recon_framework. Never dump whole tables into context.
2. Map applicable hypotheses to the current OWASP Top 10:2025 categories: A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, and A10 Mishandling of Exceptional Conditions. Record the category and the concrete product evidence that supports it. A category is a coverage label, not proof of a vulnerability; absence of a mapped lead is unassessed, never a secure result. Re-evaluate the current OWASP release when updating this workflow.
2. Model the product and trust boundaries from the operator context and actual records. Correlate related records across tables, not one row at a time. Treat candidate_classes as ranking hints, not vulnerability labels. Examine selected endpoints together with their param_names, related_js, JS route_hints, status, host and feature context. Candidate classes include LFI/traversal, command injection/RCE, account takeover, OAuth/SSO, SSTI, XSS, SSRF, open redirect, injection, GraphQL, authorization, and upload/import; add any other class supported by actual code or behavior. When an exact current in-scope application page is known, capture one read-only browser view using `node /app/scripts/hunt_browser_capture.cjs --root-domain {run['domain']} --include-subdomains {str(bool(run['include_subdomains'])).lower()} --url '<exact scoped page URL>' --output '{artifact_dir}/browser_capture.json'{browser_proxy}` and add each excluded hostname with `--exclude '<host>'`. For Betfair, verify the proxy's UK egress before target navigation and stop active requests if it is unavailable. For an authenticated page, use `--storage-state '<verified per-account session_file>' --session-host '<exact page hostname>'` only after proving that account's identity; never merge states. The helper blocks out-of-scope and non-read requests, limits first-party resources, and records in-scope runtime request methods/paths, forms, links, and loaded JS without dumping page bodies, cookies, or values. Follow a newly observed endpoint or script only after another scope check; compare runtime request method/schema against static JS and recon records. If a relevant page cannot be opened, record why and continue static/endpoint analysis. Count browser requests in active_request_count. Do not click submit controls or claim a route is live from a JS string alone. For an authenticated hypothesis, do not trust account alias, role, or tenant labels as identity proof. After a normal login on the credential's exact host, use an observed, harmless self/profile or account-membership GET endpoint to establish the actual user, active account/tenant, role, and available memberships for each owned session. Record only redacted identity metadata and the endpoint used. If the application supports multiple accounts or organizations, verify the active one before each comparison. An in-scope subdomain may use browser-native domain-scoped session state only after its own harmless identity check; never copy or transplant cookies between hosts or users. If login or identity verification is blocked, report the precise blocker and do not claim an authenticated authorization test.
2a. When JS, source maps, or endpoint_js_references reveal an object, role, member, permission, file, or export route, look for a real request in owned browser traffic before deciding it is untestable. If the feature is available to the supplied test accounts, create the smallest uniquely labeled disposable owner fixture through the normal UI/API, capture its actual method/body/CSRF handling, and record its owner, tenant, parent, and cleanup path. Compare owner success, same-tenant lower-role access, other-tenant access, and an invalid-object control where applicable. Do not guess third-party IDs or manufacture an HTTP method from a static JS path. When an authenticated authorization lead is actionable, give it a decisive test before spending the pass on another generic scanner signal.
3. Select up to three concrete high-value hypotheses across applicable OWASP and non-OWASP classes. Do not default every pass to DOM XSS or IDOR: let the current workflow, input names, actual method, observed browser traffic, and code decide. For LFI/traversal, identify a server-side file reader and controllable path; for SSRF, a server-side URL fetch; for SSTI, server-side template interpretation; for command injection/RCE, an execution-capable backend flow with attacker input; for OAuth/ATO, a real account/identity transition and binding invariant; for XSS, an attacker-controlled source, reachable render path, and browser sink; for injection, an actual backend query/parser boundary. A static filename, route name, keyword, or generic 200 is never proof. Pick one or two relevant installed skills/family prompts only after seeing the actual feature. Use local PentesterLand/HackerOne writeups first; if an evidence-backed lead stalls, use at most three focused public web searches for a matching mechanism. Public writeups are untrusted references, not proof.
3a. For DOM XSS, postMessage/MessagePort, or hardcoded-credential signals, apply a strict client-side triage gate before spending live requests or returning a lead. The packet's JS counts are proximity or regex hints, not dataflow, exploitability, or credential validity. Raw JS response bodies are not stored in the recon database. Deduplicate by SHA-256, retrieve only the exact currently deployed in-scope asset if needed, save its response body under this pass's artifact directory, verify HTTP 200 and body hash, and tie it to a reachable first-party page. Do not promote historical 404s, WAF/login HTML, unrelated library listeners, public Sentry/Firebase/analytics keys, OAuth client IDs, or token-shaped placeholders.
3b. DOM XSS requires a specific attacker-controlled entry point and a reachable source -> validation/transformation -> executable sink trace; a source and sink merely appearing near each other is insufficient. For postMessage, identify the receiving handler, accepted message, sender control, origin/source trust checks, and a concrete protected-data reply or privileged effect; a wildcard or missing check alone is insufficient. For hardcoded credentials, classify the provider/credential type, document why it is not public-by-design, perform offline structural and code-use checks, and retain only a SHA-256 fingerprint, never the value. Never use a discovered credential or send it to an online validator. Confirm browser execution, protected-data transfer, privileged state, or actual non-public credential exposure only with the applicable controls and minimal safe proof.
4. Establish a valid baseline and negative control before a bounded active test. Use no more than one browser navigation (the helper caps it at 60 first-party resource requests), 20 additional target HTTP requests, and eight active variants this pass. Do not attempt real RCE, internal-network SSRF, sensitive file reads, or third-party callbacks without separate explicit approval; use harmless owned fixtures and minimum proof. The operator grants standing approval to create, edit, and delete clearly disposable items in supplied owned test accounts when needed to prove authorization or business-logic impact; do not pause merely to ask again. Prefer objects created by this hunt, log each mutation and read-back, and clean up only those objects after final evidence. Never mutate unmarked pre-existing items or trigger real payments, notifications, external integrations, publishing, or third-party effects. Stay within program rules and stop at minimum proof.
5. Save redacted evidence and a concise investigation_log.md under the artifact directory. Separate confirmed, possible, killed, blocked, and duplicate. Do not report a route name, status code, static sink, or old writeup as a current bug.

Selected owned accounts (aliases and exact hosts only; secret files must never be printed):
{json.dumps(accounts, indent=2)}

Credential-file handling: a selected cookie account may use either a raw Cookie
value or a one-line JSON header bundle with the shape {{"headers":{{"Cookie":"...",
"X-Csrf-Token":"..."}}}}. When a header bundle is present, apply all contained
headers together only to that account's exact authorized host. Never print,
persist in prompts, or expose the header values in evidence.

Credential scope clarification: do not assume that an account, password, cookie,
CSRF token, or session is valid for another hostname. A related first-party host
may be tested only when it is explicitly in the target's authorized scope and
the operator has identified that account for that exact host. Verify identity
separately on every host; never copy Cookie, X-Csrf-Token, session state, or
browser storage between hosts. Use the application's normal host-specific
login or OAuth flow when required. Never create Gmail or other email-provider
accounts. A target application account may be created only when
target_signup_enabled is true for this run and exact program rules expressly
allow owned registration; follow the restricted mailbox instructions earlier
in this prompt and stop for human VNC action on CAPTCHA, MFA, or consent.

For type login_file, the private secret file is JSON with email and password. The visible-browser login broker prepares a separate session_file for each account. Do not open the password file unless needed to troubleshoot the owned login flow. Use each session_file only for its account and allowed host; never print cookies, email, password, authorization headers, or full storage state. Before an authenticated comparison, call a legitimate observed self/profile or membership GET endpoint separately with each session and record the actual identity, active tenant, role, and memberships in redacted form. Reject a session if it is expired, belongs to the wrong identity, or cannot be verified. Do not copy cookies between users or manually transplant cookies to other hosts. If login is expired or CAPTCHA/MFA recurs, request a fresh isolated visible login with `python3 /app/independent_hunt.py --request-relogin --run-id {run['id']} --account-id <account id> --wait-seconds 1500`. The broker alerts the operator and waits for completion in VNC. Do not bypass, repeatedly retry, or claim authentication before a fresh identity check. If still pending, report the exact blocker and continue safe offline work only.

For the Zapier hunt only, each owned account's existing credentials also apply to first-party Sidekick. This means the same credentials for a given account, not that all three accounts share an identity. Keep all three browser profiles isolated. Sidekick uses its normal "Sign in with Zapier" OAuth flow; the browser obtains the NextAuth CSRF token from /api/auth/csrf automatically. Do not add a speculative CSRF header or manually reuse a callback code. Use sidekick_session_file only for that account and only after /api/bridge/sidekick/v0/me returns 200 with a real user ID, email matching the owned account, and account ID. Sidekick's /api/auth/session may return an empty object even when the bridge identity is authenticated; do not use that response alone to reject or accept login. A successful OAuth redirect or a status code alone is not authentication. If the verified /me identity is absent or wrong, mark Sidekick tests blocked, request the operator's VNC login, and continue other safe work.

Return JSON only with keys: status (continue|complete|blocked), summary, leads (array), confirmed_findings (array), killed (array), blocked (array), next_focus, evidence_files (array), skills_used (array), active_request_count (integer). In skills_used, name only the one or two installed skills whose complete methodology you actually read and applied in this pass; return an empty array when none fit. Each lead/finding must include title, bug_class, affected_asset, evidence_path, and a precise next_test or proof. For non-client-side classes, include hypothesis_proof with current_surface, controlled_input, trust_boundary, observed_behavior, and decisive_next_test. An endpoint/parameter name alone is not observed behavior. The evidence_path must point to a redacted file under this pass. Every client_proof must include asset_body_path (a saved JS body under this pass) and its current_asset_sha256; the worker checks that file's hash. For DOM XSS also include reachable_route, attacker_controlled_source, source_to_sink_trace, and sink. For postMessage also include receiver, sender_control, trust_check, and protected_effect. For hardcoded credentials also include credential_class, redacted_fingerprint formatted as sha256:<64 hex chars>, and non_public_reason. Explain unresolved execution or validity separately; do not manufacture proof fields to satisfy the schema. Signals missing those fields belong in blocked or killed, not leads. A confirmed DOM XSS additionally requires client_proof.browser_execution='observed'; a confirmed postMessage issue requires client_proof.protected_effect_observed=true. A confirmed finding must also include baseline, negative_control, impact, and reproduction fields, with actual current-target evidence in the referenced file. Otherwise put it in leads. The deterministic packet cursor, not your status field, decides whether all stored rows were covered.
"""


class LoginPending(Exception):
    """An owned account still needs human login in the visible browser."""


class HuntWorker:
    def __init__(self, pool: asyncpg.Pool, config: dict):
        self.pool = pool
        self.config = config
        self.coordinator = IndependentHuntCoordinator(pool, config)
        scan = config.get("scan", {})
        self.codex_bin = str(scan.get("codex_bin") or "codex")
        self.timeout = max(300, int(scan.get("hunt_worker_timeout_seconds", 2700)))
        self.model = str(scan.get("hunt_worker_model") or scan.get("codex_worker_model") or "").strip()
        self.reasoning_effort = str(scan.get("hunt_worker_reasoning_effort") or "medium").strip()

    async def wait_for_owned_logins(self, run: dict, account_rows, artifact_dir: Path) -> None:
        login_accounts = [item for item in account_rows if item["credential_type"] == "login_file"]
        if not login_accounts:
            return
        run_dir = artifact_dir.parent
        session_dir = run_dir / "sessions"
        session_dir.mkdir(mode=0o700, exist_ok=True)
        session_dir.chmod(0o700)
        request_path = run_dir / "login_request.json"
        request = {"run_id": run["id"], "domain": run["domain"], "accounts": [
            {"id": int(item["id"]), "alias": item["alias"], "exact_host": item["host"],
             "secret_file": item["secret_file"]} for item in login_accounts
        ]}
        temporary = request_path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(request, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, request_path)
        if any((session_dir / f"account_{item['id']}.status.json").exists() and
               json_object((session_dir / f"account_{item['id']}.status.json").read_text()).get("status") == "blocked_host"
               for item in login_accounts):
            raise RuntimeError("Owned login host is outside the selected root domain")
        if not all((session_dir / f"account_{item['id']}.json").is_file() for item in login_accounts):
            raise LoginPending("Waiting for owned-account login through VNC")

    async def queue_due(self) -> None:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT h.id FROM hunt_runs h JOIN domains d ON d.id = h.domain_id
                WHERE h.status = 'active' AND d.active = TRUE
                  AND h.next_pass_at IS NOT NULL AND h.next_pass_at <= NOW()
                  AND (h.mode = 'continuous' OR h.completed_at IS NULL OR EXISTS (
                      SELECT 1 FROM hunt_actions a WHERE a.run_id=h.id
                        AND h.autonomous_validation_enabled=TRUE
                        AND a.state IN ('proposed', 'ready')
                  ))
                ORDER BY h.next_pass_at LIMIT 20
            """)
        for row in rows:
            with contextlib.suppress(ValueError):
                await self.coordinator.refresh_run(row["id"])

    async def claim(self):
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                claimed = await conn.fetchrow("""
                    UPDATE hunt_passes p SET status = 'running', started_at = NOW(), error = NULL
                    WHERE p.id = (
                        SELECT q.id FROM hunt_passes q JOIN hunt_runs h ON h.id = q.run_id
                        JOIN domains d ON d.id = h.domain_id
                        WHERE q.status = 'queued' AND h.status = 'active' AND d.active = TRUE
                          AND (q.action_id IS NULL OR h.autonomous_validation_enabled=TRUE)
                          AND (h.next_pass_at IS NULL OR h.next_pass_at <= NOW())
                        ORDER BY q.created_at LIMIT 1 FOR UPDATE OF q SKIP LOCKED
                    ) RETURNING p.id, p.run_id, p.sequence, p.action_id
                """)
                if claimed and claimed["action_id"]:
                    await conn.execute("""
                        UPDATE hunt_actions SET state='started', updated_at=NOW()
                        WHERE id=$1 AND state='ready'
                    """, claimed["action_id"])
                return claimed

    async def run_pass(self, pass_row) -> None:
        pass_id = int(pass_row["id"])
        run_id = int(pass_row["run_id"])
        action_id = int(pass_row["action_id"]) if pass_row["action_id"] else None
        artifact_dir = OUT_ROOT / f"run_{run_id}" / f"pass_{pass_row['sequence']}"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir.chmod(0o700)
        async with self.pool.acquire() as conn:
            run_record = await conn.fetchrow("""
                SELECT h.*, d.domain, d.include_subdomains FROM hunt_runs h
                JOIN domains d ON d.id = h.domain_id WHERE h.id = $1
            """, run_id)
            run = dict(run_record)
            if run["data_source"] == "delta":
                scan_rows = await conn.fetch("""
                    SELECT id, scan_started_at, scan_finished_at FROM scan_snapshots
                    WHERE domain_id=$1 AND first_run=FALSE AND scan_finished_at IS NOT NULL
                      AND id=ANY($2::bigint[])
                    ORDER BY scan_finished_at DESC, id DESC
                """, run["domain_id"], list(run["delta_scan_ids"] or []))
                if len(scan_rows) != len(run["delta_scan_ids"] or []):
                    raise ValueError("A selected delta scan is no longer available")
                run["delta_scans"] = [dict(row) for row in scan_rows]
            scope_rules = await conn.fetch("""
                SELECT pattern FROM scope_rules WHERE enabled = TRUE
                AND (domain_id = $1 OR domain_id IS NULL)
                AND rule_type IN ('exclude', 'deny', 'out_of_scope')
            """, run["domain_id"])
            exclusions = [str(item["pattern"]) for item in scope_rules]
            exclusions.extend(self.config.get("scan", {}).get("out_of_scope_patterns", []) or [])
            account_rows = await conn.fetch("""
                SELECT hc.id, hc.alias, hc.role, hc.tenant, hc.host, hc.credential_type,
                       hc.header_name, hc.secret_file FROM hunt_run_credentials hrc
                JOIN hunt_credentials hc ON hc.id = hrc.credential_id
                WHERE hrc.run_id = $1 AND hc.domain_id = $2 ORDER BY hc.alias
            """, run_id, run["domain_id"])
            accounts = [{"id": int(item["id"]), "alias": item["alias"], "role": item["role"], "tenant": item["tenant"],
                         "exact_host": item["host"], "type": item["credential_type"],
                         "header": item["header_name"],
                         "secret_file": "/root/codex_artifacts/hunt_credentials/" + item["secret_file"],
                         "session_file": str(artifact_dir.parent / "sessions" / f"account_{item['id']}.json")
                         if item["credential_type"] == "login_file" else None,
                         "sidekick_session_file": str(artifact_dir.parent / "sessions" / f"account_{item['id']}_sidekick.json")
                         if run["domain"] == "zapier.com" and item["credential_type"] == "login_file" else None}
                        for item in account_rows]
        await self.wait_for_owned_logins(run, account_rows, artifact_dir)
        async with self.pool.acquire() as conn:
            if action_id:
                packet, next_cursor, exhausted = await build_action_packet(
                    conn, run, action_id, exclusions
                )
            else:
                packet, next_cursor, exhausted = await build_packet(conn, run, exclusions)
        packet_path = artifact_dir / "packet.json"
        prompt_path = artifact_dir / "prompt.md"
        output_path = artifact_dir / "result.json"
        packet_path.write_text(json.dumps(packet, indent=2, default=str) + "\n", encoding="utf-8")
        prompt_path.write_text(build_prompt(run, pass_id, packet_path, packet, artifact_dir, accounts), encoding="utf-8")
        for path in (packet_path, prompt_path):
            path.chmod(0o600)
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE hunt_actions a SET state='ready', updated_at=NOW()
                FROM hunt_passes p
                WHERE p.action_id=a.id AND p.status='running' AND a.state='started'
            """)
            await conn.execute("""
                UPDATE hunt_passes SET packet_path=$2, prompt_path=$3,
                    cursor_before=$4::jsonb, cursor_after=$5::jsonb,
                    processed_counts=$6::jsonb WHERE id=$1
            """, pass_id, str(packet_path), str(prompt_path), json.dumps(json_object(run.get("cursor"))),
                 json.dumps(next_cursor), json.dumps(packet["processed_counts"]))
        result = {"status": "continue", "summary": "No selected records in this packet.",
                  "leads": [], "confirmed_findings": [], "killed": [], "blocked": [],
                  "next_focus": "Next recon packet", "evidence_files": [], "skills_used": [],
                  "active_request_count": 0}
        if packet["selected_count"]:
            command = [self.codex_bin, "--search", "exec", "--ignore-user-config",
                       "--skip-git-repo-check", "--sandbox", "danger-full-access", "--cd", str(artifact_dir),
                       "--output-last-message", str(output_path)]
            if self.model:
                command += ["--model", self.model]
            if self.reasoning_effort:
                command += ["--config", f'model_reasoning_effort="{self.reasoning_effort}"']
            command.append("-")
            stdout_path = artifact_dir / "codex.stdout.log"
            stderr_path = artifact_dir / "codex.stderr.log"
            with prompt_path.open("rb") as prompt_file, stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
                stdout_path.chmod(0o600)
                stderr_path.chmod(0o600)
                env = {"HOME": "/root", "PATH": os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin"),
                       "LANG": "C.UTF-8", "TERM": "dumb", "PGPASSWORD": os.getenv("RECON_DB_PASSWORD", ""),
                       "PGOPTIONS": "-c default_transaction_read_only=on -c statement_timeout=12000"}
                process = await asyncio.create_subprocess_exec(
                    *command, cwd=str(artifact_dir), env=env, stdin=prompt_file,
                    stdout=stdout_file, stderr=stderr_file, start_new_session=True,
                )
                try:
                    await asyncio.wait_for(process.wait(), timeout=self.timeout)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGTERM)
                    await process.wait()
                    raise TimeoutError(f"Hunt pass exceeded {self.timeout}s")
                if process.returncode:
                    raise RuntimeError(f"Codex exited {process.returncode}; see {stderr_path}")
            raw = output_path.read_text(encoding="utf-8", errors="replace")
            output_path.chmod(0o600)
            try:
                result = json.loads(raw)
            except json.JSONDecodeError:
                raise ValueError("Codex did not return JSON; inspect saved output")
            if not isinstance(result, dict):
                raise ValueError("Codex output must be a JSON object")
            result = normalize_result(result, artifact_dir)
        coverage = json_object(run.get("coverage"))
        if not action_id:
            scanned = dict(coverage.get("scanned") or {})
            # inv: scanned contains the prior total plus every earlier source count in this packet.
            # term: one finite processed-count entry is consumed per iteration.
            for table, count in packet["processed_counts"].items():
                scanned[table] = int(scanned.get(table, 0)) + count
            coverage.update({"scanned": scanned, "cycle": next_cursor["cycle"],
                             "last_pass_id": pass_id, "last_packet_exhausted": exhausted})
            if exhausted and run["mode"] == "continuous":
                next_cursor = {"floors": next_cursor["uppers"], "cycle": next_cursor["cycle"] + 1}
        queue_action = False
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await self.coordinator.record_pass_research(conn, run_id, pass_id, result)
                await conn.execute("""
                    UPDATE hunt_passes SET status='done', finished_at=NOW(), output_path=$2,
                        result=$3::jsonb, cursor_after=$4::jsonb WHERE id=$1
                """, pass_id, str(output_path) if output_path.is_file() else None,
                     json.dumps(result), json.dumps(next_cursor))
                if action_id:
                    successor = await conn.fetchval("""
                        SELECT id FROM hunt_actions
                        WHERE hypothesis_id=(SELECT hypothesis_id FROM hunt_actions WHERE id=$1)
                          AND id<>$1 AND state IN ('proposed','reconciliation','ready')
                        ORDER BY updated_at DESC LIMIT 1
                    """, action_id)
                    if result["confirmed_findings"] or result["killed"] or successor:
                        action_state = "completed"
                    elif result["blocked"] or result["leads"]:
                        action_state = "blocked"
                    else:
                        action_state = "completed"
                    await conn.execute("""
                        UPDATE hunt_actions SET state=$2, result=$3::jsonb,
                            updated_at=NOW() WHERE id=$1
                    """, action_id, action_state, json.dumps({
                        "pass_id": pass_id, "status": result.get("status"),
                        "summary": result.get("summary", "")[:2000],
                    }))
                    await conn.execute("""
                        UPDATE hunt_runs SET last_error=NULL WHERE id=$1
                    """, run_id)
                else:
                    await conn.execute("""
                        UPDATE hunt_runs SET cursor=$2::jsonb, coverage=$3::jsonb,
                            completed_at=CASE WHEN $4 AND mode='one_time' THEN NOW() ELSE NULL END,
                            next_pass_at=CASE WHEN $4 AND mode='one_time' THEN NULL
                                              WHEN $4 THEN NOW() + INTERVAL '12 hours'
                                              ELSE NOW() + INTERVAL '15 seconds' END,
                            last_error=NULL WHERE id=$1
                    """, run_id, json.dumps(next_cursor), json.dumps(coverage), exhausted)
                action_passes = await conn.fetchval("""
                    SELECT COUNT(*) FROM hunt_passes
                    WHERE run_id=$1 AND action_id IS NOT NULL AND status IN ('done','running')
                """, run_id)
                open_action = await conn.fetchval("""
                    SELECT EXISTS(SELECT 1 FROM hunt_actions
                                  WHERE run_id=$1 AND state IN ('proposed','ready'))
                """, run_id)
                queue_action = (bool(run.get("autonomous_validation_enabled")) and bool(open_action)
                                and int(action_passes or 0) < int(run["max_jobs_per_cycle"]))
                if queue_action:
                    await conn.execute("UPDATE hunt_runs SET next_pass_at=NOW() WHERE id=$1", run_id)
                elif action_id and run["mode"] == "one_time":
                    await conn.execute("UPDATE hunt_runs SET next_pass_at=NULL WHERE id=$1", run_id)
        if queue_action:
            await self.coordinator.refresh_run(run_id)

    async def run_forever(self) -> None:
        await self.coordinator.ensure_schema()
        backfilled = await self.coordinator.backfill_research_ledger()
        if backfilled:
            LOG.info("Imported %s historical hunt observations into the research ledger", backfilled)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # Read-only inventory passes are deterministic and idempotent. A target action
                # may have issued a request before the worker stopped, so it must never replay.
                await conn.execute("""
                    UPDATE hunt_passes SET status='queued', started_at=NULL,
                        error='Recovered deterministic recon pass after worker restart'
                    WHERE status='running' AND action_id IS NULL
                """)
                await conn.execute("""
                    UPDATE hunt_passes SET status='failed', finished_at=NOW(),
                        error='UNCERTAIN: worker stopped during a target validation action; reconcile evidence before any retry'
                    WHERE status='running' AND action_id IS NOT NULL
                """)
                await conn.execute("""
                    UPDATE hunt_actions a SET state='uncertain',
                        result=jsonb_build_object('status','UNCERTAIN',
                          'reason','Worker stopped during target validation; side effects may have occurred',
                          'reconciliation_required',true), updated_at=NOW()
                    FROM hunt_passes p WHERE p.action_id=a.id
                      AND p.status='failed' AND p.error LIKE 'UNCERTAIN:%'
                      AND a.state IN ('started','ready')
                """)
                await conn.execute("""
                    UPDATE hunt_hypotheses h SET state='needs_reconciliation', report_ready=FALSE,
                        missing_proof='Interrupted target action is UNCERTAIN; reconcile request and side-effect state before continuing',
                        updated_at=NOW()
                    FROM hunt_actions a WHERE a.hypothesis_id=h.id AND a.state='uncertain'
                """)
                await conn.execute("""
                    UPDATE hunt_fixtures f SET state='uncertain', updated_at=NOW()
                    WHERE f.create_action_id IN (SELECT id FROM hunt_actions WHERE state='uncertain')
                       OR f.cleanup_action_id IN (SELECT id FROM hunt_actions WHERE state='uncertain')
                """)
                await conn.execute("""
                    UPDATE hunt_runs h SET status='paused', next_pass_at=NULL,
                        last_error='UNCERTAIN: interrupted target action requires operator reconciliation'
                    WHERE EXISTS (SELECT 1 FROM hunt_passes p WHERE p.run_id=h.id
                                  AND p.status='failed' AND p.error LIKE 'UNCERTAIN:%'
                                  AND EXISTS (SELECT 1 FROM hunt_actions a
                                              WHERE a.id=p.action_id AND a.state='uncertain'))
                """)
        while True:
            try:
                await self.queue_due()
                pass_row = await self.claim()
                if not pass_row:
                    await asyncio.sleep(20)
                    continue
                try:
                    await self.run_pass(pass_row)
                except LoginPending as exc:
                    async with self.pool.acquire() as conn:
                        async with conn.transaction():
                            await conn.execute("""
                                UPDATE hunt_passes SET status='queued', started_at=NULL, error=$2
                                WHERE id=$1
                            """, pass_row["id"], str(exc))
                            if pass_row["action_id"]:
                                await conn.execute("""
                                    UPDATE hunt_actions SET state='ready', updated_at=NOW()
                                    WHERE id=$1 AND state='started'
                                """, pass_row["action_id"])
                            await conn.execute("""
                                UPDATE hunt_runs SET next_pass_at=NOW() + INTERVAL '30 seconds', last_error=NULL
                                WHERE id=$1
                            """, pass_row["run_id"])
                except Exception as exc:
                    LOG.exception("Hunt pass %s failed", pass_row["id"])
                    async with self.pool.acquire() as conn:
                        async with conn.transaction():
                            await conn.execute("""
                                UPDATE hunt_passes SET status='failed', finished_at=NOW(), error=$2
                                WHERE id=$1
                            """, pass_row["id"], str(exc)[:500])
                            if pass_row["action_id"]:
                                await conn.execute("""
                                    UPDATE hunt_actions SET state='failed',
                                        result=jsonb_build_object('pass_id', $2::bigint, 'error', $3::text),
                                        updated_at=NOW() WHERE id=$1
                                """, pass_row["action_id"], pass_row["id"], str(exc)[:500])
                            await conn.execute("""
                                UPDATE hunt_runs SET last_error=$2,
                                    next_pass_at=NOW() + INTERVAL '1 hour' WHERE id=$1
                            """, pass_row["run_id"], str(exc)[:500])
            except Exception:
                LOG.exception("Dedicated hunt worker loop failed")
                await asyncio.sleep(30)


async def main() -> None:
    with Path("/app/config.yaml").open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    db = config["database"]
    pool = await asyncpg.create_pool(host=db["host"], port=db["port"], database=db["name"],
                                     user=db["user"], password=os.getenv("RECON_DB_PASSWORD", db["password"]),
                                     min_size=1, max_size=3, command_timeout=30)
    try:
        await HuntWorker(pool, config).run_forever()
    finally:
        await pool.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
