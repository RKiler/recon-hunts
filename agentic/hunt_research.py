"""Durable research-ledger normalization for Independent Hunts.

The worker is free to describe a result in natural language. This module turns
that result into stable, conservative records. It never promotes a pass result
to confirmed evidence; only the worker's already-gated confirmed_findings list
can produce E3/confirmed state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import unquote, urlsplit


RESEARCH_STATES = {
    "hypothesis", "candidate", "supported", "confirmed", "rejected",
    "duplicate", "out_of_scope", "blocked_missing_fixture",
    "blocked_human_login", "killed", "needs_reconciliation",
}
EVIDENCE_LEVELS = {"E0", "E1", "E2", "E3"}
STATE_PRIORITY = {
    "confirmed": 100,
    "needs_reconciliation": 95,
    "supported": 90,
    "candidate": 80,
    "blocked_human_login": 65,
    "blocked_missing_fixture": 60,
    "hypothesis": 50,
    "duplicate": 20,
    "out_of_scope": 15,
    "rejected": 10,
    "killed": 10,
}
EVIDENCE_RANK = {"E0": 0, "E1": 1, "E2": 2, "E3": 3}
POSITIVE_STATES = {"candidate", "supported", "confirmed"}
NEGATIVE_STATES = {"rejected", "killed"}

OWASP_TOP10_2025 = (
    ("A01:2025", "Broken Access Control", {"access_control", "ssrf_redirect"}),
    ("A02:2025", "Security Misconfiguration", {"security_misconfiguration"}),
    ("A03:2025", "Software Supply Chain Failures", {"cloud_supply_chain"}),
    ("A04:2025", "Cryptographic Failures", {"cryptographic_failures"}),
    ("A05:2025", "Injection", {"server_injection", "client_injection"}),
    ("A06:2025", "Insecure Design", {"business_logic", "file_handling"}),
    ("A07:2025", "Authentication Failures", {"authentication", "oauth_sso"}),
    ("A08:2025", "Software or Data Integrity Failures", {"software_data_integrity"}),
    ("A09:2025", "Security Logging and Alerting Failures", {"logging_audit"}),
    ("A10:2025", "Mishandling of Exceptional Conditions", {"exceptional_conditions"}),
)


def owasp_top10_2025_coverage(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map recorded hypothesis families to OWASP categories; absence is not a pass."""
    family_counts: dict[str, int] = {}
    for item in hypotheses:
        family = str(item.get("bug_family") or "")
        family_counts[family] = family_counts.get(family, 0) + int(item.get("hypothesis_count", 1))
    output = []
    for code, title, families in OWASP_TOP10_2025:
        count = sum(family_counts.get(family, 0) for family in families)
        output.append({
            "code": code,
            "title": title,
            "hypothesis_count": count,
            "state": "signals_recorded" if count else "no_mapped_signal",
        })
    return output

_UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f-]{27,}$")
_OPAQUE = re.compile(r"(?i)^[0-9a-f_-]{16,}$")
_PLACEHOLDER = re.compile(r"\{[^/{}]+\}|<[^/<>]+>")
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class ResearchObservation:
    """One conservative observation extracted from one pass result item."""

    source_kind: str
    state: str
    evidence_level: str
    priority: int
    dedup_key: str
    bug_family: str
    title: str
    affected_asset: str
    feature: str
    controlled_input: str
    boundary_class: str
    actor_context: str
    next_action: str
    missing_proof: str
    summary: str
    evidence_path: str
    source_hash: str
    source_item: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _bounded_text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    return _WHITESPACE.sub(" ", str(value)).strip()[:limit]


def _family(item: dict[str, Any]) -> str:
    label = " ".join(_bounded_text(item.get(key), 300) for key in ("bug_class", "title")).lower()
    families = (
        (r"misconfig|security.?configuration|default.?configuration", "security_misconfiguration"),
        (r"idor|bola|bfla|access.?control|authorization|tenant.?isolation", "access_control"),
        (r"oauth|saml|sso|account.?link", "oauth_sso"),
        (r"session|jwt|authentication|account.?takeover|ato\b", "authentication"),
        (r"cryptograph|weak.?encrypt|weak.?hash|plaintext.?secret", "cryptographic_failures"),
        (r"graphql", "graphql"),
        (r"xss|postmessage|messageport|html.?injection", "client_injection"),
        (r"ssrf|open.?redirect|webhook|url.?fetch", "ssrf_redirect"),
        (r"sql|nosql|ssti|command.?injection|rce|injection", "server_injection"),
        (r"upload|traversal|lfi|xxe|file", "file_handling"),
        (r"cors|csrf|clickjack", "browser_trust"),
        (r"cache|desync|smuggl", "http_cache_desync"),
        (r"integrity|tamper|deserializ|unsigned|untrusted.?update", "software_data_integrity"),
        (r"logging|audit.?trail|alerting|security.?monitoring", "logging_audit"),
        (r"exception|error.?handling|fail.?open|unhandled.?error", "exceptional_conditions"),
        (r"secret|credential|information.?disclosure|sensitive", "information_disclosure"),
        (r"race|replay|business.?logic|billing|quota|coupon", "business_logic"),
        (r"cloud|bucket|takeover|supply.?chain", "cloud_supply_chain"),
    )
    # inv: every earlier pattern was checked in priority order and did not match.
    # term: one finite tuple entry is consumed per iteration.
    for pattern, family in families:
        if re.search(pattern, label):
            return family
    return "other"


def _asset_parts(value: Any) -> tuple[str, str]:
    raw = _bounded_text(value, 1000)
    if not raw:
        return "unknown", "/unknown"
    candidate = raw if "://" in raw else f"https://unknown.invalid/{raw.lstrip('/')}"
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "unknown").lower()
        path = unquote(parsed.path or "/")
    except ValueError:
        return "unknown", "/unknown"
    normalized = []
    # inv: normalized contains the canonical form of every path segment already visited.
    # term: one finite path segment is consumed per iteration.
    for segment in path.split("/"):
        if not segment:
            continue
        if _PLACEHOLDER.fullmatch(segment) or segment.isdigit() or _UUID.fullmatch(segment) or _OPAQUE.fullmatch(segment):
            normalized.append("{id}")
        else:
            normalized.append(segment.lower()[:120])
    return host, "/" + "/".join(normalized) if normalized else "/"


def _proof(item: dict[str, Any]) -> dict[str, Any]:
    value = item.get("hypothesis_proof")
    return value if isinstance(value, dict) else {}


def _controlled_input(item: dict[str, Any]) -> str:
    proof = _proof(item)
    text = " ".join(_bounded_text(value, 500) for value in (
        item.get("controlled_input"), item.get("input_location"), proof.get("controlled_input")
    )).lower()
    if re.search(r"conversation.?id|attachment|message.?id", text):
        return "conversation_object"
    if re.search(r"login.?id|user.?id|session identity|path identity", text):
        return "identity_path"
    if re.search(r"tenant|workspace|org(?:anization)?.?id|account.?id", text):
        return "tenant_id"
    if re.search(r"role|permission|is.?admin|owner", text):
        return "role_or_permission"
    if re.search(r"redirect|url|uri|callback", text):
        return "url"
    if re.search(r"file|path|filename|object.?key", text):
        return "file_path"
    if re.search(r"query|search|text|input|parameter", text):
        return "request_input"
    _, path = _asset_parts(item.get("affected_asset"))
    return "path_id" if "{id}" in path else "route"


def _boundary_class(item: dict[str, Any]) -> str:
    proof = _proof(item)
    text = " ".join(_bounded_text(value, 700) for value in (
        item.get("expected_boundary"), item.get("boundary_class"), proof.get("trust_boundary")
    )).lower()
    if re.search(r"bind|session identity|authenticated.*identity|path identity", text):
        return "identity_binding"
    if re.search(r"ownership|cross.?account|another user|private object", text):
        return "object_ownership"
    if re.search(r"tenant|workspace|organization", text):
        return "tenant_isolation"
    if re.search(r"role|permission|admin|privilege", text):
        return "role_authorization"
    if re.search(r"origin|cross.?origin|message sender", text):
        return "origin_trust"
    if re.search(r"parser|filesystem|server.?side|backend|interpreter", text):
        return "backend_interpretation"
    return "feature_boundary"


def _actor_context(item: dict[str, Any]) -> str:
    text = " ".join(_bounded_text(item.get(key), 120) for key in (
        "attacker_role", "victim_role", "actor_context", "tenant_context"
    )).lower()
    return re.sub(r"[^a-z0-9_-]+", "_", text).strip("_")[:160] or "unspecified"


def _dedup_key(item: dict[str, Any], family: str, controlled_input: str,
               boundary_class: str, actor_context: str) -> str:
    host, route = _asset_parts(item.get("affected_asset"))
    payload = {
        "family": family,
        "host": host,
        "route": route,
        "input": controlled_input,
        "boundary": boundary_class,
        "actor": actor_context,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _next_action(item: dict[str, Any]) -> str:
    proof = _proof(item)
    values = (
        item.get("next_action"), item.get("next_test"), item.get("precise_next_test"),
        item.get("precise_next_test_or_proof"), proof.get("decisive_next_test"),
    )
    # inv: best is the first non-empty bounded action among values already visited.
    # term: one finite candidate is consumed per iteration.
    for value in values:
        text = _bounded_text(value, 2000)
        if text:
            return text
    return ""


def _missing_proof(item: dict[str, Any], source_kind: str) -> str:
    values = (item.get("missing_proof"), item.get("reason"), item.get("blocker"), item.get("review_reason"))
    # inv: no earlier value contained a non-empty missing-proof description.
    # term: one finite candidate is consumed per iteration.
    for value in values:
        text = _bounded_text(value, 2000)
        if text:
            return text
    return "Pass marked this work blocked without a precise prerequisite." if source_kind == "blocked" else ""


def _state_and_level(source_kind: str, item: dict[str, Any]) -> tuple[str, str]:
    if source_kind == "confirmed_findings":
        return "confirmed", "E3"
    if source_kind == "leads":
        if item.get("baseline") and item.get("negative_control"):
            return "supported", "E2"
        return "candidate", "E1"
    if source_kind == "blocked":
        proof = _proof(item)
        return "blocked_missing_fixture", "E1" if item.get("evidence_path") or proof.get("observed_behavior") else "E0"
    if source_kind == "killed":
        return "killed", "E1" if item.get("evidence_path") else "E0"
    raise ValueError(f"Unsupported result source kind: {source_kind}")


def merge_research_state(current: str, incoming: str) -> str:
    """Merge two result-derived states without silently erasing contradictions."""
    if current not in RESEARCH_STATES or incoming not in RESEARCH_STATES:
        raise ValueError("Unknown research state")
    if current == incoming:
        return current
    if "confirmed" in {current, incoming}:
        return "confirmed"
    if "needs_reconciliation" in {current, incoming}:
        return "needs_reconciliation"
    if (current in POSITIVE_STATES and incoming in NEGATIVE_STATES) or (
        incoming in POSITIVE_STATES and current in NEGATIVE_STATES
    ):
        return "needs_reconciliation"
    if current in {"duplicate", "out_of_scope"}:
        return current
    if incoming in {"duplicate", "out_of_scope"}:
        return incoming
    if current in POSITIVE_STATES or incoming in POSITIVE_STATES:
        return max((current, incoming), key=lambda state: STATE_PRIORITY[state])
    if current in NEGATIVE_STATES or incoming in NEGATIVE_STATES:
        return max((current, incoming), key=lambda state: STATE_PRIORITY[state])
    return max((current, incoming), key=lambda state: STATE_PRIORITY[state])


def merge_evidence_level(current: str, incoming: str) -> str:
    if current not in EVIDENCE_LEVELS or incoming not in EVIDENCE_LEVELS:
        raise ValueError("Unknown evidence level")
    return max((current, incoming), key=lambda level: EVIDENCE_RANK[level])


def reconcile_validation_state(current: str, incoming: str, action_pass: bool,
                               source_item: Any, evidence_path: str) -> str:
    """Resolve a contradiction only from a controlled validation-action result."""
    merged = merge_research_state(current, incoming)
    if current != "needs_reconciliation" or not action_pass:
        return merged
    item = source_item if isinstance(source_item, dict) else {}
    if incoming in {"confirmed", "supported"}:
        return incoming
    if (incoming == "killed" and evidence_path and item.get("baseline") and
            item.get("negative_control")):
        return "killed"
    return merged


def extract_research_observations(result: Any) -> list[ResearchObservation]:
    """Extract deterministic, conservative observations from a pass result."""
    if not isinstance(result, dict):
        return []
    observations: list[ResearchObservation] = []
    # inv: observations contains one normalized record for every valid result item already visited.
    # term: the finite four result collections and their finite items are consumed exactly once.
    for source_kind in ("confirmed_findings", "leads", "blocked", "killed"):
        items = result.get(source_kind)
        if not isinstance(items, list):
            continue
        for raw in items:
            if not isinstance(raw, dict):
                continue
            item = {str(key): value for key, value in raw.items()}
            state, level = _state_and_level(source_kind, item)
            family = _family(item)
            controlled_input = _controlled_input(item)
            boundary_class = _boundary_class(item)
            actor_context = _actor_context(item)
            title = _bounded_text(item.get("title") or item.get("bug_class") or "Untitled hunt observation", 500)
            affected_asset = _bounded_text(item.get("affected_asset") or "unknown", 1000)
            proof = _proof(item)
            summary = _bounded_text(
                item.get("summary") or proof.get("observed_behavior") or item.get("reason") or title, 3000
            )
            canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
            observations.append(ResearchObservation(
                source_kind=source_kind,
                state=state,
                evidence_level=level,
                priority=STATE_PRIORITY[state],
                dedup_key=_dedup_key(item, family, controlled_input, boundary_class, actor_context),
                bug_family=family,
                title=title,
                affected_asset=affected_asset,
                feature=_bounded_text(item.get("feature") or proof.get("current_surface"), 500),
                controlled_input=controlled_input,
                boundary_class=boundary_class,
                actor_context=actor_context,
                next_action=_next_action(item),
                missing_proof=_missing_proof(item, source_kind),
                summary=summary,
                evidence_path=_bounded_text(item.get("evidence_path"), 1500),
                source_hash=hashlib.sha256(canonical.encode()).hexdigest(),
                source_item=item,
            ))
    return observations


def research_completion(inventory_exhausted: bool, state_counts: dict[str, int]) -> dict[str, str]:
    """Return honest, independent inventory and research completion labels."""
    inventory_state = "inventory_exhausted" if inventory_exhausted else "inventory_in_progress"
    if state_counts.get("needs_reconciliation", 0):
        research_state = "reconciliation_required"
    elif state_counts.get("confirmed", 0):
        research_state = "confirmed_pending_report_review"
    elif state_counts.get("supported", 0) or state_counts.get("candidate", 0):
        research_state = "validation_ready"
    elif state_counts.get("blocked_missing_fixture", 0) or state_counts.get("blocked_human_login", 0):
        research_state = "campaign_blocked"
    elif state_counts:
        research_state = "no_open_hypotheses"
    else:
        research_state = "no_durable_hypotheses"
    return {"inventory_state": inventory_state, "research_state": research_state}
