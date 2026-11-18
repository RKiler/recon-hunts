"""Shared bug-job categories and ROI allocation helpers.

The watcher, worker, and dashboard use the same mapping so queue scheduling and
reported yield cannot drift apart as new job types are introduced.
"""

from __future__ import annotations

from typing import Any, Mapping


DEFAULT_CATEGORY_ALLOCATIONS: dict[str, float] = {
    "authorization_graphql": 0.40,
    "authentication_lifecycle": 0.20,
    "javascript_client": 0.15,
    "input_workflow": 0.15,
    "exposure_supply_secrets": 0.10,
}


JOB_CATEGORY_MAP: dict[str, str] = {
    "idor_bac_test": "authorization_graphql",
    "graphql_authz_test": "authorization_graphql",
    "mobile_api_parity_review": "authorization_graphql",
    "auth_session_review": "authentication_lifecycle",
    "crypto_token_review": "authentication_lifecycle",
    "email_parser_idn_review": "authentication_lifecycle",
    "xss_reflection_test": "javascript_client",
    "js_dom_xss_review": "javascript_client",
    "websocket_review": "javascript_client",
    "cors_misconfig_test": "javascript_client",
    "cache_desync_review": "javascript_client",
    "ssrf_candidate_test": "input_workflow",
    "upload_attack_surface": "input_workflow",
    "injection_review": "input_workflow",
    "business_logic_review": "input_workflow",
    "integrity_review": "input_workflow",
    "exceptional_condition_review": "input_workflow",
    "ai_llm_workflow_review": "input_workflow",
    "delta_intelligence_review": "exposure_supply_secrets",
    "js_endpoint_extraction": "exposure_supply_secrets",
    "js_secret_review": "exposure_supply_secrets",
    "source_map_review": "exposure_supply_secrets",
    "new_admin_route_review": "exposure_supply_secrets",
    "cloud_storage_review": "exposure_supply_secrets",
    "component_supply_chain_review": "exposure_supply_secrets",
    "logging_audit_review": "exposure_supply_secrets",
    "report_triage_review": "exposure_supply_secrets",
}


ALIASES: dict[str, str] = {
    "owasp_a01_broken_access_control": "idor_bac_test",
    "owasp_a02_cryptographic_failures": "crypto_token_review",
    "owasp_a03_injection": "injection_review",
    "owasp_a04_insecure_design": "business_logic_review",
    "owasp_a05_security_misconfiguration": "new_admin_route_review",
    "owasp_a06_vulnerable_components": "component_supply_chain_review",
    "owasp_a07_authentication_failures": "auth_session_review",
    "owasp_a08_software_data_integrity": "integrity_review",
    "owasp_a09_logging_monitoring_failures": "logging_audit_review",
    "owasp_a10_ssrf": "ssrf_candidate_test",
    "owasp2025_a01_broken_access_control": "idor_bac_test",
    "owasp2025_a02_security_misconfiguration": "new_admin_route_review",
    "owasp2025_a03_software_supply_chain_failures": "component_supply_chain_review",
    "owasp2025_a04_cryptographic_failures": "crypto_token_review",
    "owasp2025_a05_injection": "injection_review",
    "owasp2025_a06_insecure_design": "business_logic_review",
    "owasp2025_a07_authentication_failures": "auth_session_review",
    "owasp2025_a08_software_data_integrity_failures": "integrity_review",
    "owasp2025_a09_security_logging_alerting_failures": "logging_audit_review",
    "owasp2025_a10_mishandling_exceptional_conditions": "exceptional_condition_review",
    "bug-bounty-access-control-idor": "idor_bac_test",
    "bug-bounty-account-takeover-auth": "auth_session_review",
    "bug-bounty-ai-llm-workflow": "ai_llm_workflow_review",
    "bug-bounty-business-logic-rate-limits": "business_logic_review",
    "bug-bounty-cache-poisoning-desync": "cache_desync_review",
    "bug-bounty-cloud-storage-takeover": "cloud_storage_review",
    "bug-bounty-cors-csrf-clickjacking": "cors_misconfig_test",
    "bug-bounty-cors-misconfiguration": "cors_misconfig_test",
    "bug-bounty-cswsh-websockets": "websocket_review",
    "bug-bounty-email-parser-idn": "email_parser_idn_review",
    "bug-bounty-file-upload-traversal-xxe": "upload_attack_surface",
    "bug-bounty-graphql-api-auth": "graphql_authz_test",
    "bug-bounty-info-disclosure-secrets": "js_secret_review",
    "bug-bounty-injection-sqli-nosqli-ssti": "injection_review",
    "bug-bounty-jwt-session-cookies": "auth_session_review",
    "bug-bounty-logging-audit-bypass": "logging_audit_review",
    "bug-bounty-master-workflow": "report_triage_review",
    "bug-bounty-mobile-desktop-api-parity": "mobile_api_parity_review",
    "bug-bounty-oauth-saml-sso": "auth_session_review",
    "bug-bounty-race-condition-concurrency": "business_logic_review",
    "bug-bounty-rce-code-injection": "injection_review",
    "bug-bounty-report-writing-triage": "report_triage_review",
    "bug-bounty-ssrf-open-redirect-webhook": "ssrf_candidate_test",
    "bug-bounty-supply-chain-components": "component_supply_chain_review",
    "bug-bounty-xss-dom-postmessage": "js_dom_xss_review",
}


def canonical_job_type(job_type: Any) -> str:
    value = str(job_type or "").strip()
    return ALIASES.get(value, value)


def job_category(job_type: Any) -> str:
    return JOB_CATEGORY_MAP.get(canonical_job_type(job_type), "input_workflow")


def normalized_allocations(value: Any = None) -> dict[str, float]:
    raw = value if isinstance(value, Mapping) else DEFAULT_CATEGORY_ALLOCATIONS
    allocations: dict[str, float] = {}
    for category in DEFAULT_CATEGORY_ALLOCATIONS:
        try:
            amount = max(0.0, float(raw.get(category, DEFAULT_CATEGORY_ALLOCATIONS[category])))
        except (TypeError, ValueError):
            amount = DEFAULT_CATEGORY_ALLOCATIONS[category]
        allocations[category] = amount
    total = sum(allocations.values())
    if total <= 0:
        return dict(DEFAULT_CATEGORY_ALLOCATIONS)
    return {category: amount / total for category, amount in allocations.items()}


def adaptive_allocations(
    configured: Mapping[str, float],
    roi: Mapping[str, Mapping[str, int]],
    *,
    minimum_sample: int = 100,
    minimum_share: float = 0.05,
    zero_result_factor: float = 0.10,
) -> dict[str, float]:
    """Throttle proven low-yield families without permanently disabling them."""

    adjusted = dict(configured)
    for category, share in list(adjusted.items()):
        metrics = roi.get(category, {})
        completed = int(metrics.get("completed", 0) or 0)
        credible = int(metrics.get("credible", 0) or 0)
        if completed >= minimum_sample and credible == 0:
            adjusted[category] = max(minimum_share, share * zero_result_factor)
    return normalized_allocations(adjusted)


def preferred_category(
    allocations: Mapping[str, float],
    started_counts: Mapping[str, int],
    total_started: int,
) -> str:
    """Return the category furthest below its target share."""

    denominator = max(1, total_started + 1)
    return max(
        allocations,
        key=lambda category: float(allocations[category])
        - (int(started_counts.get(category, 0) or 0) / denominator),
    )
