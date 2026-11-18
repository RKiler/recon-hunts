"""Local-only browser fixture for HackBot UI; no production target requests."""

from __future__ import annotations

import os
from pathlib import Path
import threading
import unittest

from flask import Flask, render_template
from werkzeug.serving import make_server

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


ROOT = Path(__file__).resolve().parents[1]
TARGET = "TARGET-11111111111141118111111111111111"
IDENTITY = "IDENTITY-22222222222242228222222222222222"
SESSION = "BSESSION-33333333333343338333333333333333"
EXCHANGE = "EXCHANGE-44444444444444448444444444444444"
RUN = "RUN-" + "d" * 32
PLAN = "PLAN-" + "c" * 32
VALIDATION = "VALIDATION-" + "e" * 32
FINDING = "FINDING-" + "f" * 32
OBJECT = "TESTOBJ-" + "9" * 32
CREATOR_SESSION = "BSESSION-" + "8" * 32
DOM_CANDIDATE = "DOM-" + "1" * 32
MESSAGE_CANDIDATE = "MSG-" + "2" * 32
API_OPERATION = "APIO-" + "3" * 32
API_CANDIDATE = "APIC-" + "4" * 32
PLANNER_RUN = "PLRUN-" + "5" * 32
PLANNER_CANDIDATE = "PLCAND-" + "6" * 32
PLANNER_TASK = "PLTASK-" + "7" * 32
DELTA = "DELTA-" + "8" * 32
BENCHMARK = "BENCH-" + "a" * 32
BASELINE = "BENCH-" + "b" * 32


def fixture(path: str):
    if path == "health":
        return {"status": "ok"}
    if path == "target-tombstones":
        return {"items": []}
    if path == "evaluation/suites":
        return {"label": "SYNTHETIC / EVALUATION",
                "items": [{"name": "local-smoke", "case_count": 2}]}
    if path == "evaluation/runs":
        return {"label": "SYNTHETIC / EVALUATION", "items": [
            {"run_id": BENCHMARK, "suite": "local-smoke", "status": "COMPLETED",
             "started_at": "2026-10-18T12:00:00+00:00"},
            {"run_id": BASELINE, "suite": "local-smoke", "status": "COMPLETED",
             "started_at": "2026-10-18T10:00:00+00:00"}]}
    if path == f"evaluation/runs/{BENCHMARK}":
        return {"label": "SYNTHETIC / EVALUATION", "run_id": BENCHMARK,
                "suite": "local-smoke", "status": "COMPLETED", "benchmark_version": "33.3",
                "bughunter_version": "fixture", "started_at": "2026-10-18T12:00:00+00:00",
                "finished_at": "2026-10-18T12:01:00+00:00", "evaluated_cases": 2,
                "total_case_runs": 2, "limitations": ["LOCAL_TRAFFIC_BACKED_ROUTE_SEEDED"],
                "model_mode": "DETERMINISTIC_ONLY", "model_usage": [],
                "model_comparison": {"status": "NOT_MEASURED", "comparison_packets": 0,
                                     "disagreement_positions": 0,
                                     "lane_statuses": {"PRIMARY": {}, "CHALLENGER": {},
                                                       "CRITIC": {}},
                                     "candidate_provenance": {},
                                     "quality": "NOT_MEASURED"},
                "specialist_breakdown": [
                    {"specialist": "EXPOSURE", "status": "MEASURED",
                     "expected_vulnerabilities": 1, "detected_vulnerabilities": 1,
                     "recall": 1, "routing_accuracy": 1, "requests": 10},
                    {"specialist": "DOM_XSS", "status": "NOT_MEASURED",
                     "expected_vulnerabilities": 0, "detected_vulnerabilities": 0,
                     "recall": None, "routing_accuracy": None, "requests": 0}],
                "failure_analysis": {"missed_cases": 0, "missed_vulnerabilities": 0,
                                     "stages": {}},
                "metrics": {"precision": 1, "recall": 1, "top_k_recall": {"10": 1},
                            "false_confirmed_findings": 0, "safety_violations": 0,
                            "requests": 16, "manual_reviews": 0},
                "cost_estimate": {"total_usd": None}}
    if path == f"evaluation/runs/{BENCHMARK}/cases":
        return {"items": [{"case_id": "local_download_a", "trial": 1,
                           "status": "COMPLETED", "error_code": None,
                           "evaluation": {"detected_vulnerabilities": 0,
                                          "false_confirmed_findings": 0,
                                          "failure_stage": None, "usage": {"requests": 6}}},
                          {"case_id": "local_download_b", "trial": 1,
                           "status": "COMPLETED", "error_code": None,
                           "evaluation": {"detected_vulnerabilities": 1,
                                          "false_confirmed_findings": 0,
                                          "failure_stage": None, "usage": {"requests": 10}}}],
                "next_offset": None}
    if path == "evaluation/readiness":
        return {"label": "SYNTHETIC / EVALUATION", "run_id": BENCHMARK,
                "readiness": {"conclusion": "NOT_READY", "gates": [
                    {"category": "PRODUCTION_TEST_MATRIX", "outcome": "NOT_MEASURED",
                     "reason_code": "NOT_MEASURED", "measured_cases": 0}]}}
    if path == "evaluation/compare":
        return {"label": "SYNTHETIC / EVALUATION", "outcome": "PASS",
                "reason_code": "COMPARABLE", "baseline_id": BASELINE,
                "current_id": BENCHMARK, "baseline": {"precision": 1, "recall": 0},
                "current": {"precision": 1, "recall": 1},
                "checks": {"new_false_confirmed": "PASS"}}
    if path == "overview":
        return {"targets": 1, "identities": 1, "browser_sessions": 1, "reauth_required": 0,
                "traffic": 1, "burp": "BURP_RUNNING", "activity": [
                    {"occurred_at": "2026-10-11T00:00:00+00:00", "event_type": "browser_started",
                     "target_id": TARGET, "identity_id": IDENTITY, "session_id": SESSION}]}
    if path == "targets":
        return {"items": [{"id": "example", "target_id": TARGET, "name": "Example program",
                           "primary_domain": "example.test", "status": "TRACKED",
                           "scope_summary": {"included_hosts": 2, "excluded_hosts": 1},
                           "counts": {"identities": 1, "browser_sessions": 1, "traffic": 1}}],
                "next_cursor": None}
    if path == "targets/setup-options":
        return {"source_kinds": ["RESEARCHER", "HACKERONE", "BUGCROWD",
                                 "PRIVATE_DOCUMENT", "IMPORTED_SCOPE"],
                "decisions": ["ALLOW", "DENY", "REQUIRE_APPROVAL"],
                "risk_fields": ["passive", "safe_read", "bounded_active",
                                "state_changing", "destructive"],
                "action_fields": ["create_disposable_objects", "modify_disposable_objects",
                                  "delete_disposable_objects", "cross_identity_testing",
                                  "account_creation", "external_side_effects",
                                  "permission_changes", "financial"],
                "defaults": {"autonomy": {"passive": "ALLOW", "safe_read": "ALLOW",
                                          "bounded_active": "DENY", "state_changing": "DENY",
                                          "destructive": "DENY",
                                          "create_disposable_objects": "DENY",
                                          "modify_disposable_objects": "DENY",
                                          "delete_disposable_objects": "DENY",
                                          "cross_identity_testing": "DENY",
                                          "account_creation": "DENY",
                                          "external_side_effects": "REQUIRE_APPROVAL",
                                          "permission_changes": "REQUIRE_APPROVAL",
                                          "financial": "DENY"}}}
    if path == "continuous/status":
        return {"enabled_targets": 1, "degraded_targets": 0, "deltas_today": 1,
                "focused_campaigns": 0, "findings_from_deltas": 0,
                "backlog_min_count": 0, "watch_cycles": 2}
    if path == "continuous/targets/example":
        return {"target_id": TARGET, "enabled": True, "status": "IDLE",
                "last_checked_at": "2026-10-18T12:00:00+00:00", "next_check_at": None,
                "last_delta_at": "2026-10-18T12:00:00+00:00", "last_campaign_at": None,
                "backlog_min_count": 0, "error_code": None,
                "settings": {"cadence": "SIX_HOURLY", "minimum_relevance": 70,
                             "daily_campaign_cap": 2, "request_cap": 12,
                             "cooldown_seconds": 86400,
                             "allowed_specialists": ["AUTHORIZATION", "API_GRAPHQL",
                                                     "DOM_XSS", "POSTMESSAGE", "EXPOSURE"]}}
    if path == "continuous/targets/example/settings":
        return {"status": "PENDING", "enabled": True}
    if path == "continuous/targets/example/check":
        return {"watch": {"status": "IDLE", "candidates_created": 0},
                "campaign": {"status": "NO_ELIGIBLE_DELTA"}}
    delta = {"delta_id": DELTA, "target_id": TARGET, "delta_type": "NEW_ENDPOINT",
             "observed_at": "2026-10-18T12:00:00+00:00",
             "display_location": "app.example.test/admin/members", "relevance": 82,
             "specialist_hints": ["AUTHORIZATION"], "status": "CLASSIFIED",
             "campaign_id": None, "campaign_status": None, "finding_count": 0,
             "source_kind": "RECON", "source_ref": "asset_events:101",
             "old_fingerprint": None, "new_fingerprint": "a" * 64,
             "semantic_hash": None, "signal_tags": ["PRIVILEGED_NAME"],
             "reason_code": "CLASSIFIED", "evidence_id": "EV-" + "7" * 32,
             "hypothesis_ids": []}
    if path == "deltas":
        return {"items": [delta], "next_cursor": None}
    if path == f"deltas/{DELTA}":
        return delta
    if path == f"deltas/{DELTA}/campaigns":
        return {"status": "CAMPAIGN_STARTED", "campaign_id": "CMP-" + "1" * 32,
                "delta_id": DELTA}
    if path == "targets/later":
        return {"id": "later", "target_id": TARGET, "name": "Later program",
                "primary_domain": "later.example.test", "status": "TRACKED",
                "scope_summary": {"included_hosts": 1, "excluded_hosts": 0},
                "counts": {"identities": 0, "browser_sessions": 0, "traffic": 0}}
    if path == "targets/example/scope":
        return {"authority": "AUTHORIZED_TARGET_SCOPE", "scope": {
            "include_hosts": ["example.test", "*.example.test"],
            "exclude_hosts": ["admin.example.test"], "include_paths": [], "exclude_paths": []}}
    if path == "targets/example/policy":
        return {"scope": {"include_hosts": ["example.test", "*.example.test"],
                          "exclude_hosts": ["admin.example.test"], "include_paths": [],
                          "exclude_paths": []}, "autonomy": {"passive": "ALLOW",
                          "safe_read": "ALLOW", "bounded_active": "DENY",
                          "state_changing": "DENY", "destructive": "DENY"},
                "rate": {"requests_per_second": 1, "requests_per_minute": 10,
                         "max_concurrency": 1, "burst": 1}}
    if path == "targets/example/bootstrap":
        return {"discovery_state": "COLD_START", "recon_availability": "NO_RECON_HISTORY",
                "latest": None, "history": [],
                "transport": {"executor_enabled": True, "direct_enabled": False,
                              "transport_ready": False, "burp_capture_ready": False,
                              "cold_start_available": False,
                              "blocked_reason": "ANONYMOUS_BURP_CAPTURE_REQUIRED"}}
    if path == "targets/example/accounts":
        return {"items": [{"alias": "owned_admin", "tenant": "org1", "role": "admin",
                           "registration": "REGISTERED", "session": "IDENTITY_VERIFIED"}],
                "configured": 1, "sessions_ready": 1, "secrets_stored": False}
    fixture_object = {"id": OBJECT, "target_id": TARGET, "object_type": "project",
                      "external_id_fingerprint": "a" * 16, "state": "READY",
                      "creator_identity_id": IDENTITY, "tenant_id": "TENANT-1",
                      "parent_id": None, "run_id": None, "plan_id": None, "recipe_id": "project",
                      "cleanup_strategy": "AUTO_CLEANUP", "cleanup_required": True,
                      "created_at": "2026-10-11T00:00:00+00:00",
                      "verified_at": "2026-10-11T00:00:01+00:00", "cleaned_at": None,
                      "evidence_ids": ["EV-" + "7" * 32]}
    if path == "objects":
        return {"items": [fixture_object], "next_cursor": None,
                "stats": {"objects": 1, "cleanup_pending": 0, "orphaned": 0}}
    if path == "objects/recipes":
        return {"items": [{"id": "project", "object_type": "project", "protocol": "REST",
                           "cleanup_strategy": "AUTO_CLEANUP"}]}
    if path == f"objects/{OBJECT}":
        return {"object": fixture_object, "active_reservation_run": None,
                "mutation_state": "RESTORED",
                "latest_readback": {"readback_exchange_id": EXCHANGE},
                "mutation_history": [{"phase": "RESTORE", "status": "VERIFIED",
                                      "readback_exchange_id": EXCHANGE,
                                      "updated_at": "2026-10-11T00:00:02+00:00"}],
                "events": [{"occurred_at": "2026-10-11T00:00:01+00:00",
                            "event_type": "OBJECT_READY", "reason_code": "OWNERSHIP_VERIFIED",
                            "source": "OBJECT_FACTORY", "exchange_id": None,
                            "evidence_ids": ["EV-" + "7" * 32]}]}
    if path == "targets/example/profile":
        return {"profile": {"generated_at": "2026-10-11T00:00:00+00:00",
                "recon_status": "AVAILABLE", "technologies": ["GraphQL"],
                "api_styles": ["GRAPHQL"], "features": ["projects", "exports"],
                "boundaries": ["TENANT", "ROLE"], "object_types": ["project"],
                "identity_capabilities": ["CROSS_TENANT_PAIR"], "recent_changes": 1,
                "javascript_heavy": False, "message_passing": True, "source_map_count": 0,
                "coverage": {"js_assets_examined": 2}, "gaps": []},
                "hypotheses_generated": 1}
    api_operation = {
        "id": API_OPERATION, "name": "GetProject", "type": "GRAPHQL_QUERY",
        "method": "POST", "endpoint": "https://app.example.test/graphql",
        "feature": "projects", "role_ids": ["admin"], "tenant_ids": ["tenant-a"],
        "identity_ids": [IDENTITY], "exchange_ids": [EXCHANGE],
        "evidence_ids": ["EV-" + "6" * 32], "source_refs": ["TRAFFIC:" + EXCHANGE],
        "fields": [{"path": "/node/id", "sensitivity": "UNKNOWN"},
                   {"path": "/node/email", "sensitivity": "SENSITIVE_NAME"}],
        "variables": ["id"], "input_types": ["ID"], "document_evidence_id": "EV-" + "6" * 32,
        "source_asset_hash": "a" * 64, "version_hash": "b" * 64,
        "last_seen": "2026-10-13T00:00:00+00:00", "state": "CURRENT",
    }
    api_candidate = {
        "id": API_CANDIDATE, "operation_id": API_OPERATION, "category": "FIELD_AUTH",
        "score": 88, "boundary_identity_id": IDENTITY, "test_object_id": OBJECT,
        "field_path": "/node/email", "status": "PLAN_ONLY", "plan_id": None,
        "run_id": None, "reasons": ["VERIFIED_OWNER_CONTROL"],
        "gaps": ["FIELD_EXPECTATION_UNKNOWN"],
    }
    if path == "api/example/coverage":
        return {"counts": {"operations_current": 1, "operations_stale": 0,
                           "candidates": 1, "candidates_ready": 0},
                "queries": 1, "mutations": 0,
                "coverage_note": "Observed operations only; not exhaustive."}
    if path == "api/example/operations":
        return {"items": [api_operation]}
    if path == f"api/example/operations/{API_OPERATION}":
        return {"operation": api_operation, "candidates": [api_candidate]}
    if path == "api/example/candidates":
        return {"items": [api_candidate]}
    if path == "api/example/analyze":
        return {"items": [api_candidate], "coverage": {"operations_current": 1}}
    dom_candidate = {
        "id": DOM_CANDIDATE, "target_id": TARGET, "recon_asset_id": 17,
        "asset_sha256": "a" * 64, "source": "location.search", "source_line": 12,
        "checks": ["protocol_check"], "transforms": ["decodeURIComponent"],
        "sink": "iframe.src", "sink_line": 18, "score": 82,
        "status": "STATIC_CANDIDATE", "route": "/preview", "mapped_source": "src/preview.js",
        "source_map_sha256": "b" * 64, "evidence_ids": ["EV-" + "1" * 32],
        "links": {"hypothesis_id": "HYP-" + "1" * 32, "plan_id": PLAN,
                  "run_id": RUN, "validation_id": VALIDATION},
    }
    if path == "domxss/example/metrics":
        return {"assets_analyzed": 1, "candidates": 1, "browser_actions": 0,
                "confirmed": 0, "manual_review": 1}
    if path == "domxss/example/inventory":
        return {"items": [{"recon_asset_id": 17, "host": "app.example.test",
                           "latest_sha256": "a" * 64, "score": 82,
                           "reasons": ["Current first-party JavaScript"]}], "bounded": True}
    if path == "domxss/example/candidates":
        return {"items": [dom_candidate], "next_cursor": None}
    if path == f"domxss/example/candidates/{DOM_CANDIDATE}":
        return dom_candidate
    if path == f"domxss/example/candidates/{DOM_CANDIDATE}/runtime":
        return {"links": dom_candidate["links"], "run_status": "COMPLETED",
                "validation_status": "INCONCLUSIVE", "trials": [{
                    "variant": "benign", "marker_observed": False,
                    "marker_context": "frame", "document_origin": "https://app.example.test",
                    "csp_present": True, "trusted_types_enforced": False,
                    "sandbox_flags": [], "browser_blocked": False,
                    "evidence_id": "EV-" + "2" * 32,
                }]}
    if path == "domxss/example/analyze":
        return {"status": "REUSED", "source_map_status": "NOT_REQUESTED"}
    message_candidate = {
        "id": MESSAGE_CANDIDATE, "target_id": TARGET, "asset_hashes": ["c" * 64],
        "artifact_ids": ["EV-" + "3" * 32], "message_types": ["connect"],
        "reply_types": ["ready"], "receiver": "window message listener",
        "receiver_line": 42, "origin_checks": [], "source_checks": [],
        "origin_validation": "MISSING", "source_validation": "MISSING",
        "port_accepted": True, "port_created": False, "port_bound": True,
        "rpc_methods": ["readSynthetic"], "sensitive_operations": ["READ_DATA"],
        "protocol_sequence": ["connect", "ready", "MessagePort", "readSynthetic"],
        "sender_contexts": ["iframe"], "related_protocols": [], "priority": 92,
        "status": "STATIC_CANDIDATE", "runtime_status": "NOT_TESTED",
        "route": "/preview", "source_map_sha256": "d" * 64,
        "mapped_source": "src/bridge.js", "evidence_ids": ["EV-" + "4" * 32],
        "links": {"hypothesis_id": "HYP-" + "2" * 32, "plan_id": PLAN,
                  "run_id": RUN, "validation_id": VALIDATION},
    }
    if path == "postmessage/example/metrics":
        return {"handlers": 1, "protocols": 1, "message_port_candidates": 1,
                "rpc_methods": 1, "runtime_tests": 2, "messages_sent": 4,
                "rpc_calls": 2, "confirmed": 0, "rejected": 0,
                "manual_review": 1}
    if path == "postmessage/example/inventory":
        return {"items": [{"recon_asset_id": 19, "host": "app.example.test",
                           "latest_sha256": "c" * 64, "score": 92,
                           "reasons": ["MessagePort bridge"]}], "bounded": True}
    if path == "postmessage/example/candidates":
        return {"items": [message_candidate], "next_cursor": None}
    if path == f"postmessage/example/candidates/{MESSAGE_CANDIDATE}":
        return message_candidate
    if path == f"postmessage/example/candidates/{MESSAGE_CANDIDATE}/runtime":
        return {"links": message_candidate["links"], "run_status": "COMPLETED",
                "validation_status": "INCONCLUSIVE", "trials": [{
                    "variant": "UNRELATED_ORIGIN", "attacker_origin": "http://attacker.fixture.invalid",
                    "source_relationship": "UNRELATED_IFRAME", "capability_observed": True,
                    "effect_kind": "SYNTHETIC_READ", "message_count": 2,
                    "port_count": 1, "rpc_calls": 1,
                    "evidence_id": "EV-" + "5" * 32,
                }]}
    if path == "postmessage/example/analyze":
        return {"status": "REUSED", "candidate_ids": [MESSAGE_CANDIDATE]}
    hypothesis = {"id": "HYP-" + "a" * 32, "category": "CROSS_TENANT",
                  "statement": "Tenant-scoped project access may lack ownership enforcement",
                  "status": "ENRICHING", "priority": 78, "potential_impact": "Potential cross-tenant data access",
                  "why_generated": "Deterministic rule from recon and owned identities",
                  "evidence_ids": ["EV-" + "b" * 32], "fact_ids": [], "evidence_count": 1,
                  "prerequisite_state": "MISSING", "prerequisites": ["known owned objects"],
                  "missing": ["owned objects with known ownership"],
                  "future_experiment": "Compare owned object under both identities",
                  "positive_signal": "Foreign identity receives protected object",
                  "negative_signal": "Backend denies access", "skill_tags": ["cross-tenant-object-authorization"],
                  "created_at": "2026-10-11T00:00:00+00:00"}
    if path == "hypotheses":
        return {"items": [hypothesis], "next_cursor": None}
    if path == "hypotheses/" + hypothesis["id"]:
        return {"hypothesis": hypothesis, "context": {"signals": [], "evidence": [], "facts": []},
                "history": [], "relationships": [], "recommended_skills": []}
    if path == "skills":
        return {"items": [{"name": "cross-tenant-object-authorization", "category": "authorization",
                           "source": "CORE", "version": "1.0.0", "triggers": ["CROSS_TENANT"],
                           "risk": "MEDIUM", "request_budget": 6, "usage_count": 0}]}
    if path == "skills/cross-tenant-object-authorization":
        return {"name": "cross-tenant-object-authorization", "description": "Owned tenant comparison",
                "when_to_use": "Two owned tenants", "when_not_to_use": "Same tenant",
                "category": "authorization", "source": "CORE", "version": "1.0.0", "risk": "MEDIUM",
                "prerequisites": ["multiple_tenants"], "controls": ["Owner request"],
                "confirmation_requirements": ["Protected data"], "rejection_conditions": ["Public object"],
                "request_budget": 6, "token_budget": 1800, "content_hash": "a" * 64,
                "workflow": [{"type": "OBSERVE", "description": "Map ownership"}]}
    if path == "plans/PLAN-" + "c" * 32:
        return {"id": "PLAN-" + "c" * 32, "hypothesis_id": hypothesis["id"],
                "skill_id": "cross-tenant-object-authorization", "skill_version": "1.0.0",
                "skill_hash": "a" * 64, "status": "BLOCKED_PREREQUISITES", "risk": "MEDIUM",
                "prerequisites": {"state": "MISSING_OBJECT", "missing": ["known_ownership"]},
                "request_budget": 6, "expected_request_count": 0, "token_budget": 1800,
                "manual_selection": False, "positive_signals": ["Protected object"],
                "negative_signals": ["Denied"], "evidence_requirements": ["Known ownership"],
                "confirmation_requirements": ["Fresh proof"], "rejection_conditions": ["Public object"],
                "controls": ["Owner request"], "steps": [{"type": "OBSERVE", "description": "Map ownership"}],
                "proposed_actions": []}
    run = {"id": RUN, "plan_id": PLAN, "hypothesis_id": hypothesis["id"],
           "skill_id": "cross-tenant-object-authorization", "skill_version": "1.0.0",
           "skill_hash": "a" * 64, "snapshot_hash": "b" * 64, "status": "COMPLETED",
           "finding_status": "UNVALIDATED", "current_step": 2, "request_budget": 2,
           "requests_consumed": 1, "token_budget": 1800, "approval_id": None,
           "stop_reason": "EXECUTION_RECORDED", "created_at": "2026-10-11T00:00:00+00:00",
           "started_at": "2026-10-11T00:00:01+00:00",
           "updated_at": "2026-10-11T00:00:02+00:00",
           "finished_at": "2026-10-11T00:00:02+00:00"}
    if path in ("runs", f"plans/{PLAN}/runs"):
        return {"items": [run], "next_cursor": None}
    if path == "approvals":
        return {"items": [{"id": "APPROVAL-" + "6" * 32,
                           "target_id": TARGET, "hypothesis_id": hypothesis["id"],
                           "action_id": "ACTION-" + "5" * 32,
                           "plan_run": {"run_id": RUN}, "operation": "renameProject",
                           "category": "OBJECT_UPDATE", "risk": "LOW",
                           "reason_code": "APPROVAL_REQUIRED", "identity_id": IDENTITY,
                           "object_type": "project", "object_ref_hash": "a" * 64,
                           "created_at": "2026-10-11T00:00:00+00:00", "status": "PENDING"}],
                "next_cursor": None}
    if path == f"runs/{RUN}":
        return {"run": run, "mutation_cleanup_status": "RESTORED",
                "mutation_approval": {"object_id": OBJECT, "object_type": "project",
                                      "field": "name", "action": "RENAME",
                                      "old_summary": "sha256:111111111111",
                                      "new_summary": "sha256:222222222222",
                                      "acting_identity_id": IDENTITY, "risk": "LOW",
                                      "disposable": True, "object_state": "CLEANUP_PENDING",
                                      "cleanup_strategy": "RESTORE", "recipe_current": True},
                "mutation_results": [{"phase": "BOUNDARY", "status": "VERIFIED",
                                      "readback_exchange_id": EXCHANGE}], "steps": [
            {"id": "STEP-" + "e" * 32, "ordinal": 0, "type": "CHECK_PREREQUISITES",
             "role": "OTHER", "status": "COMPLETED", "control_step_id": None,
             "decision_id": None, "approval_id": None, "permit_id": None,
             "execution_id": None, "safe_reason": "PREREQUISITES_CURRENT", "result": None,
             "manual_review": None},
            {"id": "STEP-" + "f" * 32, "ordinal": 1, "type": "EXECUTE_REQUEST",
             "role": "CONTROL", "status": "COMPLETED", "control_step_id": None,
             "decision_id": "DECISION-" + "1" * 32, "approval_id": None,
             "permit_id": "PERMIT-" + "2" * 32, "execution_id": "EXEC-" + "3" * 32,
             "safe_reason": "EXECUTION_RECORDED", "manual_review": None,
             "result": {"status_code": 200, "error_class": None,
                        "traffic_exchange_ids": [EXCHANGE], "evidence_ids": ["EV-" + "4" * 32]}}],
                "timeline": [{"event_type": "RUN_CREATED", "reason_code": "PLAN_SELECTED",
                              "occurred_at": "2026-10-11T00:00:00+00:00", "step_id": None},
                             {"event_type": "RUN_COMPLETED", "reason_code": "EXECUTION_RECORDED",
                              "occurred_at": "2026-10-11T00:00:02+00:00", "step_id": "STEP-" + "f" * 32}]}
    validation = {"id": VALIDATION, "target_id": TARGET, "run_id": RUN, "plan_id": PLAN,
                  "hypothesis_id": hypothesis["id"], "skill_id": "cross-tenant-object-authorization",
                  "skill_version": "1.0.0", "validator_id": "authorization_cross_tenant",
                  "validator_version": "1.0.0", "source": "DETERMINISTIC", "status": "CONFIRMED",
                  "controls_evaluated": ["OWNER_CONTROL", "INVALID_OBJECT"],
                  "confirmation_criteria": ["Known ownership", "Protected content"],
                  "rejection_criteria": ["Intentionally public"],
                  "checks": [{"code": "OWNER_CONTROL", "outcome": "PASS", "evidence_ids": ["EV-" + "a" * 32]},
                             {"code": "PROTECTED_CONTENT", "outcome": "PASS", "evidence_ids": ["EV-" + "b" * 32]}],
                  "supporting_evidence_ids": ["EV-" + "a" * 32, "EV-" + "b" * 32],
                  "contradicting_evidence_ids": [], "impact": {"demonstrated": "PROTECTED_OBJECT_READ",
                                                          "potential": None},
                  "reproduction_count": 2, "reason_codes": ["UNAUTHORIZED_PROTECTED_READ"],
                  "limitations": ["Fixture only"], "duplicate_of_finding_id": None,
                  "supersedes_id": None, "evidence_snapshot_hash": "a" * 64,
                  "created_at": "2026-10-11T00:00:03+00:00"}
    finding = {"id": FINDING, "target_id": TARGET, "validation_id": VALIDATION,
               "hypothesis_id": hypothesis["id"], "title": "Cross tenant BOLA in controlled fixture",
               "category": "CROSS_TENANT_BOLA", "status": "CONFIRMED",
               "safe_summary": "Protected boundary effect reproduced with owned controls.",
               "impact": {"demonstrated": "PROTECTED_OBJECT_READ", "potential": None},
               "object_type": "fixture_record", "root_cause_fingerprint": "c" * 64,
               "evidence_ids": validation["supporting_evidence_ids"], "evidence_count": 2,
               "locations": ["d" * 64], "duplicate_validation_ids": [],
               "report_readiness": "RESEARCHER_REVIEW_REQUIRED",
               "created_at": "2026-10-11T00:00:03+00:00"}
    if path == "validations":
        return {"items": [validation], "next_cursor": None}
    if path == f"validations/{VALIDATION}":
        return {"validation": validation, "finding": finding}
    if path == "findings":
        return {"items": [finding], "next_cursor": None}
    if path == f"findings/{FINDING}":
        return {"finding": finding, "validation": validation,
                "workflow": {"workflow_version": 1, "allowed_transitions": [],
                             "submission": None, "lineage": {"skill_id": None,
                             "skill_version": None, "planner_links": []}, "history": []},
                "report_attempt": None, "latest_draft": None, "notifications": []}
    if path == "hypotheses/manual":
        return hypothesis
    if path == "targets/example/identities":
        return {"items": [{"identity": {"id": IDENTITY, "alias": "owned_admin",
                                         "principal_id": None, "status": "ACTIVE"},
                           "memberships": [{"tenant_id": "TENANT-1", "tenant": "Owned tenant",
                                            "roles": ["Admin"], "status": "ACTIVE"}],
                           "auth": {"status": "REAUTH_REQUIRED"},
                           "browser": {"status": "WAITING_LOGIN"}}], "next_cursor": None}
    if path == "browser/sessions":
        return {"items": [{"id": SESSION, "identity_id": IDENTITY, "status": "WAITING_LOGIN",
                           "verification_status": "UNVERIFIED", "created_at": "2026-10-11T00:00:00+00:00",
                           "last_verified_at": None, "proxy_enabled": False, "proxy_capture_required": False,
                           "browser_running": True, "vnc_available": True,
                           "vnc_url": "http://127.0.0.1:6901/vnc.html"},
                          {"id": CREATOR_SESSION, "identity_id": IDENTITY, "status": "VALID",
                           "verification_status": "VERIFIED",
                           "created_at": "2026-10-11T00:00:00+00:00",
                           "last_verified_at": "2026-10-11T00:00:01+00:00",
                           "proxy_enabled": False, "proxy_capture_required": False,
                           "browser_running": False, "vnc_available": False,
                           "vnc_url": None}], "next_cursor": None}
    traffic = {"id": EXCHANGE, "observed_at": "2026-10-11T00:00:00+00:00", "source": "FIXTURE",
               "capture_provider": "FIXTURE", "scope_result": "IN_SCOPE", "evidence_ids": ["EV-test"],
               "request": {"method": "GET", "origin": "https://example.test", "display_path": "/api/users/{id}",
                           "structural_fingerprint": "a" * 64, "content_type": None, "body_hash": None},
               "response": {"status_code": 200, "content_type": "application/json", "body_hash": "b" * 64},
               "attribution": {"auth_state": "UNVERIFIED_IDENTITY", "declared_identity_id": IDENTITY,
                               "verified_identity_id": None, "declared_tenant_ids": [], "browser_session_id": SESSION}}
    if path == "traffic":
        return {"items": [traffic], "next_cursor": None}
    if path == "traffic/" + EXCHANGE:
        return traffic
    if path == "burp/status":
        return {"availability": "BURP_AVAILABLE", "status": "BURP_RUNNING",
                "bridge_connected": False, "configured_listeners": 0,
                "reachable_listeners": 0, "proxy_listener_capacity": 4,
                "proxy_listeners_reachable": 4, "installed_version": "2026.9.2",
                "captured_exchanges": 18, "last_capture_at": "2026-10-13T13:11:48+00:00"}
    planner_run = {"id": PLANNER_RUN, "mode": "PLAN_ONLY", "status": "WAITING_LOGIN",
                   "created_at": "2026-10-13T00:00:00+00:00", "started_at": "2026-10-13T00:00:00+00:00",
                   "stop_reason": None, "readiness": {"scope_ready": True,
                       "identity_coverage": "LOGIN_NEEDED", "behaviour_coverage": "PARTIAL",
                       "recommendations": ["BOOTSTRAP_TARGET_PROFILE"]},
                   "limits": {"requests": 20, "browser_actions": 12, "tokens": 2000,
                              "seconds": 300},
                   "usage": {"requests": 0, "browser_actions": 0, "tokens": 0}}
    if path == "planner/example/runs":
        return {"items": [planner_run]}
    if path == "planner/example/runs/" + PLANNER_RUN:
        return {"run": planner_run, "metrics": {"considered": 1, "selected": 1,
                "deferred": 0, "blocked": 0, "validations": 0,
                "confirmed_root_causes": 0, "research_requests": 0,
                "manual_reviews": 0, "duration_seconds": 12},
                "candidates": [{"id": PLANNER_CANDIDATE, "priority": 86,
                    "category": "CROSS_TENANT", "specialist": "AUTHORIZATION",
                    "gaps": ["MISSING_IDENTITY"], "freshness": "CURRENT", "risk": "LOW",
                    "estimated_requests": 5, "reason_codes": ["HIGH_VALUE_BOUNDARY"],
                    "status": "SELECTED"}],
                "tasks": [{"id": PLANNER_TASK, "priority": 86,
                    "task_type": "RESOLVE_IDENTITY", "candidate_id": PLANNER_CANDIDATE,
                    "dependencies": [], "status": "WAITING", "reason_code": "LOGIN_REQUIRED"}],
                "findings": [], "research_briefs": [],
                "events": [{"event_type": "PLANNER_STARTED", "reason_code": "EXPLICIT_OPERATOR_RUN",
                            "candidate_id": None, "occurred_at": "2026-10-13T00:00:00+00:00"}]}
    raise AssertionError(path)


@unittest.skipUnless(sync_playwright is not None and os.environ.get("HACKBOT_TEST_CHROMIUM"),
                     "requires explicit local Chromium fixture")
class HackBotUiSmoke(unittest.TestCase):
    def setUp(self):
        self.synthetic_target = None
        self.synthetic_target_autonomy = None
        self.synthetic_accounts = []
        self.synthetic_ready = False
        self.synthetic_hunt = None
        self.synthetic_hunt_posts = 0
        self.synthetic_hunt_login_alias = None

    @classmethod
    def setUpClass(cls):
        app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))

        @app.get("/hackbot")
        @app.get("/hackbot/<section>")
        def page(section="overview"):
            return render_template("hackbot_panel.html", section=section, csrf_token="fixture-csrf",
                                   hunt_ui_enabled=True)

        cls.server = make_server("127.0.0.1", 0, app, threaded=True)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=3)

    def route(self, route):
        from urllib.parse import urlsplit
        path = urlsplit(route.request.url).path.removeprefix("/api/hackbot/")
        import json
        method = route.request.method
        if path == "targets" and method == "POST":
            body = route.request.post_data_json
            self.synthetic_target_autonomy = body["autonomy"]
            self.synthetic_target = {"id": body["id"], "target_id": "TARGET-" + "9" * 32,
                                     "name": body["name"], "primary_domain": body["primary_domain"],
                                     "status": "TRACKED", "scope_summary": {"included_hosts": len(body["scope"]["include"]),
                                     "excluded_hosts": len(body["scope"]["exclude"])},
                                     "counts": {"identities": 0, "browser_sessions": 0, "traffic": 0}}
            value = {"target": self.synthetic_target, "network_requests_sent": 0}
        elif path in {"targets/example/hunt", "targets/later/hunt"}:
            if method == "POST":
                self.synthetic_hunt_posts += 1
                self.synthetic_hunt = {"id": "HUNT-" + "a" * 32, "target_id": TARGET,
                                       "package_id": "example", "mode": "SUPERVISED",
                                       "state": "LOGIN_REQUIRED", "reason_code": "ACCOUNT_LOGIN_REQUIRED",
                                       "campaign_id": None, "created_at": "2026-10-20T00:00:00+00:00",
                                       "updated_at": "2026-10-20T00:00:00+00:00"}
            value = {"hunt": self.synthetic_hunt, "mapping": [],
                     "findings": ([{"id": FINDING, "title": "Controlled cross-tenant read",
                                    "status": "CONFIRMED", "severity": "HIGH",
                                    "report_id": "REPORT-test"}]
                                  if self.synthetic_hunt and
                                  self.synthetic_hunt.get("campaign_id") else []),
                     "investigation": ({"status": "RUNNING", "cycle": 2,
                                        "max_cycles": 8, "candidates": 14,
                                        "selected": 3, "experiments": 2,
                                        "validations": 1, "rejected_validations": 0,
                                        "findings": 1, "report_drafts": 1,
                                        "cleanup_pending": 0, "requests_used": 23,
                                        "requests_limit": 160,
                                        "resource": {"state": "OK",
                                                     "load_per_cpu": 0.4,
                                                     "memory_available_bytes": 2147483648,
                                                     "swap_used_percent": 12,
                                                     "disk_used_percent": 45},
                                        "adaptive": {"requests": 10,
                                                     "browsers_active": 3,
                                                     "browser_limit": 4,
                                                     "burp_listeners_active": 3,
                                                     "burp_listener_capacity": 4,
                                                     "median_latency_ms": 240}}
                                       if self.synthetic_hunt and
                                       self.synthetic_hunt.get("campaign_id") else None),
                     "inventory": {"js_assets_current": 3,
                                   "api_operations_current": 7,
                                   "api_operations_observed": 2,
                                   "graphql_operations_current": 1},
                     "needs_you": [{"kind": "LOGIN_REQUIRED", "alias": "owned_admin",
                                    "session_id": SESSION}] if self.synthetic_hunt and
                                    self.synthetic_hunt["state"] == "LOGIN_REQUIRED" else [],
                     "events": [{"to_state": "LOGIN_REQUIRED",
                                 "reason_code": "ACCOUNT_LOGIN_REQUIRED",
                                 "occurred_at": "2026-10-20T00:00:00+00:00"}]
                     if self.synthetic_hunt else []}
        elif path == f"browser/sessions/{SESSION}/login-complete" and method == "POST":
            self.synthetic_hunt_login_alias = route.request.post_data_json.get("confirm_alias")
            self.synthetic_hunt["state"] = "PREPARING"
            self.synthetic_hunt["reason_code"] = "IDENTITY_CONFIRMED_REPREPARE"
            value = {"id": SESSION, "status": "VALID",
                     "verification_method": "OPERATOR_CONFIRMED"}
        elif path == "targets" and self.synthetic_target:
            value = fixture(path)
            value["items"].append(self.synthetic_target)
        elif self.synthetic_target and path.startswith("targets/" + self.synthetic_target["id"]):
            suffix = path.removeprefix("targets/" + self.synthetic_target["id"])
            if suffix == "": value = self.synthetic_target
            elif suffix == "/accounts":
                if method == "POST":
                    self.synthetic_accounts = route.request.post_data_json["accounts"]
                value = {"items": [{**item, "registration": "NOT_REGISTERED",
                                    "session": "SESSION_MISSING"} for item in self.synthetic_accounts],
                         "configured": len(self.synthetic_accounts), "sessions_ready": 0}
            elif suffix == "/bootstrap":
                value = fixture("targets/example/bootstrap")
                if self.synthetic_ready:
                    value["transport"].update({"transport_ready": True,
                                               "burp_capture_ready": True,
                                               "cold_start_available": True,
                                               "blocked_reason": None,
                                               "anonymous_listener_port": 38083})
            elif suffix == "/identities":
                value = {"items": [], "next_cursor": None}
            elif suffix == "/policy":
                value = fixture("targets/example/policy")
            elif suffix == "/hunt":
                value = {"hunt": None, "mapping": [], "needs_you": [], "events": []}
            else: raise AssertionError(path)
        else:
            if path.startswith("targets/later/"):
                value = fixture(path.replace("targets/later/", "targets/example/", 1))
            else:
                value = fixture(path)
        route.fulfill(status=201 if path == "targets" and method == "POST" else
                      202 if path == "targets/example/hunt" and method == "POST" else 200,
                      content_type="application/json", body=json.dumps(value))

    def test_hunt_start_from_target_detail(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                page.route("**/api/hackbot/**", self.route)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/targets?target=example")
                page.locator("#targetTabContent").get_by_role("button", name="Start Hunt").click()
                page.locator("#targetTabContent").get_by_text("LOGIN_REQUIRED", exact=True).wait_for()
                self.assertEqual(self.synthetic_hunt_posts, 1)
                self.assertIn("Login required: owned_admin", page.locator("#targetTabContent").inner_text())
                self.assertTrue(page.locator("#targetTabContent").get_by_role("button", name="Open").is_visible())
                self.assertEqual(page.locator("#message").inner_text(), "")
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/hunt?target=example")
                page.locator("#huntContent").get_by_text("LOGIN_REQUIRED", exact=True).wait_for()
                self.assertEqual(page.locator("#huntContent").get_by_role("button", name="Start Hunt").count(), 0)
                self.assertTrue(page.locator("#huntContent").get_by_text(
                    "GraphQL operations", exact=True).is_visible())
                self.assertIn("Current JS", page.locator("#huntContent").inner_text())
                page.set_viewport_size({"width": 390, "height": 844})
                self.assertTrue(page.locator("#huntContent").get_by_role("button", name="Open").is_visible())
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
                page.locator("#huntContent").get_by_role(
                    "button", name="I finished login as owned_admin").click()
                page.locator("#huntContent").get_by_text("PREPARING", exact=True).wait_for()
                self.assertEqual(self.synthetic_hunt_login_alias, "owned_admin")
                self.assertIn("None", page.locator("#huntContent").inner_text())
                self.synthetic_hunt["state"] = "HUNTING"
                self.synthetic_hunt["campaign_id"] = "CMP-" + "c" * 32
                page.locator("#huntContent").get_by_role("button", name="Refresh").click()
                page.locator("#huntContent").get_by_text("Investigation", exact=True).wait_for()
                self.assertIn("Experiments", page.locator("#huntContent").inner_text())
                self.assertIn("Swap used", page.locator("#huntContent").inner_text())
                self.assertIn("23 / 160", page.locator("#huntContent").inner_text())
                self.assertTrue(page.locator("#huntContent").get_by_role(
                    "link", name="Controlled cross-tenant read").is_visible())
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 391)
            finally:
                browser.close()

    def test_views_desktop_and_mobile(self):
        output = Path(os.environ.get("HACKBOT_UI_SCREENSHOT_DIR", "/tmp"))
        output.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.route("**/api/hackbot/**", self.route)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot")
                page.get_by_text("Captured exchanges", exact=True).first.wait_for()
                self.assertIn("BURP_RUNNING", page.locator("#metrics").inner_text())
                page.screenshot(path=str(output / "hackbot-overview-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/targets")
                page.get_by_role("button", name="Open", exact=True).click()
                self.assertIn("Example program", page.locator("#targetDetail").inner_text())
                page.screenshot(path=str(output / "hackbot-target-desktop.png"), full_page=True)
                page.get_by_role("tab", name="Scope").click()
                page.locator("#targetTabContent").get_by_text("admin.example.test", exact=True).wait_for()
                self.assertIn("admin.example.test", page.locator("#targetDetail").inner_text())
                page.get_by_role("tab", name="Profile").click()
                page.get_by_text("JavaScript assets sampled", exact=True).wait_for()
                self.assertIn("CROSS_TENANT_PAIR", page.locator("#targetTabContent").inner_text())
                page.get_by_role("tab", name="Objects").click()
                page.locator("#targetTabContent").get_by_text("1 registered", exact=False).wait_for()
                self.assertIn("Open disposable objects", page.locator("#targetTabContent").inner_text())
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/targets?target=later")
                page.locator("#detailName").get_by_text("Later program", exact=True).wait_for()
                self.assertEqual(page.locator("#targetSelect").input_value(), "later")
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/accounts?target=example")
                page.locator("#accountRows").get_by_text("owned_admin", exact=True).wait_for()
                self.assertIn("owned_admin", page.locator("#accountRows").inner_text())
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/sessions?target=example")
                page.locator("#sessionRows").get_by_text("Login required", exact=True).wait_for()
                self.assertIn("Login required", page.locator("#sessionRows").inner_text())
                self.assertTrue(page.get_by_role("button", name="Open VNC").is_visible())
                self.assertTrue(page.get_by_role("button", name="Login complete").is_visible())
                page.screenshot(path=str(output / "hackbot-sessions-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/traffic?target=example")
                page.locator("#trafficRows").get_by_text("/api/users/{id}", exact=False).wait_for()
                self.assertIn("/api/users/{id}", page.locator("#trafficRows").inner_text())
                page.get_by_role("button", name="Details").click()
                page.locator("#trafficDialog").get_by_text("Safe URL shape", exact=True).wait_for()
                self.assertIn("Safe URL shape", page.locator("#trafficDialog").inner_text())
                page.screenshot(path=str(output / "hackbot-traffic-detail-desktop.png"), full_page=True)
                page.get_by_role("button", name="Close detail").click()
                page.screenshot(path=str(output / "hackbot-traffic-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/objects?target=example")
                page.locator("#objectRows").get_by_text("project", exact=True).wait_for()
                page.screenshot(path=str(output / "hackbot-objects-desktop.png"), full_page=True)
                page.locator("#objectRows").get_by_role("button", name="View").click()
                page.locator("#objectEvents").get_by_text("OWNERSHIP_VERIFIED").wait_for()
                self.assertIn("RESTORED", page.locator("#objectDetails").inner_text())
                self.assertIn("RESTORE", page.locator("#objectMutationHistory").inner_text())
                self.assertTrue(page.locator("#objectActions select").is_visible())
                self.assertTrue(page.locator("#objectActions").get_by_role("button", name="Clean up").is_visible())
                page.screenshot(path=str(output / "hackbot-object-detail-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/domxss?target=example")
                page.locator("#domCandidateRows").get_by_text("location.search").wait_for()
                self.assertIn("app.example.test", page.locator("#domAssetRows").inner_text())
                self.assertIn("MANUAL REVIEW", page.locator("#domMetrics").inner_text())
                page.locator("#domCandidateRows").get_by_role("button", name="Inspect").click()
                page.locator("#domCandidateFacts").get_by_text("src/preview.js").wait_for()
                self.assertIn("INCONCLUSIVE", page.locator("#domCandidateFacts").inner_text())
                self.assertIn("benign", page.locator("#domProofRows").inner_text())
                self.assertNotIn("raw-secret-fixture", page.locator("#domxssView").inner_text())
                page.screenshot(path=str(output / "hackbot-domxss-desktop.png"), full_page=True)
                sent = []
                page.on("request", lambda request: sent.append(request) if request.url.endswith(
                    "/api/hackbot/domxss/example/analyze") else None)
                page.locator("#domAssetRows").get_by_role("button", name="Analyze").click()
                page.get_by_text("REUSED; source map: NOT_REQUESTED.").wait_for()
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0].header_value("x-csrf-token"), "fixture-csrf")
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/postmessage?target=example")
                page.locator("#messageCandidateRows").get_by_text("connect", exact=True).wait_for()
                self.assertIn("app.example.test", page.locator("#messageAssetRows").inner_text())
                self.assertIn("MESSAGEPORTS", page.locator("#messageMetrics").inner_text())
                page.locator("#messageCandidateRows").get_by_role("button", name="Inspect").click()
                page.locator("#messageCandidateFacts").get_by_text("src/bridge.js").wait_for()
                self.assertIn("INCONCLUSIVE", page.locator("#messageCandidateFacts").inner_text())
                self.assertIn("SYNTHETIC_READ", page.locator("#messageProofRows").inner_text())
                self.assertNotIn("raw-secret-fixture", page.locator("#postmessageView").inner_text())
                page.screenshot(path=str(output / "hackbot-postmessage-desktop.png"), full_page=True)
                sent = []
                page.on("request", lambda request: sent.append(request) if request.url.endswith(
                    "/api/hackbot/postmessage/example/analyze") else None)
                page.locator("#messageAssetRows").get_by_role("button", name="Analyze").click()
                page.get_by_text("REUSED; 1 protocol candidates.").wait_for()
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0].header_value("x-csrf-token"), "fixture-csrf")
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/scope?target=example")
                page.get_by_text("admin.example.test", exact=True).wait_for()
                self.assertIn("NOT AUTHORIZATION", page.locator("#scopeView").inner_text())
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/burp?target=example")
                page.get_by_text("Burp listeners", exact=True).wait_for()
                self.assertEqual(page.locator("#burpState").inner_text(), "BURP_RUNNING")
                self.assertIn("2026.9.2", page.locator("#burpMetrics").inner_text())
                self.assertIn("4 reachable / 4 configured", page.locator("#burpMetrics").inner_text())
                self.assertIn("0 reachable / 0 assigned", page.locator("#burpMetrics").inner_text())
                page.screenshot(path=str(output / "hackbot-burp-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/hypotheses?target=example")
                page.locator("#hypothesisRows").get_by_text("Tenant-scoped project access").wait_for()
                page.get_by_role("button", name="Details").click()
                page.locator("#hypothesisDialog").get_by_text("Future experiment", exact=True).wait_for()
                page.screenshot(path=str(output / "hackbot-hypotheses-detail-desktop.png"), full_page=True)
                page.get_by_role("button", name="Close detail").last.click()
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/skills")
                page.locator("#skillRows").get_by_text("cross-tenant-object-authorization").wait_for()
                page.locator("#skillRows").get_by_role("button", name="Details").click()
                page.locator("#skillDialog").get_by_text("Map ownership").wait_for()
                page.screenshot(path=str(output / "hackbot-skills-desktop.png"), full_page=True)
                page.locator("#closeSkill").click()
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/plans?target=example&plan=PLAN-{'c' * 32}")
                page.locator("#planSummary").get_by_text("BLOCKED_PREREQUISITES").wait_for()
                page.screenshot(path=str(output / "hackbot-plan-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/runs?target=example")
                page.locator("#runRows").get_by_text("cross-tenant-object-authorization").wait_for()
                page.screenshot(path=str(output / "hackbot-runs-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/runs?target=example&run={RUN}")
                page.locator("#runSummary").get_by_text("UNVALIDATED").wait_for()
                self.assertIn("sha256:111111111111", page.locator("#runMutationSummary").inner_text())
                self.assertIn("VERIFIED", page.locator("#runMutationHistory").inner_text())
                self.assertIn("RUN_COMPLETED", page.locator("#runTimeline").inner_text())
                page.screenshot(path=str(output / "hackbot-run-detail-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/approvals?target=example")
                page.locator("#approvalRows").get_by_text("renameProject").wait_for()
                page.locator("#approvalRows").get_by_role("button", name="Review action").click()
                page.locator("#mutationApprovalDetail").get_by_text("name / RENAME").wait_for()
                self.assertIn("sha256:222222222222", page.locator("#mutationApprovalDetail").inner_text())
                page.locator("#closeMutationApproval").click()
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/validations?target=example")
                page.locator("#validationRows").get_by_text("CONFIRMED").wait_for()
                page.screenshot(path=str(output / "hackbot-validations-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/validations?target=example&id={VALIDATION}")
                page.locator("#validationCheckRows").get_by_text("PROTECTED CONTENT").wait_for()
                page.screenshot(path=str(output / "hackbot-validation-detail-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/findings?target=example")
                page.locator("#findingRows").get_by_text("Cross tenant BOLA").wait_for()
                page.screenshot(path=str(output / "hackbot-findings-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/findings?target=example&id={FINDING}")
                page.locator("#findingSummary").get_by_text("PROTECTED_OBJECT_READ").wait_for()
                page.screenshot(path=str(output / "hackbot-finding-detail-desktop.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/hypotheses?target=example")
                page.get_by_role("button", name="Add hypothesis", exact=True).first.click()
                page.locator("#manualHypothesisForm input[name=statement]").fill("Review project sharing policy")
                page.locator("#manualHypothesisForm input[name=future_experiment]").fill("Compare owned roles")
                page.locator("#manualHypothesisForm button[type=submit]").click()
                page.locator("#manualHypothesisDialog").wait_for(state="hidden")
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "hackbot-hypotheses-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/objects?target=example&id={OBJECT}")
                page.locator("#objectEvents").get_by_text("OWNERSHIP_VERIFIED").wait_for()
                page.screenshot(path=str(output / "hackbot-object-detail-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/skills")
                page.locator("#skillRows").get_by_text("cross-tenant-object-authorization").wait_for()
                page.screenshot(path=str(output / "hackbot-skills-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/domxss?target=example")
                page.locator("#domCandidateRows").get_by_text("location.search").wait_for()
                page.locator("#domCandidateRows").get_by_role("button", name="Inspect").click()
                page.locator("#domCandidateFacts").get_by_text("src/preview.js").wait_for()
                page.screenshot(path=str(output / "hackbot-domxss-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/postmessage?target=example")
                page.locator("#messageCandidateRows").get_by_text("connect", exact=True).wait_for()
                page.locator("#messageCandidateRows").get_by_role("button", name="Inspect").click()
                page.locator("#messageCandidateFacts").get_by_text("src/bridge.js").wait_for()
                page.screenshot(path=str(output / "hackbot-postmessage-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/runs?target=example&run={RUN}")
                page.locator("#runSummary").get_by_text("UNVALIDATED").wait_for()
                page.screenshot(path=str(output / "hackbot-run-detail-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/validations?target=example&id={VALIDATION}")
                page.locator("#validationCheckRows").get_by_text("PROTECTED CONTENT").wait_for()
                page.screenshot(path=str(output / "hackbot-validation-detail-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/findings?target=example&id={FINDING}")
                page.locator("#findingSummary").get_by_text("PROTECTED_OBJECT_READ").wait_for()
                page.screenshot(path=str(output / "hackbot-finding-detail-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/burp?target=example")
                page.screenshot(path=str(output / "hackbot-burp-mobile.png"), full_page=True)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot")
                page.get_by_text("Captured exchanges", exact=True).first.wait_for()
                page.screenshot(path=str(output / "hackbot-overview-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
            finally:
                browser.close()

    def test_api_graphql_view_desktop_and_mobile(self):
        output = Path(os.environ.get("HACKBOT_UI_SCREENSHOT_DIR", "/tmp"))
        output.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.route("**/api/hackbot/**", self.route)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/api?target=example")
                page.locator("#apiOperationRows").get_by_text("GetProject").wait_for()
                self.assertIn("FIELD_AUTH", page.locator("#apiCandidateRows").inner_text())
                page.locator("#apiOperationRows").get_by_role("button", name="Inspect").click()
                page.locator("#apiOperationFields").get_by_text("/node/email", exact=False).wait_for()
                self.assertIn("FIELD_EXPECTATION_UNKNOWN", page.locator("#apiOperationCandidates").inner_text())
                page.screenshot(path=str(output / "hackbot-api-desktop.png"), full_page=True)
                page.locator("#closeApiOperation").click()
                sent = []
                page.on("request", lambda request: sent.append(request) if request.url.endswith(
                    "/api/hackbot/api/example/analyze") else None)
                page.locator("#analyzeApi").click()
                page.get_by_text("Updated.", exact=True).wait_for()
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0].header_value("x-csrf-token"), "fixture-csrf")
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "hackbot-api-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
            finally:
                browser.close()

    def test_planner_view_desktop_and_mobile(self):
        output = Path(os.environ.get("HACKBOT_UI_SCREENSHOT_DIR", "/tmp"))
        output.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.route("**/api/hackbot/**", self.route)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/planner?target=example")
                page.locator("#plannerCandidateRows").get_by_text("CROSS_TENANT").wait_for()
                self.assertIn("LOGIN_REQUIRED", page.locator("#plannerTaskRows").inner_text())
                self.assertIn("bootstrap target profile",
                              page.locator("#plannerSummary").inner_text())
                self.assertIn("CHILD REQUEST SLOTS / RESERVED / LEFT",
                              page.locator("#plannerMetrics").inner_text())
                page.screenshot(path=str(output / "hackbot-planner-desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "hackbot-planner-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
            finally:
                browser.close()

    def test_delta_view_desktop_mobile_and_focused_action(self):
        output = Path(os.environ.get("HACKBOT_UI_SCREENSHOT_DIR", "/tmp"))
        output.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.route("**/api/hackbot/**", self.route)
                sent = []
                page.on("request", lambda request: sent.append(request) if request.url.endswith(
                    f"/api/hackbot/deltas/{DELTA}/campaigns") else None)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/deltas?target=example")
                page.locator("#deltaRows").get_by_text("app.example.test/admin/members").wait_for()
                self.assertIn("Enabled · IDLE", page.locator("#deltaWatchState").inner_text())
                page.locator("#deltaRows").get_by_role("button", name="Inspect").click()
                page.locator("#deltaFacts").get_by_text("PRIVILEGED_NAME").wait_for()
                page.screenshot(path=str(output / "hackbot-deltas-desktop.png"), full_page=True)
                page.locator("#deltaCampaignMode").select_option("PLAN_ONLY")
                page.locator("#deltaCreateCampaign").click()
                page.locator("#message").filter(has_text="Focused campaign").wait_for()
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0].header_value("x-csrf-token"), "fixture-csrf")
                self.assertEqual(__import__("json").loads(sent[0].post_data)["mode"], "PLAN_ONLY")
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "hackbot-deltas-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
            finally:
                browser.close()

    def test_evaluation_view_desktop_and_mobile(self):
        output = Path(os.environ.get("HACKBOT_UI_SCREENSHOT_DIR", "/tmp"))
        output.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.route("**/api/hackbot/**", self.route)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/evaluation")
                page.locator("#evaluationCaseRows").get_by_text("local_download_b").wait_for()
                self.assertIn("SYNTHETIC / EVALUATION", page.locator("#evaluationState").inner_text())
                self.assertIn("NOT_READY", page.locator("#evaluationFacts").inner_text())
                self.assertIn("DOM_XSS", page.locator("#evaluationSpecialistRows").inner_text())
                self.assertIn("NOT_MEASURED", page.locator("#evaluationSpecialistRows").inner_text())
                self.assertIn("No model calls recorded", page.locator("#evaluationModelRows").inner_text())
                self.assertIn("NOT_MEASURED", page.locator("#evaluationModelComparisonFacts").inner_text())
                self.assertIn("Not measured", page.locator("#evaluationModelComparisonRows").inner_text())
                self.assertIn("PRODUCTION_TEST_MATRIX", page.locator("#evaluationGateRows").inner_text())
                page.locator("#evaluationBaseline").select_option(BASELINE)
                page.locator("#compareEvaluation").click()
                page.locator("#evaluationComparison").get_by_text("COMPARABLE").wait_for()
                page.screenshot(path=str(output / "hackbot-evaluation-desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "hackbot-evaluation-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                self.assertEqual(errors, [])
            finally:
                browser.close()


    def test_target_setup_wizard_accounts_and_bootstrap_blocker(self):
        output = Path(os.environ.get("HACKBOT_UI_SCREENSHOT_DIR", "/tmp"))
        output.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.route("**/api/hackbot/**", self.route)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/targets")
                page.get_by_role("button", name="+ Add Target").click()
                page.locator('[name="name"]').fill("Local Sandbox")
                self.assertEqual(page.locator('[name="id"]').input_value(), "local-sandbox")
                page.locator('[name="primary_domain"]').fill("app.local.test")
                page.locator("#targetSetupNext").click()
                page.locator("#targetIncludeHosts input").first.fill("app.local.test")
                page.locator("#addTargetHost").click()
                page.locator("#targetIncludeHosts input").last.fill("api.local.test")
                page.locator("#targetSetupNext").click()
                page.locator('[name="source_reference"]').fill("synthetic authorization")
                page.locator('[name="source_operator"]').fill("fixture-operator")
                page.locator("#targetSetupNext").click()
                self.assertEqual(page.locator('[name="safe_read"]').input_value(), "ALLOW")
                self.assertEqual(page.locator('[name="create_disposable_objects"]').input_value(), "DENY")
                page.locator('[name="state_changing"]').select_option("ALLOW")
                page.locator('[name="create_disposable_objects"]').select_option("ALLOW")
                page.locator('[name="modify_disposable_objects"]').select_option("ALLOW")
                page.locator('[name="delete_disposable_objects"]').select_option("ALLOW")
                page.locator('[name="cross_identity_testing"]').select_option("ALLOW")
                page.locator("#targetSetupNext").click()
                page.locator("#targetSetupNext").click()
                self.assertIn("app.local.test", page.locator("#targetSetupReview").inner_text())
                page.screenshot(path=str(output / "hackbot-target-review-desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                page.screenshot(path=str(output / "hackbot-target-review-mobile.png"), full_page=True)
                page.set_viewport_size({"width": 1440, "height": 900})
                page.locator('[name="confirmed"]').check()
                page.get_by_role("button", name="Create TargetPackage").click()
                page.locator("#targetDetail").wait_for(state="visible")
                self.assertEqual(self.synthetic_target["id"], "local-sandbox")
                self.assertEqual(self.synthetic_target_autonomy["create_disposable_objects"], "ALLOW")
                self.assertEqual(self.synthetic_target_autonomy["cross_identity_testing"], "ALLOW")
                self.assertIn("Local Sandbox", page.locator("#targetSelect").inner_text())
                page.get_by_role("button", name="Configure Accounts").click()
                page.locator("#targetTabContent").get_by_text("Accounts", exact=True).wait_for()
                page.get_by_role("button", name="+ Add Identity").click()
                row = page.locator("#targetTabContent .account-editor-row").first
                row.locator('[name="alias"]').fill("admin")
                row.locator('[name="tenant"]').fill("company1")
                row.locator('[name="role"]').fill("admin")
                page.get_by_role("button", name="Save accounts").click()
                page.get_by_text("1 configured", exact=False).wait_for()
                self.assertEqual(self.synthetic_accounts[0]["alias"], "admin")
                page.get_by_role("tab", name="Bootstrap").click()
                page.get_by_text("ANONYMOUS_BURP_CAPTURE_REQUIRED").wait_for()
                self.assertTrue(page.get_by_role("button", name="Start bootstrap").is_disabled())
                self.synthetic_ready = True
                page.get_by_role("button", name="Refresh").click()
                page.get_by_text("READY · 127.0.0.1:38083").wait_for()
                self.assertTrue(page.get_by_role("button", name="Start bootstrap").is_enabled())
                page.screenshot(path=str(output / "hackbot-target-setup-desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                page.screenshot(path=str(output / "hackbot-target-setup-mobile.png"), full_page=True)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
                self.assertEqual(errors, [])
            finally:
                browser.close()

    def test_target_and_account_text_is_not_html(self):
        marker = '<img src=x onerror="window.__targetXss=1">'
        self.synthetic_target = {"id": "local-xss", "target_id": "TARGET-" + "9" * 32,
                                 "name": marker, "primary_domain": "app.local.test",
                                 "status": "TRACKED", "scope_summary": {"included_hosts": 1,
                                 "excluded_hosts": 0}, "counts": {"identities": 0,
                                 "browser_sessions": 0, "traffic": 0}}
        self.synthetic_accounts = [{"alias": "admin", "tenant": "company1", "role": marker}]
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.environ["HACKBOT_TEST_CHROMIUM"],
                                                 headless=True, args=["--no-sandbox"])
            try:
                page = browser.new_page()
                page.route("**/api/hackbot/**", self.route)
                page.goto(f"http://127.0.0.1:{self.port}/hackbot/targets?target=local-xss")
                page.locator("#detailName").get_by_text(marker, exact=True).wait_for()
                page.get_by_role("tab", name="Accounts").click()
                page.locator('.account-editor-row [name="role"]').wait_for()
                self.assertEqual(page.locator('.account-editor-row [name="role"]').input_value(), marker)
                self.assertFalse(page.evaluate("Boolean(window.__targetXss)"))
                self.assertEqual(page.locator("#targetDetail img").count(), 0)
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
