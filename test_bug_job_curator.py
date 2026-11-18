import unittest
from datetime import datetime, timedelta, timezone

from bug_job_curator import Decision, apply_group_limits, deterministic_decision


NOW = datetime(2026, 9, 18, tzinfo=timezone.utc)


def job(**overrides):
    value = {
        "id": 1,
        "domain_id": 1,
        "target": "example.com",
        "asset_type": "endpoint",
        "asset_value": "https://app.example.com/api/search?q=test",
        "job_type": "xss_reflection_test",
        "priority": 96,
        "scope_ok": True,
        "source_table": "endpoints",
        "source_id": 10,
        "source_observed_at": NOW - timedelta(hours=1),
        "required_context": {
            "payload": {
                "url": "https://app.example.com/api/search?q=test",
                "status_code": 200,
                "parameters": [{"name": "q"}],
            },
            "bug_job_high_signal_reasons": ["xss-signal"],
        },
        "js_risk": {},
    }
    value.update(overrides)
    return value


class CuratorDecisionTests(unittest.TestCase):
    def test_keeps_parameter_backed_xss(self):
        decision = deterministic_decision(job(), NOW, 30)
        self.assertEqual("keep", decision.action)
        self.assertGreaterEqual(decision.score, 96)

    def test_defers_generic_changed_javascript(self):
        candidate = job(
            asset_type="js_asset",
            asset_value="https://static.example.com/app.js",
            job_type="js_dom_xss_review",
            source_table="js_assets",
            source_http_status=200,
            required_context={
                "payload": {"asset_url": "https://static.example.com/app.js", "http_status": 200},
                "bug_job_high_signal_reasons": ["changed-asset", "new-or-changed-javascript-body"],
            },
            js_risk={"dom_sink_count": 0, "postmessage_count": 0, "location_source_count": 2},
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)

    def test_keeps_mandatory_delta_javascript_review_without_static_signal(self):
        sha256 = "d" * 64
        candidate = job(
            asset_type="js_asset",
            asset_value="https://static.example.com/app.js",
            job_type="js_dom_xss_review",
            source_table="js_assets",
            source_http_status=200,
            required_context={
                "payload": {
                    "asset_url": "https://static.example.com/app.js",
                    "http_status": 200,
                    "is_new": True,
                    "is_changed": False,
                },
                "mandatory_delta_js_dom_review": True,
                "javascript_sha256": sha256,
                "scan_lane": "fast_delta",
                "is_delta_scan": True,
                "bug_job_high_signal_reasons": ["delta-new-or-changed-javascript-body"],
            },
            js_risk={"dom_sink_count": 0, "postmessage_count": 0},
        )
        decision = deterministic_decision(candidate, NOW, 30)
        self.assertEqual("keep", decision.action)
        self.assertGreaterEqual(decision.score, 97)

    def test_delta_javascript_review_requires_exact_scan_metadata(self):
        candidate = job(
            asset_type="js_asset",
            asset_value="https://static.example.com/app.js",
            job_type="js_dom_xss_review",
            source_table="js_assets",
            source_http_status=200,
            required_context={
                "payload": {"http_status": 200, "is_new": True},
                "mandatory_delta_js_dom_review": True,
                "javascript_sha256": "d" * 64,
                "scan_lane": "first_run",
                "is_delta_scan": False,
            },
            js_risk={},
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)

    def test_keeps_dom_source_sink_combination(self):
        candidate = job(
            asset_type="js_asset",
            asset_value="https://static.example.com/app.js",
            job_type="js_dom_xss_review",
            source_table="js_assets",
            source_http_status=200,
            required_context={"payload": {"http_status": 200}},
            js_risk={
                "dom_sink_count": 2,
                "postmessage_count": 0,
                "location_source_count": 1,
                "dom_source_sink_proximity_count": 1,
            },
        )
        self.assertEqual("keep", deterministic_decision(candidate, NOW, 30).action)

    def test_defers_file_wide_dom_keyword_cooccurrence(self):
        candidate = job(
            asset_type="js_asset",
            asset_value="https://static.example.com/app.js",
            job_type="js_dom_xss_review",
            source_table="js_assets",
            source_http_status=200,
            required_context={"payload": {"http_status": 200}},
            js_risk={
                "dom_sink_count": 2,
                "location_source_count": 3,
                "dom_source_sink_proximity_count": 0,
            },
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)

    def test_defers_lexical_graphql_javascript(self):
        candidate = job(
            asset_type="js_asset",
            asset_value="https://static.example.com/vendor.js",
            job_type="graphql_authz_test",
            source_table="js_assets",
            js_risk={"graphql_hint_count": 4, "graphql_operation_count": 0},
            graphql_client_endpoint_count=0,
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)

    def test_keeps_protocol_confirmed_graphql_endpoint(self):
        candidate = job(
            asset_value="https://api.example.com/graphql",
            job_type="graphql_authz_test",
            graphql_protocol_confirmed=True,
        )
        self.assertEqual("keep", deterministic_decision(candidate, NOW, 30).action)

    def test_source_map_requires_sensitive_static_analysis_signal(self):
        candidate = job(
            asset_value="https://static.example.com/app.js.map",
            job_type="source_map_review",
            required_context={"payload": {"status_code": 200}},
            linked_secret_like_count=0,
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)
        candidate["linked_secret_like_count"] = 1
        self.assertEqual("keep", deterministic_decision(candidate, NOW, 30).action)

    def test_auth_and_logging_require_owned_actor_profiles(self):
        candidate = job(
            asset_value="https://app.example.com/audit",
            job_type="logging_audit_review",
            required_context={"payload": {"status_code": 200}},
            auth_profile_count=0,
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)
        candidate["auth_profile_count"] = 2
        self.assertEqual("keep", deterministic_decision(candidate, NOW, 30).action)

    def test_idor_identifier_requires_two_owned_actor_profiles(self):
        candidate = job(
            asset_value="https://app.example.com/api/users/123",
            job_type="idor_bac_test",
            required_context={"payload": {"status_code": 200, "parameters": [{"name": "user_id"}]}},
            auth_profile_count=0,
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)
        candidate["auth_profile_count"] = 2
        self.assertEqual("keep", deterministic_decision(candidate, NOW, 30).action)

    def test_delta_summary_requires_concrete_prefiltered_source_ids(self):
        candidate = job(
            job_type="delta_intelligence_review",
            source_table="scan_snapshots",
            required_context={"delta_intelligence": True, "snapshot_ids": [10]},
        )
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)
        candidate["required_context"]["high_signal_source_ids"] = [123]
        self.assertEqual("keep", deterministic_decision(candidate, NOW, 30).action)

    def test_defers_stale_source(self):
        candidate = job(source_observed_at=NOW - timedelta(days=31))
        self.assertEqual("defer", deterministic_decision(candidate, NOW, 30).action)

    def test_does_not_keep_upload_route_name_without_input_evidence(self):
        candidate = job(
            asset_value="https://app.example.com/upload/",
            job_type="upload_attack_surface",
            required_context={"payload": {"status_code": 200, "parameters": []}},
        )
        self.assertEqual("review", deterministic_decision(candidate, NOW, 30).action)

    def test_group_limit_retains_strongest_admin_routes(self):
        jobs = []
        decisions = {}
        for index, path in enumerate(("/actuator/health", "/actuator/env", "/actuator/logfile"), start=1):
            candidate = job(
                id=index,
                job_type="new_admin_route_review",
                asset_value=f"https://admin.example.com{path}",
            )
            jobs.append(candidate)
            decisions[index] = Decision("review", 90, "route")
        apply_group_limits(jobs, decisions)
        self.assertEqual("defer", decisions[1].action)
        self.assertEqual("review", decisions[2].action)
        self.assertEqual("review", decisions[3].action)


if __name__ == "__main__":
    unittest.main()
