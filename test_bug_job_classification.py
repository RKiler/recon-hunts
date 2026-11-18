import unittest

from continuous_recon import AppConfig, ContinuousReconFramework


class BugJobClassificationTests(unittest.TestCase):
    def framework(self, **scan_overrides):
        scan = {
            "max_concurrent_domains": 1,
            "bug_jobs_enabled": True,
            "bug_jobs_high_signal_only": True,
            "bug_jobs_max_per_asset": 1,
            "bug_jobs_collapse_endpoint_jobs": True,
            "bug_jobs_enqueue_playbooks": True,
            "bug_jobs_playbook_min_priority": 85,
        }
        scan.update(scan_overrides)
        return ContinuousReconFramework(
            AppConfig(
                {
                    "scan": scan,
                    "tools": {},
                    "database": {},
                    "redis": {},
                    "alerts": {},
                    "shodan": {},
                }
            )
        )

    def job_types(self, location, payload=None, item_type="endpoint", source_table="endpoints"):
        jobs = self.framework().classify_bug_jobs(
            source_table,
            123,
            item_type,
            location,
            payload or {},
            {"priority": "medium", "score": 45, "reasons": [], "recommended_actions": []},
        )
        return [job["job_type"] for job in jobs]

    def test_boring_endpoint_is_not_queued(self):
        self.assertEqual(self.job_types("https://example.com/about"), [])

    def test_endpoint_with_object_id_gets_idor_job(self):
        self.assertIn("idor_bac_test", self.job_types("https://example.com/api/projects/123456/users"))

    def test_custom_role_assignment_is_prioritized_for_authz(self):
        jobs = self.framework().classify_bug_jobs(
            "endpoints",
            123,
            "endpoint",
            "https://example.com/api/roles/assign?target_user_id=abc&permission=view_payroll",
            {"url": "https://example.com/api/roles/assign?target_user_id=abc&permission=view_payroll"},
            {"priority": "medium", "score": 45, "reasons": [], "recommended_actions": []},
        )
        job = next(item for item in jobs if item["job_type"] == "idor_bac_test")
        self.assertGreaterEqual(job["priority"], 96)
        self.assertTrue(job["required_context"]["custom_role_permission_review"])
        self.assertEqual(job["required_context"]["job_category"], "authorization_graphql")

    def test_async_result_endpoint_requests_secondary_operation_review(self):
        jobs = self.framework().classify_bug_jobs(
            "endpoints",
            123,
            "endpoint",
            "https://example.com/api/jobs/123456/results?download_id=abc",
            {"url": "https://example.com/api/jobs/123456/results?download_id=abc"},
            {"priority": "medium", "score": 45, "reasons": [], "recommended_actions": []},
        )
        job = next(item for item in jobs if item["job_type"] == "idor_bac_test")
        self.assertTrue(job["required_context"]["secondary_operation_review"])
        self.assertIn("create/status/result/download", job["required_context"]["sibling_operations_to_check"])

    def test_url_parameter_gets_ssrf_or_redirect_job(self):
        self.assertIn("ssrf_candidate_test", self.job_types("https://example.com/login?next=https://example.org"))

    def test_xss_parameter_gets_high_priority_xss_job(self):
        jobs = self.framework().classify_bug_jobs(
            "endpoints",
            123,
            "endpoint",
            "https://example.com/search?q=test",
            {"url": "https://example.com/search?q=test"},
            {"priority": "medium", "score": 45, "reasons": [], "recommended_actions": []},
        )
        xss_job = next(job for job in jobs if job["job_type"] == "xss_reflection_test")
        self.assertGreaterEqual(xss_job["priority"], 90)

    def test_lfi_parameter_gets_high_priority_upload_traversal_job(self):
        jobs = self.framework().classify_bug_jobs(
            "endpoints",
            123,
            "endpoint",
            "https://example.com/download?file=report.pdf",
            {"url": "https://example.com/download?file=report.pdf"},
            {"priority": "medium", "score": 45, "reasons": [], "recommended_actions": []},
        )
        upload_job = next(job for job in jobs if job["job_type"] == "upload_attack_surface")
        self.assertGreaterEqual(upload_job["priority"], 90)

    def test_query_filter_gets_high_priority_injection_job(self):
        jobs = self.framework().classify_bug_jobs(
            "endpoints",
            123,
            "endpoint",
            "https://example.com/api/search?filter=status:open&sort=date",
            {"url": "https://example.com/api/search?filter=status:open&sort=date"},
            {"priority": "medium", "score": 45, "reasons": [], "recommended_actions": []},
        )
        injection_job = next(job for job in jobs if job["job_type"] == "injection_review")
        self.assertGreaterEqual(injection_job["priority"], 90)

    def test_plain_id_is_authz_not_injection_signal(self):
        jobs = self.framework(bug_jobs_max_per_asset=3, bug_jobs_collapse_endpoint_jobs=False).classify_bug_jobs(
            "endpoints",
            123,
            "endpoint",
            "https://example.com/api/orders?id=123456",
            {"url": "https://example.com/api/orders?id=123456"},
            {"priority": "medium", "score": 45, "reasons": [], "recommended_actions": []},
        )
        self.assertIn("idor_bac_test", [job["job_type"] for job in jobs])
        self.assertNotIn("injection_review", [job["job_type"] for job in jobs])

    def test_common_path_denial_without_parameters_is_not_queued(self):
        self.assertEqual(
            self.job_types(
                "https://example.com/download",
                {"url": "https://example.com/download", "source": "common_path_probe", "status_code": 403},
            ),
            [],
        )

    def test_common_path_graphql_404_is_not_queued(self):
        self.assertEqual(
            self.job_types(
                "https://example.com/graphql",
                {"url": "https://example.com/graphql", "source": "common_path_probe", "status_code": 404},
            ),
            [],
        )

    def test_endpoint_overlap_keeps_only_highest_signal_job(self):
        self.assertEqual(
            self.job_types("https://example.com/api/export?id=123456&file=report.pdf&q=test"),
            ["upload_attack_surface"],
        )

    def test_graphql_endpoint_gets_graphql_job(self):
        self.assertIn("graphql_authz_test", self.job_types("https://example.com/graphql"))

    def test_generic_admin_path_is_not_enough_for_codex_job(self):
        self.assertEqual(self.job_types("https://example.com/admin/edit.php"), [])

    def test_ffuf_discovered_admin_path_gets_exposure_review_not_idor(self):
        jobs = self.framework().classify_bug_jobs(
            "endpoints",
            123,
            "endpoint",
            "https://example.com/admin/edit.php",
            {"url": "https://example.com/admin/edit.php", "source": "ffuf", "status_code": 200},
            {"priority": "low", "score": 23, "reasons": ["HTTP 200"], "recommended_actions": []},
        )
        self.assertEqual([job["job_type"] for job in jobs], ["new_admin_route_review"])
        self.assertEqual(jobs[0]["priority"], 99)
        self.assertTrue(jobs[0]["required_context"]["forced_browsing_review"])

    def test_route_name_is_not_mistaken_for_read_or_opaque_object_id(self):
        self.assertEqual(self.job_types("https://example.com/__lcp_index_meta__/ready"), [])

    def test_mixed_opaque_path_identifier_is_high_signal(self):
        self.assertIn(
            "idor_bac_test",
            self.job_types("https://example.com/api/items/ab12cd34ef56gh78"),
        )

    def test_generic_js_is_not_queued(self):
        self.assertEqual(
            self.job_types(
                "https://example.com/static/app.js",
                {"asset_url": "https://example.com/static/app.js"},
                item_type="js_asset",
                source_table="js_assets",
            ),
            [],
        )

    def test_first_run_new_javascript_does_not_force_dom_review(self):
        jobs = self.framework(
            bug_jobs_dom_review_all_new_js=False,
            bug_jobs_dom_review_all_delta_js=True,
        ).classify_bug_jobs(
            "js_assets",
            123,
            "js_asset",
            "https://example.com/static/app.js",
            {
                "asset_url": "https://example.com/static/app.js",
                "http_status": 200,
                "sha256": "a" * 64,
                "is_new": True,
                "first_run": True,
                "scan_lane": "first_run",
                "is_delta_scan": False,
            },
            {"priority": "low", "score": 10, "reasons": [], "recommended_actions": []},
        )
        self.assertNotIn("js_dom_xss_review", [job["job_type"] for job in jobs])

    def test_every_new_or_changed_delta_js_body_gets_dom_review(self):
        sha256 = "a" * 64
        for change_flags in ({"is_new": True}, {"is_changed": True}):
            jobs = self.framework(
                bug_jobs_dom_review_all_new_js=False,
                bug_jobs_dom_review_all_delta_js=True,
            ).classify_bug_jobs(
                "js_assets",
                123,
                "js_asset",
                "https://example.com/static/app.js",
                {
                    "asset_url": "https://example.com/static/app.js",
                    "http_status": 200,
                    "sha256": sha256,
                    "is_new": False,
                    "is_changed": False,
                    "first_run": False,
                    "scan_lane": "fast_delta",
                    "is_delta_scan": True,
                    **change_flags,
                },
                {"priority": "low", "score": 10, "reasons": [], "recommended_actions": []},
            )
            dom_job = next(job for job in jobs if job["job_type"] == "js_dom_xss_review")
            self.assertGreaterEqual(dom_job["priority"], 90)
            self.assertTrue(dom_job["required_context"]["mandatory_delta_js_dom_review"])
            self.assertEqual(dom_job["required_context"]["javascript_sha256"], sha256)

    def test_failed_js_response_and_source_map_do_not_force_dom_review(self):
        for url, status in (
            ("https://example.com/static/missing.js", 404),
            ("https://example.com/static/app.js.map", 200),
        ):
            jobs = self.framework(
                bug_jobs_dom_review_all_new_js=False,
                bug_jobs_dom_review_all_delta_js=True,
            ).classify_bug_jobs(
                "js_assets",
                123,
                "js_asset",
                url,
                {
                    "asset_url": url,
                    "http_status": status,
                    "sha256": "b" * 64,
                    "is_new": True,
                    "first_run": False,
                    "scan_lane": "fast_delta",
                    "is_delta_scan": True,
                },
                {"priority": "low", "score": 10, "reasons": [], "recommended_actions": []},
            )
            self.assertNotIn("js_dom_xss_review", [job["job_type"] for job in jobs])

    def test_dom_review_dedupes_mirrored_urls_by_javascript_sha(self):
        framework = self.framework()
        context = {
            "mandatory_delta_js_dom_review": True,
            "javascript_sha256": "c" * 64,
            "payload": {"sha256": "c" * 64},
        }
        first = framework.canonical_js_dom_review_asset_key(
            "https://cdn1.example.com/static/app.123.js",
            context,
        )
        second = framework.canonical_js_dom_review_asset_key(
            "https://cdn2.example.com/assets/mirror.js",
            context,
        )
        self.assertEqual(first, second)
        self.assertEqual(first, f"sha256:{'c' * 64}")

    def test_changed_js_gets_endpoint_extraction_job(self):
        self.assertIn(
            "js_endpoint_extraction",
            self.job_types(
                "https://example.com/static/app.js",
                {"asset_url": "https://example.com/static/app.js", "is_changed": True},
                item_type="js_asset",
                source_table="js_assets",
            ),
        )

    def test_js_dom_sink_gets_dom_xss_job(self):
        self.assertIn(
            "js_dom_xss_review",
            self.job_types(
                "https://example.com/static/app.js",
                {"asset_url": "https://example.com/static/app.js", "risk_summary": {"dom_sink": "innerHTML location.hash"}},
                item_type="js_asset",
                source_table="js_assets",
            ),
        )

    def test_source_map_gets_source_map_job(self):
        self.assertIn(
            "source_map_review",
            self.job_types(
                "https://example.com/static/app.js.map",
                {"asset_url": "https://example.com/static/app.js.map"},
                item_type="js_asset",
                source_table="js_assets",
            ),
        )

    def test_mapbox_hostname_is_not_a_source_map_signal(self):
        self.assertNotIn(
            "source_map_review",
            self.job_types("https://example.com/www.mapbox.com/api-documentation/"),
        )

    def test_staging_host_gets_admin_route_review(self):
        self.assertIn(
            "new_admin_route_review",
            self.job_types(
                "https://admin.staging.example.com",
                {"url": "https://admin.staging.example.com", "is_new_live_host": True},
                item_type="live_host",
                source_table="live_hosts",
            ),
        )

    def test_jwt_endpoint_gets_crypto_review(self):
        self.assertIn(
            "crypto_token_review",
            self.job_types("https://example.com/api/jwt/verify?nonce=test"),
        )

    def test_package_manifest_gets_supply_chain_review(self):
        self.assertIn(
            "component_supply_chain_review",
            self.job_types("https://example.com/package-lock.json"),
        )

    def test_generic_exposed_path_finding_is_not_mislabeled_as_idor(self):
        self.assertNotIn(
            "idor_bac_test",
            self.job_types(
                "https://admin.example.com/swagger.json",
                {"finding_type": "interesting_exposed_path", "details": {"status_code": 200}},
                item_type="finding",
                source_table="findings",
            ),
        )

    def test_signed_event_gets_integrity_review(self):
        self.assertIn(
            "integrity_review",
            self.job_types("https://example.com/api/events?event_id=test&idempotency=test"),
        )

    def test_security_event_endpoint_gets_logging_review(self):
        self.assertIn(
            "logging_audit_review",
            self.job_types("https://example.com/security/events"),
        )

    def test_server_error_gets_exceptional_condition_review(self):
        self.assertIn(
            "exceptional_condition_review",
            self.job_types(
                "https://example.com/api/unstable",
                {"url": "https://example.com/api/unstable", "status_code": 500},
            ),
        )

    def test_canonical_bug_job_asset_key_normalizes_equivalent_urls(self):
        fw = self.framework()
        self.assertEqual(
            fw.canonical_bug_job_asset_key("endpoint", "HTTPS://Example.COM:443/api/users/?a=1#frag"),
            "https://example.com/api/users?a=%7Bvalue%7D",
        )

    def test_canonical_bug_job_asset_key_collapses_endpoint_ids_and_values(self):
        fw = self.framework()
        self.assertEqual(
            fw.canonical_bug_job_asset_key("endpoint", "https://example.com/api/users/123456?token=abc&id=123"),
            fw.canonical_bug_job_asset_key("endpoint", "https://example.com/api/users/654321?id=456&token=def"),
        )

    def test_low_priority_playbook_is_not_enqueued_as_bug_job(self):
        fw = self.framework()
        item = {
            "check_type": "file_upload_traversal_xxe",
            "priority": "medium",
            "reasons": ["file or parser workflow"],
        }
        self.assertFalse(
            fw.should_enqueue_playbook_bug_job(
                item,
                "endpoint",
                "https://example.com/download?file=report.pdf",
                {"priority": "medium", "score": 45},
                {},
            )
        )

    def test_high_signal_high_priority_playbook_is_enqueued(self):
        fw = self.framework()
        item = {
            "check_type": "ssrf_open_redirect_callback",
            "priority": "high",
            "reasons": ["URL-like sink"],
        }
        self.assertTrue(
            fw.should_enqueue_playbook_bug_job(
                item,
                "endpoint",
                "https://example.com/callback?url=https://callback.example",
                {"priority": "high", "score": 90},
                {},
            )
        )


if __name__ == "__main__":
    unittest.main()
