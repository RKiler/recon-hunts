import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from independent_hunt import json_object, request_owned_relogin
from datetime import datetime

from independent_hunt_worker import (HuntWorker, LoginPending, build_prompt, candidate_classes,
                                     context_terms, enrich_top_endpoints, normalize_result,
                                     rank_row, scoped_row, source_filter)


class IndependentHuntTests(unittest.TestCase):
    def test_jsonb_values_are_decoded(self):
        self.assertEqual(json_object('{"next_lt":{"endpoints":5}}'), {"next_lt": {"endpoints": 5}})
        self.assertEqual(json_object("invalid"), {})

    def test_scope_rejects_foreign_hosts(self):
        row = {"source_table": "endpoints", "host": "https://api.example.com", "asset": "/api/projects"}
        self.assertTrue(scoped_row(row, "example.com", True, []))
        self.assertFalse(scoped_row({**row, "host": "https://api.example.com.evil.test"}, "example.com", True, []))
        self.assertFalse(scoped_row({**row, "asset": "https://outside.test/redirect"}, "example.com", True, []))
        self.assertFalse(scoped_row(row, "example.com", True, ["api.example.com"]))

    def test_context_ranks_matching_feature_without_claiming_bug(self):
        terms = context_terms("Only inspect project member invitations and role changes")
        score, matched = rank_row({"source_table": "endpoints", "id": 1,
                                   "asset": "/api/projects/1/members/invite"}, terms)
        self.assertTrue(matched)
        self.assertGreater(score, 0)
        self.assertNotIn("only", terms)
        self.assertEqual(context_terms("Find Zapier admin endpoints on zapier.com", "zapier.com"),
                         ["admin", "endpoints"])

    def test_prompt_is_not_item_scoped_or_bug_job_driven(self):
        run = {"id": 4, "domain": "example.com", "data_scope": "all",
               "application_context": "Owned project and member roles", "include_subdomains": True}
        packet = {"scope_exclusions": [], "records_examined": 3000, "selected_count": 30,
                  "top_signals": [{"source_table": "endpoints", "id": 5, "asset": "/api/projects"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            prompt = build_prompt(run, 12, path / "packet.json", packet, path, [])
        self.assertIn("independent authorized domain hunt", prompt)
        self.assertIn("not a bug-job task", prompt)
        self.assertIn("Do not restrict yourself to recently created bug jobs", prompt)
        self.assertIn("20 additional target HTTP requests", prompt)
        self.assertIn("deterministic packet cursor", prompt)
        self.assertIn("harmless self/profile or account-membership GET endpoint", prompt)
        self.assertIn("do not trust account alias, role, or tenant labels", prompt)
        self.assertIn("standing approval to create, edit, and delete clearly disposable items", prompt)
        self.assertIn("same-tenant lower-role access, other-tenant access", prompt)
        self.assertIn("capture its actual method/body/CSRF handling", prompt)
        self.assertIn("--request-relogin", prompt)
        self.assertIn("source and sink merely appearing near each other is insufficient", prompt)
        self.assertIn("public Sentry/Firebase/analytics keys", prompt)
        self.assertIn("client_proof", prompt)
        self.assertIn("hunt_browser_capture.cjs", prompt)
        self.assertIn("LFI/traversal, command injection/RCE", prompt)
        self.assertIn("hypothesis_proof", prompt)

    def test_betfair_browser_capture_uses_uk_proxy_only_for_betfair(self):
        packet = {"scope_exclusions": [], "records_examined": 0, "selected_count": 0,
                  "top_signals": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            base_run = {"id": 4, "data_scope": "all", "application_context": "",
                        "include_subdomains": True}
            betfair = build_prompt({**base_run, "domain": "betfair.com"}, 1,
                                   path / "packet.json", packet, path, [])
            other = build_prompt({**base_run, "domain": "example.com"}, 1,
                                 path / "packet.json", packet, path, [])
        self.assertIn("--proxy http://nordvpn-egress:8888", betfair)
        self.assertNotIn("--proxy http://nordvpn-egress:8888", other)

    def test_js_ranking_uses_counts_not_summary_field_names(self):
        asset = {"source_table": "js_assets", "asset": "https://app.example.com/app.js",
                 "http_status": 200, "sha256": "a" * 64, "secret_pattern_count": 0,
                 "analysis_summary": json.dumps({"dom_source_sink_proximity_count": 0,
                                                 "postmessage_receiver_count": 0,
                                                 "postmessage_data_flow_count": 0,
                                                 "postmessage_sensitive_effect_count": 0})}
        self.assertEqual(rank_row(asset, [])[0], 0)
        self.assertEqual(rank_row({**asset, "analysis_summary": json.dumps({
            "dom_source_sink_proximity_count": 1})}, [])[0], 8)
        self.assertEqual(rank_row({**asset, "analysis_summary": json.dumps({
            "postmessage_receiver_count": 1, "postmessage_data_flow_count": 1,
            "postmessage_sensitive_effect_count": 1})}, [])[0], 9)
        self.assertEqual(rank_row({**asset, "secret_pattern_count": 1}, [])[0], 4)
        self.assertEqual(rank_row({**asset, "http_status": 403}, [])[0], 0)
        self.assertGreater(rank_row({**asset, "route_hints": ["/oauth/callback"]}, [])[0], 0)

    def test_endpoint_and_parameter_classes_use_request_inputs(self):
        endpoint = {"source_table": "endpoints", "asset": "/api/files/download",
                    "method": "GET", "param_names": ["file_path"]}
        self.assertIn("lfi_path_traversal", candidate_classes(endpoint))
        self.assertGreater(rank_row(endpoint, [])[0], 0)
        parameter = {"source_table": "url_parameters", "asset": "url",
                     "path": "/api/image/preview"}
        self.assertIn("ssrf", candidate_classes(parameter))

    def test_scanner_labels_do_not_outrank_verified_secrets(self):
        for finding_type in ("js_dom_xss_candidate", "js_sensitive_admin_surface",
                             "js_secret_like_strings"):
            finding = {"source_table": "findings", "finding_type": finding_type,
                       "asset": "https://app.example.com/app.js"}
            self.assertEqual(rank_row(finding, [])[0], 0)
        leak = {"source_table": "credential_leaks", "asset": "https://app.example.com/app.js",
                "verified": True, "detector_name": "provider"}
        self.assertEqual(rank_row(leak, [])[0], 12)
        guessed = {"source_table": "api_surfaces", "asset": "https://app.example.com/graphql",
                   "surface_type": "graphql", "status_code": 403, "operations_count": 0}
        self.assertEqual(rank_row(guessed, [])[0], 0)

    def test_relogin_request_rejects_unselected_account(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "runs" / "run_7"
            run_dir.mkdir(parents=True)
            (run_dir / "login_request.json").write_text(json.dumps({
                "run_id": 7, "accounts": [{"id": 4}]
            }))
            with patch("independent_hunt.SESSION_ROOT", root / "runs"), patch(
                "independent_hunt.LOGIN_SIGNALS", root / "signals"
            ):
                with self.assertRaises(ValueError):
                    request_owned_relogin(7, 5, 0)
                self.assertFalse(request_owned_relogin(7, 4, 0))
                self.assertTrue((root / "signals" / "run_7_account_4.retry").exists())

    def test_long_application_context_is_read_from_packet_not_inlined(self):
        run = {"id": 4, "domain": "example.com", "data_scope": "all",
               "application_context": "owned workflow " * 10000, "include_subdomains": True}
        packet = {"scope_exclusions": [], "records_examined": 0, "selected_count": 0,
                  "top_signals": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            prompt = build_prompt(run, 1, path / "packet.json", packet, path, [])
        self.assertIn("read the full application_context field", prompt)
        self.assertIn(str(path / "packet.json"), prompt)
        self.assertNotIn("owned workflow owned workflow", prompt)

    def test_unsubstantiated_confirmation_is_blocked(self):
        result = normalize_result({"confirmed_findings": [{"title": "Possible issue"}], "leads": [],
                                   "active_request_count": "unknown"})
        self.assertEqual(result["confirmed_findings"], [])
        self.assertEqual(len(result["blocked"]), 1)
        self.assertEqual(result["active_request_count"], 0)

    def test_client_leads_need_specific_proof_without_losing_raw_observation(self):
        weak = {"title": "DOM XSS from scanner", "bug_class": "DOM XSS",
                "affected_asset": "https://app.example.com/app.js", "evidence_path": "scan.json"}
        strong = {**weak, "client_proof": {
            "current_asset_sha256": "a" * 64, "reachable_route": "/editor",
            "attacker_controlled_source": "location.search:q",
            "source_to_sink_trace": "q -> decodeURIComponent -> innerHTML",
            "sink": "innerHTML"}}
        result = normalize_result({"leads": [weak, strong, {"title": "BOLA", "bug_class": "BOLA"}]})
        self.assertEqual(len(result["leads"]), 1)
        self.assertEqual(len(result["blocked"]), 2)
        self.assertIn("Missing current client-side proof", result["blocked"][0]["reason"])

    def test_postmessage_and_secret_proof_gates(self):
        cases = [
            ({"title": "Message listener", "bug_class": "postMessage", "client_proof": {
                "current_asset_sha256": "a" * 64, "receiver": "window message handler",
                "sender_control": "foreign popup", "trust_check": "source only",
                "protected_effect": "private owned-file reply"}}, 1),
            ({"title": "Client secret leak", "bug_class": "hardcoded credential", "client_proof": {
                "current_asset_sha256": "b" * 64, "credential_class": "OAuth client secret",
                "redacted_fingerprint": "sha256:" + "c" * 64,
                "non_public_reason": "server-only token used in auth"}}, 1),
            ({"title": "Public SDK key", "bug_class": "hardcoded credential"}, 0),
            ({"title": "Hardcoded credentials", "bug_class": "credential leakage"}, 0),
            ({"title": "Raw token in result", "bug_class": "exposed secret", "client_proof": {
                "current_asset_sha256": "b" * 64, "credential_class": "service token",
                "redacted_fingerprint": "raw-token-value", "non_public_reason": "server-only"}}, 0),
        ]
        for item, accepted in cases:
            with self.subTest(item=item["title"]):
                result = normalize_result({"leads": [item]})
                self.assertEqual(len(result["leads"]), accepted)
                self.assertEqual(len(result["blocked"]), 1 - accepted)

    def test_confirmed_client_issue_requires_observed_effect(self):
        base = {"title": "Cross-origin message leak", "bug_class": "postMessage",
                "affected_asset": "https://app.example.com/editor", "evidence_path": "trace.md",
                "baseline": "owner receives marker", "negative_control": "wrong type denied",
                "impact": "private marker returned", "reproduction": "owned fixture steps",
                "client_proof": {"current_asset_sha256": "a" * 64, "receiver": "editor window",
                                 "sender_control": "foreign popup", "trust_check": "source-only",
                                 "protected_effect": "owned marker reply"}}
        result = normalize_result({"confirmed_findings": [base]})
        self.assertEqual(len(result["confirmed_findings"]), 0)
        self.assertIn("observed protected effect", result["blocked"][0]["reason"])
        base["client_proof"]["protected_effect_observed"] = True
        result = normalize_result({"confirmed_findings": [base]})
        self.assertEqual(len(result["confirmed_findings"]), 1)

    def test_client_proof_requires_current_hash_and_existing_evidence(self):
        item = {"title": "DOM XSS", "bug_class": "DOM XSS", "evidence_path": "trace.md",
                "client_proof": {"current_asset_sha256": "not-a-hash", "reachable_route": "/editor",
                                 "attacker_controlled_source": "location.hash", "source_to_sink_trace": "hash -> html",
                                 "sink": "innerHTML"}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = normalize_result({"leads": [item]}, root)
            self.assertEqual(len(result["blocked"]), 1)
            self.assertIn("valid current_asset_sha256", result["blocked"][0]["reason"])
            self.assertIn("existing evidence_path", result["blocked"][0]["reason"])
            (root / "trace.md").write_text("redacted trace")
            body = root / "current.js"
            body.write_text("const marker = location.hash;", encoding="utf-8")
            item["client_proof"]["asset_body_path"] = str(body)
            item["client_proof"]["current_asset_sha256"] = "a" * 64
            result = normalize_result({"leads": [item]}, root)
            self.assertIn("matching current JS body SHA-256", result["blocked"][0]["reason"])
            item["client_proof"]["current_asset_sha256"] = hashlib.sha256(body.read_bytes()).hexdigest()
            result = normalize_result({"leads": [item]}, root)
            self.assertEqual(len(result["leads"]), 1)

    def test_general_lead_requires_current_behavior_and_local_evidence(self):
        item = {"title": "Potential file read", "bug_class": "LFI", "evidence_path": "trace.json",
                "hypothesis_proof": {"current_surface": "GET /api/files/download",
                                     "controlled_input": "owned file_path parameter",
                                     "trust_boundary": "request path to server file reader",
                                     "observed_behavior": "owned marker file returned for valid path",
                                     "decisive_next_test": "compare out-of-directory harmless fixture"}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(len(normalize_result({"leads": [item]}, root)["blocked"]), 1)
            (root / "trace.json").write_text("{}")
            self.assertEqual(len(normalize_result({"leads": [item]}, root)["leads"]), 1)
            weak = {**item, "hypothesis_proof": {**item["hypothesis_proof"], "observed_behavior": ""}}
            self.assertEqual(len(normalize_result({"leads": [weak]}, root)["blocked"]), 1)
            outside = {**item, "evidence_path": "../outside.json"}
            self.assertEqual(len(normalize_result({"leads": [outside]}, root)["blocked"]), 1)

    def test_selected_delta_windows_are_bound_parameters(self):
        start = datetime(2026, 10, 1)
        finish = datetime(2026, 10, 2)
        run = {"domain_id": 5, "data_source": "delta", "delta_scans": [
            {"id": 11, "scan_started_at": start, "scan_finished_at": finish},
            {"id": 12, "scan_started_at": finish, "scan_finished_at": datetime(2026, 10, 3)},
        ]}
        clause, params = source_filter(run, "js_assets", "s.domain_id = $1")
        self.assertIn("t.first_seen >= $2", clause)
        self.assertIn("t.first_seen <= $5", clause)
        self.assertEqual(params[0], 5)
        self.assertEqual(len(params), 5)
        snapshot_clause, snapshot_params = source_filter(run, "scan_snapshots", "t.domain_id = $1")
        self.assertIn("t.id = ANY($2::bigint[])", snapshot_clause)
        self.assertEqual(snapshot_params, [5, [11, 12]])


class HuntLoginTests(unittest.IsolatedAsyncioTestCase):
    async def test_top_endpoint_js_links_are_scope_filtered(self):
        conn = type("Connection", (), {})()
        conn.fetch = AsyncMock(return_value=[
            {"endpoint_id": 3, "js_asset_id": 9,
             "asset_url": "https://static.example.com/app.js?token=super-secret",
             "sha256": "a" * 64, "http_status": 200},
            {"endpoint_id": 3, "js_asset_id": 10,
             "asset_url": "https://other.test/app.js", "sha256": "b" * 64,
             "http_status": 200},
        ])
        signals = [{"source_table": "endpoints", "id": 3, "asset": "/api/files"}]
        await enrich_top_endpoints(conn, signals, "example.com", True, [])
        self.assertEqual(len(signals[0]["related_js"]), 1)
        self.assertNotIn("super-secret", signals[0]["related_js"][0]["asset_url"])
        self.assertIn("%5Bredacted%5D", signals[0]["related_js"][0]["asset_url"])

    async def test_owned_login_preflight_uses_separate_account_states(self):
        worker = HuntWorker(None, {"scan": {}})
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run_1"
            pass_dir = run_dir / "pass_1"
            pass_dir.mkdir(parents=True)
            sessions = run_dir / "sessions"
            sessions.mkdir()
            (sessions / "account_10.json").write_text("{}")
            (sessions / "account_11.json").write_text("{}")
            accounts = [
                {"id": 10, "alias": "owner-a", "host": "zapier.com", "credential_type": "login_file", "secret_file": "a" * 32 + ".secret"},
                {"id": 11, "alias": "owner-b", "host": "zapier.com", "credential_type": "login_file", "secret_file": "b" * 32 + ".secret"},
            ]
            await worker.wait_for_owned_logins({"id": 1, "domain": "zapier.com"}, accounts, pass_dir)
            request = json.loads((run_dir / "login_request.json").read_text())
            self.assertEqual([item["id"] for item in request["accounts"]], [10, 11])
            self.assertNotIn("password", (run_dir / "login_request.json").read_text())
            self.assertEqual((run_dir / "login_request.json").stat().st_mode & 0o777, 0o600)

    async def test_owned_login_preflight_is_not_zapier_only(self):
        worker = HuntWorker(None, {"scan": {}})
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run_2"
            pass_dir = run_dir / "pass_1"
            pass_dir.mkdir(parents=True)
            sessions = run_dir / "sessions"
            sessions.mkdir()
            (sessions / "account_12.json").write_text("{}")
            accounts = [{"id": 12, "alias": "owner", "host": "app.example.com",
                         "credential_type": "login_file", "secret_file": "a" * 32 + ".secret"}]
            await worker.wait_for_owned_logins({"id": 2, "domain": "example.com"}, accounts, pass_dir)
            request = json.loads((run_dir / "login_request.json").read_text())
            self.assertEqual(request["domain"], "example.com")
            self.assertEqual(request["accounts"][0]["exact_host"], "app.example.com")

    async def test_missing_login_yields_without_blocking_other_hunts(self):
        worker = HuntWorker(None, {"scan": {}})
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run_3"
            pass_dir = run_dir / "pass_1"
            pass_dir.mkdir(parents=True)
            accounts = [{"id": 13, "alias": "owner", "host": "app.example.com",
                         "credential_type": "login_file", "secret_file": "a" * 32 + ".secret"}]
            with self.assertRaises(LoginPending):
                await worker.wait_for_owned_logins({"id": 3, "domain": "example.com"}, accounts, pass_dir)
            self.assertTrue((run_dir / "login_request.json").exists())


if __name__ == "__main__":
    unittest.main()
