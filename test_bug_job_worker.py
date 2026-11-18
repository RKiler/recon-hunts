import asyncio
import json
import tempfile
import time
import unittest
from unittest import mock
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock

from bug_job_worker import (
    FAMILY_PROMPTS,
    BugJobWorker,
    CodexExecutionError,
    CodexJobTimeout,
    canonical_alert_asset,
    clean_alert_text,
    classify_codex_failure,
    command_count,
    extract_job_result,
    normalize_confidence,
    reset_daily_budget_state,
)


class BugJobWorkerSafetyTests(unittest.TestCase):
    @staticmethod
    def focused_worker() -> BugJobWorker:
        worker = BugJobWorker.__new__(BugJobWorker)
        worker.use_prompt_library = True
        worker.agents_path = Path("/root/AGENTS.md")
        worker.prompt_library_root = Path("/root/bug_hunt_prompt_library")
        worker.interaction_hub_enabled = False
        worker.max_db_candidates = 25
        worker.delta_max_db_rows = 250
        worker.max_active_requests = 20
        worker.max_variants = 8
        worker.discord_review_alert_signal_types = {
            "security_sensitive_endpoint",
            "hardcoded_credential",
            "sensitive_api_key",
            "authorization_issue",
            "authentication_issue",
            "bypass",
            "information_exposure",
            "xss",
            "dom_xss",
            "postmessage_origin_trust",
            "ssrf",
            "open_redirect",
            "command_injection",
            "lfi_path_traversal",
            "sql_nosql_injection",
            "xxe",
            "deserialization",
            "graphql",
            "oauth_sso",
            "jwt_session",
            "file_upload",
            "cors_csrf",
            "cache",
            "race_condition",
            "business_logic",
            "cloud_storage",
            "supply_chain",
            "other_owasp_top10",
        }
        worker.discord_review_webhook_url = "https://discord.invalid/lead-webhook"
        worker.discord_review_username = "Recon Codex Leads"
        worker.discord_review_alert_require_signal = True
        return worker

    def test_owasp_2025_aliases_have_focused_profiles(self):
        worker = BugJobWorker.__new__(BugJobWorker)
        aliases = {
            "owasp2025_a01_broken_access_control": "A01:2025",
            "owasp2025_a02_security_misconfiguration": "A02:2025",
            "owasp2025_a03_software_supply_chain_failures": "A03:2025",
            "owasp2025_a04_cryptographic_failures": "A04:2025",
            "owasp2025_a05_injection": "A05:2025",
            "owasp2025_a06_insecure_design": "A06:2025",
            "owasp2025_a07_authentication_failures": "A07:2025",
            "owasp2025_a08_software_data_integrity_failures": "A08:2025",
            "owasp2025_a09_security_logging_alerting_failures": "A09:2025",
            "owasp2025_a10_mishandling_exceptional_conditions": "A10:2025",
        }
        for alias, category in aliases.items():
            profile = worker.job_profile(alias)
            self.assertIn(category, profile["owasp"])
            self.assertGreater(len(profile["skills"]), 0)

    def test_failure_classification_opens_only_expected_circuits(self):
        self.assertEqual(classify_codex_failure("insufficient_quota"), "quota")
        self.assertEqual(classify_codex_failure("429 Too Many Requests"), "rate_limit")
        self.assertEqual(
            classify_codex_failure(
                "prompt mentions rate limit\n"
                "ERROR: The 'gpt-6-sol' model is not supported when using Codex with a ChatGPT account."
            ),
            "job_failure",
        )
        self.assertEqual(classify_codex_failure("authentication required"), "authentication")
        self.assertEqual(classify_codex_failure("connection reset by peer"), "transient")
        self.assertEqual(
            classify_codex_failure(
                "prompt says authentication required\nERROR: Selected model is at capacity. Please try a different model."
            ),
            "transient",
        )
        self.assertEqual(
            classify_codex_failure(
                "prompt discusses an unauthorized endpoint\n"
                "ERROR: unexpected status 402 Payment Required: Insufficient Balance"
            ),
            "quota",
        )
        self.assertEqual(classify_codex_failure("prompt rejected"), "job_failure")

    def test_command_count_handles_asyncpg_status(self):
        self.assertEqual(command_count("UPDATE 12"), 12)
        self.assertEqual(command_count("UPDATE 0"), 0)
        self.assertEqual(command_count("invalid"), 0)

    def test_extract_job_result_accepts_markdown_wrapped_json(self):
        payload = {
            "job_id": 42,
            "finding_status": "possible",
            "outcome_class": "NEEDS_MANUAL_REVIEW",
            "confidence": 65,
        }
        wrapped = "Verification complete. Final result:\n\n```json\n" + json.dumps(payload) + "\n```"
        self.assertEqual(extract_job_result(wrapped), payload)

    def test_extract_job_result_prefers_final_result_object(self):
        text = '{"progress": "working"}\nFinal:\n```json\n{"job_id": 9, "finding_status": "none", "confidence": 80}\n```'
        result = extract_job_result(text)
        self.assertEqual(result["job_id"], 9)
        self.assertEqual(result["finding_status"], "none")

    def test_extract_job_result_repairs_narrow_model_json_defects(self):
        wrapped = r'''```json
        {
          "job_id": 42,
          "finding_status": "none",
          "outcome_class": "KILLED_FALSE_POSITIVE",
          "impact": "value is concatenated into src=\'marker\'",
        }
        ```'''
        result = extract_job_result(wrapped)
        self.assertEqual(result["job_id"], 42)
        self.assertEqual(result["finding_status"], "none")

    def test_normalize_confidence_accepts_percent_and_probability_scales(self):
        self.assertEqual(normalize_confidence(88), 88)
        self.assertEqual(normalize_confidence(0.4), 40)
        self.assertEqual(normalize_confidence(120), 100)
        self.assertIsNone(normalize_confidence("unknown"))

    def test_runtime_state_reports_all_parallel_slots(self):
        async def exercise() -> None:
            with tempfile.TemporaryDirectory() as temp_dir:
                worker = BugJobWorker.__new__(BugJobWorker)
                worker.out_dir = Path(temp_dir)
                worker.state_path = worker.out_dir / ".worker_state.json"
                worker.runtime_state = {}
                worker.pause_until = None
                worker.pause_reason = ""
                worker.parallelism = 2
                worker.daily_date = date.today()
                worker.daily_started_count = 12
                worker.daily_domain_counts = {7: 2, 8: 1}
                worker.active_jobs = {
                    1: {"slot": 1, "job_id": 101, "domain_id": 7, "target": "one.example"},
                    2: {"slot": 2, "job_id": 102, "domain_id": 8, "target": "two.example"},
                }

                await worker.set_runtime_state("idle")
                state = json.loads(worker.state_path.read_text(encoding="utf-8"))
                self.assertEqual(state["worker"], "bug-job-worker-pool")
                self.assertEqual(state["status"], "running")
                self.assertEqual(state["parallelism"], 2)
                self.assertEqual(state["active_count"], 2)
                self.assertEqual(state["current_job_ids"], [101, 102])

        asyncio.run(exercise())

    def test_production_mode_clears_persisted_test_budget_pause(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            worker = BugJobWorker.__new__(BugJobWorker)
            worker.state_path = Path(temp_dir) / ".worker_state.json"
            worker.test_mode = False
            worker.state_path.write_text(
                json.dumps(
                    {
                        "pause_reason": "test_budget",
                        "pause_until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                    }
                ),
                encoding="utf-8",
            )
            worker._load_runtime_state()
            self.assertEqual("", worker.pause_reason)
            self.assertIsNone(worker.pause_until)

    def test_daily_budget_reset_preserves_history_and_starts_new_window(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / ".worker_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "status": "paused",
                        "pause_reason": "daily_budget",
                        "daily_started_count": 109,
                        "daily_domain_counts": {"7": 12},
                        "daily_category_counts": {"javascript_client": 90},
                        "active_count": 0,
                        "historical_marker": "preserved",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(0, reset_daily_budget_state(state_path))
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(0, state["daily_started_count"])
            self.assertEqual({}, state["daily_domain_counts"])
            self.assertEqual({}, state["daily_category_counts"])
            self.assertEqual("preserved", state["historical_marker"])
            self.assertTrue(state["daily_budget_reset_at"])

    def test_raised_daily_cap_clears_persisted_budget_pause(self):
        worker = BugJobWorker.__new__(BugJobWorker)
        worker.pause_reason = "daily_budget"
        worker.pause_until = datetime.now(timezone.utc) + timedelta(hours=4)
        worker.daily_started_count = 100
        worker.max_jobs_per_day = 150

        worker.reconcile_daily_budget_pause()

        self.assertIsNone(worker.pause_until)
        self.assertEqual(worker.pause_reason, "")

    def test_vpn_snapshot_requires_a_valid_public_egress_ip(self):
        async def exercise() -> None:
            worker = BugJobWorker.__new__(BugJobWorker)
            worker.vpn_failover_enabled = True
            worker.vpn_proxy_url = "http://nordvpn-egress:8888"
            worker._vpn_control_request = AsyncMock(
                side_effect=[
                    {"status": "running"},
                    {"public_ip": ""},
                ]
            )

            snapshot = await worker.vpn_gateway_snapshot()

            self.assertEqual(snapshot["status"], "unavailable")
            self.assertEqual(snapshot["reason"], "VPN has no valid public egress IP")
            self.assertNotIn("public_ip", snapshot)

        asyncio.run(exercise())

    def test_expired_provider_pause_allows_only_one_canary_slot(self):
        async def exercise() -> None:
            with tempfile.TemporaryDirectory() as temp_dir:
                worker = BugJobWorker.__new__(BugJobWorker)
                worker.out_dir = Path(temp_dir)
                worker.state_path = worker.out_dir / ".worker_state.json"
                worker.runtime_state = {}
                worker.pause_until = datetime.now(timezone.utc) - timedelta(seconds=1)
                worker.pause_reason = "quota"
                worker.parallelism = 2
                worker.daily_date = date.today()
                worker.daily_started_count = 0
                worker.daily_domain_counts = {}
                worker.active_jobs = {}
                worker.provider_recovery_lock = asyncio.Lock()
                worker.provider_probe_slot = None

                self.assertTrue(await worker.provider_gate(1))
                self.assertEqual(worker.provider_probe_slot, 1)
                self.assertFalse(await worker.provider_gate(2))

                await worker.complete_provider_probe(1)
                self.assertIsNone(worker.provider_probe_slot)
                self.assertTrue(await worker.provider_gate(2))

        asyncio.run(exercise())

    def test_interaction_hub_is_scoped_to_callback_capable_jobs(self):
        worker = BugJobWorker.__new__(BugJobWorker)
        worker.interaction_hub_enabled = True
        worker.interaction_http_base = "https://callbacks.example/c/token"
        worker.interaction_webhook_base = "https://callbacks.example/webhook/token"
        worker.interaction_redirect_base = "https://callbacks.example/r/token"
        worker.interaction_xss_base = "https://callbacks.example/x/token"
        worker.interaction_db_path = "/interaction-hub-data/interactions.sqlite3"
        worker.interaction_query_helper = "/app/scripts/query_interaction_callbacks.py"
        base_job = {
            "id": 42,
            "target": "example.com",
            "asset_value": "https://app.example.com/fetch?url=",
        }

        callback_text = worker.interaction_hub_prompt({**base_job, "job_type": "ssrf_candidate_test"})
        self.assertIn("Generic HTTP/SSRF/XXE callback", callback_text)
        self.assertIn("Open-redirect destination", callback_text)
        self.assertIn("job-42-", callback_text)
        self.assertIn("query_interaction_callbacks.py", callback_text)

        unrelated_text = worker.interaction_hub_prompt({**base_job, "job_type": "idor_bac_test"})
        self.assertEqual(unrelated_text, "")

    def test_claim_quality_gate_requires_same_current_high_signal_type(self):
        class FakeFramework:
            @staticmethod
            def classify_bug_jobs(*_args, **_kwargs):
                return [{"job_type": "graphql_authz_test", "priority": 94}]

        worker = BugJobWorker.__new__(BugJobWorker)
        worker.framework = FakeFramework()
        worker.min_priority = 90
        worker.allow_legacy_jobs = False
        job = {
            "required_context": {"payload": {"url": "https://example.com/graphql"}},
            "source_table": "endpoints",
            "source_id": 1,
            "asset_type": "endpoint",
            "asset_value": "https://example.com/graphql",
            "job_type": "injection_review",
        }
        self.assertFalse(worker.claim_is_current_high_signal(job))
        job["job_type"] = "graphql_authz_test"
        self.assertTrue(worker.claim_is_current_high_signal(job))

    def test_delta_review_quality_gate_requires_bounded_snapshot_context(self):
        worker = BugJobWorker.__new__(BugJobWorker)
        worker.framework = object()
        worker.allow_legacy_jobs = False
        job = {
            "required_context": {
                "delta_intelligence": True,
                "snapshot_ids": [44, 45],
                "window_start": "2026-09-17T00:00:00Z",
                "window_end": "2026-09-17T12:00:00Z",
            },
            "source_table": "scan_snapshots",
            "source_id": 45,
            "asset_type": "domain_delta",
            "asset_value": "recon-delta://example.com?snapshot=45",
            "job_type": "delta_intelligence_review",
        }
        self.assertTrue(worker.claim_is_current_high_signal(job))
        job["source_id"] = 46
        self.assertFalse(worker.claim_is_current_high_signal(job))

    def test_delta_javascript_dom_review_bypasses_static_signal_classifier(self):
        class FakeFramework:
            @staticmethod
            def classify_bug_jobs(*_args, **_kwargs):
                return []

        worker = BugJobWorker.__new__(BugJobWorker)
        worker.framework = FakeFramework()
        worker.min_priority = 90
        worker.allow_legacy_jobs = False
        job = {
            "required_context": {
                "payload": {"http_status": 200, "is_new": True, "is_changed": False},
                "mandatory_delta_js_dom_review": True,
                "javascript_sha256": "a" * 64,
                "scan_lane": "fast_delta",
                "is_delta_scan": True,
            },
            "source_table": "js_assets",
            "source_id": 1,
            "asset_type": "js_asset",
            "asset_value": "https://static.example.com/app.js",
            "job_type": "js_dom_xss_review",
        }
        self.assertTrue(worker.claim_is_current_high_signal(job))
        job["required_context"]["is_delta_scan"] = False
        self.assertFalse(worker.claim_is_current_high_signal(job))

    def test_legacy_automatic_job_without_classifier_context_is_rejected(self):
        worker = BugJobWorker.__new__(BugJobWorker)
        worker.framework = object()
        worker.min_priority = 90
        worker.allow_legacy_jobs = False
        self.assertFalse(
            worker.claim_is_current_high_signal(
                {
                    "required_context": {},
                    "source_table": "endpoints",
                    "source_id": 1,
                    "asset_type": "endpoint",
                    "asset_value": "https://example.com/api/items/123",
                    "job_type": "idor_bac_test",
                }
            )
        )

    def test_nonzero_process_is_classified_without_printing_provider_output(self):
        async def exercise() -> None:
            with tempfile.TemporaryDirectory() as temp_dir:
                worker = BugJobWorker.__new__(BugJobWorker)
                worker.workspace = Path(temp_dir)
                worker.timeout_seconds = 10
                with self.assertRaises(CodexExecutionError) as raised:
                    await worker.execute_codex(
                        ["python3", "-c", "import sys; sys.stderr.write('429 rate limit'); sys.exit(1)"],
                        Path(temp_dir),
                    )
                self.assertEqual(raised.exception.category, "rate_limit")

        asyncio.run(exercise())

    def test_execute_codex_passes_only_configured_provider_secret(self):
        async def exercise() -> None:
            with tempfile.TemporaryDirectory() as temp_dir:
                worker = BugJobWorker.__new__(BugJobWorker)
                worker.workspace = Path(temp_dir)
                worker.timeout_seconds = 10
                worker.codex_provider_env_key = "DEEPSEEK_API_KEY"
                worker.codex_passthrough_env = ("PGPASSWORD",)
                output = Path(temp_dir) / "child-env.txt"
                command = [
                    "python3",
                    "-c",
                    (
                        "import os, pathlib; "
                        f"pathlib.Path({str(output)!r}).write_text("
                        "str(bool(os.getenv('DEEPSEEK_API_KEY'))) + ':' + "
                        "str(bool(os.getenv('PGPASSWORD'))) + ':' + "
                        "str(bool(os.getenv('UNRELATED_SECRET'))) + ':' + "
                        "str('default_transaction_read_only=on' in os.getenv('PGOPTIONS', '')))"
                    ),
                ]
                with mock.patch.dict(
                    "os.environ",
                    {
                        "DEEPSEEK_API_KEY": "provider-secret",
                        "PGPASSWORD": "database-secret",
                        "UNRELATED_SECRET": "do-not-pass",
                    },
                    clear=False,
                ):
                    await worker.execute_codex(command, Path(temp_dir))
                self.assertEqual(output.read_text(encoding="utf-8"), "True:True:False:True")

        asyncio.run(exercise())

    def test_execute_codex_rejects_missing_provider_secret(self):
        async def exercise() -> None:
            with tempfile.TemporaryDirectory() as temp_dir:
                worker = BugJobWorker.__new__(BugJobWorker)
                worker.workspace = Path(temp_dir)
                worker.timeout_seconds = 10
                worker.codex_provider_env_key = "DEEPSEEK_API_KEY"
                worker.codex_passthrough_env = ()
                with mock.patch.dict("os.environ", {}, clear=True):
                    with self.assertRaises(CodexExecutionError) as raised:
                        await worker.execute_codex(["true"], Path(temp_dir))
                self.assertEqual(raised.exception.category, "authentication")

        asyncio.run(exercise())

    def test_timeout_stops_process_group(self):
        async def exercise() -> None:
            with tempfile.TemporaryDirectory() as temp_dir:
                worker = BugJobWorker.__new__(BugJobWorker)
                worker.workspace = Path(temp_dir)
                worker.timeout_seconds = 1
                started = time.monotonic()
                with self.assertRaises(CodexJobTimeout):
                    await worker.execute_codex(
                        ["python3", "-c", "import time; time.sleep(30)"],
                        Path(temp_dir),
                    )
                self.assertLess(time.monotonic() - started, 5)

        asyncio.run(exercise())

    def test_every_native_job_type_has_an_installed_family_prompt(self):
        worker = self.focused_worker()
        for job_type, expected_filename in FAMILY_PROMPTS.items():
            job = {
                "job_type": job_type,
                "asset_value": "https://example.com/api/items/123",
                "hypothesis": "focused test",
                "required_context": {},
            }
            selected = worker.family_prompt_filename(job, worker.job_profile(job_type))
            self.assertIsNotNone(selected, job_type)
            self.assertTrue((worker.prompt_library_root / "prompts" / selected).is_file(), job_type)
            if job_type not in {"auth_session_review", "ssrf_candidate_test", "js_dom_xss_review", "injection_review", "business_logic_review"}:
                self.assertEqual(selected, expected_filename)

    def test_all_prompt_families_are_reachable_from_focused_jobs(self):
        worker = self.focused_worker()
        cases = [
            ("delta_intelligence_review", "recon-delta://example.com?snapshot=42", "new scan delta"),
            ("idor_bac_test", "https://example.com/api/users/123", ""),
            ("auth_session_review", "https://example.com/login", "account lifecycle"),
            ("auth_session_review", "https://example.com/mfa/verify", "OTP verification code"),
            ("auth_session_review", "https://example.com/oauth/callback", "OIDC SSO redirect_uri"),
            ("crypto_token_review", "https://example.com/api/token", "JWT session"),
            ("graphql_authz_test", "https://example.com/graphql", "GraphQL operation"),
            ("xss_reflection_test", "https://example.com/search?q=x", "reflected input"),
            ("js_dom_xss_review", "https://example.com/app.js", "postMessage window.opener"),
            ("ssrf_candidate_test", "https://example.com/fetch?url=x", "server fetch"),
            ("ssrf_candidate_test", "https://example.com/login?next=x", "open redirect"),
            ("injection_review", "https://example.com/search?filter=x", "SQL query"),
            ("injection_review", "https://example.com/render?template=x", "SSTI template"),
            ("upload_attack_surface", "https://example.com/upload", "file upload"),
            ("cors_misconfig_test", "https://example.com/api/private", "CORS"),
            ("cache_desync_review", "https://example.com/private.css", "cache deception"),
            ("js_secret_review", "https://example.com/app.js", "source map secret"),
            ("cloud_storage_review", "https://bucket.example.com/", "cloud storage"),
            ("business_logic_review", "https://example.com/checkout", "workflow invariant"),
            ("exceptional_condition_review", "https://example.com/jobs/123", "retry rollback"),
            ("new_admin_route_review", "https://admin.example.com/debug", "admin debug"),
            ("websocket_review", "wss://example.com/events", "subscription"),
            ("component_supply_chain_review", "https://example.com/package-lock.json", "dependency"),
            ("mobile_api_parity_review", "https://example.com/mobile/v1", "legacy client"),
            ("ai_llm_workflow_review", "https://example.com/api/agent", "RAG tool"),
            ("logging_audit_review", "https://example.com/audit", "security events"),
            ("email_parser_idn_review", "https://example.com/invite", "email identity"),
        ]
        selected = set()
        for job_type, asset, hypothesis in cases:
            job = {
                "job_type": job_type,
                "asset_value": asset,
                "hypothesis": hypothesis,
                "required_context": {},
            }
            selected.add(worker.family_prompt_filename(job, worker.job_profile(job_type)))
        available = {path.name for path in (worker.prompt_library_root / "prompts").glob("[0-9][0-9]-*.md")}
        # Prompt 08 remains available for full target-wide sessions. Focused JS
        # worker jobs use the combined DOM/postMessage prompt 27 instead.
        available.discard("08-postmessage-opener-iframe-trust.md")
        self.assertEqual(selected, available)

    def test_endpoint_context_is_bounded_to_exact_row_and_one_hop_links(self):
        worker = self.focused_worker()
        job = {
            "source_table": "endpoints",
            "source_id": 123,
            "asset_type": "endpoint",
        }
        scope = "\n".join(worker.item_context_scope(job))
        self.assertIn("endpoints:123", scope)
        self.assertIn("url_parameters for this endpoint_id", scope)
        self.assertIn("directly linked", scope)
        self.assertIn("at most five", scope)

    def test_js_dom_finding_context_recovers_exact_js_asset_and_analysis(self):
        worker = self.focused_worker()
        job = {
            "source_table": "findings",
            "source_id": 456,
            "asset_type": "finding",
            "job_type": "js_dom_xss_review",
        }
        scope = "\n".join(worker.item_context_scope(job))
        self.assertIn("findings:456", scope)
        self.assertIn("js_asset_id", scope)
        self.assertIn("asset_url equals this finding location", scope)
        self.assertIn("matching js_analysis_results", scope)

    def test_generated_prompt_overrides_family_to_current_item_only(self):
        worker = self.focused_worker()
        job = {
            "id": 42,
            "domain_id": 7,
            "target": "example.com",
            "asset_type": "endpoint",
            "asset_value": "https://app.example.com/api/export?id=123",
            "job_type": "upload_attack_surface",
            "source_table": "endpoints",
            "source_id": 123,
            "hypothesis": "The exact export endpoint may expose another owned object's file.",
            "required_context": {"payload": {"method": "GET"}},
        }
        prompt = worker.build_prompt(job, Path("/tmp/job_42/evidence"))
        self.assertIn("13-file-upload-traversal-lfi-xxe.md", prompt)
        self.assertIn("Item-scoped recon query boundary", prompt)
        self.assertIn("do not build a root-domain inventory", prompt)
        self.assertIn("Do not query every endpoint", prompt)
        self.assertIn('"source_table": "endpoints"', prompt)
        self.assertIn('"source_id": 123', prompt)
        self.assertIn('"item_scope_respected": true', prompt)

    def test_discord_alert_requires_unique_item_scoped_confirmation(self):
        worker = self.focused_worker()
        worker.discord_alerts_enabled = True
        worker.discord_webhook_url = "https://discord.invalid/webhook"
        worker.discord_alert_statuses = {"confirmed"}
        worker.discord_alert_min_confidence = 75
        self.assertTrue(worker.should_alert("confirmed", 90, "CONFIRMED_UNIQUE", True))
        self.assertFalse(worker.should_alert("confirmed", 90, "CONFIRMED_DUPLICATE", True))
        self.assertFalse(worker.should_alert("confirmed", 90, "CONFIRMED_UNIQUE", False))
        self.assertFalse(worker.should_alert("confirmed", 90, None, True))
        self.assertFalse(worker.should_alert("possible", 95, "CONFIRMED_UNIQUE", True))

    def test_review_alert_requires_concrete_anomaly_and_local_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            job_dir = Path(temp_dir)
            evidence = job_dir / "evidence" / "response.json"
            evidence.parent.mkdir()
            evidence.write_text('{"status": 200}', encoding="utf-8")
            output = job_dir / "result.json"
            output.write_text("{}", encoding="utf-8")
            worker = self.focused_worker()
            worker.discord_alerts_enabled = True
            worker.discord_webhook_url = "https://discord.invalid/webhook"
            worker.discord_alert_statuses = {"confirmed"}
            worker.discord_alert_min_confidence = 75
            worker.discord_review_alerts_enabled = True
            worker.discord_review_alert_min_confidence = 65
            worker.discord_review_alert_outcomes = {"STRONG_CANDIDATE", "NEEDS_MANUAL_REVIEW"}
            worker.discord_review_alert_priorities = {"medium", "high", "critical"}
            result = {
                "finding_status": "possible",
                "outcome_class": "STRONG_CANDIDATE",
                "item_scope_respected": True,
                "confidence": 82,
                "manual_review_priority": "high",
                "alert_signals": ["authorization_issue"],
                "vulnerability_class": "Potential cross-tenant file authorization failure",
                "title": "Owned control returned a foreign file metadata shape",
                "observed_anomaly": "The negative-control object returned the same private metadata keys as the owner baseline.",
                "manual_review_reason": "A second owned tenant object is required to determine whether the response contains foreign data.",
                "recommended_next_step": "Replay with the second owned tenant object and compare identifiers.",
                "tests_performed": ["owner and invalid-object comparison"],
                "data_sources_used": ["recon database", "live response"],
                "evidence_files": ["evidence/response.json"],
            }
            self.assertEqual(worker.classify_alert(result, output), "review")
            result["manual_review_priority"] = "medium"
            result["confidence"] = 70
            self.assertEqual(worker.classify_alert(result, output), "review")
            result["alert_signals"] = []
            self.assertIsNone(worker.classify_alert(result, output))
            result["alert_signals"] = ["authorization_issue"]
            result["evidence_files"] = ["/etc/passwd"]
            self.assertIsNone(worker.classify_alert(result, output))

    def test_review_alert_does_not_promote_ordinary_auth_blocker(self):
        worker = self.focused_worker()
        worker.discord_alerts_enabled = True
        worker.discord_webhook_url = "https://discord.invalid/webhook"
        worker.discord_alert_statuses = {"confirmed"}
        worker.discord_alert_min_confidence = 75
        worker.discord_review_alerts_enabled = True
        worker.discord_review_alert_min_confidence = 75
        worker.discord_review_alert_outcomes = {"STRONG_CANDIDATE", "NEEDS_MANUAL_REVIEW"}
        worker.discord_review_alert_priorities = {"high", "critical"}
        result = {
            "finding_status": "possible",
            "outcome_class": "NEEDS_MANUAL_REVIEW",
            "item_scope_respected": True,
            "confidence": 90,
            "manual_review_priority": "low",
            "vulnerability_class": "Unverified file workflow",
            "title": "Authentication is required",
            "observed_anomaly": "No anomaly was observed because the route returned a login page.",
            "manual_review_reason": "An authenticated session was not available.",
            "recommended_next_step": "Provide a session.",
            "tests_performed": ["anonymous GET"],
            "data_sources_used": ["live response"],
            "evidence_files": [],
        }
        self.assertIsNone(worker.classify_alert(result, Path("/tmp/result.json")))

    def test_dom_review_static_signal_never_alerts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            job_dir = Path(temp_dir)
            evidence = job_dir / "evidence" / "static-trace.txt"
            evidence.parent.mkdir()
            evidence.write_text("postMessage listener with no live effect", encoding="utf-8")
            output = job_dir / "result.json"
            output.write_text("{}", encoding="utf-8")
            worker = self.focused_worker()
            worker.discord_alerts_enabled = True
            worker.discord_webhook_url = "https://discord.invalid/webhook"
            worker.discord_alert_statuses = {"confirmed"}
            worker.discord_alert_min_confidence = 75
            worker.discord_review_alerts_enabled = True
            worker.discord_review_alert_min_confidence = 50
            worker.discord_review_alert_outcomes = {"STRONG_CANDIDATE", "NEEDS_MANUAL_REVIEW"}
            worker.discord_review_alert_priorities = {"high", "critical"}
            result = {
                "finding_status": "possible",
                "outcome_class": "STRONG_CANDIDATE",
                "item_scope_respected": True,
                "confidence": 95,
                "manual_review_priority": "high",
                "alert_signals": ["postmessage_origin_trust"],
                "vulnerability_class": "Potential postMessage origin trust issue",
                "title": "Static message listener lacks an obvious origin check",
                "observed_anomaly": "Static code contains a listener but no live target behavior was reached.",
                "manual_review_reason": "A reachable integration page would be required.",
                "recommended_next_step": "Locate the current target page that initializes this listener.",
                "tests_performed": ["static source-to-sink trace"],
                "data_sources_used": ["js_assets", "js_analysis_results"],
                "evidence_files": ["evidence/static-trace.txt"],
                "browser_security_flow": "static_only",
                "impact_dimensions": ["confidentiality"],
                "runtime_or_reachability_proof": "No live route or browser behavior was established.",
                "dom_worker_alert_eligible": False,
            }
            self.assertIsNone(worker.classify_alert(result, output, "js_dom_xss_review"))

    def test_dom_review_foreign_origin_integrity_lead_can_alert(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            job_dir = Path(temp_dir)
            evidence = job_dir / "evidence" / "runtime.json"
            evidence.parent.mkdir()
            evidence.write_text('{"foreign_origin_accepted": true}', encoding="utf-8")
            output = job_dir / "result.json"
            output.write_text("{}", encoding="utf-8")
            worker = self.focused_worker()
            worker.discord_alerts_enabled = True
            worker.discord_webhook_url = "https://discord.invalid/webhook"
            worker.discord_alert_statuses = {"confirmed"}
            worker.discord_alert_min_confidence = 75
            worker.discord_review_alerts_enabled = True
            worker.discord_review_alert_min_confidence = 50
            worker.discord_review_alert_outcomes = {"STRONG_CANDIDATE", "NEEDS_MANUAL_REVIEW"}
            worker.discord_review_alert_priorities = {"high", "critical"}
            result = {
                "finding_status": "possible",
                "outcome_class": "STRONG_CANDIDATE",
                "item_scope_respected": True,
                "confidence": 86,
                "manual_review_priority": "high",
                "alert_signals": ["postmessage_origin_trust"],
                "vulnerability_class": "postMessage origin and source trust failure",
                "title": "Foreign opener reaches a privileged browser action",
                "observed_anomaly": "A foreign-origin opener message reached the owned-account action handler.",
                "manual_review_reason": "One reversible owned-object confirmation remains before report classification.",
                "recommended_next_step": "Repeat with a fresh owned object and independently read back the state.",
                "tests_performed": ["foreign-origin sender baseline and trusted-origin negative control"],
                "data_sources_used": ["js_assets", "live browser response"],
                "evidence_files": ["evidence/runtime.json"],
                "browser_security_flow": "foreign_origin_privileged_effect",
                "impact_dimensions": ["integrity"],
                "runtime_or_reachability_proof": "The current in-scope page accepted the foreign opener message and invoked the action handler.",
                "dom_worker_alert_eligible": True,
            }
            self.assertEqual(worker.classify_alert(result, output, "js_dom_xss_review"), "review")

    def test_review_lead_can_alert_without_anomaly_signal_when_operator_action_is_specific(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            job_dir = Path(temp_dir)
            evidence = job_dir / "evidence" / "verification.json"
            evidence.parent.mkdir()
            evidence.write_text('{"status": 401}', encoding="utf-8")
            output = job_dir / "result.json"
            output.write_text("{}", encoding="utf-8")
            worker = self.focused_worker()
            worker.discord_alerts_enabled = True
            worker.discord_webhook_url = "https://discord.invalid/confirmed-webhook"
            worker.discord_alert_statuses = {"confirmed"}
            worker.discord_alert_min_confidence = 75
            worker.discord_review_alerts_enabled = True
            worker.discord_review_alert_min_confidence = 50
            worker.discord_review_alert_outcomes = {
                "STRONG_CANDIDATE",
                "NEEDS_MANUAL_REVIEW",
                "BLOCKED",
            }
            worker.discord_review_alert_priorities = {"medium", "high", "critical"}
            worker.discord_review_alert_require_signal = False
            result = {
                "finding_status": "possible",
                "outcome_class": "NEEDS_MANUAL_REVIEW",
                "item_scope_respected": True,
                "confidence": 90,
                "manual_review_priority": "medium",
                "alert_signals": None,
                "vulnerability_class": "Authenticated upload processing boundary",
                "title": "Owned upload baseline is required",
                "observed_anomaly": "No exploit anomaly was observed; authentication occurs before parser handling.",
                "manual_review_reason": "An owned bearer session and disposable PNG are required for a valid parser baseline.",
                "recommended_next_step": "Upload one tiny owned PNG, then change one parser input at a time.",
                "tests_performed": ["anonymous GET and POST controls"],
                "data_sources_used": ["recon database", "live response"],
                "evidence_files": ["evidence/verification.json"],
            }
            self.assertEqual(worker.classify_alert(result, output), "review")

    def test_alert_asset_fingerprint_ignores_query_values(self):
        first = canonical_alert_asset(
            "HTTPS://Example.COM:443/download?id=123&token=secret#fragment"
        )
        second = canonical_alert_asset("https://example.com/download?token=other&id=456")
        self.assertEqual(first, second)
        self.assertEqual(first, "https://example.com/download?id=&token=")

    def test_alert_text_redacts_common_credential_shapes(self):
        text = clean_alert_text(
            "authorization: Bearer abc.def ghi "
            "AKIAABCDEFGHIJKLMNOP ghp_abcdefghijklmnopqrstuvwxyz123456 "  # gitleaks:allow - synthetic fixtures
            "eyJabcdefghijk.abcdefghijk.abcdefghijk"
        )
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", text)  # gitleaks:allow - synthetic fixture
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", text)
        self.assertNotIn("eyJabcdefghijk.abcdefghijk.abcdefghijk", text)


if __name__ == "__main__":
    unittest.main()
