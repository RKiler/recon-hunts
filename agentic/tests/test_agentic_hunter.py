import unittest
import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import agentic_hunter_worker as worker
from agentic_hunter import AgenticHunter, host_belongs_to_root, normalize_exact_host


class AgenticHunterTests(unittest.TestCase):
    def test_agentic_vnc_request_waits_for_isolated_session(self):
        with TemporaryDirectory() as directory, patch.object(worker, "LOGIN_ROOT", Path(directory)):
            run = {"id": 6, "domain": "example.com"}
            accounts = [{"id": 12, "alias": "owner", "exact_host": "app.example.com",
                         "type": "login_file", "secret_name": "owned.secret",
                         "secret_file": "/private/owned.secret"}]
            ready, statuses = worker.request_login(run, accounts)
            self.assertFalse(ready)
            self.assertEqual(statuses[0]["status"], "preparing")
            request = json.loads((Path(directory) / "run_1000000006/login_request.json").read_text())
            self.assertEqual(request["accounts"][0]["run_label"], "agentic-run-6")
            self.assertEqual(request["accounts"][0]["exact_host"], "app.example.com")
            self.assertNotIn("secret_file", accounts[0]["session_file"])
            session = Path(accounts[0]["session_file"])
            session.parent.mkdir(parents=True)
            session.write_text("{}")
            ready, statuses = worker.request_login(run, accounts)
            self.assertTrue(ready)
            self.assertEqual(statuses[0]["status"], "ready_for_identity_verification")

    def test_manual_vnc_account_uses_same_handoff(self):
        with TemporaryDirectory() as directory, patch.object(worker, "LOGIN_ROOT", Path(directory)):
            accounts = [{"id": 13, "alias": "manual", "exact_host": "app.example.com",
                         "type": "manual_login", "secret_name": "placeholder.secret"}]
            ready, statuses = worker.request_login({"id": 7, "domain": "example.com"}, accounts)
            self.assertFalse(ready)
            self.assertEqual(statuses[0]["status"], "preparing")
            request = json.loads((Path(directory) / "run_1000000007/login_request.json").read_text())
            self.assertEqual(request["accounts"][0]["credential_type"], "manual_login")

    def test_scope_uses_parsed_hostname(self):
        self.assertTrue(worker.scoped_host("https://api.example.com/v1", "example.com", True))
        self.assertTrue(worker.scoped_host("https://example.com/", "example.com", False))
        self.assertFalse(worker.scoped_host("https://api.example.com/v1", "example.com", False))
        self.assertFalse(worker.scoped_host("https://example.com.evil.test/", "example.com", True))
        self.assertFalse(worker.scoped_host("https://evil.test/?next=example.com", "example.com", True))
        self.assertFalse(worker.scoped_host("javascript:alert(1)", "example.com", True))

    def test_exact_host_is_canonical_and_does_not_expand_scope(self):
        self.assertEqual(normalize_exact_host(" Sidekick.Zapier.com. "), "sidekick.zapier.com")
        self.assertTrue(host_belongs_to_root("sidekick.zapier.com", "zapier.com", True))
        self.assertFalse(host_belongs_to_root("sidekick.zapier.com", "zapier.com", False))
        for value in ("*.zapier.com", "https://sidekick.zapier.com/", "sidekick.zapier.com:443",
                      "sidekick.zapier.com.evil.test", "a..zapier.com"):
            if value == "sidekick.zapier.com.evil.test":
                self.assertFalse(host_belongs_to_root(value, "zapier.com", True))
            else:
                with self.assertRaises(ValueError):
                    normalize_exact_host(value)
        run = {"domain": "zapier.com", "include_subdomains": True,
               "target_host": "sidekick.zapier.com"}
        self.assertTrue(worker.run_scoped_host("https://sidekick.zapier.com/a", run))
        self.assertFalse(worker.run_scoped_host("https://zapier.com/a", run))
        self.assertFalse(worker.run_scoped_host("https://other.zapier.com/a", run))

    def test_display_url_drops_values_and_fragment(self):
        shown = worker.display_url("https://example.com/reset?token=secret&q=hello#fragment")
        self.assertEqual(shown, "https://example.com/reset?q=%7Bvalue%7D&token=%7Bvalue%7D")
        self.assertNotIn("secret", shown)

    def test_foreign_absolute_endpoint_rejected(self):
        self.assertEqual(worker.endpoint_url("https://app.example.com", "https://cdn.evil.test/a",
                                             "example.com", True), "")
        self.assertEqual(worker.endpoint_url("https://app.example.com", "/api/users/1",
                                             "example.com", True), "https://app.example.com/api/users/1")

    def test_hunt_prompt_excludes_upstream_full_scanner(self):
        run = {"id": 1, "domain": "example.com", "include_subdomains": True}
        prompt = worker.hunt_prompt(run, Path("/tmp/packet.json"), Path("/tmp/run"),
                                    product_capture_path=Path("/tmp/product_capture.json"),
                                    request_allowance=75, remaining_budget=300)
        self.assertIn("Do not invoke the upstream full scanner", prompt)
        self.assertIn("allowance of 75 target HTTP requests", prompt)
        self.assertIn("300 unspent target requests", prompt)
        self.assertIn("one request per second per host", prompt)
        self.assertIn("negative control", prompt)
        self.assertIn("product_capture.json", prompt)
        self.assertIn("access control/IDOR/BOLA/BFLA", prompt)
        self.assertIn("no mailbox connection", prompt)

    def test_product_links_stay_in_scope_and_skip_state_changes(self):
        run = {"domain": "example.com", "include_subdomains": True,
               "target_host": "app.example.com"}
        capture = {"target": "https://app.example.com/", "links": [
            "https://other.example.com/app", "https://app.example.com/logout",
            "https://app.example.com/projects", "https://app.example.com/delete/account",
            "https://app.example.com/docs",
        ]}
        self.assertEqual(worker.product_page_candidates(capture, run), [
            "https://app.example.com/projects", "https://app.example.com/docs"])

    def test_same_route_different_bug_labels_deduplicates(self):
        first = {"skill": "hunt-xss", "asset": "https://app.example.com/api/items/123", "method": "GET"}
        second = {**first, "skill": "hunt-idor"}
        self.assertEqual(worker.route_key(first), worker.route_key(second))

    def test_upstream_router_is_loaded(self):
        source = worker.SIGNAL_PATH
        if not source.is_file():
            self.skipTest("Upstream checkout is unavailable")
        with patch.object(worker, "SIGNAL_PATH", source):
            routes = list(worker.load_router()("https://app.example.com/api/graphql", "url"))
        self.assertTrue(any(item[0] == "hunt-graphql" for item in routes))

    def test_route_key_collapses_numeric_object_ids(self):
        first = {"skill": "hunt-idor", "asset": "https://app.example.com/api/users/123", "method": "GET"}
        second = {"skill": "hunt-idor", "asset": "https://app.example.com/api/users/456", "method": "GET"}
        self.assertEqual(worker.route_key(first), worker.route_key(second))

    def test_request_allowance_carries_unused_budget_forward(self):
        self.assertEqual(worker.next_request_allowance(300, 0, 4), 75)
        self.assertEqual(worker.next_request_allowance(300, 20, 3), 94)
        self.assertEqual(worker.next_request_allowance(300, 280, 1), 20)
        self.assertEqual(worker.next_request_allowance(300, 300, 1), 0)


class AgenticDeltaWindowTests(unittest.IsolatedAsyncioTestCase):
    async def test_waiting_login_resumes_only_after_broker_session(self):
        with TemporaryDirectory() as directory, patch.object(worker, "LOGIN_ROOT", Path(directory)):
            conn = type("Connection", (), {})()
            conn.fetch = AsyncMock(side_effect=[
                [{"id": 6, "domain_id": 1, "credential_ids": [12], "summary": {}}],
                [{"id": 12, "alias": "owner", "host": "app.example.com",
                  "credential_type": "login_file"}],
            ])
            conn.execute = AsyncMock()

            class Pool:
                @asynccontextmanager
                async def acquire(self):
                    yield conn

            hunter = object.__new__(worker.AgenticWorker)
            hunter.pool = Pool()
            await hunter.refresh_login_waiters()
            self.assertNotIn("status='queued'", str(conn.execute.call_args_list))
            session = worker.login_session_dir(6) / "account_12.json"
            session.parent.mkdir(parents=True)
            session.write_text("{}")
            conn.fetch = AsyncMock(side_effect=[
                [{"id": 6, "domain_id": 1, "credential_ids": [12], "summary": {}}],
                [{"id": 12, "alias": "owner", "host": "app.example.com",
                  "credential_type": "login_file"}],
            ])
            await hunter.refresh_login_waiters()
            self.assertIn("status='queued'", str(conn.execute.call_args_list))

    async def test_lead_detail_includes_source_and_validation_history(self):
        conn = type("Connection", (), {})()
        conn.fetchrow = AsyncMock(side_effect=[
            {"id": 7, "run_id": 3, "domain_id": 1, "title": "Review endpoint",
             "skill": "hunt-idor", "signal": "authorization", "source_table": "endpoints",
             "source_id": 42, "asset": "https://app.example.com/api/item/{id}",
             "priority": "high", "status": "lead", "confidence": 0,
             "rationale": "Object ID", "created_at": datetime(2026, 10, 10),
             "run_action": "hunt", "run_status": "done", "artifact_dir": None,
             "summary": {"summary": "No confirmation"}, "domain": "example.com"},
            {"method": "GET", "status_code": 200, "source": "js_analysis",
             "risk_tags": [], "first_seen": datetime(2026, 10, 9),
             "last_seen": datetime(2026, 10, 10), "live_host": "https://app.example.com",
             "parameter_names": ["id"]},
        ])
        conn.fetch = AsyncMock(return_value=[
            {"id": 9, "status": "done", "created_at": datetime(2026, 10, 10),
             "finished_at": datetime(2026, 10, 10),
             "summary": {"summary": "Rejected by negative control"}, "error": None},
        ])

        class Pool:
            @asynccontextmanager
            async def acquire(self):
                yield conn

        detail = await AgenticHunter(Pool()).get_lead_detail(7)
        self.assertEqual(detail["source"]["parameter_names"], ["id"])
        self.assertEqual(detail["source"]["last_seen"], "2026-10-10T00:00:00Z")
        self.assertEqual(detail["validations"][0]["summary"], "Rejected by negative control")

    async def test_validation_uses_lead_exact_host_without_running_worker(self):
        conn = type("Connection", (), {})()
        conn.fetchrow = AsyncMock(side_effect=[
            {"id": 1, "domain": "example.com", "active": True, "include_subdomains": True},
            {"id": 7, "domain_id": 1, "asset": "https://app.example.com/api/items"},
            {"id": 10, "status": "queued", "created_at": datetime(2026, 10, 10)},
        ])

        class Transaction:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

        conn.transaction = lambda: Transaction()

        class Pool:
            @asynccontextmanager
            async def acquire(self):
                yield conn

        result = await AgenticHunter(Pool()).create_run(1, "validate", "all", parent_lead_id=7)
        self.assertEqual(result["target_host"], "app.example.com")
        self.assertEqual(result["status"], "queued")
        self.assertEqual(result["request_budget"], 10)

    async def test_hunt_resumes_with_existing_pass_directory(self):
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "run_3"
            (artifact / "pass_01").mkdir(parents=True)
            (artifact / "packet.json").write_text(json.dumps({
                "domain_id": 1, "data_source": "all", "target_host": "app.example.com",
                "leads": [], "coverage": {},
            }), encoding="utf-8")

            conn = type("Connection", (), {})()
            conn.fetchrow = AsyncMock(return_value={"domain": "example.com", "include_subdomains": True})
            conn.fetchval = AsyncMock(return_value={})
            conn.execute = AsyncMock()

            class Pool:
                @asynccontextmanager
                async def acquire(self):
                    yield conn

            hunter = object.__new__(worker.AgenticWorker)
            hunter.pool = Pool()
            hunter.router = None
            hunter.manager = None
            row = {"id": 3, "domain_id": 1, "target_host": "app.example.com",
                   "action": "hunt", "data_source": "all", "credential_ids": [],
                   "max_passes": 1, "request_budget": 300,
                   "focus": "", "parent_lead_id": None}
            result = {"summary": "checked", "leads": [], "confirmed_findings": [],
                      "blocked": [], "active_request_count": 0}
            with patch.object(worker, "ROOT", Path(directory)), \
                    patch.object(worker, "capture_product", new_callable=AsyncMock,
                                 return_value={"pages": [], "request_count": 0}), \
                    patch.object(worker, "run_codex", new_callable=AsyncMock, return_value=result) as codex, \
                    patch("independent_hunt_worker.normalize_result", side_effect=lambda value, _: value):
                summary = await hunter.process(row)

            codex.assert_awaited_once()
            self.assertEqual(summary["passes_completed"], 1)
            self.assertEqual(summary["codex_request_count"], 0)
            self.assertEqual(summary["request_budget"], 300)

    async def test_missing_request_count_charges_allowance_and_stops(self):
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "run_4"
            artifact.mkdir()
            leads = [{"source_table": "endpoints", "source_id": index,
                      "lead_key": f"endpoint-{index}",
                      "asset": f"https://app.example.com/api/item/{index}",
                      "signal": "auth", "skill": "hunt-idor", "priority": "high",
                      "why": "controlled object"} for index in range(9)]
            (artifact / "packet.json").write_text(json.dumps({
                "domain_id": 1, "data_source": "all", "target_host": "app.example.com",
                "leads": leads, "coverage": {},
            }), encoding="utf-8")
            conn = type("Connection", (), {})()
            conn.fetchrow = AsyncMock(return_value={"domain": "example.com", "include_subdomains": True})
            conn.fetchval = AsyncMock(return_value={})
            conn.execute = AsyncMock()

            class Pool:
                @asynccontextmanager
                async def acquire(self):
                    yield conn

            hunter = object.__new__(worker.AgenticWorker)
            hunter.pool = Pool()
            hunter.router = None
            hunter.manager = None
            row = {"id": 4, "domain_id": 1, "target_host": "app.example.com",
                   "action": "hunt", "data_source": "all", "credential_ids": [],
                   "max_passes": 2, "request_budget": 300,
                   "focus": "", "parent_lead_id": None}
            result = {"summary": "checked", "leads": [], "confirmed_findings": [], "blocked": []}
            with patch.object(worker, "ROOT", Path(directory)), \
                    patch.object(worker, "capture_product", new_callable=AsyncMock,
                                 return_value={"pages": [], "request_count": 0}), \
                    patch.object(worker, "run_codex", new_callable=AsyncMock, return_value=result) as codex, \
                    patch("independent_hunt_worker.normalize_result", side_effect=lambda value, _: value):
                summary = await hunter.process(row)

            codex.assert_awaited_once()
            self.assertEqual(summary["passes_completed"], 1)
            self.assertEqual(summary["codex_request_count"], 150)
            self.assertIn("budget_accounting_warning", summary)

    async def test_run_codex_creates_private_logs_and_reads_result(self):
        with TemporaryDirectory() as directory:
            artifact = Path(directory)

            async def start_codex(*command, **kwargs):
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text('{"status": "done"}', encoding="utf-8")
                process = type("Process", (), {"returncode": 0})()
                process.wait = AsyncMock()
                return process

            with patch.object(worker.asyncio, "create_subprocess_exec", side_effect=start_codex):
                result = await worker.run_codex("test prompt", artifact)

            self.assertEqual(result, {"status": "done"})
            for name in ("prompt.md", "codex.stdout.log", "codex.stderr.log", "result.json"):
                self.assertEqual((artifact / name).stat().st_mode & 0o777, 0o600)

    async def test_uses_each_completed_delta_window(self):
        conn = type("Conn", (), {})()
        conn.fetch = AsyncMock(return_value=[
            {"id": 8, "scan_started_at": datetime(2026, 10, 8),
             "scan_finished_at": datetime(2026, 10, 8, 1)},
            {"id": 6, "scan_started_at": datetime(2026, 10, 1),
             "scan_finished_at": datetime(2026, 10, 1, 1)},
        ])
        window = await worker.latest_delta_window(conn, 5)
        self.assertEqual(window[0], datetime(2026, 10, 8))
        self.assertEqual(window[2], datetime(2026, 10, 1))
        self.assertEqual(window[4], [8, 6])


if __name__ == "__main__":
    unittest.main()
