from __future__ import annotations

import json
from pathlib import Path
import socketserver
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from flask import Flask, abort
from werkzeug.serving import make_server

from hackbot_gateway import UnixHTTPConnection, install_hackbot_routes


ROOT = Path(__file__).resolve().parents[1]


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode("ascii").strip()
        headers = {}
        while True:
            raw = self.rfile.readline().decode("ascii").strip()
            if not raw:
                break
            key, value = raw.split(":", 1)
            headers[key.lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0")))
        self.server.requests.append((line, headers, body))
        if line.startswith("GET /v1/reports/") and "/download?" in line:
            payload = b"# Synthetic report\nNo secrets.\n"
            content_type = "text/plain; charset=utf-8"
        else:
            payload = json.dumps({"ok": True}).encode()
            content_type = "application/json"
        self.wfile.write(f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n"
                         f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        socket_path = str(Path(self.temp.name) / "service.sock")
        self.server = socketserver.UnixStreamServer(socket_path, Handler)
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.app = Flask(__name__, template_folder=str(ROOT / "templates"),
                         static_folder=str(ROOT / "static"))
        self.app.config["TESTING"] = True
        self.enabled = True
        self.logged_in = True

        def csrf():
            from flask import request
            if request.headers.get("X-CSRF-Token") != "test-csrf":
                abort(403)

        install_hackbot_routes(self.app, authorized=lambda: self.logged_in,
                               auth_enabled=lambda: self.enabled,
                               csrf_token=lambda: "test-csrf", require_csrf=csrf,
                               socket_path=socket_path, hunt_ui_enabled=True)
        self.client = self.app.test_client()

    def test_read_only_routes_allow_single_worker_queueing(self):
        with patch("hackbot_gateway.UnixHTTPConnection", wraps=UnixHTTPConnection) as connection:
            for resource in ("bootstrap", "policy", "accounts"):
                self.assertEqual(self.client.get(f"/api/hackbot/targets/example/{resource}").status_code, 200)
                self.assertEqual(connection.call_args.kwargs["timeout"], 15.0)
            self.assertEqual(self.client.get("/api/hackbot/health").status_code, 200)
            self.assertEqual(connection.call_args.kwargs["timeout"], 15.0)
            self.assertEqual(self.client.post("/api/hackbot/targets/example/bootstrap", json={},
                                              headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)
            self.assertEqual(connection.call_args.kwargs["timeout"], 3.0)

    def test_evaluation_is_authenticated_read_only_and_allowlisted(self):
        run = "BENCH-" + "a" * 32
        self.logged_in = False
        self.assertEqual(self.client.get("/hackbot/evaluation").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/evaluation/runs").status_code, 401)
        self.logged_in = True
        page = self.client.get("/hackbot/evaluation")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="evaluationView"', page.data)
        for path in ("evaluation/suites", "evaluation/runs?limit=20",
                     f"evaluation/runs/{run}",
                     f"evaluation/runs/{run}/cases?limit=20&offset=0",
                     f"evaluation/compare?baseline_id={run}&current_id={run}",
                     f"evaluation/readiness?run_id={run}"):
            self.assertEqual(self.client.get("/api/hackbot/" + path).status_code, 200, path)
        self.assertNotIn("authorization", self.server.requests[-1][1])
        for path in ("evaluation/delete-all", "evaluation/runs/BENCH-invalid",
                     f"evaluation/runs/{run}/trace", "evaluation/runs",):
            self.assertEqual(self.client.post("/api/hackbot/" + path, json={},
                                              headers={"X-CSRF-Token": "test-csrf"}).status_code,
                             400)
        for path in ("evaluation/runs?target=example",
                     f"evaluation/runs/{run}/cases?offset=0&offset=1",
                     "evaluation/readiness?run_id=BENCH-invalid",
                     "evaluation/compare?baseline_id=BENCH-invalid"):
            self.assertEqual(self.client.get("/api/hackbot/" + path).status_code, 400, path)

    def test_session_delete_requires_auth_csrf_and_exact_route(self):
        path = "/api/hackbot/browser/sessions/BSESSION-" + "a" * 32 + "?target=example"
        self.logged_in = False
        self.assertEqual(self.client.delete(path).status_code, 401)
        self.logged_in = True
        self.assertEqual(self.client.delete(path).status_code, 403)
        self.assertEqual(self.client.delete(path, json={}, headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)
        self.assertTrue(self.server.requests[-1][0].startswith("DELETE /v1/browser/sessions/"))
        self.assertEqual(self.client.delete("/api/hackbot/browser/sessions/../../targets/example",
                                            headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)
        self.assertEqual(self.client.delete("/api/hackbot/targets/example", json={"confirm_package_id":"example"},
                                            headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)
        account = "/api/hackbot/targets/example/accounts/admin"
        self.assertEqual(self.client.delete(account, json={}).status_code, 403)
        self.assertEqual(self.client.delete(account, json={},
                                            headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)
        self.assertEqual(self.client.delete("/api/hackbot/targets/../../etc/passwd", json={},
                                            headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)

    def test_identity_confirmation_requires_auth_and_csrf(self):
        path = "/api/hackbot/browser/sessions/BSESSION-" + "a" * 32 + "/confirm-identity?target=example"
        self.logged_in = False
        self.assertEqual(self.client.post(path, json={"confirm_alias": "admin"}).status_code, 401)
        self.logged_in = True
        self.assertEqual(self.client.post(path, json={"confirm_alias": "admin"}).status_code, 403)
        response = self.client.post(path, json={"confirm_alias": "admin"},
                                    headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertTrue(line.startswith("POST /v1/browser/sessions/BSESSION-"))
        self.assertNotIn("x-csrf-token", headers)
        self.assertNotIn("cookie", headers)
        self.assertEqual(json.loads(body), {"confirm_alias": "admin"})

    def test_hunt_status_proxy_requires_auth(self):
        self.logged_in = False
        self.assertEqual(self.client.get("/api/hackbot/targets/example/hunt").status_code,
                         401)
        self.logged_in = True
        self.assertEqual(self.client.get("/api/hackbot/targets/example/hunt").status_code,
                         200)
        self.assertTrue(self.server.requests[-1][0].startswith(
            "GET /v1/targets/example/hunt"))
        self.assertNotIn("cookie", self.server.requests[-1][1])

    def test_dashboard_restart_reconnects_to_existing_hunt_service(self):
        fresh = Flask("restarted-hunt-gateway", template_folder=str(ROOT / "templates"),
                      static_folder=str(ROOT / "static"))
        install_hackbot_routes(fresh, authorized=lambda: self.logged_in,
                               auth_enabled=lambda: self.enabled,
                               csrf_token=lambda: "test-csrf",
                               require_csrf=lambda: None,
                               socket_path=str(Path(self.temp.name) / "service.sock"),
                               hunt_ui_enabled=True)
        response = fresh.test_client().get("/api/hackbot/targets/example/hunt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"ok": True})
        self.assertEqual(self.server.requests[-1][0],
                         "GET /v1/targets/example/hunt HTTP/1.1")

    def test_hunt_start_proxy_requires_auth_csrf_and_exact_route(self):
        path = "/api/hackbot/targets/example/hunt"
        self.logged_in = False
        self.assertEqual(self.client.post(path, json={}).status_code, 401)
        self.logged_in = True
        self.assertEqual(self.client.post(path, json={}).status_code, 403)
        self.assertEqual(self.client.post(path, data="not json",
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)
        self.assertEqual(self.client.post(path + "/start", json={},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)
        response = self.client.post(path, json={"mode": "SUPERVISED"},
                                    headers={"X-CSRF-Token": "test-csrf",
                                             "Cookie": "private-fixture",
                                             "Authorization": "Bearer private-fixture"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertEqual(line, "POST /v1/targets/example/hunt HTTP/1.1")
        self.assertEqual(json.loads(body), {"mode": "SUPERVISED"})
        self.assertNotIn("cookie", headers)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("x-csrf-token", headers)

    def test_hunt_ui_is_disabled_by_default(self):
        app = Flask("hunt-off", template_folder=str(ROOT / "templates"),
                    static_folder=str(ROOT / "static"))
        install_hackbot_routes(app, authorized=lambda: True,
                               auth_enabled=lambda: True,
                               csrf_token=lambda: "test-csrf",
                               require_csrf=lambda: None)
        client = app.test_client()
        self.assertEqual(client.get("/hackbot/hunt").status_code, 404)
        page = client.get("/hackbot/targets")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(b'id="huntView"', page.data)
        self.assertNotIn(b'data-target-tab="hunt"', page.data)
        self.assertEqual(client.post("/api/hackbot/targets/example/hunt", json={}).status_code,
                         409)

    def test_hunt_view_is_available_to_authenticated_operator_when_enabled(self):
        self.logged_in = False
        self.assertEqual(self.client.get("/hackbot/hunt").status_code, 401)
        self.logged_in = True
        page = self.client.get("/hackbot/hunt")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="huntView"', page.data)
        self.assertIn(b'data-target-tab="hunt"', page.data)
        self.assertIn(b'"huntEnabled": true', page.data)

    def test_auth_gate_and_csrf(self):
        self.logged_in = False
        self.assertEqual(self.client.get("/api/hackbot/targets").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/targets/example/bootstrap").status_code, 401)
        self.assertEqual(self.client.post("/api/hackbot/targets/example/bootstrap", json={}).status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/validations?target=example").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/findings?target=example").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/objects?target=example").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/authorization/example/profile").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/domxss/example/candidates").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/domxss/example/inventory").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/postmessage/example/candidates").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/postmessage/example/metrics").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/exposure/example/candidates").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/evidence/EVIDENCE-test?target=example").status_code, 401)
        self.assertEqual(self.client.get("/hackbot").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/findings").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/objects").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/authorization").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/domxss").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/postmessage").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/exposure").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/research").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/reports").status_code, 401)
        self.assertEqual(self.client.get("/hackbot/operations").status_code, 401)

        self.assertEqual(self.client.get("/api/hackbot/operations").status_code, 401)
        self.assertEqual(self.client.post("/api/hackbot/operations/maintenance",
                                          json={"action": "RETENTION_PLAN"}).status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/reports?target=example").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/research/example/gaps").status_code, 401)
        self.logged_in = True
        self.enabled = False
        self.assertEqual(self.client.get("/api/hackbot/targets").status_code, 503)
        self.enabled = True
        operations_page = self.client.get("/hackbot/operations")
        self.assertEqual(operations_page.status_code, 200)
        for control in (b'operationsBackupCreate', b'operationsBackupVerify',
                        b'operationsRetentionPlan', b'operationsRetentionRun',
                        b'operationsRetentionConfirm', b'operationsProfilePlan',
                        b'operationsProfileRun', b'operationsProfileConfirm',
                        b'operationsCandidates'):
            self.assertIn(control, operations_page.data)
        self.assertNotIn(b'operationsRestore', operations_page.data)
        self.assertEqual(self.client.get("/api/hackbot/operations").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/operations/maintenance").status_code, 200)
        self.assertEqual(self.client.post("/api/hackbot/operations", json={},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)
        self.assertEqual(self.client.post("/api/hackbot/operations/maintenance",
                                          json={"action": "RETENTION_PLAN"}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/operations/maintenance",
                                          json={"action": "PROFILE_RUN", "confirmed": True}).status_code, 403)
        approved = self.client.post("/api/hackbot/operations/maintenance",
                                    json={"action": "RETENTION_PLAN"},
                                    headers={"X-CSRF-Token": "test-csrf",
                                             "Authorization": "Bearer private-fixture"})
        self.assertEqual(approved.status_code, 200)
        self.assertNotIn("authorization", self.server.requests[-1][1])
        self.assertEqual(json.loads(self.server.requests[-1][2])["action"], "RETENTION_PLAN")
        review = "MAINT-" + "a" * 32
        approved_run = self.client.post("/api/hackbot/operations/maintenance",
                                        json={"action": "PROFILE_RUN", "confirmed": True,
                                              "review_id": review},
                                        headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(approved_run.status_code, 200)
        self.assertEqual(json.loads(self.server.requests[-1][2])["review_id"], review)
        self.assertEqual(self.client.post("/api/hackbot/operations/delete",
                                          json={}, headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)
        self.assertEqual(self.client.post("/api/hackbot/browser/sessions", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/targets/example/profile", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/targets/example/bootstrap", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/targets/example/bootstrap/BOOT-" +
                                          "a" * 32 + "/cancel", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/domxss/example/analyze",
                                          json={"recon_asset_id": 7}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/postmessage/example/analyze",
                                          json={"recon_asset_id": 7}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/exposure/example/discover",
                                          json={"source": "recon"}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/research/example/requests",
                                          json={"gap_ref": "hypothesis:HYP-" + "a" * 32}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/notifications/test",
                                          json={"target": "example"}).status_code, 403)

    def test_target_setup_uses_auth_csrf_and_private_socket(self):
        self.logged_in = False
        self.assertEqual(self.client.get("/hackbot/targets").status_code, 401)
        self.assertEqual(self.client.post("/api/hackbot/targets", json={}).status_code, 401)
        self.logged_in = True
        page = self.client.get("/hackbot/targets")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="addTarget"', page.data)
        self.assertIn(b'id="targetSetupForm"', page.data)
        self.assertIn(b'id="deletedTargetHistory"', page.data)
        self.assertEqual(self.client.get("/api/hackbot/targets/example/delete-preview").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/target-tombstones").status_code, 200)
        self.assertEqual(self.client.post("/api/hackbot/targets/example/clean-runtime", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/targets/example/clean-runtime", json={},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)
        for path in ("targets", "targets/example/accounts"):
            self.assertEqual(self.client.post("/api/hackbot/" + path, json={}).status_code, 403)
        self.assertEqual(self.client.get("/api/hackbot/targets/setup-options").status_code, 200)
        response = self.client.post("/api/hackbot/targets", json={"confirmed": True},
                                    headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.server.requests[-1][0].startswith("POST /v1/targets "))
        response = self.client.post("/api/hackbot/targets/example/accounts",
                                    json={"accounts": []},
                                    headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.server.requests[-1][0].startswith(
            "POST /v1/targets/example/accounts "))
        for path in ("targets/../escape/accounts", "targets//accounts"):
            self.assertEqual(self.client.post("/api/hackbot/" + path, json={},
                headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)

    def test_campaign_routes_are_authenticated_csrf_protected_and_allowlisted(self):
        campaign = "CMP-" + "a" * 32
        self.logged_in = False
        self.assertEqual(self.client.get("/hackbot/campaigns").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/campaigns").status_code, 401)
        self.assertEqual(self.client.post("/api/hackbot/campaigns", json={}).status_code, 401)
        self.logged_in = True
        page = self.client.get("/hackbot/campaigns?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="campaignsView"', page.data)
        self.assertIn(b'id="campaignRows"', page.data)
        self.assertIn(b'id="campaignCoverage"', page.data)
        self.assertIn(b'id="campaignOutcome"', page.data)
        self.assertIn(b'id="campaignTasks"', page.data)
        self.assertIn(b'id="campaignShowArchived"', page.data)
        self.assertEqual(self.client.get("/api/hackbot/campaigns?target=example").status_code,
                         200)
        self.assertEqual(self.client.get(f"/api/hackbot/campaigns/{campaign}").status_code,
                         200)
        self.assertEqual(self.client.post("/api/hackbot/campaigns",
                                          json={"target": "example"}).status_code, 403)
        self.assertEqual(self.client.post(f"/api/hackbot/campaigns/{campaign}/cancel",
                                          json={}).status_code, 403)
        self.assertEqual(self.client.post(f"/api/hackbot/campaigns/{campaign}/archive",
                                          json={}).status_code, 403)
        self.assertEqual(self.client.post(f"/api/hackbot/campaigns/{campaign}/archive",
                                          json={}, headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)
        payload = {"target": "example", "mode": "ANALYZE_ONLY", "preset": "SMALL"}
        sent = self.client.post("/api/hackbot/campaigns", json=payload,
                                headers={"X-CSRF-Token": "test-csrf",
                                         "Authorization": "Bearer fixture-only"})
        self.assertEqual(sent.status_code, 200)
        self.assertEqual(json.loads(self.server.requests[-1][2]), payload)
        self.assertNotIn("authorization", self.server.requests[-1][1])
        for path in ("campaigns/delete-all", f"campaigns/{campaign}/tasks",
                     "campaigns/CMP-invalid/pause"):
            self.assertEqual(self.client.post("/api/hackbot/" + path, json={},
                                              headers={"X-CSRF-Token": "test-csrf"}).status_code,
                             400)

    def test_delta_routes_share_auth_csrf_and_bounded_gateway(self):
        delta = "DELTA-" + "a" * 32
        self.logged_in = False
        self.assertEqual(self.client.get("/hackbot/deltas").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/continuous/status").status_code, 401)
        self.assertEqual(self.client.post("/api/hackbot/continuous/targets/example/check",
                                          json={}).status_code, 401)
        self.logged_in = True
        self.assertEqual(self.client.get("/hackbot/deltas?target=example").status_code, 200)
        for path in ("continuous/status", "continuous/targets/example",
                     "deltas?target=example&limit=20",
                     f"deltas/{delta}?target=example"):
            self.assertEqual(self.client.get("/api/hackbot/" + path).status_code, 200)
        for path in ("continuous/targets/example/settings",
                     "continuous/targets/example/check",
                     f"deltas/{delta}/campaigns"):
            self.assertEqual(self.client.post("/api/hackbot/" + path,
                                              json={}).status_code, 403)
            self.assertEqual(self.client.post("/api/hackbot/" + path,
                                              json={"target": "example"},
                                              headers={"X-CSRF-Token": "test-csrf"}).status_code,
                             200)
        self.assertNotIn("authorization", self.server.requests[-1][1])
        self.assertNotIn("x-csrf-token", self.server.requests[-1][1])
        for path in ("continuous/targets/example/delete", "continuous/restart",
                     "deltas/delete-all", "deltas/DELTA-invalid/campaigns"):
            self.assertEqual(self.client.post("/api/hackbot/" + path, json={},
                                              headers={"X-CSRF-Token": "test-csrf"}).status_code,
                             400)

    def test_reports_and_notifications_are_scoped_authenticated_and_csrf_protected(self):
        report = "REPORT-" + "a" * 32
        finding = "FINDING-" + "b" * 32
        page = self.client.get("/hackbot/reports?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="reportsView"', page.data)
        for path in ("reports?target=example", f"reports/{report}?target=example",
                     f"reports/{report}/download?target=example",
                     "notifications/status?target=example", "notifications?target=example",
                     f"findings/{finding}?target=example"):
            response = self.client.get("/api/hackbot/" + path)
            self.assertEqual(response.status_code, 200, path)
        download = self.client.get(f"/api/hackbot/reports/{report}/download?target=example")
        self.assertEqual(download.mimetype, "text/plain")
        self.assertEqual(download.data, b"# Synthetic report\nNo secrets.\n")
        self.assertIn(report + ".md", download.headers["Content-Disposition"])
        self.assertEqual(download.headers["X-Content-Type-Options"], "nosniff")
        for path in ("reports/REPORT-invalid/download", "reports/" + report + "/submit",
                     "notifications/delete", "notifications/TEST" ):
            self.assertEqual(self.client.get("/api/hackbot/" + path).status_code, 400)
        for path in (f"findings/{finding}/report", f"findings/{finding}/workflow",
                     f"reports/{report}/edit", "notifications/test"):
            self.assertEqual(self.client.post("/api/hackbot/" + path,
                                              json={"target": "example"}).status_code, 403)
        edit = self.client.post(f"/api/hackbot/reports/{report}/edit",
                                json={"target": "example", "content": "a" * 20000},
                                headers={"X-CSRF-Token": "test-csrf",
                                         "Authorization": "Bearer secret",
                                         "Cookie": "session=secret"})
        self.assertEqual(edit.status_code, 200)
        _, headers, body = self.server.requests[-1]
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertEqual(len(json.loads(body)["content"]), 20000)

    def test_target_controlled_report_text_does_not_execute_in_dashboard(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright is unavailable")
        server = make_server("127.0.0.1", 0, self.app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        report = "REPORT-" + "a" * 32
        finding = "FINDING-" + "b" * 32
        hostile = '<img src=x onerror="document.documentElement.dataset.compromised=1">'

        def mock_api(route):
            path = route.request.url.split("/api/hackbot/", 1)[-1].split("?", 1)[0]
            if path == "health":
                data = {"status": "ok"}
            elif path == "targets":
                data = {"items": [{"id": "example", "name": "Example",
                    "primary_domain": "example.test", "status": "TRACKED",
                    "scope_summary": {"included_hosts": 1, "excluded_hosts": 0},
                    "counts": {"identities": 0, "browser_sessions": 0, "traffic": 0}}],
                    "next_cursor": None}
            elif path == "reports/" + report:
                data = {"report": {"id": report, "finding_id": finding,
                    "version": 1, "readiness": "READY", "provenance": "DETERMINISTIC",
                    "severity_status": "UNASSESSED", "quality_codes": [],
                    "created_at": "2026-01-01T00:00:00Z", "previous_report_id": None},
                    "markdown": "# Synthetic report\n" + hostile}
            elif path == "notifications/status":
                data = {"discord_configured": False, "smtp_configured": False,
                        "configured_providers": [], "delivery": {"sent": 0, "failed": 0}}
            elif path == "notifications":
                data = {"items": [], "next_cursor": None}
            else:
                route.fulfill(status=404, json={"error": "unexpected_fixture_request"})
                return
            route.fulfill(status=200, json=data)

        with sync_playwright() as playwright:
            browser_path = Path.home() / ".cache/ms-playwright/chromium-1228/chrome-linux64/chrome"
            browser = playwright.chromium.launch(headless=True,
                **({"executable_path": str(browser_path)} if browser_path.exists() else {}))
            try:
                page = browser.new_page()
                page.route("**/api/hackbot/**", mock_api)
                page.goto(f"http://127.0.0.1:{server.server_port}/hackbot/reports"
                          f"?target=example&id={report}", wait_until="networkidle")
                self.assertIn(hostile, page.locator("#reportMarkdown").inner_text())
                self.assertEqual(page.locator("#reportMarkdown img").count(), 0)
                self.assertIsNone(page.evaluate("document.documentElement.dataset.compromised"))
            finally:
                browser.close()

    def test_research_page_allowlist_and_no_credential_forwarding(self):
        page = self.client.get("/hackbot/research?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="researchView"', page.data)
        self.assertIn(b'data-target-tab="research"', page.data)
        base = "/api/hackbot/research/example"
        for route in ("/gaps", "/requests", "/metrics", "/requests/RREQ-" + "a" * 32,
                      "/briefs/RBRF-" + "b" * 32):
            self.assertEqual(self.client.get(base + route).status_code, 200)
        for route in ("/fetch", "/search", "/briefs/RBRF-invalid", "/requests/RREQ-invalid"):
            self.assertEqual(self.client.get(base + route).status_code, 400)
        response = self.client.post(base + "/requests", json={"gap_ref": "hypothesis:HYP-" + "a" * 32},
                                    headers={"X-CSRF-Token": "test-csrf", "Authorization": "Bearer secret",
                                             "Cookie": "session=secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/research/example/requests", line)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertEqual(json.loads(body)["gap_ref"], "hypothesis:HYP-" + "a" * 32)
        self.assertEqual(self.client.post(base + "/requests/RREQ-" + "a" * 32 + "/cancel", json={},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)
        self.assertEqual(self.client.post(base + "/briefs/RBRF-" + "a" * 32 + "/refresh", json={},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)

    def test_planner_page_routes_auth_csrf_and_no_credential_forwarding(self):
        base = "/api/hackbot/planner/example/runs"
        run = "PLRUN-" + "a" * 32
        candidate = "PLCAND-" + "b" * 32
        self.logged_in = False
        self.assertEqual(self.client.get("/hackbot/planner").status_code, 401)
        self.assertEqual(self.client.get(base).status_code, 401)
        self.assertEqual(self.client.post(base, json={}).status_code, 401)
        self.logged_in = True
        page = self.client.get("/hackbot/planner?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="plannerView"', page.data)
        for path in (base, base + "/" + run, base + "/" + run + "/candidates",
                     base + "/" + run + "/tasks",
                     base + "/" + run + "/candidates/" + candidate + "/relationships"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        for path in (base + "/all", base + "/" + run + "/execute-raw",
                     base + "/" + run + "/candidates/PLCAND-invalid/relationships"):
            self.assertEqual(self.client.get(path).status_code, 400, path)
        post_paths = (base, base + "/" + run + "/advance", base + "/" + run + "/pause",
                      base + "/" + run + "/resume", base + "/" + run + "/cancel",
                      base + "/" + run + "/candidates/" + candidate + "/override")
        for path in post_paths:
            self.assertEqual(self.client.post(path, json={}).status_code, 403, path)
        response = self.client.post(base, json={"mode": "ANALYZE_ONLY"},
                                    headers={"X-CSRF-Token": "test-csrf",
                                             "Authorization": "Bearer private-token",
                                             "Cookie": "session=private-token"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/planner/example/runs", line)
        self.assertEqual(json.loads(body), {"mode": "ANALYZE_ONLY"})
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertNotIn(b"private-token", body)

    def test_bootstrap_target_tab_and_proxy(self):
        page = self.client.get("/hackbot/targets?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'data-target-tab="bootstrap"', page.data)
        self.assertEqual(self.client.get("/api/hackbot/targets/example/bootstrap").status_code, 200)
        self.assertIn("GET /v1/targets/example/bootstrap", self.server.requests[-1][0])
        response = self.client.post("/api/hackbot/targets/example/bootstrap",
                                    json={"identity_policy": "anonymous_only"},
                                    headers={"X-CSRF-Token": "test-csrf", "Authorization": "Bearer live-secret",
                                             "Cookie": "session=live-secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/targets/example/bootstrap", line)
        self.assertEqual(json.loads(body), {"identity_policy": "anonymous_only"})
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        run_path = "/api/hackbot/targets/example/bootstrap/BOOT-" + "a" * 32
        self.assertEqual(self.client.get(run_path).status_code, 200)
        self.assertIn("GET /v1/targets/example/bootstrap/BOOT-", self.server.requests[-1][0])
        self.assertEqual(self.client.post(run_path + "/cancel", json={},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 200)

    def test_behaviour_panel_and_private_proxy(self):
        page = self.client.get("/hackbot/behaviour?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="behaviourView"', page.data)
        self.assertIn(b'data-target-tab="behaviour"', page.data)
        base = "/api/hackbot/targets/example/behaviour"
        for suffix in ("", "/coverage", "/features", "/workflows", "/matrix", "/gaps",
                       "/runs/LEARN-" + "a" * 32):
            self.assertEqual(self.client.get(base + suffix).status_code, 200)
        for suffix in ("/raw", "/runs/LEARN-invalid", "/runs/LEARN-" + "a" * 32 + "/delete"):
            self.assertEqual(self.client.get(base + suffix).status_code, 400)
        for suffix in ("", "/refresh", "/expectations", "/runs/LEARN-" + "a" * 32 + "/cancel"):
            self.assertEqual(self.client.post(base + suffix, json={}).status_code, 403)
        response = self.client.post(base, json={"limits": {"max_traffic_records": 25}},
                                    headers={"X-CSRF-Token": "test-csrf",
                                             "Authorization": "Bearer secret", "Cookie": "session=secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/targets/example/behaviour", line)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertEqual(json.loads(body), {"limits": {"max_traffic_records": 25}})
        self.logged_in = False
        self.assertEqual(self.client.get(base).status_code, 401)
        self.assertEqual(self.client.get("/hackbot/behaviour").status_code, 401)

    def test_exposure_page_and_proxy_do_not_forward_credentials(self):
        page = self.client.get("/hackbot/exposure?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'data-section="exposure"', page.data)
        self.assertIn(b'id="exposureCandidateRows"', page.data)
        self.assertNotIn(b'show secret', page.data.lower())
        self.assertEqual(self.client.get("/api/hackbot/exposure/example/metrics").status_code, 200)
        self.assertIn("GET /v1/exposure/example/metrics", self.server.requests[-1][0])
        self.assertEqual(self.client.get("/api/hackbot/exposure/example/artifacts").status_code, 200)
        self.assertIn("GET /v1/exposure/example/artifacts", self.server.requests[-1][0])
        self.assertEqual(self.client.get("/api/hackbot/exposure/example/captures").status_code, 200)
        self.assertIn("GET /v1/exposure/example/captures", self.server.requests[-1][0])
        self.assertEqual(self.client.get("/api/hackbot/exposure/example/field-exchanges").status_code, 200)
        self.assertIn("GET /v1/exposure/example/field-exchanges", self.server.requests[-1][0])
        candidate = "/api/hackbot/exposure/example/candidates/EXP-" + "a" * 32
        self.assertEqual(self.client.get(candidate).status_code, 200)
        for path in ("/api/hackbot/exposure/example/fetch",
                     "/api/hackbot/exposure/example/probe",
                     candidate + "/reveal",
                     "/api/hackbot/exposure/example/candidates/EXP-invalid"):
            self.assertEqual(self.client.get(path).status_code, 400, path)
        self.assertEqual(self.client.get("/api/hackbot/exposure/example/candidates?raw=1").status_code, 400)
        for path, body in (("/api/hackbot/exposure/example/discover", {"source": "recon"}),
                           ("/api/hackbot/exposure/example/analyze", {"kind": "js", "artifact_id": "DOMA-1"}),
                           ("/api/hackbot/exposure/example/analyze-field", {
                               "owner_exchange_id": "EXCHANGE-1", "member_exchange_id": "EXCHANGE-2"}),
                           (candidate + "/prepare", {}),
                           (candidate + "/bind-read", {"test_object_id": "TESTOBJ-1",
                                                       "owner_session_id": "BSESSION-1"}),
                           (candidate + "/bind-field", {"test_object_id": "TESTOBJ-1",
                                                        "owner_session_id": "BSESSION-1",
                                                        "member_session_id": "BSESSION-2"})):
            self.assertEqual(self.client.post(path, json=body).status_code, 403, path)
        response = self.client.post("/api/hackbot/exposure/example/discover",
                                    json={"source": "traffic"},
                                    headers={"X-CSRF-Token": "test-csrf",
                                             "Authorization": "Bearer live-secret",
                                             "Cookie": "session=live-secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/exposure/example/discover", line)
        self.assertEqual(json.loads(body), {"source": "traffic"})
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertNotIn(b"live-secret", body)

    def test_domxss_page_and_proxy_share_auth_and_csrf_boundary(self):
        page = self.client.get("/hackbot/domxss?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'data-section="domxss"', page.data)
        self.assertIn(b'id="domCandidateRows"', page.data)
        self.assertIn(b'"csrf": "test-csrf"', page.data)
        self.assertNotIn(b"protected-response-body", page.data)
        self.assertEqual(self.client.get("/api/hackbot/domxss/example/metrics").status_code, 200)
        self.assertIn("GET /v1/domxss/example/metrics", self.server.requests[-1][0])
        self.assertEqual(self.client.get("/api/hackbot/domxss/example/candidates/DOM-" +
                                         "a" * 32 + "/runtime").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/domxss/example/inventory?raw=1").status_code, 400)
        candidate_path = "/api/hackbot/domxss/example/candidates/DOM-" + "a" * 32
        for path, body in (("/api/hackbot/domxss/example/analyze", {"recon_asset_id": 7}),
                           (candidate_path + "/route", {"exchange_id": "EXCHANGE-test"}),
                           (candidate_path + "/prepare", {}),
                           (candidate_path + "/bind-plan", {"browser_session_id": "BSESSION-test"})):
            self.assertEqual(self.client.post(path, json=body).status_code, 403, path)
        response = self.client.post("/api/hackbot/domxss/example/analyze",
                                    json={"recon_asset_id": 7},
                                    headers={"X-CSRF-Token": "test-csrf", "Authorization": "Bearer live-secret",
                                             "Cookie": "session=live-secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/domxss/example/analyze", line)
        self.assertEqual(json.loads(body), {"recon_asset_id": 7})
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertNotIn(b"live-secret", body)

    def test_typed_mutation_review_views(self):
        runs = self.client.get("/hackbot/runs?target=example")
        self.assertEqual(runs.status_code, 200)
        self.assertIn(b'runMutationSection', runs.data)
        approvals = self.client.get("/hackbot/approvals?target=example")
        self.assertEqual(approvals.status_code, 200)
        self.assertIn(b'mutationApprovalDialog', approvals.data)
        self.assertEqual(self.client.post("/api/hackbot/hypotheses/manual", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/hypotheses/HYP-" + "a" * 32 + "/plan",
                                          json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/hypotheses/HYP-" + "a" * 32 + "/skills/route",
                                          json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/policy/evaluate", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/objects", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/authorization/example/hunts",
                                          json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/hackbot/objects/TESTOBJ-" + "a" * 32 +
                                          "/cleanup", json={}).status_code, 403)
        run_id = "RUN-" + "a" * 32
        plan_id = "PLAN-" + "a" * 32
        step_id = "STEP-" + "a" * 32
        for path in (f"/api/hackbot/plans/{plan_id}/runs", f"/api/hackbot/runs/{run_id}/advance",
                     f"/api/hackbot/runs/{run_id}/pause", f"/api/hackbot/runs/{run_id}/resume",
                     f"/api/hackbot/runs/{run_id}/cancel",
                     f"/api/hackbot/runs/{run_id}/validate",
                     f"/api/hackbot/runs/{run_id}/steps/{step_id}/complete"):
            self.assertEqual(self.client.post(path, json={}).status_code, 403, path)
        self.assertEqual(self.client.post("/api/hackbot/approvals/APPROVAL-" + "a" * 32 + "/approve",
                                          json={}).status_code, 403)
        self.assertEqual(self.server.requests, [])

    def test_postmessage_routes_share_auth_csrf_and_bounded_gateway(self):
        page = self.client.get("/hackbot/postmessage?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'data-section="postmessage"', page.data)
        self.assertIn(b'id="messageCandidateRows"', page.data)
        self.assertEqual(self.client.get("/api/hackbot/postmessage/example/metrics").status_code, 200)
        self.assertIn("GET /v1/postmessage/example/metrics", self.server.requests[-1][0])
        candidate = "/api/hackbot/postmessage/example/candidates/MSG-" + "a" * 32
        self.assertEqual(self.client.get(candidate + "/runtime").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/postmessage/example/inventory?raw=1").status_code,
                         400)
        self.assertEqual(self.client.post("/api/hackbot/postmessage/example/send",
                                          json={"payload": "arbitrary"},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)
        for path, body in (("/api/hackbot/postmessage/example/analyze", {"recon_asset_id": 7}),
                           (candidate + "/route", {"exchange_id": "EXCHANGE-test"}),
                           (candidate + "/prepare", {}),
                           (candidate + "/bind-plan", {"browser_session_id": "BSESSION-test"})):
            self.assertEqual(self.client.post(path, json=body).status_code, 403, path)
        response = self.client.post("/api/hackbot/postmessage/example/analyze",
                                    json={"recon_asset_id": 7},
                                    headers={"X-CSRF-Token": "test-csrf",
                                             "Authorization": "Bearer live-secret",
                                             "Cookie": "session=live-secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/postmessage/example/analyze", line)
        self.assertEqual(json.loads(body), {"recon_asset_id": 7})
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertNotIn(b"live-secret", body)

    def test_api_routes_share_auth_csrf_and_bounded_gateway(self):
        self.logged_in = False
        self.assertEqual(self.client.get("/hackbot/api?target=example").status_code, 401)
        self.assertEqual(self.client.get("/api/hackbot/api/example/coverage").status_code, 401)
        self.logged_in = True
        page = self.client.get("/hackbot/api?target=example")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="apiView"', page.data)
        self.assertIn(b'id="moreApiOperations"', page.data)
        self.assertIn(b'id="moreApiCandidates"', page.data)
        self.assertIn(b'id="moreApiOperationCandidates"', page.data)
        base = "/api/hackbot/api/example"
        operation = base + "/operations/APIO-" + "a" * 32
        candidate = base + "/candidates/APIC-" + "b" * 32
        for path in (base + "/coverage", base + "/operations?state=CURRENT",
                     base + "/candidates", operation, candidate):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertEqual(self.client.get(base + "/operations?state=CURRENT&limit=50&cursor=YQ").status_code, 200)
        self.assertIn("cursor=YQ", self.server.requests[-1][0])
        self.assertEqual(self.client.get(
            base + "/candidates?limit=50&operation_id=APIO-" + "a" * 32 +
            "&cursor=YQ").status_code, 200)
        self.assertIn("operation_id=APIO-" + "a" * 32, self.server.requests[-1][0])
        self.assertEqual(self.client.get(base + "/operations?operation_id=APIO-" +
                                         "a" * 32).status_code, 400)
        self.assertEqual(self.client.get(base + "/candidates?operation_id=invalid").status_code, 400)
        self.assertEqual(self.client.get(base + "/candidates?limit=50&cursor=YQ").status_code, 200)
        self.assertIn("cursor=YQ", self.server.requests[-1][0])
        self.assertEqual(self.client.get(base + "/execute?query=mutation").status_code, 400)
        self.assertEqual(self.client.get(base + "/operations/invalid").status_code, 400)
        self.assertEqual(self.client.post(base + "/query", json={"query": "{ users { id } }"},
                                          headers={"X-CSRF-Token": "test-csrf"}).status_code, 400)
        for path in (base + "/analyze", candidate + "/prepare", candidate + "/start",
                     candidate + "/advance"):
            self.assertEqual(self.client.post(path, json={}).status_code, 403, path)
        response = self.client.post(base + "/analyze", json={"mode": "PLAN_ONLY"},
                                    headers={"X-CSRF-Token": "test-csrf",
                                             "Authorization": "Bearer live-secret",
                                             "Cookie": "session=live-secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/api/example/analyze", line)
        self.assertEqual(json.loads(body), {"mode": "PLAN_ONLY"})
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertNotIn(b"live-secret", body)

    def test_proxy_forwards_no_dashboard_credentials(self):
        response = self.client.post("/api/hackbot/browser/sessions?target=example",
                                    json={"target": "example"},
                                    headers={"X-CSRF-Token": "test-csrf", "Authorization": "Bearer live-secret",
                                             "Cookie": "session=live-secret"})
        self.assertEqual(response.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/browser/sessions?target=example", line)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("x-csrf-token", headers)
        self.assertNotIn(b"live-secret", body)
        self.assertEqual(json.loads(body), {"target": "example"})

    def test_pages_navigation_and_bounded_routes(self):
        for path in ("/hackbot", "/hackbot/targets", "/hackbot/accounts", "/hackbot/sessions",
                     "/hackbot/traffic", "/hackbot/scope", "/hackbot/burp",
                     "/hackbot/hypotheses", "/hackbot/approvals", "/hackbot/skills", "/hackbot/plans",
                     "/hackbot/runs", "/hackbot/validations", "/hackbot/findings",
                     "/hackbot/objects", "/hackbot/authorization", "/hackbot/domxss",
                     "/hackbot/postmessage", "/hackbot/exposure"):
            page = self.client.get(path)
            self.assertEqual(page.status_code, 200, path)
            self.assertIn(b'href="/hackbot/traffic"', page.data)
            self.assertIn(b'href="/hackbot/hypotheses"', page.data)
            self.assertIn(b'href="/hackbot/approvals"', page.data)
            self.assertIn(b'href="/hackbot/skills"', page.data)
            self.assertIn(b'href="/hackbot/validations"', page.data)
            self.assertIn(b'href="/hackbot/findings"', page.data)
            self.assertIn(b'href="/hackbot/objects"', page.data)
            self.assertIn(b'href="/hackbot/authorization"', page.data)
            self.assertIn(b'href="/hackbot/domxss"', page.data)
            self.assertIn(b'href="/hackbot/postmessage"', page.data)
            self.assertIn(b'href="/hackbot/exposure"', page.data)
            if path == "/hackbot/authorization":
                self.assertIn(b'id="authorizationEvidenceDialog"', page.data)
        self.assertEqual(self.client.get("/api/hackbot/../../etc/passwd").status_code, 400)
        self.assertEqual(self.client.get("/api/hackbot/targets?unexpected=1").status_code, 400)
        self.assertEqual(self.client.get("/api/hackbot/objects?target=example&type=project&cleanup=pending").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/authorization/example/profile").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/evidence/EVIDENCE-test?target=example").status_code, 200)
        self.assertIn("GET /v1/evidence/EVIDENCE-test?target=example", self.server.requests[-1][0])
        self.assertEqual(self.client.get("/api/hackbot/authorization/example/candidates?hunt_id=AUTHH-test").status_code, 200)
        created_hunt = self.client.post("/api/hackbot/authorization/example/hunts",
                                        json={"mode": "PLAN_ONLY", "candidate_limit": 2},
                                        headers={"X-CSRF-Token": "test-csrf", "Cookie": "session=secret"})
        self.assertEqual(created_hunt.status_code, 200)
        self.assertIn("POST /v1/authorization/example/hunts", self.server.requests[-1][0])
        self.assertNotIn("cookie", self.server.requests[-1][1])
        result = self.client.post("/api/hackbot/objects/TESTOBJ-" + "a" * 32 + "/cleanup",
                                  json={"target": "example", "session_id": "BSESSION-" + "b" * 32},
                                  headers={"X-CSRF-Token": "test-csrf", "Cookie": "session=secret"})
        self.assertEqual(result.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/objects/TESTOBJ-", line)
        self.assertNotIn("cookie", headers)
        self.assertEqual(json.loads(body)["target"], "example")
        response = self.client.post("/api/hackbot/targets/example/profile", json={},
                                    headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("POST /v1/targets/example/profile", self.server.requests[-1][0])
        self.assertEqual(self.client.get("/api/hackbot/hypotheses?category=EXPOSURE").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/approvals?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/skills").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/skills/example-skill").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/plans/PLAN-" + "a" * 32 + "?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/plans/PLAN-" + "a" * 32 + "/runs?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/runs?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/runs/RUN-" + "a" * 32 + "?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/validations?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/findings?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/validations/VALIDATION-" + "a" * 32 +
                                         "?target=example").status_code, 200)
        self.assertEqual(self.client.get("/api/hackbot/findings/FINDING-" + "a" * 32 +
                                         "?target=example").status_code, 200)
        advanced = self.client.post("/api/hackbot/runs/RUN-" + "a" * 32 + "/advance",
                                    json={"target": "example"},
                                    headers={"X-CSRF-Token": "test-csrf", "Cookie": "session=secret"})
        self.assertEqual(advanced.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/runs/RUN-", line)
        self.assertNotIn("cookie", headers)
        self.assertEqual(json.loads(body), {"target": "example"})
        validated = self.client.post("/api/hackbot/runs/RUN-" + "a" * 32 + "/validate",
                                     json={"target": "example"},
                                     headers={"X-CSRF-Token": "test-csrf", "Cookie": "session=secret"})
        self.assertEqual(validated.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("/validate", line)
        self.assertNotIn("cookie", headers)
        self.assertEqual(json.loads(body), {"target": "example"})
        planned = self.client.post("/api/hackbot/hypotheses/HYP-" + "a" * 32 + "/plan",
                                   json={"target": "example", "skill_id": "example-skill", "selection": "MANUAL"},
                                   headers={"X-CSRF-Token": "test-csrf", "Cookie": "session=secret"})
        self.assertEqual(planned.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/hypotheses/HYP-", line)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("secret", body.decode())
        self.assertEqual(self.client.get("/api/hackbot/targets/example/policy").status_code, 200)
        checked = self.client.post("/api/hackbot/policy/evaluate",
                                   json={"target": "example", "category": "SAFE_READ"},
                                   headers={"X-CSRF-Token": "test-csrf", "Cookie": "session=secret"})
        self.assertEqual(checked.status_code, 200)
        line, headers, body = self.server.requests[-1]
        self.assertIn("POST /v1/policy/evaluate", line)
        self.assertNotIn("cookie", headers)
        self.assertEqual(json.loads(body)["category"], "SAFE_READ")


if __name__ == "__main__":
    unittest.main()
