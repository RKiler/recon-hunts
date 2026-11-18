"""Local dashboard-to-service Hunt intake; no target or recon traffic."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest
from unittest.mock import patch

from flask import Flask, abort, request
from werkzeug.serving import make_server

from hackbot.browser import IdentityObservation
from hackbot.config import (BrowserSettings, BurpSettings, ResourceSettings,
                            TargetSettings, load_config)
from hackbot.service import BugHunterRuntime, create_app
from hackbot.store import EvidenceFactStore
from hackbot_gateway import install_hackbot_routes


class _FixtureDriver:
    name = "FAKE"

    def __init__(self) -> None:
        self.running: set[str] = set()

    def start(self, session_id: str, _profile, *, display, proxy) -> None:
        self.running.add(session_id)

    def stop(self, session_id: str) -> None:
        self.running.discard(session_id)

    def is_running(self, _session_id: str) -> bool:
        return _session_id in self.running

    def observe_identity(self, _session_id: str, _rule) -> IdentityObservation:
        return IdentityObservation()


class HuntOperatorGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        base = load_config(environ={"HOME": str(root), "XDG_CONFIG_HOME": str(root),
                                    "XDG_STATE_HOME": str(root)})
        config = replace(base, targets=TargetSettings(root / "targets"),
                         browser=BrowserSettings(profile_root=root / "profiles",
                                                 display=":901",
                                                 vnc_url="http://127.0.0.1:6901/vnc.html"),
                         burp=BurpSettings(True, root / "burp"),
                         resources=ResourceSettings(min_available_memory_bytes=0))
        EvidenceFactStore.from_config(config).initialize()
        self.runtime = BugHunterRuntime(config, driver=_FixtureDriver(),
                                        vnc_ready=lambda: True)
        socket_path = root / "control.sock"
        self.service = make_server("unix://" + str(socket_path), 0,
                                   create_app(runtime=self.runtime), threaded=True)
        service_thread = Thread(target=self.service.serve_forever, daemon=True)
        service_thread.start()
        self.addCleanup(service_thread.join, 3)
        self.addCleanup(self.service.server_close)
        self.addCleanup(self.service.shutdown)

        dashboard = Flask(__name__)
        self.logged_in = True

        def csrf() -> None:
            if request.headers.get("X-CSRF-Token") != "fixture-csrf":
                abort(403)

        install_hackbot_routes(dashboard, authorized=lambda: self.logged_in,
                               csrf_token=lambda: "fixture-csrf", require_csrf=csrf,
                               auth_enabled=lambda: True, socket_path=str(socket_path),
                               hunt_ui_enabled=True)
        self.client = dashboard.test_client()

    @staticmethod
    def _target_payload() -> dict[str, object]:
        return {
            "name": "Synthetic SaaS", "id": "synthetic-saas",
            "primary_domain": "app.synthetic.test", "confirmed": True,
            "scope": {"include": ["app.synthetic.test", "api.synthetic.test"],
                      "exclude": [], "schemes": ["https"], "ports": [443]},
            "source": {"kind": "RESEARCHER", "reference": "local synthetic fixture",
                       "operator": "test-operator"},
            "rules": {"automated_testing_allowed": True,
                      "account_creation_allowed": False,
                      "forbidden_actions": ["credential_stuffing"]},
            "autonomy": {"passive": "ALLOW", "safe_read": "ALLOW",
                         "bounded_active": "DENY", "state_changing": "DENY",
                         "destructive": "DENY"},
            "rate": {"requests_per_second": 1, "requests_per_minute": 30,
                     "max_concurrency": 1, "burst": 1},
        }

    def _post(self, path: str, payload: dict[str, object]):
        return self.client.post("/api/hackbot/" + path, json=payload,
                                headers={"X-CSRF-Token": "fixture-csrf"})

    def test_target_accounts_and_hunt_use_real_gateway_and_service(self) -> None:
        self.logged_in = False
        self.assertEqual(self._post("targets", self._target_payload()).status_code, 401)
        self.logged_in = True
        self.assertEqual(self.client.post("/api/hackbot/targets",
                                          json=self._target_payload()).status_code, 403)
        with patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")), \
             patch.object(self.runtime, "launch_hunt_preparation") as launch:
            created = self._post("targets", self._target_payload())
            self.assertEqual(created.status_code, 201, created.get_data(as_text=True))
            accounts = self._post("targets/synthetic-saas/accounts", {"accounts": [
                {"alias": "org1_admin", "tenant": "org1", "role": "admin"},
                {"alias": "org1_member", "tenant": "org1", "role": "member"},
                {"alias": "org2_admin", "tenant": "org2", "role": "admin"},
            ]})
            self.assertEqual(accounts.status_code, 200, accounts.get_data(as_text=True))
            self.assertEqual(accounts.get_json()["configured"], 3)
            self.assertTrue(all(item["registration"] == "REGISTERED"
                                for item in accounts.get_json()["items"]))
            started = self._post("targets/synthetic-saas/hunt", {"mode": "SUPERVISED"})
            self.assertEqual(started.status_code, 202, started.get_data(as_text=True))
            run = started.get_json()["hunt"]
            self.assertEqual(run["state"], "PREPARING")
            self.assertEqual(run["mode"], "SUPERVISED")
            launch.assert_called_once_with("synthetic-saas", run["id"])
            status = self.client.get("/api/hackbot/targets/synthetic-saas/hunt")
            self.assertEqual(status.status_code, 200)
            self.assertEqual(status.get_json()["hunt"]["id"], run["id"])
            duplicate = self._post("targets/synthetic-saas/hunt", {})
            self.assertEqual(duplicate.status_code, 409)
            self.assertEqual(duplicate.get_json()["hunt"]["id"], run["id"])
            launch.assert_called_once()
        self.assertTrue((self.runtime.config.targets.root / "synthetic-saas" /
                         "target.yaml").is_file())
        self.assertTrue((self.runtime.config.targets.root / "synthetic-saas" /
                         "accounts.yaml").is_file())

    def test_start_hunt_automatically_prepares_captured_login_sessions(self) -> None:
        self.assertEqual(self._post("targets", self._target_payload()).status_code, 201)
        accounts = self._post("targets/synthetic-saas/accounts", {"accounts": [
            {"alias": "org1_admin", "tenant": "org1", "role": "admin"},
            {"alias": "org1_member", "tenant": "org1", "role": "member"},
            {"alias": "org2_admin", "tenant": "org2", "role": "admin"},
        ]})
        self.assertEqual(accounts.status_code, 200)
        with patch.object(self.runtime, "ensure_burp_bridge"), \
             patch.object(self.runtime.burp, "ready", return_value=True), \
             patch.object(self.runtime.executor, "execute",
                          side_effect=AssertionError("target traffic sent")):
            started = self._post("targets/synthetic-saas/hunt", {})
            self.assertEqual(started.status_code, 202, started.get_data(as_text=True))
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                status = self.client.get("/api/hackbot/targets/synthetic-saas/hunt").get_json()
                if status["hunt"]["state"] != "PREPARING":
                    break
                time.sleep(0.1)
            else:
                self.fail("Hunt did not finish local session preparation")
            self.assertEqual(status["hunt"]["state"], "LOGIN_REQUIRED", status)
            self.assertEqual({item["alias"] for item in status["needs_you"]},
                             {"org1_admin", "org1_member", "org2_admin"})
            self.assertTrue(all(item["kind"] == "LOGIN_REQUIRED"
                                for item in status["needs_you"]))
            for item in status["needs_you"]:
                session = self.client.get(
                    f"/api/hackbot/browser/sessions/{item['session_id']}?target=synthetic-saas")
                self.assertEqual(session.status_code, 200)
                self.assertEqual(session.get_json()["status"], "WAITING_LOGIN")
                self.assertTrue(session.get_json()["proxy_capture_required"])
            owned = next(item for item in status["needs_you"]
                         if item["alias"] == "org1_admin")
            route = (f"browser/sessions/{owned['session_id']}"
                     "?target=synthetic-saas")
            completed = self._post(route.replace("?", "/login-complete?", 1),
                                   {"confirm_alias": "org1_admin"})
            self.assertEqual(completed.status_code, 200, completed.get_data(as_text=True))
            self.assertEqual(completed.get_json()["status"], "VALID")
            self.assertEqual(completed.get_json()["verification_method"],
                             "OPERATOR_CONFIRMED")
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                resumed = self.client.get("/api/hackbot/targets/synthetic-saas/hunt").get_json()
                if resumed["hunt"]["state"] == "LOGIN_REQUIRED":
                    break
                time.sleep(0.1)
            else:
                self.fail("Hunt did not resume after owned identity confirmation")
            self.assertEqual({item["alias"] for item in resumed["needs_you"]},
                             {"org1_member", "org2_admin"})


if __name__ == "__main__":
    unittest.main()
