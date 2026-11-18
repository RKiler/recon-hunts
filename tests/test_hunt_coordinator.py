import unittest
import json
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from hunt_coordinator import candidate_allowed, classify_endpoint, normalize_application_context, root_host_allowed, safe_asset_display, select_candidates
from hunt_credentials import read_login_file, remove_secret, validate_credential, write_secret


def row(job_id, family_type, source_id, asset, host, priority=95):
    return {
        "id": job_id,
        "job_type": family_type,
        "source_table": "endpoints",
        "source_id": source_id,
        "asset_value": asset,
        "source_url": host,
        "source_observed_at": datetime(2026, 10, 4),
        "status": "queued",
        "priority": priority,
    }


class HuntCoordinatorTests(unittest.TestCase):
    def test_scope_requires_real_hostname_boundary(self):
        self.assertTrue(root_host_allowed("https://api.example.com/x", "example.com", True))
        self.assertFalse(root_host_allowed("https://example.com.evil.test/x", "example.com", True))
        self.assertFalse(root_host_allowed("https://api.example.com/x", "example.com", False))
        self.assertFalse(root_host_allowed("https://[broken/x", "example.com", True))

    def test_candidate_scope_checks_source_and_exclusions(self):
        good = row(1, "idor_bac_test", 1, "https://api.example.com/api/projects/1", "https://api.example.com")
        self.assertTrue(candidate_allowed(good, "example.com", True, []))
        self.assertFalse(candidate_allowed(good, "example.com", True, ["api.example.com"]))
        self.assertFalse(candidate_allowed(good, "example.com", True, ["*.example.com"]))
        malicious = dict(good, asset_value="https://evil.test/api/projects/1")
        self.assertFalse(candidate_allowed(malicious, "example.com", True, []))
        foreign_source = dict(good, source_url="https://cdn.evil.test")
        self.assertFalse(candidate_allowed(foreign_source, "example.com", True, []))
        unknown_path = dict(good, source_table="findings", source_url="", asset_value="/admin")
        self.assertFalse(candidate_allowed(unknown_path, "example.com", True, []))

    def test_family_selection_balances_and_deduplicates_source(self):
        rows = [
            row(1, "idor_bac_test", 7, "https://api.example.com/api/users/7", "https://api.example.com"),
            row(2, "xss_reflection_test", 7, "https://api.example.com/api/users/7", "https://api.example.com"),
            row(3, "xss_reflection_test", 8, "https://api.example.com/search", "https://api.example.com"),
            row(4, "auth_session_review", 9, "https://api.example.com/login", "https://api.example.com"),
        ]
        selected = select_candidates(rows, "example.com", True, [], 3)
        self.assertEqual({item["source_id"] for _, item in selected}, {7, 8, 9})
        self.assertEqual({family for family, _ in selected}, {"A01", "A05", "A07"})

    def test_endpoint_signal_requires_concrete_input(self):
        self.assertEqual(classify_endpoint("/api/projects", "GET", ["project_id"], 200, 2)[0][0], "idor_bac_test")
        self.assertEqual(classify_endpoint("/preview", "GET", ["url"], 200, 0)[0][0], "ssrf_candidate_test")
        self.assertEqual(classify_endpoint("/search", "GET", ["q"], 200, 0)[0][0], "xss_reflection_test")
        self.assertEqual(classify_endpoint("/search", "GET", ["q"], 404, 0), [])
        self.assertEqual(classify_endpoint("/api/projects", "GET", ["project_id"], 200, 1), [])
        self.assertEqual(classify_endpoint("/api/projects", "GET", [], 200, 2), [])
        self.assertEqual(classify_endpoint("http://[bad/", "GET", ["project_id"], 200, 2), [])

    def test_selection_spreads_types_within_one_family(self):
        rows = [
            row(1, "js_dom_xss_review", 1, "https://app.example.com/a.js", "https://app.example.com", 99),
            row(2, "js_dom_xss_review", 2, "https://app.example.com/b.js", "https://app.example.com", 98),
            row(3, "xss_reflection_test", 3, "https://app.example.com/search", "https://app.example.com", 95),
        ]
        selected = select_candidates(rows, "example.com", True, [], 2)
        self.assertEqual({item["job_type"] for _, item in selected}, {"js_dom_xss_review", "xss_reflection_test"})

    def test_display_never_returns_query_values(self):
        self.assertEqual(
            safe_asset_display("https://app.example.com/callback?code=secret123&state=other"),
            "https://app.example.com/callback?code=%5Bredacted%5D&state=%5Bredacted%5D",
        )

    def test_application_context_accepts_long_text_and_account_descriptions(self):
        self.assertEqual(normalize_application_context("  Multi-tenant product  "), "Multi-tenant product")
        self.assertEqual(normalize_application_context("x" * 12000), "x" * 12000)
        with self.assertRaises(ValueError):
            normalize_application_context(None)
        self.assertEqual(
            normalize_application_context("Cookie: session=stored-in-owned-account-file"),
            "Cookie: session=stored-in-owned-account-file",
        )

    def test_owned_credential_host_and_file_safety(self):
        fields = validate_credential("example.com", {
            "alias": "owner-a", "host": "app.example.com", "credential_type": "cookie",
            "secret": "session=private-test-value", "role": "Admin", "tenant": "A",
        })
        self.assertEqual(fields["header_name"], "Cookie")
        with self.assertRaises(ValueError):
            validate_credential("example.com", {**fields, "host": "example.com.evil.test"})
        with self.assertRaises(ValueError):
            validate_credential("example.com", {**fields, "secret": "bad\r\nHost: evil.test"})
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            folder.chmod(0o700)
            name = write_secret(fields["secret"], folder)
            path = folder / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(), fields["secret"])
            remove_secret(name, folder)
            self.assertFalse(path.exists())

    def test_email_password_file_import_is_restricted(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            folder.chmod(0o700)
            display_root = Path("/root/codex_artifacts/hunt_credentials/imports")
            source = folder / "owner.json"
            source.write_text(json.dumps({"email": "owner@example.com", "password": "owned-test-password"}))
            source.chmod(0o600)
            payload = {"alias": "owner-a", "host": "app.example.com", "credential_type": "login_file",
                       "credential_path": str(display_root / source.name)}
            fields = validate_credential("example.com", payload, folder, display_root)
            self.assertEqual(fields["header_name"], "")
            self.assertEqual(json.loads(fields["secret"])["email"], "owner@example.com")
            with self.assertRaises(ValueError):
                validate_credential("example.com", {**payload, "host": "outside.test"}, folder, display_root)
            with self.assertRaises(ValueError):
                read_login_file(str(display_root / ".." / source.name), folder, display_root)
            link = folder / "link.json"
            link.symlink_to(source)
            with self.assertRaises(ValueError):
                read_login_file(str(display_root / link.name), folder, display_root)
            source.chmod(0o644)
            self.assertEqual(json.loads(read_login_file(str(display_root / source.name), folder, display_root))["email"], "owner@example.com")
            self.assertEqual(source.stat().st_mode & 0o777, 0o600)
            source.write_text(json.dumps({"Email": "owner@example.com", "Password": "owned-test-password"}))
            self.assertEqual(json.loads(read_login_file(str(display_root / source.name), folder, display_root))["password"], "owned-test-password")
            source.write_bytes(b"x" * 16385)
            with self.assertRaisesRegex(ValueError, "at most 16 KiB"):
                read_login_file(str(display_root / source.name), folder, display_root)
            source.write_text(json.dumps({"email": "owner@example.com", "password": "test", "token": "extra"}))
            with self.assertRaises(ValueError):
                read_login_file(str(display_root / source.name), folder, display_root)

    def test_username_password_file_import_is_supported(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            folder.chmod(0o700)
            display_root = Path("/root/codex_artifacts/hunt_credentials/imports")
            source = folder / "owner.json"
            source.write_text(json.dumps({"Username": "owned-test-user", "Password": "owned-test-password"}))
            source.chmod(0o600)
            normalized = json.loads(read_login_file(str(display_root / source.name), folder, display_root))
            self.assertEqual(normalized, {"username": "owned-test-user", "password": "owned-test-password"})

            source.write_text(json.dumps({
                "email": "owner@example.com", "username": "owner", "password": "owned-test-password",
            }))
            with self.assertRaises(ValueError):
                read_login_file(str(display_root / source.name), folder, display_root)

    def test_inline_owned_login_is_exact_host_and_validated(self):
        payload = {"alias": "owner", "host": "sidekick.example.com", "credential_type": "login_file",
                   "email": "owner@example.com", "password": "owned-test-password"}
        fields = validate_credential("example.com", payload)
        self.assertEqual(fields["host"], "sidekick.example.com")
        self.assertEqual(json.loads(fields["secret"]),
                         {"email": "owner@example.com", "password": "owned-test-password"})
        with self.assertRaises(ValueError):
            validate_credential("example.com", {**payload, "host": "outside.test"})
        with self.assertRaises(ValueError):
            validate_credential("example.com", {**payload, "password": "bad\nvalue"})
        with self.assertRaises(ValueError):
            validate_credential("example.com", {**payload, "credential_path": "also.json"})

        username_payload = {
            "alias": "owner-user", "host": "sidekick.example.com", "credential_type": "login_file",
            "username": "owned-test-user", "password": "owned-test-password",
        }
        username_fields = validate_credential("example.com", username_payload)
        self.assertEqual(json.loads(username_fields["secret"]),
                         {"username": "owned-test-user", "password": "owned-test-password"})

    def test_manual_vnc_login_needs_no_secret(self):
        payload = {"alias": "owner-vnc", "host": "app.example.com", "credential_type": "manual_login"}
        fields = validate_credential("example.com", payload)
        self.assertEqual(fields["secret"], "manual-login")
        self.assertEqual(fields["header_name"], "")
        with self.assertRaises(ValueError):
            validate_credential("example.com", {**payload, "secret": "session=other"})


if __name__ == "__main__":
    unittest.main()
