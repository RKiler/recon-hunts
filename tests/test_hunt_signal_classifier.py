import unittest

from hunt_signal_classifier import classify_route, route_hint


class HuntSignalClassifierTests(unittest.TestCase):
    def classes(self, path, params=(), method="GET"):
        return {item[0] for item in classify_route(path, params, method)}

    def test_server_fetch_and_file_read_need_matching_workflows(self):
        self.assertIn("ssrf", self.classes("/api/image/preview", ["image_url"]))
        self.assertIn("lfi_path_traversal", self.classes("/api/reports/download", ["file_path"]))
        self.assertNotIn("ssrf", self.classes("/api/projects", ["project_id"]))

    def test_identity_template_and_execution_candidates(self):
        self.assertIn("oauth_sso", self.classes("/oauth/callback", ["redirect_uri", "state"]))
        self.assertIn("account_takeover", self.classes("/account/reset", ["token"]))
        self.assertIn("ssti", self.classes("/templates/render", ["template"]))
        self.assertIn("rce_command_injection", self.classes("/api/build/execute", ["command"]))

    def test_rendering_query_and_authz_candidates(self):
        self.assertIn("xss", self.classes("/comments/preview", ["markdown"]))
        self.assertIn("injection", self.classes("/api/search", ["filter"]))
        self.assertIn("authorization", self.classes("/api/members", ["tenant_id"], "PATCH"))
        self.assertIn("open_redirect", self.classes("/login", ["next"]))

    def test_route_hints_drop_values_and_external_urls(self):
        self.assertEqual(route_hint("/api/files/abcdefghijklmnopqrstuvwxyz0123456789?token=private"),
                         "/api/files/{id}")
        self.assertIsNone(route_hint("https://third-party.test/api"))
        self.assertIsNone(route_hint("//third-party.test/api"))
        self.assertIsNone(route_hint("/path\nheader: value"))
        self.assertEqual(self.classes("/plain/path", []), set())


if __name__ == "__main__":
    unittest.main()
