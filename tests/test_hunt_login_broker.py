import unittest

from scripts.hunt_login_broker import host_in_scope, login_context_options, login_left_page


class HuntLoginBrokerTests(unittest.TestCase):
    def test_exact_host_and_subdomain_boundary(self):
        self.assertTrue(host_in_scope("app.example.com", "example.com"))
        self.assertFalse(host_in_scope("example.com.evil.test", "example.com"))
        self.assertFalse(host_in_scope("other.example.com", "app.example.com"))

    def test_only_known_zapier_route_auto_completes(self):
        self.assertTrue(login_left_page("https://zapier.com/app/dashboard", "zapier.com"))
        self.assertFalse(login_left_page("https://zapier.com/app/login", "zapier.com"))
        self.assertFalse(login_left_page("https://example.com/dashboard", "example.com"))
        self.assertFalse(login_left_page("https://zapier.com.evil.test/app/dashboard", "zapier.com"))

    def test_betfair_login_uses_isolated_vpn_proxy(self):
        self.assertEqual(login_context_options("betfair.com"), {"proxy": {"server": "http://127.0.0.1:8888"}})
        self.assertEqual(login_context_options("zapier.com"), {})


if __name__ == "__main__":
    unittest.main()
