import unittest

from continuous_recon import ContinuousReconFramework


class AuthProfileTests(unittest.TestCase):
    def setUp(self):
        self.framework = ContinuousReconFramework.__new__(ContinuousReconFramework)

    def test_combines_cookie_and_custom_header_for_matching_host(self):
        domain = {
            "domain": "finn.no",
            "_auth_profiles": [
                {
                    "profile_type": "cookie",
                    "host_pattern": "*.finn.no",
                    "secret_ref": "Cookie: session=test",
                    "metadata": {},
                },
                {
                    "profile_type": "header",
                    "host_pattern": "*.finn.no",
                    "header_name": "X-Csrf-Token",
                    "secret_ref": "csrf-test",
                    "metadata": {},
                },
            ],
        }

        headers = self.framework.auth_profile_headers(domain, "https://www.finn.no/account")

        self.assertEqual(headers["Cookie"], "session=test")
        self.assertEqual(headers["X-Csrf-Token"], "csrf-test")

    def test_does_not_attach_auth_to_unrelated_host(self):
        domain = {
            "domain": "finn.no",
            "_auth_profiles": [
                {
                    "profile_type": "cookie",
                    "host_pattern": "*.finn.no",
                    "secret_ref": "Cookie: session=test",
                    "metadata": {},
                }
            ],
        }

        self.assertEqual(
            self.framework.auth_profile_headers(domain, "https://example.com/"),
            {},
        )


if __name__ == "__main__":
    unittest.main()
