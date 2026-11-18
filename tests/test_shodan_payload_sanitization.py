import unittest

from continuous_recon import ContinuousReconFramework


def assert_no_nuls(testcase: unittest.TestCase, value: object) -> None:
    if isinstance(value, str):
        testcase.assertNotIn("\x00", value)
    elif isinstance(value, dict):
        for key, item in value.items():
            testcase.assertNotIn("\x00", str(key))
            assert_no_nuls(testcase, item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            assert_no_nuls(testcase, item)


class ShodanPayloadSanitizationTests(unittest.TestCase):
    def test_host_payload_strips_nuls_from_direct_and_nested_values(self) -> None:
        parsed = ContinuousReconFramework.parse_shodan_host_payload(
            {
                "ip_str": "192.0.2.1\x00",
                "org": "Example\x00 Org",
                "isp": "Example\x00 ISP",
                "hostnames": ["www.exa\x00mple.com"],
                "tags": ["edge\x00service"],
                "vulns": {"CVE-2026-0001\x00": {}},
                "ports": [443],
                "data": [
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "Proxy\x00 Product",
                        "version": "1.2\x003",
                        "info": "extra\x00info",
                        "data": "banner\x00body",
                        "_shodan": {"module": "https\x00"},
                        "ssl": {"cert": {"subject": {"CN": "example\x00.com"}}},
                    }
                ],
            }
        )

        assert_no_nuls(self, parsed)
        self.assertEqual(parsed["org"], "Example Org")
        self.assertEqual(parsed["services"][0]["banner"], "bannerbody")
        self.assertEqual(parsed["services"][0]["product"], "Proxy Product")

    def test_domain_payload_strips_nuls_before_validation_and_storage(self) -> None:
        names, records = ContinuousReconFramework.parse_shodan_domain_payload(
            "example.com",
            {
                "subdomains": ["ap\x00i"],
                "data": [
                    {
                        "subdomain": "ww\x00w",
                        "type": "TXT",
                        "value": "verification=abc\x00123",
                        "last_seen": "2026-09-01T00:00:00Z\x00",
                    }
                ],
            },
        )

        self.assertEqual(names, {"api.example.com", "www.example.com"})
        self.assertEqual(records[0]["value"], "verification=abc123")
        assert_no_nuls(self, records)


if __name__ == "__main__":
    unittest.main()
