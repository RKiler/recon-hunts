import unittest

from domain_management import (
    DomainValidationError,
    domain_options_from_payload,
    normalize_domain,
    parse_domain_values,
)


class DomainManagementTests(unittest.TestCase):
    def test_normalizes_url_wildcard_and_case(self) -> None:
        self.assertEqual(normalize_domain("*.Example.COM."), "example.com")
        self.assertEqual(normalize_domain("https://WWW.Example.com/path?q=1"), "www.example.com")

    def test_rejects_ips_ports_and_single_labels(self) -> None:
        for value in ("127.0.0.1", "example.com:8443", "localhost"):
            with self.subTest(value=value), self.assertRaises(DomainValidationError):
                normalize_domain(value)

    def test_batch_parser_deduplicates_preserving_order(self) -> None:
        self.assertEqual(
            parse_domain_values("example.com, *.example.org\nEXAMPLE.com"),
            ["example.com", "example.org"],
        )

    def test_standard_preset_matches_normal_recon_defaults(self) -> None:
        options = domain_options_from_payload({"preset": "standard"})
        self.assertEqual(options["scan_interval_hours"], 48)
        self.assertTrue(options["enable_katana"])
        self.assertTrue(options["enable_hakrawler"])
        self.assertTrue(options["enable_js_analysis"])
        self.assertTrue(options["enable_screenshots"])
        self.assertFalse(options["enable_ffuf"])
        self.assertFalse(options["enable_nuclei"])

    def test_option_overrides_are_typed_and_bounded(self) -> None:
        options = domain_options_from_payload(
            {"preset": "light", "options": {"enable_ffuf": "true", "max_live_hosts": "250"}}
        )
        self.assertTrue(options["enable_ffuf"])
        self.assertTrue(options["enable_screenshots"])
        self.assertEqual(options["max_live_hosts"], 250)
        with self.assertRaises(DomainValidationError):
            domain_options_from_payload({"options": {"scan_interval_hours": 0}})


if __name__ == "__main__":
    unittest.main()
