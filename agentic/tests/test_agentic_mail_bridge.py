import unittest
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from unittest.mock import patch

from scripts import agentic_mail_bridge as bridge


class MailBridgeTests(unittest.TestCase):
    def test_exact_https_host_only(self):
        good = "https://accounts.example.com/verify?code=private"
        self.assertTrue(bridge.matching_link(good, "accounts.example.com"))
        for candidate in (
            "http://accounts.example.com/verify",
            "https://accounts.example.com.evil.test/verify",
            "https://attacker@accounts.example.com/verify",
            "https://accounts.example.com:8443/verify",
            "https://other.example.com/verify",
            "https://accounts.example.com/logout?email=1",
            "https://accounts.example.com/reset-password?confirm=1",
            "https://accounts.example.com/privacy",
        ):
            self.assertFalse(bridge.matching_link(candidate, "accounts.example.com"))

    def test_html_and_plain_links_are_filtered(self):
        message = EmailMessage()
        message.set_content("Verify: https://accounts.example.com/verify?code=one")
        message.add_alternative(
            '<a href="https://accounts.example.com/verify?code=two">Verify</a>'
            '<a href="https://evil.test/verify">Ignore</a>', subtype="html"
        )
        links = bridge.extract_links(message, "accounts.example.com")
        self.assertEqual(len(links), 2)
        self.assertTrue(all("evil.test" not in link for link in links))

    def test_find_requires_recent_timestamp(self):
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        with self.assertRaises(ValueError):
            bridge.find_messages("accounts.example.com", old)

    def test_open_requires_owned_signup_confirmation(self):
        with self.assertRaises(ValueError):
            bridge.handle({"action": "open", "host": "accounts.example.com", "handle": "opaque"})

    def test_find_does_not_expose_raw_link(self):
        with patch.object(bridge, "find_messages", return_value=[{"handle": "opaque", "host": "accounts.example.com"}]):
            result = bridge.handle({"action": "find", "host": "accounts.example.com",
                                    "after": datetime.now(timezone.utc).isoformat()})
        self.assertEqual(result["matches"], [{"handle": "opaque", "host": "accounts.example.com"}])


if __name__ == "__main__":
    unittest.main()
