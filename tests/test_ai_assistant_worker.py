import unittest

from ai_assistant_worker import (
    QUERY_SCHEMA,
    redact,
    redact_url,
    resolve_domain_from_question,
    search_term,
    search_terms,
)


class AiAssistantWorkerTests(unittest.TestCase):
    def test_redacts_sensitive_fields_and_authorization_values(self):
        payload = redact({
            "url": "https://app.example.com/reset?token=complete-value&next=/home",
            "authorization": "Bearer complete-value",
            "notes": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "contact": "person@example.com",
        })
        self.assertEqual(payload["authorization"], "[redacted]")
        self.assertNotIn("complete-value", payload["url"])
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", payload["notes"])
        self.assertNotIn("person@example.com", payload["contact"])

    def test_url_redaction_preserves_route_and_parameter_names(self):
        value = redact_url("https://api.example.com/v1/export?report_id=123&token=secret#fragment")
        self.assertIn("/v1/export", value)
        self.assertIn("report_id=", value)
        self.assertIn("token=", value)
        self.assertNotIn("123", value)
        self.assertNotIn("secret", value)
        self.assertNotIn("fragment", value)

    def test_search_term_prefers_specific_signal(self):
        self.assertEqual(search_term("What GraphQL endpoints are on example.com?"), "example.com")
        self.assertEqual(search_term("show xss leads"), "leads")

    def test_search_terms_remove_domain_question_noise(self):
        terms = search_terms(
            "How many staging subs does amplitude domain have?",
            {"amplitude", "amplitude.com", "com"},
        )
        self.assertEqual(terms, ["staging"])

    def test_resolves_root_domain_named_without_tld(self):
        domains = [{"id": 7, "domain": "amplitude.com"}, {"id": 8, "domain": "example.com"}]
        self.assertEqual(
            resolve_domain_from_question("How many staging subs does amplitude have?", domains)["id"],
            7,
        )

    def test_output_schema_rejects_extra_properties(self):
        self.assertFalse(QUERY_SCHEMA["additionalProperties"])
        self.assertIn("answer", QUERY_SCHEMA["required"])
        self.assertIn("source_refs", QUERY_SCHEMA["required"])


if __name__ == "__main__":
    unittest.main()
