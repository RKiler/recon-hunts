import os
import unittest
from unittest.mock import patch

from search_intelligence import (
    QUERY_TEMPLATES,
    canonical_url,
    is_in_scope,
    provider_from_config,
)


class SearchIntelligenceTests(unittest.TestCase):
    def test_query_catalog_is_curated_and_bounded(self):
        categories = [category for category, _ in QUERY_TEMPLATES]
        self.assertEqual(len(categories), len(set(categories)))
        self.assertIn("api", categories)
        self.assertIn("auth", categories)
        self.assertIn("documents", categories)
        self.assertLessEqual(len(categories), 20)

    def test_canonical_url_normalizes_host_path_and_query(self):
        self.assertEqual(
            canonical_url("HTTPS://App.Example.COM//api//v1?b=2&a=1"),
            "https://app.example.com/api/v1?a=1&b=2",
        )

    def test_scope_is_subdomain_boundary_aware(self):
        self.assertTrue(is_in_scope("app.example.com", "example.com"))
        self.assertTrue(is_in_scope("example.com", "example.com"))
        self.assertFalse(is_in_scope("example.com.attacker.test", "example.com"))

    def test_provider_auto_selection(self):
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-key"}, clear=True):
            provider = provider_from_config({"provider": "auto"})
        self.assertIsNotNone(provider)
        self.assertEqual(provider.name, "serper")

    def test_google_cse_requires_engine_id(self):
        provider = provider_from_config(
            {"provider": "google_cse", "google_api_key": "key"}
        )
        self.assertIsNone(provider)


if __name__ == "__main__":
    unittest.main()
