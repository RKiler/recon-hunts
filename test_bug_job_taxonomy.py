import unittest

from bug_job_taxonomy import (
    adaptive_allocations,
    job_category,
    normalized_allocations,
    preferred_category,
)


class BugJobTaxonomyTests(unittest.TestCase):
    def test_high_value_families_map_consistently(self):
        self.assertEqual(job_category("idor_bac_test"), "authorization_graphql")
        self.assertEqual(job_category("bug-bounty-graphql-api-auth"), "authorization_graphql")
        self.assertEqual(job_category("auth_session_review"), "authentication_lifecycle")
        self.assertEqual(job_category("js_dom_xss_review"), "javascript_client")
        self.assertEqual(job_category("ssrf_candidate_test"), "input_workflow")
        self.assertEqual(job_category("js_secret_review"), "exposure_supply_secrets")

    def test_allocations_are_normalized(self):
        values = normalized_allocations({"authorization_graphql": 4, "authentication_lifecycle": 2})
        self.assertAlmostEqual(sum(values.values()), 1.0)
        self.assertGreater(values["authorization_graphql"], values["authentication_lifecycle"])

    def test_low_yield_family_is_reduced_but_not_disabled(self):
        configured = normalized_allocations()
        adjusted = adaptive_allocations(
            configured,
            {"javascript_client": {"completed": 120, "credible": 0}},
            minimum_sample=100,
        )
        self.assertGreater(adjusted["javascript_client"], 0)
        self.assertLess(adjusted["javascript_client"], configured["javascript_client"])

    def test_preferred_category_tracks_largest_share_deficit(self):
        allocations = normalized_allocations()
        selected = preferred_category(
            allocations,
            {"authorization_graphql": 40, "authentication_lifecycle": 20, "javascript_client": 0},
            60,
        )
        self.assertEqual(selected, "javascript_client")


if __name__ == "__main__":
    unittest.main()
