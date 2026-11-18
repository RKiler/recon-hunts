import unittest
from collections import Counter

from delta_intelligence_worker import numeric_new_counts, signal_score


class DeltaIntelligenceWorkerTests(unittest.TestCase):
    def test_numeric_new_counts_rejects_noise_and_zeroes(self) -> None:
        self.assertEqual(
            numeric_new_counts(
                {
                    "endpoints": 12,
                    "js_assets": "3",
                    "unchanged": 0,
                    "bad": "not-a-number",
                    "boolean": True,
                }
            ),
            {"endpoints": 12, "js_assets": 3},
        )
        self.assertEqual(
            numeric_new_counts('{"new_urls": 7, "new_ports": 0}'),
            {"new_urls": 7},
        )

    def test_signal_score_rewards_correlated_high_value_delta(self) -> None:
        baseline = signal_score({"subdomains": 1}, Counter(), Counter())
        high_signal = signal_score(
            {"endpoints": 4, "js_assets": 2, "api_surfaces": 1},
            Counter({"new_graphql_surface": 1, "new_admin_route": 1}),
            Counter({"high": 1}),
        )
        self.assertGreater(high_signal, baseline)
        self.assertLessEqual(high_signal, 100)


if __name__ == "__main__":
    unittest.main()
