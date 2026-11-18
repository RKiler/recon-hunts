import unittest
from datetime import datetime

from continuous_recon import AppConfig, ContinuousReconFramework, new_scan_summary


class NucleiSchedulerTests(unittest.TestCase):
    def framework(self):
        return ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "max_concurrent_live_hosts": 1,
                        "nuclei_enabled": True,
                        "nuclei_only_on_deep_scan": True,
                        "nuclei_batching_enabled": True,
                        "nuclei_batch_window_hours": 72,
                        "nuclei_batch_count": 3,
                        "nuclei_max_hosts_per_domain": 2,
                        "nuclei_only_on_interesting_hosts": True,
                        "host_priority_keywords": ["api", "admin", "login"],
                    }
                }
            )
        )

    def test_nuclei_batch_status_is_deterministic(self):
        framework = self.framework()
        now = datetime.fromtimestamp(0)

        active = framework.nuclei_batch_status({"id": 3, "domain": "active.example"}, now)
        inactive = framework.nuclei_batch_status({"id": 1, "domain": "inactive.example"}, now)

        self.assertTrue(active["enabled"])
        self.assertEqual(active["domain_batch"], 0)
        self.assertFalse(inactive["enabled"])
        self.assertEqual(inactive["reason"], "inactive_batch")

    def test_fast_scan_without_deep_scan_skips_nuclei(self):
        framework = self.framework()
        summary = new_scan_summary("example.com", first_run=False)
        hosts = [{"live_host_id": 1, "url": "https://api.example.com", "status_code": 200}]

        selected = framework.select_nuclei_hosts(
            {"id": 3, "domain": "example.com", "enable_nuclei": True},
            hosts,
            first_run=False,
            deep_scan=False,
            summary=summary,
        )

        self.assertEqual(selected, set())
        self.assertEqual(summary["nuclei_batch"][0]["reason"], "not_deep_scan")

    def test_active_deep_batch_selects_top_interesting_hosts_up_to_cap(self):
        framework = self.framework()
        framework.nuclei_batch_status = lambda domain_info: {"enabled": True, "reason": "active_batch"}
        summary = new_scan_summary("example.com", first_run=False)
        hosts = [
            {"live_host_id": 1, "url": "https://static.example.com", "status_code": 200},
            {"live_host_id": 2, "url": "https://api.example.com", "status_code": 200},
            {"live_host_id": 3, "url": "https://admin.example.com", "status_code": 403},
            {"live_host_id": 4, "url": "https://login.example.com", "status_code": 200},
        ]

        selected = framework.select_nuclei_hosts(
            {"id": 3, "domain": "example.com", "enable_nuclei": True},
            hosts,
            first_run=False,
            deep_scan=True,
            summary=summary,
        )

        self.assertEqual(len(selected), 2)
        self.assertTrue(selected.issubset({2, 3, 4}))
        self.assertGreaterEqual(len(summary["nuclei_skipped_hosts"]), 2)

    def test_inactive_deep_batch_skips_all_hosts(self):
        framework = self.framework()
        framework.nuclei_batch_status = lambda domain_info: {"enabled": False, "reason": "inactive_batch"}
        summary = new_scan_summary("example.com", first_run=False)
        hosts = [{"live_host_id": 1, "url": "https://api.example.com", "status_code": 200}]

        selected = framework.select_nuclei_hosts(
            {"id": 1, "domain": "example.com", "enable_nuclei": True},
            hosts,
            first_run=False,
            deep_scan=True,
            summary=summary,
        )

        self.assertEqual(selected, set())
        self.assertEqual(summary["nuclei_skipped_hosts"][0]["reason"], "inactive_nuclei_batch")


if __name__ == "__main__":
    unittest.main()
