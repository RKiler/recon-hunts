import asyncio
import unittest

from continuous_recon import AppConfig, ContinuousReconFramework


class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    def framework(self):
        framework = ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 2,
                        "idle_sleep_seconds": 300,
                    }
                }
            )
        )
        framework.pending_domains = [
            {"id": 1, "domain": "one.example"},
            {"id": 2, "domain": "two.example"},
            {"id": 3, "domain": "three.example"},
        ]
        framework.started_domains = []
        framework.release_events = {
            domain["id"]: asyncio.Event()
            for domain in framework.pending_domains
        }

        async def get_domains(limit=None, excluded_domain_ids=None):
            excluded = excluded_domain_ids or set()
            return [
                domain
                for domain in framework.pending_domains
                if domain["id"] not in excluded
                and domain["id"] not in framework.started_domains
            ][:limit]

        async def run_domain(domain):
            framework.started_domains.append(domain["id"])
            await framework.release_events[domain["id"]].wait()

        framework.get_domains_to_scan = get_domains
        framework.run_domain_scan = run_domain
        return framework

    async def test_fills_only_available_slots_without_duplicates(self):
        framework = self.framework()
        active = {}

        self.assertEqual(await framework.fill_domain_scan_slots(active), 2)
        await asyncio.sleep(0)
        self.assertEqual(set(active), {1, 2})
        self.assertEqual(framework.started_domains, [1, 2])
        self.assertEqual(await framework.fill_domain_scan_slots(active), 0)

        for event in framework.release_events.values():
            event.set()
        await framework.reap_domain_scan_tasks(active, 1)
        await framework.reap_domain_scan_tasks(active, 1)

    async def test_refills_slot_as_soon_as_one_scan_finishes(self):
        framework = self.framework()
        active = {}

        await framework.fill_domain_scan_slots(active)
        await asyncio.sleep(0)
        framework.release_events[1].set()
        self.assertEqual(await framework.reap_domain_scan_tasks(active, 1), 1)

        self.assertEqual(await framework.fill_domain_scan_slots(active), 1)
        await asyncio.sleep(0)
        self.assertEqual(set(active), {2, 3})
        self.assertEqual(framework.started_domains, [1, 2, 3])

        framework.release_events[2].set()
        framework.release_events[3].set()
        await framework.reap_domain_scan_tasks(active, 1)
        await framework.reap_domain_scan_tasks(active, 1)


if __name__ == "__main__":
    unittest.main()
