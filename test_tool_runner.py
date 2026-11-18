import asyncio
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from continuous_recon import AppConfig, ContinuousReconFramework, ToolRunResult


class ToolRunnerTests(unittest.IsolatedAsyncioTestCase):
    def framework(self, timeout_seconds=5):
        return ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "tool_timeout_seconds": timeout_seconds,
                    }
                }
            )
        )

    async def test_file_capture_is_not_held_open_by_detached_child(self):
        framework = self.framework()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "spawn_child.py"
            script.write_text(
                textwrap.dedent(
                    """
                    import os
                    import subprocess
                    import sys

                    subprocess.Popen(
                        [sys.executable, "-c", "import time; time.sleep(2)"],
                        start_new_session=True,
                    )
                    print("parent-finished")
                    """
                ),
                encoding="utf-8",
            )

            output = await asyncio.wait_for(
                framework.run_tool(
                    sys.executable,
                    str(script),
                    capture_output_files=True,
                ),
                timeout=1,
            )

        self.assertEqual(output.strip(), "parent-finished")

    async def test_timeout_terminates_process_group(self):
        framework = self.framework(timeout_seconds=1)
        started = asyncio.get_running_loop().time()

        output = await framework.run_tool(
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
        )

        self.assertEqual(output, "")
        self.assertLess(asyncio.get_running_loop().time() - started, 5)

    async def test_file_capture_preserves_partial_output_on_timeout(self):
        framework = self.framework(timeout_seconds=1)
        result = await framework.run_tool_result(
            sys.executable,
            "-c",
            "import time; print('partial-result', flush=True); time.sleep(30)",
            capture_output_files=True,
        )

        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout.strip(), "partial-result")

    async def test_httpx_timeout_splits_batch_and_deduplicates_partial_output(self):
        framework = ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "httpx_batch_size": 4,
                        "httpx_fallback_min_batch_size": 1,
                        "httpx_max_split_depth": 2,
                        "httpx_batch_timeout_seconds": 10,
                    },
                    "tools": {"httpx": "httpx"},
                }
            )
        )
        framework.run_tool_result = AsyncMock(
            side_effect=[
                ToolRunResult(stdout='{"url":"https://a.example.com"}\n', timed_out=True),
                ToolRunResult(
                    stdout=(
                        '{"url":"https://a.example.com"}\n'
                        '{"url":"https://b.example.com"}\n'
                    )
                ),
                ToolRunResult(stdout='{"url":"https://c.example.com"}\n'),
            ]
        )
        summary = {"httpx_probe": {"known_subdomains_reused": 4}}

        payloads = await framework.collect_httpx_payloads(
            "example.com",
            ["a.example.com", "b.example.com", "c.example.com", "d.example.com"],
            summary,
        )

        self.assertEqual({payload["url"] for payload in payloads}, {
            "https://a.example.com",
            "https://b.example.com",
            "https://c.example.com",
        })
        self.assertEqual(summary["httpx_probe"]["status"], "complete")
        self.assertEqual(summary["httpx_probe"]["timed_out_batches"], 1)
        self.assertEqual(summary["httpx_probe"]["split_retries"], 1)
        self.assertEqual(summary["httpx_probe"]["incomplete_inputs"], 0)
        self.assertEqual(summary["httpx_probe"]["known_subdomains_reused"], 4)

    async def test_dnsx_timeout_splits_batch_and_keeps_partial_output(self):
        framework = ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "dnsx_batch_size": 2,
                        "dnsx_fallback_min_batch_size": 1,
                        "dnsx_max_split_depth": 2,
                        "dnsx_batch_timeout_seconds": 10,
                    },
                    "tools": {"dnsx": "dnsx"},
                }
            )
        )
        framework.run_tool_result = AsyncMock(
            side_effect=[
                ToolRunResult(stdout='{"host":"a.example.com","a":["192.0.2.1"]}\n', timed_out=True),
                ToolRunResult(stdout='{"host":"a.example.com","a":["192.0.2.1"]}\n'),
                ToolRunResult(stdout='{"host":"b.example.com","a":["192.0.2.2"]}\n'),
            ]
        )
        summary = {}

        payloads = await framework.collect_dnsx_payloads(
            "example.com",
            ["a.example.com", "b.example.com"],
            summary,
        )

        self.assertEqual({payload["host"] for payload in payloads}, {"a.example.com", "b.example.com"})
        self.assertEqual(summary["dnsx_probe"]["status"], "complete")
        self.assertEqual(summary["dnsx_probe"]["timed_out_batches"], 1)
        self.assertEqual(summary["dnsx_probe"]["split_retries"], 1)

    async def test_passive_provider_circuit_skips_requests_during_cooldown(self):
        framework = self.framework()
        framework.passive_source_circuit_until["crtsh"] = asyncio.get_running_loop().time() + 60

        payload = await framework.fetch_passive_json(
            "crtsh",
            "example.com",
            "https://invalid.example.test/",
        )

        self.assertIsNone(payload)

    def test_subdomain_normalization_requires_dns_label_boundary(self):
        framework = self.framework()

        self.assertEqual(
            framework.normalize_subdomain_candidate("*.API.Example.com.", "example.com"),
            "api.example.com",
        )
        self.assertEqual(
            framework.normalize_subdomain_candidate("example.com", "example.com"),
            "example.com",
        )
        self.assertIsNone(
            framework.normalize_subdomain_candidate("notexample.com", "example.com")
        )
        self.assertIsNone(
            framework.normalize_subdomain_candidate("example.com.invalid", "example.com")
        )

    async def test_crtname_provider_parses_and_scope_filters_subdomains(self):
        framework = self.framework()
        framework.fetch_passive_json = AsyncMock(
            return_value=[
                {"sub": "example.com"},
                {"sub": "api.example.com"},
                {"sub": "*.cdn.example.com"},
                {"sub": "notexample.com"},
                {"other": "ignored.example.com"},
                "malformed",
            ]
        )

        results = await framework.run_crtname("example.com")

        self.assertEqual(
            results,
            {"example.com", "api.example.com", "cdn.example.com"},
        )
        framework.fetch_passive_json.assert_awaited_once_with(
            "crtname",
            "example.com",
            "https://crt.name/v1/search?apex=example.com",
        )

    def test_recursive_zone_candidates_prioritize_dense_high_value_suffixes(self):
        framework = ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "recursive_passive_max_zone_labels": 2,
                        "recursive_passive_priority_keywords": ["dev", "internal"],
                    }
                }
            )
        )

        candidates = framework.select_recursive_zone_candidates(
            "example.com",
            {
                "api.dev.example.com",
                "admin.dev.example.com",
                "one.public.example.com",
                "notexample.com",
            },
            {"example.com"},
            3,
        )

        self.assertEqual(candidates[0], "dev.example.com")
        self.assertNotIn("notexample.com", candidates)

    def test_delegation_parser_rejects_cname_only_answers(self):
        cname_answer = "ads.example.com. 300 IN CNAME edge.example.net."
        ns_answer = "dev.example.com. 300 IN NS ns1.example.net."
        parent_soa = "example.com. 300 IN SOA ns1.example.net. hostmaster.example.net. 1 2 3 4 5"

        self.assertFalse(
            ContinuousReconFramework.dns_answer_has_exact_record(
                cname_answer,
                "ads.example.com",
                "NS",
            )
        )
        self.assertTrue(
            ContinuousReconFramework.dns_answer_has_exact_record(
                ns_answer,
                "dev.example.com",
                "NS",
            )
        )
        self.assertFalse(
            ContinuousReconFramework.dns_answer_has_exact_record(
                parent_soa,
                "dev.example.com",
                "SOA",
            )
        )

    async def test_recursive_passive_discovery_records_separate_provenance(self):
        framework = ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "recursive_passive_discovery_enabled": True,
                        "recursive_passive_sources": ["crtname"],
                        "recursive_subdomain_tools": ["subfinder"],
                        "recursive_passive_max_depth": 1,
                        "recursive_passive_max_candidates": 1,
                        "recursive_passive_candidates_per_round": 1,
                    }
                }
            )
        )
        framework.is_delegated_zone = AsyncMock(return_value=True)
        framework.run_crtname = AsyncMock(
            return_value={"dev.example.com", "new.api.dev.example.com"}
        )
        framework.run_recursive_subdomain_tool = AsyncMock(
            return_value={"new.cli.dev.example.com"}
        )
        summary = {}

        results = await framework.enumerate_recursive_passive_subdomains(
            "example.com",
            {"dev.example.com", "known.api.dev.example.com"},
            summary,
        )

        self.assertEqual(
            results["crtname_recursive"],
            {"dev.example.com", "new.api.dev.example.com"},
        )
        self.assertEqual(
            results["subfinder_recursive"],
            {"new.cli.dev.example.com"},
        )
        self.assertEqual(summary["passive_recursion"]["new_names"], 2)
        self.assertEqual(summary["passive_recursion"]["zones_queried"], ["dev.example.com"])

    async def test_recursive_cli_tool_filters_output_to_nested_zone(self):
        framework = ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {"max_concurrent_domains": 1},
                    "tools": {"subfinder": "subfinder"},
                }
            )
        )
        framework.run_tool = AsyncMock(
            return_value=(
                "api.dev.example.com\n"
                "deep.api.dev.example.com\n"
                "outside.example.com\n"
            )
        )

        results = await framework.run_recursive_subdomain_tool(
            "subfinder",
            "dev.example.com",
        )

        self.assertEqual(
            results,
            {"api.dev.example.com", "deep.api.dev.example.com"},
        )
        framework.run_tool.assert_awaited_once_with(
            "subfinder",
            "-d",
            "dev.example.com",
            "-silent",
            capture_output_files=True,
        )


if __name__ == "__main__":
    unittest.main()
