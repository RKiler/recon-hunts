from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from continuous_recon import (
    AppConfig,
    ContinuousReconFramework,
    extract_katana_urls,
    screenshot_filename,
)
from js_analysis import extract_js_urls_from_text, looks_like_js_url


def framework() -> ContinuousReconFramework:
    return ContinuousReconFramework(
        AppConfig(
            {
                "scan": {"max_concurrent_domains": 1},
                "database": {},
                "redis": {},
                "alerts": {},
                "tools": {},
            }
        )
    )


class JavaScriptUrlSafetyTests(unittest.TestCase):
    def test_accepts_supported_javascript_paths(self) -> None:
        self.assertTrue(looks_like_js_url("https://static.example.com/app.min.js?v=1"))
        self.assertTrue(looks_like_js_url("/chunks/module.mjs"))
        self.assertTrue(looks_like_js_url("./worker.cjs"))

    def test_rejects_code_fragment_masquerading_as_url(self) -> None:
        value = "https://example.com/g;n.parseJSON=function(b){if(a.JSON&&a.JS"
        self.assertFalse(looks_like_js_url(value))
        self.assertEqual(extract_js_urls_from_text("https://example.com/app.js", value), [])


class ScopeAndDnsTests(unittest.TestCase):
    def test_target_and_explicit_cdn_scope(self) -> None:
        recon = framework()
        domain = {
            "domain": "example.com",
            "_scope_rules": [
                {"rule_type": "include", "pattern": "*.approved-cdn.test"},
            ],
        }
        self.assertTrue(recon.is_target_or_explicitly_allowed_url(domain, "https://app.example.com/a.js"))
        self.assertTrue(recon.is_target_or_explicitly_allowed_url(domain, "https://static.approved-cdn.test/a.js"))
        self.assertFalse(recon.is_target_or_explicitly_allowed_url(domain, "https://unrelated.test/a.js"))
        self.assertFalse(recon.is_target_or_explicitly_allowed_url(domain, "https://evilapproved-cdn.test/a.js"))

    def test_httpx_ip_address_normalization(self) -> None:
        payload = {
            "a": ["192.0.2.2", "bad"],
            "aaaa": ["2001:db8::1"],
            "host_ip": "192.0.2.2",
        }
        self.assertEqual(
            ContinuousReconFramework.httpx_payload_ip_addresses(payload),
            ["192.0.2.2", "2001:db8::1"],
        )


class KatanaFastProfileTests(unittest.IsolatedAsyncioTestCase):
    def test_extracts_request_endpoints_and_form_actions_from_jsonl(self) -> None:
        output = "\n".join(
            [
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": "https://app.example.com/"},
                        "response": {
                            "forms": [
                                {"method": "POST", "action": "/login", "parameters": ["email"]}
                            ]
                        },
                    }
                ),
                json.dumps(
                    {
                        "request": {
                            "method": "GET",
                            "endpoint": "https://app.example.com/static/app.js",
                        }
                    }
                ),
                "https://app.example.com/legacy",
                "not-json",
            ]
        )

        self.assertEqual(
            extract_katana_urls(output, "https://app.example.com"),
            [
                "https://app.example.com/",
                "https://app.example.com/login",
                "https://app.example.com/static/app.js",
                "https://app.example.com/legacy",
            ],
        )

    async def test_fast_profile_enables_js_crawl_jsonl_and_forms(self) -> None:
        recon = ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "katana_depth": 1,
                        "katana_concurrency": 2,
                        "katana_rate_limit": 2,
                        "katana_crawl_duration": "45s",
                        "http_timeout_seconds": 15,
                        "katana_js_crawl": True,
                        "katana_jsonl": True,
                        "katana_form_extraction": True,
                    },
                    "database": {},
                    "redis": {},
                    "alerts": {},
                    "tools": {"katana": "katana"},
                }
            )
        )
        observed_args: tuple[str, ...] = ()

        async def fake_run_tool(*args: str, **_kwargs: object) -> str:
            nonlocal observed_args
            observed_args = args
            return json.dumps(
                {"request": {"method": "GET", "endpoint": "https://app.example.com/api/me"}}
            )

        recon.run_tool = fake_run_tool  # type: ignore[method-assign]
        urls = await recon.discover_katana_urls(
            {"domain": "example.com"}, "https://app.example.com", 100
        )

        self.assertEqual(urls, ["https://app.example.com/api/me"])
        for flag in ("-jc", "-j", "-or", "-ob", "-fx"):
            self.assertIn(flag, observed_args)


class ScreenshotSafetyTests(unittest.IsolatedAsyncioTestCase):
    def test_screenshot_filename_bounds_pathological_hostnames(self) -> None:
        hostname = ".".join(["very-long-host-segment"] * 20) + ".example.com"
        name = screenshot_filename(
            f"https://{hostname}/",
            datetime(2026, 9, 17, 2, 30, 45, 123456),
        )
        self.assertLessEqual(len(name.encode("utf-8")), 220)
        self.assertTrue(name.startswith("20260917023045123456_"))
        self.assertTrue(name.endswith(".png"))

    async def test_parallel_captures_use_private_tool_directories(self) -> None:
        recon = framework()
        tool_directories: list[Path] = []
        persisted: list[tuple[int, Path, bytes]] = []

        async def fake_run_tool(*args: str, **_kwargs: object) -> str:
            target_url = args[args.index("--url") + 1]
            output_dir = Path(args[args.index("--screenshot-path") + 1])
            tool_directories.append(output_dir)
            await asyncio.sleep(0.01)
            (output_dir / "gowitness.png").write_bytes(target_url.encode("utf-8"))
            return ""

        async def fake_save(
            _domain_info: dict[str, object],
            live_host_id: int,
            _url: str,
            screenshot_path: Path,
            _capture_reason: str,
            _summary: dict[str, object] | None = None,
        ) -> None:
            persisted.append((live_host_id, screenshot_path, screenshot_path.read_bytes()))

        recon.run_tool = fake_run_tool  # type: ignore[method-assign]
        recon.save_screenshot_record = fake_save  # type: ignore[method-assign]
        domain = {"domain": "example.com", "enable_screenshots": True}
        hosts = [
            {"live_host_id": 1, "url": "https://one.example.com"},
            {"live_host_id": 2, "url": "https://two.example.com"},
        ]

        with tempfile.TemporaryDirectory() as root, patch(
            "continuous_recon.SCREENSHOT_ROOT", Path(root)
        ):
            await asyncio.gather(
                *(recon.capture_screenshot(domain, host, "test") for host in hosts)
            )
            self.assertEqual(len(set(tool_directories)), 2)
            self.assertEqual({item[0] for item in persisted}, {1, 2})
            self.assertEqual(
                {item[2] for item in persisted},
                {host["url"].encode("utf-8") for host in hosts},
            )
            self.assertFalse(list((Path(root) / "example.com").glob(".capture-*")))


if __name__ == "__main__":
    unittest.main()
