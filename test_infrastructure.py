import asyncio
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

from continuous_recon import (
    AppConfig,
    ContinuousReconFramework,
    select_discord_alert_config,
)


class InfrastructureTests(unittest.IsolatedAsyncioTestCase):
    def framework(self):
        return ContinuousReconFramework(
            AppConfig(
                {
                    "scan": {
                        "max_concurrent_domains": 1,
                        "port_scan_quick_ports": [80, 443, 8080],
                    },
                    "tools": {"naabu": "naabu", "nmap": "nmap"},
                    "shodan": {"enabled": True, "api_key": "test-key"},
                }
            )
        )

    def test_cdn_classification_uses_cname(self):
        classification, provider = self.framework().classify_ip_asset(
            {"cname": ["target.map.fastly.net"]}
        )
        self.assertEqual(classification, "cdn")
        self.assertEqual(provider, "target.map.fastly.net")

    def test_shodan_alerts_use_dedicated_discord_config(self):
        alerts = {
            "discord": {
                "enabled": True,
                "webhook_url": "https://discord.example/global",
            },
            "shodan_discord": {
                "enabled": True,
                "webhook_url": "https://discord.example/shodan",
            },
        }
        selected = select_discord_alert_config(
            alerts,
            "shodan_change",
            {"source": "shodan"},
        )
        self.assertEqual(selected["webhook_url"], "https://discord.example/shodan")

    def test_non_shodan_alerts_keep_global_discord_config(self):
        alerts = {
            "discord": {
                "enabled": True,
                "webhook_url": "https://discord.example/global",
            },
            "shodan_discord": {
                "enabled": True,
                "webhook_url": "https://discord.example/shodan",
            },
        }
        selected = select_discord_alert_config(alerts, "scan_summary", {})
        self.assertEqual(selected["webhook_url"], "https://discord.example/global")

    def test_infrastructure_changes_use_shodan_discord_config(self):
        alerts = {
            "discord": {
                "enabled": True,
                "webhook_url": "https://discord.example/global",
            },
            "shodan_discord": {
                "enabled": True,
                "webhook_url": "https://discord.example/shodan",
            },
        }
        selected = select_discord_alert_config(
            alerts,
            "infrastructure_change",
            {"source": "port_scan"},
        )
        self.assertEqual(selected["webhook_url"], "https://discord.example/shodan")

    def test_amass_cleanup_only_targets_orphaned_engines(self):
        class FakePath:
            def __init__(self, name, command, parent):
                self.name = name
                self.command = command
                self.parent = parent

            def __truediv__(self, item):
                return FakeProcFile(self, item)

        class FakeProcFile:
            def __init__(self, process, item):
                self.process = process
                self.item = item

            def read_bytes(self):
                return self.process.command

            def read_text(self, encoding=None):
                return f"Name:\ttest\nPPid:\t{self.process.parent}\n"

        processes = [
            FakePath("101", b"/usr/local/bin/amass\0engine\0", 1),
            FakePath("102", b"/usr/local/bin/amass\0enum\0", 1),
            FakePath("103", b"/usr/local/bin/amass\0engine\0", 55),
        ]
        with (
            patch.object(Path, "iterdir", return_value=processes),
            patch("continuous_recon.os.kill") as kill,
            patch("continuous_recon.asyncio.sleep") as sleep,
        ):
            import asyncio

            asyncio.run(self.framework().cleanup_orphaned_amass_engines())

        self.assertEqual(kill.call_count, 2)
        self.assertTrue(all(call.args[0] == 101 for call in kill.call_args_list))
        sleep.assert_called_once_with(0.5)

    def test_quick_profile_rechecks_existing_open_ports(self):
        args, scanned = self.framework().port_scan_arguments(
            {
                "profile": "quick",
                "ip_address": "192.0.2.1",
                "classification": "unknown",
                "existing_services": [{"port": 8443, "state": "open"}],
            }
        )
        self.assertEqual(scanned, {80, 443, 8080, 8443})
        self.assertIn("80,443,8080,8443", args)

    def test_naabu_json_parser(self):
        output = '\n'.join(
            [
                '{"host":"192.0.2.1","port":443}',
                '{"host":"192.0.2.1","port":8443}',
                "invalid",
            ]
        )
        self.assertEqual(self.framework().parse_naabu_ports(output), {443, 8443})

    def test_nmap_xml_parser(self):
        output = """
        <nmaprun>
          <host><ports>
            <port protocol="tcp" portid="443">
              <state state="open"/>
              <service name="https" product="nginx" version="1.24" conf="10"/>
            </port>
          </ports></host>
        </nmaprun>
        """
        services = self.framework().parse_nmap_services(output)
        self.assertEqual(services[443]["service"], "https")
        self.assertEqual(services[443]["product"], "nginx")
        self.assertEqual(services[443]["version"], "1.24")

    def test_shodan_domain_parser_handles_relative_and_absolute_names(self):
        names, records = self.framework().parse_shodan_domain_payload(
            "example.com",
            {
                "subdomains": ["api", "www.example.com"],
                "data": [
                    {"subdomain": "api", "type": "A", "value": "192.0.2.10"},
                    {"subdomain": "mail", "type": "MX", "value": "mx.example.net."},
                ],
            },
        )
        self.assertEqual(
            names,
            {"api.example.com", "www.example.com", "mail.example.com"},
        )
        self.assertEqual(records[0]["hostname"], "api.example.com")
        self.assertEqual(records[1]["value"], "mx.example.net")

    def test_shodan_host_parser_deduplicates_services_and_collects_cves(self):
        parsed = self.framework().parse_shodan_host_payload(
            {
                "ip_str": "192.0.2.10",
                "ports": [443],
                "hostnames": ["api.example.com"],
                "vulns": {"CVE-2024-0001": {}},
                "data": [
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "version": "1.24",
                        "timestamp": "2026-06-01T00:00:00.000000",
                        "_shodan": {"module": "https"},
                    },
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "version": "1.25",
                        "timestamp": "2026-06-02T00:00:00.000000",
                        "_shodan": {"module": "https"},
                    },
                ],
            }
        )
        self.assertEqual(parsed["ports"], [443])
        self.assertEqual(len(parsed["services"]), 1)
        self.assertEqual(parsed["services"][0]["version"], "1.25")
        self.assertEqual(parsed["vulnerabilities"], ["CVE-2024-0001"])

    def test_shodan_profile_verifies_passive_ports(self):
        args, scanned = self.framework().port_scan_arguments(
            {
                "profile": "shodan",
                "ip_address": "192.0.2.1",
                "classification": "origin",
                "existing_services": [
                    {"port": 8443, "state": "passive_unverified"},
                    {"port": 443, "state": "open"},
                ],
            }
        )
        self.assertEqual(scanned, {80, 443, 8080, 8443})
        self.assertIn("80,443,8080,8443", args)

    def test_passive_port_confirmation_is_not_reopened(self):
        framework = self.framework()
        self.assertEqual(
            framework.classify_open_port_transition("passive_unverified"),
            "verified",
        )
        self.assertEqual(
            framework.classify_open_port_transition("closed"),
            "reopened",
        )
        self.assertEqual(
            framework.classify_open_port_transition("not_observed"),
            "reopened",
        )
        self.assertEqual(
            framework.classify_open_port_transition("open"),
            "unchanged",
        )

    async def test_current_dns_hosts_for_ip_filters_stale_associations(self):
        framework = self.framework()

        async def fake_getaddrinfo(hostname, port, family, type):
            address = "192.0.2.10" if hostname == "current.example.com" else "192.0.2.20"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]

        with patch.object(
            asyncio.get_running_loop(),
            "getaddrinfo",
            side_effect=fake_getaddrinfo,
        ):
            matches = await framework.current_dns_hosts_for_ip(
                "192.0.2.10",
                ["current.example.com", "stale.example.com"],
            )

        self.assertEqual(matches, ["current.example.com"])

    def test_shodan_cdn_classification_uses_provider_and_hostname(self):
        self.assertEqual(
            self.framework().classify_shodan_host(
                {"org": "Cloudflare, Inc.", "isp": "", "hostnames": []}
            ),
            ("cdn", "cloudflare"),
        )
        self.assertEqual(
            self.framework().classify_shodan_host(
                {"org": "", "isp": "", "hostnames": ["edge.example.fastly.net"]}
            ),
            ("cdn", "fastly"),
        )


if __name__ == "__main__":
    unittest.main()
