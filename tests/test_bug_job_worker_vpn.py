import tempfile
import unittest
from pathlib import Path

from bug_job_worker import BugJobWorker


class BugJobWorkerVpnGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.worker = BugJobWorker()
        self.worker.vpn_failover_enabled = True
        self.worker.vpn_domain_allowlist = []
        self.worker.max_active_requests = 12
        self.job = {
            "target": "example.com",
            "asset_value": "https://app.example.com/api/me",
            "scope_ok": True,
        }

    def strict_result(self, evidence_path: str) -> dict:
        return {
            "item_scope_respected": True,
            "outcome_class": "BLOCKED",
            "active_request_count": 2,
            "tests_performed": ["Repeated a benign GET with an invalid-path control"],
            "evidence_files": [evidence_path],
            "transport_block": {
                "detected": True,
                "kind": "waf_ip_reputation",
                "repeated_with_benign_baseline": True,
                "application_denial_ruled_out": True,
                "retry_after_seconds": 0,
                "safe_to_retry": True,
                "exact_requests": ["GET /api/me without authentication"],
            },
        }

    def test_accepts_only_evidenced_transport_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            job_dir = Path(directory)
            evidence = job_dir / "evidence" / "block.txt"
            evidence.parent.mkdir()
            evidence.write_text("HTTP 403 edge request id and repeated benign control", encoding="utf-8")
            output = job_dir / "result_direct.json"
            output.write_text("{}", encoding="utf-8")
            result = self.strict_result(str(evidence))
            eligible, reason = self.worker.vpn_retry_eligible(self.job, result, output)
        self.assertTrue(eligible, reason)

    def test_rejects_rate_limit_and_application_denial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            job_dir = Path(directory)
            evidence = job_dir / "block.txt"
            evidence.write_text("control", encoding="utf-8")
            output = job_dir / "result_direct.json"
            output.write_text("{}", encoding="utf-8")
            result = self.strict_result(str(evidence))
            result["transport_block"]["kind"] = "edge_rate_limit"
            result["transport_block"]["retry_after_seconds"] = 60
            eligible, _ = self.worker.vpn_retry_eligible(self.job, result, output)
            self.assertFalse(eligible)
            result["transport_block"]["kind"] = "application_denial"
            result["transport_block"]["retry_after_seconds"] = 0
            eligible, _ = self.worker.vpn_retry_eligible(self.job, result, output)
            self.assertFalse(eligible)

    def test_rejects_retry_that_exceeds_original_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            job_dir = Path(directory)
            evidence = job_dir / "block.txt"
            evidence.write_text("control", encoding="utf-8")
            output = job_dir / "result_direct.json"
            output.write_text("{}", encoding="utf-8")
            result = self.strict_result(str(evidence))
            result["active_request_count"] = 12
            eligible, _ = self.worker.vpn_retry_eligible(self.job, result, output)
        self.assertFalse(eligible)

    def test_domain_allowlist_matches_subdomains_only(self) -> None:
        self.worker.vpn_domain_allowlist = ["example.com"]
        self.assertTrue(self.worker.vpn_domain_allowed(self.job))
        other = dict(self.job, target="notexample.com", asset_value="https://notexample.com/")
        self.assertFalse(self.worker.vpn_domain_allowed(other))


if __name__ == "__main__":
    unittest.main()
