import unittest

from ffuf_worker import FfufQueueWorker
from queue_ffuf_scan import profiles_for_host


class FfufBatchTests(unittest.TestCase):
    def test_api_admin_kubernetes_profiles(self):
        profiles = profiles_for_host(
            {
                "url": "https://api-admin.svc.dev.finn.no",
                "title": "",
                "webserver": "UploadServer",
                "technologies": ["Google Cloud"],
            }
        )
        self.assertEqual(profiles[0], "baseline")
        self.assertIn("api", profiles)
        self.assertIn("admin", profiles)
        self.assertIn("kubernetes", profiles)

    def test_technology_specific_profiles(self):
        profiles = profiles_for_host(
            {
                "url": "https://blog.example.com",
                "title": "WordPress",
                "webserver": "Apache",
                "technologies": ["Java", "Spring"],
            }
        )
        self.assertIn("spring", profiles)
        self.assertIn("apache", profiles)
        self.assertIn("wordpress", profiles)

    def test_wordlist_normalization_removes_leading_slashes(self):
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile("w", delete=False) as source:
            source.write("/admin\nadmin\n# comment\n/api\n")
            source_path = Path(source.name)
        normalized_path = Path(FfufQueueWorker.normalize_wordlist(source_path))
        try:
            self.assertEqual(normalized_path.read_text().splitlines(), ["admin", "api"])
        finally:
            source_path.unlink(missing_ok=True)
            normalized_path.unlink(missing_ok=True)

    def test_json_object_accepts_asyncpg_json_text(self):
        self.assertEqual(
            FfufQueueWorker.json_object('{"profile":"api"}'),
            {"profile": "api"},
        )

    def test_run_specific_match_statuses_include_auth_and_method_gates(self):
        statuses = FfufQueueWorker.match_statuses(
            {"match_status": [200, "401", 403, 405, 500, "invalid"]},
            {"ffuf_match_status": [200]},
        )
        self.assertEqual(statuses, [200, 401, 403, 405, 500])

    def test_auto_profile_uses_focused_match_statuses_for_old_queued_runs(self):
        statuses = FfufQueueWorker.match_statuses(
            {"profile": "bug_jobs_auto"},
            {
                "ffuf_match_status": [200, 301],
                "bug_jobs_auto_ffuf_match_status": [200, 401, 403, 405, 500],
            },
        )
        self.assertEqual(statuses, [200, 401, 403, 405, 500])

    def test_auto_profile_uses_focused_wordlist_for_old_queued_runs(self):
        wordlist = FfufQueueWorker.effective_wordlist(
            {"wordlist_path": "/app/wordlists/commons.txt"},
            {"profile": "bug_jobs_auto"},
            {"bug_jobs_auto_ffuf_wordlist": "/app/wordlists/bug-jobs-panels-auth.txt"},
        )
        self.assertEqual(str(wordlist), "/app/wordlists/bug-jobs-panels-auth.txt")

    def test_manual_profile_keeps_selected_wordlist(self):
        wordlist = FfufQueueWorker.effective_wordlist(
            {"wordlist_path": "/app/wordlists/manual.txt"},
            {"profile": "manual"},
            {"bug_jobs_auto_ffuf_wordlist": "/app/wordlists/bug-jobs-panels-auth.txt"},
        )
        self.assertEqual(str(wordlist), "/app/wordlists/manual.txt")

    def test_auto_profile_keeps_one_representative_per_response_fingerprint(self):
        self.assertEqual(
            FfufQueueWorker.max_hits_per_fingerprint(
                {"profile": "bug_jobs_auto"},
                {"ffuf_max_hits_per_fingerprint": 25},
            ),
            1,
        )

    def test_manual_profile_keeps_broader_response_fingerprint_limit(self):
        self.assertEqual(
            FfufQueueWorker.max_hits_per_fingerprint(
                {"profile": "manual"},
                {"ffuf_max_hits_per_fingerprint": 25},
            ),
            25,
        )


if __name__ == "__main__":
    unittest.main()
