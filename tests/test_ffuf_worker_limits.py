from __future__ import annotations

import unittest

from ffuf_worker import FfufQueueWorker


class FfufWorkerLimitTests(unittest.TestCase):
    def test_identical_response_shapes_share_a_fingerprint(self) -> None:
        first = {
            "url": "https://example.test/admin",
            "status": 200,
            "length": 1234,
            "words": 42,
            "lines": 17,
        }
        second = {
            "url": "https://example.test/random-path",
            "status": "200",
            "length": "1234",
            "words": "42",
            "lines": "17",
        }

        self.assertEqual(
            FfufQueueWorker.hit_fingerprint(first),
            FfufQueueWorker.hit_fingerprint(second),
        )

    def test_redirect_destination_is_part_of_fingerprint(self) -> None:
        first = {"status": 302, "length": 0, "words": 0, "lines": 0, "redirectlocation": "/login"}
        second = {"status": 302, "length": 0, "words": 0, "lines": 0, "redirectlocation": "/admin"}

        self.assertNotEqual(
            FfufQueueWorker.hit_fingerprint(first),
            FfufQueueWorker.hit_fingerprint(second),
        )


if __name__ == "__main__":
    unittest.main()
