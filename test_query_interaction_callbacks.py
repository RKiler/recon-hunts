import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.query_interaction_callbacks import query


class InteractionCallbackQueryTests(unittest.TestCase):
    def test_query_redacts_callback_token_from_output(self):
        token = "abcdefghijklmnop1234567890"  # gitleaks:allow - synthetic redaction fixture
        marker = "job-42-testmarker"
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "interactions.sqlite3"
            with sqlite3.connect(db_path) as conn:
                conn.executescript(
                    """
                    CREATE TABLE callback_tokens (
                        id INTEGER PRIMARY KEY, token TEXT, label TEXT
                    );
                    CREATE TABLE interactions (
                        id INTEGER PRIMARY KEY, token_id INTEGER,
                        received_at TEXT, kind TEXT, method TEXT, path TEXT,
                        query_string TEXT, source_ip TEXT, user_agent TEXT,
                        body_sha256 TEXT, body_preview TEXT
                    );
                    """
                )
                conn.execute(
                    "INSERT INTO callback_tokens(id, token, label) VALUES (1, ?, 'test')",
                    (token,),
                )
                conn.execute(
                    """
                    INSERT INTO interactions(
                        id, token_id, received_at, kind, method, path,
                        query_string, source_ip, user_agent, body_sha256, body_preview
                    ) VALUES (1, 1, 'now', 'http_callback', 'GET', ?, '', '127.0.0.1', 'test', '', '')
                    """,
                    (f"/c/{token}/{marker}",),
                )

            rows = query(db_path, marker, 10)
            self.assertEqual(len(rows), 1)
            self.assertNotIn(token, str(rows[0]))
            self.assertIn("[CALLBACK_TOKEN]", rows[0]["path"])


if __name__ == "__main__":
    unittest.main()
