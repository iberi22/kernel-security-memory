import json
import unittest
from unittest.mock import patch, MagicMock
from scripts.mine_candidates import process_commit, MiningError

class TestMineCandidatesOffline(unittest.TestCase):
    def test_process_commit_success(self):
        sha = "60c0c230c6f046da536d3df8b39a20b9a9fd6af0"
        mock_response = {
            "sha": sha,
            "commit": {
                "message": "Some fix\n\nFixes: f718863aca46 (\"netfilter: fix walk\")\n"
            },
            "parents": [{"sha": "f82777e8ce6c039cdcacbcf1eb8619b99a20c06d"}],
            "files": [{"filename": "net/netfilter/nft_set_rbtree.c"}]
        }
        raw_body = json.dumps(mock_response).encode('utf-8')

        result = process_commit(sha, raw_body, "https://api.github.com/repos/torvalds/linux/commits/60c0c230c6f046da536d3df8b39a20b9a9fd6af0")

        self.assertEqual(result["sha"], sha)
        self.assertTrue(result["sole_parent"])
        self.assertEqual(result["parents"], ["f82777e8ce6c039cdcacbcf1eb8619b99a20c06d"])
        self.assertEqual(result["changed_files"], ["net/netfilter/nft_set_rbtree.c"])
        self.assertEqual(len(result["candidate_signals"]), 1)

        sig = result["candidate_signals"][0]
        self.assertEqual(sig["type"], "fixes_trailer")
        self.assertEqual(sig["target"], "f718863aca46")
        self.assertEqual(sig["status"], "NOT_CONFIRMED")

    def test_process_commit_merge_ambiguity(self):
        sha = "1234567890123456789012345678901234567890"
        mock_response = {
            "sha": sha,
            "commit": {"message": "Merge branch..."},
            "parents": [{"sha": "parent1"}, {"sha": "parent2"}]
        }
        raw_body = json.dumps(mock_response).encode('utf-8')
        result = process_commit(sha, raw_body, "http://example.com")

        self.assertFalse(result["sole_parent"])
        self.assertEqual(result["parents"], ["parent1", "parent2"])

    def test_process_commit_invalid_json(self):
        with self.assertRaises(MiningError) as context:
            process_commit("sha1", b"not json", "http://example.com")
        self.assertIn("Invalid JSON", str(context.exception))



import io
import urllib.error
from scripts.mine_candidates import fetch_commit_bounded

class TestMineCandidatesNetwork(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_fetch_commit_bounded_oversized(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"x" * 8192, b"x" * 8192, b"x" * 8192] # Will cross 16KB
        mock_response.url = "http://example.com"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        cumulative_bytes = [0]
        with self.assertRaises(MiningError) as context:
            fetch_commit_bounded("sha1", None, cumulative_bytes, per_response_limit=16384)

        self.assertIn("exceeded 16384 bytes", str(context.exception))

    @patch("urllib.request.urlopen")
    def test_fetch_commit_bounded_cumulative_oversized(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"x" * 8192, b"x" * 8192, b"x" * 8192]
        mock_response.url = "http://example.com"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        cumulative_bytes = [10000] # Already used some
        with self.assertRaises(MiningError) as context:
            fetch_commit_bounded("sha1", None, cumulative_bytes, cumulative_limit=20000)

        self.assertIn("Cumulative fetch limit 20000 bytes exceeded", str(context.exception))

    @patch("urllib.request.urlopen")
    def test_fetch_commit_bounded_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://example.com", code=404, msg="Not Found", hdrs={}, fp=None
        )

        cumulative_bytes = [0]
        with self.assertRaises(MiningError) as context:
            fetch_commit_bounded("sha1", None, cumulative_bytes)

        self.assertIn("HTTP 404", str(context.exception))
        # Ensure token is not in the error message
        self.assertNotIn("token", str(context.exception).lower())

    def test_live_smoke(self):
        import os
        if not os.environ.get("RUN_LIVE_SMOKE"):
            self.skipTest("Skipping live smoke test. Set RUN_LIVE_SMOKE=1 to run.")

        # We only do a light check on the real seed
        sha = "60c0c230c6f046da536d3df8b39a20b9a9fd6af0"
        cumulative_bytes = [0]
        token = os.environ.get("GITHUB_TOKEN")
        body, url = fetch_commit_bounded(sha, token, cumulative_bytes)

        from scripts.mine_candidates import process_commit
        result = process_commit(sha, body, url)
        self.assertEqual(result["sha"], sha)
        self.assertTrue(result["sole_parent"])
        self.assertGreater(len(result["candidate_signals"]), 0)

if __name__ == '__main__':
    unittest.main()
