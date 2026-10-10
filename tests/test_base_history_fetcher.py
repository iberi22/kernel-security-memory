#!/usr/bin/env python3
"""Unit tests for BaseHistoryFetcher."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from base_history_fetcher import BaseHistoryFetcher


class _CountingFetcher(BaseHistoryFetcher):
    """Fetcher whose network layer is replaced by a call counter."""

    def __init__(self, *args, **kwargs):
        self.calls_made = 0
        super().__init__(*args, **kwargs)

    def make_nvd_request(self, url):
        self.calls_made += 1
        self.requests_count += 1  # mirrors the counter in the real request path
        return {"vulnerabilities": [], "totalResults": 0}


class _FakeResponse:
    """Minimal context-manager response yielding fixed chunks."""

    def __init__(self, chunks):
        self.chunks = list(chunks)

    def read(self, _size=-1):
        return self.chunks.pop(0) if self.chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class TestBaseHistoryFetcher(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_initialization_defaults_and_paths(self):
        fetcher = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
        )
        self.assertEqual(fetcher.project, "testproj")
        self.assertEqual(fetcher.status, "NOT_FETCHED")
        self.assertEqual(fetcher.coverage, "INCOMPLETE")
        self.assertIsNone(fetcher.cursor_date)
        self.assertFalse(fetcher.window_closed)

    def test_save_and_load_state_cursor_paused(self):
        fetcher = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
        )
        sample_rec = {
            "advisory_id": "CVE-2020-1234",
            "published": "2020-05-01",
            "cwe": "CWE-119",
            "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/example/testproj/commit/1111111111111111111111111111111111111111"],
            "fix_shas": ["1111111111111111111111111111111111111111"],
            "subsystem": "core",
        }
        fetcher.kept_records["CVE-2020-1234"] = sample_rec
        fetcher.requests_count = 15
        fetcher.save_state("INCOMPLETE", {"next_start_date": "2020-06-01"})

        # Reload state in fresh instance
        reloaded = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
        )
        self.assertEqual(reloaded.status, "CURSOR_PAUSED")
        self.assertEqual(reloaded.cursor_date, "2020-06-01")
        self.assertFalse(reloaded.window_closed)
        self.assertEqual(reloaded.requests_count, 15)
        self.assertEqual(len(reloaded.kept_records), 1)

    def test_observed_empty_status(self):
        fetcher = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
        )
        fetcher.save_state("COMPLETE", None)
        self.assertEqual(fetcher.status, "OBSERVED_EMPTY")
        self.assertTrue(fetcher.window_closed)
        self.assertIsNone(fetcher.cursor_date)

    def test_network_error_preservation_not_silent(self):
        fetcher = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
            retry_sleep=0.01,
        )

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused by peer")
            res = fetcher.make_nvd_request("https://services.nvd.nist.gov/fake")
            self.assertIsNone(res)
            self.assertGreater(len(fetcher.errors), 0)
            self.assertIn("Connection refused by peer", fetcher.errors[0])

    def test_request_cap_counts_only_the_current_run(self):
        """A persisted lifetime request count must not pause a later run before its first call.

        Regression: the outer loop compared self.requests_count (lifetime, reloaded from
        index.json) against max_calls, so once 400 lifetime requests were recorded every
        later run paused immediately and never advanced the cursor.
        """
        self.out_dir.mkdir(parents=True, exist_ok=True)
        # Index left by earlier runs: lifetime counter already above the per-run cap.
        (self.out_dir / "index.json").write_text(json.dumps({
            "schema_version": "cve-history-v1",
            "project": "testproj",
            "coverage": "INCOMPLETE",
            "cursor_date": "1999-01-01",
            "requests": 400,
            "resume": {"next_start_date": "1999-01-01"},
        }), encoding="utf-8")

        fetcher = _CountingFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
            window_start="1999-01-01",
            window_end="1999-06-30",
            max_calls=1,
            rate_limit_sleep=0.0,
        )

        completed = fetcher.fetch_history()

        # The run used its own budget and paused at the per-run cap, not on the
        # persisted lifetime count.
        self.assertEqual(fetcher.calls_made, 1)
        self.assertFalse(completed)
        # The first slice was really fetched, so the cursor advanced past it instead of
        # being stuck at the window start.
        self.assertEqual(fetcher.cursor_date, "1999-04-01")
        self.assertEqual(fetcher.status, "CURSOR_PAUSED")
        # The lifetime counter keeps accumulating (provenance) instead of gating the run.
        self.assertEqual(fetcher.requests_count, 401)

    def test_retry_path_enforces_cumulative_byte_cap(self):
        """A 403/429 retry must honor the cumulative byte cap, not only the per-response cap."""
        fetcher = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
            per_response_limit=1 * 1024 * 1024,
            cumulative_limit=1000,
            retry_sleep=0.0,
        )
        # Valid JSON, but bigger than the cumulative cap once padded.
        padded = b" " * 1200 + b"{}"
        error = urllib.error.HTTPError(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            429,
            "Too Many Requests",
            {},  # type: ignore[arg-type]
            None,
        )

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = [error, _FakeResponse([padded])]
            res = fetcher.make_nvd_request("https://services.nvd.nist.gov/rest/json/cves/2.0")

        self.assertIsNone(res)
        self.assertGreater(fetcher.cumulative_bytes, fetcher.cumulative_limit)
        self.assertTrue(any("Cumulative limit" in err for err in fetcher.errors), fetcher.errors)
        # The aborted retry must not be counted as a completed request.
        self.assertEqual(fetcher.requests_count, 0)

    def test_offline_validation_passes_and_fails_appropriately(self):
        fetcher = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
        )
        # Empty unwritten directory should fail offline validation
        self.assertFalse(fetcher.validate_offline())

        # Write valid data
        sample_rec = {
            "advisory_id": "CVE-2020-1234",
            "published": "2020-05-01",
            "cwe": "CWE-119",
            "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/example/testproj/commit/1111111111111111111111111111111111111111"],
            "fix_shas": ["1111111111111111111111111111111111111111"],
            "subsystem": "core",
        }
        fetcher.kept_records["CVE-2020-1234"] = sample_rec
        fetcher.save_state("INCOMPLETE", {"next_start_date": "2020-06-01"})
        self.assertTrue(fetcher.validate_offline())


if __name__ == "__main__":
    unittest.main()
