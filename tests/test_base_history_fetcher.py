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
