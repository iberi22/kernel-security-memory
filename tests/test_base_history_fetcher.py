#!/usr/bin/env python3
"""Unit tests for BaseHistoryFetcher."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from unittest.mock import MagicMock, patch
import urllib.error

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from base_history_fetcher import BaseHistoryFetcher
from fetcher_io import CorruptStateError


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

    def test_window_end_defaults_to_the_run_date(self):
        """window.end was the frozen literal 2026-10-08, freezing the scan."""
        with mock.patch.dict(os.environ, {"KSM_TODAY": "2031-02-03"}):
            fetcher = BaseHistoryFetcher(
                project="testproj",
                repo="https://github.com/example/testproj",
                keyword="testproj",
                out_dir=self.out_dir,
            )
            self.assertEqual(fetcher.window_end, "2031-02-03")
            self.assertEqual(fetcher.end_date_limit.isoformat(), "2031-02-03")
            fetcher.save_state("COMPLETE", None)
            index = json.loads((self.out_dir / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["window"], {"start": "1999-01-01", "end": "2031-02-03"})
            self.assertTrue(fetcher.validate_offline())

    def test_corrupt_index_is_fatal_instead_of_an_empty_rewrite(self):
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "index.json").write_text('{"schema_version": "cve-history-v1", "requ',
                                                 encoding="utf-8")
        (self.out_dir / "catalog.jsonl").write_text("", encoding="utf-8")
        with self.assertRaises(CorruptStateError):
            BaseHistoryFetcher(
                project="testproj",
                repo="https://github.com/example/testproj",
                keyword="testproj",
                out_dir=self.out_dir,
            )
        # The damaged file is still there: nothing was rewritten over it.
        self.assertIn("requ", (self.out_dir / "index.json").read_text(encoding="utf-8"))

    def test_corrupt_catalog_line_is_fatal(self):
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "catalog.jsonl").write_text(
            '{"advisory_id": "CVE-2020-1234", "published": "2020-05-01"}\n'
            '{"advisory_id": "CVE-2020-1235", "pub', encoding="utf-8")
        with self.assertRaises(CorruptStateError):
            BaseHistoryFetcher(
                project="testproj",
                repo="https://github.com/example/testproj",
                keyword="testproj",
                out_dir=self.out_dir,
            )

    def test_complete_window_is_not_re_fetched_or_rewound(self):
        """A COMPLETE catalog used to be re-fetched and rewound to window_start."""
        sample_rec = {
            "advisory_id": "CVE-2020-1234",
            "published": "2020-05-01",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "patch_urls": [],
            "fix_shas": [],
            "subsystem": "core",
        }
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "catalog.jsonl").write_text(json.dumps(sample_rec) + "\n", encoding="utf-8")
        index_path = self.out_dir / "index.json"
        index_path.write_text(json.dumps({
            "schema_version": "cve-history-v1",
            "project": "testproj",
            "coverage": "COMPLETE",
            "status": "COMPLETE",
            "cursor_date": None,
            "window_closed": True,
            "requests": 113,
            "resume": None,
        }), encoding="utf-8")
        before = index_path.read_text(encoding="utf-8")

        fetcher = _CountingFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
            max_calls=1,
            rate_limit_sleep=0.0,
        )
        self.assertTrue(fetcher.fetch_history())
        self.assertEqual(fetcher.calls_made, 0)
        self.assertEqual(index_path.read_text(encoding="utf-8"), before)

    def test_previous_run_errors_do_not_block_completion(self):
        """One recorded timeout used to park the catalog at its cursor forever."""
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "catalog.jsonl").write_text("", encoding="utf-8")
        last_slice = "1999-04-01"
        (self.out_dir / "index.json").write_text(json.dumps({
            "schema_version": "cve-history-v1",
            "project": "testproj",
            "coverage": "INCOMPLETE",
            "cursor_date": last_slice,
            "requests": 19,
            "resume": {"next_start_date": last_slice},
            "errors": ["Network timeout/error on NVD: read timed out"],
        }), encoding="utf-8")

        fetcher = _CountingFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
            window_start="1999-01-01",
            window_end="1999-04-10",
            max_calls=10,
            rate_limit_sleep=0.0,
        )
        self.assertTrue(fetcher.fetch_history())
        self.assertGreater(fetcher.calls_made, 0)
        index = json.loads((self.out_dir / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["coverage"], "COMPLETE")
        self.assertEqual(index["errors"], [])
        self.assertIn("Network timeout/error on NVD: read timed out", index["error_history"])
        self.assertTrue(fetcher.validate_offline())

    def test_save_state_replaces_the_catalog_before_the_index(self):
        fetcher = BaseHistoryFetcher(
            project="testproj",
            repo="https://github.com/example/testproj",
            keyword="testproj",
            out_dir=self.out_dir,
        )
        replaced = []
        real_replace = os.replace

        def spy_replace(src, dst):
            replaced.append((Path(src).name, Path(dst).name))
            return real_replace(src, dst)

        with mock.patch("os.replace", side_effect=spy_replace):
            fetcher.save_state("INCOMPLETE", {"next_start_date": "2020-06-01"})
        self.assertEqual([dst for _, dst in replaced], ["catalog.jsonl", "index.json"])
        self.assertTrue(all(src != dst for src, dst in replaced), replaced)

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
