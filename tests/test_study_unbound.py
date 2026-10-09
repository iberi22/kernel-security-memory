"""Offline unit tests for Unbound DNS security study slice fetcher and validator."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.studies.fetch_unbound import validate_offline, validate_record, validate_url_host


class TestStudyUnboundOffline(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.base_dir = os.path.join(self.test_dir, "docs", "studies", "fable-2026-06", "unbound")
        self.records_dir = os.path.join(self.base_dir, "records")
        os.makedirs(self.records_dir, exist_ok=True)

        self.study_json_path = os.path.join(self.base_dir, "study.json")
        self.patterns_md_path = os.path.join(self.base_dir, "patterns.md")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_valid_slice(self, recorded=0, records=None, counts=None):
        if records is None:
            records = []
        if counts is None:
            counts = {}

        notes_str = (
            "Slice fetched from upstream advisory endpoints."
            if recorded > 0
            else "No qualified advisories found; the empty result is the observation for window 2026-06-09 to 2026-10-08."
        )

        study_data = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {
                "id": "unbound",
                "repo": "https://github.com/NLnetLabs/unbound",
                "github": "NLnetLabs/unbound"
            },
            "coverage": "WINDOW_SAMPLED",
            "method": {
                "used_query": "https://api.osv.dev/v1/query",
                "http_status": 200,
                "examined": 0,
                "limits": {
                    "max_examined": 40,
                    "max_records": 8
                }
            },
            "counts_by_family": counts,
            "recorded": recorded,
            "records": records,
            "skipped": [],
            "errors": [],
            "notes": notes_str
        }

        with open(self.study_json_path, "w", encoding="utf-8") as f:
            json.dump(study_data, f, indent=2)

        patterns_md = """# Unbound DNS Security Patterns

Window: 2026-06-09 .. 2026-10-08

## Counts

No security pattern families recorded in this window.

## Records

Every pattern family classification in this slice is an analyst hypothesis.
No records were matched for this study slice.

## Limits

This file is a bounded study slice, not a global cross-project ranking.
"""
        with open(self.patterns_md_path, "w", encoding="utf-8") as f:
            f.write(patterns_md)

    def test_validate_url_host(self):
        self.assertTrue(validate_url_host("https://github.com/NLnetLabs/unbound/commit/123"))
        self.assertTrue(validate_url_host("https://api.osv.dev/v1/query"))
        self.assertFalse(validate_url_host("http://github.com/NLnetLabs/unbound"))
        self.assertFalse(validate_url_host("https://malicious.example.com/payload"))

    def test_offline_validator_missing_files(self):
        with patch("scripts.studies.fetch_unbound.STUDY_JSON_PATH", self.study_json_path):
            self.assertEqual(validate_offline(), 1)

    def test_offline_validator_valid_empty_slice(self):
        self._write_valid_slice(recorded=0)
        with patch("scripts.studies.fetch_unbound.STUDY_JSON_PATH", self.study_json_path), \
             patch("scripts.studies.fetch_unbound.PATTERNS_MD_PATH", self.patterns_md_path), \
             patch("scripts.studies.fetch_unbound.BASE_DIR", self.base_dir):
            self.assertEqual(validate_offline(), 0)

    def test_offline_validator_invalid_schema_version(self):
        self._write_valid_slice(recorded=0)
        with open(self.study_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["schema_version"] = "invalid-v1"
        with open(self.study_json_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with patch("scripts.studies.fetch_unbound.STUDY_JSON_PATH", self.study_json_path):
            self.assertEqual(validate_offline(), 1)

    def test_record_validation(self):
        rec_path = os.path.join(self.records_dir, "unbound-cve-2026-1234.json")
        rec_data = {
            "schema_version": "study-record-v1",
            "id": "unbound-cve-2026-1234",
            "project": "unbound",
            "advisory_id": "CVE-2026-1234",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "a" * 40,
                "url": "https://github.com/NLnetLabs/unbound/commit/" + "a" * 40,
                "committed_at": "2026-06-10T12:00:00Z"
            },
            "insecure_pattern": "An unchecked bounds condition allowed excessive memory usage.",
            "mitigation": "The patch adds strict size validation checks.",
            "evidence": [
                {
                    "url": "https://github.com/NLnetLabs/unbound/commit/" + "a" * 40,
                    "sha256": "b" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        ok, msg = validate_record(rec_data, rec_path)
        self.assertTrue(ok, msg)

        # Invalid short sha
        rec_data["fix"]["sha"] = "short"
        ok, msg = validate_record(rec_data, rec_path)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
