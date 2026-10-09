import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.studies.fetch_curl import (
    validate_study_json,
    validate_record_json,
    validate_patterns_md,
    run_offline
)

class TestStudyCurlOffline(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_validate_study_json_valid(self):
        study = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {
                "id": "curl",
                "repo": "https://github.com/curl/curl",
                "github": "curl/curl"
            },
            "coverage": "WINDOW_SAMPLED",
            "method": {
                "used_query": "https://api.osv.dev/v1/query",
                "http_status": 200,
                "examined": 10,
                "limits": {
                    "max_examined": 40,
                    "max_records": 8
                }
            },
            "counts_by_family": {"bounds": 1},
            "recorded": 1,
            "records": ["records/curl-cve-2026-0001.json"],
            "skipped": [],
            "errors": [],
            "notes": "Sample slice"
        }
        ok, err = validate_study_json(study)
        self.assertTrue(ok, err)

    def test_validate_study_json_invalid_window(self):
        study = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-01-01",
                "end": "2026-10-08",
                "anchor": "invalid anchor"
            },
            "project": {
                "id": "curl",
                "repo": "https://github.com/curl/curl",
                "github": "curl/curl"
            },
            "coverage": "WINDOW_SAMPLED",
            "method": {
                "used_query": "q",
                "http_status": 200,
                "examined": 5,
                "limits": {"max_examined": 40, "max_records": 8}
            },
            "counts_by_family": {},
            "recorded": 0,
            "records": [],
            "skipped": [],
            "errors": [],
            "notes": "empty observation"
        }
        ok, err = validate_study_json(study)
        self.assertFalse(ok)
        self.assertIn("window mismatch", err)

    def test_validate_record_json_valid(self):
        record = {
            "schema_version": "study-record-v1",
            "id": "curl-cve-2026-0001",
            "project": "curl",
            "advisory_id": "CVE-2026-0001",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "bounds",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "1234567890abcdef1234567890abcdef12345678",
                "url": "https://github.com/curl/curl/commit/1234567890abcdef1234567890abcdef12345678",
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "Missing bounds check on header length.",
            "mitigation": "Enforces strict length check.",
            "evidence": [
                {
                    "url": "https://github.com/curl/curl/commit/1234567890abcdef1234567890abcdef12345678",
                    "sha256": "a" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }
        ok, err = validate_record_json(record, "curl-cve-2026-0001")
        self.assertTrue(ok, err)

    def test_validate_record_json_bad_sha(self):
        record = {
            "schema_version": "study-record-v1",
            "id": "curl-cve-2026-0001",
            "project": "curl",
            "advisory_id": "CVE-2026-0001",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "bounds",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "shortsha",
                "url": "https://github.com/curl/curl/commit/shortsha",
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "Missing check.",
            "mitigation": "Adds check.",
            "evidence": [
                {
                    "url": "https://github.com/curl/curl",
                    "sha256": "a" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }
        ok, err = validate_record_json(record, "curl-cve-2026-0001")
        self.assertFalse(ok)
        self.assertIn("fix.sha must be full 40 lowercase hex", err)

    def test_validate_patterns_md_valid(self):
        content = """# Security Fix Frequency Study for curl

Window: 2026-06-09 .. 2026-10-08

## Counts

- bounds: 1

## Records

- records/curl-cve-2026-0001.json

## Limits

Every pattern family label listed here is a hypothesis proposed for classification analysis.
This file is one slice of curl security fixes, not a cross-project ranking or complete security audit.
"""
        ok, err = validate_patterns_md(content, {"bounds": 1})
        self.assertTrue(ok, err)

    def test_run_offline_fails_on_empty_fixture(self):
        # Point paths to empty tmpdir
        s_json = os.path.join(self.tmpdir, "study.json")
        p_md = os.path.join(self.tmpdir, "patterns.md")
        rec_dir = os.path.join(self.tmpdir, "records")

        with patch("scripts.studies.fetch_curl.STUDY_JSON", s_json), \
             patch("scripts.studies.fetch_curl.PATTERNS_MD", p_md), \
             patch("scripts.studies.fetch_curl.RECORDS_DIR", rec_dir):
            ret = run_offline()
            self.assertEqual(ret, 1)

if __name__ == "__main__":
    unittest.main()
