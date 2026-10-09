"""
tests/test_study_git.py

Unit tests for Git study slice fetcher and offline validator.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from scripts.studies.fetch_git import (
    validate_offline,
    validate_record,
    validate_url_host,
    STUDY_ROOT,
    STUDY_JSON,
    PATTERNS_MD,
    RECORDS_DIR
)


class TestStudyGit(unittest.TestCase):

    def test_validate_url_host(self):
        self.assertTrue(validate_url_host("https://github.com/git/git"))
        self.assertTrue(validate_url_host("https://api.osv.dev/v1/query"))
        self.assertFalse(validate_url_host("https://malicious.example.com/payload"))
        self.assertFalse(validate_url_host("http://github.com/git/git"))

    def test_validate_record_success_and_failures(self):
        valid_record = {
            "schema_version": "study-record-v1",
            "id": "git-ghsa-test",
            "project": "git",
            "advisory_id": "GHSA-test",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "bounds",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "1234567890abcdef1234567890abcdef12345678",
                "url": "https://github.com/git/git/commit/1234567890abcdef1234567890abcdef12345678",
                "committed_at": "2026-07-01T00:00:00Z"
            },
            "insecure_pattern": "Missing bounds check.",
            "mitigation": "Enforces bounds check.",
            "evidence": [
                {
                    "url": "https://github.com/git/git",
                    "sha256": "a" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "Single advisory record."
        }
        ok, err = validate_record("test_rec.json", valid_record)
        self.assertTrue(ok, err)

        # Invalid schema version
        bad_rec = dict(valid_record, schema_version="v2")
        ok, err = validate_record("test_rec.json", bad_rec)
        self.assertFalse(ok)

        # Invalid fix SHA (short hex)
        bad_rec = json.loads(json.dumps(valid_record))
        bad_rec["fix"]["sha"] = "12345678"
        ok, err = validate_record("test_rec.json", bad_rec)
        self.assertFalse(ok)

        # Disallowed fix URL
        bad_rec = json.loads(json.dumps(valid_record))
        bad_rec["fix"]["url"] = "https://untrusted.com/commit/1234567890abcdef1234567890abcdef12345678"
        ok, err = validate_record("test_rec.json", bad_rec)
        self.assertFalse(ok)

    def test_offline_validation_missing_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("scripts.studies.fetch_git.STUDY_ROOT", tmpdir), \
                 patch("scripts.studies.fetch_git.STUDY_JSON", os.path.join(tmpdir, "study.json")), \
                 patch("scripts.studies.fetch_git.PATTERNS_MD", os.path.join(tmpdir, "patterns.md")):
                self.assertFalse(validate_offline())

    def test_offline_validation_valid_empty_slice(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            study_json_path = os.path.join(tmpdir, "study.json")
            patterns_md_path = os.path.join(tmpdir, "patterns.md")

            study_data = {
                "schema_version": "study-slice-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {
                    "id": "git",
                    "repo": "https://github.com/git/git",
                    "github": "git/git"
                },
                "coverage": "INCOMPLETE",
                "method": {
                    "used_query": "POST https://api.osv.dev/v1/query",
                    "http_status": 200,
                    "examined": 0,
                    "limits": {
                        "max_examined": 40,
                        "max_records": 8
                    }
                },
                "counts_by_family": {},
                "recorded": 0,
                "records": [],
                "skipped": [],
                "errors": [],
                "notes": "No advisories found; the empty result is the observation."
            }

            with open(study_json_path, "w", encoding="utf-8") as f:
                json.dump(study_data, f)

            patterns_content = (
                "# Git Security Fix Patterns\n\n"
                "Window: 2026-06-09 .. 2026-10-08\n\n"
                "## Counts\n\n"
                "No pattern families observed in this window.\n\n"
                "Every pattern family label above is an analyst hypothesis.\n\n"
                "## Records\n\n"
                "No record files in this slice.\n\n"
                "## Limits\n\n"
                "This file is one slice, not a cross-project ranking.\n"
            )
            with open(patterns_md_path, "w", encoding="utf-8") as f:
                f.write(patterns_content)

            with patch("scripts.studies.fetch_git.STUDY_ROOT", tmpdir), \
                 patch("scripts.studies.fetch_git.STUDY_JSON", study_json_path), \
                 patch("scripts.studies.fetch_git.PATTERNS_MD", patterns_md_path):
                self.assertTrue(validate_offline())

    def test_offline_validation_invalid_recorded_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            study_json_path = os.path.join(tmpdir, "study.json")
            patterns_md_path = os.path.join(tmpdir, "patterns.md")

            study_data = {
                "schema_version": "study-slice-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {
                    "id": "git",
                    "repo": "https://github.com/git/git",
                    "github": "git/git"
                },
                "coverage": "WINDOW_SAMPLED",
                "method": {
                    "used_query": "POST https://api.osv.dev/v1/query",
                    "http_status": 200,
                    "examined": 1,
                    "limits": {
                        "max_examined": 40,
                        "max_records": 8
                    }
                },
                "counts_by_family": {"bounds": 1},
                "recorded": 1,
                "records": [],  # Mismatch: recorded is 1 but records list is empty!
                "skipped": [],
                "errors": [],
                "notes": "Recorded 1 record."
            }

            with open(study_json_path, "w", encoding="utf-8") as f:
                json.dump(study_data, f)

            with open(patterns_md_path, "w", encoding="utf-8") as f:
                f.write("Git Patterns\nWindow: 2026-06-09 .. 2026-10-08\n## Counts\n## Records\n## Limits\n")

            with patch("scripts.studies.fetch_git.STUDY_ROOT", tmpdir), \
                 patch("scripts.studies.fetch_git.STUDY_JSON", study_json_path), \
                 patch("scripts.studies.fetch_git.PATTERNS_MD", patterns_md_path):
                self.assertFalse(validate_offline())


if __name__ == "__main__":
    unittest.main()
