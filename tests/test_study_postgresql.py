"""Offline unit tests for PostgreSQL security study slice validation [WAVE-2.11]."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies.fetch_postgresql import validate_slice_offline, is_allowlisted_url


class TestStudyPostgreSQL(unittest.TestCase):
    """Offline test suite for PostgreSQL security slice contract and validator."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.records_dir = os.path.join(self.test_dir, "records")
        os.makedirs(self.records_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_valid_slice(self):
        study_data = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {
                "id": "postgresql",
                "repo": "https://github.com/postgres/postgres",
                "github": "postgres/postgres"
            },
            "coverage": "INCOMPLETE",
            "method": {
                "used_query": "https://api.osv.dev/v1/query",
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
            "notes": "Zero PostgreSQL advisories observed; this empty result is the observation."
        }
        with open(os.path.join(self.test_dir, "study.json"), "w", encoding="utf-8") as f:
            json.dump(study_data, f)

        patterns_md = (
            "# PostgreSQL Security Patterns (2026-06-09 .. 2026-10-08)\n\n"
            "Window: 2026-06-09 .. 2026-10-08\n\n"
            "## Counts\n"
            "- (no records observed in slice)\n\n"
            "## Records\n"
            "- none\n\n"
            "## Limits\n"
            "Every pattern family label listed here is a hypothesis.\n"
            "This file represents one slice of PostgreSQL security advisories and is not a cross-project ranking.\n"
        )
        with open(os.path.join(self.test_dir, "patterns.md"), "w", encoding="utf-8") as f:
            f.write(patterns_md)

    def test_empty_directory_fails_offline(self):
        """Confirm offline validation returns False on an empty directory."""
        empty_dir = tempfile.mkdtemp()
        try:
            self.assertFalse(validate_slice_offline(empty_dir))
        finally:
            shutil.rmtree(empty_dir)

    def test_valid_empty_slice_passes(self):
        """Confirm offline validation passes on a valid empty slice structure."""
        self._write_valid_slice()
        self.assertTrue(validate_slice_offline(self.test_dir))

    def test_allowlisted_url_checker(self):
        """Test URL allowlist verification logic."""
        self.assertTrue(is_allowlisted_url("https://github.com/postgres/postgres/commit/123"))
        self.assertTrue(is_allowlisted_url("https://api.osv.dev/v1/query"))
        self.assertTrue(is_allowlisted_url("https://www.postgresql.org/about/news/"))
        self.assertFalse(is_allowlisted_url("http://github.com/postgres/postgres"))
        self.assertFalse(is_allowlisted_url("https://malicious-site.example.com/payload"))

    def test_invalid_schema_version_fails(self):
        """Confirm study.json with wrong schema_version is rejected."""
        self._write_valid_slice()
        study_path = os.path.join(self.test_dir, "study.json")
        with open(study_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["schema_version"] = "invalid-v2"
        with open(study_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        self.assertFalse(validate_slice_offline(self.test_dir))

    def test_valid_record_slice_passes(self):
        """Confirm offline validation passes when valid record files are present."""
        self._write_valid_slice()

        record_data = {
            "schema_version": "study-record-v1",
            "id": "postgresql-CVE-2026-0001",
            "project": "postgresql",
            "advisory_id": "CVE-2026-0001",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "a" * 40,
                "url": "https://github.com/postgres/postgres/commit/" + "a" * 40,
                "committed_at": "2026-07-01T00:00:00Z"
            },
            "insecure_pattern": "Missing bounds check on input buffer.",
            "mitigation": "Patched boundary check.",
            "evidence": [
                {
                    "url": "https://github.com/postgres/postgres/commit/" + "a" * 40,
                    "sha256": "b" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "Single advisory record."
        }
        rec_path = os.path.join(self.records_dir, "postgresql-CVE-2026-0001.json")
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(record_data, f)

        study_path = os.path.join(self.test_dir, "study.json")
        with open(study_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["recorded"] = 1
        data["records"] = ["records/postgresql-CVE-2026-0001.json"]
        data["counts_by_family"] = {"logic": 1}
        data["coverage"] = "WINDOW_SAMPLED"
        data["notes"] = "Observed 1 PostgreSQL security advisory in window."
        with open(study_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        self.assertTrue(validate_slice_offline(self.test_dir))


if __name__ == "__main__":
    unittest.main()
