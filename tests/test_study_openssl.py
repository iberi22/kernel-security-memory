"""Offline unit tests for OpenSSL security study slice."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies import fetch_openssl


class TestStudyOpenSSL(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_offline_validation_success_fixture(self):
        records_dir = os.path.join(self.temp_dir, "records")
        os.makedirs(records_dir, exist_ok=True)

        rec_filename = "openssl-CVE-2026-0001.json"
        rec_data = {
            "schema_version": "study-record-v1",
            "id": "openssl-CVE-2026-0001",
            "project": "openssl",
            "advisory_id": "CVE-2026-0001",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "1111222233334444555566667777888899990000",
                "url": "https://github.com/openssl/openssl/commit/1111222233334444555566667777888899990000",
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "Missing validation check.",
            "mitigation": "Enforces boundary checks.",
            "evidence": [
                {
                    "url": "https://github.com/openssl/openssl/commit/1111222233334444555566667777888899990000",
                    "sha256": "a" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "Single advisory record."
        }
        with open(os.path.join(records_dir, rec_filename), "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        study_data = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {
                "id": "openssl",
                "repo": "https://github.com/openssl/openssl",
                "github": "openssl/openssl"
            },
            "coverage": "WINDOW_SAMPLED",
            "method": {
                "used_query": "POST https://api.osv.dev/v1/query",
                "http_status": 200,
                "examined": 1,
                "limits": {"max_examined": 40, "max_records": 8}
            },
            "counts_by_family": {"logic": 1},
            "recorded": 1,
            "records": [f"records/{rec_filename}"],
            "skipped": [],
            "errors": [],
            "notes": "Valid fixture."
        }
        with open(os.path.join(self.temp_dir, "study.json"), "w", encoding="utf-8") as f:
            json.dump(study_data, f)

        patterns_md = (
            "# openssl security study\n"
            "Window: 2026-06-09 .. 2026-10-08\n\n"
            "## Counts\n- logic: 1\n\n"
            "## Records\n- records/openssl-CVE-2026-0001.json\n\n"
            "## Limits\nSlice test."
        )
        with open(os.path.join(self.temp_dir, "patterns.md"), "w", encoding="utf-8") as f:
            f.write(patterns_md)

        res = fetch_openssl.validate_offline(self.temp_dir)
        self.assertTrue(res)

    def test_offline_validation_empty_dir_fails(self):
        res = fetch_openssl.validate_offline(self.temp_dir)
        self.assertFalse(res)

    def test_offline_validation_bad_schema_fails(self):
        study_data = {
            "schema_version": "bad-schema-version",
            "window": {"start": "2026-06-09", "end": "2026-10-08", "anchor": "Claude Fable 5 public announcement 2026-06-09"},
            "project": {"id": "openssl"},
            "coverage": "WINDOW_SAMPLED",
            "recorded": 0,
            "records": [],
            "counts_by_family": {},
            "notes": "Empty result."
        }
        with open(os.path.join(self.temp_dir, "study.json"), "w", encoding="utf-8") as f:
            json.dump(study_data, f)
        with open(os.path.join(self.temp_dir, "patterns.md"), "w", encoding="utf-8") as f:
            f.write("openssl\nWindow: 2026-06-09 .. 2026-10-08\n## Counts\n## Records\n## Limits\n")

        res = fetch_openssl.validate_offline(self.temp_dir)
        self.assertFalse(res)

    def test_offline_validation_bad_record_sha_fails(self):
        records_dir = os.path.join(self.temp_dir, "records")
        os.makedirs(records_dir, exist_ok=True)

        rec_filename = "openssl-CVE-2026-0002.json"
        rec_data = {
            "schema_version": "study-record-v1",
            "id": "openssl-CVE-2026-0002",
            "project": "openssl",
            "advisory_id": "CVE-2026-0002",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "shortsha123",  # Invalid short SHA
                "url": "https://github.com/openssl/openssl/commit/shortsha123",
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "Missing check.",
            "mitigation": "Enforces bounds.",
            "evidence": [
                {
                    "url": "https://github.com/openssl/openssl/commit/shortsha123",
                    "sha256": "b" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "Single advisory record."
        }
        with open(os.path.join(records_dir, rec_filename), "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        study_data = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {"id": "openssl"},
            "coverage": "WINDOW_SAMPLED",
            "recorded": 1,
            "records": [f"records/{rec_filename}"],
            "counts_by_family": {"logic": 1},
            "notes": "Bad SHA test."
        }
        with open(os.path.join(self.temp_dir, "study.json"), "w", encoding="utf-8") as f:
            json.dump(study_data, f)

        with open(os.path.join(self.temp_dir, "patterns.md"), "w", encoding="utf-8") as f:
            f.write("openssl\nWindow: 2026-06-09 .. 2026-10-08\n## Counts\n## Records\n## Limits\n")

        res = fetch_openssl.validate_offline(self.temp_dir)
        self.assertFalse(res)

    def test_offline_validation_disallowed_evidence_host_fails(self):
        records_dir = os.path.join(self.temp_dir, "records")
        os.makedirs(records_dir, exist_ok=True)

        rec_filename = "openssl-CVE-2026-0003.json"
        rec_data = {
            "schema_version": "study-record-v1",
            "id": "openssl-CVE-2026-0003",
            "project": "openssl",
            "advisory_id": "CVE-2026-0003",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "1111222233334444555566667777888899990000",
                "url": "https://github.com/openssl/openssl/commit/1111222233334444555566667777888899990000",
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "Missing check.",
            "mitigation": "Enforces bounds.",
            "evidence": [
                {
                    "url": "https://malicious-host.example.com/bad",
                    "sha256": "c" * 64,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "Single advisory record."
        }
        with open(os.path.join(records_dir, rec_filename), "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        study_data = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {"id": "openssl"},
            "coverage": "WINDOW_SAMPLED",
            "recorded": 1,
            "records": [f"records/{rec_filename}"],
            "counts_by_family": {"logic": 1},
            "notes": "Host test."
        }
        with open(os.path.join(self.temp_dir, "study.json"), "w", encoding="utf-8") as f:
            json.dump(study_data, f)

        with open(os.path.join(self.temp_dir, "patterns.md"), "w", encoding="utf-8") as f:
            f.write("openssl\nWindow: 2026-06-09 .. 2026-10-08\n## Counts\n## Records\n## Limits\n")

        res = fetch_openssl.validate_offline(self.temp_dir)
        self.assertFalse(res)


if __name__ == "__main__":
    unittest.main()
