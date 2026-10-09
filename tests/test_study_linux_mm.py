import json
import os
import shutil
import tempfile
import unittest
import subprocess
import sys

from scripts.studies.fetch_linux_mm import run_offline


class TestStudyLinuxMM(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.test_dir)

        # Create docs/studies/fable-2026-06/linux-mm/ directory structure
        self.study_dir = os.path.join("docs", "studies", "fable-2026-06", "linux-mm")
        self.records_dir = os.path.join(self.study_dir, "records")
        os.makedirs(self.records_dir, exist_ok=True)

        self.study_json_path = os.path.join(self.study_dir, "study.json")
        self.patterns_md_path = os.path.join(self.study_dir, "patterns.md")

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.test_dir)

    def _write_valid_fixture(self, recorded=0, records=None, counts=None):
        if records is None:
            records = []
        if counts is None:
            counts = {}

        study_data = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {
                "id": "linux",
                "repo": "https://github.com/torvalds/linux",
                "github": "torvalds/linux"
            },
            "coverage": "INCOMPLETE" if recorded == 0 else "WINDOW_SAMPLED",
            "method": {
                "used_query": "https://api.osv.dev/v1/query",
                "http_status": 200,
                "examined": 10,
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
            "notes": "Empty slice observed for Linux mm fixes in window 2026-06-09 to 2026-10-08." if recorded == 0 else "Sampled slice."
        }

        with open(self.study_json_path, "w", encoding="utf-8") as f:
            json.dump(study_data, f, indent=2)

        patterns_content = """# Linux Memory Management Fixes Frequency Study

Window: 2026-06-09 .. 2026-10-08

## Counts

- none: 0

## Records

Every family label is a hypothesis.

## Limits

This file is one slice, not a cross-project ranking.
"""
        with open(self.patterns_md_path, "w", encoding="utf-8") as f:
            f.write(patterns_content)

    def test_offline_valid_empty_slice(self):
        self._write_valid_fixture(recorded=0)
        with self.assertRaises(SystemExit) as cm:
            run_offline()
        self.assertEqual(cm.exception.code, 0)

    def test_offline_missing_study_json(self):
        with self.assertRaises(SystemExit) as cm:
            run_offline()
        self.assertNotEqual(cm.exception.code, 0)

    def test_offline_invalid_schema_version(self):
        self._write_valid_fixture(recorded=0)
        with open(self.study_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["schema_version"] = "invalid-version"
        with open(self.study_json_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with self.assertRaises(SystemExit) as cm:
            run_offline()
        self.assertNotEqual(cm.exception.code, 0)

    def test_offline_valid_record_slice(self):
        rec_path = "records/linux-mm-cve-2026-1234.json"
        full_rec_path = os.path.join(self.study_dir, rec_path)

        rec_data = {
            "schema_version": "study-record-v1",
            "id": "linux-mm-cve-2026-1234",
            "project": "linux",
            "advisory_id": "CVE-2026-1234",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "memory-lifetime",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "1234567890abcdef1234567890abcdef12345678",
                "url": "https://github.com/torvalds/linux/commit/1234567890abcdef1234567890abcdef12345678",
                "committed_at": "2026-07-01T00:00:00Z"
            },
            "insecure_pattern": "Missing bounds check in mm.",
            "mitigation": "Enforces bounds check in mm.",
            "evidence": [
                {
                    "url": "https://api.github.com/repos/torvalds/linux/commits/1234567890abcdef1234567890abcdef12345678",
                    "sha256": "a" * 64,
                    "observed_at": "2026-10-08T12:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        with open(full_rec_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f, indent=2)

        self._write_valid_fixture(
            recorded=1,
            records=[rec_path],
            counts={"memory-lifetime": 1}
        )

        with self.assertRaises(SystemExit) as cm:
            run_offline()
        self.assertEqual(cm.exception.code, 0)

    def test_offline_record_invalid_sha(self):
        rec_path = "records/linux-mm-cve-2026-1234.json"
        full_rec_path = os.path.join(self.study_dir, rec_path)

        rec_data = {
            "schema_version": "study-record-v1",
            "id": "linux-mm-cve-2026-1234",
            "project": "linux",
            "advisory_id": "CVE-2026-1234",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "memory-lifetime",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "shortsha",
                "url": "https://github.com/torvalds/linux/commit/shortsha",
                "committed_at": "2026-07-01T00:00:00Z"
            },
            "insecure_pattern": "Missing bounds check in mm.",
            "mitigation": "Enforces bounds check in mm.",
            "evidence": [
                {
                    "url": "https://api.github.com/repos/torvalds/linux/commits/shortsha",
                    "sha256": "a" * 64,
                    "observed_at": "2026-10-08T12:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        with open(full_rec_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f, indent=2)

        self._write_valid_fixture(
            recorded=1,
            records=[rec_path],
            counts={"memory-lifetime": 1}
        )

        with self.assertRaises(SystemExit) as cm:
            run_offline()
        self.assertNotEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
