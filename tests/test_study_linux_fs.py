"""
Unit tests for Linux Filesystem Security Study slice (WAVE-2.02).
"""

import json
import os
import tempfile
import unittest
import shutil
from scripts.studies.fetch_linux_fs import validate_offline


class TestStudyLinuxFs(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.records_dir = os.path.join(self.test_dir, "records")
        os.makedirs(self.records_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _create_valid_slice(self, recorded=0):
        expected_window = {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        }
        records = []
        counts = {}

        if recorded > 0:
            for i in range(recorded):
                rec_id = f"CVE-2026-900{i}"
                rec_filename = f"linux-fs-{rec_id}.json"
                rec_rel = f"records/{rec_filename}"
                records.append(rec_rel)
                counts["logic"] = counts.get("logic", 0) + 1

                rec_data = {
                    "schema_version": "study-record-v1",
                    "id": f"linux-fs-{rec_id}",
                    "project": "linux",
                    "advisory_id": rec_id,
                    "cwe": None,
                    "cwe_state": "UNKNOWN",
                    "pattern_family": "logic",
                    "pattern_family_status": "hypothesis",
                    "fix": {
                        "sha": "a" * 40,
                        "url": "https://github.com/torvalds/linux/commit/" + "a" * 40,
                        "committed_at": "2026-07-01T12:00:00Z"
                    },
                    "insecure_pattern": "Missing bounds validation in VFS.",
                    "mitigation": "Enforces boundary checks.",
                    "evidence": [
                        {
                            "url": "https://github.com/torvalds/linux/commit/" + "a" * 40,
                            "sha256": "b" * 64,
                            "observed_at": "2026-10-08T00:00:00Z"
                        }
                    ],
                    "limits": "Single advisory record."
                }
                with open(os.path.join(self.test_dir, rec_rel), "w", encoding="utf-8") as f:
                    json.dump(rec_data, f)

        notes = (
            f"Fetched {recorded} records."
            if recorded > 0
            else "The empty result is the observation for this slice."
        )

        study_data = {
            "schema_version": "study-slice-v1",
            "window": expected_window,
            "project": {
                "id": "linux",
                "repo": "https://github.com/torvalds/linux",
                "github": "torvalds/linux"
            },
            "coverage": "WINDOW_SAMPLED",
            "method": {
                "used_query": "https://api.osv.dev/v1/query",
                "http_status": 200,
                "examined": recorded,
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
            "notes": notes
        }

        with open(os.path.join(self.test_dir, "study.json"), "w", encoding="utf-8") as f:
            json.dump(study_data, f)

        md_content = f"""# Linux Filesystem Security Fixes Analysis

Window: 2026-06-09 .. 2026-10-08

## Counts

- logic: {recorded}

Every family label listed above is an analyst hypothesis.

## Records

- records/sample.json

## Limits

This file describes one slice for linux filesystem fixes only, not a cross-project ranking.
"""
        with open(os.path.join(self.test_dir, "patterns.md"), "w", encoding="utf-8") as f:
            f.write(md_content)

    def test_offline_validation_empty_fixture_success(self):
        self._create_valid_slice(recorded=0)
        ret = validate_offline(self.test_dir)
        self.assertEqual(ret, 0)

    def test_offline_validation_populated_fixture_success(self):
        self._create_valid_slice(recorded=2)
        ret = validate_offline(self.test_dir)
        self.assertEqual(ret, 0)

    def test_offline_validation_missing_study_json_fails(self):
        ret = validate_offline(self.test_dir)
        self.assertEqual(ret, 1)

    def test_offline_validation_invalid_schema_fails(self):
        self._create_valid_slice(recorded=0)
        study_path = os.path.join(self.test_dir, "study.json")
        with open(study_path, "r") as f:
            data = json.load(f)
        data["schema_version"] = "wrong-schema"
        with open(study_path, "w") as f:
            json.dump(data, f)
        ret = validate_offline(self.test_dir)
        self.assertEqual(ret, 1)

    def test_offline_validation_notes_empty_observation_required(self):
        self._create_valid_slice(recorded=0)
        study_path = os.path.join(self.test_dir, "study.json")
        with open(study_path, "r") as f:
            data = json.load(f)
        data["notes"] = "Some other notes without required string."
        with open(study_path, "w") as f:
            json.dump(data, f)
        ret = validate_offline(self.test_dir)
        self.assertEqual(ret, 1)

    def test_offline_validation_invalid_record_sha_fails(self):
        self._create_valid_slice(recorded=1)
        rec_path = os.path.join(self.test_dir, "records", "linux-fs-CVE-2026-9000.json")
        with open(rec_path, "r") as f:
            data = json.load(f)
        data["fix"]["sha"] = "shortsha"
        with open(rec_path, "w") as f:
            json.dump(data, f)
        ret = validate_offline(self.test_dir)
        self.assertEqual(ret, 1)


if __name__ == "__main__":
    unittest.main()
