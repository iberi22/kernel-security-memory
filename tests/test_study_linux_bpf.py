"""Offline unit tests for Linux BPF study slice fetching and verification."""

import json
import os
import shutil
import tempfile
import unittest
from scripts.studies.fetch_linux_bpf import run_offline_check, run_fetch


class TestStudyLinuxBPF(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _create_valid_fixture(self):
        records_dir = os.path.join(self.test_dir, "records")
        os.makedirs(records_dir, exist_ok=True)

        rec_filename = "records/linux-bpf-CVE-2026-0001.json"
        rec_path = os.path.join(self.test_dir, rec_filename)
        rec_obj = {
            "schema_version": "study-record-v1",
            "id": "linux-bpf-CVE-2026-0001",
            "project": "linux",
            "advisory_id": "CVE-2026-0001",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "0123456789abcdef0123456789abcdef01234567",
                "url": "https://github.com/torvalds/linux/commit/0123456789abcdef0123456789abcdef01234567",
                "committed_at": "2026-06-10T12:00:00Z"
            },
            "insecure_pattern": "Missing state validation in BPF subsystem.",
            "mitigation": "Enforces proper condition checks in BPF kernel routines.",
            "evidence": [
                {
                    "url": "https://github.com/torvalds/linux/commit/0123456789abcdef0123456789abcdef01234567",
                    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory observation, not a global security ranking."
        }
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(rec_obj, f, indent=2)

        study_obj = {
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
            "coverage": "WINDOW_SAMPLED",
            "method": {
                "used_query": "https://api.osv.dev/v1/query",
                "http_status": 200,
                "examined": 1,
                "limits": {
                    "max_examined": 40,
                    "max_records": 8
                }
            },
            "counts_by_family": {
                "logic": 1
            },
            "recorded": 1,
            "records": [rec_filename],
            "skipped": [],
            "errors": [],
            "notes": "Observed 1 Linux BPF security fix records."
        }
        with open(os.path.join(self.test_dir, "study.json"), "w", encoding="utf-8") as f:
            json.dump(study_obj, f, indent=2)

        patterns_content = (
            "# Frequency note for linux BPF fixes\n"
            "Window: 2026-06-09 .. 2026-10-08\n\n"
            "## Counts\n"
            "- logic: 1\n\n"
            "## Records\n"
            "- records/linux-bpf-CVE-2026-0001.json\n\n"
            "## Limits\n"
            "Every family label is a hypothesis. This file is one slice, not a cross-project ranking.\n"
        )
        with open(os.path.join(self.test_dir, "patterns.md"), "w", encoding="utf-8") as f:
            f.write(patterns_content)

    def test_offline_valid_slice(self):
        self._create_valid_fixture()
        code = run_offline_check(self.test_dir)
        self.assertEqual(code, 0)

    def test_offline_invalid_schema_version(self):
        self._create_valid_fixture()
        study_path = os.path.join(self.test_dir, "study.json")
        with open(study_path, "r", encoding="utf-8") as f:
            d = json.load(f)
        d["schema_version"] = "invalid-schema"
        with open(study_path, "w", encoding="utf-8") as f:
            json.dump(d, f)

        code = run_offline_check(self.test_dir)
        self.assertEqual(code, 1)

    def test_offline_missing_notes_when_empty(self):
        self._create_valid_fixture()
        study_path = os.path.join(self.test_dir, "study.json")
        with open(study_path, "r", encoding="utf-8") as f:
            d = json.load(f)
        d["recorded"] = 0
        d["records"] = []
        d["counts_by_family"] = {}
        d["notes"] = ""
        with open(study_path, "w", encoding="utf-8") as f:
            json.dump(d, f)

        code = run_offline_check(self.test_dir)
        self.assertEqual(code, 1)

    def test_offline_invalid_record_sha(self):
        self._create_valid_fixture()
        rec_path = os.path.join(self.test_dir, "records", "linux-bpf-CVE-2026-0001.json")
        with open(rec_path, "r", encoding="utf-8") as f:
            r = json.load(f)
        r["fix"]["sha"] = "shortsha"
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(r, f)

        code = run_offline_check(self.test_dir)
        self.assertEqual(code, 1)

    def test_offline_disallowed_evidence_host(self):
        self._create_valid_fixture()
        rec_path = os.path.join(self.test_dir, "records", "linux-bpf-CVE-2026-0001.json")
        with open(rec_path, "r", encoding="utf-8") as f:
            r = json.load(f)
        r["evidence"][0]["url"] = "https://unauthorized-domain.com/patch.diff"
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(r, f)

        code = run_offline_check(self.test_dir)
        self.assertEqual(code, 1)

    def test_offline_invalid_patterns_headings(self):
        self._create_valid_fixture()
        patterns_path = os.path.join(self.test_dir, "patterns.md")
        with open(patterns_path, "w", encoding="utf-8") as f:
            f.write("# Frequency note for linux BPF fixes\nWindow: 2026-06-09 .. 2026-10-08\n## Limits\n## Counts\n## Records\n")

        code = run_offline_check(self.test_dir)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
