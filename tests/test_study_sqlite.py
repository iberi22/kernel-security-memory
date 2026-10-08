import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import scripts.studies.fetch_sqlite as fetch_sqlite


class TestStudySqliteOffline(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.base_dir = os.path.join(self.tmp_dir, "docs", "studies", "fable-2026-06", "sqlite")
        self.records_dir = os.path.join(self.base_dir, "records")
        os.makedirs(self.records_dir, exist_ok=True)

        self.study_json_path = os.path.join(self.base_dir, "study.json")
        self.patterns_md_path = os.path.join(self.base_dir, "patterns.md")

        # Patch module paths to use temporary directory
        self.patcher_base = patch.object(fetch_sqlite, "BASE_DIR", self.base_dir)
        self.patcher_study = patch.object(fetch_sqlite, "STUDY_JSON_PATH", self.study_json_path)
        self.patcher_patterns = patch.object(fetch_sqlite, "PATTERNS_MD_PATH", self.patterns_md_path)
        self.patcher_records = patch.object(fetch_sqlite, "RECORDS_DIR", self.records_dir)

        self.patcher_base.start()
        self.patcher_study.start()
        self.patcher_patterns.start()
        self.patcher_records.start()

    def tearDown(self):
        self.patcher_records.stop()
        self.patcher_patterns.stop()
        self.patcher_study.stop()
        self.patcher_base.stop()
        shutil.rmtree(self.tmp_dir)

    def _create_valid_record(self, record_id="sqlite-CVE-2026-39113"):
        rec = {
            "schema_version": "study-record-v1",
            "id": record_id,
            "project": "sqlite",
            "advisory_id": "CVE-2026-39113",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "bounds",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "169f68ed88b34cb68f720191c64c058f2ccec508",
                "url": "https://github.com/sqlite/sqlite/commit/169f68ed88b34cb68f720191c64c058f2ccec508",
                "committed_at": "2026-07-01T12:00:00Z"
            },
            "insecure_pattern": "Insufficient bounds check in array indexing.",
            "mitigation": "Enforce explicit upper-bound check before memory access.",
            "evidence": [
                {
                    "url": "https://github.com/sqlite/sqlite/commit/169f68ed88b34cb68f720191c64c058f2ccec508",
                    "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }
        rel_path = f"records/{record_id}.json"
        abs_path = os.path.join(self.base_dir, rel_path)
        with open(abs_path, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
        return rel_path

    def _create_valid_slice(self, recorded=1):
        recs = []
        counts = {}
        if recorded > 0:
            rel = self._create_valid_record("sqlite-CVE-2026-39113")
            recs.append(rel)
            counts["bounds"] = 1

        study_data = {
            "schema_version": "study-slice-v1",
            "window": {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09"
            },
            "project": {
                "id": "sqlite",
                "repo": "https://github.com/sqlite/sqlite",
                "github": "sqlite/sqlite"
            },
            "coverage": "WINDOW_SAMPLED" if recorded > 0 else "INCOMPLETE",
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
            "records": recs,
            "skipped": [],
            "errors": [],
            "notes": "Recorded 1 SQLite advisory." if recorded > 0 else "No matching security fix advisories were recorded (empty slice)."
        }

        with open(self.study_json_path, "w", encoding="utf-8") as f:
            json.dump(study_data, f, indent=2)

        patterns_md = """# SQLite Security Fix Frequency Study

Window: 2026-06-09 .. 2026-10-08

## Counts

- bounds: 1

## Records

- records/sqlite-CVE-2026-39113.json

## Limits

This file represents one bounded slice of SQLite security fixes.
"""
        with open(self.patterns_md_path, "w", encoding="utf-8") as f:
            f.write(patterns_md)

    def test_offline_valid_slice_passes(self):
        self._create_valid_slice(recorded=1)
        with self.assertRaises(SystemExit) as cm:
            fetch_sqlite.validate_offline()
        self.assertEqual(cm.exception.code, 0)

    def test_offline_empty_slice_passes(self):
        self._create_valid_slice(recorded=0)
        with self.assertRaises(SystemExit) as cm:
            fetch_sqlite.validate_offline()
        self.assertEqual(cm.exception.code, 0)

    def test_offline_missing_study_json_fails(self):
        # Do not create study.json
        with self.assertRaises(SystemExit) as cm:
            fetch_sqlite.validate_offline()
        self.assertNotEqual(cm.exception.code, 0)

    def test_offline_invalid_schema_version_fails(self):
        self._create_valid_slice(recorded=1)
        with open(self.study_json_path, "r", encoding="utf-8") as f:
            d = json.load(f)
        d["schema_version"] = "invalid-v2"
        with open(self.study_json_path, "w", encoding="utf-8") as f:
            json.dump(d, f)

        with self.assertRaises(SystemExit) as cm:
            fetch_sqlite.validate_offline()
        self.assertNotEqual(cm.exception.code, 0)

    def test_offline_invalid_record_sha_fails(self):
        self._create_valid_slice(recorded=1)
        rec_path = os.path.join(self.base_dir, "records", "sqlite-CVE-2026-39113.json")
        with open(rec_path, "r", encoding="utf-8") as f:
            rec = json.load(f)
        rec["fix"]["sha"] = "ab123"  # Short sha
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(rec, f)

        with self.assertRaises(SystemExit) as cm:
            fetch_sqlite.validate_offline()
        self.assertNotEqual(cm.exception.code, 0)

    def test_url_allowlist_checker(self):
        self.assertTrue(fetch_sqlite.is_url_allowlisted("https://github.com/sqlite/sqlite"))
        self.assertTrue(fetch_sqlite.is_url_allowlisted("https://www.sqlite.org/src/info/123"))
        self.assertFalse(fetch_sqlite.is_url_allowlisted("http://github.com/sqlite/sqlite"))  # HTTP not HTTPS
        self.assertFalse(fetch_sqlite.is_url_allowlisted("https://malicious.example.com/exploit"))

    def test_cwe_parsing_and_pattern_family(self):
        cwe_id, cwe_st = fetch_sqlite.parse_cwe("This issue is classified under CWE-125 buffer over-read.")
        self.assertEqual(cwe_id, "CWE-125")
        self.assertEqual(cwe_st, "STATED_BY_ADVISORY")

        cwe_id_none, cwe_st_none = fetch_sqlite.parse_cwe("No classification here.")
        self.assertIsNone(cwe_id_none)
        self.assertEqual(cwe_st_none, "UNKNOWN")

        self.assertEqual(fetch_sqlite.classify_pattern_family("use-after-free in parser"), "memory-lifetime")
        self.assertEqual(fetch_sqlite.classify_pattern_family("buffer over-read in sqlite3.c"), "bounds")
        self.assertEqual(fetch_sqlite.classify_pattern_family("unclear vulnerability"), "unknown")


if __name__ == "__main__":
    unittest.main()
