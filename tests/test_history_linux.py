"""Offline unit tests for Linux CVE patch catalog fetching and offline validation."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies.fetch_history_linux import (
    extract_cwe,
    extract_subsystem,
    extract_shas,
    parse_nvd_item,
    validate_offline,
)


class TestHistoryLinux(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.linux_dir = os.path.join(self.test_dir, "docs", "studies", "cve-history", "linux")
        os.makedirs(self.linux_dir, exist_ok=True)
        self.index_path = os.path.join(self.linux_dir, "index.json")
        self.catalog_path = os.path.join(self.linux_dir, "catalog.jsonl")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_subsystem_extraction(self):
        self.assertEqual(extract_subsystem(["https://git.kernel.org/linus/net/core/dev.c"]), "net")
        self.assertEqual(extract_subsystem(["https://github.com/torvalds/linux/commit/123/fs/ext4"]), "fs")
        self.assertEqual(extract_subsystem(["https://git.kernel.org/mm/slub.c"]), "mm")
        self.assertEqual(extract_subsystem(["https://git.kernel.org/kernel/bpf/verifier.c"]), "bpf")
        self.assertEqual(extract_subsystem(["https://example.com/kernel/sys.c"]), "unassigned")

    def test_sha_extraction(self):
        urls = [
            "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=a1b2c3d4e5f678901234567890abcdef12345678",
            "https://github.com/torvalds/linux/commit/A1B2C3D4E5F678901234567890ABCDEF12345678"
        ]
        shas = extract_shas(urls)
        self.assertEqual(shas, ["a1b2c3d4e5f678901234567890abcdef12345678"])

    def test_cwe_extraction(self):
        weaknesses_valid = [
            {"description": [{"lang": "en", "value": "CWE-119"}]}
        ]
        cwe, state = extract_cwe(weaknesses_valid)
        self.assertEqual(cwe, "CWE-119")
        self.assertEqual(state, "STATED_BY_ADVISORY")

        weaknesses_none = []
        cwe, state = extract_cwe(weaknesses_none)
        self.assertIsNone(cwe)
        self.assertEqual(state, "UNKNOWN")

    def test_parse_nvd_item(self):
        item = {
            "cve": {
                "id": "CVE-2021-99999",
                "published": "2021-06-01T12:00:00.000",
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-416"}]}
                ],
                "references": [
                    {"url": "https://git.kernel.org/linus/1111111111222222222233333333334444444444"}
                ]
            }
        }
        rec = parse_nvd_item(item)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2021-99999")
        self.assertEqual(rec["published"], "2021-06-01")
        self.assertEqual(rec["cwe"], "CWE-416")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertEqual(rec["fix_shas"], ["1111111111222222222233333333334444444444"])
        self.assertNotIn("description", rec)

    def test_offline_validation_missing_files(self):
        # Patch module paths to point to non-existent temporary files
        import scripts.studies.fetch_history_linux as fetch_mod
        orig_idx = fetch_mod.INDEX_PATH
        orig_cat = fetch_mod.CATALOG_PATH
        try:
            fetch_mod.INDEX_PATH = self.index_path
            fetch_mod.CATALOG_PATH = self.catalog_path
            self.assertFalse(validate_offline())
        finally:
            fetch_mod.INDEX_PATH = orig_idx
            fetch_mod.CATALOG_PATH = orig_cat

    def test_offline_validation_valid_and_invalid_schema(self):
        import scripts.studies.fetch_history_linux as fetch_mod
        orig_idx = fetch_mod.INDEX_PATH
        orig_cat = fetch_mod.CATALOG_PATH
        try:
            fetch_mod.INDEX_PATH = self.index_path
            fetch_mod.CATALOG_PATH = self.catalog_path

            # Create valid index and catalog
            rec = {
                "advisory_id": "CVE-2020-1234",
                "published": "2020-01-01",
                "cwe": "CWE-119",
                "cwe_state": "STATED_BY_ADVISORY",
                "patch_urls": ["https://git.kernel.org/net/1111111111222222222233333333334444444444"],
                "fix_shas": ["1111111111222222222233333333334444444444"],
                "subsystem": "net"
            }
            with open(self.catalog_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")

            index_data = {
                "schema_version": "cve-history-v1",
                "project": "linux",
                "repo": "https://github.com/torvalds/linux",
                "window": {"start": "1999-01-01", "end": "2026-10-08"},
                "keyword": "linux kernel",
                "coverage": "COMPLETE",
                "entry_count": 1,
                "with_fix_sha": 1,
                "requests": 1,
                "resume": None,
                "errors": [],
                "notes": "Descriptions were not stored."
            }
            with open(self.index_path, "w", encoding="utf-8") as f:
                json.dump(index_data, f)

            self.assertTrue(validate_offline())

            # Corrupt catalog with forbidden 'description' key
            rec_bad = dict(rec)
            rec_bad["description"] = "Forbidden description"
            with open(self.catalog_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(rec_bad) + "\n")

            self.assertFalse(validate_offline())

        finally:
            fetch_mod.INDEX_PATH = orig_idx
            fetch_mod.CATALOG_PATH = orig_cat


if __name__ == "__main__":
    unittest.main()
