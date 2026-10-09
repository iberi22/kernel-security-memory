"""Offline unit tests for systemd CVE history fetching and validation script."""

import json, os, shutil, tempfile, unittest
from scripts.studies import fetch_history_systemd


class TestHistorySystemd(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def _write_files(self, index_data, catalog_items):
        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index_data, f)
        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            for item in catalog_items:
                f.write(json.dumps(item) + "\n")

    def test_offline_fails_when_files_missing(self):
        """--offline should fail when catalog or index file does not exist."""
        self.assertFalse(fetch_history_systemd.validate_offline(self.test_dir))

    def test_offline_passes_valid_catalog_and_index(self):
        """--offline should succeed when index and catalog match schema and constraints."""
        idx = {
            "schema_version": "cve-history-v1", "project": "systemd", "repo": "https://github.com/systemd/systemd",
            "window": {"start": "1999-01-01", "end": "2026-10-08"}, "keyword": "systemd", "coverage": "COMPLETE",
            "entry_count": 1, "with_fix_sha": 1, "requests": 5, "resume": None, "errors": [], "notes": "Descriptions were omitted per policy.",
        }
        cat = {
            "advisory_id": "CVE-2021-33910", "published": "2021-07-20", "cwe": "CWE-789", "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/systemd/systemd/commit/441e14d2f1403d0962edd23d38eabac40d461260"],
            "fix_shas": ["441e14d2f1403d0962edd23d38eabac40d461260"], "subsystem": None,
        }
        self._write_files(idx, [cat])
        self.assertTrue(fetch_history_systemd.validate_offline(self.test_dir))

    def test_offline_fails_on_forbidden_description_key(self):
        """Catalog record must not contain a 'description' key."""
        idx = {
            "schema_version": "cve-history-v1", "project": "systemd", "repo": "https://github.com/systemd/systemd",
            "window": {"start": "1999-01-01", "end": "2026-10-08"}, "keyword": "systemd", "coverage": "COMPLETE",
            "entry_count": 1, "with_fix_sha": 0, "requests": 1, "resume": None, "errors": [], "notes": "Descriptions were omitted per policy.",
        }
        cat = {
            "advisory_id": "CVE-2021-0001", "published": "2021-01-01", "cwe": None, "cwe_state": "UNKNOWN",
            "patch_urls": [], "fix_shas": [], "subsystem": None, "description": "This should be forbidden",
        }
        self._write_files(idx, [cat])
        self.assertFalse(fetch_history_systemd.validate_offline(self.test_dir))

    def test_ownership_and_transformation_filtering(self):
        """Test transformation filters non-systemd CVEs and handles CWE / SHAs correctly."""
        systemd_cve = {
            "id": "CVE-2021-33910", "published": "2021-07-20T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:systemd_project:systemd:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-789"}]}],
            "references": [{"url": "https://github.com/systemd/systemd/commit/441e14d2f1403d0962edd23d38eabac40d461260"}],
        }
        rec = fetch_history_systemd.transform_cve_item(systemd_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2021-33910")
        self.assertEqual(rec["published"], "2021-07-20")
        self.assertEqual(rec["cwe"], "CWE-789")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertIn("441e14d2f1403d0962edd23d38eabac40d461260", rec["fix_shas"])

        non_systemd = {
            "id": "CVE-2021-9999", "published": "2021-01-01T00:00:00.000",
            "configurations": [], "references": [{"url": "https://example.com/unrelated-software"}],
        }
        self.assertIsNone(fetch_history_systemd.transform_cve_item(non_systemd))

    def test_sha_extraction_and_url_cap(self):
        """Test patch URL capping at 3 and extraction of 40-hex lowercase SHAs."""
        cve_item = {
            "id": "CVE-2018-15688", "published": "2018-10-26T14:15:00.000",
            "references": [
                {"url": "https://github.com/systemd/systemd/commit/4954f07d55caf3767f4077685a73e655cfab8044"},
                {"url": "https://github.com/systemd/systemd/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/systemd/systemd/commit/0000000000000000000000000000000000000000"},
                {"url": "https://github.com/systemd/systemd/commit/1111111111111111111111111111111111111111"},
            ],
        }
        urls, shas = fetch_history_systemd.extract_patch_urls_and_shas(cve_item)
        self.assertEqual(len(urls), 3)
        self.assertIn("4954f07d55caf3767f4077685a73e655cfab8044", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertIn("0000000000000000000000000000000000000000", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)

    def test_cwe_extraction_and_state(self):
        """Test extracting CWE string or returning None."""
        self.assertEqual(fetch_history_systemd.extract_cwe({"weaknesses": [{"description": [{"value": "CWE-119"}]}]}), "CWE-119")
        self.assertIsNone(fetch_history_systemd.extract_cwe({"weaknesses": []}))

    def test_line_length_cap_under_500_bytes(self):
        """Test that transformed record serialized JSON does not exceed 500 bytes."""
        long_url = "https://github.com/systemd/systemd/commit/" + "a" * 200
        cve_item = {
            "id": "CVE-2023-1234", "published": "2023-05-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:systemd_project:systemd:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"value": "CWE-20"}]}],
            "references": [{"url": long_url}, {"url": long_url + "2"}, {"url": long_url + "3"}],
        }
        rec = fetch_history_systemd.transform_cve_item(cve_item)
        self.assertIsNotNone(rec)
        encoded = json.dumps(rec, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 500)


if __name__ == "__main__":
    unittest.main()
