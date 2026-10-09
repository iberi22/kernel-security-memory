"""Offline unit tests for Unbound CVE history fetching and validation script."""

import json, os, shutil, tempfile, unittest
from scripts.studies import fetch_history_unbound


class TestHistoryUnbound(unittest.TestCase):
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
        self.assertFalse(fetch_history_unbound.validate_offline(self.test_dir))

    def test_offline_passes_valid_catalog_and_index(self):
        idx = {
            "schema_version": "cve-history-v1", "project": "unbound", "repo": "https://github.com/NLnetLabs/unbound",
            "window": {"start": "1999-01-01", "end": "2026-10-08"}, "keyword": "unbound", "coverage": "COMPLETE",
            "entry_count": 1, "with_fix_sha": 1, "requests": 5, "resume": None, "errors": [], "notes": "Descriptions were omitted per policy.",
        }
        cat = {
            "advisory_id": "CVE-2020-28935", "published": "2020-12-07", "cwe": "CWE-59", "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/NLnetLabs/unbound/commit/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"],
            "fix_shas": ["1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"], "subsystem": None,
        }
        self._write_files(idx, [cat])
        self.assertTrue(fetch_history_unbound.validate_offline(self.test_dir))

    def test_offline_fails_on_forbidden_description_key(self):
        idx = {
            "schema_version": "cve-history-v1", "project": "unbound", "repo": "https://github.com/NLnetLabs/unbound",
            "window": {"start": "1999-01-01", "end": "2026-10-08"}, "keyword": "unbound", "coverage": "COMPLETE",
            "entry_count": 1, "with_fix_sha": 0, "requests": 1, "resume": None, "errors": [], "notes": "Descriptions were omitted per policy.",
        }
        cat = {
            "advisory_id": "CVE-2020-0001", "published": "2020-01-01", "cwe": None, "cwe_state": "UNKNOWN",
            "patch_urls": [], "fix_shas": [], "subsystem": None, "description": "Forbidden description",
        }
        self._write_files(idx, [cat])
        self.assertFalse(fetch_history_unbound.validate_offline(self.test_dir))

    def test_ownership_and_transformation_filtering(self):
        unbound_cve = {
            "id": "CVE-2020-28935", "published": "2020-12-07T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:nlnetlabs:unbound:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-59"}]}],
            "references": [{"url": "https://github.com/NLnetLabs/unbound/commit/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"}],
        }
        rec = fetch_history_unbound.transform_cve_item(unbound_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2020-28935")
        self.assertEqual(rec["published"], "2020-12-07")
        self.assertEqual(rec["cwe"], "CWE-59")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertIn("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", rec["fix_shas"])

        non_unbound = {
            "id": "CVE-2021-9999", "published": "2021-01-01T00:00:00.000",
            "configurations": [], "references": [{"url": "https://example.com/other"}],
        }
        self.assertIsNone(fetch_history_unbound.transform_cve_item(non_unbound))

    def test_sha_extraction_and_url_cap(self):
        cve_item = {
            "id": "CVE-2020-28935", "published": "2020-12-07T14:15:00.000",
            "references": [
                {"url": "https://github.com/NLnetLabs/unbound/commit/4954f07d55caf3767f4077685a73e655cfab8044"},
                {"url": "https://github.com/NLnetLabs/unbound/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/NLnetLabs/unbound/commit/0000000000000000000000000000000000000000"},
                {"url": "https://github.com/NLnetLabs/unbound/commit/1111111111111111111111111111111111111111"},
            ],
        }
        urls, shas = fetch_history_unbound.extract_patch_urls_and_shas(cve_item)
        self.assertEqual(len(urls), 3)
        self.assertIn("4954f07d55caf3767f4077685a73e655cfab8044", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertIn("0000000000000000000000000000000000000000", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)

    def test_cwe_extraction_and_state(self):
        self.assertEqual(fetch_history_unbound.extract_cwe({"weaknesses": [{"description": [{"value": "CWE-119"}]}]}), "CWE-119")
        self.assertIsNone(fetch_history_unbound.extract_cwe({"weaknesses": []}))

    def test_line_length_cap_under_500_bytes(self):
        long_url = "https://github.com/NLnetLabs/unbound/commit/" + "a" * 200
        cve_item = {
            "id": "CVE-2023-1234", "published": "2023-05-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:nlnetlabs:unbound:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"value": "CWE-20"}]}],
            "references": [{"url": long_url}, {"url": long_url + "2"}, {"url": long_url + "3"}],
        }
        rec = fetch_history_unbound.transform_cve_item(cve_item)
        self.assertIsNotNone(rec)
        encoded = json.dumps(rec, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 500)


if __name__ == "__main__":
    unittest.main()
