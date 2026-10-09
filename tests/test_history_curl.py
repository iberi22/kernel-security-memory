"""Offline unit tests for curl CVE history fetching and validation script."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies import fetch_history_curl


class TestHistoryCurl(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_offline_fails_when_files_missing(self):
        """--offline should fail (return False) when catalog or index file does not exist."""
        res = fetch_history_curl.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_offline_passes_valid_catalog_and_index(self):
        """--offline should succeed when index and catalog match schema and constraints."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "curl",
            "repo": "https://github.com/curl/curl",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "curl",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 1,
            "requests": 10,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        catalog_item = {
            "advisory_id": "CVE-2023-38545",
            "published": "2023-10-18",
            "cwe": "CWE-119",
            "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/curl/curl/commit/1234567890abcdef1234567890abcdef12345678"],
            "fix_shas": ["1234567890abcdef1234567890abcdef12345678"],
            "subsystem": None,
        }

        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index_data, f)

        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(catalog_item) + "\n")

        res = fetch_history_curl.validate_offline(self.test_dir)
        self.assertTrue(res)

    def test_offline_fails_on_forbidden_description_key(self):
        """Catalog record must not contain a 'description' key."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "curl",
            "repo": "https://github.com/curl/curl",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "curl",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 0,
            "requests": 1,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        catalog_item = {
            "advisory_id": "CVE-2023-0001",
            "published": "2023-01-01",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "patch_urls": [],
            "fix_shas": [],
            "subsystem": None,
            "description": "This should be forbidden",
        }

        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index_data, f)

        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(catalog_item) + "\n")

        res = fetch_history_curl.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_ownership_and_transformation_filtering(self):
        """Test transformation filters non-curl CVEs and handles CWE / SHAs correctly."""
        curl_cve = {
            "id": "CVE-2023-38545",
            "published": "2023-10-18T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [
                {
                    "description": [{"lang": "en", "value": "CWE-119"}]
                }
            ],
            "references": [
                {
                    "url": "https://github.com/curl/curl/commit/1234567890abcdef1234567890abcdef12345678"
                }
            ],
        }

        rec = fetch_history_curl.transform_cve_item(curl_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2023-38545")
        self.assertEqual(rec["published"], "2023-10-18")
        self.assertEqual(rec["cwe"], "CWE-119")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertEqual(rec["fix_shas"], ["1234567890abcdef1234567890abcdef12345678"])

        non_curl_cve = {
            "id": "CVE-2022-9999",
            "published": "2022-01-01T00:00:00.000",
            "configurations": [],
            "references": [{"url": "https://example.com/other-package"}],
        }

        rec_filtered = fetch_history_curl.transform_cve_item(non_curl_cve)
        self.assertIsNone(rec_filtered)

    def test_sha_extraction_and_url_cap(self):
        """Test patch URL capping at 3 and extraction of 40-hex lowercase SHAs."""
        cve_item = {
            "id": "CVE-2021-22901",
            "published": "2021-05-26T12:15:00.000",
            "references": [
                {"url": "https://curl.se/docs/CVE-2021-22901.html"},
                {"url": "https://github.com/curl/curl/commit/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
                {"url": "https://github.com/curl/curl/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/curl/curl/commit/1111111111111111111111111111111111111111"},
            ],
        }

        urls, shas = fetch_history_curl.extract_patch_urls_and_shas(cve_item)
        self.assertEqual(len(urls), 3)
        self.assertIn("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)


if __name__ == "__main__":
    unittest.main()
