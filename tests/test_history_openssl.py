"""Offline unit tests for OpenSSL CVE history fetching and validation script."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies import fetch_history_openssl


class TestHistoryOpenSSL(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_offline_fails_when_files_missing(self):
        """--offline should fail (return False) when catalog or index file does not exist."""
        res = fetch_history_openssl.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_offline_passes_valid_catalog_and_index(self):
        """--offline should succeed when index and catalog match schema and constraints."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "openssl",
            "repo": "https://github.com/openssl/openssl",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "openssl",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 1,
            "requests": 10,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        catalog_item = {
            "advisory_id": "CVE-2023-0286",
            "published": "2023-02-07",
            "cwe": "CWE-119",
            "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/openssl/openssl/commit/2c42d31f24d2d46e9f693e54be16a3e5e408544a"],
            "fix_shas": ["2c42d31f24d2d46e9f693e54be16a3e5e408544a"],
            "subsystem": None,
        }

        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index_data, f)

        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(catalog_item) + "\n")

        res = fetch_history_openssl.validate_offline(self.test_dir)
        self.assertTrue(res)

    def test_offline_fails_on_forbidden_description_key(self):
        """Catalog record must not contain a 'description' key."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "openssl",
            "repo": "https://github.com/openssl/openssl",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "openssl",
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

        res = fetch_history_openssl.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_ownership_and_transformation_filtering(self):
        """Test transformation filters non-openssl CVEs and handles CWE / SHAs correctly."""
        openssl_cve = {
            "id": "CVE-2022-0778",
            "published": "2022-03-15T15:15:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [
                {
                    "description": [{"lang": "en", "value": "CWE-835"}]
                }
            ],
            "references": [
                {
                    "url": "https://github.com/openssl/openssl/commit/a843515438848f0701831c19b387e33527fb9ed9"
                }
            ],
        }

        rec = fetch_history_openssl.transform_cve_item(openssl_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2022-0778")
        self.assertEqual(rec["published"], "2022-03-15")
        self.assertEqual(rec["cwe"], "CWE-835")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertEqual(rec["fix_shas"], ["a843515438848f0701831c19b387e33527fb9ed9"])

        non_openssl_cve = {
            "id": "CVE-2022-9999",
            "published": "2022-01-01T00:00:00.000",
            "configurations": [],
            "references": [{"url": "https://example.com/other-package"}],
        }

        rec_filtered = fetch_history_openssl.transform_cve_item(non_openssl_cve)
        self.assertIsNone(rec_filtered)

    def test_sha_extraction_and_url_cap(self):
        """Test patch URL capping at 3 and extraction of 40-hex lowercase SHAs."""
        cve_item = {
            "id": "CVE-2021-3711",
            "published": "2021-08-24T14:15:00.000",
            "references": [
                {"url": "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
                {"url": "https://github.com/openssl/openssl/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/openssl/openssl/commit/0000000000000000000000000000000000000000"},
                {"url": "https://github.com/openssl/openssl/commit/1111111111111111111111111111111111111111"},
            ],
        }

        urls, shas = fetch_history_openssl.extract_patch_urls_and_shas(cve_item)
        self.assertEqual(len(urls), 3)
        self.assertIn("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertIn("0000000000000000000000000000000000000000", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)


if __name__ == "__main__":
    unittest.main()
