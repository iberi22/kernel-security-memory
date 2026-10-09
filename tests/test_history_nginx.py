"""Offline unit tests for nginx CVE history fetching and validation script."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies import fetch_history_nginx


class TestHistoryNginx(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_offline_fails_when_files_missing(self):
        """--offline should fail (return False) when catalog or index file does not exist."""
        res = fetch_history_nginx.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_offline_passes_valid_catalog_and_index(self):
        """--offline should succeed when index and catalog match schema and constraints."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "nginx",
            "repo": "https://github.com/nginx/nginx",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "nginx",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 1,
            "requests": 10,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        catalog_item = {
            "advisory_id": "CVE-2021-23017",
            "published": "2021-06-01",
            "cwe": "CWE-193",
            "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/nginx/nginx/commit/a5895347f32997107770eb59336d8d6411d37149"],
            "fix_shas": ["a5895347f32997107770eb59336d8d6411d37149"],
            "subsystem": None,
        }

        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index_data, f)

        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(catalog_item) + "\n")

        res = fetch_history_nginx.validate_offline(self.test_dir)
        self.assertTrue(res)

    def test_offline_fails_on_forbidden_description_key(self):
        """Catalog record must not contain a 'description' key."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "nginx",
            "repo": "https://github.com/nginx/nginx",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "nginx",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 0,
            "requests": 1,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        catalog_item = {
            "advisory_id": "CVE-2021-0001",
            "published": "2021-01-01",
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

        res = fetch_history_nginx.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_ownership_and_transformation_filtering(self):
        """Test transformation filters non-nginx CVEs and handles CWE / SHAs correctly."""
        nginx_cve = {
            "id": "CVE-2021-23017",
            "published": "2021-06-01T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [
                {
                    "description": [{"lang": "en", "value": "CWE-193"}]
                }
            ],
            "references": [
                {
                    "url": "https://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"
                },
                {
                    "url": "https://github.com/nginx/nginx/commit/a5895347f32997107770eb59336d8d6411d37149"
                }
            ],
        }

        rec = fetch_history_nginx.transform_cve_item(nginx_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2021-23017")
        self.assertEqual(rec["published"], "2021-06-01")
        self.assertEqual(rec["cwe"], "CWE-193")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertIn("a5895347f32997107770eb59336d8d6411d37149", rec["fix_shas"])

        non_nginx_cve = {
            "id": "CVE-2021-9999",
            "published": "2021-01-01T00:00:00.000",
            "configurations": [],
            "references": [{"url": "https://example.com/unrelated-software"}],
        }

        rec_filtered = fetch_history_nginx.transform_cve_item(non_nginx_cve)
        self.assertIsNone(rec_filtered)

    def test_sha_extraction_and_url_cap(self):
        """Test patch URL capping at 3 and extraction of 40-hex lowercase SHAs."""
        cve_item = {
            "id": "CVE-2019-9511",
            "published": "2019-08-13T14:15:00.000",
            "references": [
                {"url": "https://hg.nginx.org/nginx/rev/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
                {"url": "https://github.com/nginx/nginx/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/nginx/nginx/commit/0000000000000000000000000000000000000000"},
                {"url": "https://github.com/nginx/nginx/commit/1111111111111111111111111111111111111111"},
            ],
        }

        urls, shas = fetch_history_nginx.extract_patch_urls_and_shas(cve_item)
        self.assertEqual(len(urls), 3)
        self.assertIn("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertIn("0000000000000000000000000000000000000000", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)

    def test_cwe_extraction_and_state(self):
        """Test extracting CWE string or returning None."""
        with_cwe = {
            "weaknesses": [{"description": [{"value": "CWE-119"}]}]
        }
        self.assertEqual(fetch_history_nginx.extract_cwe(with_cwe), "CWE-119")

        without_cwe = {"weaknesses": []}
        self.assertIsNone(fetch_history_nginx.extract_cwe(without_cwe))

    def test_line_length_cap_under_500_bytes(self):
        """Test that transformed record serialized JSON does not exceed 500 bytes."""
        long_url = "https://github.com/nginx/nginx/commit/" + "a" * 200
        cve_item = {
            "id": "CVE-2023-1234",
            "published": "2023-05-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"value": "CWE-20"}]}],
            "references": [
                {"url": long_url},
                {"url": long_url + "2"},
                {"url": long_url + "3"},
            ],
        }
        rec = fetch_history_nginx.transform_cve_item(cve_item)
        self.assertIsNotNone(rec)
        encoded = json.dumps(rec, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 500)


if __name__ == "__main__":
    unittest.main()
