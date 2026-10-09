"""Offline unit tests for OpenSSH CVE history fetching and validation script."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies import fetch_history_openssh


class TestHistoryOpenSSH(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_offline_fails_when_files_missing(self):
        """--offline should fail (return False) when catalog or index file does not exist."""
        res = fetch_history_openssh.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_offline_passes_valid_catalog_and_index(self):
        """--offline should succeed when index and catalog match schema and constraints."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "openssh",
            "repo": "https://github.com/openssh/openssh-portable",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "openssh",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 1,
            "requests": 10,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        catalog_item = {
            "advisory_id": "CVE-2024-6387",
            "published": "2024-07-01",
            "cwe": "CWE-362",
            "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://github.com/openssh/openssh-portable/commit/e1f438970e5a337a17070a637c1b9e19697cad09"],
            "fix_shas": ["e1f438970e5a337a17070a637c1b9e19697cad09"],
            "subsystem": None,
        }

        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index_data, f)

        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(catalog_item) + "\n")

        res = fetch_history_openssh.validate_offline(self.test_dir)
        self.assertTrue(res)

    def test_offline_fails_on_forbidden_description_key(self):
        """Catalog record must not contain a 'description' key."""
        index_data = {
            "schema_version": "cve-history-v1",
            "project": "openssh",
            "repo": "https://github.com/openssh/openssh-portable",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "openssh",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 0,
            "requests": 1,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        catalog_item = {
            "advisory_id": "CVE-2024-6387",
            "published": "2024-07-01",
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

        res = fetch_history_openssh.validate_offline(self.test_dir)
        self.assertFalse(res)

    def test_ownership_and_transformation_filtering(self):
        """Test transformation filters non-openssh CVEs and handles CWE / SHAs correctly."""
        openssh_cve = {
            "id": "CVE-2024-6387",
            "published": "2024-07-01T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [
                {
                    "description": [{"lang": "en", "value": "CWE-362"}]
                }
            ],
            "references": [
                {
                    "url": "https://github.com/openela-main/openssh/commit/e1f438970e5a337a17070a637c1b9e19697cad09"
                }
            ],
        }

        rec = fetch_history_openssh.transform_cve_item(openssh_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2024-6387")
        self.assertEqual(rec["published"], "2024-07-01")
        self.assertEqual(rec["cwe"], "CWE-362")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertEqual(rec["fix_shas"], ["e1f438970e5a337a17070a637c1b9e19697cad09"])

        non_openssh_cve = {
            "id": "CVE-2024-9999",
            "published": "2024-01-01T00:00:00.000",
            "configurations": [],
            "references": [{"url": "https://example.com/other-package"}],
        }

        rec_filtered = fetch_history_openssh.transform_cve_item(non_openssh_cve)
        self.assertIsNone(rec_filtered)

    def test_sha_extraction_and_url_cap(self):
        """Test patch URL capping at 3 and extraction of 40-hex lowercase SHAs."""
        cve_item = {
            "id": "CVE-2023-38408",
            "published": "2023-07-20T14:15:00.000",
            "references": [
                {"url": "https://anongit.mindrot.org/openssh.git/commit/?id=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
                {"url": "https://github.com/openssh/openssh-portable/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/openssh/openssh-portable/commit/0000000000000000000000000000000000000000"},
                {"url": "https://github.com/openssh/openssh-portable/commit/1111111111111111111111111111111111111111"},
            ],
        }

        urls, shas = fetch_history_openssh.extract_patch_urls_and_shas(cve_item)
        self.assertEqual(len(urls), 3)
        self.assertIn("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertIn("0000000000000000000000000000000000000000", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)


if __name__ == "__main__":
    unittest.main()
