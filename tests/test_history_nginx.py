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


class TestHistoryNginxIndexStateContract(unittest.TestCase):
    """A fetch run must write the honest-state fields the catalog manifest enforces."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_determine_status_matches_manifest_contract(self):
        cases = [
            ((0, "COMPLETE", None, 10, "1999-01-01"), ("OBSERVED_EMPTY", None, True)),
            ((3, "COMPLETE", None, 10, "1999-01-01"), ("COMPLETE", None, True)),
            ((0, "INCOMPLETE", {"next_start_date": "2007-06-22"}, 35, "1999-01-01"), ("CURSOR_PAUSED", "2007-06-22", False)),
            ((0, "INCOMPLETE", {"next_start_date": "1999-01-01"}, 0, "1999-01-01"), ("NOT_FETCHED", None, False)),
        ]
        for args, expected in cases:
            self.assertEqual(fetch_history_nginx.determine_status(*args), expected)

    def test_fetch_writes_cursor_paused_index_without_network(self):
        nginx_cve = {
            "id": "CVE-2021-23017", "published": "2021-06-01T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-193"}]}],
            "references": [{"url": "https://github.com/nginx/nginx/commit/a5895347f32997107770eb59336d8d6411d37149"}],
        }
        calls = {"n": 0}

        def fake_request(url, cumulative_bytes):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"vulnerabilities": [{"cve": nginx_cve}], "totalResults": 1}
            raise RuntimeError("simulated NVD outage")

        class FakeClock:
            """Advance a virtual clock instead of really sleeping between NVD calls."""

            def __init__(self):
                self.now = 1000.0

            def time(self):
                self.now += 1.0
                return self.now

            def sleep(self, _seconds):
                return None

        original_request, original_time = fetch_history_nginx.make_nvd_request, fetch_history_nginx.time
        fetch_history_nginx.make_nvd_request = fake_request
        fetch_history_nginx.time = FakeClock()
        try:
            fetch_history_nginx.fetch_nvd_data(self.test_dir, max_time_seconds=60)
        finally:
            fetch_history_nginx.make_nvd_request = original_request
            fetch_history_nginx.time = original_time

        with open(os.path.join(self.test_dir, "index.json"), encoding="utf-8") as f:
            idx = json.load(f)
        self.assertEqual(idx["coverage"], "INCOMPLETE")
        self.assertEqual(idx["status"], "CURSOR_PAUSED")
        self.assertFalse(idx["window_closed"])
        self.assertIn("next_start_date", idx["resume"])
        self.assertEqual(idx["entry_count"], 1)
        self.assertIn("window remains open", idx["notes"])
        self.assertTrue(fetch_history_nginx.validate_offline(self.test_dir))


if __name__ == "__main__":
    unittest.main()
