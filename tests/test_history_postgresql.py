"""Offline unit tests for PostgreSQL CVE history fetching and validation script."""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies import fetch_history_postgresql


class TestHistoryPostgresql(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_offline_fails_when_files_missing(self):
        self.assertFalse(fetch_history_postgresql.validate_offline(self.test_dir))

    def test_offline_passes_valid_catalog_and_index(self):
        idx = {
            "schema_version": "cve-history-v1",
            "project": "postgresql",
            "repo": "https://github.com/postgres/postgres",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "postgresql",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 1,
            "requests": 10,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        rec = {
            "advisory_id": "CVE-2023-5868",
            "published": "2023-11-09",
            "cwe": "CWE-89",
            "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://git.postgresql.org/gitweb/?p=postgresql.git;a=commitdiff;h=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"],
            "fix_shas": ["1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"],
            "subsystem": None,
        }
        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(idx, f)
        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        self.assertTrue(fetch_history_postgresql.validate_offline(self.test_dir))

    def test_offline_fails_on_forbidden_description_key(self):
        idx = {
            "schema_version": "cve-history-v1",
            "project": "postgresql",
            "repo": "https://github.com/postgres/postgres",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "keyword": "postgresql",
            "coverage": "COMPLETE",
            "entry_count": 1,
            "with_fix_sha": 0,
            "requests": 1,
            "resume": None,
            "errors": [],
            "notes": "Descriptions were omitted per policy.",
        }
        rec = {
            "advisory_id": "CVE-2023-0001",
            "published": "2023-01-01",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "patch_urls": [],
            "fix_shas": [],
            "subsystem": None,
            "description": "Forbidden",
        }
        with open(os.path.join(self.test_dir, "index.json"), "w", encoding="utf-8") as f:
            json.dump(idx, f)
        with open(os.path.join(self.test_dir, "catalog.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        self.assertFalse(fetch_history_postgresql.validate_offline(self.test_dir))

    def test_ownership_and_transformation_filtering(self):
        pg_cve = {
            "id": "CVE-2023-5868",
            "published": "2023-11-09T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:postgresql:postgresql:15.0:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
            "references": [
                {"url": "https://www.postgresql.org/support/security/CVE-2023-5868/"},
                {"url": "https://git.postgresql.org/gitweb/?p=postgresql.git;a=commitdiff;h=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
            ],
        }
        rec = fetch_history_postgresql.transform_cve_item(pg_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2023-5868")
        self.assertEqual(rec["cwe"], "CWE-89")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertEqual(rec["fix_shas"], ["1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"])

        non_pg = {"id": "CVE-2023-9999", "published": "2023-01-01T00:00:00.000", "configurations": [], "references": [{"url": "https://example.com/other"}]}
        self.assertIsNone(fetch_history_postgresql.transform_cve_item(non_pg))

    def test_sha_extraction_and_url_cap(self):
        cve = {
            "id": "CVE-2023-5868",
            "published": "2023-11-09T14:15:00.000",
            "references": [
                {"url": "https://git.postgresql.org/gitweb/?p=postgresql.git;a=commitdiff;h=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
                {"url": "https://github.com/postgres/postgres/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/postgres/postgres/commit/0000000000000000000000000000000000000000"},
                {"url": "https://github.com/postgres/postgres/commit/1111111111111111111111111111111111111111"},
            ],
        }
        urls, shas = fetch_history_postgresql.extract_patch_urls_and_shas(cve)
        self.assertEqual(len(urls), 3)
        self.assertIn("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)

    def test_cwe_extraction_and_state(self):
        self.assertEqual(fetch_history_postgresql.extract_cwe({"weaknesses": [{"description": [{"value": "CWE-119"}]}]}), "CWE-119")
        self.assertIsNone(fetch_history_postgresql.extract_cwe({"weaknesses": []}))

    def test_line_length_cap_under_500_bytes(self):
        long_url = "https://github.com/postgres/postgres/commit/" + "a" * 200
        cve = {
            "id": "CVE-2023-1234",
            "published": "2023-05-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"value": "CWE-20"}]}],
            "references": [{"url": long_url}, {"url": long_url + "2"}, {"url": long_url + "3"}],
        }
        rec = fetch_history_postgresql.transform_cve_item(cve)
        self.assertIsNotNone(rec)
        encoded = json.dumps(rec, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 500)


class TestHistoryPostgresqlIndexStateContract(unittest.TestCase):
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
            self.assertEqual(fetch_history_postgresql.determine_status(*args), expected)

    def test_fetch_writes_cursor_paused_index_without_network(self):
        pg_cve = {
            "id": "CVE-2023-5868", "published": "2023-11-09T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:postgresql:postgresql:15.0:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
            "references": [{"url": "https://git.postgresql.org/gitweb/?p=postgresql.git;a=commitdiff;h=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"}],
        }
        calls = {"n": 0}

        def fake_request(url, cumulative_bytes):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"vulnerabilities": [{"cve": pg_cve}], "totalResults": 1}
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

        original_request, original_time = fetch_history_postgresql.make_nvd_request, fetch_history_postgresql.time
        fetch_history_postgresql.make_nvd_request = fake_request
        fetch_history_postgresql.time = FakeClock()
        try:
            fetch_history_postgresql.fetch_nvd_data(self.test_dir, max_time_seconds=60)
        finally:
            fetch_history_postgresql.make_nvd_request = original_request
            fetch_history_postgresql.time = original_time

        with open(os.path.join(self.test_dir, "index.json"), encoding="utf-8") as f:
            idx = json.load(f)
        self.assertEqual(idx["coverage"], "INCOMPLETE")
        self.assertEqual(idx["status"], "CURSOR_PAUSED")
        self.assertFalse(idx["window_closed"])
        self.assertIn("next_start_date", idx["resume"])
        self.assertEqual(idx["entry_count"], 1)
        self.assertIn("window remains open", idx["notes"])
        self.assertTrue(fetch_history_postgresql.validate_offline(self.test_dir))


if __name__ == "__main__":
    unittest.main()
