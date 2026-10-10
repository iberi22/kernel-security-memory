"""Offline unit tests for qemu CVE history fetching and validation script."""

import json, os, shutil, tempfile, unittest
from scripts.studies import fetch_history_qemu


class TestHistoryQemu(unittest.TestCase):
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
        self.assertFalse(fetch_history_qemu.validate_offline(self.test_dir))

    def test_offline_passes_valid_catalog_and_index(self):
        """--offline should succeed when index and catalog match schema and constraints."""
        idx = {
            "schema_version": "cve-history-v1", "project": "qemu", "repo": "https://gitlab.com/qemu-project/qemu",
            "window": {"start": "1999-01-01", "end": "2026-10-08"}, "keyword": "qemu", "coverage": "COMPLETE",
            "entry_count": 1, "with_fix_sha": 1, "requests": 5, "resume": None, "errors": [], "notes": "Descriptions were omitted per policy.",
        }
        cat = {
            "advisory_id": "CVE-2021-3750", "published": "2021-09-20", "cwe": "CWE-416", "cwe_state": "STATED_BY_ADVISORY",
            "patch_urls": ["https://gitlab.com/qemu-project/qemu/-/commit/f2e1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"],
            "fix_shas": ["f2e1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"], "subsystem": None,
        }
        self._write_files(idx, [cat])
        self.assertTrue(fetch_history_qemu.validate_offline(self.test_dir))

    def test_offline_fails_on_forbidden_description_key(self):
        """Catalog record must not contain a 'description' key."""
        idx = {
            "schema_version": "cve-history-v1", "project": "qemu", "repo": "https://gitlab.com/qemu-project/qemu",
            "window": {"start": "1999-01-01", "end": "2026-10-08"}, "keyword": "qemu", "coverage": "COMPLETE",
            "entry_count": 1, "with_fix_sha": 0, "requests": 1, "resume": None, "errors": [], "notes": "Descriptions were omitted per policy.",
        }
        cat = {
            "advisory_id": "CVE-2021-0001", "published": "2021-01-01", "cwe": None, "cwe_state": "UNKNOWN",
            "patch_urls": [], "fix_shas": [], "subsystem": None, "description": "This should be forbidden",
        }
        self._write_files(idx, [cat])
        self.assertFalse(fetch_history_qemu.validate_offline(self.test_dir))

    def test_ownership_and_transformation_filtering(self):
        """Test transformation filters non-qemu CVEs and handles CWE / SHAs correctly."""
        qemu_cve = {
            "id": "CVE-2021-3750", "published": "2021-09-20T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:qemu:qemu:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-416"}]}],
            "references": [{"url": "https://gitlab.com/qemu-project/qemu/-/commit/f2e1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"}],
        }
        rec = fetch_history_qemu.transform_cve_item(qemu_cve)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["advisory_id"], "CVE-2021-3750")
        self.assertEqual(rec["published"], "2021-09-20")
        self.assertEqual(rec["cwe"], "CWE-416")
        self.assertEqual(rec["cwe_state"], "STATED_BY_ADVISORY")
        self.assertIn("f2e1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", rec["fix_shas"])

        non_qemu = {
            "id": "CVE-2021-9999", "published": "2021-01-01T00:00:00.000",
            "configurations": [], "references": [{"url": "https://example.com/unrelated-software"}],
        }
        self.assertIsNone(fetch_history_qemu.transform_cve_item(non_qemu))

    def test_sha_extraction_and_url_cap(self):
        """Test patch URL capping at 3 and extraction of 40-hex lowercase SHAs."""
        cve_item = {
            "id": "CVE-2020-12345", "published": "2020-05-10T14:15:00.000",
            "references": [
                {"url": "https://gitlab.com/qemu-project/qemu/-/commit/4954f07d55caf3767f4077685a73e655cfab8044"},
                {"url": "https://gitlab.com/qemu-project/qemu/-/commit/FEDCBA9876543210FEDCBA9876543210FEDCBA98"},
                {"url": "https://github.com/qemu/qemu/commit/0000000000000000000000000000000000000000"},
                {"url": "https://github.com/qemu/qemu/commit/1111111111111111111111111111111111111111"},
            ],
        }
        urls, shas = fetch_history_qemu.extract_patch_urls_and_shas(cve_item)
        self.assertEqual(len(urls), 3)
        self.assertIn("4954f07d55caf3767f4077685a73e655cfab8044", shas)
        self.assertIn("fedcba9876543210fedcba9876543210fedcba98", shas)
        self.assertIn("0000000000000000000000000000000000000000", shas)
        self.assertNotIn("1111111111111111111111111111111111111111", shas)

    def test_cwe_extraction_and_state(self):
        """Test extracting CWE string or returning None."""
        self.assertEqual(fetch_history_qemu.extract_cwe({"weaknesses": [{"description": [{"value": "CWE-119"}]}]}), "CWE-119")
        self.assertIsNone(fetch_history_qemu.extract_cwe({"weaknesses": []}))

    def test_line_length_cap_under_500_bytes(self):
        """Test that transformed record serialized JSON does not exceed 500 bytes."""
        long_url = "https://gitlab.com/qemu-project/qemu/-/commit/" + "a" * 200
        cve_item = {
            "id": "CVE-2023-1234", "published": "2023-05-01T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:qemu:qemu:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"value": "CWE-20"}]}],
            "references": [{"url": long_url}, {"url": long_url + "2"}, {"url": long_url + "3"}],
        }
        rec = fetch_history_qemu.transform_cve_item(cve_item)
        self.assertIsNotNone(rec)
        encoded = json.dumps(rec, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), 500)


class TestHistoryQemuIndexStateContract(unittest.TestCase):
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
            self.assertEqual(fetch_history_qemu.determine_status(*args), expected)

    def test_fetch_writes_cursor_paused_index_without_network(self):
        qemu_cve = {
            "id": "CVE-2021-3750", "published": "2021-09-20T12:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:qemu:qemu:*:*:*:*:*:*:*:*"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-416"}]}],
            "references": [{"url": "https://gitlab.com/qemu-project/qemu/-/commit/f2e1a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"}],
        }
        calls = {"n": 0}

        def fake_request(url, cumulative_bytes):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"vulnerabilities": [{"cve": qemu_cve}], "totalResults": 1}
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

        original_request, original_time = fetch_history_qemu.make_nvd_request, fetch_history_qemu.time
        fetch_history_qemu.make_nvd_request = fake_request
        fetch_history_qemu.time = FakeClock()
        try:
            fetch_history_qemu.fetch_nvd_data(self.test_dir, max_time_seconds=60)
        finally:
            fetch_history_qemu.make_nvd_request = original_request
            fetch_history_qemu.time = original_time

        with open(os.path.join(self.test_dir, "index.json"), encoding="utf-8") as f:
            idx = json.load(f)
        self.assertEqual(idx["coverage"], "INCOMPLETE")
        self.assertEqual(idx["status"], "CURSOR_PAUSED")
        self.assertFalse(idx["window_closed"])
        self.assertIn("next_start_date", idx["resume"])
        self.assertEqual(idx["entry_count"], 1)
        self.assertIn("window remains open", idx["notes"])
        self.assertTrue(fetch_history_qemu.validate_offline(self.test_dir))


if __name__ == "__main__":
    unittest.main()
