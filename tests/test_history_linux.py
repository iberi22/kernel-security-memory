"""Offline unit tests for Linux CVE patch catalog fetching and offline validation."""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from scripts.studies.fetch_history_linux import (
    extract_cwe,
    extract_subsystem,
    extract_shas,
    parse_nvd_item,
    validate_offline,
)
from scripts.studies.fetcher_io import CorruptStateError


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


class _FakeResponse:
    """Context-manager response for a Linux fetch with a faked NVD."""

    def __init__(self, payload):
        self._payload = payload
        self.status = 200

    def read(self, _size=-1):
        chunk, self._payload = self._payload, b""
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class TestLinuxFetchHardening(unittest.TestCase):
    """fetch_history_linux.py owns its loop instead of using BaseHistoryFetcher."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.index_path = self.out_dir / "index.json"
        self.catalog_path = self.out_dir / "catalog.jsonl"

    def _write_index(self, **overrides):
        payload = {
            "schema_version": "cve-history-v1",
            "project": "linux",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "coverage": "INCOMPLETE",
            "status": "CURSOR_PAUSED",
            "cursor_date": "2007-06-22",
            "window_closed": False,
            "entry_count": 0,
            "with_fix_sha": 0,
            "requests": 19,
            "resume": {"next_start_date": "2007-06-22"},
            "errors": [],
            "notes": "stub",
        }
        payload.update(overrides)
        self.index_path.write_text(json.dumps(payload), encoding="utf-8")
        return payload

    def test_carried_error_no_longer_blocks_completion(self):
        """The unbound-style state: a cursor parked by one recorded timeout."""
        from scripts.studies import fetch_history_linux

        self._write_index(
            cursor_date="2026-10-12",
            resume={"next_start_date": "2026-10-12"},
            errors=["Fetch error: The read operation timed out"],
        )
        self.catalog_path.write_text("", encoding="utf-8")

        response = _FakeResponse(b'{"vulnerabilities": [], "totalResults": 0}')
        with mock.patch.dict(os.environ, {"KSM_TODAY": "2026-10-12"}), \
             mock.patch.object(fetch_history_linux, "INDEX_PATH", str(self.index_path)), \
             mock.patch.object(fetch_history_linux, "CATALOG_PATH", str(self.catalog_path)), \
             mock.patch("urllib.request.urlopen", return_value=response), \
             mock.patch("time.sleep"), redirect_stdout(io.StringIO()):
            completed = fetch_history_linux.fetch_history(max_calls=1000)

        index = json.loads(self.index_path.read_text(encoding="utf-8"))
        self.assertTrue(completed, "a previous run's error must not park the cursor")
        self.assertEqual(index["coverage"], "COMPLETE")
        self.assertEqual(index["errors"], [])
        self.assertIn("Fetch error: The read operation timed out", index["error_history"])

    def test_corrupt_index_is_fatal_and_named(self):
        from scripts.studies import fetch_history_linux

        self.index_path.write_text('{"project": "linux", "window"', encoding="utf-8")
        self.catalog_path.write_text("", encoding="utf-8")
        with mock.patch.object(fetch_history_linux, "INDEX_PATH", str(self.index_path)), \
             mock.patch.object(fetch_history_linux, "CATALOG_PATH", str(self.catalog_path)), \
             mock.patch("time.sleep"):
            with self.assertRaises(CorruptStateError) as ctx:
                fetch_history_linux.fetch_history(max_calls=1)
        self.assertIn(str(self.index_path), str(ctx.exception))

    def test_complete_window_is_not_rewritten_as_incomplete(self):
        from scripts.studies import fetch_history_linux

        record = {"advisory_id": "CVE-2020-1234", "published": "2020-01-01"}
        self.catalog_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        self._write_index(coverage="COMPLETE", status="COMPLETE", cursor_date=None,
                          window_closed=True, entry_count=1, requests=113, resume=None)
        before = self.index_path.read_text(encoding="utf-8")

        with mock.patch.object(fetch_history_linux, "INDEX_PATH", str(self.index_path)), \
             mock.patch.object(fetch_history_linux, "CATALOG_PATH", str(self.catalog_path)), \
             mock.patch("urllib.request.urlopen") as urlopen, \
             mock.patch("time.sleep"), redirect_stdout(io.StringIO()):
            completed = fetch_history_linux.fetch_history(max_calls=1000)

        urlopen.assert_not_called()
        self.assertTrue(completed)
        self.assertEqual(self.index_path.read_text(encoding="utf-8"), before)
