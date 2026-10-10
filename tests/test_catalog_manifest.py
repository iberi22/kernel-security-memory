#!/usr/bin/env python3
"""Unit tests for build_catalog_manifest and catalog status classification."""

from pathlib import Path
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from build_catalog_manifest import determine_status, generate_manifest, verify_manifest


class TestCatalogManifest(unittest.TestCase):
    def test_generate_manifest_structure(self):
        manifest = generate_manifest()
        self.assertEqual(manifest["schema_version"], "cve-catalog-manifest-v1")
        self.assertGreaterEqual(manifest["project_count"], 12)
        self.assertGreaterEqual(manifest["total_entries"], 400)
        self.assertIn("projects", manifest)
        self.assertIn("status_summary", manifest)
        # Status counts must account for every project; the snapshot catalogs
        # (linux-cna, curl-upstream, openssl-upstream) are SNAPSHOT_COMPLETE.
        self.assertEqual(sum(manifest["status_summary"].values()), manifest["project_count"])
        self.assertGreaterEqual(manifest["status_summary"]["SNAPSHOT_COMPLETE"], 3)

        for proj in manifest["projects"]:
            self.assertIn("name", proj)
            self.assertIn("entry_count", proj)
            self.assertIn("status", proj)
            self.assertIn("window_closed", proj)
            self.assertIn("files", proj)
            self.assertIn("index_json", proj["files"])
            self.assertIn("catalog_jsonl", proj["files"])
            self.assertEqual(len(proj["files"]["catalog_jsonl"]["sha256"]), 64)

    def test_cursor_paused_five_projects(self):
        """Verify the 5 projects with partial cursors have CURSOR_PAUSED and valid cursor dates."""
        manifest = generate_manifest()
        projects_by_name = {p["name"]: p for p in manifest["projects"]}

        expected_paused = {
            "linux": "2007-06-22",
            "openssl": "2012-10-19",
            "curl": "2006-08-22",
            "glibc": "2000-12-21",
            "openssh": "2001-06-19",
        }

        for name, expected_cursor in expected_paused.items():
            self.assertIn(name, projects_by_name)
            proj = projects_by_name[name]
            self.assertEqual(proj["status"], "CURSOR_PAUSED", f"{name} must be CURSOR_PAUSED")
            self.assertEqual(proj["cursor_date"], expected_cursor, f"{name} cursor mismatch")
            self.assertFalse(proj["window_closed"], f"{name} window must NOT be closed")
            self.assertGreater(proj["entry_count"], 0)

    def test_nvd_keyword_projects_are_paused_not_complete(self):
        """The 7 NVD keyword catalogs fetched on 2026-10-09 stay honestly CURSOR_PAUSED."""
        manifest = generate_manifest()
        projects_by_name = {p["name"]: p for p in manifest["projects"]}
        for name in ["git", "postgresql", "qemu", "sqlite", "systemd", "unbound", "nginx"]:
            self.assertIn(name, projects_by_name)
            proj = projects_by_name[name]
            self.assertEqual(proj["status"], "CURSOR_PAUSED", f"{name} must be CURSOR_PAUSED")
            self.assertIsNotNone(proj["cursor_date"])
            self.assertFalse(proj["window_closed"])

    def test_snapshot_catalogs_are_closed(self):
        manifest = generate_manifest()
        projects_by_name = {p["name"]: p for p in manifest["projects"]}
        for name in ["linux-cna", "curl-upstream", "openssl-upstream"]:
            proj = projects_by_name[name]
            self.assertEqual(proj["status"], "SNAPSHOT_COMPLETE")
            self.assertTrue(proj["window_closed"])
            self.assertGreater(proj["entry_count"], 0)

    def test_determine_status_logic(self):
        """Test distinction between NOT_FETCHED, OBSERVED_EMPTY, CURSOR_PAUSED, and COMPLETE."""
        # 1. Un-fetched scaffold (0 entries, 0 bytes, requests 0, cursor at start)
        idx_scaffold = {
            "coverage": "INCOMPLETE",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "requests": 0,
            "resume": {"next_start_date": "1999-01-01"},
        }
        status, cursor, closed = determine_status(idx_scaffold, entries=0, catalog_bytes=0)
        self.assertEqual(status, "NOT_FETCHED")
        self.assertIsNone(cursor)
        self.assertFalse(closed)

        # 2. Observed genuinely empty (COMPLETE coverage, 0 entries)
        idx_observed_empty = {
            "coverage": "COMPLETE",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "requests": 150,
            "resume": None,
        }
        status, cursor, closed = determine_status(idx_observed_empty, entries=0, catalog_bytes=0)
        self.assertEqual(status, "OBSERVED_EMPTY")
        self.assertIsNone(cursor)
        self.assertTrue(closed)

        # 3. Cursor paused (INCOMPLETE coverage, cursor advanced)
        idx_paused = {
            "coverage": "INCOMPLETE",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "requests": 35,
            "resume": {"next_start_date": "2007-06-22"},
        }
        status, cursor, closed = determine_status(idx_paused, entries=338, catalog_bytes=89305)
        self.assertEqual(status, "CURSOR_PAUSED")
        self.assertEqual(cursor, "2007-06-22")
        self.assertFalse(closed)

        # 4. Truly complete with entries
        idx_complete = {
            "coverage": "COMPLETE",
            "window": {"start": "1999-01-01", "end": "2026-10-08"},
            "requests": 150,
            "resume": None,
        }
        status, cursor, closed = determine_status(idx_complete, entries=120, catalog_bytes=15000)
        self.assertEqual(status, "COMPLETE")
        self.assertIsNone(cursor)
        self.assertTrue(closed)

        # 5. Upstream snapshot catalog
        idx_snapshot = {"coverage": "COMPLETE_AT_COMMIT", "status": "FETCHED"}
        status, cursor, closed = determine_status(idx_snapshot, entries=10, catalog_bytes=100)
        self.assertEqual(status, "SNAPSHOT_COMPLETE")
        self.assertTrue(closed)
        # FETCHED without a complete-snapshot coverage must not be promoted
        status, _, _ = determine_status({"coverage": "INCOMPLETE", "status": "FETCHED"}, 0, 0)
        self.assertNotEqual(status, "SNAPSHOT_COMPLETE")

    def test_verify_manifest_offline(self):
        """Verify on-disk manifest passes self-check."""
        self.assertTrue(verify_manifest())

    def test_verify_manifest_detects_stale_fix_sha_total(self):
        import build_catalog_manifest as bcm
        import io, json, tempfile
        from contextlib import redirect_stderr, redirect_stdout
        data = json.loads(bcm.MANIFEST_FILE.read_text(encoding="utf-8"))
        data["total_with_fix_sha"] -= 1
        original = bcm.MANIFEST_FILE
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "manifest.json"
            stale.write_text(json.dumps(data), encoding="utf-8")
            bcm.MANIFEST_FILE = stale
            try:
                with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                    self.assertFalse(bcm.verify_manifest())
            finally:
                bcm.MANIFEST_FILE = original


if __name__ == "__main__":
    unittest.main()
