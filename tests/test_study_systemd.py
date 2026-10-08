"""Unit tests for systemd study slice fetcher and offline validator."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

# Import functions from fetch_systemd script
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "studies"))
import fetch_systemd


class TestStudySystemd(unittest.TestCase):
    """Test suite for systemd study fetcher and offline contract validator."""

    def test_in_window(self):
        """Test window filtering logic for 2026-06-09..2026-10-08."""
        self.assertTrue(fetch_systemd.in_window("2026-06-09"))
        self.assertTrue(fetch_systemd.in_window("2026-07-15"))
        self.assertTrue(fetch_systemd.in_window("2026-10-08"))
        self.assertFalse(fetch_systemd.in_window("2026-06-08"))
        self.assertFalse(fetch_systemd.in_window("2026-10-09"))
        self.assertFalse(fetch_systemd.in_window("2025-01-01"))
        self.assertFalse(fetch_systemd.in_window("UNKNOWN"))

    def test_categorize_pattern_family(self):
        """Test classification of vulnerability summaries into pattern families."""
        self.assertEqual(fetch_systemd.categorize_pattern_family("use-after-free in systemd-resolved"), "memory-lifetime")
        self.assertEqual(fetch_systemd.categorize_pattern_family("out-of-bounds read in journald"), "bounds")
        self.assertEqual(fetch_systemd.categorize_pattern_family("integer overflow in systemd-tmpfiles"), "integer")
        self.assertEqual(fetch_systemd.categorize_pattern_family("privilege escalation via polkit authorization"), "authz")
        self.assertEqual(fetch_systemd.categorize_pattern_family("unknown issue in systemd"), "unknown")

    def test_url_host_validation(self):
        """Test host allowlist validation for evidence and fix URLs."""
        self.assertTrue(fetch_systemd.validate_url_host("https://github.com/systemd/systemd/commit/1122334455667788990011223344556677889900"))
        self.assertTrue(fetch_systemd.validate_url_host("https://api.osv.dev/v1/vulns/GHSA-1234"))
        self.assertFalse(fetch_systemd.validate_url_host("http://github.com/systemd/systemd/commit/123"))
        self.assertFalse(fetch_systemd.validate_url_host("https://untrusted-domain.com/patch"))

    def test_offline_check_missing_files(self):
        """Test that offline validation fails when study files are absent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Change working directory to empty temp dir so default paths won't exist
            cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                cmd = [sys.executable, os.path.join(cwd, "scripts", "studies", "fetch_systemd.py"), "--offline"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("OFFLINE CHECK ERROR", res.stderr)
            finally:
                os.chdir(cwd)

    def test_offline_check_valid_fixture(self):
        """Test that offline validation succeeds on a valid study fixture."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                study_dir = os.path.join("docs", "studies", "fable-2026-06", "systemd")
                os.makedirs(os.path.join(study_dir, "records"), exist_ok=True)

                study_json = {
                    "schema_version": "study-slice-v1",
                    "window": {
                        "start": "2026-06-09",
                        "end": "2026-10-08",
                        "anchor": "Claude Fable 5 public announcement 2026-06-09"
                    },
                    "project": {
                        "id": "systemd",
                        "repo": "https://github.com/systemd/systemd",
                        "github": "systemd/systemd"
                    },
                    "coverage": "INCOMPLETE",
                    "method": {
                        "used_query": "https://api.osv.dev/v1/query",
                        "http_status": 200,
                        "examined": 0,
                        "limits": {"max_examined": 40, "max_records": 8}
                    },
                    "counts_by_family": {f: 0 for f in fetch_systemd.PATTERN_FAMILIES},
                    "recorded": 0,
                    "records": [],
                    "skipped": [],
                    "errors": [],
                    "notes": "No qualifying security advisories found for systemd in the window 2026-06-09 through 2026-10-08; empty result is the observation."
                }
                with open(os.path.join(study_dir, "study.json"), "w", encoding="utf-8") as f:
                    json.dump(study_json, f, indent=2)

                patterns_md = fetch_systemd.generate_patterns_md(study_json["counts_by_family"], [])
                with open(os.path.join(study_dir, "patterns.md"), "w", encoding="utf-8") as f:
                    f.write(patterns_md)

                cmd = [sys.executable, os.path.join(cwd, "scripts", "studies", "fetch_systemd.py"), "--offline"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
            finally:
                os.chdir(cwd)

    def test_offline_check_invalid_fixture_notes(self):
        """Test that offline validation fails when recorded=0 but notes missing empty observation statement."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                study_dir = os.path.join("docs", "studies", "fable-2026-06", "systemd")
                os.makedirs(os.path.join(study_dir, "records"), exist_ok=True)

                study_json = {
                    "schema_version": "study-slice-v1",
                    "window": {
                        "start": "2026-06-09",
                        "end": "2026-10-08",
                        "anchor": "Claude Fable 5 public announcement 2026-06-09"
                    },
                    "project": {
                        "id": "systemd",
                        "repo": "https://github.com/systemd/systemd",
                        "github": "systemd/systemd"
                    },
                    "coverage": "INCOMPLETE",
                    "method": {
                        "used_query": "https://api.osv.dev/v1/query",
                        "http_status": 200,
                        "examined": 0,
                        "limits": {"max_examined": 40, "max_records": 8}
                    },
                    "counts_by_family": {f: 0 for f in fetch_systemd.PATTERN_FAMILIES},
                    "recorded": 0,
                    "records": [],
                    "skipped": [],
                    "errors": [],
                    "notes": "Invalid notes string."
                }
                with open(os.path.join(study_dir, "study.json"), "w", encoding="utf-8") as f:
                    json.dump(study_json, f, indent=2)

                patterns_md = fetch_systemd.generate_patterns_md(study_json["counts_by_family"], [])
                with open(os.path.join(study_dir, "patterns.md"), "w", encoding="utf-8") as f:
                    f.write(patterns_md)

                cmd = [sys.executable, os.path.join(cwd, "scripts", "studies", "fetch_systemd.py"), "--offline"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("OFFLINE CHECK ERROR", res.stderr)
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
