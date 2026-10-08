"""Offline unittest for linux-net study slice."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from scripts.studies import fetch_linux_net

STUDY_JSON_PATH = os.path.join("docs", "studies", "fable-2026-06", "linux-net", "study.json")
PATTERNS_MD_PATH = os.path.join("docs", "studies", "fable-2026-06", "linux-net", "patterns.md")


class TestStudyLinuxNet(unittest.TestCase):
    def test_offline_validation_on_nonexistent_or_invalid_dir(self):
        """Test that validate_slice_offline fails if files are missing."""
        # Save current directory
        orig_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            try:
                result = fetch_linux_net.validate_slice_offline()
                self.assertFalse(result)
            finally:
                os.chdir(orig_cwd)

    def test_offline_cli_execution_fails_when_missing(self):
        """Test that CLI --offline exits non-zero when files are missing."""
        orig_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            try:
                res = subprocess.run(
                    [sys.executable, "-m", "scripts.studies.fetch_linux_net", "--offline"],
                    capture_output=True,
                )
                self.assertNotEqual(res.returncode, 0)
            finally:
                os.chdir(orig_cwd)

    def test_study_json_schema_offline(self):
        """Verify committed study.json schema and structure."""
        self.assertTrue(os.path.exists(STUDY_JSON_PATH), f"Missing {STUDY_JSON_PATH}")
        with open(STUDY_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("schema_version"), "study-slice-v1")
        self.assertEqual(
            data.get("window"),
            {
                "start": "2026-06-09",
                "end": "2026-10-08",
                "anchor": "Claude Fable 5 public announcement 2026-06-09",
            },
        )
        self.assertEqual(data.get("project", {}).get("id"), "linux")
        self.assertIn(data.get("coverage"), ("INCOMPLETE", "WINDOW_SAMPLED"))
        recorded = data.get("recorded")
        self.assertIsInstance(recorded, int)
        self.assertTrue(0 <= recorded <= 8)
        self.assertEqual(len(data.get("records", [])), recorded)
        self.assertEqual(sum(data.get("counts_by_family", {}).values()), recorded)
        self.assertTrue(data.get("notes"))

    def test_patterns_md_headings_offline(self):
        """Verify required headings and window line in patterns.md."""
        self.assertTrue(os.path.exists(PATTERNS_MD_PATH), f"Missing {PATTERNS_MD_PATH}")
        with open(PATTERNS_MD_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Window: 2026-06-09 .. 2026-10-08", content)
        self.assertIn("## Counts", content)
        self.assertIn("## Records", content)
        self.assertIn("## Limits", content)

    def test_fetch_linux_net_script_offline_pass(self):
        """Verify that python3 scripts/studies/fetch_linux_net.py --offline exits 0 on valid committed slice."""
        res = subprocess.run(
            [sys.executable, "scripts/studies/fetch_linux_net.py", "--offline"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Offline validation failed: {res.stderr}")


if __name__ == "__main__":
    unittest.main()
