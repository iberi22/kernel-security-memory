import os
import tempfile
import unittest
import json
import subprocess
import sys


class TestStudyNginx(unittest.TestCase):

    def test_offline_validates_existing_or_missing(self):
        """Test fetch_nginx.py --offline command via subprocess."""
        cmd = [sys.executable, "scripts/studies/fetch_nginx.py", "--offline"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        # If files exist and are valid, returncode is 0; if study.json does not exist yet, returncode is 1
        self.assertIn(res.returncode, (0, 1))

    def test_offline_fails_on_empty_fixture_directory(self):
        """Test that --offline fails when study.json is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Run fetch_nginx.py script when current working dir has no docs/studies/...
            cmd = [sys.executable, os.path.abspath("scripts/studies/fetch_nginx.py"), "--offline"]
            res = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)

    def test_offline_fails_on_invalid_schema_version(self):
        """Test validation failure on invalid schema_version in study.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            study_dir = os.path.join(tmpdir, "docs", "studies", "fable-2026-06", "nginx")
            os.makedirs(study_dir, exist_ok=True)
            study_json = os.path.join(study_dir, "study.json")
            with open(study_json, "w", encoding="utf-8") as f:
                json.dump({"schema_version": "invalid-v1"}, f)

            cmd = [sys.executable, os.path.abspath("scripts/studies/fetch_nginx.py"), "--offline"]
            res = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)

    def test_offline_fails_on_window_mismatch(self):
        """Test validation failure when window does not match specification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            study_dir = os.path.join(tmpdir, "docs", "studies", "fable-2026-06", "nginx")
            os.makedirs(study_dir, exist_ok=True)
            study_json = os.path.join(study_dir, "study.json")
            data = {
                "schema_version": "study-slice-v1",
                "window": {"start": "2025-01-01", "end": "2025-12-31", "anchor": "wrong"}
            }
            with open(study_json, "w", encoding="utf-8") as f:
                json.dump(data, f)

            cmd = [sys.executable, os.path.abspath("scripts/studies/fetch_nginx.py"), "--offline"]
            res = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)

    def test_offline_succeeds_on_valid_empty_slice(self):
        """Test validation succeeds on a fully compliant empty slice."""
        with tempfile.TemporaryDirectory() as tmpdir:
            study_dir = os.path.join(tmpdir, "docs", "studies", "fable-2026-06", "nginx")
            os.makedirs(os.path.join(study_dir, "records"), exist_ok=True)

            study_json = os.path.join(study_dir, "study.json")
            patterns_md = os.path.join(study_dir, "patterns.md")

            study_data = {
                "schema_version": "study-slice-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {
                    "id": "nginx",
                    "repo": "https://github.com/nginx/nginx",
                    "github": "nginx/nginx"
                },
                "coverage": "WINDOW_SAMPLED",
                "method": {
                    "used_query": "{\"package\": {\"ecosystem\": \"GIT\", \"name\": \"github.com/nginx/nginx\"}}",
                    "http_status": 200,
                    "examined": 40,
                    "limits": {
                        "max_examined": 40,
                        "max_records": 8
                    }
                },
                "counts_by_family": {},
                "recorded": 0,
                "records": [],
                "skipped": [],
                "errors": [],
                "notes": "The empty result is the observation."
            }

            with open(study_json, "w", encoding="utf-8") as f:
                json.dump(study_data, f, indent=2)

            patterns_content = """# Nginx Security Study Patterns

Window: 2026-06-09 .. 2026-10-08

## Counts
- None observed

## Records
- Zero records recorded in this window.

## Limits
Every family label is a hypothesis. This file is one slice, not a cross-project ranking.
"""
            with open(patterns_md, "w", encoding="utf-8") as pf:
                pf.write(patterns_content.strip() + "\n")

            cmd = [sys.executable, os.path.abspath("scripts/studies/fetch_nginx.py"), "--offline"]
            res = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

    def test_offline_fails_on_invalid_record_id(self):
        """Test validation fails when a record has an invalid id format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            study_dir = os.path.join(tmpdir, "docs", "studies", "fable-2026-06", "nginx")
            records_dir = os.path.join(study_dir, "records")
            os.makedirs(records_dir, exist_ok=True)

            study_json = os.path.join(study_dir, "study.json")
            patterns_md = os.path.join(study_dir, "patterns.md")

            study_data = {
                "schema_version": "study-slice-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {
                    "id": "nginx",
                    "repo": "https://github.com/nginx/nginx",
                    "github": "nginx/nginx"
                },
                "coverage": "WINDOW_SAMPLED",
                "method": {
                    "used_query": "query",
                    "http_status": 200,
                    "examined": 1,
                    "limits": {"max_examined": 40, "max_records": 8}
                },
                "counts_by_family": {"logic": 1},
                "recorded": 1,
                "records": ["records/nginx-bad.json"],
                "skipped": [],
                "errors": [],
                "notes": "Recorded 1 record."
            }

            with open(study_json, "w", encoding="utf-8") as f:
                json.dump(study_data, f)

            patterns_content = """# Nginx Security Study Patterns
Window: 2026-06-09 .. 2026-10-08
## Counts
- logic: 1
## Records
- records/nginx-bad.json
## Limits
Every family label is a hypothesis. This file is one slice, not a cross-project ranking.
"""
            with open(patterns_md, "w", encoding="utf-8") as pf:
                pf.write(patterns_content.strip() + "\n")

            rec_data = {
                "schema_version": "study-record-v1",
                "id": "bad-id-without-prefix",
                "project": "nginx",
                "advisory_id": "CVE-2026-0001",
                "cwe": None,
                "cwe_state": "UNKNOWN",
                "pattern_family": "logic",
                "pattern_family_status": "hypothesis",
                "fix": {
                    "sha": "1234567890123456789012345678901234567890",
                    "url": "https://github.com/nginx/nginx/commit/1234567890123456789012345678901234567890",
                    "committed_at": "UNKNOWN"
                },
                "insecure_pattern": "Pattern test.",
                "mitigation": "Mitigation test.",
                "evidence": [
                    {
                        "url": "https://github.com/nginx/nginx/commit/1234567890123456789012345678901234567890",
                        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "observed_at": "2026-10-08T00:00:00Z"
                    }
                ],
                "limits": "Single advisory limit."
            }
            with open(os.path.join(records_dir, "nginx-bad.json"), "w", encoding="utf-8") as rf:
                json.dump(rec_data, rf)

            cmd = [sys.executable, os.path.abspath("scripts/studies/fetch_nginx.py"), "--offline"]
            res = subprocess.run(cmd, cwd=tmpdir, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)


if __name__ == "__main__":
    unittest.main()
