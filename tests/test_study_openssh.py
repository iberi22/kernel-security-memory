"""Unit tests for OpenSSH study slice fetcher and contract validator.

Runs offline without network requests.
"""

import json
import os
import shutil
import tempfile
import unittest

from scripts.studies.fetch_openssh import (
    validate_slice_offline,
    validate_record_file,
    is_url_allowlisted,
    STUDY_BASE_DIR,
)


class TestStudyOpenSSH(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_committed_slice_valid(self):
        """Verify that the committed study slice in docs/ passes offline validation."""
        self.assertTrue(validate_slice_offline(STUDY_BASE_DIR))

    def test_url_allowlist(self):
        """Test URL allowlisting logic."""
        self.assertTrue(is_url_allowlisted("https://api.osv.dev/v1/query"))
        self.assertTrue(is_url_allowlisted("https://github.com/openssh/openssh-portable"))
        self.assertFalse(is_url_allowlisted("http://github.com/openssh/openssh-portable"))
        self.assertFalse(is_url_allowlisted("https://malicious-site.com/exploit"))

    def test_record_file_validation_success(self):
        """Test record file validator with valid data."""
        rec_path = os.path.join(self.tmpdir, "openssh-CVE-2026-0001.json")
        rec_data = {
            "schema_version": "study-record-v1",
            "id": "openssh-CVE-2026-0001",
            "project": "openssh",
            "advisory_id": "CVE-2026-0001",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "1234567890abcdef1234567890abcdef12345678",
                "url": "https://github.com/openssh/openssh-portable/commit/1234567890abcdef1234567890abcdef12345678",
                "committed_at": "UNKNOWN",
            },
            "insecure_pattern": "Insecure logic check.",
            "mitigation": "Mitigated logic check.",
            "evidence": [
                {
                    "url": "https://github.com/openssh/openssh-portable/commit/1234567890abcdef1234567890abcdef12345678",
                    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "observed_at": "2026-10-08T00:00:00Z",
                }
            ],
            "limits": "Single advisory observation.",
        }
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        ok, err = validate_record_file(rec_path)
        self.assertTrue(ok, f"Expected valid record but got error: {err}")

    def test_record_file_invalid_schema(self):
        """Test record file validator rejects invalid schema version."""
        rec_path = os.path.join(self.tmpdir, "openssh-CVE-2026-0002.json")
        rec_data = {
            "schema_version": "study-record-v0",
            "id": "openssh-CVE-2026-0002",
        }
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        ok, err = validate_record_file(rec_path)
        self.assertFalse(ok)
        self.assertIn("Invalid schema_version", err)

    def test_record_file_invalid_sha(self):
        """Test record file validator rejects short or non-hex commit SHA."""
        rec_path = os.path.join(self.tmpdir, "openssh-CVE-2026-0003.json")
        rec_data = {
            "schema_version": "study-record-v1",
            "id": "openssh-CVE-2026-0003",
            "project": "openssh",
            "advisory_id": "CVE-2026-0003",
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": "shortsha123",
                "url": "https://github.com/openssh/openssh-portable",
            },
            "insecure_pattern": "Pattern.",
            "mitigation": "Mitigation.",
            "evidence": [],
            "limits": "Limits.",
        }
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f)

        ok, err = validate_record_file(rec_path)
        self.assertFalse(ok)
        self.assertIn("Invalid fix sha", err)

    def test_slice_offline_missing_file(self):
        """Test offline slice validator fails when study.json is missing."""
        empty_dir = os.path.join(self.tmpdir, "empty_slice")
        os.makedirs(empty_dir, exist_ok=True)
        self.assertFalse(validate_slice_offline(empty_dir))


if __name__ == "__main__":
    unittest.main()
