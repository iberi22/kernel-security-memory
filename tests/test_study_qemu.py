"""Tests for QEMU security study offline contract validator and fetcher."""

import json
import os
import sys
import tempfile
import unittest

from scripts.studies.fetch_qemu import run_offline, is_host_allowlisted, classify_vulnerability


class StudyQemuOfflineTests(unittest.TestCase):

    def test_allowlisted_hosts(self):
        """Test host allowlist validation."""
        self.assertTrue(is_host_allowlisted("https://api.osv.dev/v1/query"))
        self.assertTrue(is_host_allowlisted("https://github.com/qemu/qemu/commit/1234567890123456789012345678901234567890"))
        self.assertTrue(is_host_allowlisted("https://gitlab.com/qemu-project/qemu/-/commit/1234567890123456789012345678901234567890"))
        self.assertFalse(is_host_allowlisted("http://unsecure-host.com/patch"))
        self.assertFalse(is_host_allowlisted("https://unauthorized-domain.com/patch"))

    def test_classify_vulnerability(self):
        """Test pattern family classification and sentence descriptions."""
        family, insecure, mitigation = classify_vulnerability({
            "id": "CVE-2022-26354",
            "details": "memory leakage in vhost-vsock error recovery path"
        })
        self.assertEqual(family, "memory-lifetime")
        self.assertIn("virtqueue", insecure)
        self.assertIn("patch", mitigation)

        fam_int, _, _ = classify_vulnerability({
            "id": "CVE-2023-42467",
            "details": "division by zero in scsi_disk_reset"
        })
        self.assertEqual(fam_int, "integer")

    def test_offline_fails_on_empty_directory(self):
        """Phase 1 requirement: --offline on an empty fixture exits 1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_offline(tmpdir)
            self.assertEqual(res, 1)

    def test_offline_fails_on_invalid_schema(self):
        """Verify offline check rejects invalid schema_version in study.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            study_file = os.path.join(tmpdir, "study.json")
            patterns_file = os.path.join(tmpdir, "patterns.md")

            study_data = {
                "schema_version": "invalid-schema",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {"id": "qemu", "repo": "https://github.com/qemu/qemu", "github": "qemu/qemu"},
                "coverage": "WINDOW_SAMPLED",
                "recorded": 0,
                "records": [],
                "counts_by_family": {},
                "notes": "Empty result observation."
            }
            with open(study_file, "w", encoding="utf-8") as f:
                json.dump(study_data, f)

            with open(patterns_file, "w", encoding="utf-8") as f:
                f.write("# QEMU\nWindow: 2026-06-09 .. 2026-10-08\n## Counts\n## Records\n## Limits\n")

            res = run_offline(tmpdir)
            self.assertEqual(res, 1)

    def test_offline_succeeds_on_valid_fixture(self):
        """Verify offline check succeeds on a perfectly valid slice fixture."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records_dir = os.path.join(tmpdir, "records")
            os.makedirs(records_dir, exist_ok=True)

            rec_file = os.path.join(records_dir, "qemu-CVE-2022-26354.json")
            rec_data = {
                "schema_version": "study-record-v1",
                "id": "qemu-CVE-2022-26354",
                "project": "qemu",
                "advisory_id": "CVE-2022-26354",
                "cwe": None,
                "cwe_state": "UNKNOWN",
                "pattern_family": "memory-lifetime",
                "pattern_family_status": "hypothesis",
                "fix": {
                    "sha": "8d1b247f3748ac4078524130c6d7ae42b6140aaf",
                    "url": "https://gitlab.com/qemu-project/qemu/-/commit/8d1b247f3748ac4078524130c6d7ae42b6140aaf",
                    "committed_at": "2022-03-16T14:02:34Z"
                },
                "insecure_pattern": "Vhost-vsock frees element without detaching from virtqueue.",
                "mitigation": "The patch detaches the element before freeing.",
                "evidence": [
                    {
                        "url": "https://api.osv.dev/v1/vulnerability/CVE-2022-26354",
                        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "observed_at": "2026-10-08T00:00:00Z"
                    }
                ],
                "limits": "Single advisory observation, not a ranking."
            }
            with open(rec_file, "w", encoding="utf-8") as f:
                json.dump(rec_data, f)

            study_file = os.path.join(tmpdir, "study.json")
            study_data = {
                "schema_version": "study-slice-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {"id": "qemu", "repo": "https://github.com/qemu/qemu", "github": "qemu/qemu"},
                "coverage": "WINDOW_SAMPLED",
                "method": {
                    "used_query": "https://api.osv.dev/v1/query",
                    "http_status": 200,
                    "examined": 40,
                    "limits": {"max_examined": 40, "max_records": 8}
                },
                "counts_by_family": {"memory-lifetime": 1},
                "recorded": 1,
                "records": ["records/qemu-CVE-2022-26354.json"],
                "skipped": [],
                "errors": [],
                "notes": "Sampled slice."
            }
            with open(study_file, "w", encoding="utf-8") as f:
                json.dump(study_data, f)

            patterns_file = os.path.join(tmpdir, "patterns.md")
            with open(patterns_file, "w", encoding="utf-8") as f:
                f.write("# QEMU Security Pattern Study\n\nWindow: 2026-06-09 .. 2026-10-08\n\n## Counts\n- memory-lifetime: 1\n\n## Records\n- qemu-CVE-2022-26354\n\n## Limits\nThis file is a slice.\n")

            res = run_offline(tmpdir)
            self.assertEqual(res, 0)


if __name__ == "__main__":
    unittest.main()
