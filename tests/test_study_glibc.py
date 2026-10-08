import json
import tempfile
import unittest
from pathlib import Path
from scripts.studies.fetch_glibc import validate_offline, classify_pattern_family


class TestStudyGlibcOffline(unittest.TestCase):
    """Offline unit tests for glibc study slice validator and classifier."""

    def test_classify_pattern_family(self):
        # Authz
        adv_authz = {
            "id": "CVE-2025-4802",
            "details": "Untrusted LD_LIBRARY_PATH environment variable vulnerability in setuid binaries",
            "database_specific": {"cwe_ids": ["CWE-426"]}
        }
        self.assertEqual(classify_pattern_family(adv_authz), "authz")

        # Bounds
        adv_bounds = {
            "id": "CVE-2022-23218",
            "details": "Buffer overflow in svcunix_create out-of-bounds write",
            "database_specific": {"cwe_ids": ["CWE-120"]}
        }
        self.assertEqual(classify_pattern_family(adv_bounds), "bounds")

        # Memory lifetime
        adv_mem = {
            "id": "CVE-2023-4806",
            "details": "Use-after-free in getaddrinfo function",
            "database_specific": {"cwe_ids": ["CWE-416"]}
        }
        self.assertEqual(classify_pattern_family(adv_mem), "memory-lifetime")

        # Integer
        adv_int = {
            "id": "CVE-2021-3998",
            "details": "Integer overflow in realpath wraparound",
            "database_specific": {"cwe_ids": ["CWE-190"]}
        }
        self.assertEqual(classify_pattern_family(adv_int), "integer")

    def test_validate_offline_empty_dir_fails(self):
        with tempfile.TemporaryDirectory() as td:
            base_dir = Path(td)
            # Empty directory should fail offline validation
            self.assertFalse(validate_offline(base_dir))

    def test_validate_offline_valid_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            base_dir = Path(td)
            rec_dir = base_dir / "records"
            rec_dir.mkdir(parents=True, exist_ok=True)

            record_id = "glibc-CVE-2025-4802"
            record_rel = f"records/{record_id}.json"
            rec_data = {
                "schema_version": "study-record-v1",
                "id": record_id,
                "project": "glibc",
                "advisory_id": "CVE-2025-4802",
                "cwe": "CWE-426",
                "cwe_state": "STATED_BY_ADVISORY",
                "pattern_family": "authz",
                "pattern_family_status": "hypothesis",
                "fix": {
                    "sha": "1e18586c5820e329f741d5c710275e165581380e",
                    "url": "https://sourceware.org/cgit/glibc/commit/?id=1e18586c5820e329f741d5c710275e165581380e",
                    "committed_at": "UNKNOWN"
                },
                "insecure_pattern": "The setuid check failed to validate environment variable configuration.",
                "mitigation": "Enforce strict checks on runtime library paths for setuid applications.",
                "evidence": [
                    {
                        "url": "https://sourceware.org/cgit/glibc/commit/?id=1e18586c5820e329f741d5c710275e165581380e",
                        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "observed_at": "2026-10-08T00:00:00Z"
                    }
                ],
                "limits": "This record represents a single glibc security advisory and is not a global security ranking."
            }
            (base_dir / record_rel).write_text(json.dumps(rec_data, indent=2), encoding="utf-8")

            study_data = {
                "schema_version": "study-slice-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {
                    "id": "glibc",
                    "repo": "https://github.com/bminor/glibc",
                    "github": "bminor/glibc"
                },
                "coverage": "WINDOW_SAMPLED",
                "method": {
                    "used_query": "https://api.osv.dev/v1/query",
                    "http_status": 200,
                    "examined": 1,
                    "limits": {
                        "max_examined": 40,
                        "max_records": 8
                    }
                },
                "counts_by_family": {"authz": 1},
                "recorded": 1,
                "records": [record_rel],
                "skipped": [],
                "errors": [],
                "notes": "Sampled 1 glibc security advisory."
            }
            (base_dir / "study.json").write_text(json.dumps(study_data, indent=2), encoding="utf-8")

            patterns_content = (
                "# glibc Security Fix Patterns\n"
                "Window: 2026-06-09 .. 2026-10-08\n\n"
                "## Counts\n"
                "- authz: 1\n\n"
                "## Records\n"
                f"- {record_rel}\n\n"
                "## Limits\n"
                "This file is one slice for glibc, not a cross-project ranking.\n"
            )
            (base_dir / "patterns.md").write_text(patterns_content, encoding="utf-8")

            self.assertTrue(validate_offline(base_dir))

    def test_validate_offline_invalid_schema_version(self):
        with tempfile.TemporaryDirectory() as td:
            base_dir = Path(td)
            study_data = {
                "schema_version": "invalid-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {"id": "glibc"},
                "coverage": "WINDOW_SAMPLED",
                "recorded": 0,
                "records": [],
                "counts_by_family": {},
                "notes": "Empty study"
            }
            (base_dir / "study.json").write_text(json.dumps(study_data), encoding="utf-8")
            (base_dir / "patterns.md").write_text("# glibc\nWindow: 2026-06-09 .. 2026-10-08\n## Counts\n## Records\n## Limits\n")
            self.assertFalse(validate_offline(base_dir))

    def test_validate_offline_invalid_host_fails(self):
        with tempfile.TemporaryDirectory() as td:
            base_dir = Path(td)
            rec_dir = base_dir / "records"
            rec_dir.mkdir(parents=True, exist_ok=True)

            record_id = "glibc-CVE-2025-4802"
            record_rel = f"records/{record_id}.json"
            rec_data = {
                "schema_version": "study-record-v1",
                "id": record_id,
                "project": "glibc",
                "advisory_id": "CVE-2025-4802",
                "cwe": None,
                "cwe_state": "UNKNOWN",
                "pattern_family": "authz",
                "pattern_family_status": "hypothesis",
                "fix": {
                    "sha": "1e18586c5820e329f741d5c710275e165581380e",
                    "url": "https://unauthorized-domain.com/commit/1e185",
                    "committed_at": "UNKNOWN"
                },
                "insecure_pattern": "Missing check.",
                "mitigation": "Add check.",
                "evidence": [
                    {
                        "url": "https://unauthorized-domain.com/commit/1e185",
                        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "observed_at": "2026-10-08T00:00:00Z"
                    }
                ],
                "limits": "Single advisory limit."
            }
            (base_dir / record_rel).write_text(json.dumps(rec_data, indent=2), encoding="utf-8")

            study_data = {
                "schema_version": "study-slice-v1",
                "window": {
                    "start": "2026-06-09",
                    "end": "2026-10-08",
                    "anchor": "Claude Fable 5 public announcement 2026-06-09"
                },
                "project": {"id": "glibc"},
                "coverage": "WINDOW_SAMPLED",
                "recorded": 1,
                "records": [record_rel],
                "counts_by_family": {"authz": 1},
                "notes": "Sampled"
            }
            (base_dir / "study.json").write_text(json.dumps(study_data), encoding="utf-8")
            (base_dir / "patterns.md").write_text("# glibc\nWindow: 2026-06-09 .. 2026-10-08\n## Counts\n## Records\n## Limits\n")

            self.assertFalse(validate_offline(base_dir))


if __name__ == "__main__":
    unittest.main()
