#!/usr/bin/env python3
"""Unit tests for enrich_fix_shas script and SHA validation rules."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from enrich_fix_shas import (
    SHA_RE,
    ROOT,
    VETTED_SHAS_SIDECAR,
    extract_commit_shas_from_urls,
    enrich_catalog,
    check_sha_in_mirror,
    extract_vetted_shas_records,
    generate_vetted_shas_sidecar,
    load_vetted_shas,
)


class TestEnrichFixShas(unittest.TestCase):
    def test_sha_regex(self):
        valid = "34fa79a6cde56d6d428ab0d3160cb094ebad3305"
        self.assertTrue(SHA_RE.fullmatch(valid))
        self.assertFalse(SHA_RE.fullmatch("34fa79a6"))
        self.assertFalse(SHA_RE.fullmatch("34FA79A6CDE56D6D428AB0D3160CB094EBAD3305"))
        self.assertFalse(SHA_RE.fullmatch(valid + "g"))

    def test_extract_commit_shas_from_urls(self):
        urls = [
            "https://github.com/git/git/commit/34fa79a6cde56d6d428ab0d3160cb094ebad3305",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a66268f1f8c5f3ca4ede7f2d0093249924ab3a96",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
        ]
        shas = extract_commit_shas_from_urls(urls)
        self.assertEqual(len(shas), 2)
        self.assertIn("34fa79a6cde56d6d428ab0d3160cb094ebad3305", shas)
        self.assertIn("a66268f1f8c5f3ca4ede7f2d0093249924ab3a96", shas)

    def test_enrich_catalog_integration(self):
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            index_file = pdir / "index.json"
            catalog_file = pdir / "catalog.jsonl"

            index_file.write_text(json.dumps({
                "schema_version": "cve-history-v1",
                "project": "sample",
                "entry_count": 2,
                "with_fix_sha": 0,
            }))

            catalog_file.write_text(
                json.dumps({
                    "advisory_id": "CVE-2021-1111",
                    "published": "2021-01-01",
                    "cwe": None,
                    "cwe_state": "UNKNOWN",
                    "patch_urls": ["https://github.com/sample/sample/commit/1111111111111111111111111111111111111111"],
                    "fix_shas": [],
                }) + "\n" +
                json.dumps({
                    "advisory_id": "CVE-2021-2222",
                    "published": "2021-02-01",
                    "cwe": "CWE-119",
                    "cwe_state": "STATED_BY_ADVISORY",
                    "patch_urls": ["https://example.com/advisory"],
                    "fix_shas": [],
                }) + "\n"
            )

            vetted = {
                "CVE-2021-2222": {"2222222222222222222222222222222222222222"}
            }

            rep = enrich_catalog(pdir, vetted, dry_run=False)
            self.assertEqual(rep["with_fix_sha"], 2)
            self.assertEqual(rep["overlap"], 1)

            updated_index = json.loads(index_file.read_text())
            self.assertEqual(updated_index["with_fix_sha"], 2)

            updated_lines = [json.loads(l) for l in catalog_file.read_text().splitlines()]
            self.assertEqual(updated_lines[0]["fix_shas"], ["1111111111111111111111111111111111111111"])
            self.assertEqual(updated_lines[0]["sha_status"], "MIRROR_UNCHECKED")
            self.assertEqual(updated_lines[1]["fix_shas"], ["2222222222222222222222222222222222222222"])
            self.assertEqual(updated_lines[1]["sha_status"], "MIRROR_UNCHECKED")

    def test_b1_zero_overlap_honest_reporting(self):
        """B1: When overlap is zero, report honestly and do NOT print 'Enrichment complete and verified'."""
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            index_file = pdir / "index.json"
            catalog_file = pdir / "catalog.jsonl"

            index_file.write_text(json.dumps({
                "schema_version": "cve-history-v1",
                "project": "sample",
                "entry_count": 1,
                "with_fix_sha": 0,
            }))

            catalog_file.write_text(
                json.dumps({
                    "advisory_id": "CVE-2000-0001",
                    "published": "2000-01-01",
                    "cwe": None,
                    "cwe_state": "UNKNOWN",
                    "patch_urls": ["https://example.com/advisory"],
                    "fix_shas": [],
                }) + "\n"
            )

            vetted = {
                "CVE-2026-9999": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
            }

            rep = enrich_catalog(pdir, vetted, dry_run=True)
            self.assertEqual(rep["overlap"], 0)
            self.assertEqual(rep["matches"], 0)
            self.assertEqual(rep["with_fix_sha"], 0)

        # Run script on real tree with --dry-run and verify terminal message
        res = subprocess.run(
            [sys.executable, str(ROOT / "scripts/studies/enrich_fix_shas.py"), "--dry-run"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Catalog scanned: 0 overlaps found with vetted records", res.stdout)
        self.assertIn("overlap: 0", res.stdout)
        self.assertIn("0 matches", res.stdout)
        self.assertNotIn("Enrichment complete and verified", res.stdout)

        # Also verify --check mode honest output
        res_check = subprocess.run(
            [sys.executable, str(ROOT / "scripts/studies/enrich_fix_shas.py"), "--check"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Catalog scanned: 0 overlaps found with vetted records", res_check.stdout)
        self.assertNotIn("Verification successful", res_check.stdout)

    def test_b2_git_mirror_verification(self):
        """B2: Check candidate SHAs against local git mirror and record NOT_IN_MIRROR or MIRROR_UNCHECKED."""
        with tempfile.TemporaryDirectory() as git_td:
            git_dir = Path(git_td)
            # Initialize a real git repo and make a commit
            subprocess.run(["git", "init", str(git_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            subprocess.run(["git", "-C", str(git_dir), "config", "user.name", "Tester"], check=True)
            subprocess.run(["git", "-C", str(git_dir), "config", "user.email", "tester@example.com"], check=True)
            (git_dir / "file.txt").write_text("test commit content\n")
            subprocess.run(["git", "-C", str(git_dir), "add", "file.txt"], check=True)
            subprocess.run(["git", "-C", str(git_dir), "commit", "-m", "initial commit"], stdout=subprocess.DEVNULL, check=True)

            rev_res = subprocess.run(["git", "-C", str(git_dir), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
            real_sha = rev_res.stdout.strip().lower()
            fake_sha = "0000000000000000000000000000000000000000"

            self.assertTrue(check_sha_in_mirror(git_dir, real_sha))
            self.assertFalse(check_sha_in_mirror(git_dir, fake_sha))

            with tempfile.TemporaryDirectory() as cat_td:
                pdir = Path(cat_td)
                index_file = pdir / "index.json"
                catalog_file = pdir / "catalog.jsonl"

                index_file.write_text(json.dumps({
                    "schema_version": "cve-history-v1",
                    "project": "sample",
                    "entry_count": 3,
                    "with_fix_sha": 0,
                }))

                catalog_file.write_text(
                    json.dumps({
                        "advisory_id": "CVE-2021-0001",
                        "published": "2021-01-01",
                        "patch_urls": [f"https://example.com/commit/{real_sha}"],
                        "fix_shas": [],
                    }) + "\n" +
                    json.dumps({
                        "advisory_id": "CVE-2021-0002",
                        "published": "2021-01-02",
                        "patch_urls": [f"https://example.com/commit/{fake_sha}"],
                        "fix_shas": [],
                    }) + "\n" +
                    json.dumps({
                        "advisory_id": "CVE-2021-0003",
                        "published": "2021-01-03",
                        "patch_urls": [],
                        "fix_shas": [],
                    }) + "\n"
                )

                # Test with git_dir passed explicitly
                rep = enrich_catalog(pdir, vetted_shas={}, dry_run=False, git_dir=git_dir)
                self.assertEqual(rep["with_fix_sha"], 2)

                lines = [json.loads(l) for l in catalog_file.read_text().splitlines()]
                self.assertEqual(lines[0]["sha_status"], "VERIFIED_IN_MIRROR")
                self.assertEqual(lines[0]["mirror_status"], "VERIFIED_IN_MIRROR")
                self.assertEqual(lines[0]["sha_statuses"][real_sha], "VERIFIED_IN_MIRROR")

                self.assertEqual(lines[1]["sha_status"], "NOT_IN_MIRROR")
                self.assertEqual(lines[1]["mirror_status"], "NOT_IN_MIRROR")
                self.assertEqual(lines[1]["sha_statuses"][fake_sha], "NOT_IN_MIRROR")

                self.assertEqual(lines[2]["sha_status"], "NOT_JOINED")
                self.assertEqual(lines[2]["mirror_status"], "NOT_JOINED")

                # Test with KSM_GIT_MIRROR env var
                os.environ["KSM_GIT_MIRROR"] = str(git_dir)
                try:
                    rep_env = enrich_catalog(pdir, vetted_shas={}, dry_run=False, git_dir=None)
                    self.assertEqual(rep_env["with_fix_sha"], 2)
                    lines_env = [json.loads(l) for l in catalog_file.read_text().splitlines()]
                    self.assertEqual(lines_env[0]["sha_status"], "VERIFIED_IN_MIRROR")
                    self.assertEqual(lines_env[1]["sha_status"], "NOT_IN_MIRROR")
                finally:
                    del os.environ["KSM_GIT_MIRROR"]

                # Test when no mirror is configured
                rep_none = enrich_catalog(pdir, vetted_shas={}, dry_run=False, git_dir=None)
                lines_none = [json.loads(l) for l in catalog_file.read_text().splitlines()]
                self.assertEqual(lines_none[0]["sha_status"], "MIRROR_UNCHECKED")
                self.assertEqual(lines_none[1]["sha_status"], "MIRROR_UNCHECKED")
                self.assertEqual(lines_none[2]["sha_status"], "NOT_JOINED")

    def test_b3_vetted_shas_sidecar(self):
        """B3: Sidecar vetted-shas.jsonl cleanly extracts all 34 unique SHAs from Fable records."""
        self.assertTrue(VETTED_SHAS_SIDECAR.exists(), "Sidecar file docs/studies/vetted-shas.jsonl must exist")

        lines = [line.strip() for line in VETTED_SHAS_SIDECAR.read_text().splitlines() if line.strip()]
        self.assertEqual(len(lines), 34, "Must contain exactly 34 records")

        shas = set()
        advisories = set()

        for idx, line in enumerate(lines, 1):
            record = json.loads(line)
            # Verify required keys
            for key in ["advisory_id", "fix_sha", "project", "record_file"]:
                self.assertIn(key, record, f"Line {idx} missing key {key}")

            adv = record["advisory_id"]
            sha = record["fix_sha"]
            proj = record["project"]
            rec_file = record["record_file"]

            self.assertTrue(SHA_RE.fullmatch(sha), f"Line {idx} has invalid SHA format: {sha}")
            self.assertEqual(sha, sha.lower(), f"Line {idx} SHA must be lowercase")
            self.assertTrue((ROOT / rec_file).exists(), f"Line {idx} record_file does not exist: {rec_file}")
            self.assertTrue(len(proj) > 0, f"Line {idx} project cannot be empty")
            self.assertTrue(len(adv) > 0, f"Line {idx} advisory_id cannot be empty")

            shas.add(sha)
            advisories.add(adv)

        self.assertEqual(len(shas), 34, "All 34 vetted SHAs must be unique")
        self.assertEqual(len(advisories), 34, "All 34 vetted advisories must be unique")

        # Test deterministic reproduction
        with tempfile.TemporaryDirectory() as td:
            temp_sidecar = Path(td) / "vetted-shas.jsonl"
            recs1 = generate_vetted_shas_sidecar(output_path=temp_sidecar)
            content1 = temp_sidecar.read_text()

            recs2 = generate_vetted_shas_sidecar(output_path=temp_sidecar)
            content2 = temp_sidecar.read_text()

            self.assertEqual(content1, content2, "Sidecar generation must be bit-for-bit deterministic")
            self.assertEqual(content1, VETTED_SHAS_SIDECAR.read_text(), "Existing sidecar must match generated output")

        # Test load_vetted_shas integration
        vetted_mapping = load_vetted_shas(sidecar_path=VETTED_SHAS_SIDECAR)
        self.assertEqual(len(vetted_mapping), 34)
        for adv, sha_set in vetted_mapping.items():
            self.assertEqual(len(sha_set), 1)
            sha = list(sha_set)[0]
            self.assertTrue(SHA_RE.fullmatch(sha))


if __name__ == "__main__":
    unittest.main()
