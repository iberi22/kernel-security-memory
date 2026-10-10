#!/usr/bin/env python3
"""Unit tests for enrich_fix_shas script and SHA validation rules."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from enrich_fix_shas import (
    GIT_TIMEOUT_SECONDS,
    MAX_LINE_BYTES,
    SHA_RE,
    ROOT,
    VETTED_SHAS_SIDECAR,
    extract_commit_shas_from_urls,
    enrich_catalog,
    check_sha_in_mirror,
    extract_vetted_shas_records,
    generate_vetted_shas_sidecar,
    git_env,
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

    def test_enriched_lines_are_compact_and_within_byte_budget(self):
        """Catalog lines keep the fetcher's compact form and never pass max_line_bytes.

        Regression: enrich_catalog used json.dumps() default separators and appended
        three status fields, inflating every line (measured +51% bytes over the whole
        catalog tree) and pushing lines past the 500-byte limit that
        BaseHistoryFetcher.validate_offline enforces.
        """
        long_url = "https://git.example.com/org/project/-/commit/" + "b" * 40
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            (pdir / "index.json").write_text(json.dumps({
                "schema_version": "cve-history-v1",
                "project": "sample",
                "entry_count": 1,
                "with_fix_sha": 0,
            }))
            entry = {
                "advisory_id": "CVE-2021-3333",
                "published": "2021-03-01",
                "cwe": "CWE-119",
                "cwe_state": "STATED_BY_ADVISORY",
                "patch_urls": [long_url + "/one", long_url + "/two", long_url + "/three"],
                "fix_shas": [],
                "subsystem": "core",
            }
            # Sanity: the entry alone fits, but it cannot also carry the status fields.
            data_only = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
            self.assertLessEqual(len(data_only.encode("utf-8")), MAX_LINE_BYTES)
            (pdir / "catalog.jsonl").write_text(data_only + "\n")

            rep = enrich_catalog(pdir, vetted_shas={}, dry_run=False)

            self.assertEqual(rep["over_limit"], 1)
            written = (pdir / "catalog.jsonl").read_text().splitlines()[0]
            # Compact separators, byte-for-byte what a re-read would re-emit.
            self.assertNotIn(", ", written)
            self.assertEqual(written, json.dumps(json.loads(written), separators=(",", ":"), ensure_ascii=False))
            # Within the budget that validate_offline enforces.
            self.assertLessEqual(len(written.encode("utf-8")), MAX_LINE_BYTES)
            # The derived status fields were dropped, the data was not.
            parsed = json.loads(written)
            self.assertNotIn("sha_status", parsed)
            self.assertNotIn("mirror_status", parsed)
            self.assertNotIn("sha_statuses", parsed)
            self.assertEqual(parsed["fix_shas"], ["b" * 40])

    def test_enriched_lines_keep_status_fields_when_they_fit(self):
        """Short entries still get the derived status fields on one compact line."""
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            (pdir / "index.json").write_text(json.dumps({
                "schema_version": "cve-history-v1", "project": "sample",
                "entry_count": 1, "with_fix_sha": 0,
            }))
            (pdir / "catalog.jsonl").write_text(json.dumps({
                "advisory_id": "CVE-2021-4444", "published": "2021-04-01",
                "cwe": None, "cwe_state": "UNKNOWN", "patch_urls": [],
                "fix_shas": [], "subsystem": "unassigned",
            }, separators=(",", ":")) + "\n")

            rep = enrich_catalog(pdir, vetted_shas={}, dry_run=False)

            self.assertEqual(rep["over_limit"], 0)
            written = (pdir / "catalog.jsonl").read_text().splitlines()[0]
            parsed = json.loads(written)
            self.assertEqual(parsed["sha_status"], "NOT_JOINED")
            self.assertEqual(parsed["mirror_status"], "NOT_JOINED")
            self.assertEqual(parsed["sha_statuses"], {})

    def test_normal_run_preserves_index_cursor_state(self):
        """A non-dry-run enrichment updates with_fix_sha only, never the cursor state."""
        original_index = {
            "schema_version": "cve-history-v1",
            "project": "sample",
            "coverage": "INCOMPLETE",
            "status": "CURSOR_PAUSED",
            "cursor_date": "2008-08-11",
            "window_closed": False,
            "entry_count": 1,
            "with_fix_sha": 0,
            "requests": 39,
            "resume": {"next_start_date": "2008-08-11"},
            "errors": [],
            "notes": "Cursor paused at 2008-08-11; window remains open (not closed).",
        }
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            (pdir / "index.json").write_text(json.dumps(original_index, indent=2) + "\n")
            (pdir / "catalog.jsonl").write_text(json.dumps({
                "advisory_id": "CVE-1999-0001", "published": "1999-01-01",
                "cwe": None, "cwe_state": "UNKNOWN",
                "patch_urls": ["https://example.com/commit/" + "c" * 40],
                "fix_shas": [], "subsystem": "unassigned",
            }, separators=(",", ":")) + "\n")

            enrich_catalog(pdir, vetted_shas={}, dry_run=False)

            updated = json.loads((pdir / "index.json").read_text())
            self.assertEqual(updated["with_fix_sha"], 1)
            for key in ("coverage", "status", "cursor_date", "window_closed",
                        "requests", "resume", "errors", "notes", "entry_count"):
                self.assertEqual(updated[key], original_index[key], f"index key {key!r} must survive")

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

        # Run the real script against a temporary fixture tree, never the live
        # repository data (whose overlap changes as fetching continues).
        with tempfile.TemporaryDirectory() as td:
            fixture_root = Path(td) / "cve-history"
            project_dir = fixture_root / "fixture"
            project_dir.mkdir(parents=True)
            fixture_catalog = (
                json.dumps({
                    "advisory_id": "CVE-1999-0001",
                    "published": "1999-01-01",
                    "cwe": None,
                    "cwe_state": "UNKNOWN",
                    "patch_urls": ["https://example.com/commit/" + "d" * 40],
                    "fix_shas": [],
                    "subsystem": "unassigned",
                }, separators=(",", ":")) + "\n" +
                json.dumps({
                    "advisory_id": "CVE-1999-0002",
                    "published": "1999-02-01",
                    "cwe": None,
                    "cwe_state": "UNKNOWN",
                    "patch_urls": ["https://example.com/advisory"],
                    "fix_shas": [],
                    "subsystem": "unassigned",
                }, separators=(",", ":")) + "\n"
            )
            (project_dir / "catalog.jsonl").write_text(fixture_catalog)
            (project_dir / "index.json").write_text(json.dumps({
                "schema_version": "cve-history-v1",
                "project": "fixture",
                "coverage": "INCOMPLETE",
                "status": "CURSOR_PAUSED",
                "cursor_date": "1999-03-01",
                "window_closed": False,
                "entry_count": 2,
                "with_fix_sha": 0,
                "requests": 4,
                "resume": {"next_start_date": "1999-03-01"},
                "errors": [],
                "notes": "fixture",
            }, indent=2) + "\n")

            for mode in ("--dry-run", "--check"):
                res = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/studies/enrich_fix_shas.py"),
                        mode,
                        "--cve-history-dir", str(fixture_root),
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertIn("Catalog scanned: 0 overlaps found with vetted records", res.stdout, mode)
                self.assertIn("overlap: 0", res.stdout, mode)
                self.assertIn("0 matches", res.stdout, mode)
                self.assertNotIn("Enrichment complete and verified", res.stdout, mode)
                self.assertNotIn("Verification successful", res.stdout, mode)

            # Check/dry-run modes must not touch the fixture tree.
            self.assertEqual((project_dir / "catalog.jsonl").read_text(), fixture_catalog)

    def test_b2_git_mirror_verification(self):
        """B2: Check candidate SHAs against local git mirror and record NOT_IN_MIRROR or MIRROR_UNCHECKED."""
        with tempfile.TemporaryDirectory() as git_td:
            git_dir = Path(git_td)
            # Initialize a real git repo and make a commit. The cleaned environment
            # is passed to every command, exactly like check_sha_in_mirror does.
            clean_env = git_env()
            subprocess.run(["git", "init", str(git_dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, env=clean_env)
            subprocess.run(["git", "-C", str(git_dir), "config", "user.name", "Tester"], check=True, env=clean_env)
            subprocess.run(["git", "-C", str(git_dir), "config", "user.email", "tester@example.com"], check=True, env=clean_env)
            (git_dir / "file.txt").write_text("test commit content\n")
            subprocess.run(["git", "-C", str(git_dir), "add", "file.txt"], check=True, env=clean_env)
            subprocess.run(["git", "-C", str(git_dir), "commit", "-m", "initial commit"], stdout=subprocess.DEVNULL, check=True, env=clean_env)

            rev_res = subprocess.run(["git", "-C", str(git_dir), "rev-parse", "HEAD"], capture_output=True, text=True, check=True, env=clean_env)
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

    def test_check_sha_in_mirror_rejects_non_commit_objects(self):
        """A blob or tree hash must not be reported as a verified commit.

        Regression: after the `sha^{commit}` lookup failed, a bare `cat-file -e <sha>`
        succeeded for any blob or tree, so such an entry was marked VERIFIED_IN_MIRROR.
        """
        with tempfile.TemporaryDirectory() as git_td:
            git_dir = Path(git_td)
            env = git_env()
            subprocess.run(["git", "init", str(git_dir)], check=True, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (git_dir / "file.txt").write_text("test commit content\n")
            blob = subprocess.run(["git", "-C", str(git_dir), "hash-object", "-w", "file.txt"],
                                  capture_output=True, text=True, check=True, env=env
                                  ).stdout.strip().lower()
            subprocess.run(["git", "-C", str(git_dir), "add", "file.txt"], check=True, env=env)
            tree = subprocess.run(["git", "-C", str(git_dir), "write-tree"],
                                  capture_output=True, text=True, check=True, env=env
                                  ).stdout.strip().lower()

            for sha, kind in ((blob, "blob"), (tree, "tree")):
                self.assertTrue(SHA_RE.fullmatch(sha), f"{kind} hash must be 40-hex")
                self.assertFalse(
                    check_sha_in_mirror(git_dir, sha),
                    f"{kind} {sha} must not count as a verified commit",
                )

    def test_check_sha_in_mirror_isolates_git_environment(self):
        """Inherited GIT_* variables must not redirect the lookup to another repository."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repos = {}
            for name in ("host", "foreign"):
                repo = root / name
                repo.mkdir()
                env = git_env()
                subprocess.run(["git", "init", str(repo)], check=True, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["git", "-C", str(repo), "config", "user.name", "T"], check=True, env=env)
                subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@e.com"], check=True, env=env)
                (repo / "file.txt").write_text(name + "\n")
                subprocess.run(["git", "-C", str(repo), "add", "file.txt"], check=True, env=env)
                subprocess.run(["git", "-C", str(repo), "commit", "-m", "c"], check=True, env=env,
                               stdout=subprocess.DEVNULL)
                repos[name] = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                             capture_output=True, text=True, check=True, env=env
                                             ).stdout.strip().lower()

            foreign_commit = repos["foreign"]
            foreign_objects = root / "foreign/.git/objects"
            with patch.dict(os.environ, {
                "GIT_OBJECT_DIRECTORY": str(foreign_objects),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(foreign_objects),
            }):
                # Still verified in its own repository...
                self.assertTrue(check_sha_in_mirror(root / "foreign", foreign_commit))
                # ...but not in the host repository, whose object store was hijacked.
                self.assertFalse(check_sha_in_mirror(root / "host", foreign_commit))

    def test_check_sha_in_mirror_uses_timeout_and_clean_env(self):
        """The git subprocess gets a bounded lifetime and a GIT_*-free environment."""
        seen = {}

        def _fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            return subprocess.CompletedProcess(cmd, 0)

        with patch("subprocess.run", side_effect=_fake_run):
            self.assertTrue(check_sha_in_mirror(".", "a" * 40))

        self.assertEqual(seen["kwargs"]["timeout"], GIT_TIMEOUT_SECONDS)
        self.assertEqual(seen["kwargs"]["env"], git_env())
        self.assertFalse([k for k in seen["kwargs"]["env"] if k.startswith("GIT_")])
        self.assertEqual(seen["cmd"][-1], ("a" * 40) + "^{commit}")

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
