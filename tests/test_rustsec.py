"""Unit tests for RustSec catalog fetching and integration."""

import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from ksm.fixfp import build_one, load_candidates
from ksm.sitedata import build_site_data, fix_url_for_commit, project_from_catalog
from scripts.studies import fetch_rustsec


def create_zip_fixture(records):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rec in records:
            adv_id = rec.get("id", "adv")
            zf.writestr(f"{adv_id}.json", json.dumps(rec, ensure_ascii=False))
    return buf.getvalue()


class TestRustsecCatalog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp.name) / "rustsec"
        self.cache_dir = self.out_dir / ".cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_zip = self.cache_dir / "all.zip"

        # Three advisories:
        # 1. FIX github commit URL
        # 2. ADVISORY reference only, but with a WEB commit URL (should not count as fix_sha)
        # 3. GHSA and CVE aliases
        self.records = [
            {
                "id": "RUSTSEC-2023-0001",
                "modified": "2023-01-15T10:00:00Z",
                "published": "2023-01-10T12:00:00Z",
                "affected": [
                    {
                        "package": {
                            "name": "foo-crate",
                            "ecosystem": "crates.io",
                        }
                    }
                ],
                "database_specific": {
                    "cwe_ids": ["CWE-119"],
                },
                "aliases": ["CVE-2023-1111"],
                "references": [
                    {
                        "type": "FIX",
                        "url": "https://github.com/rust-owner/foo-crate/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    },
                    {
                        "type": "WEB",
                        "url": "https://github.com/rust-owner/foo-crate/pull/42",
                    },
                ],
            },
            {
                "id": "RUSTSEC-2022-0002",
                "modified": "2022-05-12T08:00:00Z",
                "published": "2022-05-01T00:00:00Z",
                "affected": [
                    {
                        "package": {
                            "name": "bar-crate",
                            "ecosystem": "crates.io",
                        }
                    }
                ],
                "references": [
                    {
                        "type": "ADVISORY",
                        "url": "https://rustsec.org/advisories/RUSTSEC-2022-0002.html",
                    },
                    {
                        "type": "WEB",
                        "url": "https://github.com/bar-owner/bar-crate/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    },
                ],
            },
            {
                "id": "RUSTSEC-2024-0003",
                "modified": "2024-08-22T14:00:00Z",
                "published": "2024-08-20T10:00:00Z",
                "affected": [
                    {
                        "package": {
                            "name": "baz-crate",
                            "ecosystem": "crates.io",
                        }
                    }
                ],
                "aliases": ["GHSA-xxxx-yyyy-zzzz", "CVE-2024-9999"],
                "references": [
                    {
                        "type": "ADVISORY",
                        "url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
                    }
                ],
            },
        ]
        self.zip_bytes = create_zip_fixture(self.records)
        self.cache_zip.write_bytes(self.zip_bytes)

    def tearDown(self):
        self.tmp.cleanup()

    def test_catalog_rows_and_fields(self):
        code = fetch_rustsec.main(["--out-dir", str(self.out_dir), "--cache", str(self.cache_zip), "--offline"])
        self.assertEqual(code, 0)

        catalog_path = self.out_dir / "catalog.jsonl"
        index_path = self.out_dir / "index.json"
        self.assertTrue(catalog_path.is_file())
        self.assertTrue(index_path.is_file())

        rows = [json.loads(line) for line in catalog_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(rows), 3)

        # Output must be sorted by advisory_id
        ids = [r["advisory_id"] for r in rows]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids, ["RUSTSEC-2022-0002", "RUSTSEC-2023-0001", "RUSTSEC-2024-0003"])

        # Row 1 (RUSTSEC-2022-0002): a WEB commit URL is never a fix_sha; it is kept
        # as a reference commit (fix candidate) with its repository
        r2 = rows[0]
        self.assertEqual(r2["package"], "bar-crate")
        self.assertEqual(r2["published"], "2022-05-01")
        self.assertIsNone(r2["cwe"])
        self.assertEqual(r2["cwe_state"], "UNKNOWN")
        self.assertEqual(r2["fix_shas"], [])
        self.assertEqual(r2["reference_commit_shas"], ["b" * 40])
        self.assertEqual(r2["repo"], "bar-owner/bar-crate")
        self.assertIn("https://github.com/bar-owner/bar-crate/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", r2["patch_urls"])

        # Row 2 (RUSTSEC-2023-0001): FIX commit URL gives fix_shas and repo
        r1 = rows[1]
        self.assertEqual(r1["package"], "foo-crate")
        self.assertEqual(r1["published"], "2023-01-10")
        self.assertEqual(r1["cwe"], "CWE-119")
        self.assertEqual(r1["cwe_state"], "STATED_BY_ADVISORY")
        self.assertEqual(r1["fix_shas"], ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
        self.assertEqual(r1["repo"], "rust-owner/foo-crate")
        self.assertEqual(r1["fix_sha_source"], "rustsec")
        self.assertEqual(len(r1["patch_urls"]), 2)

        # Row 3 (RUSTSEC-2024-0003): Aliases sorted
        r3 = rows[2]
        self.assertEqual(r3["package"], "baz-crate")
        self.assertEqual(r3["aliases"], ["CVE-2024-9999", "GHSA-xxxx-yyyy-zzzz"])

        # Index metadata
        idx = json.loads(index_path.read_text(encoding="utf-8"))
        self.assertEqual(idx["project"], "rustsec")
        self.assertEqual(idx["coverage"], "COMPLETE_AT_SNAPSHOT")
        self.assertEqual(idx["status"], "SNAPSHOT_COMPLETE")
        self.assertEqual(idx["entry_count"], 3)
        self.assertEqual(idx["with_fix_sha"], 1)
        self.assertEqual(idx["with_cwe"], 1)
        self.assertEqual(idx["fetched_at"], "2024-08-22T14:00:00Z")

    def test_ghsa_twin_is_folded_into_the_rustsec_row(self):
        build_catalog_and_index = fetch_rustsec.build_catalog_and_index
        parse_records_from_zip = fetch_rustsec.parse_records_from_zip
        records = [
            {"id": "RUSTSEC-2031-0001", "aliases": ["CVE-2031-1"], "published": "2031-01-01T00:00:00Z",
             "modified": "2031-01-02T00:00:00Z",
             "affected": [{"package": {"ecosystem": "crates.io", "name": "c"}}], "references": []},
            {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["RUSTSEC-2031-0001", "CVE-2031-1"],
             "published": "2031-01-01T00:00:00Z", "modified": "2031-01-02T00:00:00Z",
             "affected": [{"package": {"ecosystem": "crates.io", "name": "c"}}],
             "references": [{"type": "WEB", "url": "https://github.com/o/c/commit/" + "e" * 40}]},
        ]
        z = create_zip_fixture(records)
        _, _, rows = build_catalog_and_index(z, parse_records_from_zip(z))
        self.assertEqual([r["advisory_id"] for r in rows], ["RUSTSEC-2031-0001"])
        self.assertEqual(rows[0]["reference_commit_shas"], ["e" * 40])
        self.assertEqual(rows[0]["repo"], "o/c")
        self.assertIn("GHSA-aaaa-bbbb-cccc", rows[0]["aliases"])

    def test_check_flag(self):
        # 1. Run generation
        fetch_rustsec.main(["--out-dir", str(self.out_dir), "--cache", str(self.cache_zip), "--offline"])

        # 2. Check passes
        code = fetch_rustsec.main(["--out-dir", str(self.out_dir), "--cache", str(self.cache_zip), "--offline", "--check"])
        self.assertEqual(code, 0)

        # 3. Modify catalog -> check fails
        catalog_path = self.out_dir / "catalog.jsonl"
        catalog_path.write_text("corrupted\n", encoding="utf-8")
        code_fail = fetch_rustsec.main(["--out-dir", str(self.out_dir), "--cache", str(self.cache_zip), "--offline", "--check"])
        self.assertEqual(code_fail, 1)


class TestRustsecFixfp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cat_dir = self.root / "docs" / "studies" / "cve-history"
        self.rustsec_dir = self.cat_dir / "rustsec"
        self.rustsec_dir.mkdir(parents=True, exist_ok=True)

        row = {
            "advisory_id": "RUSTSEC-2023-0001",
            "aliases": ["CVE-2023-1111"],
            "cwe": "CWE-119",
            "cwe_state": "STATED_BY_ADVISORY",
            "fix_sha_source": "rustsec",
            "fix_shas": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "package": "foo-crate",
            "patch_urls": [],
            "published": "2023-01-10",
            "repo": "custom-owner/custom-repo",
            "subsystem": None,
        }
        (self.rustsec_dir / "catalog.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_load_candidates_includes_repo(self):
        cands = load_candidates(self.cat_dir, only_project="rustsec")
        self.assertEqual(len(cands), 1)
        c = cands[0]
        self.assertEqual(c["project"], "rustsec")
        self.assertEqual(c["advisory_id"], "RUSTSEC-2023-0001")
        self.assertEqual(c["fix_sha"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(c["repo"], "custom-owner/custom-repo")

    def test_build_one_fetches_from_candidate_repo(self):
        candidate = {
            "project": "rustsec",
            "advisory_id": "RUSTSEC-2023-0001",
            "fix_sha": "a" * 40,
            "repo": "custom-owner/custom-repo",
            "cwe": "CWE-119",
        }
        calls = []

        def fake_fetch_commit(repo, sha):
            calls.append((repo, sha))
            return {
                "sha": sha,
                "parents": [{"sha": "b" * 40}],
                "files": [
                    {
                        "filename": "src/lib.rs",
                        "status": "modified",
                        "patch": "@@ -1,3 +1,3 @@\n-old\n+new\n",
                    }
                ],
            }

        def fake_fetch_blob(repo, sha, path):
            return b"fn foo() {}\n"

        def fake_run_fp(path, lang, ranges):
            return {
                "coverage": "OK",
                "functions": [
                    {
                        "name": "foo",
                        "start_line": 1,
                        "end_line": 2,
                        "kgrams": {"k1": 1},
                        "calls": [],
                        "guards": [],
                    }
                ],
            }

        out_fp_dir = self.root / "fingerprints"
        doc, repo_used = build_one(
            candidate,
            out_fp_dir,
            fetch_commit=fake_fetch_commit,
            fetch_blob=fake_fetch_blob,
            run_fingerprint=fake_run_fp,
        )

        self.assertEqual(calls, [("custom-owner/custom-repo", "a" * 40)])
        self.assertEqual(repo_used, "custom-owner/custom-repo")
        self.assertEqual(doc["project"], "rustsec")
        self.assertEqual(doc["repo"], "custom-owner/custom-repo")

        fp_file = out_fp_dir / "rustsec" / "RUSTSEC-2023-0001.json"
        self.assertTrue(fp_file.is_file())
        saved = json.loads(fp_file.read_text(encoding="utf-8"))
        self.assertEqual(saved["project"], "rustsec")
        self.assertEqual(saved["repo"], "custom-owner/custom-repo")


class TestRustsecSitedata(unittest.TestCase):
    def test_project_from_catalog(self):
        self.assertEqual(project_from_catalog("rustsec"), "rustsec")

    def test_fix_url_for_commit(self):
        url = fix_url_for_commit("rustsec", "a" * 40, repo="custom-owner/custom-repo")
        self.assertEqual(url, f"https://github.com/custom-owner/custom-repo/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    def test_site_data_rustsec_aliases_and_repo(self):
        with tempfile.TemporaryDirectory() as tmp_root, tempfile.TemporaryDirectory() as tmp_out:
            root = Path(tmp_root)
            out = Path(tmp_out)
            cat_dir = root / "docs" / "studies" / "cve-history" / "rustsec"
            cat_dir.mkdir(parents=True, exist_ok=True)
            row = {
                "advisory_id": "RUSTSEC-2023-0001",
                "aliases": ["CVE-2023-1111"],
                "cwe": "CWE-119",
                "cwe_state": "STATED_BY_ADVISORY",
                "fix_sha_source": "rustsec",
                "fix_shas": ["a" * 40],
                "package": "foo-crate",
                "patch_urls": [],
                "published": "2023-01-10",
                "repo": "custom-owner/custom-repo",
                "subsystem": None,
            }
            (cat_dir / "catalog.jsonl").write_text(json.dumps(row) + chr(10), encoding="utf-8")
            (cat_dir / "index.json").write_text(json.dumps({"project": "rustsec", "coverage": "COMPLETE_AT_SNAPSHOT"}) + chr(10), encoding="utf-8")

            build_site_data(repo_root=root, out_dir=out, no_bundle=True)

            cve_path = out / "cve" / "rustsec" / "RUSTSEC-2023-0001.json"
            self.assertTrue(cve_path.is_file())
            cve_doc = json.loads(cve_path.read_text(encoding="utf-8"))
            self.assertEqual(cve_doc["repo"], "custom-owner/custom-repo")
            self.assertEqual(cve_doc["aliases"], ["CVE-2023-1111"])
            self.assertEqual(len(cve_doc["fixes"]), 1)
            self.assertEqual(cve_doc["fixes"][0]["url"], "https://github.com/custom-owner/custom-repo/commit/" + "a" * 40)

            search_path = out / "search.json"
            self.assertTrue(search_path.is_file())
            search_rows = json.loads(search_path.read_text(encoding="utf-8"))
            found = [r for r in search_rows if r[0] == "RUSTSEC-2023-0001"]
            self.assertEqual(len(found), 1)
            # Text column is row[4]
            self.assertIn("CVE-2023-1111", found[0][4])


if __name__ == "__main__":
    unittest.main()
