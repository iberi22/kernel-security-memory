"""Unit tests for Vulnerability Atlas site data builder."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from ksm.cwe_groups import GROUP_NAMES, get_cwe_group
from ksm.sitedata import build_site_data

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "site-repo"


class TestSiteData(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp_dir.name)
        self._epoch = os.environ.get("SOURCE_DATE_EPOCH")
        os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        build_site_data(repo_root=FIXTURE_ROOT, out_dir=self.out_dir)

    def tearDown(self):
        self.tmp_dir.cleanup()
        if self._epoch is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = self._epoch

    def test_project_merge(self):
        index_p = self.out_dir / "index.json"
        self.assertTrue(index_p.is_file())
        with open(index_p, encoding="utf-8") as f:
            index = json.load(f)

        self.assertEqual(index["totals"]["cves"], 6)
        self.assertEqual(index["totals"]["projects"], 2)
        self.assertEqual(index["totals"]["with_fix"], 6)
        self.assertEqual(index["totals"]["with_fragments"], 1)
        self.assertEqual(index["totals"]["with_fingerprint"], 1)

        projs = {p["name"]: p for p in index["projects"]}
        self.assertIn("curl", projs)
        self.assertIn("git", projs)

        curl_p = projs["curl"]
        self.assertEqual(curl_p["repo"], "curl/curl")
        self.assertEqual(sorted(curl_p["catalogs"]), ["curl", "curl-upstream"])
        self.assertEqual(curl_p["cves"], 4)
        self.assertEqual(curl_p["with_fix"], 4)
        self.assertEqual(curl_p["with_fragments"], 1)
        self.assertEqual(curl_p["with_fingerprint"], 1)

        # CVE-2099-0001 merged detail
        cve1_p = self.out_dir / "cve" / "curl" / "CVE-2099-0001.json"
        self.assertTrue(cve1_p.is_file())
        with open(cve1_p, encoding="utf-8") as f:
            cve1 = json.load(f)

        self.assertEqual(cve1["id"], "CVE-2099-0001")
        self.assertEqual(cve1["project"], "curl")
        self.assertEqual(cve1["published"], "2023-01-10")
        self.assertEqual(cve1["cwe"], "CWE-787")
        self.assertEqual(cve1["cwe_source"], "catalog")
        self.assertEqual(sorted(cve1["catalogs"]), ["curl", "curl-upstream"])
        self.assertEqual(len(cve1["fixes"]), 2)
        shas = [fx["sha"] for fx in cve1["fixes"]]
        self.assertEqual(shas, ["1111111111111111111111111111111111111111", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
        self.assertIsNotNone(cve1["fragments"])
        self.assertIsNotNone(cve1["fingerprint"])

    def test_overlay_precedence(self):
        cve3_p = self.out_dir / "cve" / "curl" / "CVE-2099-0003.json"
        self.assertTrue(cve3_p.is_file())
        with open(cve3_p, encoding="utf-8") as f:
            cve3 = json.load(f)

        # Catalog had cwe: None, overlay supplied CWE-476
        self.assertEqual(cve3["cwe"], "CWE-476")
        self.assertEqual(cve3["cwe_source"], "nvd-primary")
        self.assertEqual(cve3["group"], "Memory safety")

    def test_cwe_group(self):
        self.assertEqual(get_cwe_group("CWE-787"), "Memory safety")
        self.assertEqual(get_cwe_group("CWE-476"), "Memory safety")
        self.assertEqual(get_cwe_group("CWE-416"), "Memory safety")
        self.assertEqual(get_cwe_group("CWE-362"), "Concurrency")
        self.assertEqual(get_cwe_group("CWE-9999"), "Other")
        self.assertEqual(get_cwe_group(None), "Unknown")
        self.assertEqual(get_cwe_group("UNKNOWN"), "Unknown")

        # index.json groups structure
        with open(self.out_dir / "index.json", encoding="utf-8") as f:
            index = json.load(f)

        groups = {g["name"]: g for g in index["groups"]}
        self.assertEqual(len(groups), len(GROUP_NAMES))
        self.assertIn("Memory safety", groups)
        self.assertEqual(groups["Memory safety"]["cves"], 6)

    def test_related_neighbours_and_shared_reasons(self):
        cve1_p = self.out_dir / "cve" / "curl" / "CVE-2099-0001.json"
        with open(cve1_p, encoding="utf-8") as f:
            cve1 = json.load(f)

        related = cve1["related"]
        self.assertIsInstance(related, list)
        self.assertGreater(len(related), 0)
        top = related[0]
        self.assertIn("id", top)
        self.assertIn("project", top)
        self.assertIn("score", top)
        self.assertIn("shared", top)
        self.assertGreater(top["score"], 0)
        self.assertLessEqual(len(top["shared"]), 3)

    def test_byte_identical_output(self):
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out1 = Path(tmp1)
            out2 = Path(tmp2)
            os.environ["SOURCE_DATE_EPOCH"] = "1700000000"

            build_site_data(repo_root=FIXTURE_ROOT, out_dir=out1)
            build_site_data(repo_root=FIXTURE_ROOT, out_dir=out2)

            files1 = sorted([p.relative_to(out1) for p in out1.rglob("*") if p.is_file()])
            files2 = sorted([p.relative_to(out2) for p in out2.rglob("*") if p.is_file()])
            self.assertEqual(files1, files2)

            for rel in files1:
                bytes1 = (out1 / rel).read_bytes()
                bytes2 = (out2 / rel).read_bytes()
                self.assertEqual(bytes1, bytes2, f"Discrepancy in file {rel}")

    def test_bundle_sha256_matches(self):
        bundle_p = self.out_dir / "bundle.tar.gz"
        sha_p = self.out_dir / "bundle.sha256"
        self.assertTrue(bundle_p.is_file())
        self.assertTrue(sha_p.is_file())

        digest = hashlib.sha256(bundle_p.read_bytes()).hexdigest()
        sha_content = sha_p.read_text(encoding="utf-8").strip()
        self.assertEqual(sha_content, f"{digest}  bundle.tar.gz")


class TestEvidenceOutsideCatalogs(unittest.TestCase):
    """Pack/fingerprint CVEs missing from every catalog, and MITRE CWE names."""

    def setUp(self):
        import shutil
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        shutil.copytree(FIXTURE_ROOT, self.repo)
        studies = self.repo / "docs" / "studies"
        (studies / "fragments" / "nginx-CVE-2031-0001.json").write_text(json.dumps(
            {"coverage": "OK", "fix_commit": "f" * 40, "files": []}), encoding="utf-8")
        fp_dir = studies / "fingerprints" / "linux-cna"
        fp_dir.mkdir(parents=True, exist_ok=True)
        (fp_dir / "CVE-2031-0002.json").write_text(json.dumps(
            {"schema": "ksm-fixfp/1", "advisory_id": "CVE-2031-0002", "project": "linux-cna",
             "fix_sha": "e" * 40, "parent_sha": "d" * 40, "cwe": "CWE-415",
             "files": [{"path": "mm/x.c", "functions": [{"name": "f", "before": {
                 "start_line": 3, "end_line": 9}, "after": {"start_line": 3, "end_line": 10},
                 "delta": {"added_guards": [], "added_calls": [], "removed_calls": []}}]}]}),
            encoding="utf-8")
        (studies / "cwe-names.json").write_text(json.dumps(
            {"notice": "MITRE notice", "names": {"CWE-415": "Double Free"}}), encoding="utf-8")
        self.out = Path(self.tmp.name) / "out"
        build_site_data(repo_root=self.repo, out_dir=self.out, no_bundle=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_path_like_ids_never_become_files(self):
        import shutil
        repo = Path(self.tmp.name) / "repo2"
        shutil.copytree(self.repo, repo)
        cat = repo / "docs" / "studies" / "cve-history" / "curl" / "catalog.jsonl"
        with open(cat, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"advisory_id": "../../escape", "cwe": "../x", "fix_shas": []}) + "\n")
        out = Path(self.tmp.name) / "out2"
        build_site_data(repo_root=repo, out_dir=out, no_bundle=True)
        self.assertFalse((Path(self.tmp.name) / "escape.json").exists())
        self.assertEqual([p for p in out.rglob("*") if ".." in p.name or p.name == "escape.json"], [])

    def test_pack_only_cve_is_listed(self):
        cve = json.loads((self.out / "cve" / "nginx" / "CVE-2031-0001.json").read_text())
        self.assertEqual(cve["catalogs"], ["pack"])
        self.assertEqual([f["sha"] for f in cve["fixes"]], ["f" * 40])

    def test_fingerprint_project_dir_is_normalised_and_named(self):
        cve = json.loads((self.out / "cve" / "linux" / "CVE-2031-0002.json").read_text())
        self.assertEqual(cve["cwe_name"], "Double Free")
        fn = cve["fingerprint"]["functions"][0]
        self.assertEqual((fn["before_range"], fn["after_range"]), ([3, 9], [3, 10]))
        index = json.loads((self.out / "index.json").read_text())
        self.assertEqual(index["cwe_names_notice"], "MITRE notice")


if __name__ == "__main__":
    unittest.main()
