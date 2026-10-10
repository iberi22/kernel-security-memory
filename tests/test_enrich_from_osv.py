#!/usr/bin/env python3
"""Offline unit tests for enrich_from_osv (inline fixtures, no network)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from enrich_from_osv import (  # noqa: E402
    DEFAULT_PROJECTS,
    OsvClient,
    collect_osv_facts,
    enrich_project,
    enrich_row,
    extract_cwe_ids,
    extract_fix_reference_shas,
    normalize_repo,
    repo_path,
)
from enrich_fix_shas import SHA_RE  # noqa: E402  shared canonical rule

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/studies/enrich_from_osv.py"
SHA_A = "172e54cda18412da73fd8eb4e444e8a5b371ca59"
SHA_B = "e818b74be2170fbe957a07b0da4401c2b694b3b8"
SHA_C = "943aea62679fb9f2d6d7abe59b5edcba21490c52"
CURL_REPO = "https://github.com/curl/curl"


def osv_doc(vuln_id, fixes=(), cwe_ids=(), aliases=()):
    """Build a minimal but shape-faithful OSV vulnerability document.

    ``fixes`` is now a list of commit ids published as FIX references inside the
    project repository (the shape fetch_upstream_advisories.py and this script
    both accept). GIT range "fixed" events are modelled separately by
    git_boundary_doc(), because they are version boundaries, not fix commits.
    """
    doc = {"id": vuln_id, "schema_version": "1.6.0", "aliases": list(aliases)}
    if fixes:
        doc["references"] = [
            {"type": "FIX", "url": f"{CURL_REPO}/commit/{sha}"} for sha in fixes
        ]
    if cwe_ids:
        doc["database_specific"] = {"cwe_ids": list(cwe_ids)}
    return doc


def git_boundary_doc(vuln_id, fixed_shas):
    """An OSV document whose only commit data is GIT range 'fixed' events."""
    return {
        "id": vuln_id,
        "schema_version": "1.6.0",
        "references": [{"type": "ADVISORY", "url": "https://curl.se/docs/x.html"}],
        "affected": [{
            "package": {"ecosystem": "GIT", "name": "github.com/curl/curl"},
            "ranges": [{
                "type": "GIT",
                "repo": "https://github.com/curl/curl.git",
                "events": [{"introduced": "0" * 40}] + [{"fixed": sha} for sha in fixed_shas],
            }],
        }],
    }


class TestExtraction(unittest.TestCase):
    def test_fix_shas_from_fix_references(self):
        doc = osv_doc("CVE-2023-38545", fixes=[SHA_A, SHA_B])
        self.assertEqual(extract_fix_reference_shas(doc, CURL_REPO), [SHA_A, SHA_B])

    def test_patch_references_are_accepted_too(self):
        doc = osv_doc("CVE-1", fixes=[SHA_A])
        doc["references"][0]["type"] = "PATCH"
        self.assertEqual(extract_fix_reference_shas(doc, CURL_REPO), [SHA_A])

    def test_git_range_fixed_events_are_not_fix_shas(self):
        """The round-1 defect: a range boundary is not a fix commit."""
        doc = git_boundary_doc("CVE-2005-3185", [SHA_C, SHA_B])
        self.assertEqual(extract_fix_reference_shas(doc, CURL_REPO), [])

    def test_references_of_another_type_are_ignored(self):
        doc = {"id": "CVE-1", "references": [
            {"type": "ADVISORY", "url": "https://curl.se/docs/CVE-1.html"},
            {"type": "WEB", "url": f"{CURL_REPO}/commit/{SHA_A}"},
        ]}
        self.assertEqual(extract_fix_reference_shas(doc, CURL_REPO), [])

    def test_fix_reference_outside_the_project_repo_is_ignored(self):
        doc = {"id": "CVE-1", "references": [
            {"type": "FIX", "url": f"https://github.com/curl/curl-stable/commit/{SHA_A}"},
            {"type": "FIX", "url": f"https://github.com/bminor/glibc/commit/{SHA_A}"},
        ]}
        self.assertEqual(extract_fix_reference_shas(doc, CURL_REPO), [])

    def test_41_hex_and_non_commit_urls_are_ignored(self):
        doc = {"id": "CVE-1", "references": [
            {"type": "FIX", "url": f"{CURL_REPO}/commit/{'a' * 41}"},
            {"type": "FIX", "url": f"{CURL_REPO}/issues/1234"},
            {"type": "FIX", "url": f"{CURL_REPO}/compare/v1...v2"},
        ]}
        self.assertEqual(extract_fix_reference_shas(doc, CURL_REPO), [])

    def test_without_a_repo_nothing_is_extracted(self):
        self.assertEqual(extract_fix_reference_shas({"id": "CVE-1"}, CURL_REPO), [])
        self.assertEqual(extract_fix_reference_shas({}, CURL_REPO), [])
        self.assertEqual(extract_fix_reference_shas(osv_doc("CVE-1", fixes=[SHA_A]), ""), [])

    def test_repo_path_strips_scheme_and_git_suffix(self):
        self.assertEqual(repo_path("https://github.com/curl/curl.git/"), "github.com/curl/curl")
        self.assertEqual(repo_path("curl"), "curl")
        self.assertEqual(repo_path(None), "")

    def test_cwe_ids_normalized_and_deduplicated(self):
        doc = {"id": "CVE-3", "database_specific": {"cwe_ids": [" cwe-787 ", "CWE-787", "CWE-125", 7, "nope"]}}
        self.assertEqual(extract_cwe_ids(doc), ["CWE-787", "CWE-125"])

    def test_cwe_ids_absent(self):
        self.assertEqual(extract_cwe_ids({"id": "CVE-4", "database_specific": None}), [])
        self.assertEqual(extract_cwe_ids({"id": "CVE-4"}), [])

    def test_normalize_repo(self):
        self.assertEqual(normalize_repo("https://github.com/curl/curl.git/"), "https://github.com/curl/curl")
        self.assertEqual(normalize_repo("https://sourceware.org/git/glibc.git"),
                         "https://sourceware.org/git/glibc")
        self.assertEqual(normalize_repo(None), "")


class TestEnrichRow(unittest.TestCase):
    def test_new_values_and_provenance(self):
        row = {"advisory_id": "CVE-1", "cwe": None, "cwe_state": "UNKNOWN",
               "patch_urls": [], "fix_shas": [], "subsystem": None}
        facts = {"fixes": [SHA_A], "cwes": ["CWE-787"]}
        enrich_row(row, facts)
        self.assertEqual(row["fix_shas"], [SHA_A])
        self.assertEqual(row["fix_sha_source"], "osv")
        self.assertEqual(row["cwe"], "CWE-787")
        self.assertEqual(row["cwe_source"], "osv")
        self.assertEqual(row["cwe_state"], "STATED_BY_ADVISORY")
        self.assertEqual(row["cwe_source"], "osv")
        self.assertNotIn("fix_repo", row)
        # no extra columns: the NVD validators still accept the row
        self.assertEqual(
            sorted(row),
            sorted(["advisory_id", "cwe", "cwe_source", "cwe_state", "fix_sha_source",
                    "fix_shas", "patch_urls", "subsystem"]),
        )

    def test_never_overwrite_existing_values(self):
        row = {"advisory_id": "CVE-1", "cwe": "CWE-119", "cwe_state": "STATED_BY_ADVISORY",
               "fix_shas": [SHA_B]}
        facts = {"fixes": [SHA_A], "cwes": ["CWE-787"]}
        enrich_row(row, facts)
        self.assertEqual(row["cwe"], "CWE-119")
        self.assertEqual(row["cwe_state"], "STATED_BY_ADVISORY")
        self.assertNotIn("cwe_source", row)
        self.assertEqual(row["fix_shas"], [SHA_B, SHA_A])
        self.assertEqual(row["fix_sha_source"], "osv")

    def test_nothing_written_without_osv_facts(self):
        row = {"advisory_id": "CVE-1", "cwe": None, "cwe_state": "UNKNOWN", "fix_shas": []}
        enrich_row(row, {"fixes": [], "cwes": []})
        self.assertEqual(row, {"advisory_id": "CVE-1", "cwe": None, "cwe_state": "UNKNOWN", "fix_shas": []})


class TestOfflinePipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.client = OsvClient(root / "osv-cache", offline=True)
        self.project = root / "curl"
        self.project.mkdir()
        self.index_body = {
            "schema_version": "cve-history-v1",
            "project": "curl",
            "repo": "https://github.com/curl/curl",
            "entry_count": 3,
            "with_fix_sha": 0,
        }
        (self.project / "index.json").write_text(json.dumps(self.index_body), encoding="utf-8")
        self.rows = [
            {"advisory_id": "CVE-2023-38545", "published": "2023-10-18", "cwe": None,
             "cwe_state": "UNKNOWN", "patch_urls": [], "fix_shas": [], "subsystem": None},
            {"advisory_id": "CVE-2022-32221", "published": "2022-06-27", "cwe": "CWE-787",
             "cwe_state": "STATED_BY_ADVISORY", "patch_urls": [], "fix_shas": [SHA_B], "subsystem": None},
            {"advisory_id": "CVE-1999-0001", "published": "1999-01-01", "cwe": None,
             "cwe_state": "UNKNOWN", "patch_urls": [], "fix_shas": [], "subsystem": None},
        ]
        self.write_rows(self.rows)
        # Cache only what OSV would answer: one vuln with an alias, one 404 body.
        cache = root / "osv-cache"
        cache.mkdir()
        (cache / "CVE-2023-38545.json").write_text(json.dumps(
            osv_doc("CVE-2023-38545", fixes=[SHA_A],
                    cwe_ids=["CWE-787"], aliases=["GHSA-95gj-4pvw-c6vm"])), encoding="utf-8")
        (cache / "GHSA-95gj-4pvw-c6vm.json").write_text(json.dumps(
            osv_doc("GHSA-95gj-4pvw-c6vm", cwe_ids=["CWE-125"])), encoding="utf-8")
        # The CVE-2005-3185 shape OSV really answers: a GIT 'fixed' event and
        # no FIX reference in the project repo. Its commit is a range boundary,
        # so it must not reach fix_shas.
        (cache / "CVE-2005-3185.json").write_text(json.dumps(
            git_boundary_doc("CVE-2005-3185", [SHA_C])), encoding="utf-8")
        (cache / "CVE-1999-0001.json").write_text(json.dumps(
            {"code": 404, "message": "not found"}), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def write_rows(self, rows):
        (self.project / "catalog.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    def read_rows(self):
        return [json.loads(line) for line in
                (self.project / "catalog.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_collect_facts_merges_aliases(self):
        facts = collect_osv_facts(self.client, "CVE-2023-38545", CURL_REPO)
        self.assertEqual(facts["fixes"], [SHA_A])
        self.assertEqual(facts["cwes"], ["CWE-787", "CWE-125"])
        self.assertEqual(facts["missing"], [])

    def test_collect_facts_ignores_git_range_boundaries(self):
        # CVE-2005-3185 is the row round 1 enriched with the GIT 'fixed' event.
        facts = collect_osv_facts(self.client, "CVE-2005-3185", CURL_REPO)
        self.assertEqual(facts["fixes"], [])
        self.assertEqual(facts["queried"], ["CVE-2005-3185"])

    def test_collect_facts_counts_404_and_cache_miss_as_missing(self):
        # CVE-1999-0001 has a cached 404 body; CVE-2022-32221 has no cache entry.
        self.assertEqual(collect_osv_facts(self.client, "CVE-1999-0001", CURL_REPO)["missing"],
                         ["CVE-1999-0001"])
        self.assertEqual(collect_osv_facts(self.client, "CVE-2022-32221", CURL_REPO)["missing"],
                         ["CVE-2022-32221"])

    def test_offline_enrichment_and_summary(self):
        catalog_text, index_text, stats = enrich_project(self.project, self.client)
        rows = [json.loads(line) for line in catalog_text.splitlines()]
        self.assertEqual(rows[0]["fix_shas"], [SHA_A])
        self.assertEqual(rows[0]["cwe"], "CWE-787")
        self.assertEqual(rows[0]["fix_sha_source"], "osv")
        self.assertEqual(rows[1]["cwe"], "CWE-787")          # existing value kept
        self.assertEqual(rows[1]["fix_shas"], [SHA_B])         # no OSV doc cached: untouched
        self.assertNotIn("fix_sha_source", rows[1])
        self.assertNotIn("cwe_source", rows[1])
        self.assertEqual(rows[2]["fix_shas"], [])
        self.assertNotIn("fix_sha_source", rows[2])
        index = json.loads(index_text)
        self.assertEqual(stats, {"project": "curl", "rows": 3, "with_fix_sha_before": 1,
                                 "with_cwe_before": 1, "not_in_osv": 2,
                                 "with_fix_sha": 2, "with_cwe": 2})
        self.assertEqual(index["entry_count"], 3)
        self.assertEqual(index["rows"], 3)
        self.assertEqual(index["with_fix_sha_before"], 1)
        self.assertEqual(index["with_fix_sha"], 2)
        self.assertEqual(index["with_cwe_before"], 1)
        self.assertEqual(index["with_cwe"], 2)
        self.assertEqual(index["not_in_osv"], 2)

    def test_offline_is_deterministic_and_idempotent(self):
        first = enrich_project(self.project, self.client)
        (self.project / "catalog.jsonl").write_text(first[0], encoding="utf-8")
        (self.project / "index.json").write_text(first[1], encoding="utf-8")
        second = enrich_project(self.project, self.client)
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])

    def test_all_emitted_shas_match_shared_regex(self):
        catalog_text, _, _ = enrich_project(self.project, self.client)
        for line in catalog_text.splitlines():
            for sha in json.loads(line)["fix_shas"]:
                self.assertTrue(SHA_RE.fullmatch(sha))

    def test_script_writes_then_checks_then_detects_drift(self):
        """Execute the real script artifact against the temp tree."""
        env = dict(os.environ, KSM_CVE_HISTORY_DIR=str(Path(self.tmp.name)))
        run = lambda *extra: subprocess.run(  # noqa: E731
            [sys.executable, str(SCRIPT), "--projects", "curl", "--offline", *extra],
            capture_output=True, text=True, env=env, cwd=str(Path(self.tmp.name)))

        pristine = run("--check")
        self.assertEqual(pristine.returncode, 1, pristine.stderr)
        self.assertIn("curl/catalog.jsonl differs", pristine.stderr)

        written = run()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertIn("with_fix_sha 1->2", written.stdout)
        rows = self.read_rows()
        self.assertEqual(rows[0]["fix_shas"], [SHA_A])
        self.assertEqual(rows[0]["cwe"], "CWE-787")
        self.assertEqual(json.loads((self.project / "index.json").read_text())["with_fix_sha"], 2)

        checked = run("--check")
        self.assertEqual(checked.returncode, 0, checked.stderr)

        rows = self.read_rows()
        rows[0]["fix_shas"] = []
        self.write_rows(rows)
        drift = run("--check")
        self.assertEqual(drift.returncode, 1)
        self.assertIn("curl/catalog.jsonl differs", drift.stderr)

        index = json.loads((self.project / "index.json").read_text())
        index["with_fix_sha"] = 99
        (self.project / "index.json").write_text(json.dumps(index), encoding="utf-8")
        drift_index = run("--check")
        self.assertEqual(drift_index.returncode, 1)
        self.assertIn("curl/index.json differs", drift_index.stderr)

    def test_offline_cache_miss_opens_no_connection(self):
        client = OsvClient(Path(self.tmp.name) / "empty-cache", offline=True)
        _, _, stats = enrich_project(self.project, client)
        self.assertEqual(stats["not_in_osv"], 3)
        self.assertEqual(stats["with_fix_sha"], 1)
        self.assertFalse((Path(self.tmp.name) / "empty-cache").exists())


class TestRepoState(unittest.TestCase):
    def test_default_projects_and_repo_catalogs_agree_with_cache(self):
        """Guard catalog drift against the committed OSV cache (skipped without cache)."""
        cache = Path(__file__).resolve().parents[1] / "docs/studies/cve-history" / "osv-cache"
        if not cache.is_dir():
            self.skipTest("osv-cache not present in this checkout")
        client = OsvClient(cache, offline=True)
        self.assertEqual(DEFAULT_PROJECTS, ("openssl", "curl", "glibc", "openssh"))
        for project in DEFAULT_PROJECTS:
            project_dir = cache.parent / project
            if not (project_dir / "catalog.jsonl").exists():
                continue
            expected_catalog, expected_index, _ = enrich_project(project_dir, client)
            self.assertEqual((project_dir / "catalog.jsonl").read_text(encoding="utf-8"),
                             expected_catalog, f"{project}/catalog.jsonl is stale")
            self.assertEqual((project_dir / "index.json").read_text(encoding="utf-8"),
                             expected_index, f"{project}/index.json is stale")


if __name__ == "__main__":
    unittest.main()
