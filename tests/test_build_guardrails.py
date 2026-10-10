#!/usr/bin/env python3
"""Tests for scripts/build_guardrails.py.

The generator must be deterministic, must only emit evidence that exists in the
repository, and must drift-check its own output. Every assertion below runs the real
generator against the real repository data.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_GUARDRAILS = REPO_ROOT / "scripts" / "build_guardrails.py"
MD_PATH = REPO_ROOT / "docs" / "skills" / "defensive-security-auditor" / "references" / "guardrails.md"
JSON_PATH = REPO_ROOT / "docs" / "skills" / "defensive-security-auditor" / "references" / "guardrails.json"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from build_guardrails import (  # noqa: E402
    build_document,
    iter_cited_shas,
    verify_citations,
)
from defensive_auditor import SECURITY_RULES  # noqa: E402

HEX40 = __import__("re").compile(r"^[0-9a-f]{40}$")

# Built once from the real repository data; both test classes assert against it.
MARKDOWN, GUARDRAILS = build_document()


class TestBuildGuardrails(TestCase):
    def test_only_families_with_rule_and_evidence_are_emitted(self):
        """A section needs an auditor rule AND a 40-hex fix commit in the repo."""
        rule_cwes = {rule["cwe_id"] for rule in SECURITY_RULES}
        for family in GUARDRAILS["families"]:
            self.assertIn(family["cwe_id"], rule_cwes)
            self.assertTrue(family["citations"], family["cwe_id"])
            self.assertTrue(family["rules"], family["cwe_id"])
            for citation in family["citations"]:
                self.assertRegex(citation["fix_commit_sha"], HEX40)

    def test_families_without_evidence_are_the_complement(self):
        covered = {f["cwe_id"] for f in GUARDRAILS["families"]}
        uncovered = {f["cwe_id"] for f in GUARDRAILS["families_without_evidence"]}
        rule_cwes = {rule["cwe_id"] for rule in SECURITY_RULES}
        self.assertEqual(covered | uncovered, rule_cwes)
        self.assertEqual(covered & uncovered, set())
        for family in GUARDRAILS["families_without_evidence"]:
            self.assertNotIn("citations", family)

    def test_at_most_three_citations_per_family(self):
        for family in GUARDRAILS["families"]:
            self.assertLessEqual(len(family["citations"]), 3, family["cwe_id"])

    def test_counts_come_from_pattern_clusters(self):
        clusters = json.loads(
            (REPO_ROOT / "docs" / "studies" / "pattern_clusters.json").read_text(encoding="utf-8")
        )["clusters"]
        by_cwe = {c["cwe_id"]: c for c in clusters}
        for family in GUARDRAILS["families"]:
            cluster = by_cwe[family["cwe_id"]]
            self.assertEqual(family["cluster_count"], cluster["count"])
            self.assertEqual(family["cluster_with_fix_sha"], cluster["with_fix_sha"])
            self.assertEqual(family["cluster_title"], cluster["title"])

    def test_rules_come_from_security_rules(self):
        by_id = {rule["id"]: rule for rule in SECURITY_RULES}
        for family in GUARDRAILS["families"]:
            for emitted in family["rules"]:
                rule = by_id[emitted["rule_id"]]
                self.assertEqual(rule["cwe_id"], family["cwe_id"])
                self.assertEqual(emitted["pattern"], rule["pattern"])
                self.assertEqual(emitted["severity"], rule["severity"])
                self.assertEqual(emitted["lesson"], rule["lesson"])

    def test_output_is_deterministic(self):
        first_md, first_json = build_document()
        second_md, second_json = build_document()
        self.assertEqual(first_md, second_md)
        self.assertEqual(
            json.dumps(first_json, sort_keys=True), json.dumps(second_json, sort_keys=True)
        )

    def test_markdown_is_generated_from_the_json_model(self):
        for family in GUARDRAILS["families"]:
            self.assertIn(f"## {family['cwe_id']}", MARKDOWN)
            for citation in family["citations"]:
                self.assertIn(citation["advisory_id"], MARKDOWN)
                self.assertIn(citation["fix_commit_sha"], MARKDOWN)

    def test_verify_citations_finds_nothing_missing(self):
        problems = verify_citations(GUARDRAILS)
        self.assertEqual(problems, [])

    def test_verify_citations_detects_a_fabricated_sha(self):
        """A citation that no source file backs must be reported, not silently kept."""
        tampered = json.loads(json.dumps(GUARDRAILS))
        tampered["families"][0]["citations"][0]["fix_commit_sha"] = "0" * 40
        problems = verify_citations(tampered)
        self.assertTrue(problems)
        self.assertIn("not found", problems[0])


class TestBuildGuardrailsCli(TestCase):
    def _run(self, *args, cwd=REPO_ROOT):
        return subprocess.run(
            [sys.executable, str(BUILD_GUARDRAILS), *args],
            capture_output=True, text=True, cwd=str(cwd),
        )

    # Generation tests write into a temporary --out-dir: the test suite must never
    # rewrite the committed skill references.
    def test_generate_then_check_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._run("--out-dir", tmp).returncode, 0)
            result = self._run("--check", "--out-dir", tmp)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("guardrails up to date", result.stdout)

    def test_check_fails_on_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._run("--out-dir", tmp).returncode, 0)
            md = Path(tmp) / MD_PATH.name
            md.write_text(md.read_text(encoding="utf-8") + "\ndrift\n", encoding="utf-8")
            result = self._run("--check", "--out-dir", tmp)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("DRIFT", result.stderr)

    def test_suite_does_not_touch_committed_references(self):
        before = (MD_PATH.read_bytes(), JSON_PATH.read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            self._run("--out-dir", tmp)
        self.assertEqual((MD_PATH.read_bytes(), JSON_PATH.read_bytes()), before)

    def test_check_is_cwd_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run("--check", cwd=tmp)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_verify_citations_flag_reports_zero_missing(self):
        result = self._run("--verify-citations")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0 missing", result.stdout)

    def test_committed_files_match_generated_output(self):
        markdown, guardrails = build_document()
        self.assertEqual(MD_PATH.read_text(encoding="utf-8"), markdown)
        self.assertEqual(
            JSON_PATH.read_text(encoding="utf-8"),
            json.dumps(guardrails, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        )

    def test_every_citation_source_file_is_listed_in_the_json(self):
        for family in GUARDRAILS["families"]:
            for citation in family["citations"]:
                source = REPO_ROOT / citation["source"]
                self.assertTrue(source.is_file(), citation["source"])
                self.assertIn(citation["fix_commit_sha"], source.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
