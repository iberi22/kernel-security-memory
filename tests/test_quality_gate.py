#!/usr/bin/env python3
"""Tests for the KSM quality gate CLI contract (strict mode and exit codes)."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

REPO_ROOT = Path(__file__).resolve().parents[1]
QUALITY_GATE = REPO_ROOT / "scripts" / "quality_gate.py"


class TestQualityGateStrictFlag(TestCase):
    """--strict must be able to disable strict mode (BooleanOptionalAction)."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _warn_target(self):
        # A MEDIUM finding (unchecked multiplication in malloc) yields verdict WARN.
        (self.base_dir / "warn.c").write_text(
            "int *table(size_t a, size_t b) { return (int *)malloc(a * b); }\n",
            encoding="utf-8",
        )
        return str(self.base_dir)

    def test_strict_flag_defaults_to_true(self):
        r = subprocess.run(
            [sys.executable, str(QUALITY_GATE), "--target", self._warn_target()],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Publication Authorized: NO", r.stdout)
        self.assertIn("strict", r.stdout)

    def test_no_strict_flag_disables_strict_mode(self):
        r = subprocess.run(
            [sys.executable, str(QUALITY_GATE), "--no-strict", "--target", self._warn_target()],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Publication Authorized: YES", r.stdout)

    def test_explicit_strict_flag_is_still_accepted(self):
        r = subprocess.run(
            [sys.executable, str(QUALITY_GATE), "--strict", "--target", self._warn_target()],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Publication Authorized: NO", r.stdout)

    def test_help_documents_both_forms(self):
        r = subprocess.run(
            [sys.executable, str(QUALITY_GATE), "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("--strict", r.stdout)
        self.assertIn("--no-strict", r.stdout)


class TestQualityGateEvidenceFreshness(TestCase):
    """--evidence must reject a citation whose hash no longer matches the tree.

    Regression guard: the gate used to re-audit the target and report the fresh hash,
    which authorised every stored citation regardless of tree drift.
    """

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.tmp_dir.name)
        # A repository-shaped tree: .git anchors relative recorded targets, and the
        # default clusters path resolves next to the evidence file.
        (self.base_dir / ".git").mkdir()
        (self.base_dir / "docs" / "studies").mkdir(parents=True)
        (self.base_dir / "pkg").mkdir()
        shutil.copy(
            REPO_ROOT / "docs" / "studies" / "pattern_clusters.json",
            self.base_dir / "docs" / "studies" / "pattern_clusters.json",
        )
        (self.base_dir / "pkg" / "clean.py").write_text(
            "def greet(name):\n    return 'hi ' + name\n", encoding="utf-8")
        self.evidence_path = self.base_dir / "docs" / "studies" / "evidence.json"
        self._generate_evidence()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _gate(self, *args, cwd):
        return subprocess.run(
            [sys.executable, str(QUALITY_GATE), *args],
            capture_output=True, text=True, cwd=str(cwd),
        )

    def _generate_evidence(self):
        r = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "defensive_auditor.py"),
             "--target", "pkg",
             "--clusters", "docs/studies/pattern_clusters.json",
             "--output", str(self.evidence_path)],
            capture_output=True, text=True, cwd=str(self.base_dir),
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_unchanged_tree_is_authorized(self):
        r = self._gate("--target", "pkg", "--evidence",
                       str(self.evidence_path), cwd=self.base_dir)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Quality Gate Status: AUTHORIZED", r.stdout)

    def test_modified_file_yields_verdict_stale(self):
        (self.base_dir / "pkg" / "clean.py").write_text(
            "def greet(name):\n    return 'hi ' + name + '!'\n", encoding="utf-8")
        r = self._gate("--target", "pkg", "--evidence",
                       str(self.evidence_path), cwd=self.base_dir)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Quality Gate Status: STALE", r.stdout)
        self.assertIn("Publication Authorized: NO", r.stdout)

    def test_added_file_yields_verdict_stale(self):
        (self.base_dir / "pkg" / "extra.py").write_text("VALUE = 2\n", encoding="utf-8")
        r = self._gate("--target", "pkg", "--evidence",
                       str(self.evidence_path), cwd=self.base_dir)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Quality Gate Status: STALE", r.stdout)

    def test_recorded_target_resolves_independently_of_cwd(self):
        # No --target: the recorded relative target must resolve through the
        # repository root anchored at the evidence file, not through the CWD.
        with tempfile.TemporaryDirectory() as elsewhere:
            unchanged = self._gate("--evidence", str(self.evidence_path), cwd=elsewhere)
            self.assertEqual(unchanged.returncode, 0, unchanged.stdout + unchanged.stderr)
            self.assertIn("Quality Gate Status: AUTHORIZED", unchanged.stdout)

            (self.base_dir / "pkg" / "clean.py").write_text("VALUE = 3\n", encoding="utf-8")
            stale = self._gate("--evidence", str(self.evidence_path), cwd=elsewhere)
            self.assertEqual(stale.returncode, 1, stale.stdout + stale.stderr)
            self.assertIn("Quality Gate Status: STALE", stale.stdout)

    def test_relative_target_without_repo_root_is_rejected(self):
        # A relative target and no .git anchor must fail closed, never guess a CWD.
        (self.base_dir / ".git").rmdir()
        r = self._gate("--evidence", str(self.evidence_path), cwd=self.base_dir)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Publication Authorized: NO", r.stdout)
        self.assertIn("repository root", r.stdout)

    def test_stale_evidence_report_contains_both_hashes(self):
        (self.base_dir / "pkg" / "clean.py").write_text("VALUE = 4\n", encoding="utf-8")
        report = self.base_dir / "docs" / "studies" / "report.json"
        r = self._gate("--target", "pkg", "--evidence", str(self.evidence_path),
                       "--output", str(report), cwd=self.base_dir)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "STALE")
        self.assertNotEqual(payload["stored_evidence_chain_hash"],
                            payload["fresh_evidence_chain_hash"])
        self.assertIn("stale", payload["reason"].lower())

    def test_absolute_target_evidence_is_checked_without_a_repo_root(self):
        """An absolute recorded target needs no .git anchor, but still must be checked."""
        with tempfile.TemporaryDirectory() as bare:
            bare_dir = Path(bare)
            (bare_dir / "pkg").mkdir()
            (bare_dir / "pkg" / "clean.py").write_text("A = 1\n", encoding="utf-8")
            evidence = bare_dir / "evidence.json"
            generated = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "defensive_auditor.py"),
                 "--target", str(bare_dir / "pkg"),
                 "--clusters", str(REPO_ROOT / "docs" / "studies" / "pattern_clusters.json"),
                 "--output", str(evidence)],
                capture_output=True, text=True, cwd=str(bare_dir),
            )
            self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)

            with tempfile.TemporaryDirectory() as elsewhere:
                fresh = self._gate(
                    "--clusters",
                    str(REPO_ROOT / "docs" / "studies" / "pattern_clusters.json"),
                    "--evidence", str(evidence), cwd=elsewhere)
                self.assertEqual(fresh.returncode, 0, fresh.stdout + fresh.stderr)
                self.assertIn("AUTHORIZED", fresh.stdout)

                (bare_dir / "pkg" / "clean.py").write_text("A = 2\n", encoding="utf-8")
                stale = self._gate(
                    "--clusters",
                    str(REPO_ROOT / "docs" / "studies" / "pattern_clusters.json"),
                    "--evidence", str(evidence), cwd=elsewhere)
                self.assertEqual(stale.returncode, 1, stale.stdout + stale.stderr)
                self.assertIn("STALE", stale.stdout)

    def test_committed_scripts_evidence_is_current_or_stale_never_false_green(self):
        """The gate must never report a hash it did not actually verify.

        On the real repository tree the gate either authorises (the committed evidence
        matches this tree) or reports STALE (the tree moved on). Both are acceptable;
        silently printing a fresh hash for a stale citation is not.
        """
        r = self._gate("--target", "scripts", "--evidence",
                       str(REPO_ROOT / "docs" / "studies" / "audit_evidence_scripts.json"),
                       cwd=REPO_ROOT)
        self.assertIn("Quality Gate Status:", r.stdout)
        if "STALE" in r.stdout:
            self.assertEqual(r.returncode, 1)
            self.assertIn("Stored Evidence Chain Hash:", r.stdout)
            self.assertIn("Fresh Audit Evidence Chain Hash:", r.stdout)
        else:
            self.assertIn("AUTHORIZED", r.stdout)
            self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    main()
