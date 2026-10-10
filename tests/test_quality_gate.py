#!/usr/bin/env python3
"""Tests for the KSM quality gate CLI contract (strict mode and exit codes)."""

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


if __name__ == "__main__":
    main()
