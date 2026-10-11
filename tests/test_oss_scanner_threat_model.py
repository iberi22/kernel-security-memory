#!/usr/bin/env python3
"""Tests for scripts/oss_scanner/threat_model.py. Offline, synthetic repos only."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "oss_scanner" / "threat_model.py"

HEADINGS = [
    "## What this project does and where untrusted input enters",
    "## Components that matter most / least",
    "## How to exercise it",
    "## How you rate severity",
    "## Anything to leave alone",
]

CONTEXT = """\
description: synthetic test project
untrusted_inputs:
  - CLI arguments
trusted:
  - local config file
components_most:
  - parser
components_least:
  - docs
exercise:
  - run pytest
leave_alone: []
severity_overrides: {"CWE-78": "critical"}
"""

TRIGGER = 'import os\n\ndef f(x):\n    os.system("EVIL_EXCERPT_MARKER_123" + x)\n'


def run_script(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=120)


class ThreatModelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        (self.repo / "node_modules").mkdir(parents=True)
        (self.repo / "data").mkdir(parents=True)
        (self.repo / "a.py").write_text(TRIGGER, encoding="utf-8")
        (self.repo / "clean.py").write_text("x = 1\n", encoding="utf-8")
        (self.repo / "node_modules" / "evil.py").write_text(
            TRIGGER, encoding="utf-8")
        (self.repo / "data" / "evil.py").write_text(
            TRIGGER, encoding="utf-8")
        self.ctx = Path(self.tmp.name) / "ctx.yaml"
        self.ctx.write_text(CONTEXT, encoding="utf-8")
        self.out = Path(self.tmp.name) / "tm.md"

    def tearDown(self):
        self.tmp.cleanup()

    def _generate(self, out=None):
        args = ["--repo", str(self.repo), "--name", "synth",
                "--context", str(self.ctx)]
        if out:
            args += ["--out", str(out)]
        return run_script(*args)

    def test_unparseable_context_is_a_clean_error(self):
        self.ctx.write_text("description: x\nexercise:\n  - `bad`\n", encoding="utf-8")
        result = self._generate(self.out)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("cannot parse context", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_headings_present(self):
        result = self._generate(self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.out.read_text(encoding="utf-8")
        for heading in HEADINGS:
            self.assertIn(heading, text)

    def test_deterministic_rerun(self):
        second = Path(self.tmp.name) / "tm2.md"
        self.assertEqual(self._generate(self.out).returncode, 0)
        self.assertEqual(self._generate(second).returncode, 0)
        self.assertEqual(self.out.read_bytes(), second.read_bytes())

    def test_check_passes_and_fails(self):
        self.assertEqual(self._generate(self.out).returncode, 0)
        check = run_script("--repo", str(self.repo), "--name", "synth",
                           "--context", str(self.ctx),
                           "--out", str(self.out), "--check")
        self.assertEqual(check.returncode, 0, check.stderr)
        with self.out.open("a", encoding="utf-8") as fh:
            fh.write("tamper\n")
        check = run_script("--repo", str(self.repo), "--name", "synth",
                           "--context", str(self.ctx),
                           "--out", str(self.out), "--check")
        self.assertNotEqual(check.returncode, 0)

    def test_excluded_dirs_not_scanned(self):
        self.assertEqual(self._generate(self.out).returncode, 0)
        text = self.out.read_text(encoding="utf-8")
        self.assertIn("a.py", text)
        self.assertNotIn("node_modules", text)
        self.assertNotIn("should-be-excluded", text)
        # data/evil.py excluded too: only one hotspot file section entry
        self.assertNotIn("data/evil.py", text)

    def test_no_code_excerpts(self):
        self.assertEqual(self._generate(self.out).returncode, 0)
        text = self.out.read_text(encoding="utf-8")
        self.assertNotIn("EVIL_EXCERPT_MARKER_123", text)
        self.assertIn("SEC-CWE-78-COMMAND-INJECTION-PYTHON", text)
        self.assertIn("CWE-78", text)

    def test_colon_in_list_item(self):
        ctx = Path(self.tmp.name) / "ctx-colon.yaml"
        ctx.write_text(
            CONTEXT.replace("  - parser",
                            "  - src/api (HTTP surface: search, graph)"),
            encoding="utf-8")
        out = Path(self.tmp.name) / "tm-colon.md"
        result = run_script("--repo", str(self.repo), "--name", "synth",
                            "--context", str(ctx), "--out", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("src/api (HTTP surface: search, graph)",
                        out.read_text(encoding="utf-8"))

    def test_missing_output_dir_created(self):
        out = Path(self.tmp.name) / "newdir" / "sub" / "tm.md"
        result = self._generate(out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(out.is_file())

    def test_repo_not_a_directory_rejected(self):
        missing = Path(self.tmp.name) / "nope"
        result = run_script("--repo", str(missing), "--name", "synth",
                            "--context", str(self.ctx),
                            "--out", str(self.out))
        self.assertEqual(result.returncode, 2,
                         result.stdout + result.stderr)
        afile = Path(self.tmp.name) / "afile"
        afile.write_text("x = 1\n", encoding="utf-8")
        result = run_script("--repo", str(afile), "--name", "synth",
                            "--context", str(self.ctx),
                            "--out", str(self.out))
        self.assertEqual(result.returncode, 2,
                         result.stdout + result.stderr)

    def test_missing_untrusted_inputs_rejected(self):
        self.ctx.write_text("description: x\n", encoding="utf-8")
        result = self._generate(self.out)
        self.assertEqual(result.returncode, 2,
                         result.stdout + result.stderr)
        self.assertIn("untrusted_inputs", result.stderr)

    def test_empty_untrusted_inputs_rejected(self):
        self.ctx.write_text("description: x\nuntrusted_inputs: []\n",
                            encoding="utf-8")
        result = self._generate(self.out)
        self.assertEqual(result.returncode, 2,
                         result.stdout + result.stderr)
        self.assertIn("untrusted_inputs", result.stderr)

    def test_fallback_parser_accepts_inline_empty_list(self):
        import unittest.mock
        sys.path.insert(0, str(REPO_ROOT / "scripts" / "oss_scanner"))
        import threat_model
        ctx = Path(self.tmp.name) / "ctx-fallback.yaml"
        ctx.write_text("description: x\nuntrusted_inputs:\n"
                       "  - cli\nleave_alone: []\n",
                       encoding="utf-8")
        with unittest.mock.patch.dict(sys.modules, {"yaml": None}):
            data = threat_model.load_context(str(ctx))
        self.assertEqual(data["leave_alone"], [])
        self.assertEqual(data["untrusted_inputs"], ["cli"])

    def test_check_ignores_ksm_commit_drift(self):
        import re
        self.assertEqual(self._generate(self.out).returncode, 0)
        text = self.out.read_text(encoding="utf-8")
        self.assertIn("KSM commit ", text)
        doctored = re.sub(r"KSM commit \S+;", "KSM commit deadbee;",
                          text)
        self.assertNotEqual(doctored, text)
        self.out.write_text(doctored, encoding="utf-8")
        check = run_script("--repo", str(self.repo), "--name", "synth",
                           "--context", str(self.ctx),
                           "--out", str(self.out), "--check")
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_leave_alone_excluded(self):
        ctx = Path(self.tmp.name) / "ctx2.yaml"
        ctx.write_text(CONTEXT.replace("leave_alone: []",
                                       "leave_alone:\n  - a.py"),
                       encoding="utf-8")
        out = Path(self.tmp.name) / "tm3.md"
        result = run_script("--repo", str(self.repo), "--name", "synth",
                            "--context", str(ctx), "--out", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        text = out.read_text(encoding="utf-8")
        self.assertNotIn("a.py`", text)
        self.assertIn("No auditor findings in scope.", text)


if __name__ == "__main__":
    unittest.main()
