#!/usr/bin/env python3
"""Tests for scripts/oss_scanner/enroll.py. Offline, tempdirs only."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"
                       / "oss_scanner"))
import enroll  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "oss_scanner" / "enroll.py"


# The upstream validator lives in a local clone of anthropics/oss-scanner; CI has none.
CLONE = os.environ.get("OSS_SCANNER_CLONE")
needs_clone = unittest.skipUnless(
    CLONE and (Path(CLONE) / "tools" / "validate.py").is_file(),
    "set OSS_SCANNER_CLONE to a local anthropics/oss-scanner clone")


def run_enroll(*args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=120, env=env)


class EnrollTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "enrollment"

    def tearDown(self):
        self.tmp.cleanup()

    def _valid_args(self):
        return ["--name", "testproj",
                "--repo-url", "https://github.com/example/testproj",
                "--contact", "sec@example.org",
                "--out", str(self.out)]

    @needs_clone
    def test_valid_enrollment_both_validators_pass(self):
        result = run_enroll(*self._valid_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ksm-checks: PASS", result.stdout)
        self.assertIn("upstream-validator: PASS", result.stdout)
        project_yaml = self.out / "projects" / "testproj" / "project.yaml"
        self.assertTrue(project_yaml.is_file())
        self.assertEqual(enroll.ksm_validate(
            self.out / "projects" / "testproj"), [])
        problems, _ = enroll.upstream_validate(
            self.out / "projects" / "testproj", CLONE)
        self.assertEqual(problems, [])

    @needs_clone
    def test_bad_key_rejected_by_both_validators(self):
        project_dir = self.out / "projects" / "testproj"
        project_dir.mkdir(parents=True)
        (project_dir / "project.yaml").write_text(
            "repo: https://github.com/example/testproj\n"
            "primary_contact: sec@example.org\n"
            "dockerfile: .oss-scanner/Dockerfile\n"
            "evil_key: true\n", encoding="utf-8")
        ksm_problems = enroll.ksm_validate(project_dir)
        self.assertTrue(any("evil_key" in p for p in ksm_problems),
                        ksm_problems)
        upstream_problems, _ = enroll.upstream_validate(project_dir, CLONE)
        self.assertTrue(any("evil_key" in p for p in upstream_problems),
                        upstream_problems)

    def test_existing_enrollment_refused_without_force(self):
        project_dir = self.out / "projects" / "testproj"
        project_dir.mkdir(parents=True)
        sentinel = project_dir / "project.yaml"
        sentinel.write_text(
            "repo: https://github.com/example/testproj\n"
            "primary_contact: sec@example.org\n"
            "auto_ccs: [keep@example.org]\n", encoding="utf-8")
        before = sentinel.read_bytes()
        result = run_enroll(*self._valid_args())
        self.assertEqual(result.returncode, 2,
                         result.stdout + result.stderr)
        self.assertIn("--force", result.stderr)
        self.assertEqual(sentinel.read_bytes(), before)

    def test_force_replaces_existing_enrollment(self):
        env = {k: v for k, v in os.environ.items()
               if k != "OSS_SCANNER_CLONE"}
        project_dir = self.out / "projects" / "testproj"
        project_dir.mkdir(parents=True)
        (project_dir / "project.yaml").write_text(
            "stale: true\n", encoding="utf-8")
        result = run_enroll(*self._valid_args(), "--force", env=env)
        self.assertNotEqual(result.returncode, 2,
                            result.stdout + result.stderr)
        text = (project_dir / "project.yaml").read_text(encoding="utf-8")
        self.assertNotIn("stale", text)
        self.assertIn("sec@example.org", text)

    def test_without_clone_never_reports_pass(self):
        env = {k: v for k, v in os.environ.items() if k != "OSS_SCANNER_CLONE"}
        result = run_enroll(*self._valid_args(), env=env)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("upstream-validator: PASS", result.stdout)
        self.assertIn("OSS_SCANNER_CLONE", result.stdout)

    def test_bad_contact_rejected(self):
        args = self._valid_args()
        args[args.index("--contact") + 1] = "not-an-email"
        result = run_enroll(*args)
        self.assertNotEqual(result.returncode, 0)

    def test_no_hardcoded_contact(self):
        # project.yaml is written before validation, with or without the clone.
        run_enroll(*self._valid_args())
        text = (self.out / "projects" / "testproj"
                / "project.yaml").read_text(encoding="utf-8")
        self.assertIn("sec@example.org", text)
        source = (REPO_ROOT / "scripts" / "oss_scanner"
                  / "enroll.py").read_text(encoding="utf-8")
        self.assertNotIn("example.org", source)
        self.assertNotIn("example.com", source)


if __name__ == "__main__":
    unittest.main()
