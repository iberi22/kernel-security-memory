"""Offline tests for scripts/studies/oss_scanner_projects.py.

A tiny synthetic fixture tree (tests/fixtures/oss_scanner) stands in for
the pinned oss-scanner clone; the fixture source is git-committed under a
fixed date so fetched_at determinism is exercised without network access.
OSV is always skipped (--no-osv): offline fields must be null.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts" / "studies"))

import oss_scanner_projects as osp  # noqa: E402

FIXTURES = REPO / "tests" / "fixtures" / "oss_scanner"
FIXED_DATE = "2026-10-01T00:00:00+00:00"


def _git(args, cwd, env=None):
    merged = dict(os.environ)
    merged.update(env or {})
    proc = subprocess.run(
        ["git"] + args, cwd=str(cwd), capture_output=True, text=True,
        timeout=60, env=merged,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def make_source(root):
    """Copy the fixture tree into tmp and commit it under a fixed date."""
    src = Path(root) / "source"
    shutil.copytree(FIXTURES, src)
    env = {
        "GIT_AUTHOR_DATE": FIXED_DATE,
        "GIT_COMMITTER_DATE": FIXED_DATE,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@t",
    }
    _git(["init", "-q"], src)
    _git(["add", "."], src)
    _git(["commit", "-qm", "fixture"], src, env)
    return src


def make_catalogs(root):
    cats = Path(root) / "catalogs"
    for name in ("alpha", "alpha-upstream", "unrelated"):
        (cats / name).mkdir(parents=True)
    return cats


class SelectionManifestTest(unittest.TestCase):
    def test_build_is_sorted_deterministic_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = make_source(tmp)
            manifest = osp.build_manifest(
                source=str(src), ref=None,
                catalogs_dir=str(make_catalogs(tmp)),
                cache_dir=str(Path(tmp) / "cache"), no_osv=True,
            )
            head = _git(["rev-parse", "HEAD"], src)
            self.assertEqual([p["name"] for p in manifest["projects"]], ["alpha", "beta"])
            alpha, beta = manifest["projects"]
            self.assertEqual(alpha["repo"], "https://github.com/example/alpha")
            self.assertEqual(alpha["branch"], "main")
            self.assertTrue(alpha["has_dockerfile_here"])
            self.assertFalse(alpha["has_threat_model"])
            self.assertEqual(alpha["ksm_catalogs"], ["alpha", "alpha-upstream"])
            self.assertIsNone(alpha["osv_git_supported"])
            # Trailing .git is stripped, missing branch is null.
            self.assertEqual(beta["repo"], "https://example.com/beta")
            self.assertIsNone(beta["branch"])
            self.assertFalse(beta["has_dockerfile_here"])
            self.assertTrue(beta["has_threat_model"])
            self.assertEqual(beta["ksm_catalogs"], [])
            # Commit provenance comes from the clone, never the wall clock.
            self.assertEqual(manifest["source_commit"], head)
            self.assertTrue(manifest["fetched_at"].startswith("2026-10-01T00:00:00"), manifest["fetched_at"])
            # No emails or PGP keys leak into the manifest.
            self.assertNotIn("@", json.dumps(manifest))

    def test_check_roundtrip_and_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = make_source(tmp)
            out = str(Path(tmp) / "manifest.json")
            base = ["--source", str(src), "--catalogs-dir", str(make_catalogs(tmp)),
                    "--cache-dir", str(Path(tmp) / "cache"), "--no-osv",
                    "--output", out]
            self.assertEqual(osp.main(base), 0)
            self.assertEqual(osp.main(base + ["--check"]), 0)
            (src / "projects" / "beta" / "project.yaml").write_text(
                "repo: https://example.com/beta2\n", encoding="utf-8"
            )
            self.assertEqual(osp.main(base + ["--check"]), 1)

    def test_exactly_one_of_source_and_ref(self):
        with self.assertRaises(SystemExit):
            osp.build_manifest(source=None, ref=None, catalogs_dir=".", cache_dir=".", no_osv=True)
        with self.assertRaises(SystemExit):
            osp.build_manifest(source="a", ref="b", catalogs_dir=".", cache_dir=".", no_osv=True)


if __name__ == "__main__":
    unittest.main()
