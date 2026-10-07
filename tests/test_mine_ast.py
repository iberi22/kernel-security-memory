"""Offline tests for scripts/mine_ast.py (stdlib only, no network)."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

from scripts.mine_ast import (
    ASTError,
    extract_units_stdlib,
    extract_units_treesitter,
    mine_file,
)

COMMIT = "60c0c230c6f046da536d3df8b39a20b9a9fd6af0"

BASIC_C = """\
#include <linux/kernel.h>

static int fixed_walk(struct rb_root *root)
{
\treturn walk_tree(root);
}

int walk_tree(struct rb_root *root);
"""

MACRO_IFDEF_C = """\
#define MAX_ENTRIES 256
#define walk_all(r) walk_tree(r)

#ifdef CONFIG_NF_TABLES
int guarded_fn(int x)
{
\treturn x + 1;
}
#endif

int plain_fn(void)
{
\treturn 0;
}
"""


class TestStdlibExtraction(unittest.TestCase):
    def test_finds_definition_not_prototype(self):
        units = extract_units_stdlib(BASIC_C, "nft_set_rbtree.c")
        names = [u["symbol"] for u in units]
        self.assertIn("fixed_walk", names)
        self.assertNotIn("walk_tree", [u["symbol"] for u in units if u["symbol"] == "walk_tree" and u["start_line"] == 8])
        # prototype on line 8 must not be extracted
        self.assertTrue(all(u["start_line"] != 8 for u in units))

    def test_line_range_and_body_hash(self):
        units = extract_units_stdlib(BASIC_C, "f.c")
        fn = next(u for u in units if u["symbol"] == "fixed_walk")
        self.assertEqual((fn["start_line"], fn["end_line"]), (3, 6))
        body = "{\n\treturn walk_tree(root);\n}"
        self.assertEqual(fn["body_sha256"], hashlib.sha256(body.encode()).hexdigest())

    def test_macros_excluded_ifdef_flagged(self):
        units = extract_units_stdlib(MACRO_IFDEF_C, "g.c")
        names = [u["symbol"] for u in units]
        self.assertNotIn("MAX_ENTRIES", names)
        self.assertNotIn("walk_all", names)
        guarded = next(u for u in units if u["symbol"] == "guarded_fn")
        plain = next(u for u in units if u["symbol"] == "plain_fn")
        self.assertTrue(guarded["conditional"])
        self.assertFalse(plain["conditional"])


class TestIdentity(unittest.TestCase):
    def test_mine_file_carries_repo_commit_blob_symbol(self):
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(BASIC_C)
            path = f.name
        try:
            rec = mine_file(path, "torvalds/linux", COMMIT, blob="abc123")
            self.assertEqual(rec["repo"], "torvalds/linux")
            self.assertEqual(rec["commit"], COMMIT)
            self.assertEqual(rec["blob"], "abc123")
            self.assertTrue(all(u["symbol"] for u in rec["units"]))
            self.assertEqual(rec["unit_count"], len(rec["units"]))
        finally:
            os.unlink(path)


class TestCleanFailures(unittest.TestCase):
    def test_treesitter_backend_fails_cleanly_without_dep(self):
        try:
            import tree_sitter  # noqa: F401
            import tree_sitter_c  # noqa: F401
            self.skipTest("tree-sitter installed; missing-dep path not testable")
        except ImportError:
            pass
        with self.assertRaises(ASTError) as ctx:
            extract_units_treesitter("int f(void){return 0;}", "f.c")
        self.assertIn("tree-sitter==0.26.0", str(ctx.exception))
        self.assertIn("tree-sitter-c==0.24.2", str(ctx.exception))

    def test_unknown_backend(self):
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("int f(void){return 0;}\n")
            path = f.name
        try:
            with self.assertRaises(ASTError):
                mine_file(path, "torvalds/linux", COMMIT, backend="nope")
        finally:
            os.unlink(path)

    def test_cli_rejects_short_commit(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as out:
            outpath = out.name
        try:
            r = subprocess.run(
                [sys.executable, "scripts/mine_ast.py", "--input", "x.c",
                 "--repo", "torvalds/linux", "--commit", "short",
                 "--output", outpath],
                capture_output=True, text=True,
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("40-hex", r.stderr)
        finally:
            os.unlink(outpath)

    def test_cli_missing_file_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            outpath = os.path.join(td, "out.json")
            r = subprocess.run(
                [sys.executable, "scripts/mine_ast.py", "--input", os.path.join(td, "nope.c"),
                 "--repo", "torvalds/linux", "--commit", COMMIT,
                 "--output", outpath],
                capture_output=True, text=True,
            )
            self.assertNotEqual(r.returncode, 0)
            with open(outpath, encoding="utf-8") as f:
                payload = json.load(f)
            self.assertEqual(payload["coverage"], "INCOMPLETE")
            self.assertTrue(payload["errors"])


if __name__ == "__main__":
    unittest.main()
