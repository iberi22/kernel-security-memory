"""Offline tests for scripts/mine_ast.py (stdlib only, no network)."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.mine_ast import (
    ASTError,
    compute_structural_diff,
    extract_fragment,
    extract_units_stdlib,
    extract_units_treesitter,
    mine_file,
    validate_fragment,
)
from tests.fixtures.linux_cve_2024_26581 import (
    AFTER_C,
    BEFORE_C,
    METADATA,
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

NESTED_PARENS_C = """\
static int reg_handler(void (*callback)(int x, void *ctx), int flags)
{
\treturn 0;
}
"""

UNBALANCED_BRACES_C = """\
int unclosed_fn(int a)
{
\tif (a > 0) {
\t\treturn a;
\t// missing closing braces
"""

UNRECOGNIZED_MACRO_C = """\
int macro_fn(int a) __asmeq_unrecognized UNKNOWN_ATTR
{
\treturn a * 2;
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
            self.assertEqual(rec["status"], "COMPLETE")
            self.assertEqual(rec["parser_skipped_count"], 0)
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


class TestFragmentContract(unittest.TestCase):
    """C1: Formal fragment contract tests."""

    def setUp(self):
        self.valid_fragment = {
            "repo": "torvalds/linux",
            "commit_sha": COMMIT,
            "blob_sha": "5fd74f993988f0c8478cd7258355c4eea90cc2e4",
            "symbol_name": "fixed_walk",
            "language": "c",
            "role": "before",
            "function_body": "static int fixed_walk(struct rb_root *root)\n{\n\treturn walk_tree(root);\n}\n",
            "lines_range": [3, 6],
            "truncated": False,
            "ast_indexed": True,
        }

    def test_schema_file_exists_and_matches_required_fields(self):
        # Resolve from the test file, not the process CWD, so the check holds
        # however unittest is invoked.
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "fragment.schema.json"
        self.assertTrue(schema_path.exists())
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        required = set(schema.get("required", []))
        expected_fields = {
            "repo",
            "commit_sha",
            "blob_sha",
            "symbol_name",
            "language",
            "role",
            "function_body",
            "lines_range",
            "truncated",
            "ast_indexed",
        }
        self.assertEqual(required, expected_fields)

    def test_validate_fragment_success(self):
        # Should not raise
        validate_fragment(self.valid_fragment)

    def test_validate_fragment_rejects_missing_fields(self):
        for field in [
            "repo",
            "commit_sha",
            "blob_sha",
            "symbol_name",
            "language",
            "role",
            "function_body",
            "lines_range",
            "truncated",
            "ast_indexed",
        ]:
            frag = copy.deepcopy(self.valid_fragment)
            del frag[field]
            with self.assertRaises(ValueError):
                validate_fragment(frag)

    def test_validate_fragment_rejects_invalid_values(self):
        # Invalid commit_sha
        bad_commit = copy.deepcopy(self.valid_fragment)
        bad_commit["commit_sha"] = "not-a-sha"
        with self.assertRaises(ValueError):
            validate_fragment(bad_commit)

        # Invalid blob_sha
        bad_blob = copy.deepcopy(self.valid_fragment)
        bad_blob["blob_sha"] = "invalid"
        with self.assertRaises(ValueError):
            validate_fragment(bad_blob)

        # Invalid role
        bad_role = copy.deepcopy(self.valid_fragment)
        bad_role["role"] = "middle"
        with self.assertRaises(ValueError):
            validate_fragment(bad_role)

        # Invalid lines_range
        bad_lines = copy.deepcopy(self.valid_fragment)
        bad_lines["lines_range"] = [10, 5]
        with self.assertRaises(ValueError):
            validate_fragment(bad_lines)

        # Non-boolean flags
        bad_flags = copy.deepcopy(self.valid_fragment)
        bad_flags["truncated"] = "false"
        with self.assertRaises(ValueError):
            validate_fragment(bad_flags)

    def test_validate_fragment_rejects_boolean_lines_range(self):
        # bool is a subclass of int, but the JSON schema type "integer" does not
        # match booleans, so the validator must reject them to stay in agreement.
        for lines_range in ([True, True], [True, 5], [3, True]):
            bad = copy.deepcopy(self.valid_fragment)
            bad["lines_range"] = lines_range
            with self.assertRaises(ValueError, msg=f"lines_range={lines_range} must be rejected"):
                validate_fragment(bad)

        # Sanity: the equivalent integer range is still valid.
        ok = copy.deepcopy(self.valid_fragment)
        ok["lines_range"] = [1, 1]
        validate_fragment(ok)

    def test_extract_fragment_basic(self):
        frag = extract_fragment(
            source=BASIC_C,
            symbol_name="fixed_walk",
            repo="torvalds/linux",
            commit_sha=COMMIT,
            blob_sha="5fd74f993988f0c8478cd7258355c4eea90cc2e4",
            role="before",
            path="net/netfilter/nft_set_rbtree.c",
        )
        self.assertEqual(frag["symbol_name"], "fixed_walk")
        self.assertEqual(frag["role"], "before")
        self.assertEqual(frag["lines_range"], [3, 6])
        self.assertFalse(frag["truncated"])
        self.assertTrue(frag["ast_indexed"])
        self.assertIn("return walk_tree(root);", frag["function_body"])

    def test_extract_fragment_truncation(self):
        frag = extract_fragment(
            source=BASIC_C,
            symbol_name="fixed_walk",
            repo="torvalds/linux",
            commit_sha=COMMIT,
            blob_sha="5fd74f993988f0c8478cd7258355c4eea90cc2e4",
            role="after",
            max_body_chars=20,
        )
        self.assertTrue(frag["truncated"])
        self.assertEqual(len(frag["function_body"]), 20)
        validate_fragment(frag)

    def test_extract_fragment_missing_symbol_raises_error(self):
        with self.assertRaises(ASTError):
            extract_fragment(
                source=BASIC_C,
                symbol_name="nonexistent_function",
                repo="torvalds/linux",
                commit_sha=COMMIT,
                blob_sha="5fd74f993988f0c8478cd7258355c4eea90cc2e4",
                role="before",
            )


class TestParserSkippedAudit(unittest.TestCase):
    """C2: Auditor of heuristic stdlib parser for skipped functions."""

    def test_nested_parentheses_marked_parser_skipped(self):
        units, skipped = extract_units_stdlib(NESTED_PARENS_C, "test_nested.c", return_skipped=True)
        self.assertEqual(len(units), 0)
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["symbol"], "reg_handler")
        self.assertEqual(skipped[0]["reason"], "nested_parentheses")

        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(NESTED_PARENS_C)
            path = f.name
        try:
            rec = mine_file(path, "torvalds/linux", COMMIT)
            self.assertEqual(rec["status"], "PARSER_SKIPPED")
            self.assertEqual(rec["parser_skipped_count"], 1)
            self.assertEqual(rec["unit_count"], 0)
        finally:
            os.unlink(path)

    def test_unbalanced_braces_marked_parser_skipped(self):
        units, skipped = extract_units_stdlib(UNBALANCED_BRACES_C, "test_unbalanced.c", return_skipped=True)
        self.assertEqual(len(units), 0)
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["symbol"], "unclosed_fn")
        self.assertEqual(skipped[0]["reason"], "unbalanced_braces")

        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(UNBALANCED_BRACES_C)
            path = f.name
        try:
            rec = mine_file(path, "torvalds/linux", COMMIT)
            self.assertEqual(rec["status"], "PARSER_SKIPPED")
            self.assertEqual(rec["parser_skipped_count"], 1)
        finally:
            os.unlink(path)

    def test_unrecognized_macro_marked_parser_skipped(self):
        units, skipped = extract_units_stdlib(UNRECOGNIZED_MACRO_C, "test_macro.c", return_skipped=True)
        self.assertEqual(len(units), 0)
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["symbol"], "macro_fn")
        self.assertEqual(skipped[0]["reason"], "unrecognized_macro")

        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(UNRECOGNIZED_MACRO_C)
            path = f.name
        try:
            rec = mine_file(path, "torvalds/linux", COMMIT)
            self.assertEqual(rec["status"], "PARSER_SKIPPED")
            self.assertEqual(rec["parser_skipped_count"], 1)
        finally:
            os.unlink(path)

    def test_cli_on_skipped_file_reports_incomplete_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            srcpath = os.path.join(td, "skipped.c")
            with open(srcpath, "w", encoding="utf-8") as f:
                f.write(NESTED_PARENS_C)
            outpath = os.path.join(td, "out.json")
            r = subprocess.run(
                [sys.executable, "scripts/mine_ast.py", "--input", srcpath,
                 "--repo", "torvalds/linux", "--commit", COMMIT,
                 "--output", outpath],
                capture_output=True, text=True,
            )
            self.assertNotEqual(r.returncode, 0)
            with open(outpath, encoding="utf-8") as f:
                payload = json.load(f)
            self.assertEqual(payload["coverage"], "INCOMPLETE")
            self.assertEqual(payload["status"], "PARSER_SKIPPED")
            self.assertEqual(payload["parser_skipped_count"], 1)
            self.assertTrue(payload["errors"])

    def test_cli_on_clean_file_reports_complete_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            srcpath = os.path.join(td, "clean.c")
            with open(srcpath, "w", encoding="utf-8") as f:
                f.write(BASIC_C)
            outpath = os.path.join(td, "out.json")
            r = subprocess.run(
                [sys.executable, "scripts/mine_ast.py", "--input", srcpath,
                 "--repo", "torvalds/linux", "--commit", COMMIT,
                 "--output", outpath],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0)
            with open(outpath, encoding="utf-8") as f:
                payload = json.load(f)
            self.assertEqual(payload["coverage"], "COMPLETE_REQUESTED_INPUTS")
            self.assertEqual(payload["status"], "COMPLETE")
            self.assertEqual(payload["parser_skipped_count"], 0)
            self.assertEqual(payload["count"], 1)


class TestCVE202426581Fixture(unittest.TestCase):
    """C3: Fixture linux-CVE-2024-26581 extraction and structural diff."""

    def test_extract_nft_rbtree_gc_elem_before_and_after(self):
        frag_before = extract_fragment(
            source=BEFORE_C,
            symbol_name=METADATA["symbol_name"],
            repo=METADATA["repo"],
            commit_sha=METADATA["commit_before"],
            blob_sha=METADATA["blob_before"],
            role="before",
            path=METADATA["file"],
            language=METADATA["language"],
        )
        self.assertEqual(frag_before["symbol_name"], "nft_rbtree_gc_elem")
        self.assertEqual(frag_before["role"], "before")
        self.assertTrue(frag_before["ast_indexed"])
        self.assertFalse(frag_before["truncated"])
        self.assertEqual(frag_before["commit_sha"], METADATA["commit_before"])
        self.assertEqual(frag_before["blob_sha"], METADATA["blob_before"])
        self.assertIn("u8 genmask", frag_before["function_body"])

        frag_after = extract_fragment(
            source=AFTER_C,
            symbol_name=METADATA["symbol_name"],
            repo=METADATA["repo"],
            commit_sha=METADATA["commit_after"],
            blob_sha=METADATA["blob_after"],
            role="after",
            path=METADATA["file"],
            language=METADATA["language"],
        )
        self.assertEqual(frag_after["symbol_name"], "nft_rbtree_gc_elem")
        self.assertEqual(frag_after["role"], "after")
        self.assertTrue(frag_after["ast_indexed"])
        self.assertFalse(frag_after["truncated"])
        self.assertEqual(frag_after["commit_sha"], METADATA["commit_after"])
        self.assertEqual(frag_after["blob_sha"], METADATA["blob_after"])
        self.assertNotIn("u8 genmask", frag_after["function_body"])
        self.assertIn("NFT_GENMASK_ANY", frag_after["function_body"])

        validate_fragment(frag_before)
        validate_fragment(frag_after)

    def test_structural_diff(self):
        frag_before = extract_fragment(
            source=BEFORE_C,
            symbol_name=METADATA["symbol_name"],
            repo=METADATA["repo"],
            commit_sha=METADATA["commit_before"],
            blob_sha=METADATA["blob_before"],
            role="before",
            path=METADATA["file"],
        )
        frag_after = extract_fragment(
            source=AFTER_C,
            symbol_name=METADATA["symbol_name"],
            repo=METADATA["repo"],
            commit_sha=METADATA["commit_after"],
            blob_sha=METADATA["blob_after"],
            role="after",
            path=METADATA["file"],
        )
        diff = compute_structural_diff(frag_before, frag_after)
        self.assertTrue(len(diff) > 0)
        # Signature change: parameter removal
        self.assertIn("-		   struct nft_rbtree_elem *rbe, u8 genmask", diff)
        self.assertIn("+		   struct nft_rbtree_elem *rbe", diff)
        # Body change: NFT_GENMASK_ANY substitution
        self.assertIn("-		    nft_set_elem_active(&rbe_prev->ext, genmask)", diff)
        self.assertIn("+		    nft_set_elem_active(&rbe_prev->ext, NFT_GENMASK_ANY)", diff)

    def test_mainline_memory_record_has_ast_indexed_true(self):
        record_path = Path("docs/memory/records/linux-CVE-2024-26581-mainline.json")
        self.assertTrue(record_path.exists())
        with open(record_path, "r", encoding="utf-8") as f:
            record = json.load(f)
        code_nodes = [n for n in record["nodes"] if n["type"] == "code_version"]
        self.assertEqual(len(code_nodes), 2)
        for node in code_nodes:
            self.assertEqual(node["attributes"]["symbol"], "nft_rbtree_gc_elem")
            self.assertTrue(
                node["attributes"]["ast_indexed"],
                f"Node {node['id']} must have ast_indexed=True",
            )


if __name__ == "__main__":
    unittest.main()
