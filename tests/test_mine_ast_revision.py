"""Revision index acceptance tests: synthetic local Git objects, no source downloads."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.build_pack import validate
from scripts.mine_ast import ASTError, mine_revision_pair

ROOT = Path(__file__).resolve().parents[1]
OBSERVED = "2026-11-02T00:00:00+00:00"
BEFORE = "int kept(void)\n{\n return 1;\n}\nint removed(void) { return 0; }\n"
AFTER = "// shifted\nint kept(void)\n{\n return 2;\n}\nint added(void) { return 3; }\n"


class RevisionIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "AST fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.write("src/unit.c", BEFORE)
        self.write("inc/stable.h", "int same(void) { return 7; }\n")
        self.write("deleted.c", "int deleted(void) { return 0; }\n")
        self.before = self.commit()
        self.write("src/unit.c", AFTER)
        self.write("inc/stable.h", "\n\nint same(void) { return 7; }\n")
        (self.repo / "deleted.c").unlink()
        self.write("added.c", "int created(void) { return 1; }\n")
        self.after = self.commit()
        # An unusable remote must never be needed, even when configured.
        self.git("remote", "add", "origin", "https://example.invalid/never-fetch.git")

    def git(self, *args):
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        result = subprocess.run(["git", "-C", str(self.repo), *args],
                                env=env, capture_output=True, check=True)
        return result.stdout.decode().strip()

    def write(self, path, text):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "Synthetic AST revision")
        return self.git("rev-parse", "HEAD")

    def index(self, **kwargs):
        return mine_revision_pair(self.repo, "fixture/project",
                                  kwargs.pop("pair", f"{self.before}..{self.after}"),
                                  observed_at=OBSERVED, **kwargs)

    @staticmethod
    def units(payload, symbol=None):
        return [n for n in payload["nodes"] if n["type"] == "code_version"
                and (symbol is None or n["attributes"]["symbol"] == symbol)]

    def test_before_after_identity_and_line_ranges(self):
        payload = self.index()
        units = self.units(payload, "kept")
        self.assertEqual(len(units), 2)
        b, a = [n["attributes"] for n in units]
        self.assertEqual((b["role"], b["revision"], b["start_line"], b["end_line"]),
                         ("before", self.before, 1, 4))
        self.assertEqual((a["role"], a["revision"], a["start_line"], a["end_line"]),
                         ("after", self.after, 2, 5))
        self.assertEqual(b["file"], "src/unit.c")
        self.assertNotEqual(b["body_sha256"], a["body_sha256"])
        self.assertNotEqual(b["git_blob"], a["git_blob"])
        self.assertEqual(payload["coverage"], "COMPLETE_REQUESTED_INPUTS")
        self.assertEqual(payload["count"], 8)
        self.assertNotIn("function_body", json.dumps(payload))

    def test_temporal_edges_have_evidence_and_validation_state(self):
        payload = self.index()
        validate(payload)
        parent_edges = [e for e in payload["edges"] if e["relation"] == "parent_of"]
        self.assertEqual(len(parent_edges), 1)
        self.assertEqual(parent_edges[0]["source"], "commit:" + self.before)
        self.assertEqual(parent_edges[0]["target"], "commit:" + self.after)
        b, a = self.units(payload, "kept")
        link = next(e for e in payload["edges"]
                    if e["source"] == b["id"] and e["target"] == a["id"])
        self.assertEqual(link["relation"], "before")
        self.assertEqual(link["status"], "hypothesis")
        self.assertEqual(len(link["evidence_ids"]), 2)
        self.assertEqual(link["known_at"], OBSERVED)
        self.assertTrue(any(e["relation"] == "after" and e["target"] == a["id"]
                            for e in payload["edges"]))

    def test_additions_deletions_and_unmatched_symbols(self):
        payload = self.index()
        self.assertEqual(len(self.units(payload, "removed")), 1)
        self.assertEqual(len(self.units(payload, "added")), 1)
        absent = [(f["file"], f["role"]) for f in payload["files"] if f["status"] == "ABSENT"]
        self.assertEqual(absent, [("added.c", "before"), ("deleted.c", "after")])
        code_ids = {n["id"] for n in self.units(payload, "removed") + self.units(payload, "added")}
        self.assertFalse(any(e["source"] in code_ids for e in payload["edges"]))

    def test_body_hash_stable_across_revisions_and_line_shifts(self):
        payload = self.index()
        b, a = [n["attributes"] for n in self.units(payload, "same")]
        expected = hashlib.sha256(b"{ return 7; }").hexdigest()
        self.assertEqual(b["body_sha256"], expected)
        self.assertEqual(a["body_sha256"], expected)
        self.assertNotEqual(b["start_line"], a["start_line"])
        self.assertNotEqual(b["content_sha256"], a["content_sha256"])
        self.assertEqual(payload, self.index())

    def test_parser_skip_retains_valid_units_and_diagnostics(self):
        self.write("skipped.c", "int bad(void (*cb)(int)) { return 0; }\n"
                   "int good(void) { return 1; }\n")
        self.after = self.commit()
        payload = self.index()
        self.assertEqual(payload["coverage"], "INCOMPLETE")
        self.assertEqual(payload["extraction_status"], "PARSER_SKIPPED")
        self.assertEqual(payload["parser_skipped_count"], 1)
        self.assertEqual(len(self.units(payload, "good")), 1)
        record = next(f for f in payload["files"] if f["file"] == "skipped.c" and f["role"] == "after")
        self.assertEqual(record["skipped"][0]["reason"], "nested_parentheses")
        self.assertTrue(payload["errors"])
        validate(payload)

    def test_actual_parents_not_arbitrary_comparison_endpoint(self):
        intermediate = self.after
        self.write("other.c", "int other(void) { return 0; }\n")
        self.after = self.commit()
        payload = self.index()
        parents = [e["source"] for e in payload["edges"] if e["relation"] == "parent_of"]
        self.assertEqual(parents, ["commit:" + intermediate])
        self.assertNotIn("commit:" + self.before, parents)

    def test_merge_retains_all_parents(self):
        left = self.after
        self.git("checkout", "-qb", "side", self.before)
        self.write("side.c", "int side(void) { return 0; }\n")
        right = self.commit()
        self.git("checkout", "-q", "--detach", left)
        self.git("merge", "--no-ff", "-qm", "Synthetic merge", right)
        self.after = self.git("rev-parse", "HEAD")
        payload = self.index()
        parents = {e["source"] for e in payload["edges"] if e["relation"] == "parent_of"}
        self.assertEqual(parents, {"commit:" + left, "commit:" + right})
        self.assertEqual(payload["revision_pair"]["before"], self.before)

    def test_ambiguous_conditional_symbols_have_no_lineage_edge(self):
        source = "#ifdef CONFIG_X\nint amb(void) { return 1; }\n#else\nint amb(void) { return 2; }\n#endif\n"
        self.write("conditional.c", source)
        first = self.commit()
        self.write("conditional.c", "\n" + source)
        second = self.commit()
        payload = self.index(pair=first + ".." + second)
        ambiguous = self.units(payload, "amb")
        self.assertEqual(len(ambiguous), 4)
        self.assertTrue(all(n["attributes"]["conditional"] for n in ambiguous))
        self.assertEqual(len({n["id"] for n in ambiguous}), 4)
        self.assertFalse(any(e["source"] in {n["id"] for n in ambiguous} for e in payload["edges"]))

    def test_missing_path_reports_incomplete(self):
        payload = self.index(paths=["missing.c"])
        self.assertEqual(payload["coverage"], "INCOMPLETE")
        self.assertEqual(payload["count"], 0)
        self.assertIn("Missing C/H input", payload["errors"][0])

    def test_non_utf8_blob_reports_incomplete(self):
        (self.repo / "invalid.c").write_bytes(b"\xff\x00")
        self.after = self.commit()
        payload = self.index()
        self.assertEqual(payload["coverage"], "INCOMPLETE")
        self.assertTrue(any("invalid.c" in e for e in payload["errors"]))

    def test_symlinks_are_diagnosed_without_reading_target(self):
        (self.repo / "linked.c").symlink_to("/etc/passwd")
        self.after = self.commit()
        payload = self.index()
        self.assertTrue(any("Unsupported Git entry mode 120000" in e for e in payload["errors"]))
        self.assertEqual(payload["coverage"], "INCOMPLETE")

    def test_missing_blob_is_incomplete_and_never_fetched(self):
        blob = self.git("rev-parse", self.after + ":src/unit.c")
        (self.repo / ".git/objects" / blob[:2] / blob[2:]).unlink()
        payload = self.index(paths=["src/unit.c"])
        self.assertEqual(payload["coverage"], "INCOMPLETE")
        self.assertTrue(any("cat-file failed" in e for e in payload["errors"]))

    def test_no_network_no_checkout_and_no_git_hooks(self):
        self.write("src/unit.c", "working tree should be ignored")
        real_run = subprocess.run
        calls = []

        def local_only(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[0], "git")
            self.assertIn(argv[4], {"rev-parse", "cat-file", "ls-tree"})
            self.assertEqual(kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(kwargs["env"]["GIT_ALLOW_PROTOCOL"], "")
            self.assertEqual(kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
            return real_run(argv, **kwargs)

        with patch("scripts.mine_ast.subprocess.run", side_effect=local_only), \
             patch("socket.socket", side_effect=AssertionError("network forbidden")):
            payload = self.index()
        self.assertEqual(payload["count"], 8)
        self.assertTrue(calls)
        self.assertEqual((self.repo / "src/unit.c").read_text(), "working tree should be ignored")

    def test_bare_repository_and_explicit_path_scope(self):
        bare = self.repo / ".git"
        payload = mine_revision_pair(bare, "fixture/project", f"{self.before}..{self.after}",
                                     paths=["src/unit.c"], observed_at=OBSERVED)
        self.assertEqual(payload["count"], 4)
        self.assertEqual(payload["scope"]["paths"], ["src/unit.c"])
        validate(payload)

    def test_invalid_and_same_revision_pairs_fail(self):
        for pair in ("HEAD", "..HEAD", "HEAD..", "HEAD...HEAD", "HEAD..HEAD", "missing..HEAD"):
            with self.subTest(pair=pair), self.assertRaises(ASTError):
                self.index(pair=pair)

    def test_cli_success_and_skip_exit_codes(self):
        output = self.repo / "index.json"
        argv = [sys.executable, str(ROOT / "scripts/mine_ast.py"), "--git-dir", str(self.repo),
                "--repo", "fixture/project", "--output", str(output)]
        result = subprocess.run(argv + ["--revision-pair", f"{self.before}..{self.after}"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        validate(json.loads(output.read_text()))
        self.write("skip.c", "int unclosed(void) {\n")
        self.after = self.commit()
        result = subprocess.run(argv + ["--revision-pair", f"{self.before}..{self.after}"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(output.read_text())
        self.assertEqual(payload["extraction_status"], "PARSER_SKIPPED")
        self.assertEqual(payload["coverage"], "INCOMPLETE")

    def test_cli_invalid_revision_writes_failure_diagnostics(self):
        output = self.repo / "index.json"
        result = subprocess.run([sys.executable, str(ROOT / "scripts/mine_ast.py"),
                                 "--git-dir", str(self.repo), "--repo", "fixture/project",
                                 "--revision-pair", "missing..HEAD", "--output", str(output)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(output.read_text())
        self.assertEqual(payload["coverage"], "INCOMPLETE")
        self.assertTrue(payload["errors"])


if __name__ == "__main__":
    unittest.main()
