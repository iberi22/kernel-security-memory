"""Offline tests for scripts/mine_pack_fragments.py (no network, synthetic fixtures).

Synthetic inputs live under tests/fixtures/pack_fragments/. Paths are resolved
from this file, not the process CWD, so the suite passes however unittest runs.
"""
import contextlib
import difflib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import scripts.mine_pack_fragments as mpf
from scripts.mine_pack_fragments import (
    analyze_file,
    dumps,
    extract_symbol,
    git_blob_sha,
    language_for,
    parse_patch,
)

FIX_DIR = Path(__file__).resolve().parent / "fixtures" / "pack_fragments"
REPO_FRAG_DIR = Path(__file__).resolve().parents[1] / "docs" / "studies" / "fragments"

PARENT_SHA = "b" * 40
FIX_SHA = "a" * 40

KERNEL_PATCH = (
    "@@ -234,7 +234,7 @@ static void nft_rbtree_gc_elem_remove(struct net *net, struct nft_set *set,\n"
    " \n"
    " static const struct nft_rbtree_elem *\n"
    "-\t\t   struct nft_rbtree_elem *rbe, u8 genmask)\n"
    "+\t\t   struct nft_rbtree_elem *rbe)\n"
    " {\n"
    "@@ -365,7 +365,7 @@ static int __nft_rbtree_insert(const struct net *net, struct nft_set *set,\n"
    "-\t\t\tremoved_end = nft_rbtree_gc_elem(set, priv, rbe, genmask);\n"
    "+\t\t\tremoved_end = nft_rbtree_gc_elem(set, priv, rbe);\n"
)


class TestPureHelpers(unittest.TestCase):
    def test_parse_patch_tracks_line_numbers_and_counts(self):
        hunks = parse_patch(KERNEL_PATCH)
        self.assertEqual(len(hunks), 2)
        self.assertEqual(hunks[0]["symbol"], "nft_rbtree_gc_elem_remove")
        self.assertEqual((hunks[0]["old_start"], hunks[0]["old_len"]), (234, 7))
        # exactly one add and one del, at the right (old/new) line numbers
        del_items = [it for it in hunks[0]["items"] if it[0] == "del"]
        add_items = [it for it in hunks[0]["items"] if it[0] == "add"]
        self.assertEqual(len(del_items), 1)
        self.assertEqual(len(add_items), 1)
        self.assertEqual(del_items[0][1], 236)  # old line
        self.assertEqual(add_items[0][2], 236)  # new line
        self.assertEqual(hunks[0]["added"], 1)
        self.assertEqual(hunks[0]["removed"], 1)

    def test_extract_symbol(self):
        self.assertEqual(extract_symbol("static int foo(struct bar *b, int flags"), "foo")
        self.assertEqual(extract_symbol("int sd_bus_process(sd_bus *bus, int **r);"), "sd_bus_process")
        self.assertIsNone(extract_symbol("global:"))          # version script label
        self.assertIsNone(extract_symbol("test_expect_success 'x' '"))  # shell directive
        self.assertIsNone(extract_symbol(""))
        self.assertIsNone(extract_symbol("if ("))             # keyword

    def test_language_for(self):
        self.assertEqual(language_for("net/x.c"), "c")
        self.assertEqual(language_for("src/sd-bus.h"), "c-header")
        self.assertEqual(language_for("t/run.sh"), "shell")
        self.assertEqual(language_for("tool.pl"), "perl")
        self.assertEqual(language_for("test/t.test"), "sqlite-test")
        self.assertEqual(language_for("pkg/x.spec"), "rpm-spec")
        self.assertEqual(language_for("sqlite.h.in"), "c-template")
        self.assertEqual(language_for("lib/x.sym"), "version-script")
        self.assertEqual(language_for("manifest"), "sqlite-manifest")
        self.assertEqual(language_for("README"), "text")
        self.assertEqual(language_for("weird.zzz"), "other")

    def test_git_blob_sha_matches_git_semantics(self):
        import hashlib
        data = b"hello\n"
        expected = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        self.assertEqual(git_blob_sha(data), expected)
        self.assertIsNone(git_blob_sha(None))


class TestAttributeC(unittest.TestCase):
    def setUp(self):
        self.before = (FIX_DIR / "before_sample.c").read_text(encoding="utf-8")
        self.after = (FIX_DIR / "after_sample.c").read_text(encoding="utf-8")
        self.patch = "".join(difflib.unified_diff(
            self.before.splitlines(True), self.after.splitlines(True),
            fromfile="a/src/foo.c", tofile="b/src/foo.c",
        ))
        self.feat = analyze_file(
            "src/foo.c", "modified", 2, 0, self.patch, "c",
            self.before, self.after, self.before.encode(), self.after.encode(),
        )

    def test_only_changed_function_is_attributed(self):
        names = [f["name"] for f in self.feat["functions"]]
        # after adds two lines only inside process(); helper/unrelated untouched
        self.assertEqual(names, ["process"])
        fn = self.feat["functions"][0]
        self.assertEqual(fn["method"], "ast")
        self.assertEqual(fn["coverage"], "OK")
        self.assertEqual(fn["lines_added"], 2)
        self.assertEqual(fn["lines_removed"], 0)
        self.assertEqual(fn["before_range"][0], fn["before_range"][1] - 7)  # 8..15
        self.assertGreaterEqual(fn["after_range"][1] - fn["after_range"][0], 8)
        for key in ("before_body_sha256", "after_body_sha256"):
            self.assertRegex(fn[key], r"^[0-9a-f]{64}$")
        self.assertEqual(self.feat["unattributed"]["added"], 0)
        self.assertEqual(self.feat["unattributed"]["removed"], 0)
        self.assertEqual(self.feat["coverage"], "OK")

    def test_no_upstream_code_leaks_into_output(self):
        text = dumps(self.feat)
        self.assertNotIn("@@", text)
        self.assertNotIn("return r * flags", text)     # an unchanged source line
        self.assertNotIn("r = helper(it->base);", text)  # a source line inside a body
        src_lines = self.before.split("\n")
        grams = set((src_lines[i], src_lines[i + 1], src_lines[i + 2])
                    for i in range(len(src_lines) - 2))
        out_lines = text.split("\n")
        hits = sum(1 for i in range(len(out_lines) - 2)
                   if (out_lines[i], out_lines[i + 1], out_lines[i + 2]) in grams)
        self.assertEqual(hits, 0)

    def test_parser_skipped_nested_parens_reported_honestly(self):
        before = "int apply(void (*cb)(int, int), int v)\n{\n\tint old = cb(v, 2);\n\treturn old;\n}\n"
        after = "int apply(void (*cb)(int, int), int v)\n{\n\tint old = cb(v, 3);\n\treturn old;\n}\n"
        patch = "".join(difflib.unified_diff(
            before.splitlines(True), after.splitlines(True), fromfile="a", tofile="b"))
        feat = analyze_file("x.c", "modified", 1, 1, patch, "c",
                            before, after, before.encode(), after.encode())
        fn = next(f for f in feat["functions"] if f["name"] == "apply")
        self.assertEqual(fn["coverage"], "PARSER_SKIPPED")
        self.assertEqual(fn["method"], "hunk_fallback")
        self.assertIn("nested_parentheses", fn["note"])
        self.assertIsNone(fn["before_body_sha256"])  # no body hash when unparsed
        self.assertEqual(feat["coverage"], "PARSER_SKIPPED")


class TestAttributeHunk(unittest.TestCase):
    def test_shell_change_is_hunk_level_and_honest(self):
        patch = (
            "@@ -17,4 +17,12 @@ test_expect_success 'clone rejects unprotected dash' '\n"
            " \ttest_i18ngrep ignoring err\n"
            " '\n"
            " \n"
            "+test_expect_success 'fsck rejects unprotected dash' '\n"
            "+\tgit fsck\n"
        )
        feat = analyze_file("t/run.sh", "modified", 6, 0, patch, "shell", None, None, None, None)
        self.assertEqual(feat["language"], "shell")
        self.assertFalse(feat["functions"])  # shell directive has no name-binding scope
        self.assertGreaterEqual(feat["unattributed"]["added"], 2)
        self.assertIn("no function/scope name", feat["unattributed"]["reason"])
        # body hashes must never be invented for non-AST languages
        text = dumps(feat)
        self.assertNotIn("@@", text)
        self.assertEqual(feat["before_blob_sha"], None)  # content not fetched for non-C


class TestOfflineRoundtrip(unittest.TestCase):
    def setUp(self):
        self._saved = (mpf.CACHE_DIR, mpf.OUT_DIR, mpf.RECORDS_DIR)
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cache = base / "cache"
        self.out = base / "out"
        self.records = base / "records"
        for d in (self.cache, self.out, self.records):
            d.mkdir(parents=True, exist_ok=True)
        mpf.CACHE_DIR, mpf.OUT_DIR, mpf.RECORDS_DIR = self.cache, self.out, self.records

        before = (FIX_DIR / "before_sample.c").read_text(encoding="utf-8")
        after = (FIX_DIR / "after_sample.c").read_text(encoding="utf-8")
        patch = "".join(difflib.unified_diff(
            before.splitlines(True), after.splitlines(True),
            fromfile="a", tofile="b"))
        adds = sum(1 for l in patch.split("\n") if l.startswith("+") and not l.startswith("+++"))
        dels = sum(1 for l in patch.split("\n") if l.startswith("-") and not l.startswith("---"))
        rec_id = "synthetic-pack-fragments-seed"
        rdir = self.cache / rec_id
        rdir.mkdir(parents=True, exist_ok=True)
        commit = {
            "parents": [{"sha": PARENT_SHA}],
            "files": [{
                "filename": "src/foo.c", "status": "modified",
                "additions": adds, "deletions": dels,
                "sha": git_blob_sha(after.encode()), "patch": patch,
            }],
        }
        (rdir / "commit.json").write_text(dumps(commit), encoding="utf-8")
        (rdir / "file-0.before").write_bytes(before.encode())
        (rdir / "file-0.after").write_bytes(after.encode())
        (self.records / "record_synthetic.json").write_text(
            (FIX_DIR / "record_synthetic.json").read_text(encoding="utf-8"), encoding="utf-8")

    def tearDown(self):
        mpf.CACHE_DIR, mpf.OUT_DIR, mpf.RECORDS_DIR = self._saved
        self.tmp.cleanup()

    def _run(self, argv):
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            rc = mpf.main(argv)
        return rc, out_buf.getvalue() + err_buf.getvalue()

    def test_offline_write_check_and_identical_rerun(self):
        out_file = self.out / "synthetic-pack-fragments-seed.json"
        rc, _ = self._run(["--offline"])
        self.assertEqual(rc, 0)
        self.assertTrue(out_file.exists())
        first = out_file.read_text(encoding="utf-8")
        # --check recomputes from cache and verifies on-disk matches
        rc_chk, out_chk = self._run(["--offline", "--check"])
        self.assertEqual(rc_chk, 0)
        self.assertIn("--check OK", out_chk)
        # rerun offline must produce byte-identical file (determinism)
        rc2, _ = self._run(["--offline"])
        self.assertEqual(rc2, 0)
        second = out_file.read_text(encoding="utf-8")
        self.assertEqual(first, second)
        # sanity: content is the expected feature and has no '@@'
        self.assertNotIn("@@", first)

    def test_check_detects_tampering(self):
        self._run(["--offline"])
        out_file = self.out / "synthetic-pack-fragments-seed.json"
        out_file.write_text(first_tamper := (out_file.read_text(encoding="utf-8") + '{"x":1}'),
                            encoding="utf-8")
        rc, out = self._run(["--offline", "--check"])
        self.assertEqual(rc, 1)
        self.assertIn("MISMATCH", out)
        _ = first_tamper

    def test_offline_missing_content_skips_with_reason(self):
        rec_id = "synthetic-pack-fragments-seed"
        (self.cache / rec_id / "file-0.after").unlink()
        rc, out = self._run(["--offline"])
        self.assertIn(rc, (1, 2))
        self.assertIn("records skipped", out)
        self.assertIn("offline: missing cached content", out)
        self.assertEqual(list(self.out.glob("*.json")), [])


class TestCommittedNoHunkHeaders(unittest.TestCase):
    def test_no_at_at_markers_in_committed_features(self):
        committed = sorted(REPO_FRAG_DIR.glob("*.json"))
        self.assertTrue(committed, "expected generated fragments to be present")
        for fp in committed:
            with self.subTest(file=fp.name):
                self.assertNotIn("@@", fp.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
