"""Offline tests for ksm/match.py with hand-written sfp fixtures (no real code)."""
import unittest
from pathlib import Path

from ksm.match import (
    cosine,
    est_jaccard,
    find_missing_guards,
    guard_rules,
    is_candidate,
    load_corpus,
    match_documents,
    render_markdown,
    self_test,
    shares_band,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "fingerprints"


def fn(name, kgrams, calls=(), guards=(), start=1, end=50, mh=None):
    return {"name": name, "start_line": start, "end_line": end,
            "node_count": 100, "kgrams": dict(kgrams),
            "minhash": list(mh) if mh is not None else [5] * 64,
            "calls": list(calls), "guards": list(guards), "vars": []}


def tdoc(fname, functions, lang="c"):
    return {"schema": "ksm-sfp/1", "file": fname, "language": lang,
            "coverage": "OK", "functions": list(functions)}


def pair_doc(adv="CVE-2030-0001", project="curl", before=None, after=None,
             delta=None, path="lib/stuff.c", mh=7):
    before = before if before is not None else fn("copy_stuff", {"aa": 3, "bb": 1}, mh=[mh] * 64)
    after = after if after is not None else fn("copy_stuff", {"cc": 3, "dd": 1}, mh=[mh] * 64)
    delta = delta if delta is not None else {"added_kgrams": {}, "removed_kgrams": {},
                                             "added_calls": [], "removed_calls": [],
                                             "added_guards": []}
    return {"schema": "ksm-fixfp/1", "advisory_id": adv, "project": project,
            "repo": f"{project}/{project}", "fix_sha": "a" * 40,
            "parent_sha": "b" * 40, "cwe": "CWE-787", "tool": "t",
            "coverage": "OK",
            "files": [{"path": path, "language": "c",
                       "functions": [{"name": "copy_stuff", "before": before,
                                      "after": after, "delta": delta}]}]}


class TestCosineAndLsh(unittest.TestCase):
    def test_cosine_identical_and_disjoint(self):
        self.assertAlmostEqual(cosine({"a": 2, "b": 1}, {"a": 2, "b": 1}), 1.0)
        self.assertAlmostEqual(cosine({"a": 1}, {"b": 1}), 0.0)
        self.assertAlmostEqual(cosine({}, {}), 1.0)
        self.assertAlmostEqual(cosine({"a": 1}, {}), 0.0)

    def test_lsh_bands(self):
        self.assertTrue(shares_band([1] * 64, [1] * 64))
        self.assertFalse(shares_band([1] * 64, [2] * 64))
        # one shared band out of 16 is enough
        m2 = [1, 1, 1, 1] + [2] * 60
        self.assertTrue(shares_band([1] * 64, m2))
        self.assertAlmostEqual(est_jaccard([1] * 64, [1] * 64), 1.0)
        self.assertAlmostEqual(est_jaccard([1] * 64, [2] * 64), 0.0)

    def test_lsh_candidate_filter(self):
        # identical kgrams (cosine 1.0) but disjoint minhash -> filtered out
        t = fn("f", {"aa": 2}, mh=[1] * 64)
        b = fn("f", {"aa": 2}, mh=[2] * 64)
        self.assertFalse(is_candidate(t, b))
        corpus = [pair_doc(before=b, after=fn("f", {"zz": 2}, mh=[2] * 64))]
        findings = match_documents([tdoc("vuln.c", [t])], corpus)
        self.assertEqual(findings, [])
        # same minhash -> candidate, structural hit fires
        b2 = fn("f", {"aa": 2}, mh=[1] * 64)
        corpus2 = [pair_doc(before=b2, after=fn("f", {"zz": 2}, mh=[1] * 64))]
        findings2 = match_documents([tdoc("vuln.c", [t])], corpus2)
        self.assertEqual(len(findings2), 1)

    def test_missing_minhash_skips_filter(self):
        t = fn("f", {"aa": 2}, mh=None)
        t.pop("minhash")
        b = fn("f", {"aa": 2}, mh=None)
        b.pop("minhash")
        self.assertTrue(is_candidate(t, b))


class TestStructural(unittest.TestCase):
    def test_structural_hit(self):
        corpus = [pair_doc()]
        target = tdoc("vuln.c", [fn("copy_stuff", {"aa": 3, "bb": 1}, mh=[7] * 64)])
        findings = match_documents(target_docs=[target], corpus=corpus)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["file"], f["function"]), ("vuln.c", "copy_stuff"))
        self.assertEqual((f["start_line"], f["end_line"]), (1, 50))
        self.assertGreaterEqual(f["score"], 0.55)
        self.assertEqual(len(f["matches"]), 1)
        m = f["matches"][0]
        self.assertEqual(m["advisory_id"], "CVE-2030-0001")
        self.assertAlmostEqual(m["s_before"], 1.0)
        self.assertAlmostEqual(m["s_after"], 0.0)
        self.assertTrue(any("CVE-2030-0001" in r for r in f["reasons"]))

    def test_fixed_version_not_flagged(self):
        corpus = [pair_doc()]
        target = tdoc("fixed.c", [fn("copy_stuff", {"cc": 3, "dd": 1}, mh=[7] * 64)])
        self.assertEqual(match_documents([target], corpus), [])

    def test_margin_required(self):
        # s_b high but within margin of s_a -> no structural hit
        before = fn("f", {"aa": 4, "bb": 1}, mh=[7] * 64)
        after = fn("f", {"aa": 4, "cc": 1}, mh=[7] * 64)
        corpus = [pair_doc(before=before, after=after)]
        target = tdoc("t.c", [fn("f", {"aa": 4, "bb": 1, "cc": 1}, mh=[7] * 64)])
        findings = match_documents([target], corpus)
        # s_b and s_a are close; margin 0.05 must suppress the hit
        for g in findings:
            for m in g["matches"]:
                self.assertFalse(m["s_before"] >= m["s_after"] + 0.05)


class TestMissingGuards(unittest.TestCase):
    def _corpus(self):
        before = fn("copy_stuff", {"aa": 2, "bb": 1}, mh=[7] * 64,
                    calls=[{"callee": "memcpy", "line": 10, "args": ["dst", "src", "n"]}])
        after = fn("copy_stuff", {"cc": 2}, mh=[7] * 64,
                   calls=[{"callee": "memcpy", "line": 12, "args": ["dst", "src", "n"]}],
                   guards=[{"kind": "if", "line": 11, "vars": ["n"]}])
        delta = {"added_kgrams": {}, "removed_kgrams": {}, "added_calls": [],
                 "removed_calls": [],
                 "added_guards": [{"kind": "if", "vars": ["n"]}]}
        return [pair_doc(before=before, after=after, delta=delta)]

    def test_missing_guard_reports_line_and_variable(self):
        corpus = self._corpus()
        t = fn("copy_stuff", {"aa": 2, "bb": 1}, mh=[7] * 64,
               calls=[{"callee": "memcpy", "line": 44, "args": ["buf", "p", "cnt"]}],
               start=30, end=60)
        findings = match_documents([tdoc("app.c", [t])], corpus)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertTrue(any(e["line"] == 44 and e["variable"] == "cnt"
                            and e["callee"] == "memcpy" for e in f["lines"]))
        m = f["matches"][0]
        self.assertTrue(any(g["line"] == 44 and g["variable"] == "cnt"
                            for g in m["missing_guards"]))
        self.assertTrue(any("cnt" in r and "memcpy" in r for r in f["reasons"]))

    def test_guarded_call_is_quiet(self):
        corpus = self._corpus()
        t = fn("copy_stuff", {"qq": 1}, mh=[8] * 64,  # unrelated kgrams, no structural hit
               calls=[{"callee": "memcpy", "line": 44, "args": ["buf", "p", "cnt"]}],
               guards=[{"kind": "if", "line": 40, "vars": ["cnt"]}])
        # same minhash family needed for candidacy; force by aligning minhash
        corpus[0]["files"][0]["functions"][0]["before"]["minhash"] = [8] * 64
        corpus[0]["files"][0]["functions"][0]["after"]["minhash"] = [8] * 64
        findings = match_documents([tdoc("app.c", [t])], corpus)
        self.assertEqual(findings, [])

    def test_wrong_argument_position_no_hit(self):
        before = fn("f", {"aa": 1}, mh=[7] * 64,
                    calls=[{"callee": "memcpy", "line": 3, "args": ["dst", "src", "n"]}])
        after = fn("f", {"aa": 1}, mh=[7] * 64,
                   calls=[{"callee": "memcpy", "line": 5, "args": ["dst", "src", "n"]}],
                   guards=[{"kind": "if", "line": 4, "vars": ["n"]}])
        delta = {"added_guards": [{"kind": "if", "vars": ["n"]}]}
        rules = guard_rules(before, after, delta)
        self.assertEqual(rules, {("memcpy", 2)})
        # T passes its size at position 0, not 2: position 2 holds "dst".
        t = fn("f", {"aa": 1}, calls=[{"callee": "memcpy", "line": 9, "args": ["n", "src", "dst"]}])
        hits = find_missing_guards(t, rules)
        self.assertEqual([(h["variable"], h["line"]) for h in hits], [("dst", 9)])

    def test_rule_requires_the_added_guard_before_the_call_in_the_fix(self):
        before = fn("f", {"aa": 1}, calls=[{"callee": "memcpy", "line": 3, "args": ["d", "s", "n"]}])
        # The added guard comes after the call: it does not protect it.
        after = fn("f", {"aa": 1}, calls=[{"callee": "memcpy", "line": 3, "args": ["d", "s", "n"]}],
                   guards=[{"kind": "if", "line": 8, "vars": ["n"]}])
        self.assertEqual(guard_rules(before, after, {"added_guards": [{"kind": "if", "vars": ["n"]}]}),
                         set())

    def test_fixed_version_never_flags_its_own_rule(self):
        corpus = self._corpus()
        after = corpus[0]["files"][0]["functions"][0]["after"]
        findings = match_documents([tdoc("fixed.c", [after])], corpus)
        self.assertEqual(findings, [])


class TestReviewRegressions(unittest.TestCase):
    def _rule_corpus(self, node_count=100):
        before = fn("f", {"aa": 1}, mh=[7] * 64,
                    calls=[{"callee": "memcpy", "line": 3, "args": ["d", "s", "n"]}])
        after = fn("f", {"bb": 1}, mh=[7] * 64,
                   calls=[{"callee": "memcpy", "line": 5, "args": ["d", "s", "n"]}],
                   guards=[{"kind": "if", "line": 4, "vars": ["n"]}])
        before["node_count"] = after["node_count"] = node_count
        return [pair_doc(before=before, after=after,
                         delta={"added_guards": [{"kind": "if", "vars": ["n"]}]})]

    def test_tiny_function_is_never_strong_or_structural(self):
        t = fn("f", {"aa": 1}, mh=[7] * 64,
               calls=[{"callee": "memcpy", "line": 9, "args": ["d", "s", "len"]}])
        t["node_count"] = 10
        got = match_documents([tdoc("t.c", [t])], self._rule_corpus(node_count=10))
        self.assertEqual(len(got), 1)  # the missing guard is still reported
        self.assertLess(got[0]["score"], 0.9)
        self.assertFalse(any(r.startswith("looks like") for r in got[0]["reasons"]))

    def test_result_check_on_the_call_line_is_not_a_precondition(self):
        t = fn("f", {"zz": 1}, mh=[7] * 64,
               calls=[{"callee": "memcpy", "line": 9, "args": ["d", "s", "len"]}],
               guards=[{"kind": "if", "line": 9, "vars": ["d", "len", "memcpy", "s"]}])
        got = match_documents([tdoc("t.c", [t])], self._rule_corpus())
        self.assertEqual([(g["line"], g["variable"]) for g in got[0]["lines"]], [(9, "len")])

    def test_non_object_corpus_file_is_ignored(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.json").write_text(json.dumps([1, 2]))
            Path(tmp, "y.json").write_text(json.dumps(pair_doc()))
            self.assertEqual(len(load_corpus(tmp)), 1)


class TestOrderingAndRender(unittest.TestCase):
    def test_deterministic_ordering(self):
        c1 = pair_doc(adv="CVE-2030-0001", before=fn("f", {"aa": 5}, mh=[7] * 64),
                      after=fn("f", {"zz": 5}, mh=[7] * 64))
        c2 = pair_doc(adv="CVE-2030-0002", project="openssl",
                      before=fn("g", {"mm": 3, "nn": 1}, mh=[9] * 64),
                      after=fn("g", {"qq": 4}, mh=[9] * 64))
        corpus = [c2, c1]  # intentionally unsorted input
        t_weak = fn("g", {"mm": 3, "nn": 1, "xx": 2}, mh=[9] * 64, start=5, end=40)
        t_strong = fn("f", {"aa": 5}, mh=[7] * 64, start=1, end=10)
        targets = [tdoc("b.c", [t_weak]), tdoc("a.c", [t_strong])]
        r1 = match_documents(targets, corpus)
        r2 = match_documents(list(reversed(targets)), list(reversed(corpus)))
        self.assertEqual([f["function"] for f in r1], ["f", "g"])
        self.assertEqual(r1, r2)  # input order must not matter
        self.assertGreaterEqual(r1[0]["score"], r1[1]["score"])
        # repeat run is byte-identical
        import json
        self.assertEqual(json.dumps(r1, sort_keys=True),
                         json.dumps(match_documents(targets, corpus), sort_keys=True))

    def test_render_markdown(self):
        corpus = [pair_doc()]
        target = tdoc("vuln.c", [fn("copy_stuff", {"aa": 3, "bb": 1}, mh=[7] * 64)])
        findings = match_documents([target], corpus)
        md = render_markdown(findings)
        self.assertIn("CVE-2030-0001", md)
        self.assertIn("copy_stuff", md)
        self.assertIn("github.com/curl/curl/commit", md)
        self.assertTrue(render_markdown([]).startswith("# KSM scan findings"))


class TestLoadCorpusAndSelfTest(unittest.TestCase):
    def test_load_corpus_ignores_index(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(FIXTURES, Path(tmp) / "fp")
            (Path(tmp) / "fp" / "index.json").write_text(
                '{"done": [], "failed": []}\n', encoding="utf-8")
            (Path(tmp) / "fp" / "notes.txt").write_text("x", encoding="utf-8")
            corpus = load_corpus(Path(tmp) / "fp")
        self.assertEqual(len(corpus), 2)
        self.assertEqual(corpus[0]["advisory_id"], "CVE-2030-0001")
        self.assertEqual(corpus[1]["advisory_id"], "CVE-2030-0002")

    def test_self_test_two_pairs(self):
        a_before = fn("fa", {"a1": 3, "a2": 1}, mh=[11] * 64)
        a_after = fn("fa", {"a3": 3, "a4": 1}, mh=[11] * 64)
        b_before = fn("fb", {"b1": 3, "b2": 1}, mh=[13] * 64)
        b_after = fn("fb", {"b3": 3, "b4": 1}, mh=[13] * 64)
        delta = {"added_kgrams": {}, "removed_kgrams": {}, "added_calls": [],
                 "removed_calls": [], "added_guards": []}
        corpus = [pair_doc(adv="CVE-A", before=a_before, after=a_after, delta=delta),
                  pair_doc(adv="CVE-B", before=b_before, after=b_after, delta=delta)]
        res = self_test(corpus)
        self.assertEqual(res["pairs"], 2)
        self.assertAlmostEqual(res["after_flagged_rate"], 0.0)
        self.assertAlmostEqual(res["before_recall"], 1.0)

    def test_self_test_empty(self):
        self.assertEqual(self_test([]),
                         {"after_flagged_rate": 0.0, "before_recall": 0.0, "pairs": 0})

    def test_self_test_on_committed_fixtures(self):
        corpus = load_corpus(FIXTURES)
        res = self_test(corpus)
        self.assertEqual(res["pairs"], 2)
        self.assertIn("after_flagged_rate", res)
        self.assertIn("before_recall", res)


if __name__ == "__main__":
    unittest.main()
