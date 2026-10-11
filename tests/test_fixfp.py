"""Offline tests for ksm/fixfp.py (no network, injected fakes)."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from ksm.fixfp import (
    REPO_MAP,
    build_all,
    build_one,
    changed_ranges,
    commit_try_order,
    compute_delta,
    dumps,
    format_ranges,
    language_for_path,
    load_candidates,
    load_index,
    parse_hunks,
    save_index,
)

MULTI_HUNK = (
    "@@ -10,7 +10,7 @@ func_a\n"
    " ctx\n"
    "-old_a\n"
    "+new_a\n"
    " ctx\n"
    "@@ -50,6 +50,7 @@ func_b\n"
    " ctx\n"
    "+added_one\n"
    "+added_two\n"
    " ctx\n"
)

ADDED_ONLY = (
    "@@ -0,0 +1,3 @@\n"
    "+one\n"
    "+two\n"
    "+three\n"
)

DELETED_ONLY = (
    "@@ -1,3 +0,0 @@\n"
    "-one\n"
    "-two\n"
    "-three\n"
)

PARENT = "b" * 40
FIX = "a" * 40


def sfp_fn(name, kgrams, calls=(), guards=(), start=1, end=20, mh=1):
    return {"name": name, "start_line": start, "end_line": end,
            "node_count": 10, "kgrams": dict(kgrams), "minhash": [mh] * 64,
            "calls": list(calls), "guards": list(guards), "vars": []}


def sfp_doc(functions, fname="lib/x.c"):
    return {"schema": "ksm-sfp/1", "file": fname, "language": "c",
            "coverage": "OK", "functions": list(functions)}


def fake_commit(files, parent=PARENT):
    return {"parents": [{"sha": parent}], "files": files}


def fake_file(filename, patch, status="modified"):
    return {"filename": filename, "status": status, "patch": patch}


class TestHunkParsing(unittest.TestCase):
    def test_multi_hunk_changed_lines(self):
        hunks = parse_hunks(MULTI_HUNK)
        self.assertEqual(len(hunks), 2)
        self.assertEqual(hunks[0]["old_changed"], [11])
        self.assertEqual(hunks[0]["new_changed"], [11])
        self.assertEqual(hunks[1]["old_changed"], [])
        self.assertEqual(hunks[1]["new_changed"], [51, 52])
        old_ranges, new_ranges = changed_ranges(hunks)
        self.assertEqual(old_ranges, [(11, 11)])
        self.assertEqual(new_ranges, [(11, 11), (51, 52)])
        self.assertEqual(format_ranges(new_ranges), "11-11,51-52")

    def test_added_only_file(self):
        hunks = parse_hunks(ADDED_ONLY)
        self.assertEqual(len(hunks), 1)
        self.assertEqual(hunks[0]["old_changed"], [])
        self.assertEqual(hunks[0]["new_changed"], [1, 2, 3])
        old_ranges, new_ranges = changed_ranges(hunks)
        self.assertEqual(old_ranges, [])
        self.assertEqual(new_ranges, [(1, 3)])
        self.assertEqual(format_ranges(old_ranges), "")

    def test_deleted_only_file(self):
        hunks = parse_hunks(DELETED_ONLY)
        self.assertEqual(len(hunks), 1)
        self.assertEqual(hunks[0]["old_changed"], [1, 2, 3])
        self.assertEqual(hunks[0]["new_changed"], [])
        old_ranges, new_ranges = changed_ranges(hunks)
        self.assertEqual(old_ranges, [(1, 3)])
        self.assertEqual(new_ranges, [])


class TestDelta(unittest.TestCase):
    def test_kgram_count_difference(self):
        before = sfp_fn("f", {"aa": 3, "bb": 1})
        after = sfp_fn("f", {"aa": 1, "cc": 2})
        d = compute_delta(before, after)
        self.assertEqual(d["added_kgrams"], {"cc": 2})
        self.assertEqual(d["removed_kgrams"], {"aa": 2, "bb": 1})

    def test_calls_and_guards(self):
        before = sfp_fn("f", {"aa": 1},
                        calls=[{"callee": "memcpy", "line": 5, "args": ["d", "s", "n"]}],
                        guards=[{"kind": "if", "line": 4, "vars": ["x"]}])
        after = sfp_fn("f", {"aa": 1},
                       calls=[{"callee": "memcpy", "line": 6, "args": ["d", "s", "n"]},
                              {"callee": "strlen", "line": 7, "args": ["s"]}],
                       guards=[{"kind": "if", "line": 4, "vars": ["x"]},
                               {"kind": "if", "line": 5, "vars": ["n"]},
                               {"kind": "if", "line": 8, "vars": ["n"]}])
        d = compute_delta(before, after)
        self.assertEqual(d["added_calls"], ["strlen"])
        self.assertEqual(d["removed_calls"], [])
        # (kind, vars) already in before is not re-reported; dupes collapse
        self.assertEqual(d["added_guards"], [{"kind": "if", "vars": ["n"]}])

    def test_none_sides(self):
        d = compute_delta(None, sfp_fn("f", {"aa": 2}))
        self.assertEqual(d["added_kgrams"], {"aa": 2})
        self.assertEqual(d["removed_kgrams"], {})
        d = compute_delta(sfp_fn("f", {"aa": 2}), None)
        self.assertEqual(d["added_kgrams"], {})
        self.assertEqual(d["removed_kgrams"], {"aa": 2})


class TestRepoMap(unittest.TestCase):
    def test_contract_map(self):
        self.assertEqual(REPO_MAP["linux"], "torvalds/linux")
        self.assertEqual(REPO_MAP["linux-cna"], "torvalds/linux")
        self.assertEqual(REPO_MAP["curl"], "curl/curl")
        self.assertEqual(REPO_MAP["openssl"], "openssl/openssl")
        self.assertEqual(REPO_MAP["git"], "git/git")
        self.assertEqual(REPO_MAP["sqlite"], "sqlite/sqlite")
        self.assertEqual(REPO_MAP["systemd"], "systemd/systemd")
        self.assertEqual(REPO_MAP["postgres"], "postgres/postgres")

    def test_stable_fallback_order(self):
        self.assertEqual(commit_try_order("torvalds/linux"),
                         ["torvalds/linux", "gregkh/linux"])
        self.assertEqual(commit_try_order("curl/curl"), ["curl/curl"])

    def test_language_map(self):
        self.assertEqual(language_for_path("a/b.c"), "c")
        self.assertEqual(language_for_path("x.hpp"), "cpp")
        self.assertEqual(language_for_path("m.rs"), "rust")
        self.assertEqual(language_for_path("s.py"), "python")
        self.assertIsNone(language_for_path("notes.md"))
        self.assertIsNone(language_for_path("run.sh"))


def write_catalog(catalog_dir, dirname, rows):
    d = Path(catalog_dir) / dirname
    d.mkdir(parents=True, exist_ok=True)
    with (d / "catalog.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def catalog_row(cve, sha, cwe="CWE-787"):
    return {"advisory_id": cve, "published": "2023-01-01", "cwe": cwe,
            "patch_urls": [], "fix_shas": [sha], "subsystem": None}


class TestBuildOne(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"
        self.before = sfp_fn("do_SOCKS5", {"aa": 2, "bb": 1},
                             calls=[{"callee": "memcpy", "line": 10,
                                     "args": ["dst", "src", "n"]}], mh=3)
        self.after = sfp_fn("do_SOCKS5", {"aa": 1, "cc": 2},
                            calls=[{"callee": "memcpy", "line": 12,
                                    "args": ["dst", "src", "n"]}],
                            guards=[{"kind": "if", "line": 11, "vars": ["n"]}], mh=3)
        self.seen = {}

    def tearDown(self):
        self.tmp.cleanup()

    def _fakes(self, commit):
        def fetch_commit(repo, sha):
            self.seen["repo"] = repo
            self.seen["sha"] = sha
            return dict(commit)
        def fetch_blob(repo, sha, path):
            return b"before-bytes" if sha == PARENT else b"after-bytes"
        def run_fp(path, lang, ranges):
            self.seen.setdefault("ranges", []).append(ranges)
            if os.path.basename(path).startswith("before_"):
                return sfp_doc([self.before])
            return sfp_doc([self.after])
        return fetch_commit, fetch_blob, run_fp

    def test_build_writes_sorted_doc(self):
        cand = {"project": "curl", "advisory_id": "CVE-2030-9001",
                "fix_sha": FIX, "cwe": "CWE-787"}
        commit = fake_commit([fake_file("lib/socks.c",
                                        "@@ -10,3 +10,4 @@ f\n ctx\n-old\n+new\n+more\n ctx\n")])
        fc, fb, rf = self._fakes(commit)
        doc, repo = build_one(cand, self.out, fetch_commit=fc, fetch_blob=fb,
                              run_fingerprint=rf, tool="code-graph@t")
        self.assertEqual(repo, "curl/curl")
        self.assertEqual(doc["schema"], "ksm-fixfp/1")
        self.assertEqual(doc["parent_sha"], PARENT)
        fn = doc["files"][0]["functions"][0]
        self.assertEqual(fn["name"], "do_SOCKS5")
        self.assertEqual(fn["delta"]["added_guards"], [{"kind": "if", "vars": ["n"]}])
        fp = self.out / "curl" / "CVE-2030-9001.json"
        text = fp.read_text(encoding="utf-8")
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, dumps(json.loads(text)))  # sorted keys, indent 1

    def test_repo_map_used(self):
        cand = {"project": "linux-cna", "advisory_id": "CVE-2030-9002",
                "fix_sha": FIX, "cwe": None}
        fc, fb, rf = self._fakes(fake_commit([]))
        build_one(cand, self.out, fetch_commit=fc, fetch_blob=fb, run_fingerprint=rf)
        self.assertEqual(self.seen["repo"], "torvalds/linux")

    def test_unsupported_files_skipped(self):
        cand = {"project": "curl", "advisory_id": "CVE-2030-9003",
                "fix_sha": FIX, "cwe": None}
        commit = fake_commit([fake_file("notes.md", "@@ -1 +1 @@\n-a\n+b\n")])
        fc, fb, rf = self._fakes(commit)
        doc, _ = build_one(cand, self.out, fetch_commit=fc, fetch_blob=fb,
                           run_fingerprint=rf)
        self.assertEqual(doc["files"], [])


class TestIndexResume(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.cat = base / "cat"
        self.out = base / "out"
        write_catalog(self.cat, "curl-upstream",
                      [catalog_row("CVE-2030-0001", "a" * 40),
                       catalog_row("CVE-2030-0002", "b" * 40)])
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def _ok_fakes(self, fail_shas=()):
        def fetch_commit(repo, sha):
            self.calls.append(sha)
            if sha in fail_shas:
                from ksm.fixfp import FetchError
                raise FetchError("commit API 404 for x@" + sha, status=404)
            return fake_commit([])
        def fetch_blob(repo, sha, path):
            return b"x"
        def run_fp(path, lang, ranges):
            return sfp_doc([])
        return fetch_commit, fetch_blob, run_fp

    def test_done_skipped_second_run(self):
        fc, fb, rf = self._ok_fakes()
        s1 = build_all(self.cat, self.out, fetch_commit=fc, fetch_blob=fb,
                       run_fingerprint=rf)
        self.assertEqual((s1["processed"], s1["done"], s1["failed"]), (2, 2, 0))
        idx = load_index(self.out)
        self.assertEqual(len(idx["done"]), 2)
        self.assertEqual(idx["done"], sorted(idx["done"],
                                             key=lambda e: (e["project"], e["advisory_id"])))
        # index written atomically: no temp files left behind
        self.assertEqual(list(self.out.glob("*.tmp")), [])
        self.calls.clear()
        s2 = build_all(self.cat, self.out, fetch_commit=fc, fetch_blob=fb,
                       run_fingerprint=rf)
        self.assertEqual((s2["processed"], s2["done"]), (0, 0))
        self.assertEqual(self.calls, [])

    def test_failed_retried_only_with_retry_failed(self):
        fc, fb, rf = self._ok_fakes(fail_shas=("b" * 40,))
        s1 = build_all(self.cat, self.out, fetch_commit=fc, fetch_blob=fb,
                       run_fingerprint=rf)
        self.assertEqual((s1["done"], s1["failed"]), (1, 1))
        idx = load_index(self.out)
        self.assertEqual(len(idx["failed"]), 1)
        self.assertIn("404", idx["failed"][0]["reason"])
        # without --retry-failed the failure is not retried
        self.calls.clear()
        s2 = build_all(self.cat, self.out, fetch_commit=fc, fetch_blob=fb,
                       run_fingerprint=rf)
        self.assertEqual(s2["processed"], 0)
        # with retry it is attempted again (and fails again here)
        s3 = build_all(self.cat, self.out, fetch_commit=fc, fetch_blob=fb,
                       run_fingerprint=rf, retry_failed=True)
        self.assertEqual(s3["processed"], 1)
        self.assertEqual(s3["failed"], 1)

    def test_api_error_records_reason_and_writes_nothing(self):
        fc, fb, rf = self._ok_fakes(fail_shas=("a" * 40, "b" * 40))
        s = build_all(self.cat, self.out, fetch_commit=fc, fetch_blob=fb,
                      run_fingerprint=rf)
        self.assertEqual(s["failed"], 2)
        idx = load_index(self.out)
        for e in idx["failed"]:
            self.assertTrue(e["reason"])
            self.assertNotIn("GITHUB_TOKEN", e["reason"])
            self.assertNotIn("Bearer", e["reason"])
        self.assertEqual(list(self.out.rglob("CVE-*.json")), [])

    def test_max_commits_and_only_project(self):
        fc, fb, rf = self._ok_fakes()
        s = build_all(self.cat, self.out, max_commits=1, fetch_commit=fc,
                      fetch_blob=fb, run_fingerprint=rf)
        self.assertEqual(s["processed"], 1)
        write_catalog(self.cat, "git-upstream", [catalog_row("CVE-2030-0009", "c" * 40)])
        self.calls.clear()
        s = build_all(self.cat, self.out, only_project="git", fetch_commit=fc,
                      fetch_blob=fb, run_fingerprint=rf)
        self.assertEqual(s["processed"], 1)
        self.assertEqual(self.calls, ["c" * 40])

    def test_rate_limit_stops_batch_without_marking_failed(self):
        from ksm.fixfp import FetchError

        def fetch_commit(repo, sha):
            self.calls.append(sha)
            raise FetchError("commit API 403 for x@" + sha, status=403)
        _, fb, rf = self._ok_fakes()
        s = build_all(self.cat, self.out, fetch_commit=fetch_commit, fetch_blob=fb,
                      run_fingerprint=rf)
        self.assertEqual((s["processed"], s["failed"]), (0, 0))
        self.assertIn("403", s["stopped"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(load_index(self.out)["failed"], [])

    def test_file_without_patch_is_not_fingerprinted_whole(self):
        ranges_seen = []

        def fetch_commit(repo, sha):
            return fake_commit([{"filename": "lib/big.c", "status": "modified"}])

        def run_fp(path, lang, ranges):
            ranges_seen.append(ranges)
            return sfp_doc([])
        _, fb, _ = self._ok_fakes()
        build_all(self.cat, self.out, max_commits=1, fetch_commit=fetch_commit,
                  fetch_blob=fb, run_fingerprint=run_fp)
        self.assertEqual(ranges_seen, [])

    def test_save_index_sorted(self):
        save_index(self.out, {"done": [
            {"project": "curl", "advisory_id": "CVE-2030-0002", "fix_sha": "b" * 40},
            {"project": "curl", "advisory_id": "CVE-2030-0001", "fix_sha": "a" * 40}],
            "failed": []})
        idx = load_index(self.out)
        self.assertEqual([e["advisory_id"] for e in idx["done"]],
                         ["CVE-2030-0001", "CVE-2030-0002"])


if __name__ == "__main__":
    unittest.main()
