"""Repo-scoped OSV batch acquisition over a real local stdlib HTTP server."""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
import fetch_upstream_advisories as F

SELECTION = F.SELECTION_PATH
FIX = "a" * 40
BOUNDARY = "b" * 40
MERGE = "c" * 40


class TestOsvRepoBatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.requests = []
        self.responses = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                query = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append(query)
                package = query["package"]["name"]
                body = owner.responses.get((package, query.get("page_token")), {})
                blob = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1/query"
        self.parents = self.root / "commit-parents.jsonl"
        self.parents.write_text("")
        self.enterContext(patch.dict(os.environ, {F.COMMIT_PARENTS_ENV: str(self.parents)}))
        self.enterContext(patch.object(F, "OSV_API_URL", self.url))

    def manifest(self, projects):
        path = self.root / "selection.json"
        path.write_text(json.dumps({"projects": projects}))
        return path

    def run_main(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = F.main(list(map(str, args)))
        return code, output.getvalue()

    def seed(self, entries):
        parent_rows = []
        for entry in entries:
            repo = entry["repo"]
            package = F._selection_meta(entry)["package"]
            record = {
                "id": "CVE-2026-12345", "published": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "database_specific": {"cwe_ids": ["CWE-79"]},
                "references": [{"type": "FIX", "url": f"{repo}/commit/{sha}"}
                               for sha in (FIX, MERGE)],
                "affected": [{"ranges": [
                    {"type": "GIT", "repo": repo, "events": [{"fixed": BOUNDARY}]},
                    {"type": "GIT", "repo": "https://github.com/other/repo",
                     "events": [{"fixed": "d" * 40}]}]}],
            }
            self.responses[(package, None)] = {"vulns": [record]}
            for sha, parents in ((FIX, 1), (MERGE, 2)):
                parent_rows.append({"repo": repo, "sha": sha, "parents": parents,
                                    "fetched_via": "local HTTP fixture"})
        self.parents.write_text("".join(json.dumps(row) + "\n" for row in parent_rows))

    def test_all_17_supported_projects_schema_and_offline_reproduction(self):
        entries = json.loads(SELECTION.read_text())["projects"]
        supported = [entry for entry in entries if entry["osv_git_supported"]]
        self.assertEqual(len(supported), 17)
        self.seed(supported)
        out = self.root / "catalogs"
        previous_openssl = dict(F.PROJECT_META["openssl"])
        args = ("--projects-file", SELECTION, "--out-dir", out)
        code, output = self.run_main(*args)
        self.assertEqual(code, 0, output)
        self.assertIn("17 completed, 6 NO_OSV_GIT_FEED, 0 failed", output)
        self.assertEqual(F.PROJECT_META["openssl"], previous_openssl)
        self.assertEqual(len(self.requests), 17)
        for entry in entries:
            directory = out / (entry["name"] + "-upstream")
            if not entry["osv_git_supported"]:
                self.assertFalse(directory.exists())
                continue
            query = next(r for r in self.requests if r["package"]["name"] == F._selection_meta(entry)["package"])
            self.assertEqual(query["package"]["ecosystem"], "GIT")
            row = json.loads((directory / "catalog.jsonl").read_text())
            self.assertEqual(set(row), {"advisory_id", "published", "cwe", "cwe_state",
                                       "patch_urls", "fix_shas", "fixed_in_shas", "subsystem", "fix_sha_source"})
            self.assertEqual(row["fix_shas"], [FIX])
            self.assertEqual(row["fixed_in_shas"], [BOUNDARY, MERGE])
            index = json.loads((directory / "index.json").read_text())
            self.assertEqual(index["schema_version"], "cve-history-v1")
            self.assertEqual(index["repo"], entry["repo"])
            self.assertEqual(index["entry_count"], 1)
            self.assertEqual(index["merge_fix_refs_demoted"], 1)
            self.assertEqual(index["source_sha256"], hashlib.sha256((directory / "source.json").read_bytes()).hexdigest())
        self.requests.clear()
        code, output = self.run_main(*args, "--offline", "--check")
        self.assertEqual(code, 0, output)
        self.assertEqual(self.requests, [])

    def test_skip_unsupported_single_default_and_explicit(self):
        for extra in ((), ("--skip-unsupported",)):
            code, output = self.run_main("--project", "anti-xss", "--out-dir", self.root / "absent", *extra)
            self.assertEqual(code, 0, output)
            self.assertIn("NO_OSV_GIT_FEED", output)
            self.assertFalse((self.root / "absent").exists())
        self.assertEqual(self.requests, [])

    def test_no_skip_unsupported_fails_before_any_network_or_output(self):
        code, output = self.run_main("--projects-file", SELECTION, "--out-dir", self.root / "absent", "--no-skip-unsupported")
        self.assertEqual(code, 1, output)
        self.assertIn("NO_OSV_GIT_FEED", output)
        self.assertEqual(self.requests, [])
        self.assertFalse((self.root / "absent").exists())

    def test_empty_response_no_catalog_and_batch_continues(self):
        entries = [{"name": name, "repo": "https://github.com/example/" + name,
                    "osv_git_supported": True} for name in ("empty", "valid")]
        self.seed(entries[1:])
        out = self.root / "catalogs"
        code, output = self.run_main("--projects-file", self.manifest(entries), "--out-dir", out)
        self.assertEqual(code, 1, output)
        self.assertIn("1 completed, 0 NO_OSV_GIT_FEED, 1 failed", output)
        self.assertFalse((out / "empty-upstream").exists())
        self.assertTrue((out / "valid-upstream/catalog.jsonl").exists())

    def test_pagination_fetches_every_page(self):
        entry = {"name": "botan", "repo": "https://github.com/randombit/botan", "osv_git_supported": True}
        self.seed([entry])
        package = F._selection_meta(entry)["package"]
        first = self.responses[(package, None)]
        second = json.loads(json.dumps(first))
        second["vulns"][0]["id"] = "CVE-2026-12346"
        first["next_page_token"] = "page-two"
        self.responses[(package, "page-two")] = second
        code, output = self.run_main("--projects-file", self.manifest([entry]), "--out-dir", self.root)
        self.assertEqual(code, 0, output)
        self.assertEqual(len((self.root / "botan-upstream/catalog.jsonl").read_text().splitlines()), 2)
        self.assertEqual(self.requests[-1]["page_token"], "page-two")

    def test_repeated_page_token_is_rejected_without_catalog(self):
        entry = {"name": "botan", "repo": "https://github.com/randombit/botan", "osv_git_supported": True}
        self.seed([entry])
        package = F._selection_meta(entry)["package"]
        response = self.responses[(package, None)]
        response["next_page_token"] = "loop"
        self.responses[(package, "loop")] = response
        code, output = self.run_main("--projects-file", self.manifest([entry]), "--out-dir", self.root)
        self.assertEqual(code, 1, output)
        self.assertIn("repeated OSV page token", output)
        self.assertFalse((self.root / "botan-upstream").exists())

    def test_invalid_manifest_name_rejected(self):
        entry = {"name": "../escape", "repo": "https://github.com/example/repo", "osv_git_supported": True}
        code, output = self.run_main("--projects-file", self.manifest([entry]), "--out-dir", self.root)
        self.assertEqual(code, 1, output)
        self.assertEqual(self.requests, [])

    def test_missing_parent_evidence_does_not_publish_catalog(self):
        entry = {"name": "botan", "repo": "https://github.com/randombit/botan", "osv_git_supported": True}
        self.seed([entry])
        self.parents.write_text("")
        code, output = self.run_main("--projects-file", self.manifest([entry]), "--out-dir", self.root)
        self.assertEqual(code, 1, output)
        self.assertIn("absent from", output)
        self.assertFalse((self.root / "botan-upstream/catalog.jsonl").exists())

    def test_unknown_project_and_check_without_offline_are_errors(self):
        self.assertEqual(self.run_main("--project", "unknown")[0], 1)
        self.assertEqual(self.run_main("--projects-file", SELECTION, "--check")[0], 2)


if __name__ == "__main__":
    unittest.main()
