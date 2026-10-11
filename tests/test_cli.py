"""Tests for the ksm CLI and data module."""

import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ksm.cli import main
from ksm.data import (
    find_cve_project,
    get_pattern_clusters_path,
    load_cve,
    load_cwe,
    load_index,
    load_search,
    resolve_data_dir,
    update,
)

FIXTURE_DATA_DIR = Path(__file__).parent / "fixtures" / "site-data"


class TestKsmCliSubcommands(unittest.TestCase):
    """Test all CLI subcommands through ksm.cli.main([...])."""

    def setUp(self):
        self.data_dir = str(FIXTURE_DATA_DIR.resolve())

    def run_cli(self, args):
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(args)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_stats_human(self):
        code, out, err = self.run_cli(["stats", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("KSM Commit:", out)
        self.assertIn("Totals:", out)
        self.assertIn("CVEs:              3", out)
        self.assertIn("curl", out)
        self.assertIn("linux", out)

    def test_stats_json(self):
        code, out, err = self.run_cli(["stats", "--data-dir", self.data_dir, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["totals"]["cves"], 3)
        self.assertEqual(len(data["projects"]), 2)

    def test_tree_cwe_human(self):
        code, out, err = self.run_cli(["tree", "--by", "cwe", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("Memory safety", out)
        self.assertIn("CWE-787", out)
        self.assertIn("curl: 1", out)

    def test_tree_cwe_filter_and_limit(self):
        code, out, err = self.run_cli([
            "tree", "--by", "cwe", "--cwe", "CWE-787", "--limit", "1", "--data-dir", self.data_dir
        ])
        self.assertEqual(code, 0)
        self.assertIn("CWE-787", out)
        self.assertNotIn("CWE-416", out)

    def test_tree_cwe_json(self):
        code, out, err = self.run_cli(["tree", "--by", "cwe", "--data-dir", self.data_dir, "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertTrue(any(g["name"] == "Memory safety" for g in data))

    def test_tree_project_human(self):
        code, out, err = self.run_cli(["tree", "--by", "project", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("Projects:", out)
        self.assertIn("curl (repo: curl/curl)", out)
        self.assertIn("linux (repo: torvalds/linux)", out)

    def test_tree_project_filter(self):
        code, out, err = self.run_cli([
            "tree", "--by", "project", "--project", "curl", "--data-dir", self.data_dir
        ])
        self.assertEqual(code, 0)
        self.assertIn("curl", out)
        self.assertNotIn("linux", out)

    def test_tree_project_json(self):
        code, out, err = self.run_cli([
            "tree", "--by", "project", "--data-dir", self.data_dir, "--json"
        ])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)

    def test_show_cve_with_auto_project(self):
        code, out, err = self.run_cli(["show", "CVE-2099-1001", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("CVE:          CVE-2099-1001", out)
        self.assertIn("Project:      curl", out)
        self.assertIn("CWE:          CWE-787", out)
        self.assertIn("6b08044702cf", out)
        self.assertIn("Fragments:    OK (1 files)", out)
        self.assertIn("Fingerprint:  Available", out)
        self.assertIn("Related:", out)

    def test_show_cve_explicit_project_json(self):
        code, out, err = self.run_cli([
            "show", "CVE-2099-1001", "--project", "curl", "--data-dir", self.data_dir, "--json"
        ])
        self.assertEqual(code, 0)
        cve = json.loads(out)
        self.assertEqual(cve["id"], "CVE-2099-1001")
        self.assertEqual(cve["project"], "curl")

    def test_show_cve_missing(self):
        code, out, err = self.run_cli(["show", "CVE-9999-99999", "--data-dir", self.data_dir])
        self.assertEqual(code, 2)
        self.assertIn("Error:", err)

    def test_related_cve_human(self):
        code, out, err = self.run_cli(["related", "CVE-2099-1001", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2099-1002", out)
        self.assertIn("curl", out)
        self.assertIn("0.42", out)

    def test_related_cve_json(self):
        code, out, err = self.run_cli([
            "related", "CVE-2099-1001", "--data-dir", self.data_dir, "--json"
        ])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], "CVE-2099-1002")

    def test_related_cve_empty(self):
        code, out, err = self.run_cli(["related", "CVE-2099-1003", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("No related CVEs found.", out)

    def test_search_substring(self):
        code, out, err = self.run_cli(["search", "SOCKS5", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2099-1001", out)
        self.assertIn("do_SOCKS5", out)

    def test_search_limit_and_json(self):
        code, out, err = self.run_cli([
            "search", "curl", "--limit", "1", "--data-dir", self.data_dir, "--json"
        ])
        self.assertEqual(code, 0)
        matches = json.loads(out)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["project"], "curl")

    def test_search_no_matches(self):
        code, out, err = self.run_cli(["search", "nonexistentquery123", "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("No matches found.", out)

    def test_audit_clean_file(self):
        target = FIXTURE_DATA_DIR / "cve" / "linux" / "CVE-2099-1003.json"
        code, out, err = self.run_cli(["audit", str(target), "--data-dir", self.data_dir])
        self.assertEqual(code, 0)
        self.assertIn("Verdict: PASS", out)
        self.assertIn("Findings: 0", out)

    def test_audit_json(self):
        target = FIXTURE_DATA_DIR / "cve" / "linux" / "CVE-2099-1003.json"
        code, out, err = self.run_cli(["audit", str(target), "--data-dir", self.data_dir, "--json"])
        self.assertEqual(code, 0)
        res = json.loads(out)
        self.assertIn("evidence_chain_hash", res)
        self.assertEqual(res["audit"]["verdict"], "PASS")

    def test_audit_strict_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_file = Path(tmp_dir) / "vuln.c"
            bad_file.write_text('#include <string.h>\nvoid f(char *s) { char buf[10]; strcpy(buf, s); }\n')
            code, out, err = self.run_cli(["audit", str(bad_file), "--strict", "--data-dir", self.data_dir])
            self.assertEqual(code, 1)
            self.assertIn("Verdict: FAIL", out)


class TestKsmScan(unittest.TestCase):
    """Test ksm scan subcommand with fake code-graph and stub ksm.match."""

    def setUp(self):
        self.data_dir = str(FIXTURE_DATA_DIR.resolve())
        self.tmp_dir = tempfile.mkdtemp()
        self.code_graph_bin = Path(self.tmp_dir) / "code-graph"

        # Create fake code-graph executable
        script = """#!/usr/bin/env python3
import json
import sys
if len(sys.argv) >= 3 and sys.argv[1] == "fingerprint":
    doc = {"schema": "ksm-sfp/1", "file": sys.argv[2], "coverage": "OK",
           "functions": [{"name": "test_fn"}]}
    print(json.dumps(doc))
"""
        self.code_graph_bin.write_text(script, encoding="utf-8")
        self.code_graph_bin.chmod(0o755)

        # Inject stub ksm.match
        self.orig_match = sys.modules.get("ksm.match")
        stub = types.ModuleType("ksm.match")
        stub.load_corpus = lambda d: [{"corpus_entry": 1}]
        stub.match_documents = lambda docs, corpus: (
            [{"finding": "match_1", "file": docs[0]["file"]}] if docs else []
        )
        stub.render_markdown = lambda findings: f"## Scan Findings: {len(findings)}\n"
        sys.modules["ksm.match"] = stub

        # Target dir with source files
        self.target_dir = Path(self.tmp_dir) / "src"
        self.target_dir.mkdir()
        (self.target_dir / "main.c").write_text("int main() { return 0; }\n")
        (self.target_dir / "util.py").write_text("def util(): pass\n")
        (self.target_dir / "ignored.txt").write_text("text\n")

    def tearDown(self):
        if self.orig_match is not None:
            sys.modules["ksm.match"] = self.orig_match
        else:
            sys.modules.pop("ksm.match", None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_scan_success(self):
        env_backup = os.environ.get("KSM_CODE_GRAPH")
        try:
            os.environ["KSM_CODE_GRAPH"] = str(self.code_graph_bin)
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                code = main(["scan", str(self.target_dir), "--data-dir", self.data_dir])
            self.assertEqual(code, 0)
            self.assertIn("## Scan Findings: 1", out_buf.getvalue())
        finally:
            if env_backup is not None:
                os.environ["KSM_CODE_GRAPH"] = env_backup
            else:
                os.environ.pop("KSM_CODE_GRAPH", None)

    def test_scan_strict_with_findings(self):
        env_backup = os.environ.get("KSM_CODE_GRAPH")
        try:
            os.environ["KSM_CODE_GRAPH"] = str(self.code_graph_bin)
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                code = main(["scan", str(self.target_dir), "--strict", "--data-dir", self.data_dir])
            self.assertEqual(code, 1)
        finally:
            if env_backup is not None:
                os.environ["KSM_CODE_GRAPH"] = env_backup
            else:
                os.environ.pop("KSM_CODE_GRAPH", None)

    def test_scan_json_and_out_file(self):
        env_backup = os.environ.get("KSM_CODE_GRAPH")
        out_file = Path(self.tmp_dir) / "out.json"
        try:
            os.environ["KSM_CODE_GRAPH"] = str(self.code_graph_bin)
            code = main([
                "scan", str(self.target_dir),
                "--json", "--out", str(out_file),
                "--data-dir", self.data_dir
            ])
            self.assertEqual(code, 0)
            self.assertTrue(out_file.is_file())
            content = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(len(content), 1)
            self.assertEqual(content[0]["finding"], "match_1")
        finally:
            if env_backup is not None:
                os.environ["KSM_CODE_GRAPH"] = env_backup
            else:
                os.environ.pop("KSM_CODE_GRAPH", None)

    def test_scan_wrong_binary_is_an_error_not_a_clean_result(self):
        # An old code-graph without `fingerprint` (or any other program) must
        # not be reported as "no findings".
        bogus = Path(self.tmp_dir) / "old-code-graph"
        bogus.write_text("#!/bin/sh\necho not-json\n", encoding="utf-8")
        bogus.chmod(0o755)
        env_backup = os.environ.get("KSM_CODE_GRAPH")
        try:
            os.environ["KSM_CODE_GRAPH"] = str(bogus)
            err_buf, out_buf = io.StringIO(), io.StringIO()
            with redirect_stderr(err_buf), redirect_stdout(out_buf):
                code = main(["scan", str(self.target_dir), "--data-dir", self.data_dir])
            self.assertEqual(code, 2)
            self.assertIn("no ksm-sfp/1 output", err_buf.getvalue())
            self.assertEqual(out_buf.getvalue(), "")
        finally:
            if env_backup is not None:
                os.environ["KSM_CODE_GRAPH"] = env_backup
            else:
                os.environ.pop("KSM_CODE_GRAPH", None)

    def test_scan_missing_binary(self):
        env_backup = os.environ.get("KSM_CODE_GRAPH")
        path_backup = os.environ.get("PATH")
        try:
            os.environ.pop("KSM_CODE_GRAPH", None)
            os.environ["PATH"] = ""
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                code = main(["scan", str(self.target_dir), "--data-dir", self.data_dir])
            self.assertEqual(code, 2)
            self.assertIn("executable not found", err_buf.getvalue())
        finally:
            if env_backup is not None:
                os.environ["KSM_CODE_GRAPH"] = env_backup
            if path_backup is not None:
                os.environ["PATH"] = path_backup


class TestKsmUpdateAndData(unittest.TestCase):
    """Test data resolution and update bundle download/verification/safe extraction."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.source_dir = Path(self.tmp_dir) / "source_server"
        self.source_dir.mkdir()

        # Create a valid bundle
        payload_dir = Path(self.tmp_dir) / "payload"
        payload_dir.mkdir()
        (payload_dir / "index.json").write_text('{"schema": "ksm-site/1"}\n', encoding="utf-8")

        self.valid_tar = self.source_dir / "bundle.tar.gz"
        with tarfile.open(self.valid_tar, "w:gz") as tf:
            tf.add(payload_dir / "index.json", arcname="index.json")

        h = hashlib.sha256(self.valid_tar.read_bytes()).hexdigest()
        (self.source_dir / "bundle.sha256").write_text(f"{h}  bundle.tar.gz\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_update_valid_bundle(self):
        dest_dir = Path(self.tmp_dir) / "installed_data"
        result_dest = update(url=str(self.source_dir), dest=dest_dir)
        self.assertEqual(result_dest, dest_dir.resolve())
        self.assertTrue((dest_dir / "index.json").is_file())

    def test_update_tampered_sha256_rejected(self):
        # Corrupt the sha256 file
        (self.source_dir / "bundle.sha256").write_text("deadbeef" * 8 + "  bundle.tar.gz\n")
        dest_dir = Path(self.tmp_dir) / "installed_data_bad"
        with self.assertRaises(ValueError) as ctx:
            update(url=str(self.source_dir), dest=dest_dir)
        self.assertIn("mismatch", str(ctx.exception).lower())
        self.assertFalse(dest_dir.exists())

    def test_update_unsafe_tar_traversal_rejected(self):
        # Create a tar with a ../ member
        evil_tar = self.source_dir / "bundle.tar.gz"
        with tarfile.open(evil_tar, "w:gz") as tf:
            # create dummy member
            info = tarfile.TarInfo(name="../escaped.txt")
            data = b"evil content"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        h = hashlib.sha256(evil_tar.read_bytes()).hexdigest()
        (self.source_dir / "bundle.sha256").write_text(f"{h}  bundle.tar.gz\n")

        dest_dir = Path(self.tmp_dir) / "installed_data_evil"
        with self.assertRaises(ValueError) as ctx:
            update(url=str(self.source_dir), dest=dest_dir)
        self.assertIn("unsafe", str(ctx.exception).lower())

    def test_data_resolution_order(self):
        # 1. Explicit argument
        d1 = resolve_data_dir("/custom/explicit")
        self.assertEqual(str(d1), "/custom/explicit")

        # 2. KSM_DATA env var
        old_env = os.environ.get("KSM_DATA")
        try:
            os.environ["KSM_DATA"] = "/env/ksm/data"
            d2 = resolve_data_dir()
            self.assertEqual(str(d2), "/env/ksm/data")
        finally:
            if old_env is not None:
                os.environ["KSM_DATA"] = old_env
            else:
                os.environ.pop("KSM_DATA", None)

    def test_shard_helpers(self):
        idx = load_index(FIXTURE_DATA_DIR)
        self.assertEqual(idx["schema"], "ksm-site/1")

        search = load_search(FIXTURE_DATA_DIR)
        self.assertEqual(len(search), 3)

        cwe = load_cwe("CWE-787", FIXTURE_DATA_DIR)
        self.assertEqual(cwe["id"], "CWE-787")

        cve = load_cve("curl", "CVE-2099-1001", FIXTURE_DATA_DIR)
        self.assertEqual(cve["id"], "CVE-2099-1001")

        proj = find_cve_project("CVE-2099-1001", FIXTURE_DATA_DIR)
        self.assertEqual(proj, "curl")


if __name__ == "__main__":
    unittest.main()
