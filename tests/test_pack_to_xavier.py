#!/usr/bin/env python3
"""Tests for scripts/pack_to_xavier.py. No external network: a local
http.server captures requests instead of a real Xavier."""

import io
import json
import os
import sys
import tempfile
import threading
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import TestCase, main

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_pack import artifacts  # noqa: E402
from pack_to_xavier import main as bridge_main  # noqa: E402
from pack_to_xavier import mem_body, verify_pack  # noqa: E402

SECRET = "tok_TESTSECRET_abc123"


def make_record(rid):
    return {
        "schema_version": "0.1.0",
        "id": rid,
        "project": "linux",
        "title": f"Title {rid}",
        "status": "observed",
        "nodes": [{"id": "n1", "type": "repository", "label": "repo",
                   "attributes": {}}],
        "edges": [],
        "evidence": [{
            "id": "e1",
            "sha256": "a" * 64,
            "url": "https://example.com/a",
            "fetch_url": "https://example.com/a",
            "observed_at": "2026-01-01",
            "hash_scope": "body",
            "source_license": "GPL-2.0",
            "extractor": "t",
            "canonicalization": "c",
        }],
        "claims": [],
        "evolution": {"outcome": "UNKNOWN", "coverage": "seed",
                      "horizon_end": None, "followups": []},
        "validation": {},
        "license": {},
    }


class CaptureHandler(BaseHTTPRequestHandler):
    store = {"POST": [], "DELETE": [], "fail": False}

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.store["fail"]:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"boom")
            return
        self.store[self.command].append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "content_type": self.headers.get("Content-Type"),
            "body": body,
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    do_POST = _reply
    do_DELETE = _reply

    def log_message(self, *args):
        pass


class BridgeTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), CaptureHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="packbridge-")
        cls.tmp = Path(cls._tmpdir.name)
        pack = cls.tmp / "pack"
        pack.mkdir(parents=True)
        for name, body in artifacts([make_record("r1"), make_record("r2")]).items():
            target = pack / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        cls.pack = str(pack)
        os.environ["XAVIER_URL"] = f"http://127.0.0.1:{cls.port}"
        os.environ["XAVIER_TOKEN"] = SECRET

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls._tmpdir.cleanup()

    def setUp(self):
        CaptureHandler.store = {"POST": [], "DELETE": [], "fail": False}

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err):
                bridge_main(list(args))
        except SystemExit as exc:
            return out.getvalue(), err.getvalue(), exc.code or 0
        except Exception as exc:  # fail-closed paths (verify errors)
            return out.getvalue() + f"Error: {exc}", err.getvalue(), 1
        return out.getvalue(), err.getvalue(), 0

    def test_payload_shape(self):
        out, err, code = self.run_main("--source", self.pack,
                                       "--path-prefix", "ksm-test")
        self.assertEqual(code, 0)
        posts = CaptureHandler.store["POST"]
        self.assertEqual(len(posts), 2)
        for post in posts:
            self.assertEqual(post["auth"], "Bearer " + SECRET)
            self.assertEqual(post["content_type"], "application/json")
            body = json.loads(post["body"].decode())
            self.assertTrue(body["path"].startswith("ksm-test/"))
            self.assertIn("payload", body)
            self.assertEqual(body["payload"]["schema_version"], "0.1.0")
        self.assertNotIn(SECRET, out + err)

    def test_dry_run_sends_nothing(self):
        out, err, code = self.run_main("--source", self.pack, "--dry-run",
                                       "--path-prefix", "ksm-test")
        self.assertEqual(code, 0)
        self.assertEqual(CaptureHandler.store["POST"], [])
        self.assertEqual(CaptureHandler.store["DELETE"], [])
        self.assertIn("DRY-RUN", out)
        self.assertNotIn(SECRET, out + err)

    def test_disconnect_deletes_by_prefix(self):
        out, err, code = self.run_main("--source", self.pack, "--disconnect",
                                       "--path-prefix", "ksm-test")
        self.assertEqual(code, 0)
        self.assertEqual(CaptureHandler.store["POST"], [])
        deletes = CaptureHandler.store["DELETE"]
        self.assertEqual(len(deletes), 2)
        self.assertTrue(all("ksm-test" in d["path"] for d in deletes))

    def test_no_secret_in_logs_or_errors(self):
        CaptureHandler.store["fail"] = True
        out, err, code = self.run_main("--source", self.pack,
                                       "--path-prefix", "ksm-test")
        self.assertNotEqual(code, 0)
        self.assertNotIn(SECRET, out + err)
        # tampered pack must fail without leaking anything either
        bad = Path(self.pack) / "records" / "r1.json"
        raw = bad.read_bytes()
        bad.write_bytes(raw.replace(b"Title r1", b"Title BROKEN\""))
        try:
            out2, err2, code2 = self.run_main("--source", self.pack)
            self.assertNotEqual(code2, 0)
            self.assertNotIn(SECRET, out2 + err2)
        finally:
            bad.write_bytes(raw)

    def test_rejects_remote_source(self):
        out, err, code = self.run_main(
            "--source", "https://example.com/pack", "--dry-run")
        self.assertNotEqual(code, 0)

    def test_dry_run_disconnect_previews_deletes(self):
        out, err, code = self.run_main("--source", self.pack, "--dry-run",
                                       "--disconnect", "--path-prefix",
                                       "ksm-test")
        self.assertEqual(code, 0)
        self.assertIn("DRY-RUN DELETE", out)
        self.assertNotIn("DRY-RUN POST", out)
        self.assertEqual(CaptureHandler.store["POST"], [])
        self.assertEqual(CaptureHandler.store["DELETE"], [])

    def test_rejects_cleartext_remote_url(self):
        os.environ["XAVIER_URL"] = "http://example.com:9999"
        try:
            out, err, code = self.run_main("--source", self.pack)
            self.assertNotEqual(code, 0)
            self.assertEqual(CaptureHandler.store["POST"], [])
        finally:
            os.environ["XAVIER_URL"] = f"http://127.0.0.1:{self.port}"

    def test_redirects_not_followed(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from pack_to_xavier import _request

        class Redirector(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(302)
                self.send_header("Location",
                                 "http://127.0.0.1:9/stolen")
                self.end_headers()

            def log_message(self, *args):
                pass

        srv = HTTPServer(("127.0.0.1", 0), Redirector)
        port = srv.server_address[1]
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                _request(f"http://127.0.0.1:{port}/v1/memories",
                         SECRET, body={"a": 1})
            # redirect refused instead of followed: 302 surfaces as error
            self.assertIn("302", str(ctx.exception))
        finally:
            srv.shutdown()
            thread.join()

    def test_inventory_covers_older_paths_on_disconnect(self):
        inv = Path(self.tmp) / "inv.json"
        inv.write_text(json.dumps(["ksm-test/old-gone"]) + "\n")
        out, err, code = self.run_main(
            "--source", self.pack, "--disconnect", "--path-prefix",
            "ksm-test", "--inventory", str(inv))
        self.assertEqual(code, 0)
        deleted = [d["path"] for d in CaptureHandler.store["DELETE"]]
        self.assertTrue(any("old-gone" in p for p in deleted))
        self.assertEqual(len(deleted), 3)

    def test_publish_writes_inventory(self):
        inv = Path(self.tmp) / "inv2.json"
        out, err, code = self.run_main(
            "--source", self.pack, "--path-prefix", "ksm-test",
            "--inventory", str(inv))
        self.assertEqual(code, 0)
        saved = json.loads(inv.read_text())
        self.assertEqual(sorted(saved), ["ksm-test/r1", "ksm-test/r2"])

    def test_traversal_path_in_manifest_rejected(self):
        import hashlib
        evil = Path(self.tmp) / "evilpack"
        (evil / "records").mkdir(parents=True)
        body = b'{"schema_version": "0.1.0"}'
        (evil / "records" / "ok.json").write_bytes(body)
        manifest = {
            "schema_version": "0.1.0",
            "files": [
                {"path": "records/../evil.json",
                 "bytes": len(body),
                 "sha256": hashlib.sha256(body).hexdigest()},
            ],
        }
        (evil / "manifest.json").write_text(json.dumps(manifest))
        from pack_to_xavier import verify_pack
        with self.assertRaises(ValueError):
            verify_pack(str(evil))

    def test_missing_env_fails_closed(self):
        del os.environ["XAVIER_TOKEN"]
        try:
            out, err, code = self.run_main("--source", self.pack)
            self.assertNotEqual(code, 0)
            self.assertEqual(CaptureHandler.store["POST"], [])
        finally:
            os.environ["XAVIER_TOKEN"] = SECRET


if __name__ == "__main__":
    main()
