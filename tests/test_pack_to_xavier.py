#!/usr/bin/env python3
"""Tests for scripts/pack_to_xavier.py. No external network: a local
http.server captures requests instead of a real Xavier."""

import io
import json
import os
import sys
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
        cls.tmp = Path(os.environ.get("TMPDIR", "/tmp/opencode")) / "packbridge"
        if cls.tmp.exists():
            import shutil
            shutil.rmtree(cls.tmp)
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
