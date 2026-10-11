"""Tests for KSM Model Context Protocol (MCP) server."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

import ksm
from ksm.mcp import MCPServer, process_requests

FIXTURE_DATA_DIR = Path(__file__).parent / "fixtures" / "site-data"


class TestMCPServer(unittest.TestCase):
    """Test MCP server in-process message handling and tool execution."""

    def setUp(self):
        self.data_dir = str(FIXTURE_DATA_DIR.resolve())
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        # Ensure ksm.deps stub is removed if injected
        sys.modules.pop("ksm.deps", None)

    def test_initialize_handshake_default_and_2025(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        r = resps[0]
        self.assertEqual(r.get("id"), 1)
        self.assertEqual(r.get("jsonrpc"), "2.0")
        result = r.get("result", {})
        self.assertEqual(result.get("protocolVersion"), "2025-06-18")
        self.assertEqual(result.get("serverInfo", {}).get("name"), "ksm")
        self.assertEqual(result.get("serverInfo", {}).get("version"), ksm.__version__)
        self.assertIn("tools", result.get("capabilities", {}))

    def test_initialize_handshake_legacy_2024(self):
        req = {
            "jsonrpc": "2.0",
            "id": "init-legacy",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        r = resps[0]
        self.assertEqual(r.get("id"), "init-legacy")
        self.assertEqual(r.get("result", {}).get("protocolVersion"), "2024-11-05")

    def test_initialize_handshake_unknown_version_falls_back(self):
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": "2099-01-01"},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        self.assertEqual(resps[0].get("result", {}).get("protocolVersion"), "2025-06-18")

    def test_notifications_produce_no_reply(self):
        reqs = [
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "method": "custom/notify"},
            {"jsonrpc": "2.0", "id": "p1", "method": "ping"},
        ]
        resps = process_requests(reqs, data_dir=self.data_dir)
        # Only the ping request with id should produce a reply
        self.assertEqual(len(resps), 1)
        self.assertEqual(resps[0].get("id"), "p1")
        self.assertEqual(resps[0].get("result"), {})

    def test_ping(self):
        req = {"jsonrpc": "2.0", "id": 10, "method": "ping"}
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        self.assertEqual(resps[0].get("id"), 10)
        self.assertEqual(resps[0].get("result"), {})

    def test_tools_list_names_and_schemas(self):
        req = {"jsonrpc": "2.0", "id": "tools-1", "method": "tools/list"}
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        tools = resps[0].get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]

        expected_names = ["ksm_stats", "ksm_search", "ksm_show", "ksm_related", "ksm_audit", "ksm_scan"]
        for expected in expected_names:
            self.assertIn(expected, tool_names)

        # ksm_deps should NOT be present when ksm.deps is not importable
        self.assertNotIn("ksm_deps", tool_names)

        # Check schemas
        for t in tools:
            self.assertIn("name", t)
            self.assertIn("description", t)
            schema = t.get("inputSchema", {})
            self.assertEqual(schema.get("type"), "object")
            self.assertIsInstance(schema.get("properties"), dict)

    def test_tools_list_with_deps_available(self):
        stub = types.ModuleType("ksm.deps")
        stub.scan_dependencies = lambda p, data_dir=None: [{"name": "fake-dep"}]
        sys.modules["ksm.deps"] = stub

        req = {"jsonrpc": "2.0", "id": "tools-2", "method": "tools/list"}
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        tools = resps[0].get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        self.assertIn("ksm_deps", tool_names)

        # Verify ksm_deps schema
        deps_tool = next(t for t in tools if t["name"] == "ksm_deps")
        self.assertIn("path", deps_tool["inputSchema"]["properties"])
        self.assertEqual(deps_tool["inputSchema"]["required"], ["path"])

    def test_tool_stats(self):
        req = {
            "jsonrpc": "2.0",
            "id": "stats-1",
            "method": "tools/call",
            "params": {"name": "ksm_stats", "arguments": {}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        r = resps[0]
        self.assertEqual(r.get("id"), "stats-1")
        self.assertNotIn("error", r)
        result = r.get("result", {})
        self.assertFalse(result.get("isError", False))
        content = result.get("content", [])
        self.assertTrue(len(content) > 0)
        self.assertEqual(content[0]["type"], "text")
        parsed = json.loads(content[0]["text"])
        self.assertIn("totals", parsed)
        self.assertIn("projects", parsed)
        self.assertEqual(parsed["totals"].get("cves"), 3)

    def test_tool_search(self):
        req = {
            "jsonrpc": "2.0",
            "id": "search-1",
            "method": "tools/call",
            "params": {"name": "ksm_search", "arguments": {"query": "curl", "limit": 2}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        result = resps[0].get("result", {})
        self.assertFalse(result.get("isError", False))
        content = result.get("content", [])
        parsed = json.loads(content[0]["text"])
        self.assertIsInstance(parsed, list)
        self.assertLessEqual(len(parsed), 2)
        self.assertTrue(all(item["project"] == "curl" for item in parsed))

    def test_tool_search_validation(self):
        # Missing query
        req = {
            "jsonrpc": "2.0",
            "id": "search-bad",
            "method": "tools/call",
            "params": {"name": "ksm_search", "arguments": {}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        result = resps[0].get("result", {})
        self.assertTrue(result.get("isError"))
        self.assertIn("query", result.get("content", [])[0]["text"])

    def test_tool_show(self):
        req = {
            "jsonrpc": "2.0",
            "id": "show-1",
            "method": "tools/call",
            "params": {"name": "ksm_show", "arguments": {"cve": "CVE-2099-1001"}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        result = resps[0].get("result", {})
        self.assertFalse(result.get("isError", False))
        parsed = json.loads(result["content"][0]["text"])
        self.assertEqual(parsed.get("id"), "CVE-2099-1001")
        self.assertEqual(parsed.get("project"), "curl")

    def test_tool_show_missing_or_not_found(self):
        # Missing cve arg
        req1 = {
            "jsonrpc": "2.0",
            "id": "show-no-cve",
            "method": "tools/call",
            "params": {"name": "ksm_show", "arguments": {}},
        }
        resps1 = process_requests([req1], data_dir=self.data_dir)
        self.assertTrue(resps1[0].get("result", {}).get("isError"))

        # Nonexistent CVE
        req2 = {
            "jsonrpc": "2.0",
            "id": "show-404",
            "method": "tools/call",
            "params": {"name": "ksm_show", "arguments": {"cve": "CVE-9999-99999"}},
        }
        resps2 = process_requests([req2], data_dir=self.data_dir)
        self.assertTrue(resps2[0].get("result", {}).get("isError"))
        self.assertIn("Error", resps2[0]["result"]["content"][0]["text"])

    def test_tool_related(self):
        req = {
            "jsonrpc": "2.0",
            "id": "related-1",
            "method": "tools/call",
            "params": {"name": "ksm_related", "arguments": {"cve": "CVE-2099-1001"}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        result = resps[0].get("result", {})
        self.assertFalse(result.get("isError", False))
        parsed = json.loads(result["content"][0]["text"])
        self.assertIsInstance(parsed, list)
        self.assertTrue(len(parsed) > 0)
        self.assertEqual(parsed[0]["id"], "CVE-2099-1002")

    def test_tool_audit(self):
        target = FIXTURE_DATA_DIR / "cve" / "linux" / "CVE-2099-1003.json"
        req = {
            "jsonrpc": "2.0",
            "id": "audit-1",
            "method": "tools/call",
            "params": {"name": "ksm_audit", "arguments": {"path": str(target)}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        result = resps[0].get("result", {})
        self.assertFalse(result.get("isError", False))
        parsed = json.loads(result["content"][0]["text"])
        self.assertIn("evidence_chain_hash", parsed)
        self.assertEqual(parsed.get("audit", {}).get("verdict"), "PASS")

    def test_tool_audit_missing_path(self):
        req = {
            "jsonrpc": "2.0",
            "id": "audit-bad",
            "method": "tools/call",
            "params": {"name": "ksm_audit", "arguments": {}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertTrue(resps[0].get("result", {}).get("isError"))

    def test_tool_scan(self):
        # Create fake code-graph executable
        code_graph_bin = Path(self.tmp_dir) / "code-graph"
        script = """#!/usr/bin/env python3
import json
import sys
if len(sys.argv) >= 3 and sys.argv[1] == "fingerprint":
    doc = {"schema": "ksm-sfp/1", "file": sys.argv[2], "coverage": "OK",
           "functions": [{"name": "test_fn"}]}
    print(json.dumps(doc))
"""
        code_graph_bin.write_text(script, encoding="utf-8")
        code_graph_bin.chmod(0o755)

        # Inject stub ksm.match
        orig_match = sys.modules.get("ksm.match")
        stub_match = types.ModuleType("ksm.match")
        stub_match.load_corpus = lambda d: [{"corpus_entry": 1}]
        stub_match.match_documents = lambda docs, corpus: (
            [{"finding": "match_1", "file": docs[0]["file"]}] if docs else []
        )
        stub_match.render_markdown = lambda findings: f"## Scan Findings: {len(findings)}\n"
        sys.modules["ksm.match"] = stub_match

        target_dir = Path(self.tmp_dir) / "src"
        target_dir.mkdir()
        (target_dir / "main.c").write_text("int main() { return 0; }\n")

        env_backup = os.environ.get("KSM_CODE_GRAPH")
        try:
            os.environ["KSM_CODE_GRAPH"] = str(code_graph_bin)
            req = {
                "jsonrpc": "2.0",
                "id": "scan-1",
                "method": "tools/call",
                "params": {"name": "ksm_scan", "arguments": {"path": str(target_dir)}},
            }
            resps = process_requests([req], data_dir=self.data_dir)
            self.assertEqual(len(resps), 1)
            result = resps[0].get("result", {})
            self.assertFalse(result.get("isError", False))
            parsed = json.loads(result["content"][0]["text"])
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0]["finding"], "match_1")
        finally:
            if env_backup is not None:
                os.environ["KSM_CODE_GRAPH"] = env_backup
            else:
                os.environ.pop("KSM_CODE_GRAPH", None)
            if orig_match is not None:
                sys.modules["ksm.match"] = orig_match
            else:
                sys.modules.pop("ksm.match", None)

    def test_tool_scan_missing_code_graph_returns_tool_error(self):
        target_dir = Path(self.tmp_dir) / "src"
        target_dir.mkdir()
        (target_dir / "main.c").write_text("int main() { return 0; }\n")

        env_backup = os.environ.get("KSM_CODE_GRAPH")
        path_backup = os.environ.get("PATH")
        try:
            os.environ.pop("KSM_CODE_GRAPH", None)
            os.environ["PATH"] = ""
            req = {
                "jsonrpc": "2.0",
                "id": "scan-no-cg",
                "method": "tools/call",
                "params": {"name": "ksm_scan", "arguments": {"path": str(target_dir)}},
            }
            resps = process_requests([req], data_dir=self.data_dir)
            self.assertEqual(len(resps), 1)
            result = resps[0].get("result", {})
            self.assertTrue(result.get("isError"))
            self.assertIn("executable not found", result["content"][0]["text"])
        finally:
            if env_backup is not None:
                os.environ["KSM_CODE_GRAPH"] = env_backup
            if path_backup is not None:
                os.environ["PATH"] = path_backup

    def test_tool_deps(self):
        # 1. When ksm.deps is available
        stub = types.ModuleType("ksm.deps")
        stub.scan_dependencies = lambda p, data_dir=None: [{"dep": "libssl", "version": "3.0"}]
        sys.modules["ksm.deps"] = stub

        req = {
            "jsonrpc": "2.0",
            "id": "deps-1",
            "method": "tools/call",
            "params": {"name": "ksm_deps", "arguments": {"path": "/fake/project"}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        result = resps[0].get("result", {})
        self.assertFalse(result.get("isError", False))
        parsed = json.loads(result["content"][0]["text"])
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["dep"], "libssl")

        # 2. When ksm.deps is NOT available
        sys.modules.pop("ksm.deps", None)
        resps2 = process_requests([req], data_dir=self.data_dir)
        self.assertTrue(resps2[0].get("result", {}).get("isError"))
        self.assertIn("Unknown tool", resps2[0]["result"]["content"][0]["text"])

    def test_unknown_tool_is_error(self):
        req = {
            "jsonrpc": "2.0",
            "id": "unknown-tool-1",
            "method": "tools/call",
            "params": {"name": "nonexistent_custom_tool", "arguments": {}},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        r = resps[0]
        self.assertEqual(r.get("id"), "unknown-tool-1")
        self.assertNotIn("error", r)  # Tool errors are returned in result, not JSON-RPC error
        result = r.get("result", {})
        self.assertTrue(result.get("isError"))
        self.assertIn("Unknown tool: nonexistent_custom_tool", result["content"][0]["text"])

    def test_unknown_method_error_32601(self):
        req = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "unknown/method",
            "params": {},
        }
        resps = process_requests([req], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        r = resps[0]
        self.assertEqual(r.get("id"), 99)
        self.assertIn("error", r)
        self.assertEqual(r["error"]["code"], -32601)
        self.assertIn("Method not found", r["error"]["message"])

    def test_bad_json_error_32700(self):
        bad_json = '{"jsonrpc": 2.0, bad-json'
        resps = process_requests([bad_json], data_dir=self.data_dir)
        self.assertEqual(len(resps), 1)
        r = resps[0]
        self.assertIsNone(r.get("id"))
        self.assertIn("error", r)
        self.assertEqual(r["error"]["code"], -32700)
        self.assertEqual(r["error"]["message"], "Parse error")

    def test_subprocess_mcp_server(self):
        """Test the server as an external process running python3 -m ksm mcp over stdio."""
        cmd = [
            sys.executable,
            "-m",
            "ksm",
            "mcp",
            "--data-dir",
            self.data_dir,
        ]

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "ksm_stats", "arguments": {}}},
        ]

        payload = "".join(json.dumps(r) + "\n" for r in requests)
        stdout_data, stderr_data = proc.communicate(input=payload, timeout=10)

        self.assertEqual(proc.returncode, 0)

        # Every single line in stdout must be valid JSON
        lines = [line.strip() for line in stdout_data.strip().split("\n") if line.strip()]
        self.assertEqual(len(lines), 4)  # 4 responses for 5 requests (notification has no reply)

        responses = []
        for line in lines:
            try:
                responses.append(json.loads(line))
            except json.JSONDecodeError as exc:
                self.fail(f"Non-JSON output on stdout: {line!r} ({exc})")

        # Verify responses in order
        self.assertEqual(responses[0]["id"], 1)
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(responses[1]["id"], 2)
        self.assertEqual(responses[1]["result"], {})
        self.assertEqual(responses[2]["id"], 3)
        self.assertIn("tools", responses[2]["result"])
        self.assertEqual(responses[3]["id"], 4)
        parsed_stats = json.loads(responses[3]["result"]["content"][0]["text"])
        self.assertEqual(parsed_stats["totals"]["cves"], 3)


if __name__ == "__main__":
    unittest.main()
