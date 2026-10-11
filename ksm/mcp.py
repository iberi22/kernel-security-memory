"""Model Context Protocol (MCP) server over stdio for Kernel Security Memory (ksm).

Implements JSON-RPC 2.0 protocol version 2025-06-18 (also accepting 2024-11-05).
Only protocol messages are written to stdout; all logs and warnings go to stderr.
"""

import importlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, TextIO, Union

import ksm
from ksm.cli import (
    run_audit,
    run_related,
    run_scan,
    run_search,
    run_show,
    run_stats,
)

SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-06-18"}
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

# JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def get_deps_module() -> Optional[Any]:
    """Return ksm.deps module if importable with scan_dependencies, else None."""
    try:
        mod = importlib.import_module("ksm.deps")
        if hasattr(mod, "scan_dependencies"):
            return mod
    except (ImportError, AttributeError):
        pass
    if "ksm.deps" in sys.modules:
        mod = sys.modules["ksm.deps"]
        if hasattr(mod, "scan_dependencies"):
            return mod
    return None


def is_deps_available() -> bool:
    """Check if ksm.deps is importable and provides scan_dependencies."""
    return get_deps_module() is not None


def jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    """Format successful JSON-RPC 2.0 response."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }


def jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Format JSON-RPC 2.0 error response."""
    err: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": err,
    }


def tool_content(data: Any) -> dict[str, Any]:
    """Format successful MCP tool response."""
    text_content = data if isinstance(data, str) else json.dumps(data, indent=2, ensure_ascii=False)
    return {
        "content": [
            {
                "type": "text",
                "text": text_content,
            }
        ]
    }


def tool_error(message: str) -> dict[str, Any]:
    """Format MCP tool error response (isError: true, not JSON-RPC error)."""
    return {
        "content": [
            {
                "type": "text",
                "text": message,
            }
        ],
        "isError": True,
    }


class MCPServer:
    """MCP server implementing JSON-RPC 2.0 over stdio."""

    def __init__(self, data_dir: Optional[Union[str, Path]] = None):
        self.data_dir = data_dir
        self.protocol_version = DEFAULT_PROTOCOL_VERSION

    def handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle initialize method handshake."""
        client_version = params.get("protocolVersion")
        if client_version in SUPPORTED_PROTOCOL_VERSIONS:
            self.protocol_version = client_version
        else:
            self.protocol_version = DEFAULT_PROTOCOL_VERSION

        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": "ksm",
                "version": getattr(ksm, "__version__", "0.1.0"),
            },
        }

    def handle_ping(self, params: Any = None) -> dict[str, Any]:
        """Handle ping method."""
        return {}

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return list of available MCP tool definitions."""
        tools = [
            {
                "name": "ksm_stats",
                "description": "Index totals and per-project counts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "ksm_search",
                "description": "Search CVE index by substring query.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query substring",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of rows to return (up to 200)",
                            "minimum": 1,
                            "maximum": 200,
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "ksm_show",
                "description": "Display detailed record for a CVE.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve": {
                            "type": "string",
                            "description": "CVE ID to show (e.g. CVE-2023-38545)",
                        },
                        "project": {
                            "type": "string",
                            "description": "Project name (auto-detected if omitted)",
                        },
                    },
                    "required": ["cve"],
                },
            },
            {
                "name": "ksm_related",
                "description": "Show related CVEs with shared features for a given advisory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cve": {
                            "type": "string",
                            "description": "CVE ID to inspect",
                        },
                        "project": {
                            "type": "string",
                            "description": "Project name (auto-detected if omitted)",
                        },
                    },
                    "required": ["cve"],
                },
            },
            {
                "name": "ksm_audit",
                "description": "Run defensive pattern regex audit on a path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to file or directory to audit",
                        },
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "ksm_scan",
                "description": "Scan code files with code-graph and match fix fingerprints.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to file or directory to scan",
                        },
                        "max_files": {
                            "type": "integer",
                            "description": "Maximum number of files to process",
                        },
                    },
                    "required": ["path"],
                },
            },
        ]

        if is_deps_available():
            tools.append({
                "name": "ksm_deps",
                "description": "Scan dependencies for a project or path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to project or manifest to scan dependencies for",
                        },
                    },
                    "required": ["path"],
                },
            })

        return tools

    def handle_tools_list(self, params: Any = None) -> dict[str, Any]:
        """Handle tools/list method."""
        return {"tools": self.get_tool_definitions()}

    def handle_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        """Handle tools/call method."""
        name = params.get("name")
        if not name:
            return tool_error("Missing tool name in params")

        args = params.get("arguments")
        if args is None or not isinstance(args, dict):
            args = {}

        if name == "ksm_stats":
            try:
                res = run_stats(data_dir=self.data_dir)
                return tool_content(res)
            except Exception as exc:
                return tool_error(f"Error running ksm_stats: {exc}")

        elif name == "ksm_search":
            if "query" not in args or not isinstance(args["query"], str):
                return tool_error("Missing required string parameter 'query'")
            limit = args.get("limit")
            if limit is not None:
                try:
                    limit = int(limit)
                except (ValueError, TypeError):
                    return tool_error("Invalid integer for limit")
                if limit > 200:
                    limit = 200
                elif limit < 1:
                    limit = 1
            try:
                res = run_search(args["query"], limit=limit, data_dir=self.data_dir)
                return tool_content(res)
            except Exception as exc:
                return tool_error(f"Error running ksm_search: {exc}")

        elif name == "ksm_show":
            cve = args.get("cve")
            if not cve or not isinstance(cve, str):
                return tool_error("Missing required string parameter 'cve'")
            project = args.get("project")
            try:
                res = run_show(cve, project=project, data_dir=self.data_dir)
                return tool_content(res)
            except Exception as exc:
                return tool_error(f"Error running ksm_show: {exc}")

        elif name == "ksm_related":
            cve = args.get("cve")
            if not cve or not isinstance(cve, str):
                return tool_error("Missing required string parameter 'cve'")
            project = args.get("project")
            try:
                res = run_related(cve, project=project, data_dir=self.data_dir)
                return tool_content(res)
            except Exception as exc:
                return tool_error(f"Error running ksm_related: {exc}")

        elif name == "ksm_audit":
            path = args.get("path")
            if not path or not isinstance(path, str):
                return tool_error("Missing required string parameter 'path'")
            try:
                res = run_audit(path, data_dir=self.data_dir)
                return tool_content(res)
            except Exception as exc:
                return tool_error(f"Error running ksm_audit: {exc}")

        elif name == "ksm_scan":
            path = args.get("path")
            if not path or not isinstance(path, str):
                return tool_error("Missing required string parameter 'path'")
            max_files = args.get("max_files")
            if max_files is not None:
                try:
                    max_files = int(max_files)
                except (ValueError, TypeError):
                    return tool_error("Invalid integer for max_files")
            try:
                res = run_scan(path, max_files=max_files, data_dir=self.data_dir)
                return tool_content(res)
            except Exception as exc:
                return tool_error(f"Error running ksm_scan: {exc}")

        elif name == "ksm_deps":
            deps_mod = get_deps_module()
            if not deps_mod:
                return tool_error(f"Unknown tool: {name}")
            path = args.get("path")
            if not path or not isinstance(path, str):
                return tool_error("Missing required string parameter 'path'")
            try:
                res = deps_mod.scan_dependencies(path, data_dir=self.data_dir)
                return tool_content(res)
            except Exception as exc:
                return tool_error(f"Error running ksm_deps: {exc}")

        else:
            return tool_error(f"Unknown tool: {name}")

    def handle_request(self, req: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Process a single JSON-RPC 2.0 request dictionary."""
        if not isinstance(req, dict):
            return jsonrpc_error(None, INVALID_REQUEST, "Invalid Request: expected JSON object")

        method = req.get("method")
        if not method or not isinstance(method, str):
            if "id" in req:
                return jsonrpc_error(req.get("id"), INVALID_REQUEST, "Invalid Request: missing method")
            return None

        # notifications/initialized receives no reply
        if method == "notifications/initialized":
            return None

        # Check if it is a notification (no id)
        if "id" not in req:
            return None

        req_id = req["id"]
        params = req.get("params")
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            if method != "ping" and method != "tools/list":
                return jsonrpc_error(req_id, INVALID_PARAMS, "Invalid params: expected object")

        if method == "initialize":
            res = self.handle_initialize(params if isinstance(params, dict) else {})
            return jsonrpc_result(req_id, res)
        elif method == "ping":
            res = self.handle_ping(params)
            return jsonrpc_result(req_id, res)
        elif method == "tools/list":
            res = self.handle_tools_list(params)
            return jsonrpc_result(req_id, res)
        elif method == "tools/call":
            if not isinstance(params, dict):
                return jsonrpc_error(req_id, INVALID_PARAMS, "Invalid params for tools/call")
            res = self.handle_tools_call(params)
            return jsonrpc_result(req_id, res)
        else:
            return jsonrpc_error(req_id, METHOD_NOT_FOUND, f"Method not found: {method}")

    def handle_line(self, line: str) -> Optional[str]:
        """Process a single newline-delimited line from stdio."""
        line = line.strip()
        if not line:
            return None

        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            return json.dumps(jsonrpc_error(None, PARSE_ERROR, "Parse error"))

        resp = self.handle_request(req)
        if resp is not None:
            return json.dumps(resp, ensure_ascii=False)
        return None


def run_server(
    data_dir: Optional[Union[str, Path]] = None,
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
) -> int:
    """Run the MCP server reading from stdin and writing to stdout."""
    in_stream = sys.stdin if stdin is None else stdin
    out_stream = sys.stdout if stdout is None else stdout

    server = MCPServer(data_dir=data_dir)
    for line in in_stream:
        out_line = server.handle_line(line)
        if out_line is not None:
            out_stream.write(out_line + "\n")
            out_stream.flush()
    return 0


def process_requests(
    requests: Union[Sequence[Union[dict[str, Any], str]], dict[str, Any], str],
    data_dir: Optional[Union[str, Path]] = None,
) -> list[dict[str, Any]]:
    """In-process driver for testing: takes request dicts/strings and returns response dicts."""
    if isinstance(requests, (dict, str)):
        requests = [requests]

    server = MCPServer(data_dir=data_dir)
    responses = []
    for req in requests:
        if isinstance(req, str):
            out_line = server.handle_line(req)
            if out_line is not None:
                responses.append(json.loads(out_line))
        elif isinstance(req, dict):
            resp = server.handle_request(req)
            if resp is not None:
                responses.append(resp)
    return responses
