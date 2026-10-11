# KSM Model Context Protocol (MCP) Server

The `ksm mcp` command runs a Model Context Protocol (MCP) server over standard input and output (stdio), communicating via JSON-RPC 2.0. This allows AI assistants and coding agents (Claude Code, OpenAI Codex, Gemini CLI, Cursor, Windsurf, etc.) to query KSM vulnerability data, search indices, code pattern audits, and fingerprint scans directly.

## Protocol Specification

- **Transport**: stdio (newline-delimited JSON-RPC 2.0 messages).
- **Protocol Versions**: Negotiates `2025-06-18` (default) and accepts legacy `2024-11-05`.
- **Standard Streams**: Only valid JSON-RPC protocol responses are printed to `stdout`. All logs, diagnostics, and warnings are emitted to `stderr`.

## Client Configuration

### Claude Code

Register KSM in Claude Code via CLI:

```bash
claude mcp add ksm -- ksm mcp
```

Or with an explicit data directory:

```bash
claude mcp add ksm -- ksm mcp --data-dir /path/to/ksm/data
```

### OpenAI Codex CLI / Desktop

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.ksm]
command = "ksm"
args = ["mcp"]
```

Or with an explicit data directory:

```toml
[mcp_servers.ksm]
command = "ksm"
args = ["mcp", "--data-dir", "/path/to/ksm/data"]
```

### Gemini CLI & Generic Clients

Configure via the client's MCP configuration file (e.g. `mcpServers` JSON block):

```json
{
  "mcpServers": {
    "ksm": {
      "command": "ksm",
      "args": ["mcp"]
    }
  }
}
```

Or when passing a custom data directory:

```json
{
  "mcpServers": {
    "ksm": {
      "command": "ksm",
      "args": ["mcp", "--data-dir", "/path/to/ksm/data"]
    }
  }
}
```

## Available Tools

The server implements the standard MCP `tools/list` and `tools/call` methods:

| Tool | Parameters | Description |
|---|---|---|
| `ksm_stats` | `{}` | Returns index totals and per-project statistics. |
| `ksm_search` | `{"query": string, "limit"?: int <= 200}` | Searches `search.json` across CVE IDs, projects, CWEs, subsystems, and function names. |
| `ksm_show` | `{"cve": string, "project"?: string}` | Retrieves detailed advisory JSON for a CVE (auto-detects owning project if omitted). |
| `ksm_related` | `{"cve": string, "project"?: string}` | Returns related CVEs sharing features and similarity scores. |
| `ksm_audit` | `{"path": string}` | Runs the defensive regex pattern auditor on the target file or directory and returns the evidence chain. |
| `ksm_scan` | `{"path": string, "max_files"?: int}` | Scans source files with Xavier `code-graph` and matches against fix fingerprints. |
| `ksm_deps` | `{"path": string}` | Locked dependencies with published advisories (OSV); needs network on the first query, then uses the local cache. |
