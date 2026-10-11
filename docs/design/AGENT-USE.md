# Using KSM from any agent (no Xavier required)

KSM was built next to Xavier (SWAL's memory service). This note records which
parts depended on it, and how every capability is reachable by any LLM or agent
through public, stdlib-only tools.

## Coupling found (2026-10-11)

| Part | Xavier dependency | Resolution |
|---|---|---|
| `ksm scan` | needs `code-graph`, built from the Xavier repo | `ksm setup` installs a prebuilt binary from this repo's releases (sha256-checked); `--from-cargo` builds it; Xavier itself is never needed at run time |
| `scripts/quality_gate.py` | wording and default target were "Xavier publication" | store-agnostic wording; same flags and JSON keys |
| `scripts/pack_to_xavier.py` | publishes to Xavier | stays as one optional adapter; nothing else imports it |
| Skill `defensive-security-auditor` | written for SWAL agents | generic skill `skills/ksm/SKILL.md` for any agent; the auditor skill stays as the deep reference |
| Docs (`XAVIER-BRIDGE.md`, `PORTABLE-MEMORY.md`) | describe the Xavier bridge | kept, marked optional |

Everything else (catalogs, site data, UI, matcher, CLI, workflows) never needed
Xavier.

## Interfaces for agents

| Interface | Use when | Entry point |
|---|---|---|
| CLI with `--json` | the agent can run shell commands | `ksm update`, `ksm setup`, `ksm doctor`, `ksm deps`, `ksm audit`, `ksm scan`, `ksm search`, `ksm show`, `ksm related` |
| MCP server (stdio) | the agent speaks MCP (Claude Code, Codex, Gemini CLI, ...) | `ksm mcp`; see `docs/MCP.md` |
| Skill | the agent loads `SKILL.md` files | `skills/ksm/SKILL.md` |
| Static data | no install at all | `https://iberi22.github.io/kernel-security-memory/data/` (JSON shards, `bundle.tar.gz`) |

All outputs are deterministic, computed from official advisories and fix
commits; no model writes any of them. Findings are hypotheses for a person or
agent to review.

## What each check answers

| Command | Question | Data |
|---|---|---|
| `ksm deps PATH` | which locked dependencies have a published advisory, and the first fixed version | OSV (RustSec, GHSA, PyPA, Go, npm), live query with a local cache |
| `ksm audit PATH` | which lines match known dangerous patterns (regex rules per CWE family) | rules in `scripts/defensive_auditor.py`, guardrails with verified fix citations |
| `ksm scan PATH` | which functions look like the vulnerable side of a known fix, or miss a check a fix added | fix fingerprints (C upstream projects, RustSec crates) |
| `ksm search/show/related` | what is known about a CVE, its fix and similar CVEs | site data bundle |

## Acceptance test

Run on `iberi22/edge-hive` (Rust workspace plus a TypeScript admin UI), read-only,
2026-10-11:

- An agent (Gemini 3.8 flash, low effort) given only `skills/ksm/SKILL.md`, a fresh
  install and an empty data dir ran `ksm update`, `ksm setup` (the release binary
  was not published yet: 404, then it used the `--from-cargo` fallback the tool
  printed), `ksm doctor` (ready), then `deps`, `audit` and `scan` with `--json`,
  read the top findings in the code and wrote a report in the skill's template.
  No step needed help.
- `ksm deps` on the working tree: 176 advisories in 74 locked packages
  (Cargo.lock 120, edge-hive-admin/src-tauri/Cargo.lock 18, edge-hive-admin/package-lock.json 38),
  e.g. wasmtime 41.0.4 RUSTSEC-2026-0085 (fixed in 42.0.2), checked against
  api.osv.dev directly. The repository ignores `Cargo.lock` in `.gitignore`, so a
  clean clone exposes only the npm lockfile: commit `Cargo.lock` for applications.
- `ksm audit`: 3 findings in shell scripts; the agent judged
  `scripts/sync-issues.sh:131` (`eval $cmd` with a title read from markdown
  front matter) a real injection risk with low exposure, the other two safe.
- `ksm scan` with 726 RustSec fix fingerprints: 0 strong, 24 weak findings
  (none confirmed). Rust coverage is new; strong matches need code derived from a
  fixed crate.
- The MCP server answered `initialize`, `tools/list` (7 tools) and `ksm_deps`
  (176 findings) over stdio.
