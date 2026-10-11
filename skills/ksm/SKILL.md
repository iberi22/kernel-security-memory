---
name: ksm
description: Check a code repository against known vulnerabilities with Kernel Security Memory (KSM) — vulnerable locked dependencies (OSV), dangerous code patterns (regex rules per CWE), and functions that resemble the vulnerable side of real fixes (structural fingerprints). Use before merging security-sensitive changes, when auditing a repo, or to look up a CVE, its fix commit and related CVEs. Deterministic; findings are hypotheses to review, not verdicts.
---

# KSM: known-vulnerability checks for a repository

## Install (once)

```bash
pipx install git+https://github.com/iberi22/kernel-security-memory   # or: uv tool install git+...
ksm update     # CVE data bundle (~5 MB)
ksm setup      # code-graph scanner binary, Linux x86_64 (needed only by `ksm scan`)
ksm doctor     # prints what is ready; exit 0 when all is
```

No account, API key or model is needed. `ksm deps` queries api.osv.dev; everything else is local.

## Check a repository

Run from anywhere; PATH is the repository root. Always prefer `--json` and read the fields.

```bash
ksm deps PATH --json    # locked deps with advisories: package, version, advisory id, aliases, fixed version
ksm audit PATH --json   # regex findings: file, line, rule id, CWE, severity
ksm scan PATH --json    # fingerprint findings: file, function, lines, variable, matched CVE, fix commit, score
```

Exit codes: 0 ok, 1 findings with `--strict`, 2 usage or missing data (the message says what to run).

## Read the results

- `deps`: a finding is real when the installed version is in the advisory's affected range. Report the
  fixed version; propose the upgrade, do not edit lockfiles by hand.
- `audit`: pattern matches. Open the line and judge it; many are safe in context.
- `scan`: `score >= 0.9` is strong. Strong findings mean the function looks like the vulnerable version of
  a known fix (most useful for code derived from that project) or calls a function without a check that the
  fix added (`lines[].variable`, `lines[].callee`). Open `matches[].commit_url` to see the real fix.
- Never claim a vulnerability from KSM output alone. Say "KSM flags ... because ..." and verify in code.

## Look up a CVE

```bash
ksm search openssl            # ids by project, CWE, subsystem, function name, alias
ksm show CVE-2016-8619 --json # CWE, fix commits, functions changed, what the fix changed
ksm related CVE-2016-8619     # similar CVEs and the shared features
```

Browse the same data at https://iberi22.github.io/kernel-security-memory/.

## MCP

If your client speaks MCP: `ksm mcp` (stdio). Tools: `ksm_stats`, `ksm_search`, `ksm_show`, `ksm_related`,
`ksm_audit`, `ksm_scan`, `ksm_deps`. Registration examples: `docs/MCP.md` in the repository.

## Report template

```
KSM check of <repo> at <commit>:
- deps: <n> advisories in <m> packages (<list: package version -> fixed version, id>)
- audit: <n> pattern findings (<top rule ids>), reviewed: <which are real>
- scan: <n> strong / <m> weak fingerprint findings (<function: matched CVE>), reviewed: <...>
Limits: findings are hypotheses; scan coverage is C upstream projects and RustSec crates.
```
