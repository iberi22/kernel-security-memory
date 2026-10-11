# Vulnerability Atlas — design (v1)

Goal: make the KSM corpus navigable by people (a static GitHub Pages UI) and by
agents (a local `ksm` CLI and Xavier), and recognise vulnerable code structures in
other repositories. Everything is built by GitHub Actions. No LLM anywhere: every
number, link and similarity score is computed by deterministic code.

```
catalogs + CWE overlay + fragments            (existing, committed)
        │
        ├─► fingerprints workflow ──► docs/studies/fingerprints/   (code-graph, hashes + identifiers, no code)
        │
        └─► build_site_data.py ──► site data (JSON shards, related-CVE vectors, bundle.tar.gz)
                    │
                    ├─► pages workflow ──► GitHub Pages UI (site/)
                    └─► `ksm` CLI (ksm update downloads the bundle; ksm scan runs code-graph + matcher)
```

## 1. Structural fingerprint `ksm-sfp/1` (producer: Xavier `code-graph fingerprint`)

One implementation only: Xavier's `code-graph` (tree-sitter). KSM never parses
code itself for fingerprints; the CI and the CLI call the binary.

```
code-graph fingerprint <FILE> [--lang c|cpp|rust|python|go|java|typescript|javascript]
                              [--ranges 10-50,80-120]
```

- `--lang` defaults to detection by extension.
- Without `--ranges`: every function in the file. With `--ranges`: only functions
  whose `[start_line, end_line]` overlaps at least one range (1-based, inclusive).
- Output: one JSON document on stdout, keys sorted, UTF-8, exit 0. Unsupported
  language or parse failure: exit 0 with `"coverage": "PARSER_SKIPPED"` and
  `"functions": []`. Unreadable file: exit 2.

```json
{
  "schema": "ksm-sfp/1",
  "tool": "code-graph <crate version>",
  "file": "<path as given>",
  "language": "c",
  "coverage": "OK",
  "functions": [
    {
      "name": "clone_submodule",
      "start_line": 1644,
      "end_line": 1760,
      "node_count": 812,
      "kgrams": {"3fa1c2d0": 4, "...": 1},
      "minhash": [123, 456, "... 64 unsigned 32-bit ints"],
      "calls": [{"callee": "memcpy", "line": 1702, "args": ["dst", "src", "len"]}],
      "guards": [{"kind": "if", "line": 1699, "vars": ["len", "max"]}],
      "vars": [{"name": "len", "lines": [1650, 1699, 1702]}]
    }
  ]
}
```

Definitions (normative; tests pin them with golden files):

- **Function nodes** per grammar: C/C++ `function_definition`; Rust `function_item`;
  Python `function_definition`; Go `function_declaration`, `method_declaration`;
  Java `method_declaration`, `constructor_declaration`; TS/JS
  `function_declaration`, `method_definition`, `arrow_function` and
  `function_expression` when bound to a name. Nested functions are reported as
  their own entries and are also part of the parent's token stream.
- **Token stream**: pre-order walk over *named* nodes of the function. Token = node
  kind, except:
  - identifier-like leaves (`identifier`, `field_identifier`, `type_identifier`,
    `property_identifier`, `shorthand_property_identifier`) → `id`;
  - numeric literals → `num`; string/char literals → `str` (children skipped);
  - comments are skipped;
  - a call's callee → `call:<name>` (see `calls`), callee subtree skipped;
  - binary/assignment/update expressions → `<kind>:<operator text>`
    (e.g. `binary_expression:<`, `assignment_expression:+=`).
- **kgrams**: every window of 3 consecutive tokens, joined with `\x1f`; key =
  first 8 hex chars of SHA-256 of the UTF-8 join; value = count. Functions with
  fewer than 3 tokens use one window with all of them.
- **minhash**: 64 values; `minhash[i] = min over kgram keys k of
  int(sha256(f"{i}:{k}")[:8], 16)`; empty kgrams → 64 × `4294967295`.
- **calls**: every call expression in source order. `callee` = last name segment
  (`a->b` → `b`, `a::b::c` → `c`, `obj.m` → `m`, `free` → `free`). `args` = per
  argument the first identifier found in pre-order, or `""` when none.
- **guards**: conditions of `if`, `while`, `for`, `do` and ternary expressions, and
  Rust `if let`/`match` scrutinees. `vars` = distinct identifiers in the condition,
  sorted. `kind` = `if|while|for|do|ternary|match`.
- **vars**: distinct identifiers (not callee names) with every line they occur on.
- `node_count`: number of named nodes in the function.

Fingerprints contain hashes, function/variable/callee names and line numbers. They
never contain source text, so they may be committed (see `DATA-POLICY.md`).

## 2. Fix fingerprints `ksm-fixfp/1` (producer: KSM CI)

`scripts/fingerprints/build_fix_fingerprints.py` runs in the fingerprints workflow:

1. Candidates: catalog rows with `fix_shas`, ordered pack records → upstream
   catalogs (curl, openssl, git, sqlite, systemd, postgres) → `linux-cna`
   (newest first). One fix SHA per CVE per run; resumable via
   `docs/studies/fingerprints/index.json` (`done`, `failed` with reason).
2. Per commit, `GET https://api.github.com/repos/{repo}/commits/{sha}`
   (token from `GITHUB_TOKEN`): parent SHA, changed files, patch hunks → changed line
   ranges on the old side and on the new side.
3. For each changed source file in a supported language, download the parent and the
   fix version from `raw.githubusercontent.com` into a temporary directory
   (deleted after use, never committed), run `code-graph fingerprint --ranges`
   on each side, pair functions by name.
4. Write `docs/studies/fingerprints/<project>/<CVE>.json`:

```json
{
  "schema": "ksm-fixfp/1",
  "advisory_id": "CVE-2023-38545",
  "project": "curl",
  "repo": "curl/curl",
  "fix_sha": "<40 hex>",
  "parent_sha": "<40 hex>",
  "cwe": "CWE-787",
  "tool": "code-graph@<xavier commit>",
  "coverage": "OK|PARTIAL|PARSER_SKIPPED|FETCH_FAILED",
  "files": [
    {
      "path": "lib/socks.c",
      "language": "c",
      "functions": [
        {
          "name": "do_SOCKS5",
          "before": "<sfp function object or null>",
          "after": "<sfp function object or null>",
          "delta": {
            "added_kgrams": {"<hex8>": 2},
            "removed_kgrams": {"<hex8>": 1},
            "added_calls": ["strlen"],
            "removed_calls": [],
            "added_guards": [{"kind": "if", "vars": ["hostname_len"]}]
          }
        }
      ]
    }
  ]
}
```

Repo map: `linux`/`linux-cna` → `torvalds/linux` (fallback `gregkh/linux` for
stable-only SHAs), `curl` → `curl/curl`, `openssl` → `openssl/openssl`, `git` →
`git/git`, `sqlite` → `sqlite/sqlite`, `systemd` → `systemd/systemd`, `postgres` →
`postgres/postgres`. Budget per run: `--max-commits` (default 300).

## 3. Matcher (`ksm scan`)

Input: target `ksm-sfp/1` documents (from `code-graph fingerprint` over a local
repo) and the fix-fingerprint corpus. Per target function T and corpus pair
(B = before, A = after, Δ):

1. Candidates: MinHash LSH, 16 bands × 4 rows; keep pairs whose estimated Jaccard
   with B ≥ 0.3.
2. `s_b = cos(T.kgrams, B.kgrams)`, `s_a = cos(T.kgrams, A.kgrams)` (count vectors).
3. **Structural hit**: `s_b ≥ 0.55` and `s_b ≥ s_a + 0.05` (T looks more like the
   vulnerable version than the fixed one).
4. **Missing-guard hit**: for every call in T whose callee is in B's calls and for
   which Δ added a guard on the variable passed at the same argument position in B,
   check whether T has a guard on its own argument variable at a line before the
   call. If not, report the call line and the variable.
5. Score = `s_b - max(0, s_a - s_b)`, plus 0.1 per missing-guard hit (cap 1.0).

Report item (JSON and Markdown): file, function, line range, lines to review
(call lines, unguarded variables), matched CVE(s) with project, CWE, fix commit URL,
score, the reasons in plain words ("fix added a check on `len` before `memcpy`;
this function calls `memcpy(buf, p, n)` with no check on `n`"). Findings are
hypotheses to review, never verdicts.

Self-test metric reported in CI: share of corpus *after* functions that the matcher
flags against their own CVE (should be 0) and share of *before* functions it finds
(recall on the corpus). Thresholds change only with these numbers.

## 4. Related CVEs ("vectors") — deterministic

Each CVE gets a sparse feature vector; TF-IDF weights; cosine similarity; top 10
neighbours with the shared features as the explanation.

| Feature | Example | Weight |
|---|---|---|
| CWE | `cwe:CWE-787` | 3 |
| CWE family (pattern cluster) | `fam:memory-bounds` | 2 |
| Project | `proj:curl` | 1 |
| Subsystem / top directory | `sub:net` | 2 |
| File path tokens | `path:socks` | 1 |
| Function names touched | `fn:do_socks5` | 3 |
| Callees added/removed by the fix | `fixcall:strlen` | 2 |
| Structural kgrams of the fixed functions | `kg:3fa1c2d0` | 1 |

Candidate neighbours come from an inverted index (features with document frequency
above 5% are ignored for candidate generation). The same vectors are exported as
`vectors.jsonl` (`{"id", "features": {name: weight}}`) for Xavier.

## 5. Site data (producer: `scripts/site/build_site_data.py`)

Output directory (gitignored, built in CI) `site/data/`:

- `index.json`: build meta (KSM commit, generated UTC, counts), projects with CVE,
  fix-SHA, fragment and fingerprint counts, CWE tree (family → CWE → project → count).
- `cwe/<CWE-ID or UNKNOWN>.json`: compact rows `[id, project, published, has_fix,
  has_fragments, has_fingerprint]`.
- `cve/<project>/<CVE>.json`: full detail: catalog row, CWE name and source, fix
  commits with GitHub repo, fragments (files, functions, ranges, blob SHAs), fix
  fingerprint summary (functions, added guards/calls), related CVEs with reasons.
- `search.json`: `[id, project, cwe, subsystem, function names]` per CVE.
- `vectors.jsonl`, `bundle.tar.gz` (+ `bundle.sha256`): everything above plus the
  fingerprint corpus, pattern clusters and guardrails, for the CLI.

### 5.1 Exact shapes

`index.json`:
```json
{"schema": "ksm-site/1", "ksm_commit": "<sha>", "generated": "<ISO-8601>",
 "totals": {"cves": 0, "with_fix": 0, "with_fragments": 0, "with_fingerprint": 0, "projects": 0},
 "projects": [{"name": "curl", "repo": "curl/curl", "catalogs": ["curl", "curl-upstream"],
               "cves": 0, "with_fix": 0, "with_fragments": 0, "with_fingerprint": 0,
               "years": {"2023": 4}}],
 "groups": [{"name": "Memory safety", "cves": 0,
             "cwes": [{"id": "CWE-787", "name": "Out-of-bounds Write", "cves": 0,
                       "projects": {"curl": 3, "linux": 120}}]}]}
```
Group names: Memory safety, Resource management, Concurrency, Injection, Input
validation and paths, Access control and crypto, Information exposure, Logic and
numeric errors, Other, Unknown. CWE `UNKNOWN` lives in group Unknown.

`cwe/<CWE-ID>.json`: `{"id", "name", "group", "rows": [[advisory_id, project, published|null, has_fix, has_fragments, has_fingerprint], ...]}` sorted by published desc then id.

`cve/<project>/<CVE>.json`:
```json
{"id": "CVE-2023-38545", "project": "curl", "repo": "curl/curl",
 "published": "2023-10-11", "cwe": "CWE-787", "cwe_name": "Out-of-bounds Write",
 "cwe_source": "catalog|nvd-primary|cisa-vulnrichment|nvd-secondary|null", "group": "Memory safety",
 "subsystem": null, "catalogs": ["curl-upstream"], "patch_urls": ["https://..."],
 "fixes": [{"sha": "<40 hex>", "url": "https://github.com/curl/curl/commit/<sha>"}],
 "fragments": {"coverage": "OK", "files": [{"path": "lib/socks.c", "language": "c",
               "before_blob_sha": "..", "after_blob_sha": "..", "status": "modified",
               "functions": [{"name": "do_SOCKS5", "before_range": [1, 2], "after_range": [1, 3],
                              "lines_added": 3, "lines_removed": 1}]}]} ,
 "fingerprint": {"fix_sha": "..", "parent_sha": "..", "functions": [{"path": "lib/socks.c",
                 "name": "do_SOCKS5", "added_calls": [], "removed_calls": [],
                 "added_guards": [{"kind": "if", "vars": ["len"]}]}]},
 "related": [{"id": "CVE-..", "project": "..", "score": 0.42, "shared": ["cwe:CWE-787", "fn:do_socks5"]}]}
```
`fragments` and `fingerprint` are `null` when absent. Fixes from linux use
`https://git.kernel.org/linus/<sha>` as `url` and repo `torvalds/linux` for the API.

`search.json`: `[[advisory_id, project, cwe|null, subsystem|null, "fn1 fn2"], ...]`.

## 6. UI (`site/`, static, no build step)

Vanilla HTML/CSS/ES modules. Hash router: `#/`, `#/cwe/<id>`, `#/project/<name>`,
`#/cve/<project>/<id>`, `#/search?q=`.

- Home: per-project coverage table, CWE distribution, how to read the data.
- Left tree: CWE family → CWE → project → CVE (switchable to project-first), lazy
  loaded from the shards.
- CVE page: metadata and source links (NVD, advisory, fix commit), files and
  functions changed with before/after line ranges, "what the fix changed"
  (added guards and calls), related CVEs with reason chips, small SVG neighbour graph.
- Before/after code: fetched live in the browser from GitHub
  (`api.github.com/repos/{repo}/commits/{sha}` for the patch,
  `raw.githubusercontent.com/{repo}/{sha}/{path}` for the two versions, sliced to the
  function range). Code is shown, never stored by KSM. Unauthenticated limit
  (60 API calls/hour) is shown when hit; raw downloads are not API-limited.

## 7. CLI (`ksm`, Python stdlib, `pipx install git+https://github.com/iberi22/kernel-security-memory`)

```
ksm update                 download bundle.tar.gz from Pages, verify sha256
ksm stats | tree [--by cwe|project] | show CVE | related CVE | search QUERY
ksm audit PATH             regex auditor (scripts/defensive_auditor.py)
ksm scan PATH [--json]     code-graph fingerprint on supported files + matcher report
```

Data lookup order: `--data-dir`, `$KSM_DATA`, the repo checkout's `site/data`,
`$XDG_DATA_HOME/ksm`. `ksm scan` needs `code-graph` on `PATH` (or `$KSM_CODE_GRAPH`);
the release workflow attaches a Linux build.

## 8. Workflows

- `fingerprints.yml` (weekly + manual): build `code-graph` at the pinned Xavier
  commit (cached), run `build_fix_fingerprints.py --max-commits 300`, run the matcher
  self-test, open a PR with the new fingerprints (same pattern as
  `refresh-catalogs.yml`).
- `pages.yml` (push to main + manual): `build_site_data.py`, upload `site/` + data,
  deploy with `actions/deploy-pages`.
- All jobs: `permissions: {}` at top level, least privilege per job.

## 9. Xavier

`code-graph fingerprint` lives in Xavier and is usable there directly. Next step
(separate change): a Xavier MCP tool that loads the KSM bundle and runs the matcher
on the indexed project.
