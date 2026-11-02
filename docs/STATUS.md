# Status

Date: 2026-11-02 UTC (re-scored: progress records reconciled with delivered code).

## Measured state

| Area | Value | Source of truth |
|---|---|---|
| Evidence pack records | 35 (1 Linux seed + 34 vetted Fable records: git 8, nginx 2, openssh 8, sqlite 8, systemd 8) | `python3 scripts/build_pack.py --check` |
| CVE catalogs | 20 catalogs, 20,513 rows, 17,734 with a 40-hex fix SHA | `docs/studies/cve-history/manifest.json` |
| Upstream snapshot catalogs | `linux-cna` 17,337 rows (all with fix SHA, kernel CNA `vulns.git`); `curl-upstream` 215 (189 SHA); `openssl-upstream` 297 (169 SHA); OSV repo-scoped `git-upstream` 25 (10), `systemd-upstream` 60 (10), `sqlite-upstream` 62 (17), `postgres-upstream` 2 (2). For OSV rows `fix_shas` come only from FIX references; GIT `fixed` boundaries (often release stamps or merges) are kept separately as `fixed_in_shas`; FIX references that are merge commits (4 in systemd, checked against the committed `commit-parents.jsonl`) are demoted to `fixed_in_shas` | `fetch_kernel_cna_shas.py`, `fetch_upstream_advisories.py` |
| NVD keyword catalogs | 12, all `CURSOR_PAUSED` between 2000 and 2012; most rows of the 7 newer ones are unrelated products | `fetch_history_*.py` |
| CWE coverage | 9,617 of 18,424 clustered CVEs (52.2%) are `UNKNOWN` (was 97.6%): 468 CWEs stated by catalogs, 8,339 from the deterministic overlay (NVD 2.0 primary 7,920, CISA vulnrichment ADP 376, NVD secondary 43). The remainder are NVD/CISA `noinfo` or pre-2002 ids. 65 ids present in two catalogs are counted once | `docs/studies/cwe-overlay.jsonl`, `docs/studies/pattern_clusters.json` |
| Fix fragments | 35 pack records: 90 files, 97 functions (94 parsed, 3 `PARSER_SKIPPED`); line ranges and body hashes only, no code | `docs/studies/fragments/` |
| Agent guardrails | 10 CWE families, 18 rules, 28 repository-backed citations with source SHA-256 hashes; matches remain review hypotheses | `docs/skills/defensive-security-auditor/references/guardrails.md` |
| OSS Scanner integration | `scripts/oss_scanner/threat_model.py` writes an OSS-Scanner `threat_model.md` from a human context file plus KSM evidence; `enroll.py` writes `project.yaml` and validates it with the upstream `tools/validate.py`; selection manifest of the 23 enrolled projects (17 with OSV GIT data) | `docs/OSS-SCANNER.md`, `docs/studies/selection/oss-scanner-projects.json` |
| Vulnerability Atlas | Static UI (`site/`) over generated site data: 18,434 CVEs in 12 projects (evidence-pack CVEs missing from catalogs included), CWE names from MITRE, top-10 related CVEs per CVE by TF-IDF over shared metadata. `ksm` CLI (`pyproject.toml`). Before/after code is fetched live from GitHub | `scripts/site/build_site_data.py`, `ksm/` |
| Fix fingerprints | 1,423 fix commits: C upstream 397 (curl 189, OpenSSL 169, SQLite 17, git 10, systemd 10, PostgreSQL 2), RustSec 726, Linux kernel 300 (first weekly batch, newest first), 1 failed, produced by Xavier `code-graph fingerprint`; no source text. Matcher self-test over 905 before/after pairs: fixed versions flagged against their own pair 1.1%. Five old releases (27,948 functions): 43 of 47 strong findings (score >= 0.9) matched a later fix of the same project (curl 7.50.0 26/27, OpenSSL 1.0.1 12/15, git 2.0.0 5/5, systemd 230 and SQLite 3.8.0 none); 0 strong findings from other projects' fixes. Unit tests never match; a function deleted by its fix counts only when near-identical | `docs/studies/fingerprints/`, `scripts/fingerprints/evaluate_release.py` |
| Agent use | CLI (`ksm update/setup/doctor/deps/audit/scan/search/show/related`, all with `--json`), MCP server (`ksm mcp`, 7 tools), public skill `skills/ksm/SKILL.md`; no Xavier needed at run time. Acceptance on edge-hive by an agent given only the skill: completed install, readiness and all three checks unaided | `docs/design/AGENT-USE.md` |
| RustSec | 2,024 advisories (OSV crates.io export, GHSA twins folded), 727 link a commit; 726 fingerprinted (`fix_evidence: advisory-commit-link`, not verified fixes) | `docs/studies/cve-history/rustsec/` |
| Public use | Pages deployed by `pages.yml` (site, data, `bundle.tar.gz`, legacy `/memory` and `/schemas`); release `code-graph-229aa969` (Linux x86_64 binary + sha256). Fresh public install (`uv tool install git+...`, `ksm update`, `ksm setup`, `ksm doctor`) ready with no local files. Scans 2026-10-11: edge-hive 149 dependency advisories in 66 packages, 3 audit findings, 0 strong scan findings; xavier 24 advisories in 23 packages, 14 audit findings, 0 strong | release `code-graph-229aa969` |
| Tests | 975 run, 4 skipped (live-network smoke tests) | `python3 -m unittest discover -s tests -p "test_*.py"` |

## Implemented

Evidence schema and deterministic JSON/SQL pack; read-only lexical+graph pack reader; honest catalog states (`NOT_FETCHED`, `CURSOR_PAUSED`, `SNAPSHOT_COMPLETE`); fix-SHA resolution from the kernel CNA, OSV and project advisory feeds; git-mirror SHA verification; heuristic C function-fragment miner with explicit `PARSER_SKIPPED` / `INCOMPLETE` coverage; CWE pattern clusters and typed SQLite graph; defensive auditor with a reproducible evidence hash and a publication quality gate (Rust memory rules fire only inside `unsafe` code); Fable-to-pack converter backed by cached GitHub commit metadata; `scripts/studies/refresh_all.py` plus a weekly workflow that proposes catalog refreshes as a pull request.

No LLM is used anywhere in extraction or enrichment.

## ADR-001 retrieval measurement (2026-11-02)

[Measured comparison](../experiments/ADR001-MEASURED.md): four stdlib retrieval
strategies over the actual 35-record SQL pack, pinned corpus/qrels hashes and
per-query artifacts. qrels-v2 is absent on this branch (W1c dependency); v1
provides four lexical positives, two separate graph probes and three negatives.
All four strategies tie: Recall@5/MRR/citation completeness = 1.0 on lexical
positives; negative abstention = 2/3. ADR-001 stays **PROPOSED** because the
simpler lexical baseline matches. Vector/LLM strategies are **NOT_RUN**.
Single-fix, non-independent labels do not establish general retrieval quality.

## Known limits

- Independent qrels review workflow and stdlib checker are implemented (see
  [review process](REVIEW-PROCESS.md)); the nine v1 judgments still lack reviewer
  metadata, so no paired-review kappa is available and labels remain exploratory.

- NVD keyword search is a weak source: slow (one request per 15 s without a key) and polluted. Per-project upstream feeds are the primary source from now on.
- Pack records keep `status=unknown` and `evolution=UNKNOWN`; pattern families and lessons are hypotheses.
- Raw upstream snapshots and the OSV cache are local, gitignored caches (they contain third-party advisory text, see `DATA-POLICY.md`); `index.json` pins their URL and sha256.
- No official machine-readable feed found for openssh, nginx, qemu, unbound and glibc; they rely on NVD keyword catalogs only.
- `--offline --check` of snapshot catalogs, the CWE overlay and fragments needs their gitignored local caches; CI recomputes from the network.
- Kernel test fixtures under `tests/fixtures/` are GPL-2.0-only excerpts carrying SPDX and provenance headers.
- "Related CVEs" vectors are deterministic TF-IDF over metadata and fingerprint features, not neural embeddings. Until more CVEs carry fingerprints, most neighbours share only CWE and project.
- Fingerprint matching finds missing patches within a project; across projects it raised no strong finding in 27,948 functions, so it neither produces noise nor, yet, finds the same bug in unrelated code. systemd and SQLite releases produced no strong finding (few fingerprinted fixes: 10 and 17).
- Local patch evolution miner: `scripts/mine_evolution.py` emits sourced follow-up candidates and explicit revert/backport edges from bounded local Git history. Coverage remains partial; it does not establish patch stability or scan external reviews/tests.
- Not implemented: neural embeddings, whole-kernel evolution scans, native Xavier mount/unmount.

## Top-20 Projects Dataset
- **Curated Dataset:** Developed `docs/studies/top20/` containing the top 20 open-source projects dataset, tracking declared CVEs, patched commits, and follow-up evolution.
- **Components:** includes methodology (`README.md`), project metadata (`projects.json`), consolidated lessons (`lessons.md`), and agent skill files (`skills/`).
- **Test suite validation:** added `tests/test_top20.py` to ensure schema constraints, project count, and citation standards are met.
