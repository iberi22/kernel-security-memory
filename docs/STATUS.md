# Status

Date: 2026-10-10 UTC.

## Measured state

| Area | Value | Source of truth |
|---|---|---|
| Evidence pack records | 35 (1 Linux seed + 34 vetted Fable records: git 8, nginx 2, openssh 8, sqlite 8, systemd 8) | `python3 scripts/build_pack.py --check` |
| CVE catalogs | 19 catalogs, 18,489 rows, 17,736 with a 40-hex fix SHA | `docs/studies/cve-history/manifest.json` |
| Upstream snapshot catalogs | `linux-cna` 17,337 rows (all with fix SHA, kernel CNA `vulns.git`); `curl-upstream` 215 (189 SHA); `openssl-upstream` 297 (169 SHA); OSV repo-scoped `git-upstream` 25 (10), `systemd-upstream` 60 (12), `sqlite-upstream` 62 (17), `postgres-upstream` 2 (2). For OSV rows `fix_shas` come only from FIX references; GIT `fixed` boundaries (often release stamps or merges) are kept separately as `fixed_in_shas` | `fetch_kernel_cna_shas.py`, `fetch_upstream_advisories.py` |
| NVD keyword catalogs | 12, all `CURSOR_PAUSED` between 2000 and 2012; most rows of the 7 newer ones are unrelated products | `fetch_history_*.py` |
| CWE coverage | 9,617 of 18,424 clustered CVEs (52.2%) are `UNKNOWN` (was 97.6%): 468 CWEs stated by catalogs, 8,339 from the deterministic overlay (NVD 2.0 primary 7,920, CISA vulnrichment ADP 376, NVD secondary 43). The remainder are NVD/CISA `noinfo` or pre-2002 ids. 65 ids present in two catalogs are counted once | `docs/studies/cwe-overlay.jsonl`, `docs/studies/pattern_clusters.json` |
| Fix fragments | 35 pack records: 90 files, 97 functions (94 parsed, 3 `PARSER_SKIPPED`); line ranges and body hashes only, no code | `docs/studies/fragments/` |
| Agent guardrails | 6 CWE families, 16 citations, every fix commit verified upstream | `docs/skills/defensive-security-auditor/references/guardrails.md` |
| Tests | 635 run, 1 skipped (live-network smoke test) | `python3 -m unittest discover -s tests -p "test_*.py"` |

## Implemented

Evidence schema and deterministic JSON/SQL pack; read-only lexical+graph pack reader; honest catalog states (`NOT_FETCHED`, `CURSOR_PAUSED`, `SNAPSHOT_COMPLETE`); fix-SHA resolution from the kernel CNA, OSV and project advisory feeds; git-mirror SHA verification; heuristic C function-fragment miner with explicit `PARSER_SKIPPED` / `INCOMPLETE` coverage; CWE pattern clusters and typed SQLite graph; defensive auditor with a reproducible evidence hash and a publication quality gate; Fable-to-pack converter backed by cached GitHub commit metadata; `scripts/studies/refresh_all.py` plus a weekly workflow that proposes catalog refreshes as a pull request.

No LLM is used anywhere in extraction or enrichment.

## Known limits

- NVD keyword search is a weak source: slow (one request per 15 s without a key) and polluted. Per-project upstream feeds are the primary source from now on.
- Pack records keep `status=unknown` and `evolution=UNKNOWN`; pattern families and lessons are hypotheses.
- Raw upstream snapshots and the OSV cache are local, gitignored caches (they contain third-party advisory text, see `DATA-POLICY.md`); `index.json` pins their URL and sha256.
- No official machine-readable feed found for openssh, nginx, qemu, unbound and glibc; they rely on NVD keyword catalogs only.
- `--offline --check` of snapshot catalogs, the CWE overlay and fragments needs their gitignored local caches; CI recomputes from the network.
- Kernel test fixtures under `tests/fixtures/` are GPL-2.0-only excerpts carrying SPDX and provenance headers.
- Not implemented: embeddings, follow-up/revert tracking, native Xavier mount/unmount.
