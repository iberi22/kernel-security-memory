# Status

Date: 2026-10-09 UTC.

## Measured state

| Area | Value | Source of truth |
|---|---|---|
| Evidence pack records | 35 (1 Linux seed + 34 vetted Fable records: git 8, nginx 2, openssh 8, sqlite 8, systemd 8) | `python3 scripts/build_pack.py --check` |
| CVE catalogs | 15 catalogs, 18,340 rows, 17,696 with a 40-hex fix SHA | `docs/studies/cve-history/manifest.json` |
| Upstream snapshot catalogs | `linux-cna` 17,337 rows (all with fix SHA, kernel CNA `vulns.git`); `curl-upstream` 215 (189 SHA, 215 CWE); `openssl-upstream` 297 (169 SHA, 74 CWE) | `fetch_kernel_cna_shas.py`, `fetch_upstream_advisories.py` |
| NVD keyword catalogs | 12, all `CURSOR_PAUSED` between 2000 and 2012; most rows of the 7 newer ones are unrelated products | `fetch_history_*.py` |
| CWE coverage | 17,834 of 18,275 clustered CVEs (97.6%) are `UNKNOWN`; all 17,337 `linux-cna` rows lack a CWE because the kernel CNA publishes none. 65 ids present in two catalogs are counted once | `docs/studies/pattern_clusters.json` |
| Tests | 508 run, 2 skipped (one live-network smoke test, one that needs the local OSV cache) | `python3 -m unittest discover -s tests -p "test_*.py"` |

## Implemented

Evidence schema and deterministic JSON/SQL pack; read-only lexical+graph pack reader; honest catalog states (`NOT_FETCHED`, `CURSOR_PAUSED`, `SNAPSHOT_COMPLETE`); fix-SHA resolution from the kernel CNA, OSV and project advisory feeds; git-mirror SHA verification; heuristic C function-fragment miner with explicit `PARSER_SKIPPED` / `INCOMPLETE` coverage; CWE pattern clusters and typed SQLite graph; defensive auditor with a reproducible evidence hash and a publication quality gate; Fable-to-pack converter backed by cached GitHub commit metadata; `scripts/studies/refresh_all.py` plus a weekly workflow that proposes catalog refreshes as a pull request.

No LLM is used anywhere in extraction or enrichment.

## Known limits

- NVD keyword search is a weak source: slow (one request per 15 s without a key) and polluted. Per-project upstream feeds are the primary source from now on.
- Pack records keep `status=unknown` and `evolution=UNKNOWN`; pattern families and lessons are hypotheses.
- Raw upstream snapshots and the OSV cache are local, gitignored caches (they contain third-party advisory text, see `DATA-POLICY.md`); `index.json` pins their URL and sha256.
- Fetcher defects still open: the Linux NVD fetcher can rewind its cursor when `resume` is null and does not stop on `COMPLETE`; `window.end` is fixed at 2026-10-08; catalogs are written non-atomically; a recorded network error blocks resume until cleared (unbound).
- Not implemented: embeddings, follow-up/revert tracking, native Xavier mount/unmount, CWE assignment for CNA rows.
