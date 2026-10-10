# Roadmap

| Stage | Deliverable | Current state (2026-10-09) |
|---|---|---|
| 0 | Public docs, evidence contract, JSON/SQL packaging | Done |
| 1 | Remote seven-method sensitivity + retrieval smoke | Dispatched to Jules; no measured ranking yet |
| 2 | Official CNA ingestion and scoped history miners | Done for the Linux kernel CNA, curl and OpenSSL feeds; NVD keyword catalogs paused (weak source) |
| 3 | C AST before/after units and temporal patch graph | Partial: heuristic C fragment miner with one verified fixture (CVE-2024-26581); typed SQLite graph |
| 4 | Curated causal lessons + independent label review | Partial: 35 pack records, lessons kept as hypotheses; no independent label review yet |
| 5 | Hybrid retrieval and revocable Xavier adapter | Partial: dry-run publisher and quality gate; vectors not built |
| 6 | Larger time/family-separated evaluation, refresh pipeline | Partial: weekly refresh workflow proposes PRs; no evaluation yet |
| Later | Additional open-source projects with selection manifest | 15 catalogs exist; selection manifest pending |

## Next

1. Fix the open fetcher defects listed in `STATUS.md` (atomic writes, Linux cursor rewind, moving window end, error-blocked resume).
2. Add upstream feeds for the remaining projects (OSV `GIT` ranges per repository, distro trackers) and retire NVD keyword search as a primary source.
3. CWE for kernel CNA rows: deterministic mapping where a source states it; anything model-assisted is stored as `hypothesis` with its method, never as `observed`.
4. Mine before/after fragments for the 17,696 rows that now carry a fix SHA, starting with the 35 pack records.
5. Build vectors and evaluate retrieval on a time-separated split.

Each stage needs evidence, source snapshots, exact verification and honest incomplete status. Generated explanations are never published automatically.
