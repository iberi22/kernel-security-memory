# Roadmap

| Stage | Deliverable | Current state (2026-10-10) |
|---|---|---|
| 0 | Public docs, evidence contract, JSON/SQL packaging | Done |
| 1 | Remote seven-method sensitivity + retrieval smoke | Dispatched to Jules; no measured ranking yet |
| 2 | Official CNA ingestion and scoped history miners | Done for the Linux kernel CNA, curl and OpenSSL feeds and OSV repo-scoped git, systemd, sqlite, postgres; deterministic CWE overlay (NVD + CISA); NVD keyword catalogs paused (weak source) |
| 3 | C AST before/after units and temporal patch graph | Partial: before/after function features for the 35 pack records (hashes and ranges, no code); typed SQLite graph |
| 4 | Curated causal lessons + independent label review | Partial: 35 pack records, lessons kept as hypotheses; no independent label review yet |
| 5 | Hybrid retrieval and revocable Xavier adapter | Partial: dry-run publisher, quality gate that rejects stale evidence, injectable guardrails for 6 CWE families; vectors not built |
| 6 | Larger time/family-separated evaluation, refresh pipeline | Partial: weekly refresh workflow proposes PRs; no evaluation yet |
| Later | Additional open-source projects with selection manifest | 19 catalogs exist; selection manifest pending |

## Next

1. Mine fragment features beyond the pack: rows of `linux-cna` and the upstream catalogs that carry a FIX commit, prioritised by CWE family.
2. Promote verified catalog rows to pack records (with commit metadata) so guardrails can cite more than three examples per family.
3. CWE for the remaining `noinfo` ids: anything model-assisted is stored as `hypothesis` with its method, never as `observed`.
4. Build vectors and evaluate retrieval on a time-separated split.
5. Look for official feeds for openssh, nginx, qemu, unbound and glibc (distribution trackers, mailing-list archives) before relying on NVD keyword search.

Each stage needs evidence, source snapshots, exact verification and honest incomplete status. Generated explanations are never published automatically.
