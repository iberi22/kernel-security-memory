# Roadmap

| Stage | Deliverable | Current state (2026-10-11) |
|---|---|---|
| 0 | Public docs, evidence contract, JSON/SQL packaging | Done |
| 1 | Remote seven-method sensitivity + retrieval smoke | Simulation run (swal-sim SECURITY-RAG-decision.md, winner flips by scenario); measured retrieval NOT_RUN; qrels-v1 pilot (recall 6/6, abstention 2/3) |
| 2 | Official CNA ingestion and scoped history miners | Done for the Linux kernel CNA, curl and OpenSSL feeds and OSV repo-scoped git, systemd, sqlite, postgres; deterministic CWE overlay (NVD + CISA); NVD keyword catalogs paused (weak source) |
| 3 | C AST before/after units and temporal patch graph | Partial: offline C AST miner delivered (mine_ast.py); before/after features for 35 pack records (hashes/ranges, no code); typed SQLite graph |
| 4 | Curated causal lessons + independent label review | Partial: 35 pack records, lessons kept as hypotheses; no independent label review yet |
| 5 | Hybrid retrieval and revocable Xavier adapter | Partial: HTTP publish/disconnect (pack_to_xavier.py) delivered; dry-run publisher, quality gate, guardrails (6 CWE), related-CVE TF-IDF, atlas UI, ksm CLI, fingerprint matcher delivered; native Xavier mount/unmount pending |
| 6 | Larger time/family-separated evaluation, refresh pipeline | Partial: weekly refresh workflow proposes PRs; no evaluation yet |
| Later | Additional open-source projects with selection manifest | 19 catalogs; selection manifest of the 23 OSS Scanner projects (`docs/studies/selection/`) |

## Next

1. Mine fragment features beyond the pack: rows of `linux-cna` and the upstream catalogs that carry a FIX commit, prioritised by CWE family.
2. Promote verified catalog rows to pack records (with commit metadata) so guardrails can cite more than three examples per family.
3. CWE for the remaining `noinfo` ids: anything model-assisted is stored as `hypothesis` with its method, never as `observed`.
4. Fingerprint the remaining fix commits through the weekly workflow (pack records first, then upstream catalogs, then linux-cna) and measure the matcher across projects, not only across versions of one project.
5. Xavier MCP tool that loads the KSM bundle and runs the matcher on the indexed project.
6. Evaluate related-CVE retrieval on a time-separated split.
7. Add OSV repo-scoped catalogs for the 17 OSS Scanner projects with OSV GIT data.
8. Ingest OSS Scanner findings of enrolled SWAL projects as `hypothesis` records once a real report exists.
9. Look for official feeds for openssh, nginx, qemu, unbound and glibc (distribution trackers, mailing-list archives) before relying on NVD keyword search.

Each stage needs evidence, source snapshots, exact verification and honest incomplete status. Generated explanations are never published automatically.

## Top-20 Open-Source Repos Projects Tracking
- Incorporate more projects beyond the core 20 to widen the lessons dataset for agents.
- Expand skill files from `docs/studies/top20/skills/` directly into broader ecosystems.
