# Iteration stack and remote operation

Status: provisional engineering choice; ADR-001 remains PROPOSED. This is not an empirical winner of seven engines.

## Recommended split

Python 3.12 workers build source-linked records and reproducible packages. Use standard library first, then isolated pinned tree-sitter/C dependencies for syntax indexing. SQLite FTS5 provides lexical search; ordinary indexed node/edge tables and bounded recursive traversal provide the evidence and temporal graph. This is a graph data model, not a claim of native graph-database features or semantic call/data-flow analysis.

Optional semantic indexing uses sqlite-vec, with its version pinned because its upstream is pre-v1. Embeddings are a rebuildable derivative, never the source of truth. Do not choose an embedding model solely because dimensions match Xavier: model ID, immutable revision, tokenizer, normalization, input template, dimensions and distance metric must all match. Until tested, vectors remain NOT_BUILT and model choice stays pending empirical comparison. Keep lexical retrieval available without extension/model downloads.

Xavier consumes packs through a read-only adapter. Its existing memory database is not the schema for this corpus. Do not restore a public SQL pack into Xavier's production database. No new Rust/Xavier wave until its Jules environment and adapter contract are verified. No AGPL implementation is copied into this MIT repository.

## Alternatives for rapid iteration

| Approach | Iteration tradeoff | Initial role |
|---|---|---|
| Python + SQLite FTS/evidence graph + optional sqlite-vec | Small workers, inspectable artifacts, cheap tests; traversal and vector scaling must be measured | Recommended prototype |
| Extend Xavier Rust as sole producer/store | Reuses retrieval, but couples experiments to large builds and native schema/encryption | Consumer first; port proven hot paths later |
| LlamaIndex PropertyGraph + code splitter | Ready orchestration/AST integrations, more dependencies and provider contracts | Optional experimental adapter |
| LightRAG or GraphRAG as canonical store | Useful text relationship/global summaries; additional extraction cost and no automatic commit causality | Secondary derived views only |
| Neo4j + Qdrant services | Strong dedicated stores; two services, backups and deployment to operate | Revisit when measured scale needs them |

The seven-candidate source comparison is in research/RAG-COMPARISON.md. LangGraph is an optional bounded orchestrator; Vul-RAG contributes a hypothesis template; PageIndex is a document hierarchy baseline. None automatically supplies patch effectiveness or temporal security evidence.

## What GitHub Actions can operate

Actions is a batch build/evaluation operator: fetch bounded sources, verify identities, create candidates, parse syntax, build lexical/vector derivatives, run leakage-resistant evaluation, publish versioned packs. Agents/Xavier serve queries while jobs are idle. Pages/raw HTTP serves static JSON; it does not run dynamic graph/vector SQL queries.

Standard hosted runners are free for public repos; public ubuntu-24.04 currently offers 4 CPUs, 16 GB RAM and 14 GB SSD. Each hosted job has a six-hour limit. Split historical Linux acquisition into resumable scoped shards, record immutable refs/cutoffs and coverage; never call an API sample all commits. Do not execute upstream code or patches. Full mining may exceed disk/time even if runner minutes are free. Initial runs are bounded and manually dispatched; periodic refresh follows tested idempotency.

Schedules can be delayed/dropped and disable after 60 days of repository inactivity. They are not an always-on service/SLA. Paid APIs, larger runners and GPU/model services are outside the free-runner promise. CPU embedding generation must be benchmarked on bounded shards before scaling.

Publish small JSON/SQL via Pages and larger immutable binary packs as release assets (each asset under 2 GiB). Never commit runtime .db/.sqlite files. Artifacts/caches are temporary build conveniences, not the authoritative corpus. A release manifest identifies source revision, coverage, file hashes, schema/index version and optional embedding contract. Consumers verify hashes, open separately read-only, and close/detach without altering existing memories.

## First waves and decision gates

Wave 1: (1) bounded immutable-source miner producing unreviewed candidates; (2) typed bounded graph query baseline with evidence; (3) hash-verified read-only pack consumer. Their file islands are disjoint. Existing simulation PR needs correction: estimated MRR and constant citation completeness are not measurements, and an unrelated /app path change must be restored.

Wave 2 after review/integration: AST units, real semantic index/model comparison, Actions workflow integration. Wave 3: temporal follow-up collection, independently reviewed qrels, RRF/ablation and reversible Xavier integration. A keyword candidate is not a confirmed vulnerability; patch age/silence never validates success.

Acceptance requires actual ranks/qrels/citations, negative queries, temporal leakage guards and measured build/query resources. Keep architecture provisional while those gates are pending. A passing test suite alone cannot validate invented evaluation metrics.

## Primary sources (checked 2026-10-07 UTC)

- https://docs.github.com/en/actions/concepts/billing-and-usage
- https://docs.github.com/en/actions/reference/limits
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule
- https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases
- https://github.com/asg017/sqlite-vec
