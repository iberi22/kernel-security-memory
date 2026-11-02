# Improvement Plan — kernel-security-memory (post Codex contrast)

Date: 2026-11-02. Source: Hermes audit + Codex contrast (gpt-6.1-sol, sandbox danger-full-access).

## Contrast (Codex vs audit)

Codex confirmed the audit's core claims and added sharper findings:
- Progress records lag implementation: `implementation-score.json` is `bootstrap`/`real_pct: null`; seven features were `planned @ 0%` though code exists.
- Corpus counts drifted: STATUS said 19 catalogs / 18,489 rows; manifest now shows 20 / 20,513 (17,734 with fix SHA).
- Tests drifted: STATUS said 863; actual 864 (3 skipped).
- Abstention gap demonstrated: qrels-v1 n1 (fabricated CVE) still returns a record (negative_abstention 2/3).
- `experiments/BASELINE.md` contradicts ROADMAP "no evaluation yet": a 9-item pilot exists (recall 6/6, abstention 2/3).
- ARCHITECTURE.md bootstrap section understated delivered miner/adapter.
- Native Xavier mount, embeddings, follow-up tracking, OSV catalogs for 17 OSS projects, independent label review remain genuinely open.
- ADR-001 stays PROPOSED; the 7-method simulation winner flips by scenario (Xavier composite vs langgraph primary).

## What was already applied (this session)
- Re-scored `.gitcore/features.json` (avg 30% -> 67.5%): linux-miner stable@90, ast partial@60, retrieval partial@50, adapter partial@70, lessons partial@60, evolution partial@25, remote-experiment partial@20.
- Updated `implementation-score.json` to `partial` with explicit open items.
- Refreshed STATUS.md (date, 20 catalogs/20,513 rows, 864 tests), ROADMAP.md (stages 1/3/5), ARCHITECTURE.md bootstrap section, README test count.
- Merged open PR #97 (fingerprints batch), pushed main.

## Prioritized improvement plan

### P0 — Credibility & hygiene (1-2 days)
1. Fix abstention gap (n1): exact CVE-id short-circuit in `query_pack.query_database` + calibrated threshold; add tests for unknown IDs, unrelated queries, valid paraphrases. Target: negative_abstention 3/3.
2. Separate denominators in STATUS: catalog rows vs unique CVEs vs curated records (35).
3. Keep `real_pct: null` until a defensible scoring method; document the method in `docs/maturity.md`.

### P1 — Evaluation (1 week)
4. Expand qrels beyond single seed: >=30 items, >=5 semantic paraphrases, >=5 negatives, independent label review (second reviewer).
5. Temporal + patch-family splits; report Recall@5, MRR, citation completeness, abstention, latency.
6. Re-run the 7-method comparison with measured retrieval (not simulation); accept ADR-001 only if a simpler baseline does not match.

### P2 — Capabilities (2-4 weeks)
7. Native Xavier mount/unmount (reversible, with import receipt + namespace) — implement + test against live Xavier API.
8. Neural embeddings: `embed_vectors.py` already has contract; wire model ID/revision/dims into pack manifest; add cosine ranker to reader.
9. Patch evolution: follow-up/revert/backport tracking for a bounded Linux cohort (REQ-005).
10. OSV repo-scoped catalogs for the 17 OSS Scanner projects with OSV GIT data (6 missing).
11. Independent label review workflow + docs.

### P3 — Continuous
12. Weekly refresh workflow proposes PRs; keep CI green (864 tests).
13. Keep STATUS/ROADMAP/features in sync via a verification script (reuse `gitcore-auto-verify` skill).

## Suggested first 3 actions
1. Implement exact-id abstention fix + tests (P0.1).
2. Write `docs/maturity.md` defining the scoring method (P0.3).
3. Expand qrels-v1 to v2 with independent labels (P1.4).
