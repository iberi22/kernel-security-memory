# Experiment protocol

Status: PLANNED / remote task dispatched separately. Research fit is not measured performance.

## Phase A — decision sensitivity

Canonical private swal-sim engine reviewed: stdlib, options × bull/base/bear/worst (0.15/0.40/0.30/0.15), deterministic seed derivation, primary/composite rankings and a bull-drop sensitivity check. Its existing models do not answer code retrieval. Its generic scorer can silently default absent metrics to zero, so the new wrapper must reject missing metrics and examine removal of EACH scenario and objective-weight changes.

Remote Jules task on swal-sim adds an isolated wrapper model: seven selected approaches, 5000 runs/seed 42, explicit ASSUMPTION parameters and uncertainty ranges. It cannot manufacture retrieval accuracy or use Monte Carlo to prove a chosen tool superior. Operational units are not dollars without actual pricing. A provisional ranking remains sensitive to supplied assumptions and needs Phase B.

## Phase B — bounded measured retrieval

Same real Linux seed corpus and source cutoff for all baseline retrieval logics: lexical metadata; lexical+code pointers; lexical+typed graph; bounded iterative graph tools. These are logic baselines, not faithful implementations of seven frameworks. Unimplemented framework adapters are NOT_RUN.

Pilot: at most 20 fixes, bounded remote downloads, no paid LLM or full kernel clone. Queries exclude target CVE/SHA and include semantic paraphrases and negative controls. Independently declared qrels and source-linked targets; if labels lack independent review report results as exploratory. Log corpus/query/qrel hashes, timing, failures and source revisions.

Full evaluation: enlarge only after ingestion integrity passes; hold out by time, project/subsystem and patch family (all backports together). For a pre-fix query exclude future follow-ups and post-fix summaries. Test before/after discrimination separately from evidence retrieval. Include add-only, deletion, rename, multi-file, merges and macro-heavy cases.

Metrics: Recall@5, MRR, edge precision, citation completeness/correctness, pairwise vulnerable/patched classification when actually run, negative-query false positives/abstention, revert/follow-up recall, latency, bytes, index build/update resources and actual model calls. Bootstrap intervals over queries/families; same budgets and index/model configuration. Every metric carries MEASURED, ASSUMPTION or NOT_RUN.

No automatic vulnerability confirmations from semantic similarity. Missing evidence produces abstention. No kernel compilation in the first experiment. Kernel regression tests need a separate explicit sandbox design.
