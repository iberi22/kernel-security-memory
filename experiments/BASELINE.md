# Baseline — exploratory retrieval measurements

## Historical v1 pilot measurement

Command: `python3 scripts/measure_baseline.py`
(see `scripts/measure_baseline.py`; per-item verdicts HIT / MISS /
ABSTAIN_CORRECT / NOT_MEASURED over a temp read-only SQLite built from
`docs/memory/kernel-security-memory.sql`).

## Measured numbers (9 items, 9 measured, 0 NOT_MEASURED)

| id | mode | expect | verdict |
|----|------|--------|---------|
| q1-lex-interval-gc | lexical | FOUND | HIT |
| q2-lex-cve-fix | lexical | FOUND | HIT |
| q3-lex-paraphrase-gc-mask | lexical | FOUND | HIT |
| q4-lex-symbol-file | lexical | FOUND | HIT |
| q5-graph-parent | graph | FOUND | HIT |
| q6-graph-fixedby-fixes | graph | FOUND | HIT |
| n1-unknown-cve | lexical | ABSTAIN | MISS (returned `linux-CVE-2024-26581-mainline`) |
| n2-unrelated-subsystem | lexical | ABSTAIN | ABSTAIN_CORRECT |
| n3-unrelated-driver | graph | ABSTAIN | ABSTAIN_CORRECT |

- **positive_recall: 6/6 = 1.000** (HIT / measurable FOUND)
- **negative_abstention: 2/3 = 0.667** (ABSTAIN_CORRECT / measurable ABSTAIN)

## Reading

- The single MISS is n1: a fabricated CVE query still retrieves the seed
  record. Cause: `query_database` joins terms with OR, so any shared token
  (e.g. `driver`, `use`, `free`) matches. This is an abstention-threshold
  gap, not a scoring artifact.
- The original pilot did not report MRR. The extended evaluator now uses
  returned result order to compute ranking metrics for either qrels version.

## Limits

- Single seed (`linux-CVE-2024-26581-mainline`), n=9: recall is
  illustrative, NOT generalizable. No bootstrap intervals, no holdout.
- One-author labels, no independent review: treat as exploratory.
- Graph probes q5/q6 seed lexical retrieval first (`query_graph` falls back
  to FTS seeding), so their HITs partly reflect lexical overlap.

## v2 measurement (2026-11-02)

Reproduce with Python standard library only:

```sh
python3 scripts/measure_baseline.py --qrels experiments/qrels-v2.json
# Optional full per-item JSON:
python3 scripts/measure_baseline.py --qrels experiments/qrels-v2.json --json-out /tmp/baseline-v2.json
```

The default remains `experiments/qrels-v1.json`. Both modes use a temporary
read-only database built from the committed SQL export. With the default
five-result budget and 35-record pack, v2 measured all 30 items,
**0 NOT_MEASURED**:

| Metric | Numerator / denominator | Value |
|--------|-------------------------|------:|
| positive_recall | 22 / 22 | 1.000000 |
| negative_abstention | 5 / 8 | 0.625000 |
| MRR | reciprocal-rank sum 22 / 22 | 1.000000 |
| Recall@5 | 22 / 22 | 1.000000 |
| citation_completeness | 22 / 22 | 1.000000 |

All FOUND targets ranked first with complete expected evidence. Abstention
misses were n1 (fabricated CVE), n4 (absent CVE) and n7 (btrfs query):
shared tokens in the OR-based lexical search still retrieve other records.
The evaluator records these failures rather than adjusting labels or the
retriever. See [QRELS.md](QRELS.md) for metric definitions, budgets and
judgment provenance.

These perfect positive scores reflect an easy, author-labeled navigation
set with explicit identifiers and correlated paraphrases; they do not
establish semantic retrieval quality or patch success. Evidence completeness
checks citation IDs, not whether the source proves a security conclusion.
No independent review, confidence interval, temporal/family holdout or
seven-method comparison has been measured. The historical v1 table above
was recorded on the original seed; corpus expansion can change results.
