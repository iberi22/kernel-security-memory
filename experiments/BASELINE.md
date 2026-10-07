# Baseline — qrels-v1 pilot measurement

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
- No MRR / composite recall reported: qrels-v1 carries unranked
  FOUND/ABSTAIN judgments only.

## Limits

- Single seed (`linux-CVE-2024-26581-mainline`), n=9: recall is
  illustrative, NOT generalizable. No bootstrap intervals, no holdout.
- One-author labels, no independent review: treat as exploratory.
- Graph probes q5/q6 seed lexical retrieval first (`query_graph` falls back
  to FTS seeding), so their HITs partly reflect lexical overlap.
