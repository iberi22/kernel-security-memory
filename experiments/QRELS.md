# QRELs — exploratory retrieval judgments

## v1: bounded pilot judgments

Version: 1.0. Seed: `docs/memory/records/linux-CVE-2024-26581-mainline.json`
(record `linux-CVE-2024-26581-mainline`; evidence `e-commit`, `e-advisory`,
`e-before`, `e-after`). q2 contains an explicit target CVE and q5/q6
contain CVE/SHA identifiers as graph probes; these are navigation controls,
not identifier-free Phase-B queries under `experiments/PROTOCOL.md`.

## Method

- Read the seed JSON: nodes (advisory, 3 commits, 2 code_versions for
  `net/netfilter/nft_set_rbtree.c` symbol `nft_rbtree_gc_elem`), edges
  (`parent_of`, `fixes`, `fixed_by`, `before`, `after`) and evidence map.
- Positive items (q1–q6): terms/symbols/relations copied from seed labels
  and claim text; each `expected_*_id` verified to exist in the seed file.
  Modes: `lexical` = FTS over record text (`scripts/query_pack.py`);
  `graph` = typed edge traversal (parent/fixed_by/fixes).
- Negative controls (n1–n3): fabricated CVE, unrelated subsystem (eBPF),
  unrelated driver (amdgpu). Expect `ABSTAIN` = `ABSTAIN_NO_MATCH` with
  empty expected lists.

## Judgments (9 items: 6 FOUND + 3 ABSTAIN)

| id | mode | expect | evidence |
|----|------|--------|----------|
| q1-lex-interval-gc | lexical | FOUND | e-commit, e-before, e-after |
| q2-lex-cve-fix | lexical | FOUND | e-advisory, e-commit |
| q3-lex-paraphrase-gc-mask | lexical | FOUND | e-commit, e-before, e-after |
| q4-lex-symbol-file | lexical | FOUND | e-before, e-after, e-commit |
| q5-graph-parent | graph | FOUND | e-commit |
| q6-graph-fixedby-fixes | graph | FOUND | e-commit, e-advisory |
| n1-unknown-cve | lexical | ABSTAIN | — |
| n2-unrelated-subsystem | lexical | ABSTAIN | — |
| n3-unrelated-driver | graph | ABSTAIN | — |

## Known limits

- Single seed => recall is illustrative, NOT generalizable. No bootstrap
  intervals, no holdout, no before/after discrimination yet (see PROTOCOL
  Phase B full evaluation).
- Labels declared by one author, no independent review => report any
  metric using these qrels as exploratory.
- Graph probes q5/q6 use explicit SHAs. The evaluator's combined positive
  rate includes both modes; it is not identifier-free lexical recall.

## v2: expanded source-checked judgments

`experiments/qrels-v2.json` version 2.0 contains **30 items: 22 FOUND and
8 ABSTAIN**, covering **7 records across 6 projects** (Linux, git, nginx,
OpenSSH, SQLite, systemd). The nine v1 queries, modes, expectations and
record/evidence judgments are preserved. Added groups are disjoint:

| Group | Count | Purpose |
|-------|------:|---------|
| p1–p5 | 5 | Semantic paraphrases of q1/q3/q4, still run through lexical retrieval |
| n4–n8 | 5 | Absent identifiers and absent subsystem topics, lexical and graph abstention |
| r1–r6 | 6 | New positive records: git CVE-2016-2315 / CVE-2016-2324, nginx CVE-2017-20005, OpenSSH CVE-2018-20685, SQLite CVE-2019-19244, systemd CVE-2020-1712 |
| g1–g5 | 5 | `fixed_by` probes for the first five new positive records |

Each item has `id`, `mode`, `expect`, `query`, `evidence` (record-local
expected evidence IDs), `reviewer`, `reviewed_at` (ISO date), and a
`record_id` for FOUND. The evaluator also accepts v1's
`expected_record_ids` / `expected_evidence_ids` fields.

The reviewer string identifies the author agent's source-consistency
review on 2026-11-02, **not independent review or a human sign-off**. New
positive targets and evidence IDs were checked against committed
`docs/memory/records/*.json`; graph targets use the recorded observed
`fixed_by` edges and their evidence. Negatives mean unsupported by this
bounded evidence pack, not absent from all public CVE catalogs. Queries
were not removed or rewritten after seeing baseline results.

These labels ask for retrieval of recorded source associations, not proof
that a patch works. v2 does not solve the single-author limitation: it
adds coverage and provenance, while independent adjudication, temporal
and family holdouts, confidence intervals and before/after discrimination
remain pending. Five paraphrases share the Linux seed and are correlated.
The new record probes deliberately include CVE IDs and graph probes include
SHAs; they test navigation and ranking, not identifier-free Phase-B semantic
recall. Graph mode remains lexical candidate seeding plus within-record
traversal; its metrics do not demonstrate independent graph discovery.

## Metric contract

Scores use returned list order (including graph's lexical seed order),
never alphabetical record IDs. Over measurable FOUND items:

- **MRR**: mean `1 / rank` of the first matching expected record; zero if
  absent. Rank is one-based. This uses the bounded result list, default 5.
- **Recall@5** (`recall_at_5`): fraction with an expected record in the first
  five results, regardless of whether all expected citations were returned.
- **citation_completeness**: fraction where the returned expected record
  contains every expected evidence ID. Missing records score zero; evidence
  from other returned records cannot satisfy this judgment.
- Existing **positive_recall** counts evidence-complete HITs, and
  **negative_abstention** counts correct empty responses over measurable
  ABSTAIN items. Ranking/citation metrics exclude ABSTAIN items.

Every metric reports its own denominator. NOT_MEASURED items contribute
neither zeroes nor a denominator; an empty denominator is JSON `null`.
The lexical retrieval budget is `max(5, --limit)` so Recall@5 always has
five candidate slots available. Graph currently returns at most five
lexically seeded records, even when a larger limit is requested. Larger
lexical budgets may change MRR and citation completeness; compare runs
only at identical budgets. Missing expected-record judgments and retrieval
errors remain NOT_MEASURED.
