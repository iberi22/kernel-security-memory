# QRELs v1 — bounded pilot judgments

Version: 1.0. Seed: `docs/memory/records/linux-CVE-2024-26581-mainline.json`
(record `linux-CVE-2024-26581-mainline`; evidence `e-commit`, `e-advisory`,
`e-before`, `e-after`; no target CVE/SHA in Phase-B pilot queries per
`experiments/PROTOCOL.md` — q5/q6 carry SHAs only as graph-edge probes,
excluded from lexical recall scoring).

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
- Graph probes q5/q6 use explicit SHAs; score lexical recall on q1–q4 only.
