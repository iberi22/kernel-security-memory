# ADR-001 measured retrieval comparison

Date: 2026-11-02. Status: **MEASURED, exploratory**. ADR-001 remains **PROPOSED**.

## Inputs and reproduction

- Source revision before this change: `2836c099db2924f239cec6d4644c40116bdc1703` on `feat/w2d-adr001`.
- Runtime: Python 3.14.7, SQLite 3.53.1; standard library only.
- Corpus: 35 actual pack records reconstructed from the checked-in SQL export; no kernel clone or network retrieval.
- Corpus SHA-256 (exact SQL bytes): `0a5b44b08bdadadaba0d761fb16eafc6e88bafe6b3f3afcd693b37ec39b5e092`.
- Qrels: `qrels-v1.json`, version `1.0`; SHA-256 `39b9f204434ad60a32814f1097391bbc5faacd2f36a82cdf4337cb7ccd7d9a2b`.
- W1c dependency: qrels-v2 is absent on this branch. The CLI prefers it when available; this run explicitly pins v1. Rerun after W1c merges.
- Exact per-query results, record-scoped citation IDs, timings and search counts: [ADR001-MEASURED.json](ADR001-MEASURED.json).

```sh
python3 scripts/measure_retrieval.py --qrels experiments/qrels-v1.json --json-out experiments/ADR001-MEASURED.json
python3 -m unittest discover -s tests -v
python3 scripts/build_pack.py --check
```

Workspace verification commands are executed through `xavier exec` as required by AGENTS.md.

## Strategies and budgets

All strategies use the same reconstructed corpus, queries, and top-five output cap. The existing FTS OR tokenizer reads at most 32 query tokens. No relevance labels or expected IDs enter retrieval.

- `lexical_metadata`: unchanged `query_pack.query_database`, five BM25 results, deterministic record-ID ties. Despite the historical name, its existing index includes titles, node labels (including code pointers), and claim text, including hypotheses.
- `lexical_code_aware`: the same query_pack FTS candidate pool (up to 50); rerank by 4 points per distinct matching symbol token plus 2 per distinct path token from node attributes, then original BM25 and record ID. This tests extra pointer weighting, not source-body or AST retrieval. Fields absent from FTS cannot introduce a candidate.
- `lexical_typed_graph`: existing query_graph uses the same top-five lexical seeds and expands observed/validated within-record paths, at most two hops and ten nodes per record. Its implementation seeds all record nodes up to that limit; this is not a cross-record graph engine.
- `bounded_iterative_graph`: the same initial graph search, followed by at most two additional graph searches. Sorted unique endpoints from returned typed paths supply queries (strip type prefix). Preserve initial order, append new records, union citations within each record, cap at five. At most three graph calls, each returning at most five records with the same per-record graph budget. No follow-up if the initial search returns no paths; follow-up candidates come only from the initial frontier.

## Metrics

Primary ranking metrics use q1–q4, the four lexical FOUND queries, as required by QRELS.md. Recall@5 is the macro mean of the fraction of relevant record IDs in the returned top five; MRR is the mean reciprocal rank of the first relevant record (zero on a miss). Binary relevance supports these exploratory ranking measures without inventing graded judgments. The older measure_baseline script deliberately does not compute them; its historical metrics remain unchanged.

Citation completeness is macro coverage of expected (record ID, evidence ID) pairs on these positives; a citation counts only if its returned evidence has a URL and SHA-256. It measures availability, not citation correctness or security effectiveness. With multiple expected records, the flat expected evidence list is required for each record. Abstention rate is empty results / all nine queries; negative abstention is empty results / the three ABSTAIN controls. elapsed_ms is total wall time for nine retrieval calls including follow-ups and database reads, excluding pack reconstruction, scoring and serialization. One ordered local run, no warm-up or repeated latency benchmark; elapsed_ms is not constrained to [0,1].

| Strategy | Recall@5 | MRR | Citation completeness | Abstention | Negative abstention | elapsed_ms |
|---|---:|---:|---:|---:|---:|---:|
| lexical_metadata | 1.0000 | 1.0000 | 1.0000 | 0.2222 | 0.6667 | 31.812 |
| lexical_code_aware | 1.0000 | 1.0000 | 1.0000 | 0.2222 | 0.6667 | 26.243 |
| lexical_typed_graph | 1.0000 | 1.0000 | 1.0000 | 0.2222 | 0.6667 | 8.019 |
| bounded_iterative_graph | 1.0000 | 1.0000 | 1.0000 | 0.2222 | 0.6667 | 15.310 |

Both SHA-bearing graph probes (q5/q6) retrieve their expected record at rank one with complete expected citations for all four strategies. They are excluded from primary ranking metrics. All strategies return records for fabricated-CVE control n1, while n2/n3 abstain: broad OR matching still produces false positives. No strategy treats an unknown exact CVE as a mandatory abstention.

Vector and LLM strategies: **NOT_RUN**. There is no pinned embedding/index or configured LLM adapter. No downloads, paid calls, or simulated accuracy values were used.

## Decision and gaps

Keep ADR-001 **PROPOSED**: lexical metadata matches all three more complex strategies on all reported quality metrics. This provides no measured justification for accepting the larger architecture. Timing differences in one tiny sequential run do not establish a performance advantage.

The corpus contains 35 records, but all six positive judgments target the same Linux fix. Labels are authored from that seed without independent review; q2 contains its CVE and q5/q6 expose SHAs. This is not the protocol-compliant identifier-free, independently judged evaluation. There is no time/project/patch-family holdout, confidence interval, edge-precision measurement, vulnerable/patched classification, follow-up recall, or measured model/index operational cost. The pack includes hypotheses in FTS; relevance does not validate them. Broader qrels-v2, independently reviewed labels, identifier-free paraphrases, graph-specific targets and temporal controls are prerequisites for an acceptance decision.

The user reports the seven-method swal-sim run is complete. Its artifact is not present in this checkout; this report neither reproduces it nor treats operational simulation as measured retrieval evidence. Deterministic scores and hashes reproduce on this corpus; elapsed times vary.
