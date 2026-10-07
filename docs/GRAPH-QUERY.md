# Evidence Graph Query Baseline

`scripts/query_graph.py` provides a bounded retrieval baseline over the immutable evidence JSON/SQL packs. It leverages lexical search (using `query_pack.py`) to find seed records and expands typed evidence graphs around the discovered seed records within defined temporal and scope bounds.

## Capabilities
- **Exact & Lexical Search Base**: Reuses the lexical matcher to locate seed records. No generic search fallback.
- **Bounded Expansion**: Bounds the graph traversal by an absolute number of maximum valid nodes (`--max-nodes`, up to 50) and graph hops from seeds (`--max-hops`, 0-2).
- **Temporal Cutoff**: The `--as-of` flag optionally provides a strict ISO UTC temporal cut-off line. Edges, claims, and evidence observed or known after this point (or explicitly missing time values) are dropped from the retrieval context.
- **Abstention**: If no lexical matches are found, the baseline strictly abstains (`ABSTAIN_NO_MATCH`). It does not guess answers.
- **No Vectors/LLMs Required**: Purely relies on explicitly validated/observed properties.

## Command Line Interface
```bash
python3 scripts/query_graph.py --query 'garbage collection' \
    [--database path/to/pack.sqlite3] \
    [--max-hops 2] \
    [--max-nodes 10] \
    [--as-of 2024-01-01T00:00:00Z]
```

## Schema & Truncation Handling
The output results object encapsulates the discovered exact evidence records, isolated to their independent subgraph namespaces. The property `truncated_nodes` signals if the configured bound limits forced early termination. Graph edge properties filter out dangling and non-validated states ensuring reliable facts are returned to agents context windows.
