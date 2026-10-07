# Architecture — proposed until measured

One retrieval logic: **evidence-first temporal code retrieval**, with an independent corpus and Xavier as an optional runtime adapter.

1. Discover official advisories and enumerate commits from pinned refs in a remote worker. Preserve raw-source hashes and coverage.
2. Resolve source commits and selected parents. Index changed C functions, files and their versioned dependencies. Retain parse failure/configuration uncertainty.
3. Build deterministic temporal edges from Git parentage and explicit trailers. Keep heuristically suggested relationships as candidate edges requiring verification.
4. Extract causal teaching records: behavior, unsafe condition, trigger/preconditions, fix action, restored invariant, tests and applicability limits. Attribute the original source; analyst explanations remain hypotheses until checked.
5. Serve immutable JSON records, shards, manifests and SQL exports. These are canonical facts/evidence. Embeddings, community summaries and trees are disposable derived views.
6. Retrieve exact CVE/SHA/symbol → lexical candidates → optional semantic candidates → RRF → typed temporal/code neighbors → exact evidence. The agent can request up to two additional searches; otherwise answer with citations or abstain.

## Borrowed ideas, not copied code

Xavier: hybrid storage/rank fusion and symbol lookup. Vul-RAG: causal knowledge instead of only CVE text. LightRAG: local/global retrieval and incremental updates. LlamaIndex: typed graph extraction and AST-aware units. LangGraph: bounded tool loop. PageIndex: navigate hierarchy and read evidence. GraphRAG: optional global summaries, without relying on it as the core runtime.

## Entities and edges

Entities: repository, advisory, commit, code_version, pattern, claim, evidence, test_observation, review_observation.

Edges: parent_of, fixes, changes, before, after, backport_of, reverts, supersedes, affects, supports, refutes. `fixes` is not always `introduces_vulnerability`: use source semantics accurately. Store both source time and capture time so later knowledge cannot leak into earlier evaluation.

Each edge has evidence IDs, validation state and known time. Claims have independent validation status; a verified source only proves that the source said something. Automated scanners do not promote author statements into empirical proof of a security property.

## Retrieval boundary

The immutable corpus is the authority for what was recorded, not a guarantee every upstream statement is true. Runtime vectors do not make inferred claims facts. Downstream audit findings require an applicable control/data path, preconditions and source citations. Source code and commit messages are untrusted data; no retrieved instructions execute.

## Bootstrap implementation

The first scripts package and validate a source-linked record, build SQLite FTS/graph SQL and query it read-only. There is no whole-kernel miner, AST index, vector model, native Xavier mount or autonomous detector yet. These are explicit roadmap items.
