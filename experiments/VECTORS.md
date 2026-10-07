# Vectors — derived-view contract (corpus JSON/SQL rules)

Vectors are a DERIVED, disposable view. The canonical facts are the JSON
records (`docs/memory/records/`) and the SQL text export
(`docs/memory/kernel-security-memory.sql`). A vector index NEVER promotes
an inferred claim to a fact and is rebuilt, never hand-edited.

## Chosen model (MANUAL generation; fixtures in CI)

| field | pinned value |
|---|---|
| model | `sentence-transformers/all-MiniLM-L6-v2` (free, Apache-2.0, CPU-runnable on Ubuntu CI hardware) |
| model revision | pinned at MANUAL generation time and recorded in the vectors manifest (`model_revision`); this PR ships NO neural vectors, so no revision is claimed |
| tokenizer | `bert-base-uncased` WordPiece, `max_seq_length=256`, truncation + padding |
| normalization | L2 unit norm on every stored vector |
| embed template | `vectors-v1`: record `title` + one line per node `label` + one line per claim `text` (same source fields as the FTS index in `scripts/build_pack.py`; see `build_text` in `scripts/embed_vectors.py`) |
| dims | 384 |
| metric | cosine (= dot product over L2-normalized vectors) |
| sqlite-vec | `sqlite-vec==0.1.9` (latest on PyPI per `pip index`, 2026-10-07; CPU wheel, no server) |
| sentence-transformers (MANUAL only) | `==6.1.0` (pinned at contract time; needs network + torch, never in CI) |

Reference constants live in `scripts/embed_vectors.py`
(`MODEL_ID`, `DIMS`, `METRIC`, `NORMALIZATION`, `TEMPLATE_VERSION`,
`SQLITE_VEC_VERSION`, `ST_VERSION`); the unit tests fail if this file
and the module disagree.

## Why MANUAL + fixtures

Downloading the model needs network and `torch` (~800 MB), which the
offline pack tests must not assume. So:

- CI/tests use the `fixture` provider: deterministic stdlib-only hashed
  char-trigram projection (384 dims, L2-normalized). It exercises the
  plumbing (format, ranking, qrels comparison) with ZERO semantic signal.
- Real vectors are generated MANUALLY on a networked machine:
  `python3 scripts/embed_vectors.py --provider st --measure` (prints the
  comparison) and the resulting file + its `model_revision` are reviewed
  before any adoption decision. `sqlite-vec` absence fails loudly:
  `require_sqlite_vec()` raises `RuntimeError` naming the pinned version
  instead of silently degrading.

## Acceptance gate (baseline from `experiments/BASELINE.md`)

Baseline qrels-v1: **positive_recall = 1.000 (6/6)**,
**negative_abstention = 0.667 (2/3)**.

Derived vectors are adopted ONLY if, measured with the same verdict
semantics over `experiments/qrels-v1.json`:

- `positive_recall == 1.000` (no recall regression), AND
- `negative_abstention > 0.667` (strict improvement: fix the n1
  fabricated-CVE MISS without losing anything else).

Anything else (regression, tie, or unmeasurable) keeps the lexical/graph
baseline as the shipped retrieval. No MRR / composite scores: qrels-v1
has unranked FOUND/ABSTAIN judgments only.

## Measurement status: NOT_MEASURED

This PR generates NO neural vectors (no `--provider st` run: network
model download + torch review pending), so there is nothing honest to
score against the gate above. Fixture-provider numbers exist only as
plumbing output in `score_fixture_against_qrels` and MUST NOT be quoted
as a benchmark. Status flips to MEASURED only with a reviewed MANUAL run
whose manifest records the exact model revision.
