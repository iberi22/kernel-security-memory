# ADR-001 — evidence-first temporal code retrieval

Status: **PROPOSED**. Architectural acceptance is pending the remote simulation and measured retrieval experiment.

## Context and options

Compare Xavier, Vul-RAG, Microsoft GraphRAG, LightRAG, LlamaIndex code/property graph, LangGraph retrieval orchestration and PageIndex. They are complementary types, not equivalent plug-and-play products. See the source-backed comparison.

## Working design

Canonical evidence graph + JSON/SQL packs, C AST units, hybrid exact/lexical/semantic retrieval with RRF, temporal expansion and a bounded reasoning loop. Integrate with Xavier by HTTP/adapters; preserve distribution independent of runtime and embeddings.

This is a testable hypothesis, not an accepted winner. Full-framework deployments and code copying are deferred. A lexical-only baseline is essential to determine whether vectors/LLM loops add value.

## Simulación

- Engine inspected: canonical private swal-sim `adr_sim.py`; current models do not include this question.
- Requested remote run: new wrapper model, 5000 runs, seed 42, canonical four scenarios; complete-metric validation and extended sensitivity.
- Results: **NOT_RUN / pending remote artifact**. No composite score or winner is asserted.
- Empirical experiment: `experiments/PROTOCOL.md`. Required alongside simulated operational assumptions.

## Acceptance gate

Record actual run command/revision, seeds, all assumptions, primary/composite disagreement, uncertainty and sensitivity. Accept only after independently assessed real-code retrieval/negative tests and measured operational constraints support the design. If a simpler retrieval baseline performs comparably, keep it.
