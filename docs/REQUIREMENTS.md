# Requirements and acceptance criteria

Scope v0: Linux mainline plus explicitly enumerated stable branches and official CNA records. Other projects come after this pilot.

| ID | Requirement | Acceptance evidence |
|---|---|---|
| REQ-001 | Immutable, versioned source provenance | Repo URL, commit SHA, blob reference/hash, observed time, extractor version |
| REQ-002 | Full history within declared refs and cutoff | Complete reachable-commit count, ref snapshot, shallow/partial state, crawl coverage/errors |
| REQ-003 | Security-fix candidate isolation | CNA links + Fixes/revert/backport trailers + semantic signals; precision audit; unlabeled candidates retained |
| REQ-004 | Correct before/after code context | Chosen parent, full file/function pointers and parser diagnostics; add-only/multifile/merge fixtures |
| REQ-005 | Subsequent patch evolution | Explicit fixes/reverts/backports/reviews, observation window, evidence grade and unknown outcomes |
| REQ-006 | Typed temporal evidence graph | Commits, symbol versions, advisories, claims, test observations and supported edges |
| REQ-007 | Code-aware indexing | C AST by revision with macro/config/parse limitations; file and function identity preserved |
| REQ-008 | Unified bounded retrieval | Exact IDs, lexical, optional semantic, rank fusion, typed expansion and budgeted evidence checks |
| REQ-009 | Portable HTTP JSON and SQL packs | Manifest hashes, schema version, reproducible export, read-only use, clean close |
| REQ-010 | Defensive teaching records | Cause, preconditions, impact, unsafe pattern, mitigation and invariant; unknown fields explicit |
| REQ-011 | Reproducible comparative evaluation | Same corpus/qrels/splits/budgets, temporal and patch-family separation, negatives, confidence intervals |
| REQ-012 | Truthful public progress | NOT_RUN/UNKNOWN represented; no mock success; measured and assumed values separate |

The distribution can be free within GitHub limits. Building indexes, hosting dynamic retrieval or invoking models may still consume compute, quotas or paid services. No paid model calls are authorized for the first smoke experiment.
