# Independent qrels review

The labels in `experiments/qrels-v1.json` are exploratory judgments by one
author with no recorded reviewer identity or review time. As of 2026-11-02,
there are nine items, no attributed review pairs, and no `qrels-v2.json`.
Cohen's kappa is **unavailable**, not zero or perfect agreement. Do not
backfill identities or timestamps without an actual review.

## Two-reviewer labeling

1. Pin the corpus revision, query set, evidence IDs, observation cutoff and
   labeling instructions before assigning reviews. Both reviewers receive
   the same material, including negative controls and graph probes.
2. Assign two distinct reviewers with stable public handles. Each labels
   every item independently, without seeing the other's labels or retrieval
   system outputs. Automated copies of one label do not count as independent
   review. A reviewer may abstain from judging due to insufficient evidence;
   leave that review pending rather than labeling it `ABSTAIN`.
3. Each completed review states `expect` (`FOUND` or `ABSTAIN`),
   `expected_record_ids`, `expected_evidence_ids`, and a rationale grounded in
   pinned evidence. `ABSTAIN` means the query should yield no supported match;
   it is a retrieval outcome label, not a missing reviewer judgment. Preserve
   observed source statements, hypotheses and validated conclusions separately.
4. Freeze the independent reviews and compute agreement before discussion.
   Flag all unreviewed and singly reviewed items; complete them before calling
   a release independently reviewed. Never interpret absence of later evidence
   as proof that a security patch succeeded.

## Review rows and validation

Store independent judgments in a separate `qrels-vN-reviews.json` object with
an `items` array. Each row copies the query's stable `id`, `query`, `mode` and
expected label fields, adding `reviewer`, `reviewed_at` and `rationale`.
Two reviewers produce two rows with the same item `id`; `(id, reviewer)`
must be unique. Do not feed this duplicated review log directly to retrieval
evaluation: the adjudicated `qrels-vN.json` has one final row per item.

`reviewer` must be a nonempty string identifying the actual reviewer (a public
handle is sufficient; no private identity data). `reviewed_at` must be the
actual completion time as an ISO-8601 timestamp with timezone, for example
`2026-11-02T19:00:00Z`. Never substitute file modification time. Both fields
are required on every independent row and final adjudicated item; on a final
item they identify the adjudicator or the reviewer who recorded consensus.
Keep links to both original review rows in the final release metadata.

Minimal checker input (normal review rows also include evidence and rationale):

```json
{
  "version": "2.0-reviews",
  "items": [
    {"id": "q1", "expect": "FOUND", "reviewer": "reviewer-a", "reviewed_at": "2026-11-02T19:00:00Z"},
    {"id": "q1", "expect": "ABSTAIN", "reviewer": "reviewer-b", "reviewed_at": "2026-11-02T19:05:00Z"}
  ]
}
```

```sh
python3 scripts/check_qrels_review.py experiments/qrels-v1.json
python3 scripts/check_qrels_review.py experiments/qrels-v2-reviews.json --reviewers reviewer-a reviewer-b
```

The stdlib checker emits JSON: per-reviewer row counts, unique item count,
errors, singly reviewed/unreviewed item IDs, paired-item count, observed
agreement and kappa. It exits 1 for missing/invalid reviewer, timestamp, ID or
outcome, duplicate reviews, malformed JSON or unreadable input. Single-reviewer
coverage is a warning (exit 0 if metadata are valid), not independent review
certification. The checker validates review metadata and outcome agreement;
evidence correctness, rationales and reviewer independence require human review.

## Agreement metric

Use unweighted nominal Cohen's kappa on the `expect` outcomes of the two named
reviewers, paired by item `id`. If exactly two reviewers exist, the checker
selects them automatically; otherwise select them with `--reviewers A B`.
Only items judged by both selected reviewers enter the denominator. Report
their names, paired count, total unique items, missing coverage, outcome
frequencies and observed agreement alongside kappa.

For N paired items, let po be the fraction with matching labels and pe the
sum, over outcome categories, of the product of the two reviewers' marginal
category proportions. Then `kappa = (po - pe) / (1 - pe)`. No pairs means
unavailable; `pe = 1` means undefined constant-label agreement. Both are
reported as JSON `null` with an explicit status, never as 1. A small pilot
with skewed classes is not a generalizable benchmark. Kappa on outcomes does
not measure agreement on evidence or record IDs; review those disagreements
separately even when outcomes match. No arbitrary kappa threshold replaces
adjudication or completeness checks.

## Adjudication and versioning

Resolve every disagreement in outcome, expected record IDs or evidence IDs.
The reviewers first compare their evidence and record a consensus rationale.
If disagreement remains, a third reviewer examines the pinned sources and
records the final decision, identity, timestamp and rationale. Preserve both
original labels unchanged. Unresolved items remain pending and are excluded
from the released scored set with an explicit exclusion reason; never silently
drop them. Compute and publish agreement from original labels, not adjudicated
ones.

Retain `qrels-v1.json` unchanged as historical exploratory data. New reviewed
labels go into a new numbered release with matching review log and updated
`experiments/QRELS.md`. Record parent version, corpus/query revisions, review
instructions, review-log path/hash, agreement report and adjudication history.
Any label, evidence, query or membership change creates a new qrels version;
metadata corrections also require a recorded revision rather than overwriting
the historical artifact. Evaluation results pin both the qrels version and
repository revision. A workflow implementation alone does not upgrade the
historical labels to independently validated labels.
