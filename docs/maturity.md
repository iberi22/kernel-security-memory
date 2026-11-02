# Maturity scoring method

This method audits evidence recorded for bounded features. It does not measure
security effectiveness, kernel patch success, corpus completeness, or the whole
roadmap. The input is the local, private `.gitcore/features.json`; public progress
remains in [STATUS.md](STATUS.md). Never publish the private orchestration files.

Run the read-only standard-library verifier from any working directory:

```sh
python3 scripts/verify_maturity.py
python3 scripts/verify_maturity.py --root /path/to/repository
```

It prints JSON and never updates progress, runs recorded commands, or imports
pack migrations. Exit 0 means the audit completed, including a non-assertable
result; malformed/missing input produces JSON with an error and exits 1.

## Per-feature computation

The seven binary checks follow the `gitcore-auto-verify` method. Award each
weight once when the condition is satisfied; otherwise award zero.

| Check | Weight | Exact condition |
|---|---:|---|
| Implementation paths exist | 0.20 | At least one declared path, and every declared path exists inside the repository |
| Passing | 0.15 | `passes` is the JSON boolean `true` |
| Tests listed | 0.15 | `tests` is a list with at least one nonblank string |
| Recently tested | 0.15 | `last_tested` parses as an ISO date on or after 2026-07-01, inclusively |
| No caveats | 0.15 | Nonblank `notes` contain none of the case-insensitive words `MVP`, `Phase`, `optional`, `polish`, or the marker `Missing:` (whitespace before the colon allowed) |
| Implementation declared | 0.10 | `implemented_in` contains at least one nonblank path |
| Stable | 0.10 | `status` equals `stable` |

`implemented_in` accepts a comma-separated string or a list of explicit paths.
Directories count as existing paths. No shell, glob or brace expansion runs.
Empty declarations fail both implementation checks. Symlinks resolving outside
the repository fail the path check. Missing fields fail their checks; missing,
non-numeric, boolean or out-of-range `progress_pct` supplies a zero cap.

For feature i:

```text
check_score_pct_i = 100 * sum(weight_j * check_ij)
score_pct_i = min(check_score_pct_i, progress_pct_i)
```

The cap preserves the skill's rule that an audit cannot promote a feature above
its declared completion. For example, protocol documentation can exist and have
a recent date while the experiment remains only 20% delivered. JSON exposes both
the uncapped check score and the capped score, plus every check and missing path.

## Aggregation and assertion gate

Every tracked feature has equal aggregate weight (1); check weights above apply
within each feature. Do not weight by `progress_pct`, which would hide unfinished
features. No category or effort weighting is inferred.

```text
diagnostic_average_pct = sum(1 * score_pct_i) / sum(1)
assertable = feature_count > 0 AND
             every feature has tests_listed AND recently_tested
real_pct = diagnostic_average_pct if assertable else null
```

Round the aggregate to two decimal places only after averaging. An empty feature
collection has null averages and `assertable: false`; an absent collection is an
input error. A record with missing fields remains in the denominator with a zero
score. Features omitted entirely from the inventory cannot be detected by this
script: review the inventory against requirements before using the result.

When the gate fails, publish per-feature scores and **not assertable**, never the
diagnostic average as a claimed maturity percentage. `.gitcore/implementation-score.json`
must retain `real_pct: null` in that situation. The script does not modify it.
An assertable score can still be below 100 or include partial features; the gate
requires verification coverage, while the checks and cap express progress.

## Worked example: current ten features

Snapshot: 2026-11-02. All declared paths exist and all recorded dates pass the
fixed cutoff. Only pack and reader list tests. All notes pass the caveat check
except retrieval, whose notes contain `optional`.

| Feature | Declared % | Check score % | Capped score % | Tests listed |
|---|---:|---:|---:|---|
| feat-pack | 100 | 100 | 100 | yes |
| feat-reader | 100 | 100 | 100 | yes |
| feat-research | 100 | 85 | 85 | no |
| feat-remote-experiment | 20 | 60 | 20 | no |
| feat-linux-miner | 90 | 70 | 70 | no |
| feat-ast | 60 | 60 | 60 | no |
| feat-evolution | 25 | 60 | 25 | no |
| feat-retrieval | 50 | 45 | 45 | no |
| feat-adapter | 70 | 60 | 60 | no |
| feat-lessons | 60 | 60 | 60 | no |

For retrieval, the earned points are paths 20 + date 15 + declaration 10 = 45.
For the remote experiment, the check score is 60 but the declared cap is 20.
The capped scores sum to 625; the diagnostic average is 625 / 10 = **62.5%**.
The declared average is 67.5%, a different quantity. The report is:

```json
{
  "aggregate": {
    "feature_count": 10,
    "diagnostic_average_pct": 62.5,
    "real_pct": null,
    "status": "not assertable"
  },
  "assertable": false
}
```

## Evidence limits and maintenance

Path existence proves existence, including documentation pointers; it does not
prove working implementation. `passes`, test lists and dates are recorded source
statements, not independently validated test observations. The caveat check is a
literal metadata heuristic: notes saying `pending`, `NOT_RUN`, or `still open`
can pass it. These limits are why the cap, assertion gate and public known limits
must accompany the result. A research comparison is not a measured benchmark.

Before claiming an aggregate, reviewers must link each feature to applicable
tests and dated successful command results at an exact source revision, reconcile
the feature inventory, and inspect remaining caveats. Preserve errors, skips,
observation windows and unknown outcomes; never replace missing evidence with
success inferred from age, silence or a merge. Running this verifier does not
refresh `last_tested`. The fixed 2026-07-01 threshold is versioned policy rather
than a rolling freshness guarantee; revise it explicitly when policy changes.

Validate changes with:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build_pack.py --check
```
