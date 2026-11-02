# Linux acquisition, security isolation and patch evolution

## What “all commits” means

All reachable commits in a recorded set of upstream refs at a fixed cutoff, not every commit ever written or hidden/unreachable objects. Mainline and stable are distinct repositories/ref namespaces. Old pre-Git history is outside v0 and must be reported. A shallow sample is never labelled a full scan.

A remote worker snapshots refs of the Linux mainline and stable repositories. For a full run, obtain commit/tree history without eager source checkout (a partial clone can defer blobs), then explicitly fetch the refs in scope. Verify the repository is not shallow; record `rev-list --count` and failed fetches. A blobless clone still downloads commit/tree history and later source blobs; it is not a tiny download. Never perform the full clone on the user's machine.

Illustrative remote-only commands, not executed in the bootstrap:

```sh
git clone --bare --filter=blob:none https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux-mainline.git
git -C linux-mainline.git rev-parse --is-shallow-repository
git -C linux-mainline.git for-each-ref --format='%(refname) %(objectname)'
git -C linux-mainline.git rev-list --all --count
```

Enumerate messages/parents/timestamps with a machine-safe format (NUL framing or length-prefixed batch reads), preserve full messages, author/committer differences and ref reachability. A GitHub REST paginated crawl is acceptable for a bounded sample, not the preferred full-history transport.

## Candidate signals

1. Official Linux CNA records/announcements and fix links; snapshot rejected/disputed/modified entries too. Parse `.dyad` versions with any component count, validate SHAs/sentinels and map branch fixes to upstream. Count files, rows, unique commits and curated patterns separately.
2. `Fixes:`, explicit `This reverts commit`, stable/upstream trailers and `Link:` to reviews. `Fixes:` means bug correction; it is not by itself a security label. CVE tokens in commit messages are insufficient.
3. Semantic candidates such as lifetime, bounds, locking, permission and validation changes. Keep inferred classification separate and manually assess precision/recall on a sample, including unlabelled fixes.

Deduplicate backports by provenance and stable patch-id where useful; patch-id matches support equivalence, not proof identical behavior under different branch code/configuration.

## Extract before/after

Use the fix's selected parent and fix tree, not a range from an arbitrary release point. For ordinary non-merge commits choose the sole parent. For merges store all parents and the deliberate comparison; never guess silently. Retrieve full blobs and symbol units for every changed file. Addition-only changes still require the old function context. Handle deletion, rename, macros, cross-file logic, missing diffs, binary changes and parse errors explicitly.

Persist paths, blob IDs/content SHA-256, revision and byte/line spans. A line diff is evidence of change, not a complete causal pattern. No kernel code verbatim is redistributed by the seed pack.

## REQ-005: Did the fix mature or fail?

Track later commits until a declared horizon: explicit reverts, commits whose `Fixes:` targets this patch, related upstream/backports, changes to the same function, review discussions and available regression/test reports. Search commit linkage AND symbol/path evolution; store coverage so missed history remains visible.

- Explicit follow-up fixing the patch: observed refinement or suspected regression, with source attribution.
- Explicit revert: reverted on that branch, not automatically vulnerable everywhere.
- Test observation: record actual command, revision, config/environment and outcome; a passing regression test supports that case, not general security.
- Same-file edit or later release inclusion: context/evolution, not evidence of effectiveness.
- No follow-up located: UNKNOWN, potentially right-censored; never “mature” merely because enough days passed.

The stdlib-only local miner is `scripts/mine_evolution.py`. It emits a JSON array
of complete records accepted by `build_pack.validate`, with commit-object SHA-256
hashes, commit SHAs and changed-file pointers. It stores no upstream source or
commit prose and never fetches objects, invokes a shell or executes source data.
Use an existing repository; do not clone Linux for this command:

```sh
python3 scripts/mine_evolution.py /path/to/local/repo FULL_FIX_SHA \
  --repository-url https://example.org/project/repo --project linux \
  --ref refs/heads/main --ref refs/heads/stable --until 2026-10-31 \
  --observed-at 2026-11-02T00:00:00Z > evolution.json
```

The HTTPS URL is a provenance/discovery pointer and is never contacted. Hashes
cover the raw local Git commit payload, not bytes downloaded from that URL.
The scan pins the requested local ref tips (default `HEAD`) and runs
`git log --follow` for each fix path. Its inclusive window starts at the fix's
committer time and ends at `--until` (default latest tip date). Ancestors of the
fix are excluded; explicitly scoped sibling branches can supply backports.
`horizon_end` records the last observed relevant commit date, including the fix,
and may precede the requested cutoff. Capture time remains separate from commit
time, so consumers must enforce both for temporal evaluation.

Same-file edits become `path_followup` observations and hypothesis `changes`
edges. Messages containing Revert or Backport/cherry-pick signals are retained
as candidates. A `reverts` or `backport_of` observed edge requires an explicit
`This reverts commit <SHA>`, `Backport [of] [commit] <SHA>`, or
`(cherry picked from commit <SHA>)` reference resolving unambiguously to the fix,
as well as a shared changed file. Source statements establish `REVERTED` or
`BACKPORTED`, not empirical security effectiveness. A revert takes precedence
when both occur in scope; inspect the individual observations by branch rather
than interpreting that summary as global patch state. Other outcomes stay
`UNKNOWN`. `FIXED_STABLE` is reserved for separately supplied positive validation
and is never inferred by this miner; schema validation requires at least sourced
passing-test support for that outcome.

Coverage is `PARTIAL` for the path heuristic, or `UNKNOWN` for a fix without
changed paths. Shallow/partial-clone state, pinned tips, observation window,
path-log commands and scan errors are recorded in `validation`. Missing local
objects fail locally; failed path logs remain explicit errors. `COMPLETE_AT_HORIZON`
is deliberately not emitted: `--follow` may miss forward renames, merge history,
symbol changes and external reviews/tests. A quiet window never proves stability.
Offline synthetic Git fixtures cover these distinctions without a kernel checkout
or network access (`tests/test_mine_evolution.py`).

The causal lesson can span several commits. Version patterns and preserve superseded explanations. For time-split evaluation exclude every fact captured after the query cutoff.

## Primary references

- [Kernel CVE process](https://docs.kernel.org/process/cve.html): assignments after fixes and applicability caveats; multiple fixes may jointly solve a problem.
- [Kernel CNA repository](https://git.kernel.org/pub/scm/linux/security/vulns.git/)
- [Git rev-list](https://git-scm.com/docs/git-rev-list), [git-log](https://git-scm.com/docs/git-log)
- [GitHub commit API](https://docs.github.com/en/rest/commits/commits)
