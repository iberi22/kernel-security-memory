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

## Did the fix mature or fail?

Track later commits until a declared horizon: explicit reverts, commits whose `Fixes:` targets this patch, related upstream/backports, changes to the same function, review discussions and available regression/test reports. Search commit linkage AND symbol/path evolution; store coverage so missed history remains visible.

- Explicit follow-up fixing the patch: observed refinement or suspected regression, with source attribution.
- Explicit revert: reverted on that branch, not automatically vulnerable everywhere.
- Test observation: record actual command, revision, config/environment and outcome; a passing regression test supports that case, not general security.
- Same-file edit or later release inclusion: context/evolution, not evidence of effectiveness.
- No follow-up located: UNKNOWN, potentially right-censored; never “mature” merely because enough days passed.

The causal lesson can span several commits. Version patterns and preserve superseded explanations. For time-split evaluation exclude every fact captured after the query cutoff.

## Primary references

- [Kernel CVE process](https://docs.kernel.org/process/cve.html): assignments after fixes and applicability caveats; multiple fixes may jointly solve a problem.
- [Kernel CNA repository](https://git.kernel.org/pub/scm/linux/security/vulns.git/)
- [Git rev-list](https://git-scm.com/docs/git-rev-list), [git-log](https://git-scm.com/docs/git-log)
- [GitHub commit API](https://docs.github.com/en/rest/commits/commits)
