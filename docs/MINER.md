# Kernel Security Memory Miner

The `scripts/mine_candidates.py` tool is a bounded immutable Linux source candidate miner. It targets the GitHub REST API to securely fetch commit metadata without downloading or compiling the entire Linux repository.

## Usage

```sh
python3 scripts/mine_candidates.py \
    --commit 60c0c230c6f046da536d3df8b39a20b9a9fd6af0 \
    --output candidates_out
```

- `--commit`: A full 40-hex SHA to fetch. You can specify this argument multiple times (max 20 commits per run).
- `--output`: The untracked directory where the batch JSON file will be written.

The miner respects an optional `GITHUB_TOKEN` environment variable to authenticate requests, but ensures this token is never logged or exposed in error messages.

## Behavior & Limits

- **Bounded Fetching:** Fetching operates on a chunked streaming basis with explicit bounds (e.g., 1MB per-response, 2MB cumulative limits). This prevents oversized responses from causing memory overreads.
- **Offline & Immutable Strategy:** Instead of cloning or compiling the kernel, the miner processes raw GitHub JSON responses. It captures a `raw_response_sha256` for integrity and fully separates the extraction logic from HTTP calls, enabling deterministic offline tests.
- **Anti-Hallucination & Evidence First:**
  - The miner does not attempt to invent CVE bindings or establish unproven causal edges.
  - When extracting `Fixes:` trailers, it flags the relation as `NOT_CONFIRMED`.
  - An incomplete run (e.g. rate-limiting or network error) will accurately reflect its `coverage` as `INCOMPLETE` rather than silently dropping failures.
  - Success is explicit: only runs completing all requests emit `COMPLETE_REQUESTED_INPUTS`.
