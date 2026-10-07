"""Bounded immutable Linux source candidate miner.

Accepts --commit full 40-hex SHA (max 20) and --output directory.
Fetches from torvalds/linux commit API.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1MB
CUMULATIVE_LIMIT = 2 * 1024 * 1024  # 2MB

class MiningError(Exception):
    """Specific error during mining, safe to log without secrets."""
    pass

def parse_args():
    parser = argparse.ArgumentParser(description="Mine immutable Linux source candidates from GitHub.")
    parser.add_argument(
        "--commit",
        action="append",
        required=True,
        help="Full 40-hex SHA commit to fetch (can be repeated, max 20)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory (untracked) for JSON results"
    )

    args = parser.parse_args()

    if len(args.commit) > 20:
        parser.error("Maximum of 20 commits allowed.")

    for sha in args.commit:
        if not re.match(r"^[0-9a-f]{40}$", sha):
            parser.error(f"Commit must be a full 40-hex SHA: {sha}")

    return args

def fetch_commit_bounded(sha, token, cumulative_bytes, cumulative_limit=CUMULATIVE_LIMIT, per_response_limit=PER_RESPONSE_LIMIT):
    url = f"https://api.github.com/repos/torvalds/linux/commits/{sha}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "kernel-security-memory-miner")
    req.add_header("Accept", "application/vnd.github.v3+json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > per_response_limit:
                    raise MiningError(f"Response for {sha} exceeded {per_response_limit} bytes.")
                if cumulative_bytes[0] > cumulative_limit:
                    raise MiningError(f"Cumulative fetch limit {cumulative_limit} bytes exceeded.")

            return body, response.url

    except urllib.error.HTTPError as e:
        raise MiningError(f"HTTP {e.code} fetching {sha}: {e.reason}")
    except urllib.error.URLError as e:
        raise MiningError(f"Network error fetching {sha}: {e.reason}")
    except TimeoutError:
        raise MiningError(f"Timeout fetching {sha}")

def process_commit(sha, raw_body, source_url):
    raw_response_sha256 = hashlib.sha256(raw_body).hexdigest()

    try:
        data = json.loads(raw_body)
    except json.JSONDecodeError:
        raise MiningError(f"Invalid JSON response for {sha}")

    # Validation of essential fields
    if "commit" not in data or "message" not in data["commit"]:
        raise MiningError(f"Missing commit message in response for {sha}")

    if "sha" not in data or data["sha"] != sha:
        raise MiningError(f"Mismatch or missing sha for {sha}")

    parents = [p["sha"] for p in data.get("parents", []) if "sha" in p]
    sole_parent = len(parents) == 1

    message = data["commit"]["message"]

    changed_files = [f["filename"] for f in data.get("files", []) if "filename" in f]

    # Security classifier: Only explicit Fixes: trailers
    candidate_signals = []
    # e.g., Fixes: f718863aca46 ("netfilter: nft_set_rbtree: fix overlap expiration walk")
    fixes_pattern = re.compile(r"^Fixes:\s+([0-9a-f]{12,40})", re.MULTILINE)
    for match in fixes_pattern.finditer(message):
        target = match.group(1)
        candidate_signals.append({
            "type": "fixes_trailer",
            "target": target,
            "status": "NOT_CONFIRMED",
            "reason": "explicit fixes trailer found, not causal proof"
        })

    return {
        "sha": sha,
        "source_url": source_url,
        "raw_response_sha256": raw_response_sha256,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "parents": parents,
        "sole_parent": sole_parent,
        "message": message,
        "changed_files": changed_files,
        "candidate_signals": candidate_signals
    }

def main():
    args = parse_args()

    import pathlib
    output_dir = pathlib.Path(args.output)

    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
    elif not output_dir.is_dir():
        sys.exit(f"Error: Output path '{output_dir}' is not a directory.")

    token = os.environ.get("GITHUB_TOKEN")

    cumulative_bytes = [0]
    results = []
    errors = []

    for sha in args.commit:
        try:
            body, url = fetch_commit_bounded(sha, token, cumulative_bytes)
            res = process_commit(sha, body, url)
            results.append(res)
        except MiningError as e:
            errors.append(str(e))

    coverage = "COMPLETE_REQUESTED_INPUTS" if not errors else "INCOMPLETE"

    batch = {
        "coverage": coverage,
        "count": len(results),
        "errors": errors,
        "commits": results
    }

    output_file = output_dir / f"batch_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(batch, f, indent=2, ensure_ascii=False)

    print(f"Batch completed: {len(results)} successful, {len(errors)} errors.")
    print(f"Coverage: {coverage}")
    print(f"Output saved to: {output_file}")

    if errors:
        sys.exit(1)

if __name__ == "__main__":
    main()
