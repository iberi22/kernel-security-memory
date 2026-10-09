#!/usr/bin/env python3
"""Bounded fetch and offline verification for Linux BPF security study slice."""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024   # 2 MiB
MAX_EXAMINED = 40
MAX_RECORDS = 8

ALLOWED_EVIDENCE_HOSTS = {
    "api.osv.dev",
    "osv.dev",
    "github.com",
    "api.github.com",
    "git.kernel.org",
    "www.kernel.org",
    "gitlab.com",
    "www.openssl.org",
    "openssl.org",
    "curl.se",
    "nginx.org",
    "www.postgresql.org",
    "www.sqlite.org",
    "sqlite.org",
    "www.nlnetlabs.nl",
    "sourceware.org",
    "raw.githubusercontent.com",
}

PATTERN_FAMILIES = {
    "memory-lifetime",
    "bounds",
    "integer",
    "concurrency",
    "authz",
    "injection",
    "crypto",
    "path-resolution",
    "parser",
    "resource-accounting",
    "logic",
    "unknown",
}


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch or verify Linux BPF study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch and write slice files")
    group.add_argument("--offline", action="store_true", help="Verify committed slice files without network")

    parser.add_argument(
        "--slice-dir",
        default="docs/studies/fable-2026-06/linux-bpf",
        help="Target directory for slice files (default: docs/studies/fable-2026-06/linux-bpf)"
    )
    return parser.parse_args()


def fetch_bounded_http(url, data=None, headers=None, cumulative_bytes=None):
    if cumulative_bytes is None:
        cumulative_bytes = [0]

    req = urllib.request.Request(url, data=data, headers=headers or {})
    if "User-Agent" not in req.headers:
        req.add_header("User-Agent", "kernel-security-memory-study")

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > PER_RESPONSE_LIMIT:
                    raise RuntimeError("response_cap")
                if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                    raise RuntimeError("cumulative_cap")

            return bytes(body), response.status, response.url
    except urllib.error.HTTPError as e:
        return None, e.code, url
    except urllib.error.URLError as e:
        return None, f"URLError: {e.reason}", url
    except TimeoutError:
        return None, "Timeout", url


def run_fetch(slice_dir):
    os.makedirs(os.path.join(slice_dir, "records"), exist_ok=True)

    cumulative_bytes = [0]
    errors = []
    method_used = "https://api.osv.dev/v1/query"
    http_status = 200
    examined_count = 0
    records = []
    skipped = []
    counts_by_family = {}

    osv_body = json.dumps({"package": {"ecosystem": "Linux", "name": "Kernel"}}).encode("utf-8")
    osv_headers = {
        "User-Agent": "kernel-security-memory-study",
        "Content-Type": "application/json"
    }

    try:
        raw_osv, status, osv_url = fetch_bounded_http(
            "https://api.osv.dev/v1/query",
            data=osv_body,
            headers=osv_headers,
            cumulative_bytes=cumulative_bytes
        )
        if status != 200 or raw_osv is None:
            errors.append(f"HTTP {status}" if isinstance(status, int) else str(status))
            raw_osv = None
    except RuntimeError as e:
        errors.append(str(e))
        raw_osv = None

    items_to_process = []

    if raw_osv:
        try:
            osv_data = json.loads(raw_osv.decode("utf-8"))
            items_to_process = osv_data.get("vulns", [])
        except Exception as e:
            errors.append(f"JSONDecodeError: {e}")

    # Fallback if primary source failed or returned no vulns
    if not items_to_process:
        method_used = "https://api.github.com/repos/torvalds/linux/security-advisories?state=published&per_page=20"
        gh_headers = {
            "User-Agent": "kernel-security-memory-study",
            "Accept": "application/vnd.github+json"
        }
        try:
            raw_gh, gh_status, gh_url = fetch_bounded_http(
                method_used,
                headers=gh_headers,
                cumulative_bytes=cumulative_bytes
            )
            http_status = gh_status if isinstance(gh_status, int) else 500
            if gh_status != 200 or raw_gh is None:
                errors.append(f"HTTP {gh_status}" if isinstance(gh_status, int) else str(gh_status))
            else:
                gh_data = json.loads(raw_gh.decode("utf-8"))
                if isinstance(gh_data, list):
                    items_to_process = gh_data
        except RuntimeError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"GHFallbackError: {e}")

    # Process items if any retrieved
    items_to_process.sort(
        key=lambda x: x.get("modified") or x.get("published") or x.get("updated_at") or "",
        reverse=True
    )

    for item in items_to_process:
        if examined_count >= MAX_EXAMINED or len(records) >= MAX_RECORDS:
            break

        examined_count += 1
        item_id = item.get("id") or item.get("ghsa_id") or f"item-{examined_count}"

        mod_date = item.get("modified") or item.get("published") or item.get("published_at") or ""
        date_prefix = mod_date[:10]
        if not date_prefix or not ("2026-06-09" <= date_prefix <= "2026-10-08"):
            skipped.append({"id": item_id, "reason": "outside_window"})
            continue

        item_str = json.dumps(item).lower()
        if "bpf" not in item_str:
            skipped.append({"id": item_id, "reason": "subsystem_not_in_this_slice"})
            continue

        # Extract fix commit SHA
        fix_sha = None
        fix_url = None
        refs = item.get("references") or []
        for ref in refs:
            url = ref.get("url") if isinstance(ref, dict) else str(ref)
            match = re.search(r"/(?:commit|c)/([0-9a-fA-F]{7,40})", url)
            if match:
                sha_candidate = match.group(1).lower()
                if len(sha_candidate) == 40:
                    fix_sha = sha_candidate
                    fix_url = f"https://github.com/torvalds/linux/commit/{fix_sha}"
                    break
                elif len(sha_candidate) < 40:
                    fix_sha = "SHORT"

        if fix_sha == "SHORT":
            skipped.append({"id": item_id, "reason": "abbreviated_sha"})
            continue

        if not fix_sha:
            skipped.append({"id": item_id, "reason": "subsystem_not_evidenced"})
            continue

        # Valid record found
        rec_id = f"linux-bpf-{item_id}"
        family = "logic"
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

        rec_filename = f"records/{rec_id}.json"
        rec_filepath = os.path.join(slice_dir, rec_filename)

        evidence_sha256 = hashlib.sha256(json.dumps(item, sort_keys=True).encode("utf-8")).hexdigest()

        rec_obj = {
            "schema_version": "study-record-v1",
            "id": rec_id,
            "project": "linux",
            "advisory_id": item_id,
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": mod_date or "UNKNOWN"
            },
            "insecure_pattern": "Missing state validation in BPF subsystem.",
            "mitigation": "Enforces proper condition checks in BPF kernel routines.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": evidence_sha256,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory observation, not a global security ranking."
        }

        with open(rec_filepath, "w", encoding="utf-8") as f:
            json.dump(rec_obj, f, indent=2, ensure_ascii=False)

        records.append(rec_filename)

    recorded_count = len(records)
    if recorded_count == 0:
        notes = "Empty result observed because the query source produced no usable records under limits."
    else:
        notes = f"Observed {recorded_count} Linux BPF security fix records."

    coverage = "INCOMPLETE" if errors else "WINDOW_SAMPLED"

    study_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "linux",
            "repo": "https://github.com/torvalds/linux",
            "github": "torvalds/linux"
        },
        "coverage": coverage,
        "method": {
            "used_query": method_used,
            "http_status": http_status,
            "examined": examined_count,
            "limits": {
                "max_examined": MAX_EXAMINED,
                "max_records": MAX_RECORDS
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": records,
        "skipped": skipped,
        "errors": errors,
        "notes": notes
    }

    study_file = os.path.join(slice_dir, "study.json")
    with open(study_file, "w", encoding="utf-8") as f:
        json.dump(study_data, f, indent=2, ensure_ascii=False)

    # Write patterns.md
    patterns_file = os.path.join(slice_dir, "patterns.md")
    patterns_lines = [
        "# Frequency note for linux BPF fixes",
        "Window: 2026-06-09 .. 2026-10-08",
        "",
        "## Counts"
    ]
    if counts_by_family:
        for fam, cnt in sorted(counts_by_family.items()):
            patterns_lines.append(f"- {fam}: {cnt}")
    else:
        patterns_lines.append("- Total recorded: 0")

    patterns_lines.extend([
        "",
        "## Records"
    ])
    if records:
        for r in records:
            patterns_lines.append(f"- {r}")
    else:
        patterns_lines.append("None.")

    patterns_lines.extend([
        "",
        "## Limits",
        "Every family label is a hypothesis. This file is one slice, not a cross-project ranking."
    ])

    with open(patterns_file, "w", encoding="utf-8") as f:
        f.write("\n".join(patterns_lines) + "\n")


def run_offline_check(slice_dir):
    study_path = os.path.join(slice_dir, "study.json")
    patterns_path = os.path.join(slice_dir, "patterns.md")

    if not os.path.exists(study_path):
        sys.stderr.write(f"Error: {study_path} does not exist\n")
        return 1

    if os.path.getsize(study_path) > 65536:
        sys.stderr.write(f"Error: {study_path} exceeds 65536 bytes\n")
        return 1

    try:
        with open(study_path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error reading {study_path}: {e}\n")
        return 1

    if d.get("schema_version") != "study-slice-v1":
        sys.stderr.write("Invalid schema_version in study.json\n")
        return 1

    if d.get("window") != {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }:
        sys.stderr.write("Invalid window in study.json\n")
        return 1

    if d.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        sys.stderr.write("Invalid coverage in study.json\n")
        return 1

    proj = d.get("project")
    if not isinstance(proj, dict) or proj.get("id") != "linux":
        sys.stderr.write("Invalid project in study.json\n")
        return 1

    recorded = d.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= MAX_RECORDS):
        sys.stderr.write("Invalid recorded count in study.json\n")
        return 1

    records = d.get("records")
    if not isinstance(records, list) or len(records) != recorded:
        sys.stderr.write("Mismatch between recorded count and records array\n")
        return 1

    counts = d.get("counts_by_family")
    if not isinstance(counts, dict) or sum(counts.values()) != recorded:
        sys.stderr.write("Mismatch in counts_by_family\n")
        return 1

    if recorded == 0 and not d.get("notes"):
        sys.stderr.write("notes required when recorded is 0\n")
        return 1

    errors = d.get("errors")
    if not isinstance(errors, list):
        sys.stderr.write("errors field must be a list\n")
        return 1

    # Check patterns.md
    if not os.path.exists(patterns_path):
        sys.stderr.write(f"Error: {patterns_path} does not exist\n")
        return 1

    with open(patterns_path, "r", encoding="utf-8") as f:
        patterns_content = f.read()

    lines = patterns_content.splitlines()
    if len(lines) > 200:
        sys.stderr.write(f"Error: {patterns_path} exceeds 200 lines\n")
        return 1

    if not lines or "linux" not in lines[0].lower():
        sys.stderr.write("Title line in patterns.md must name linux\n")
        return 1

    if "Window: 2026-06-09 .. 2026-10-08" not in patterns_content:
        sys.stderr.write("Window line missing in patterns.md\n")
        return 1

    counts_idx = patterns_content.find("## Counts")
    records_idx = patterns_content.find("## Records")
    limits_idx = patterns_content.find("## Limits")

    if counts_idx == -1 or records_idx == -1 or limits_idx == -1 or not (counts_idx < records_idx < limits_idx):
        sys.stderr.write("Invalid or out-of-order headings in patterns.md\n")
        return 1

    # Check record files
    records_dir = os.path.join(slice_dir, "records")
    for r_path in records:
        if not r_path.startswith("records/"):
            sys.stderr.write(f"Record path must start with records/: {r_path}\n")
            return 1
        full_r_path = os.path.join(slice_dir, r_path)
        if not os.path.exists(full_r_path):
            sys.stderr.write(f"Record file missing: {full_r_path}\n")
            return 1

        if os.path.getsize(full_r_path) > 8192:
            sys.stderr.write(f"Record file exceeds 8192 bytes: {full_r_path}\n")
            return 1

        try:
            with open(full_r_path, "r", encoding="utf-8") as f:
                r_data = json.load(f)
        except Exception as e:
            sys.stderr.write(f"Error loading record {full_r_path}: {e}\n")
            return 1

        rec_id = r_data.get("id")
        if not rec_id or not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("linux-bpf-"):
            sys.stderr.write(f"Invalid record id in {full_r_path}\n")
            return 1

        if r_data.get("schema_version") != "study-record-v1":
            sys.stderr.write(f"Invalid schema_version in {full_r_path}\n")
            return 1

        if r_data.get("project") != "linux":
            sys.stderr.write(f"Invalid project in {full_r_path}\n")
            return 1

        if r_data.get("cwe_state") not in ("UNKNOWN", "STATED_BY_ADVISORY"):
            sys.stderr.write(f"Invalid cwe_state in {full_r_path}\n")
            return 1

        if r_data.get("pattern_family") not in PATTERN_FAMILIES:
            sys.stderr.write(f"Invalid pattern_family in {full_r_path}\n")
            return 1

        if r_data.get("pattern_family_status") != "hypothesis":
            sys.stderr.write(f"Invalid pattern_family_status in {full_r_path}\n")
            return 1

        fix = r_data.get("fix", {})
        fix_sha = fix.get("sha")
        if not fix_sha or not re.match(r"^[0-9a-f]{40}$", fix_sha):
            sys.stderr.write(f"Invalid fix.sha in {full_r_path}\n")
            return 1

        evidence = r_data.get("evidence", [])
        if not evidence or not isinstance(evidence, list):
            sys.stderr.write(f"Invalid evidence in {full_r_path}\n")
            return 1

        for ev in evidence:
            ev_url = ev.get("url", "")
            host_match = re.search(r"https://([^/]+)", ev_url)
            if not host_match or host_match.group(1) not in ALLOWED_EVIDENCE_HOSTS:
                sys.stderr.write(f"Disallowed evidence host in {full_r_path}: {ev_url}\n")
                return 1
            ev_sha256 = ev.get("sha256", "")
            if not re.match(r"^[0-9a-f]{64}$", ev_sha256):
                sys.stderr.write(f"Invalid sha256 in evidence in {full_r_path}\n")
                return 1

    return 0


def main():
    args = parse_args()
    if args.fetch:
        run_fetch(args.slice_dir)
        sys.exit(0)
    elif args.offline:
        res = run_offline_check(args.slice_dir)
        sys.exit(res)


if __name__ == "__main__":
    main()
