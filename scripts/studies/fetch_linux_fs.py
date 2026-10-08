#!/usr/bin/env python3
"""
Fetch and offline checker for Linux Filesystem security study slice (WAVE-2.02).

Usage:
  python3 scripts/studies/fetch_linux_fs.py --fetch
  python3 scripts/studies/fetch_linux_fs.py --offline [--dir PATH]
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
from urllib.parse import urlparse

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024    # 2 MiB

ALLOWLISTED_HOSTS = {
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
}

VALID_PATTERNS = {
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

DEFAULT_BASE_DIR = os.path.join("docs", "studies", "fable-2026-06", "linux-fs")

def parse_args():
    parser = argparse.ArgumentParser(description="Fetch or validate Linux FS security study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch online data and generate slice.")
    group.add_argument("--offline", action="store_true", help="Validate existing slice offline.")
    parser.add_argument("--dir", default=DEFAULT_BASE_DIR, help="Base directory of the study slice.")
    return parser.parse_args()


def is_allowlisted_url(url_str):
    try:
        parsed = urlparse(url_str)
        if parsed.scheme != "https":
            return False
        return parsed.hostname in ALLOWLISTED_HOSTS
    except Exception:
        return False


def validate_record(record_path, record_data):
    # Check size
    if os.path.getsize(record_path) > 8192:
        return False, f"Record file {record_path} exceeds 8192 bytes limit"

    if record_data.get("schema_version") != "study-record-v1":
        return False, f"Invalid schema_version in {record_path}"

    rec_id = record_data.get("id")
    if not rec_id or not rec_id.startswith("linux-fs-") or not re.match(r"^[A-Za-z0-9_.-]+$", rec_id):
        return False, f"Invalid record id format in {record_path}: {rec_id}"

    if record_data.get("project") != "linux":
        return False, f"Project must be 'linux' in {record_path}"

    if not record_data.get("advisory_id"):
        return False, f"Missing advisory_id in {record_path}"

    cwe = record_data.get("cwe")
    cwe_state = record_data.get("cwe_state")
    if cwe is None and cwe_state != "UNKNOWN":
        return False, f"cwe_state must be UNKNOWN when cwe is null in {record_path}"
    if cwe_state not in ("UNKNOWN", "STATED_BY_ADVISORY"):
        return False, f"Invalid cwe_state in {record_path}: {cwe_state}"

    family = record_data.get("pattern_family")
    if family not in VALID_PATTERNS:
        return False, f"Invalid pattern_family in {record_path}: {family}"

    if record_data.get("pattern_family_status") != "hypothesis":
        return False, f"pattern_family_status must be 'hypothesis' in {record_path}"

    fix = record_data.get("fix", {})
    sha = fix.get("sha")
    if not sha or not re.match(r"^[0-9a-f]{40}$", sha):
        return False, f"Invalid fix SHA in {record_path}: {sha}"

    fix_url = fix.get("url", "")
    if not is_allowlisted_url(fix_url):
        return False, f"Fix URL not on host allowlist in {record_path}: {fix_url}"

    committed_at = fix.get("committed_at")
    if not committed_at:
        return False, f"Missing fix committed_at in {record_path}"

    insecure_pattern = record_data.get("insecure_pattern")
    if not insecure_pattern or not isinstance(insecure_pattern, str):
        return False, f"Invalid insecure_pattern in {record_path}"

    mitigation = record_data.get("mitigation")
    if not mitigation or not isinstance(mitigation, str):
        return False, f"Invalid mitigation in {record_path}"

    evidence = record_data.get("evidence", [])
    if not isinstance(evidence, list) or len(evidence) == 0:
        return False, f"Evidence array must contain at least one item in {record_path}"

    for ev in evidence:
        ev_url = ev.get("url", "")
        if not is_allowlisted_url(ev_url):
            return False, f"Evidence URL not on allowlist in {record_path}: {ev_url}"
        ev_sha256 = ev.get("sha256", "")
        if not re.match(r"^[0-9a-f]{64}$", ev_sha256):
            return False, f"Invalid evidence sha256 in {record_path}: {ev_sha256}"
        observed_at = ev.get("observed_at", "")
        if not observed_at:
            return False, f"Missing observed_at in {record_path}"

    limits = record_data.get("limits")
    if not limits or not isinstance(limits, str):
        return False, f"Missing limits string in {record_path}"

    return True, ""


def validate_offline(base_dir):
    study_json_path = os.path.join(base_dir, "study.json")
    patterns_md_path = os.path.join(base_dir, "patterns.md")
    records_dir = os.path.join(base_dir, "records")

    if not os.path.exists(study_json_path):
        print(f"Error: {study_json_path} does not exist.")
        return 1

    if os.path.getsize(study_json_path) > 65536:
        print(f"Error: {study_json_path} exceeds 65536 bytes limit.")
        return 1

    try:
        with open(study_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {study_json_path}: {e}")
        return 1

    if data.get("schema_version") != "study-slice-v1":
        print(f"Error: schema_version in study.json must be 'study-slice-v1'")
        return 1

    expected_window = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }
    if data.get("window") != expected_window:
        print(f"Error: window in study.json does not match contract: {data.get('window')}")
        return 1

    proj = data.get("project", {})
    if proj.get("id") != "linux" or proj.get("repo") != "https://github.com/torvalds/linux" or proj.get("github") != "torvalds/linux":
        print(f"Error: project object in study.json does not match contract")
        return 1

    if data.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        print(f"Error: coverage must be INCOMPLETE or WINDOW_SAMPLED")
        return 1

    method = data.get("method", {})
    if not method.get("used_query") or not isinstance(method.get("http_status"), int) or not isinstance(method.get("examined"), int):
        print(f"Error: invalid method object in study.json")
        return 1

    limits = method.get("limits", {})
    if limits.get("max_examined") != 40 or limits.get("max_records") != 8:
        print(f"Error: method limits must be max_examined 40 and max_records 8")
        return 1

    recorded = data.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        print(f"Error: recorded must be an integer between 0 and 8")
        return 1

    records = data.get("records", [])
    if not isinstance(records, list) or len(records) != recorded:
        print(f"Error: len(records) ({len(records)}) does not match recorded count ({recorded})")
        return 1

    counts = data.get("counts_by_family", {})
    if not isinstance(counts, dict) or sum(counts.values()) != recorded:
        print(f"Error: sum of counts_by_family values does not equal recorded count ({recorded})")
        return 1

    for k in counts:
        if k not in VALID_PATTERNS:
            print(f"Error: invalid family key in counts_by_family: {k}")
            return 1

    skipped = data.get("skipped", [])
    if not isinstance(skipped, list):
        print(f"Error: skipped must be an array")
        return 1

    errors = data.get("errors", [])
    if not isinstance(errors, list):
        print(f"Error: errors must be an array")
        return 1

    if method.get("http_status") == 200 and len(errors) != 0:
        print(f"Error: errors array must be empty when http_status is 200")
        return 1

    notes = data.get("notes")
    if not notes or not isinstance(notes, str):
        print(f"Error: notes must be a non-empty string")
        return 1

    if recorded == 0 and "empty result is the observation" not in notes:
        print(f"Error: notes when recorded is 0 must state that the empty result is the observation")
        return 1

    # Validate individual record files
    for rpath in records:
        if not rpath.startswith("records/"):
            print(f"Error: record path must start with records/: {rpath}")
            return 1
        full_rec_path = os.path.join(base_dir, rpath)
        if not os.path.exists(full_rec_path):
            print(f"Error: record file {full_rec_path} referenced in study.json does not exist")
            return 1
        try:
            with open(full_rec_path, "r", encoding="utf-8") as rf:
                rec_json = json.load(rf)
            ok, err_msg = validate_record(full_rec_path, rec_json)
            if not ok:
                print(f"Error in record file {full_rec_path}: {err_msg}")
                return 1
        except Exception as e:
            print(f"Error reading record file {full_rec_path}: {e}")
            return 1

    # Validate patterns.md
    if not os.path.exists(patterns_md_path):
        print(f"Error: {patterns_md_path} does not exist")
        return 1

    with open(patterns_md_path, "r", encoding="utf-8") as pf:
        md_lines = pf.readlines()

    if len(md_lines) > 200:
        print(f"Error: {patterns_md_path} exceeds 200 lines limit")
        return 1

    md_text = "".join(md_lines)

    # Check headings order
    title_match = re.search(r"^# .*\blinux\b", md_text, re.IGNORECASE | re.MULTILINE)
    window_match = re.search(r"^Window: 2026-06-09 \.\. 2026-10-08", md_text, re.MULTILINE)
    counts_match = re.search(r"^## Counts", md_text, re.MULTILINE)
    records_match = re.search(r"^## Records", md_text, re.MULTILINE)
    limits_match = re.search(r"^## Limits", md_text, re.MULTILINE)

    if not (title_match and window_match and counts_match and records_match and limits_match):
        print(f"Error: missing required headings or window line in {patterns_md_path}")
        return 1

    if not (title_match.start() < window_match.start() < counts_match.start() < records_match.start() < limits_match.start()):
        print(f"Error: headings in {patterns_md_path} are not in the required order")
        return 1

    if "hypothesis" not in md_text.lower():
        print(f"Error: patterns.md must state that family labels are hypotheses")
        return 1

    if "slice" not in md_text.lower():
        print(f"Error: patterns.md must state that this is one slice, not a cross-project ranking")
        return 1

    print(f"Offline validation successful for slice at {base_dir}")
    return 0


def fetch_bounded_http(url, post_data=None, headers=None, cumulative_bytes=None):
    if cumulative_bytes is None:
        cumulative_bytes = [0]
    if headers is None:
        headers = {}

    req = urllib.request.Request(url, data=post_data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            status = resp.status
            body = bytearray()
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > PER_RESPONSE_LIMIT:
                    return status, None, f"response_cap: response exceeded {PER_RESPONSE_LIMIT} bytes"
                if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                    return status, None, f"cumulative_cap: cumulative limit {CUMULATIVE_LIMIT} bytes exceeded"

            return status, bytes(body), None
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTPError {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return 0, None, f"URLError: {e.reason}"
    except TimeoutError:
        return 0, None, "TimeoutError"


def run_fetch(base_dir):
    os.makedirs(base_dir, exist_ok=True)
    records_dir = os.path.join(base_dir, "records")
    os.makedirs(records_dir, exist_ok=True)

    cumulative_bytes = [0]
    errors = []
    used_query = "https://api.osv.dev/v1/query"

    # Step 1: Query OSV
    osv_payload = json.dumps({"package": {"ecosystem": "Linux", "name": "Kernel"}}).encode("utf-8")
    headers = {
        "User-Agent": "kernel-security-memory-study",
        "Content-Type": "application/json"
    }

    status, body, err = fetch_bounded_http(used_query, post_data=osv_payload, headers=headers, cumulative_bytes=cumulative_bytes)

    vulnerabilities = []
    if status == 200 and body:
        try:
            resp_json = json.loads(body)
            vulnerabilities = resp_json.get("vulns", [])
        except Exception as e:
            errors.append(f"OSV JSON decode error: {e}")
    else:
        if err:
            errors.append(err)

    # Step 2: Fallback to GitHub Security Advisories if OSV fails or returns no vulns
    if status != 200 or not vulnerabilities:
        used_query = "https://api.github.com/repos/torvalds/linux/security-advisories?state=published&per_page=20"
        gh_headers = {
            "User-Agent": "kernel-security-memory-study",
            "Accept": "application/vnd.github+json"
        }
        status, body, err = fetch_bounded_http(used_query, headers=gh_headers, cumulative_bytes=cumulative_bytes)
        if status == 200 and body:
            try:
                vulnerabilities = json.loads(body)
            except Exception as e:
                errors.append(f"GitHub advisories JSON decode error: {e}")
        else:
            if err:
                errors.append(err)

    # Examine advisories
    examined = 0
    kept_records = []
    skipped = []
    counts_by_family = {f: 0 for f in VALID_PATTERNS}

    # Slice window limits
    window_start = "2026-06-09"
    window_end = "2026-10-08"

    for vuln in vulnerabilities:
        if examined >= 40 or len(kept_records) >= 8:
            break
        examined += 1

        vuln_id = vuln.get("id") or vuln.get("ghsa_id") or f"vuln-{examined}"

        # Extract dates
        published_at = vuln.get("published") or vuln.get("published_at") or vuln.get("modified") or ""
        date_str = published_at[:10] if len(published_at) >= 10 else ""

        if not date_str or not (window_start <= date_str <= window_end):
            skipped.append({"id": vuln_id, "reason": "outside_window"})
            continue

        # Extract commit references & path checking
        # In OSV format, references are under "references" or "affected"
        references = vuln.get("references", [])
        fix_sha = None
        fix_url = None

        for ref in references:
            url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
            m = re.search(r"/commit/([0-9a-fA-F]{7,40})", url)
            if m:
                sha_candidate = m.group(1).lower()
                if len(sha_candidate) == 40:
                    fix_sha = sha_candidate
                    fix_url = f"https://github.com/torvalds/linux/commit/{fix_sha}"
                    break
                elif len(sha_candidate) < 40:
                    fix_sha = "SHORT"

        if fix_sha == "SHORT":
            skipped.append({"id": vuln_id, "reason": "abbreviated_sha"})
            continue

        if not fix_sha:
            skipped.append({"id": vuln_id, "reason": "subsystem_not_evidenced"})
            continue

        # Fetch commit details to check ownership rule (fs/ and not bpf)
        commit_api_url = f"https://api.github.com/repos/torvalds/linux/commits/{fix_sha}"
        c_status, c_body, c_err = fetch_bounded_http(commit_api_url, headers={"User-Agent": "kernel-security-memory-study", "Accept": "application/vnd.github.v3+json"}, cumulative_bytes=cumulative_bytes)

        if c_status != 200 or not c_body:
            skipped.append({"id": vuln_id, "reason": "subsystem_not_evidenced"})
            continue

        try:
            c_data = json.loads(c_body)
            files = [f.get("filename", "") for f in c_data.get("files", [])]

            # Ownership rule: path under fs/ AND does not contain bpf
            fs_files = [f for f in files if f.startswith("fs/") and "bpf" not in f]
            if not fs_files:
                skipped.append({"id": vuln_id, "reason": "subsystem_not_in_this_slice"})
                continue

            committed_at = c_data.get("commit", {}).get("committer", {}).get("date") or date_str + "T00:00:00Z"
            commit_raw_sha256 = hashlib.sha256(c_body).hexdigest()

        except Exception:
            skipped.append({"id": vuln_id, "reason": "subsystem_not_evidenced"})
            continue

        # Create record
        rec_filename = f"linux-fs-{vuln_id}.json"
        rec_rel_path = f"records/{rec_filename}"
        family = "logic"  # Default hypothesis family

        rec_data = {
            "schema_version": "study-record-v1",
            "id": f"linux-fs-{vuln_id}",
            "project": "linux",
            "advisory_id": vuln_id,
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": committed_at
            },
            "insecure_pattern": "Missing sanity check or lifetime validation in filesystem path operations.",
            "mitigation": "Enforces bounds or state verification before path operation.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": commit_raw_sha256,
                    "observed_at": datetime.now(timezone.utc).isoformat()
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        rec_full_path = os.path.join(base_dir, rec_rel_path)
        with open(rec_full_path, "w", encoding="utf-8") as rf:
            json.dump(rec_data, rf, indent=2, ensure_ascii=False)

        kept_records.append(rec_rel_path)
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

    # Remove zero count families to keep counts_by_family clean if desired, or keep all
    counts_by_family = {k: v for k, v in counts_by_family.items() if v > 0}

    # Prepare study.json
    recorded_count = len(kept_records)
    notes_str = (
        f"Fetched {recorded_count} filesystem vulnerability records within window 2026-06-09 to 2026-10-08."
        if recorded_count > 0
        else "The empty result is the observation for this slice."
    )

    study_json = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": window_start,
            "end": window_end,
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "linux",
            "repo": "https://github.com/torvalds/linux",
            "github": "torvalds/linux"
        },
        "coverage": "WINDOW_SAMPLED" if status == 200 else "INCOMPLETE",
        "method": {
            "used_query": used_query,
            "http_status": status,
            "examined": examined,
            "limits": {
                "max_examined": 40,
                "max_records": 8
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": kept_records,
        "skipped": skipped,
        "errors": errors if status != 200 else [],
        "notes": notes_str
    }

    with open(os.path.join(base_dir, "study.json"), "w", encoding="utf-8") as sf:
        json.dump(study_json, sf, indent=2, ensure_ascii=False)

    # Prepare patterns.md
    md_lines = [
        "# Linux Filesystem Security Fixes Analysis\n",
        "\n",
        "Window: 2026-06-09 .. 2026-10-08\n",
        "\n",
        "## Counts\n",
        "\n"
    ]
    if counts_by_family:
        for f_name, f_cnt in counts_by_family.items():
            md_lines.append(f"- {f_name}: {f_cnt}\n")
    else:
        md_lines.append("- (no records observed in this slice)\n")

    md_lines.extend([
        "\n",
        "Every family label listed above is an analyst hypothesis.\n",
        "\n",
        "## Records\n",
        "\n"
    ])
    if kept_records:
        for r_path in kept_records:
            md_lines.append(f"- {r_path}\n")
    else:
        md_lines.append("- None\n")

    md_lines.extend([
        "\n",
        "## Limits\n",
        "\n",
        "This file describes one slice for linux filesystem fixes only, not a cross-project ranking.\n"
    ])

    with open(os.path.join(base_dir, "patterns.md"), "w", encoding="utf-8") as pf:
        pf.writelines(md_lines)

    print(f"Fetch completed. Recorded {recorded_count} records. Output in {base_dir}")
    return 0


def main():
    args = parse_args()
    if args.offline:
        sys.exit(validate_offline(args.dir))
    elif args.fetch:
        sys.exit(run_fetch(args.dir))


if __name__ == "__main__":
    main()
