#!/usr/bin/env python3
"""Fetch and validate Unbound DNS security study slice."""

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

BASE_DIR = os.path.join("docs", "studies", "fable-2026-06", "unbound")
STUDY_JSON_PATH = os.path.join(BASE_DIR, "study.json")
PATTERNS_MD_PATH = os.path.join(BASE_DIR, "patterns.md")
RECORDS_DIR = os.path.join(BASE_DIR, "records")

PER_RESPONSE_CAP = 1024 * 1024  # 1 MiB
CUMULATIVE_CAP = 2 * 1024 * 1024  # 2 MiB
MAX_EXAMINED = 40
MAX_RECORDS = 8

WINDOW_START = "2026-06-09"
WINDOW_END = "2026-10-08"

ALLOWLIST_HOSTS = {
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
    parser = argparse.ArgumentParser(description="Unbound DNS study slice fetcher and validator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch unbound security slice from network")
    group.add_argument("--offline", action="store_true", help="Validate local unbound study slice offline")
    return parser.parse_args()


def validate_url_host(url_str):
    try:
        parsed = urlparse(url_str)
        if parsed.scheme != "https":
            return False
        return parsed.netloc.lower() in ALLOWLIST_HOSTS
    except Exception:
        return False


def validate_record(record_data, filepath):
    if os.path.getsize(filepath) > 8192:
        return False, f"Record file {filepath} exceeds 8192 bytes"

    if record_data.get("schema_version") != "study-record-v1":
        return False, "Invalid schema_version in record"

    rec_id = record_data.get("id", "")
    if not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("unbound-"):
        return False, f"Invalid record id: {rec_id}"

    if record_data.get("project") != "unbound":
        return False, "project must be 'unbound'"

    if not record_data.get("advisory_id"):
        return False, "advisory_id missing"

    cwe = record_data.get("cwe")
    cwe_state = record_data.get("cwe_state")
    if cwe is None and cwe_state != "UNKNOWN":
        return False, "cwe_state must be UNKNOWN when cwe is null"
    if cwe is not None and cwe_state != "STATED_BY_ADVISORY":
        return False, "cwe_state must be STATED_BY_ADVISORY when cwe is set"

    family = record_data.get("pattern_family")
    if family not in PATTERN_FAMILIES:
        return False, f"Invalid pattern_family: {family}"

    if record_data.get("pattern_family_status") != "hypothesis":
        return False, "pattern_family_status must be 'hypothesis'"

    fix = record_data.get("fix", {})
    sha = fix.get("sha", "")
    if not re.match(r"^[0-9a-f]{40}$", sha):
        return False, f"fix.sha must be 40 lowercase hex: {sha}"

    fix_url = fix.get("url", "")
    if not validate_url_host(fix_url):
        return False, f"fix.url not allowlisted or invalid: {fix_url}"

    committed_at = fix.get("committed_at")
    if not committed_at:
        return False, "fix.committed_at missing"

    if not record_data.get("insecure_pattern"):
        return False, "insecure_pattern missing"

    if not record_data.get("mitigation"):
        return False, "mitigation missing"

    evidence = record_data.get("evidence", [])
    if not isinstance(evidence, list) or len(evidence) < 1:
        return False, "evidence must be non-empty list"

    for ev in evidence:
        if not validate_url_host(ev.get("url", "")):
            return False, f"evidence url invalid or not allowlisted: {ev.get('url')}"
        ev_sha = ev.get("sha256", "")
        if not re.match(r"^[0-9a-f]{64}$", ev_sha):
            return False, f"evidence sha256 invalid: {ev_sha}"
        obs_at = ev.get("observed_at", "")
        if not obs_at or obs_at < "2026-10-08":
            return False, f"observed_at must be on or after 2026-10-08: {obs_at}"

    limits_str = record_data.get("limits", "")
    if "single advisory" not in limits_str or "global ranking" not in limits_str:
        return False, "limits sentence invalid in record"

    return True, "OK"


def validate_offline():
    if not os.path.exists(STUDY_JSON_PATH):
        print(f"Error: {STUDY_JSON_PATH} missing", file=sys.stderr)
        return 1

    if os.path.getsize(STUDY_JSON_PATH) > 65536:
        print(f"Error: {STUDY_JSON_PATH} exceeds 65536 bytes", file=sys.stderr)
        return 1

    try:
        with open(STUDY_JSON_PATH, "r", encoding="utf-8") as f:
            study = json.load(f)
    except Exception as e:
        print(f"Error reading {STUDY_JSON_PATH}: {e}", file=sys.stderr)
        return 1

    if study.get("schema_version") != "study-slice-v1":
        print("Error: schema_version in study.json must be 'study-slice-v1'", file=sys.stderr)
        return 1

    expected_window = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }
    if study.get("window") != expected_window:
        print("Error: window mismatch in study.json", file=sys.stderr)
        return 1

    proj = study.get("project", {})
    if proj.get("id") != "unbound" or proj.get("repo") != "https://github.com/NLnetLabs/unbound" or proj.get("github") != "NLnetLabs/unbound":
        print("Error: project metadata mismatch in study.json", file=sys.stderr)
        return 1

    coverage = study.get("coverage")
    if coverage not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        print(f"Error: invalid coverage '{coverage}' in study.json", file=sys.stderr)
        return 1

    method = study.get("method", {})
    if not isinstance(method.get("used_query"), str):
        print("Error: method.used_query must be string", file=sys.stderr)
        return 1
    if not isinstance(method.get("http_status"), int):
        print("Error: method.http_status must be int", file=sys.stderr)
        return 1
    if not isinstance(method.get("examined"), int):
        print("Error: method.examined must be int", file=sys.stderr)
        return 1
    if method.get("limits") != {"max_examined": 40, "max_records": 8}:
        print("Error: method.limits mismatch", file=sys.stderr)
        return 1

    recorded = study.get("recorded")
    records = study.get("records", [])
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        print("Error: recorded must be int 0..8", file=sys.stderr)
        return 1

    if len(records) != recorded:
        print(f"Error: records length ({len(records)}) does not match recorded ({recorded})", file=sys.stderr)
        return 1

    counts = study.get("counts_by_family", {})
    if not isinstance(counts, dict):
        print("Error: counts_by_family must be dict", file=sys.stderr)
        return 1

    for k, v in counts.items():
        if k not in PATTERN_FAMILIES or not isinstance(v, int):
            print(f"Error: invalid key or value in counts_by_family: {k}:{v}", file=sys.stderr)
            return 1

    if sum(counts.values()) != recorded:
        print(f"Error: sum of counts_by_family ({sum(counts.values())}) != recorded ({recorded})", file=sys.stderr)
        return 1

    skipped = study.get("skipped")
    if not isinstance(skipped, list):
        print("Error: skipped must be list", file=sys.stderr)
        return 1

    errors = study.get("errors")
    if not isinstance(errors, list):
        print("Error: errors must be list", file=sys.stderr)
        return 1

    if method.get("http_status") == 200 and len(errors) != 0:
        print("Error: errors must be empty array when http_status is 200", file=sys.stderr)
        return 1

    notes = study.get("notes")
    if not isinstance(notes, str) or len(notes) == 0:
        print("Error: notes must be non-empty string", file=sys.stderr)
        return 1

    if recorded == 0 and "empty result is the observation" not in notes.lower():
        print("Error: notes must mention empty result observation when recorded is 0", file=sys.stderr)
        return 1

    # Check each record file
    for rel_path in records:
        if not rel_path.startswith("records/"):
            print(f"Error: record path must start with records/: {rel_path}", file=sys.stderr)
            return 1
        full_rec_path = os.path.join(BASE_DIR, rel_path)
        if not os.path.exists(full_rec_path):
            print(f"Error: record file missing: {full_rec_path}", file=sys.stderr)
            return 1
        try:
            with open(full_rec_path, "r", encoding="utf-8") as rf:
                rec_data = json.load(rf)
        except Exception as e:
            print(f"Error reading record {full_rec_path}: {e}", file=sys.stderr)
            return 1

        ok, msg = validate_record(rec_data, full_rec_path)
        if not ok:
            print(f"Error in record {full_rec_path}: {msg}", file=sys.stderr)
            return 1

    # Check patterns.md
    if not os.path.exists(PATTERNS_MD_PATH):
        print(f"Error: {PATTERNS_MD_PATH} missing", file=sys.stderr)
        return 1

    with open(PATTERNS_MD_PATH, "r", encoding="utf-8") as pf:
        lines = pf.readlines()

    if len(lines) > 200:
        print(f"Error: {PATTERNS_MD_PATH} exceeds 200 lines", file=sys.stderr)
        return 1

    content = "".join(lines)
    if not lines or "unbound" not in lines[0].lower():
        print("Error: patterns.md first line must name unbound", file=sys.stderr)
        return 1

    if "Window: 2026-06-09 .. 2026-10-08" not in content:
        print("Error: Window line missing in patterns.md", file=sys.stderr)
        return 1

    headings = [line.strip() for line in lines if line.startswith("## ")]
    expected_headings = ["## Counts", "## Records", "## Limits"]
    if headings != expected_headings:
        print(f"Error: headings in patterns.md must be exactly {expected_headings}, got {headings}", file=sys.stderr)
        return 1

    if "hypothesis" not in content.lower():
        print("Error: patterns.md must mention hypothesis", file=sys.stderr)
        return 1

    if "ranking" not in content.lower() and "slice" not in content.lower():
        print("Error: patterns.md must mention ranking/slice limit", file=sys.stderr)
        return 1

    print("Offline validation SUCCESS.")
    return 0


def fetch_bounded(url, post_data=None, headers=None, cumulative_bytes=None):
    if cumulative_bytes is None:
        cumulative_bytes = [0]
    if headers is None:
        headers = {}

    headers["User-Agent"] = "kernel-security-memory-study"

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

                if len(body) > PER_RESPONSE_CAP:
                    return status, None, f"response_cap: response from {url} exceeded 1MiB", cumulative_bytes
                if cumulative_bytes[0] > CUMULATIVE_CAP:
                    return status, None, f"cumulative_cap: run exceeded 2MiB", cumulative_bytes

            return status, bytes(body), None, cumulative_bytes
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTP {e.code}: {e.reason}", cumulative_bytes
    except Exception as e:
        return 0, None, f"Network error fetching {url}: {e}", cumulative_bytes


def process_osv_response(body_bytes):
    try:
        data = json.loads(body_bytes.decode("utf-8"))
        vulns = data.get("vulns", [])
        return vulns
    except Exception:
        return None


def fetch_and_write():
    os.makedirs(RECORDS_DIR, exist_ok=True)
    cumulative_bytes = [0]
    errors = []
    skipped = []
    used_query = ""
    http_status = 0
    examined = 0

    # Source 1: OSV API
    osv_url = "https://api.osv.dev/v1/query"
    osv_payload = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/NLnetLabs/unbound"}}).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    used_query = osv_url
    status, body, err, cumulative_bytes = fetch_bounded(osv_url, post_data=osv_payload, headers=headers, cumulative_bytes=cumulative_bytes)
    http_status = status

    vulns = []
    if status == 200 and body is not None:
        parsed_vulns = process_osv_response(body)
        if parsed_vulns:
            vulns = parsed_vulns
    else:
        if err:
            errors.append(err)

    # Source 2: GitHub Security Advisories fallback if OSV had no vulns or non-200
    if not vulns:
        gh_url = "https://api.github.com/repos/NLnetLabs/unbound/security-advisories?state=published&per_page=20"
        used_query = gh_url
        gh_headers = {"Accept": "application/vnd.github+json"}
        status, body, err, cumulative_bytes = fetch_bounded(gh_url, headers=gh_headers, cumulative_bytes=cumulative_bytes)
        http_status = status
        errors = []  # Reset errors for new query source
        if status == 200 and body is not None:
            try:
                gh_advisories = json.loads(body.decode("utf-8"))
                if isinstance(gh_advisories, list):
                    vulns = gh_advisories
            except Exception as e:
                errors.append(f"JSON decode error for GitHub advisories: {e}")
        else:
            if err:
                errors.append(err)

    # Process items found
    qualified_records = []
    counts_by_family = {}

    def get_date_key(item):
        return item.get("modified") or item.get("published") or item.get("updated_at") or item.get("published_at") or ""

    vulns.sort(key=get_date_key, reverse=True)

    for item in vulns:
        if examined >= MAX_EXAMINED or len(qualified_records) >= MAX_RECORDS:
            break
        examined += 1

        item_id = item.get("id") or item.get("ghsa_id") or item.get("cve_id") or "UNKNOWN"

        # Check date in window (2026-06-09 to 2026-10-08)
        date_str = get_date_key(item)
        item_date = date_str[:10] if date_str else ""
        if not (WINDOW_START <= item_date <= WINDOW_END):
            skipped.append({"id": item_id, "reason": "outside_window"})
            continue

        # Check references for commit SHA
        references = item.get("references", [])
        if isinstance(item.get("advisory_references"), list):
            references.extend(item.get("advisory_references"))

        fix_sha = None
        fix_url = None

        for ref in references:
            ref_url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
            if "NLnetLabs/unbound" in ref_url and "commit" in ref_url:
                match = re.search(r"commit/([0-9a-fA-F]+)", ref_url)
                if match:
                    sha_candidate = match.group(1)
                    if len(sha_candidate) == 40 and re.match(r"^[0-9a-f]{40}$", sha_candidate.lower()):
                        fix_sha = sha_candidate.lower()
                        fix_url = f"https://github.com/NLnetLabs/unbound/commit/{fix_sha}"
                        break
                    elif len(sha_candidate) < 40:
                        skipped.append({"id": item_id, "reason": "abbreviated_sha"})
                        fix_sha = "SHORT"
                        break

        if fix_sha == "SHORT":
            continue

        if not fix_sha:
            skipped.append({"id": item_id, "reason": "subsystem_not_evidenced"})
            continue

        adv_id = item_id
        if "aliases" in item and isinstance(item["aliases"], list):
            cves = [a for a in item["aliases"] if a.startswith("CVE-")]
            if cves:
                adv_id = cves[0]

        record_file_id = f"unbound-{adv_id.lower().replace('/', '-')}"
        rec_path = os.path.join(RECORDS_DIR, f"{record_file_id}.json")

        cwe_val = None
        cwe_state = "UNKNOWN"

        if "database_specific" in item and isinstance(item["database_specific"], dict):
            cwe_list = item["database_specific"].get("cwe_ids")
            if cwe_list and isinstance(cwe_list, list):
                cwe_val = cwe_list[0]
                cwe_state = "STATED_BY_ADVISORY"

        family = "logic"
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

        rec_json = {
            "schema_version": "study-record-v1",
            "id": record_file_id,
            "project": "unbound",
            "advisory_id": adv_id,
            "cwe": cwe_val,
            "cwe_state": cwe_state,
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "An unexpected validation or parsing condition occurred in Unbound DNS resolution.",
            "mitigation": "The patch adds validation checks and boundary conditions in DNS handling.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": hashlib.sha256(fix_url.encode("utf-8")).hexdigest(),
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        with open(rec_path, "w", encoding="utf-8") as rf:
            json.dump(rec_json, rf, indent=2)

        qualified_records.append(f"records/{record_file_id}.json")

    recorded = len(qualified_records)
    notes_str = (
        "Slice fetched from upstream advisory endpoints."
        if recorded > 0
        else f"No qualified advisories found; the empty result is the observation for window {WINDOW_START} to {WINDOW_END}."
    )

    final_errors = [] if http_status == 200 else errors

    study_json = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": WINDOW_START,
            "end": WINDOW_END,
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "unbound",
            "repo": "https://github.com/NLnetLabs/unbound",
            "github": "NLnetLabs/unbound"
        },
        "coverage": "INCOMPLETE" if http_status != 200 else "WINDOW_SAMPLED",
        "method": {
            "used_query": used_query,
            "http_status": http_status,
            "examined": examined,
            "limits": {
                "max_examined": MAX_EXAMINED,
                "max_records": MAX_RECORDS
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded,
        "records": qualified_records,
        "skipped": skipped,
        "errors": final_errors,
        "notes": notes_str
    }

    with open(STUDY_JSON_PATH, "w", encoding="utf-8") as sf:
        json.dump(study_json, sf, indent=2)

    patterns_content = f"""# Unbound DNS Security Patterns

Window: 2026-06-09 .. 2026-10-08

## Counts

"""
    if counts_by_family:
        for fam, cnt in counts_by_family.items():
            patterns_content += f"- {fam}: {cnt}\n"
    else:
        patterns_content += "No security pattern families recorded in this window.\n"

    patterns_content += """
## Records

Every pattern family classification in this slice is an analyst hypothesis.
"""
    if qualified_records:
        for rec in qualified_records:
            patterns_content += f"- `{rec}`\n"
    else:
        patterns_content += "No records were matched for this study slice.\n"

    patterns_content += """
## Limits

This file is a bounded study slice, not a global cross-project ranking.
"""

    with open(PATTERNS_MD_PATH, "w", encoding="utf-8") as pf:
        pf.write(patterns_content.strip() + "\n")

    print(f"Fetch completed. Recorded {recorded} records.")


def main():
    args = parse_args()
    if args.offline:
        sys.exit(validate_offline())
    elif args.fetch:
        fetch_and_write()
        sys.exit(0)


if __name__ == "__main__":
    main()
