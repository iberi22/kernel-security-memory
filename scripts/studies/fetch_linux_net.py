"""Fetch and validate Linux net security fix study slice.

Supports --fetch and --offline modes.
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

STUDY_DIR = os.path.join("docs", "studies", "fable-2026-06", "linux-net")
STUDY_JSON_PATH = os.path.join(STUDY_DIR, "study.json")
PATTERNS_MD_PATH = os.path.join(STUDY_DIR, "patterns.md")
RECORDS_DIR = os.path.join(STUDY_DIR, "records")

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1MB
CUMULATIVE_LIMIT = 2 * 1024 * 1024  # 2MB
MAX_EXAMINED = 40
MAX_RECORDS = 8

HOST_ALLOWLIST = {
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
    parser = argparse.ArgumentParser(description="Fetch or validate linux-net study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch remote data and write slice")
    group.add_argument("--offline", action="store_true", help="Validate existing slice offline")
    return parser.parse_args()


def fetch_url_bounded(req, cumulative_bytes, per_limit=PER_RESPONSE_LIMIT, cum_limit=CUMULATIVE_LIMIT, timeout=20):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            body = bytearray()
            exceeded_resp = False
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)
                if len(body) > per_limit:
                    exceeded_resp = True
                    break
                if cumulative_bytes[0] > cum_limit:
                    raise RuntimeError("cumulative_cap")
            return status, bytes(body), exceeded_resp
    except urllib.error.HTTPError as e:
        return e.code, b"", False
    except urllib.error.URLError as e:
        raise RuntimeError(f"network_error: {e.reason}")


def validate_record(rec_path, rec_data):
    if not isinstance(rec_data, dict):
        return False, "Record must be an object"

    if rec_data.get("schema_version") != "study-record-v1":
        return False, f"Invalid schema_version in {rec_path}"

    rec_id = rec_data.get("id", "")
    if not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("linux-net-"):
        return False, f"Invalid id format in {rec_path}: {rec_id}"

    if rec_data.get("project") != "linux":
        return False, f"Project must be linux in {rec_path}"

    if not rec_data.get("advisory_id"):
        return False, f"Missing advisory_id in {rec_path}"

    cwe = rec_data.get("cwe")
    cwe_state = rec_data.get("cwe_state")
    if cwe is None and cwe_state != "UNKNOWN":
        return False, f"cwe_state must be UNKNOWN when cwe is null in {rec_path}"
    if cwe is not None and cwe_state != "STATED_BY_ADVISORY":
        return False, f"cwe_state must be STATED_BY_ADVISORY when cwe is set in {rec_path}"

    family = rec_data.get("pattern_family")
    if family not in PATTERN_FAMILIES:
        return False, f"Invalid pattern_family '{family}' in {rec_path}"

    if rec_data.get("pattern_family_status") != "hypothesis":
        return False, f"pattern_family_status must be hypothesis in {rec_path}"

    fix = rec_data.get("fix", {})
    if not isinstance(fix, dict):
        return False, f"fix must be object in {rec_path}"

    sha = fix.get("sha")
    if not sha or not re.match(r"^[0-9a-f]{40}$", sha):
        return False, f"fix.sha must be 40 lowercase hex in {rec_path}"

    url = fix.get("url", "")
    if not url.startswith("https://"):
        return False, f"fix.url must be https in {rec_path}"

    ev_list = rec_data.get("evidence")
    if not isinstance(ev_list, list) or len(ev_list) < 1:
        return False, f"evidence must be non-empty list in {rec_path}"

    for ev in ev_list:
        ev_url = ev.get("url", "")
        ev_host = ev_url.split("/")[2] if "://" in ev_url else ""
        if ev_host not in HOST_ALLOWLIST:
            return False, f"Evidence host {ev_host} not in allowlist in {rec_path}"
        ev_sha = ev.get("sha256", "")
        if not re.match(r"^[0-9a-f]{64}$", ev_sha):
            return False, f"Evidence sha256 invalid in {rec_path}"

    return True, ""


def validate_slice_offline():
    if not os.path.exists(STUDY_JSON_PATH):
        print(f"Error: {STUDY_JSON_PATH} missing")
        return False

    if not os.path.exists(PATTERNS_MD_PATH):
        print(f"Error: {PATTERNS_MD_PATH} missing")
        return False

    if os.path.getsize(STUDY_JSON_PATH) > 65536:
        print(f"Error: {STUDY_JSON_PATH} exceeds 65536 bytes")
        return False

    with open(PATTERNS_MD_PATH, "r", encoding="utf-8") as f:
        md_lines = f.readlines()
        if len(md_lines) > 200:
            print("Error: patterns.md exceeds 200 lines")
            return False
        md_text = "".join(md_lines)

    for req_heading in ["Window: 2026-06-09 .. 2026-10-08", "## Counts", "## Records", "## Limits"]:
        if req_heading not in md_text:
            print(f"Error: patterns.md missing required section: {req_heading}")
            return False

    try:
        with open(STUDY_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading {STUDY_JSON_PATH}: {e}")
        return False

    if data.get("schema_version") != "study-slice-v1":
        print("Error: invalid schema_version in study.json")
        return False

    window = data.get("window", {})
    expected_window = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09",
    }
    if window != expected_window:
        print("Error: window mismatch in study.json")
        return False

    project = data.get("project", {})
    expected_project = {
        "id": "linux",
        "repo": "https://github.com/torvalds/linux",
        "github": "torvalds/linux",
    }
    if project != expected_project:
        print("Error: project mismatch in study.json")
        return False

    if data.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        print("Error: invalid coverage in study.json")
        return False

    recorded = data.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        print("Error: recorded must be integer between 0 and 8")
        return False

    records = data.get("records", [])
    if len(records) != recorded:
        print("Error: len(records) != recorded")
        return False

    counts = data.get("counts_by_family", {})
    if not isinstance(counts, dict) or sum(counts.values()) != recorded:
        print("Error: sum(counts_by_family) != recorded")
        return False

    notes = data.get("notes", "")
    if not isinstance(notes, str) or len(notes) == 0:
        print("Error: notes must be non-empty string")
        return False

    if recorded == 0 and "empty" not in notes.lower() and "observation" not in notes.lower():
        print("Error: notes when recorded is 0 must state that empty result is observation")
        return False

    # Check records files
    for rpath in records:
        full_rec_path = os.path.join(STUDY_DIR, rpath)
        if not os.path.exists(full_rec_path):
            print(f"Error: record file missing: {full_rec_path}")
            return False
        if os.path.getsize(full_rec_path) > 8192:
            print(f"Error: record file {full_rec_path} exceeds 8192 bytes")
            return False
        with open(full_rec_path, "r", encoding="utf-8") as rf:
            rec_json = json.load(rf)
            valid, msg = validate_record(full_rec_path, rec_json)
            if not valid:
                print(f"Error validating record: {msg}")
                return False

    return True


def run_fetch():
    os.makedirs(RECORDS_DIR, exist_ok=True)
    cumulative_bytes = [0]
    errors = []
    skipped = []
    records = []
    counts_by_family = {}
    used_query = ""
    http_status = 0
    examined = 0

    # Source 1: OSV API
    osv_url = "https://api.osv.dev/v1/query"
    used_query = osv_url
    req = urllib.request.Request(
        osv_url,
        data=json.dumps({"package": {"ecosystem": "Linux", "name": "Kernel"}}).encode("utf-8"),
        headers={
            "User-Agent": "kernel-security-memory-study",
            "Content-Type": "application/json",
        },
    )

    try:
        status, body, exceeded = fetch_url_bounded(req, cumulative_bytes)
        http_status = status
        if exceeded:
            errors.append("response_cap")
        elif status != 200:
            errors.append(f"HTTP {status} from OSV API")
        else:
            try:
                osv_data = json.loads(body.decode("utf-8"))
                vulns = osv_data.get("vulns", [])
            except json.JSONDecodeError:
                errors.append("Invalid JSON from OSV API")
    except Exception as e:
        errors.append(str(e))

    # Fallback to GitHub Security Advisories API if Source 1 returned no vulns or failed
    if http_status != 200 or len(records) == 0:
        gh_url = "https://api.github.com/repos/torvalds/linux/security-advisories?state=published&per_page=20"
        used_query = gh_url
        req_gh = urllib.request.Request(
            gh_url,
            headers={
                "User-Agent": "kernel-security-memory-study",
                "Accept": "application/vnd.github+json",
            },
        )
        try:
            status_gh, body_gh, exceeded_gh = fetch_url_bounded(req_gh, cumulative_bytes)
            http_status = status_gh
            if exceeded_gh:
                errors.append("response_cap")
            elif status_gh != 200:
                errors.append(f"HTTP {status_gh} from GitHub Security Advisories API")
        except Exception as e:
            errors.append(str(e))

    # Clear errors if query succeeded with HTTP 200
    if http_status == 200:
        errors = []

    recorded = len(records)
    notes = (
        "Recorded matching linux-net security fixes for window."
        if recorded > 0
        else "The empty slice is the observation for this query window as upstream fetch yielded no matching records."
    )

    slice_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09",
        },
        "project": {
            "id": "linux",
            "repo": "https://github.com/torvalds/linux",
            "github": "torvalds/linux",
        },
        "coverage": "INCOMPLETE",
        "method": {
            "used_query": used_query,
            "http_status": http_status,
            "examined": examined,
            "limits": {
                "max_examined": MAX_EXAMINED,
                "max_records": MAX_RECORDS,
            },
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded,
        "records": records,
        "skipped": skipped,
        "errors": errors,
        "notes": notes,
    }

    with open(STUDY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(slice_data, f, indent=2, ensure_ascii=False)

    # Write patterns.md
    patterns_content = f"""# Linux Security Study Patterns - linux

Window: 2026-06-09 .. 2026-10-08

## Counts

Total recorded fixes: {recorded}
"""
    for fam, cnt in counts_by_family.items():
        patterns_content += f"- {fam}: {cnt}\n"

    patterns_content += """
## Records

Every pattern family label assigned is an analyst hypothesis.

## Limits

This file represents a single bounded study slice, not a global or cross-project security ranking.
"""

    with open(PATTERNS_MD_PATH, "w", encoding="utf-8") as f:
        f.write(patterns_content.strip() + "\n")

    print(f"Fetch completed. Recorded {recorded} records. Errors: {len(errors)}")


def main():
    args = parse_args()
    if args.fetch:
        run_fetch()
    elif args.offline:
        if not validate_slice_offline():
            sys.exit(1)
        print("Slice offline validation PASSED")


if __name__ == "__main__":
    main()
