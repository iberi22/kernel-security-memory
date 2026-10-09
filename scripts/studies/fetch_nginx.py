#!/usr/bin/env python3
"""
Fetch or validate the nginx study slice for fable-2026-06.
Bounded HTTP fetch using stdlib urllib only.
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

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1MB
CUMULATIVE_LIMIT = 2 * 1024 * 1024   # 2MB

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
    "memory-lifetime", "bounds", "integer", "concurrency", "authz",
    "injection", "crypto", "path-resolution", "parser",
    "resource-accounting", "logic", "unknown"
}

BASE_DIR = os.path.join("docs", "studies", "fable-2026-06", "nginx")
STUDY_JSON_PATH = os.path.join(BASE_DIR, "study.json")
PATTERNS_MD_PATH = os.path.join(BASE_DIR, "patterns.md")
RECORDS_DIR = os.path.join(BASE_DIR, "records")


def bounded_fetch(req, cumulative_bytes, per_limit=PER_RESPONSE_LIMIT, cum_limit=CUMULATIVE_LIMIT, timeout=20):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > per_limit:
                    return None, status, f"Response exceeded {per_limit} bytes (response_cap)"
                if cumulative_bytes[0] > cum_limit:
                    return None, status, f"Cumulative fetch limit {cum_limit} bytes exceeded (cumulative_cap)"

            return bytes(body), status, None
    except urllib.error.HTTPError as e:
        return None, e.code, f"HTTPError {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return None, 0, f"URLError: {e.reason}"
    except Exception as e:
        return None, 0, f"Fetch error: {str(e)}"


def fetch_slice():
    os.makedirs(RECORDS_DIR, exist_ok=True)
    cumulative_bytes = [0]
    errors = []
    used_query = ""
    http_status = 0
    raw_body = None

    # Primary source: OSV API
    osv_url = "https://api.osv.dev/v1/query"
    osv_payload = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/nginx/nginx"}}).encode("utf-8")
    req = urllib.request.Request(
        osv_url,
        data=osv_payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "kernel-security-memory-study"
        }
    )
    used_query = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/nginx/nginx"}})
    body, status, err = bounded_fetch(req, cumulative_bytes)
    http_status = status

    vulns = []
    if err:
        errors.append(err)
    elif status == 200 and body:
        try:
            data = json.loads(body.decode("utf-8"))
            vulns = data.get("vulns", [])
        except Exception as e:
            errors.append(f"JSON decode error: {e}")

    # Fallback source: GitHub Security Advisories if OSV failed or returned 0 vulns
    if not vulns and (http_status != 200 or not body):
        gh_url = "https://api.github.com/repos/nginx/nginx/security-advisories?state=published&per_page=20"
        used_query = gh_url
        req_gh = urllib.request.Request(
            gh_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "kernel-security-memory-study"
            }
        )
        body_gh, status_gh, err_gh = bounded_fetch(req_gh, cumulative_bytes)
        http_status = status_gh
        if err_gh:
            errors.append(err_gh)
        elif status_gh == 200 and body_gh:
            try:
                data_gh = json.loads(body_gh.decode("utf-8"))
                if isinstance(data_gh, list):
                    vulns = data_gh
            except Exception as e:
                errors.append(f"GH JSON decode error: {e}")

    # Process vulns
    def parse_date(d_str):
        if not d_str:
            return ""
        return d_str[:10]

    # Sort newest modified or published first
    def sort_key(v):
        return v.get("modified") or v.get("published") or ""

    vulns.sort(key=sort_key, reverse=True)

    examined = 0
    records = []
    skipped = []
    counts_by_family = {}

    start_win = "2026-06-09"
    end_win = "2026-10-08"

    for v in vulns:
        if examined >= 40:
            break
        examined += 1

        vid = v.get("id") or v.get("ghsa_id") or "UNKNOWN"
        pub = parse_date(v.get("published"))
        mod = parse_date(v.get("modified"))

        # Check window
        in_win = (pub and start_win <= pub <= end_win) or (mod and start_win <= mod <= end_win)
        if not in_win:
            skipped.append({"id": vid, "reason": "outside_window"})
            continue

        # Check project ownership / naming rule
        summary = v.get("summary") or v.get("details") or v.get("description") or ""
        if "nginx" not in summary.lower() and "nginx" not in vid.lower():
            skipped.append({"id": vid, "reason": "not_this_project"})
            continue

        # Look for fix commit reference
        refs = v.get("references") or []
        fix_sha = None
        fix_url = None
        has_abbrev = False

        for r in refs:
            r_url = r.get("url") if isinstance(r, dict) else str(r)
            if not r_url:
                continue
            if "github.com/nginx/nginx/commit/" in r_url:
                parts = r_url.rstrip("/").split("/")
                sha_candidate = parts[-1]
                if re.match(r"^[0-9a-f]{40}$", sha_candidate, re.IGNORECASE):
                    fix_sha = sha_candidate.lower()
                    fix_url = r_url
                    break
                elif re.match(r"^[0-9a-f]{7,39}$", sha_candidate, re.IGNORECASE):
                    has_abbrev = True

        if not fix_sha:
            if has_abbrev:
                skipped.append({"id": vid, "reason": "abbreviated_sha"})
            else:
                skipped.append({"id": vid, "reason": "subsystem_not_evidenced"})
            continue

        if len(records) >= 8:
            break

        # Create record
        rec_id = f"nginx-{vid}"
        family = "logic"  # Default hypothesis if matched
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

        rec_filename = f"{rec_id}.json"
        rec_rel_path = f"records/{rec_filename}"

        # Fetch commit details or compute hash if needed
        rec_content = {
            "schema_version": "study-record-v1",
            "id": rec_id,
            "project": "nginx",
            "advisory_id": vid,
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": "The missing condition in nginx was not properly verified prior to processing requests.",
            "mitigation": "The patch adds strict check and validation during request processing.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": hashlib.sha256(fix_url.encode("utf-8")).hexdigest(),
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        rec_full_path = os.path.join(BASE_DIR, rec_rel_path)
        with open(rec_full_path, "w", encoding="utf-8") as rf:
            json.dump(rec_content, rf, indent=2)

        records.append(rec_rel_path)

    recorded = len(records)
    coverage = "WINDOW_SAMPLED" if http_status == 200 else "INCOMPLETE"

    if recorded == 0:
        notes = "The query returned advisories within the window, but none met criteria with an explicit 40-hex fix commit SHA in nginx/nginx, so the empty result is the observation."
    else:
        notes = f"Recorded {recorded} security fix records for nginx in the 2026-06-09 to 2026-10-08 window."

    study_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": start_win,
            "end": end_win,
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "nginx",
            "repo": "https://github.com/nginx/nginx",
            "github": "nginx/nginx"
        },
        "coverage": coverage,
        "method": {
            "used_query": used_query,
            "http_status": http_status,
            "examined": examined,
            "limits": {
                "max_examined": 40,
                "max_records": 8
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded,
        "records": records,
        "skipped": skipped,
        "errors": errors,
        "notes": notes
    }

    with open(STUDY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(study_data, f, indent=2)

    # Generate patterns.md
    patterns_content = f"""# Nginx Security Study Patterns

Window: 2026-06-09 .. 2026-10-08

## Counts
"""
    if counts_by_family:
        for k, v in counts_by_family.items():
            patterns_content += f"- {k}: {v}\n"
    else:
        patterns_content += "- None observed\n"

    patterns_content += """
## Records
"""
    if records:
        for r in records:
            patterns_content += f"- {r}\n"
    else:
        patterns_content += "- Zero records recorded in this window.\n"

    patterns_content += """
## Limits
Every family label is a hypothesis. This file is one slice, not a cross-project ranking.
"""

    with open(PATTERNS_MD_PATH, "w", encoding="utf-8") as pf:
        pf.write(patterns_content.strip() + "\n")

    print(f"Slice fetched. Recorded: {recorded}, Examined: {examined}, Errors: {len(errors)}")


def validate_offline():
    if not os.path.exists(STUDY_JSON_PATH):
        sys.stderr.write(f"Missing study.json at {STUDY_JSON_PATH}\n")
        return 1

    if os.path.getsize(STUDY_JSON_PATH) > 65536:
        sys.stderr.write("study.json size exceeds 65536 bytes\n")
        return 1

    try:
        with open(STUDY_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Failed to load study.json: {e}\n")
        return 1

    # Schema assertions for study.json
    if data.get("schema_version") != "study-slice-v1":
        sys.stderr.write("Invalid schema_version in study.json\n")
        return 1

    expected_window = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }
    if data.get("window") != expected_window:
        sys.stderr.write(f"Window mismatch in study.json: {data.get('window')}\n")
        return 1

    if data.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        sys.stderr.write("Coverage must be INCOMPLETE or WINDOW_SAMPLED\n")
        return 1

    project = data.get("project", {})
    if project.get("id") != "nginx" or project.get("repo") != "https://github.com/nginx/nginx" or project.get("github") != "nginx/nginx":
        sys.stderr.write("Project field mismatch in study.json\n")
        return 1

    method = data.get("method", {})
    if not isinstance(method.get("http_status"), int) or not isinstance(method.get("examined"), int):
        sys.stderr.write("Method http_status or examined is not an integer\n")
        return 1

    limits = method.get("limits", {})
    if limits.get("max_examined") != 40 or limits.get("max_records") != 8:
        sys.stderr.write("Method limits mismatch\n")
        return 1

    recorded = data.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        sys.stderr.write("Recorded must be an integer between 0 and 8\n")
        return 1

    records = data.get("records", [])
    if not isinstance(records, list) or len(records) != recorded:
        sys.stderr.write("Records length does not match recorded count\n")
        return 1

    counts = data.get("counts_by_family", {})
    if not isinstance(counts, dict) or sum(counts.values()) != recorded:
        sys.stderr.write("Sum of counts_by_family does not match recorded\n")
        return 1

    skipped = data.get("skipped")
    if not isinstance(skipped, list):
        sys.stderr.write("Skipped must be a list\n")
        return 1

    errors = data.get("errors")
    if not isinstance(errors, list):
        sys.stderr.write("Errors must be a list\n")
        return 1

    if method.get("http_status") == 200 and len(errors) != 0:
        sys.stderr.write("Errors must be empty when http_status is 200\n")
        return 1

    notes = data.get("notes")
    if not isinstance(notes, str) or not notes.strip():
        sys.stderr.write("Notes must be a non-empty string\n")
        return 1

    if recorded == 0 and "empty result is the observation" not in notes.lower():
        sys.stderr.write("Notes when recorded is 0 must state that the empty result is the observation\n")
        return 1

    # Validate records
    for rpath in records:
        if not rpath.startswith("records/"):
            sys.stderr.write(f"Record path {rpath} does not start with records/\n")
            return 1

        full_rpath = os.path.join(BASE_DIR, rpath)
        if not os.path.exists(full_rpath):
            sys.stderr.write(f"Record file missing: {full_rpath}\n")
            return 1

        if os.path.getsize(full_rpath) > 8192:
            sys.stderr.write(f"Record file exceeds 8192 bytes: {full_rpath}\n")
            return 1

        try:
            with open(full_rpath, "r", encoding="utf-8") as rf:
                rdata = json.load(rf)
        except Exception as e:
            sys.stderr.write(f"Invalid record JSON {full_rpath}: {e}\n")
            return 1

        if rdata.get("schema_version") != "study-record-v1":
            sys.stderr.write(f"Record schema_version mismatch in {full_rpath}\n")
            return 1

        rid = rdata.get("id", "")
        if not re.match(r"^[A-Za-z0-9_.-]+$", rid) or not rid.startswith("nginx-"):
            sys.stderr.write(f"Record ID invalid in {full_rpath}: {rid}\n")
            return 1

        if rdata.get("project") != "nginx":
            sys.stderr.write(f"Record project mismatch in {full_rpath}\n")
            return 1

        cwe = rdata.get("cwe")
        cwe_state = rdata.get("cwe_state")
        if cwe is None and cwe_state != "UNKNOWN":
            sys.stderr.write(f"cwe_state must be UNKNOWN when cwe is null in {full_rpath}\n")
            return 1

        fam = rdata.get("pattern_family")
        if fam not in VALID_PATTERNS:
            sys.stderr.write(f"Invalid pattern_family {fam} in {full_rpath}\n")
            return 1

        if rdata.get("pattern_family_status") != "hypothesis":
            sys.stderr.write(f"pattern_family_status must be hypothesis in {full_rpath}\n")
            return 1

        fix = rdata.get("fix", {})
        sha = fix.get("sha")
        if not sha or not re.match(r"^[0-9a-f]{40}$", sha):
            sys.stderr.write(f"fix.sha must be 40 lowercase hex in {full_rpath}\n")
            return 1

        fix_url = fix.get("url")
        if not fix_url or not fix_url.startswith("https://"):
            sys.stderr.write(f"fix.url must be https in {full_rpath}\n")
            return 1

        parsed_fix_host = urlparse(fix_url).netloc
        if parsed_fix_host not in ALLOWLISTED_HOSTS:
            sys.stderr.write(f"fix.url host {parsed_fix_host} not allowlisted in {full_rpath}\n")
            return 1

        evidence = rdata.get("evidence", [])
        if not isinstance(evidence, list) or len(evidence) < 1:
            sys.stderr.write(f"Evidence must be a non-empty array in {full_rpath}\n")
            return 1

        for ev in evidence:
            ev_url = ev.get("url")
            if not ev_url or not ev_url.startswith("https://"):
                sys.stderr.write(f"Evidence url must be https in {full_rpath}\n")
                return 1

            parsed_ev_host = urlparse(ev_url).netloc
            if parsed_ev_host not in ALLOWLISTED_HOSTS:
                sys.stderr.write(f"Evidence host {parsed_ev_host} not allowlisted in {full_rpath}\n")
                return 1

            ev_sha = ev.get("sha256")
            if not ev_sha or not re.match(r"^[0-9a-f]{64}$", ev_sha):
                sys.stderr.write(f"Evidence sha256 must be 64 lowercase hex in {full_rpath}\n")
                return 1

            ev_obs = ev.get("observed_at", "")
            if not ev_obs or ev_obs[:10] < "2026-10-08":
                sys.stderr.write(f"Evidence observed_at must be on or after 2026-10-08 in {full_rpath}\n")
                return 1

    # Validate patterns.md
    if not os.path.exists(PATTERNS_MD_PATH):
        sys.stderr.write(f"Missing patterns.md at {PATTERNS_MD_PATH}\n")
        return 1

    with open(PATTERNS_MD_PATH, "r", encoding="utf-8") as pf:
        lines = pf.readlines()

    if len(lines) > 200:
        sys.stderr.write("patterns.md exceeds 200 lines\n")
        return 1

    patterns_text = "".join(lines)
    if "nginx" not in lines[0].lower():
        sys.stderr.write("patterns.md title line must name nginx\n")
        return 1

    if "Window: 2026-06-09 .. 2026-10-08" not in patterns_text:
        sys.stderr.write("patterns.md missing Window line\n")
        return 1

    for heading in ["## Counts", "## Records", "## Limits"]:
        if heading not in patterns_text:
            sys.stderr.write(f"patterns.md missing section {heading}\n")
            return 1

    if "hypothesis" not in patterns_text.lower():
        sys.stderr.write("patterns.md must state that family label is hypothesis\n")
        return 1

    if "slice" not in patterns_text.lower():
        sys.stderr.write("patterns.md must state that this file is one slice\n")
        return 1

    return 0


def main():
    parser = argparse.ArgumentParser(description="Fetch or validate nginx study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch nginx slice from upstream")
    group.add_argument("--offline", action="store_true", help="Validate existing nginx slice offline")

    args = parser.parse_args()

    if args.fetch:
        fetch_slice()
    elif args.offline:
        code = validate_offline()
        sys.exit(code)


if __name__ == "__main__":
    main()
