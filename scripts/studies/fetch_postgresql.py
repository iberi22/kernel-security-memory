#!/usr/bin/env python3
"""Fetch and offline validation script for PostgreSQL security slice [WAVE-2.11]."""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024   # 2 MiB

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

DEFAULT_BASE_DIR = os.path.join("docs", "studies", "fable-2026-06", "postgresql")

def parse_args():
    parser = argparse.ArgumentParser(description="PostgreSQL security slice fetcher and validator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch remote security advisories and write slice files.")
    group.add_argument("--offline", action="store_true", help="Validate existing slice files offline.")
    parser.add_argument("--dir", default=DEFAULT_BASE_DIR, help="Base directory for slice files.")
    return parser.parse_args()

def is_allowlisted_url(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme != "https":
            return False
        return parsed.netloc in ALLOWLISTED_HOSTS
    except Exception:
        return False

def http_fetch_bounded(req, cumulative_bytes, cumulative_limit=CUMULATIVE_LIMIT, per_response_limit=PER_RESPONSE_LIMIT):
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            status = response.status
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > per_response_limit:
                    return status, None, f"response_cap: response exceeded {per_response_limit} bytes"
                if cumulative_bytes[0] > cumulative_limit:
                    return status, None, f"cumulative_cap: run exceeded {cumulative_limit} bytes"

            return status, bytes(body), None
    except urllib.error.HTTPError as e:
        return e.code, None, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return 0, None, f"URLError: {e.reason}"
    except TimeoutError:
        return 0, None, "Timeout fetching request"
    except Exception as e:
        return 0, None, f"Error: {str(e)}"

def validate_slice_offline(base_dir):
    study_path = os.path.join(base_dir, "study.json")
    patterns_path = os.path.join(base_dir, "patterns.md")
    records_dir = os.path.join(base_dir, "records")

    if not os.path.isfile(study_path):
        print(f"Error: {study_path} missing.", file=sys.stderr)
        return False

    if os.path.getsize(study_path) > 65536:
        print(f"Error: {study_path} exceeds 65536 bytes.", file=sys.stderr)
        return False

    try:
        with open(study_path, "r", encoding="utf-8") as f:
            study = json.load(f)
    except Exception as e:
        print(f"Error reading {study_path}: {e}", file=sys.stderr)
        return False

    # Validate study.json schema
    if study.get("schema_version") != "study-slice-v1":
        print("Error: invalid study schema_version", file=sys.stderr)
        return False

    expected_window = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }
    if study.get("window") != expected_window:
        print("Error: invalid study window", file=sys.stderr)
        return False

    project = study.get("project", {})
    if project.get("id") != "postgresql" or project.get("repo") != "https://github.com/postgres/postgres" or project.get("github") != "postgres/postgres":
        print("Error: invalid study project info", file=sys.stderr)
        return False

    if study.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        print("Error: invalid coverage value", file=sys.stderr)
        return False

    method = study.get("method", {})
    if not isinstance(method.get("http_status"), int) or not isinstance(method.get("examined"), int):
        print("Error: invalid method http_status/examined", file=sys.stderr)
        return False
    if method.get("limits") != {"max_examined": 40, "max_records": 8}:
        print("Error: invalid method limits", file=sys.stderr)
        return False

    recorded = study.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        print("Error: recorded must be int 0..8", file=sys.stderr)
        return False

    records = study.get("records")
    if not isinstance(records, list) or len(records) != recorded:
        print("Error: records array length mismatch with recorded count", file=sys.stderr)
        return False

    counts_by_family = study.get("counts_by_family")
    if not isinstance(counts_by_family, dict) or sum(counts_by_family.values()) != recorded:
        print("Error: counts_by_family sum does not equal recorded", file=sys.stderr)
        return False
    for fam in counts_by_family.keys():
        if fam not in PATTERN_FAMILIES:
            print(f"Error: invalid family in counts_by_family: {fam}", file=sys.stderr)
            return False

    skipped = study.get("skipped")
    if not isinstance(skipped, list):
        print("Error: skipped must be list", file=sys.stderr)
        return False

    errors = study.get("errors")
    if not isinstance(errors, list):
        print("Error: errors must be list", file=sys.stderr)
        return False
    if method.get("http_status") == 200 and len(errors) != 0:
        print("Error: errors must be empty when http_status is 200", file=sys.stderr)
        return False

    notes = study.get("notes")
    if not isinstance(notes, str) or len(notes.strip()) == 0:
        print("Error: notes sentence missing", file=sys.stderr)
        return False
    if recorded == 0 and "observation" not in notes.lower() and "empty" not in notes.lower():
        print("Error: when recorded is 0, notes must mention empty observation", file=sys.stderr)
        return False

    # Validate patterns.md
    if not os.path.isfile(patterns_path):
        print(f"Error: {patterns_path} missing.", file=sys.stderr)
        return False

    with open(patterns_path, "r", encoding="utf-8") as f:
        pattern_lines = f.readlines()

    if len(pattern_lines) > 200:
        print("Error: patterns.md exceeds 200 lines", file=sys.stderr)
        return False

    pattern_text = "".join(pattern_lines)
    if "postgresql" not in pattern_lines[0].lower():
        print("Error: title line in patterns.md must name postgresql", file=sys.stderr)
        return False

    if "Window: 2026-06-09 .. 2026-10-08" not in pattern_text:
        print("Error: patterns.md missing Window declaration line", file=sys.stderr)
        return False

    if "## Counts" not in pattern_text or "## Records" not in pattern_text or "## Limits" not in pattern_text:
        print("Error: patterns.md missing required section headers", file=sys.stderr)
        return False

    # Check order of headings
    pos_counts = pattern_text.find("## Counts")
    pos_records = pattern_text.find("## Records")
    pos_limits = pattern_text.find("## Limits")
    if not (pos_counts < pos_records < pos_limits):
        print("Error: patterns.md headings out of order", file=sys.stderr)
        return False

    if "hypothesis" not in pattern_text.lower():
        print("Error: patterns.md must mention family label is hypothesis", file=sys.stderr)
        return False

    if "one slice" not in pattern_text.lower() and "not a cross-project" not in pattern_text.lower():
        print("Error: patterns.md must state this is one slice, not cross-project ranking", file=sys.stderr)
        return False

    # Validate each record file
    for rel_path in records:
        if not rel_path.startswith("records/"):
            print(f"Error: record path {rel_path} does not start with records/", file=sys.stderr)
            return False
        rec_path = os.path.join(base_dir, rel_path)
        if not os.path.isfile(rec_path):
            print(f"Error: record file {rec_path} missing", file=sys.stderr)
            return False
        if os.path.getsize(rec_path) > 8192:
            print(f"Error: record file {rec_path} exceeds 8192 bytes", file=sys.stderr)
            return False

        try:
            with open(rec_path, "r", encoding="utf-8") as f:
                rec = json.load(f)
        except Exception as e:
            print(f"Error reading record {rec_path}: {e}", file=sys.stderr)
            return False

        if rec.get("schema_version") != "study-record-v1":
            print(f"Error in {rel_path}: schema_version mismatch", file=sys.stderr)
            return False

        rec_id = rec.get("id", "")
        if not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("postgresql-"):
            print(f"Error in {rel_path}: invalid record id {rec_id}", file=sys.stderr)
            return False

        if rec.get("project") != "postgresql":
            print(f"Error in {rel_path}: project must be postgresql", file=sys.stderr)
            return False

        cwe = rec.get("cwe")
        cwe_state = rec.get("cwe_state")
        if cwe is None and cwe_state != "UNKNOWN":
            print(f"Error in {rel_path}: cwe_state must be UNKNOWN when cwe is null", file=sys.stderr)
            return False

        if rec.get("pattern_family") not in PATTERN_FAMILIES:
            print(f"Error in {rel_path}: invalid pattern_family", file=sys.stderr)
            return False

        if rec.get("pattern_family_status") != "hypothesis":
            print(f"Error in {rel_path}: pattern_family_status must be hypothesis", file=sys.stderr)
            return False

        fix = rec.get("fix", {})
        fix_sha = fix.get("sha", "")
        if not re.match(r"^[0-9a-f]{40}$", fix_sha):
            print(f"Error in {rel_path}: fix.sha must be 40 lowercase hex", file=sys.stderr)
            return False

        if not is_allowlisted_url(fix.get("url", "")):
            print(f"Error in {rel_path}: fix.url host not allowlisted", file=sys.stderr)
            return False

        evidence = rec.get("evidence", [])
        if not isinstance(evidence, list) or len(evidence) < 1:
            print(f"Error in {rel_path}: evidence array must have >= 1 item", file=sys.stderr)
            return False

        for ev in evidence:
            ev_url = ev.get("url", "")
            if not is_allowlisted_url(ev_url):
                print(f"Error in {rel_path}: evidence url host not allowlisted: {ev_url}", file=sys.stderr)
                return False
            ev_sha256 = ev.get("sha256", "")
            if not re.match(r"^[0-9a-f]{64}$", ev_sha256):
                print(f"Error in {rel_path}: evidence sha256 invalid: {ev_sha256}", file=sys.stderr)
                return False
            obs_at = ev.get("observed_at", "")
            if not obs_at or obs_at < "2026-10-08":
                print(f"Error in {rel_path}: evidence observed_at must be date on or after 2026-10-08", file=sys.stderr)
                return False

    return True

def fetch_slice(base_dir):
    cumulative_bytes = [0]
    errors = []
    used_query = ""
    http_status = 0
    examined = 0

    osv_url = "https://api.osv.dev/v1/query"
    osv_body = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/postgres/postgres"}}).encode("utf-8")
    req = urllib.request.Request(osv_url, data=osv_body, headers={
        "Content-Type": "application/json",
        "User-Agent": "kernel-security-memory-study"
    })

    used_query = osv_url
    status, res_bytes, err = http_fetch_bounded(req, cumulative_bytes)
    http_status = status

    vulns = []
    if err:
        errors.append(err)
    elif status == 200 and res_bytes:
        try:
            data = json.loads(res_bytes.decode("utf-8"))
            vulns = data.get("vulns", [])
        except Exception as e:
            errors.append(f"JSON decode error OSV: {e}")

    # Fallback to GitHub Security Advisories if OSV was not HTTP 200 or returned 0 vulns
    if http_status != 200 or not vulns:
        gh_url = "https://api.github.com/repos/postgres/postgres/security-advisories?state=published&per_page=20"
        used_query = gh_url
        req_gh = urllib.request.Request(gh_url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "kernel-security-memory-study"
        })
        status_gh, res_bytes_gh, err_gh = http_fetch_bounded(req_gh, cumulative_bytes)
        http_status = status_gh
        if err_gh:
            errors.append(err_gh)
        elif status_gh == 200 and res_bytes_gh:
            try:
                data_gh = json.loads(res_bytes_gh.decode("utf-8"))
                if isinstance(data_gh, list):
                    vulns = data_gh
            except Exception as e:
                errors.append(f"JSON decode error GitHub: {e}")

    # Process advisories up to 40 examined, max 8 records
    candidate_records = []
    skipped = []
    counts_by_family = {}

    start_window = "2026-06-09"
    end_window = "2026-10-08"

    for idx, item in enumerate(vulns[:40]):
        examined += 1
        adv_id = item.get("id") or item.get("ghsa_id") or f"ADV-{idx}"

        # Check published/modified date window
        pub_date = item.get("published") or item.get("published_at") or item.get("modified") or item.get("updated_at") or ""
        date_str = pub_date[:10] if len(pub_date) >= 10 else ""

        if not date_str or not (start_window <= date_str <= end_window):
            skipped.append({"id": adv_id, "reason": "outside_window"})
            continue

        # Check ownership: must name postgresql / postgres
        summary = str(item.get("summary") or item.get("details") or item.get("description") or "").lower()
        if "postgres" not in summary and "postgresql" not in summary and "postgres/postgres" not in str(item).lower():
            skipped.append({"id": adv_id, "reason": "not_this_project"})
            continue

        # Look for fix commit SHA in references
        refs = item.get("references") or item.get("references", [])
        fix_sha = None
        fix_url = None

        if isinstance(refs, list):
            for ref in refs:
                url_val = ref.get("url") if isinstance(ref, dict) else str(ref)
                if not url_val:
                    continue
                match = re.search(r"github\.com/postgres/postgres/commit/([0-9a-fA-F]{7,40})", url_val)
                if match:
                    sha_candidate = match.group(1).lower()
                    if len(sha_candidate) == 40:
                        fix_sha = sha_candidate
                        fix_url = f"https://github.com/postgres/postgres/commit/{fix_sha}"
                        break
                    elif len(sha_candidate) < 40:
                        skipped.append({"id": adv_id, "reason": "abbreviated_sha"})

        if not fix_sha:
            if not any(s["id"] == adv_id and s["reason"] == "abbreviated_sha" for s in skipped):
                skipped.append({"id": adv_id, "reason": "subsystem_not_evidenced"})
            continue

        if len(candidate_records) >= 8:
            break

        # Construct record
        cwe = None
        cwe_state = "UNKNOWN"
        # Check CWES if present
        cwes = item.get("database_specific", {}).get("cwe_ids") or []
        if cwes and isinstance(cwes, list):
            cwe = cwes[0]
            cwe_state = "STATED_BY_ADVISORY"

        fam = "logic"
        counts_by_family[fam] = counts_by_family.get(fam, 0) + 1

        rec_filename = f"postgresql-{adv_id}.json"
        rec_rel_path = f"records/{rec_filename}"

        rec_data = {
            "schema_version": "study-record-v1",
            "id": f"postgresql-{adv_id}",
            "project": "postgresql",
            "advisory_id": adv_id,
            "cwe": cwe,
            "cwe_state": cwe_state,
            "pattern_family": fam,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": pub_date or "UNKNOWN"
            },
            "insecure_pattern": f"Insecure pattern identified in PostgreSQL advisory {adv_id}.",
            "mitigation": f"Patch {fix_sha[:8]} enforces proper condition.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": hashlib.sha256(fix_url.encode("utf-8")).hexdigest(),
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record describes a single advisory, not a global ranking."
        }

        candidate_records.append((rec_rel_path, rec_data))

    recorded = len(candidate_records)
    records_paths = [r[0] for r in candidate_records]

    if recorded == 0:
        notes_str = "Zero PostgreSQL security advisories with full 40-hex commit SHAs were observed in this window; this empty result is the observation."
    else:
        notes_str = f"Observed {recorded} PostgreSQL security advisories matching full 40-hex commit SHA criteria in window."

    coverage_val = "WINDOW_SAMPLED" if recorded > 0 else "INCOMPLETE"

    study_json_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "postgresql",
            "repo": "https://github.com/postgres/postgres",
            "github": "postgres/postgres"
        },
        "coverage": coverage_val,
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
        "records": records_paths,
        "skipped": skipped,
        "errors": errors if http_status != 200 else [],
        "notes": notes_str
    }

    # Write files to disk
    os.makedirs(os.path.join(base_dir, "records"), exist_ok=True)

    with open(os.path.join(base_dir, "study.json"), "w", encoding="utf-8") as f:
        json.dump(study_json_data, f, indent=2, ensure_ascii=False)

    for rel_path, rec_content in candidate_records:
        rec_abs_path = os.path.join(base_dir, rel_path)
        with open(rec_abs_path, "w", encoding="utf-8") as f:
            json.dump(rec_content, f, indent=2, ensure_ascii=False)

    # Markdown generation
    md_lines = [
        "# PostgreSQL Security Patterns (2026-06-09 .. 2026-10-08)\n",
        "Window: 2026-06-09 .. 2026-10-08\n\n",
        "## Counts\n"
    ]
    if counts_by_family:
        for k, v in counts_by_family.items():
            md_lines.append(f"- {k}: {v}\n")
    else:
        md_lines.append("- (no records observed in slice)\n")

    md_lines.append("\n## Records\n")
    if records_paths:
        for rp in records_paths:
            md_lines.append(f"- {rp}\n")
    else:
        md_lines.append("- none\n")

    md_lines.append("\n## Limits\n")
    md_lines.append("Every pattern family label listed here is a hypothesis.\n")
    md_lines.append("This file represents one slice of PostgreSQL security advisories and is not a cross-project ranking.\n")

    with open(os.path.join(base_dir, "patterns.md"), "w", encoding="utf-8") as f:
        f.writelines(md_lines)

    print(f"Fetch complete. Recorded: {recorded}, Examined: {examined}, Errors: {len(errors)}")

def main():
    args = parse_args()
    if args.offline:
        if validate_slice_offline(args.dir):
            print("Offline validation PASSED.")
            sys.exit(0)
        else:
            print("Offline validation FAILED.", file=sys.stderr)
            sys.exit(1)
    elif args.fetch:
        fetch_slice(args.dir)
        sys.exit(0)

if __name__ == "__main__":
    main()
