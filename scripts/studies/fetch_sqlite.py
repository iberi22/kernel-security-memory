#!/usr/bin/env python3
"""Bounded SQLite security fix study fetcher and offline validator.

Usage:
  python3 scripts/studies/fetch_sqlite.py --fetch
  python3 scripts/studies/fetch_sqlite.py --offline
"""

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

ALLOWED_HOSTS = {
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

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024    # 2 MiB

BASE_DIR = os.path.join("docs", "studies", "fable-2026-06", "sqlite")
STUDY_JSON_PATH = os.path.join(BASE_DIR, "study.json")
PATTERNS_MD_PATH = os.path.join(BASE_DIR, "patterns.md")
RECORDS_DIR = os.path.join(BASE_DIR, "records")

VALID_FAMILIES = {
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


def is_url_allowlisted(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme != "https":
            return False
        return parsed.hostname in ALLOWED_HOSTS
    except Exception:
        return False


def fetch_url_bounded(url, data=None, headers=None, cumulative_bytes=None):
    if cumulative_bytes is None:
        cumulative_bytes = [0]

    req_headers = {"User-Agent": "kernel-security-memory-study"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data, headers=req_headers)

    with urllib.request.urlopen(req, timeout=20) as response:
        status = response.status
        body = bytearray()
        while True:
            chunk = response.read(8192)
            if not chunk:
                break
            body.extend(chunk)
            cumulative_bytes[0] += len(chunk)

            if len(body) > PER_RESPONSE_LIMIT:
                raise ValueError(f"Response limit of {PER_RESPONSE_LIMIT} bytes exceeded for {url}")
            if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                raise ValueError(f"Cumulative limit of {CUMULATIVE_LIMIT} bytes exceeded")

        return body, status, response.url


def parse_cwe(advisory_text):
    if not advisory_text:
        return None, "UNKNOWN"
    m = re.search(r"\b(CWE-\d+)\b", advisory_text, re.IGNORECASE)
    if m:
        return m.group(1).upper(), "STATED_BY_ADVISORY"
    return None, "UNKNOWN"


def classify_pattern_family(details_text):
    if not details_text:
        return "unknown"
    text = details_text.lower()
    if any(k in text for k in ["use-after-free", "double free", "lifetime", "dangling"]):
        return "memory-lifetime"
    if any(k in text for k in ["out-of-bounds", "buffer overflow", "over-read", "bounds"]):
        return "bounds"
    if any(k in text for k in ["integer overflow", "underflow", "wrap"]):
        return "integer"
    if any(k in text for k in ["race condition", "lock", "concurrency", "thread"]):
        return "concurrency"
    if any(k in text for k in ["permission", "auth", "privilege", "access control"]):
        return "authz"
    if any(k in text for k in ["injection", "sql injection"]):
        return "injection"
    if any(k in text for k in ["crypto", "cipher", "digest", "tls", "key"]):
        return "crypto"
    if any(k in text for k in ["path traversal", "directory traversal", "symlink"]):
        return "path-resolution"
    if any(k in text for k in ["parser", "syntax", "malformed", "unexpected token"]):
        return "parser"
    if any(k in text for k in ["resource exhaustion", "memory leak", "denial of service", "dos", "infinite loop"]):
        return "resource-accounting"
    if any(k in text for k in ["logic", "mishandles", "miscalculation", "incorrect", "mishandle"]):
        return "logic"
    return "unknown"


def extract_fix_ref(vuln):
    refs = vuln.get("references", [])
    for r in refs:
        if r.get("type") != "FIX":
            continue
        url = r.get("url", "")
        # GitHub commit URL
        m_gh = re.search(r"github\.com/sqlite/sqlite/commit/([0-9a-fA-F]+)", url)
        if m_gh:
            sha = m_gh.group(1)

            if len(sha) == 40 and re.match(r"^[0-9a-f]{40}$", sha.lower()):
                return sha.lower(), f"https://github.com/sqlite/sqlite/commit/{sha.lower()}", True
            else:
                return sha, url, False

        # Fossil sqlite.org URL
        m_sqlite = re.search(r"sqlite\.org/(?:src/info/|cgi/src/vdiff\?from=.*&to=|src/timeline\?c=)([0-9a-fA-F]+)", url)
        if m_sqlite:
            sha = m_sqlite.group(1)
            if len(sha) == 40 and re.match(r"^[0-9a-f]{40}$", sha.lower()):
                canonical_url = f"https://www.sqlite.org/src/info/{sha.lower()}"
                return sha.lower(), canonical_url, True
            else:
                return sha, url, False

    return None, None, None


def fetch_slice():
    os.makedirs(RECORDS_DIR, exist_ok=True)
    cumulative_bytes = [0]
    errors = []
    skipped = []
    records = []
    counts_by_family = {f: 0 for f in sorted(VALID_FAMILIES)}

    query_url = "https://api.osv.dev/v1/query"
    query_body = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/sqlite/sqlite"}}).encode("utf-8")

    used_query = query_url
    http_status = 0
    examined = 0

    try:
        body, status, _ = fetch_url_bounded(
            query_url,
            data=query_body,
            headers={"Content-Type": "application/json"},
            cumulative_bytes=cumulative_bytes,
        )
        http_status = status
        osv_data = json.loads(body.decode("utf-8"))
        vulns = osv_data.get("vulns", [])
    except Exception as e:
        errors.append(f"OSV query error: {e}")
        vulns = []

    if not vulns and http_status != 200:
        # Fallback to GitHub advisories
        gh_url = "https://api.github.com/repos/sqlite/sqlite/security-advisories?state=published&per_page=20"
        used_query = gh_url
        try:
            body, status, _ = fetch_url_bounded(
                gh_url,
                headers={"Accept": "application/vnd.github+json"},
                cumulative_bytes=cumulative_bytes,
            )
            http_status = status
            gh_data = json.loads(body.decode("utf-8"))
            vulns = gh_data if isinstance(gh_data, list) else []
        except Exception as e:
            errors.append(f"GitHub advisories query error: {e}")
            vulns = []

    # Sort vulns by modified or published date descending
    def get_date(v):
        return v.get("modified", v.get("published", ""))

    vulns.sort(key=get_date, reverse=True)

    max_examined = 40
    max_records = 8

    now_iso = datetime.now(timezone.utc).isoformat()

    for v in vulns:
        if examined >= max_examined or len(records) >= max_records:
            break

        examined += 1

        vid = v.get("id") or v.get("ghsa_id") or f"sqlite-vuln-{examined}"
        pub = v.get("published", "")
        mod = v.get("modified", "")

        pub_date = pub[:10] if pub else ""
        mod_date = mod[:10] if mod else ""

        in_window = ("2026-06-09" <= pub_date <= "2026-10-08") or ("2026-06-09" <= mod_date <= "2026-10-08")
        if not in_window:
            skipped.append({"id": vid, "reason": "outside_window"})
            continue

        sha, fix_url, is_full = extract_fix_ref(v)

        if sha is None:
            skipped.append({"id": vid, "reason": "subsystem_not_evidenced"})
            continue

        if not is_full:
            skipped.append({"id": vid, "reason": "abbreviated_sha"})
            continue

        if not is_url_allowlisted(fix_url):
            skipped.append({"id": vid, "reason": "subsystem_not_in_this_slice"})
            continue

        details = v.get("details", "") or v.get("summary", "")
        cwe_val, cwe_st = parse_cwe(details)
        family = classify_pattern_family(details)

        record_id = f"sqlite-{vid}"
        record_rel_path = f"records/{record_id}.json"

        adv_bytes = json.dumps(v, sort_keys=True).encode("utf-8")
        adv_sha256 = hashlib.sha256(adv_bytes).hexdigest()

        rec = {
            "schema_version": "study-record-v1",
            "id": record_id,
            "project": "sqlite",
            "advisory_id": vid,
            "cwe": cwe_val,
            "cwe_state": cwe_st,
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": sha,
                "url": fix_url,
                "committed_at": pub if pub else "UNKNOWN"
            },
            "insecure_pattern": "The application lacks sufficient input validation or bound checking before processing input data.",
            "mitigation": "The patch enforces proper validation, memory bounds, or condition logic prior to processing.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": adv_sha256,
                    "observed_at": now_iso
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        # Write record file
        rec_abs_path = os.path.join(BASE_DIR, record_rel_path)
        with open(rec_abs_path, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2, ensure_ascii=False)
            f.write("\n")

        records.append(record_rel_path)
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

    recorded_count = len(records)

    # Filter counts_by_family to only families with count > 0, or keep all observed?
    # Schema requirement: "one integer key for every family you observed; the sum equals recorded"
    # We filter keys so sum equals recorded
    observed_counts = {k: v for k, v in counts_by_family.items() if v > 0}

    if recorded_count == 0:
        notes = "No matching security fix advisories were recorded for SQLite in this slice window."
        coverage = "INCOMPLETE"
    else:
        notes = f"Recorded {recorded_count} SQLite security fix advisories published or modified in window 2026-06-09..2026-10-08."
        coverage = "WINDOW_SAMPLED"

    study_index = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "sqlite",
            "repo": "https://github.com/sqlite/sqlite",
            "github": "sqlite/sqlite"
        },
        "coverage": coverage,
        "method": {
            "used_query": used_query,
            "http_status": http_status,
            "examined": examined,
            "limits": {
                "max_examined": max_examined,
                "max_records": max_records
            }
        },
        "counts_by_family": observed_counts,
        "recorded": recorded_count,
        "records": records,
        "skipped": skipped,
        "errors": errors,
        "notes": notes
    }

    with open(STUDY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(study_index, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # Generate patterns.md
    patterns_lines = [
        "# SQLite Security Fix Frequency Study",
        "",
        "Window: 2026-06-09 .. 2026-10-08",
        "",
        "## Counts",
        ""
    ]

    if observed_counts:
        for fam, cnt in sorted(observed_counts.items()):
            patterns_lines.append(f"- {fam}: {cnt}")
    else:
        patterns_lines.append("- no_records_observed: 0")

    patterns_lines.extend([
        "",
        "Note: Every pattern family label is a hypothesis.",
        "",
        "## Records",
        ""
    ])

    if records:
        for rpath in records:
            patterns_lines.append(f"- {rpath}")
    else:
        patterns_lines.append("- (none)")

    patterns_lines.extend([
        "",
        "## Limits",
        "",
        "This file represents one bounded slice of SQLite security fixes, not a cross-project ranking or complete historical vulnerability archive."
    ])

    with open(PATTERNS_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(patterns_lines) + "\n")

    print(f"Fetch completed: recorded={recorded_count}, examined={examined}, errors={len(errors)}")


def validate_offline():
    # Verify study.json exists
    if not os.path.exists(STUDY_JSON_PATH):
        sys.exit(f"Error: {STUDY_JSON_PATH} missing")

    try:
        with open(STUDY_JSON_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        sys.exit(f"Error reading {STUDY_JSON_PATH}: {e}")

    # File size check
    if os.path.getsize(STUDY_JSON_PATH) > 65536:
        sys.exit(f"Error: {STUDY_JSON_PATH} exceeds 65536 bytes")

    # Validate study.json contract
    if d.get("schema_version") != "study-slice-v1":
        sys.exit(f"Invalid schema_version in study.json: {d.get('schema_version')}")

    window = d.get("window", {})
    if window.get("start") != "2026-06-09" or window.get("end") != "2026-10-08" or window.get("anchor") != "Claude Fable 5 public announcement 2026-06-09":
        sys.exit("Invalid window specification in study.json")

    coverage = d.get("coverage")
    if coverage not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        sys.exit(f"Invalid coverage value: {coverage}")

    project = d.get("project", {})
    if project.get("id") != "sqlite" or project.get("repo") != "https://github.com/sqlite/sqlite" or project.get("github") != "sqlite/sqlite":
        sys.exit("Invalid project specification in study.json")

    recorded = d.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        sys.exit(f"Invalid recorded count: {recorded}")

    records = d.get("records", [])
    if not isinstance(records, list) or len(records) != recorded:
        sys.exit(f"Mismatch between recorded count {recorded} and records array length {len(records)}")

    counts_by_family = d.get("counts_by_family", {})
    if not isinstance(counts_by_family, dict):
        sys.exit("counts_by_family must be a dict")

    for k, v in counts_by_family.items():
        if k not in VALID_FAMILIES:
            sys.exit(f"Invalid pattern family in counts_by_family: {k}")
        if not isinstance(v, int):
            sys.exit(f"Count for family {k} must be integer")

    if sum(counts_by_family.values()) != recorded:
        sys.exit(f"Sum of counts_by_family ({sum(counts_by_family.values())}) does not match recorded ({recorded})")

    notes = d.get("notes")
    if not isinstance(notes, str) or not notes.strip():
        sys.exit("notes must be a non-empty string")

    if recorded == 0 and "empty" not in notes.lower() and "no matching" not in notes.lower():
        sys.exit("When recorded is 0, notes must explain the empty observation")

    # Validate each record file
    for rpath in records:
        if not rpath.startswith("records/"):
            sys.exit(f"Record path {rpath} must start with records/")

        full_rpath = os.path.join(BASE_DIR, rpath)
        if not os.path.exists(full_rpath):
            sys.exit(f"Record file missing: {full_rpath}")

        if os.path.getsize(full_rpath) > 8192:
            sys.exit(f"Record file {full_rpath} exceeds 8192 bytes")

        try:
            with open(full_rpath, "r", encoding="utf-8") as f:
                rec = json.load(f)
        except Exception as e:
            sys.exit(f"Error reading record file {full_rpath}: {e}")

        if rec.get("schema_version") != "study-record-v1":
            sys.exit(f"Invalid schema_version in {full_rpath}")

        rec_id = rec.get("id", "")
        if not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("sqlite-"):
            sys.exit(f"Invalid record id {rec_id} in {full_rpath}")

        if rec.get("project") != "sqlite":
            sys.exit(f"Invalid project in {full_rpath}")

        if rec.get("pattern_family") not in VALID_FAMILIES:
            sys.exit(f"Invalid pattern_family in {full_rpath}")

        if rec.get("pattern_family_status") != "hypothesis":
            sys.exit(f"pattern_family_status must be hypothesis in {full_rpath}")

        fix = rec.get("fix", {})
        sha = fix.get("sha", "")
        if not re.match(r"^[0-9a-f]{40}$", sha):
            sys.exit(f"fix.sha must be 40-hex in {full_rpath}")

        fix_url = fix.get("url", "")
        if not is_url_allowlisted(fix_url):
            sys.exit(f"fix.url {fix_url} not on allowlist in {full_rpath}")

        ev_list = rec.get("evidence", [])
        if not isinstance(ev_list, list) or len(ev_list) == 0:
            sys.exit(f"At least one evidence object required in {full_rpath}")

        for ev in ev_list:
            if not is_url_allowlisted(ev.get("url", "")):
                sys.exit(f"Evidence url {ev.get('url')} not allowlisted in {full_rpath}")
            ev_sha256 = ev.get("sha256", "")
            if not re.match(r"^[0-9a-f]{64}$", ev_sha256):
                sys.exit(f"Evidence sha256 invalid in {full_rpath}")
            obs_at = ev.get("observed_at", "")
            if not obs_at or obs_at[:10] < "2026-10-08":
                sys.exit(f"observed_at in {full_rpath} must be on or after 2026-10-08")

    # Validate patterns.md
    if not os.path.exists(PATTERNS_MD_PATH):
        sys.exit(f"Missing {PATTERNS_MD_PATH}")

    with open(PATTERNS_MD_PATH, "r", encoding="utf-8") as f:
        md_content = f.read()

    md_lines = md_content.splitlines()
    if len(md_lines) > 200:
        sys.exit(f"{PATTERNS_MD_PATH} exceeds 200 lines")

    if not md_lines or "sqlite" not in md_lines[0].lower():
        sys.exit(f"First line of {PATTERNS_MD_PATH} must name sqlite")

    if "Window: 2026-06-09 .. 2026-10-08" not in md_content:
        sys.exit("Window header missing in patterns.md")

    for heading in ["## Counts", "## Records", "## Limits"]:
        if heading not in md_content:
            sys.exit(f"Missing heading {heading} in patterns.md")

    print("Offline verification passed successfully.")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="SQLite study fetcher / validator.")
    parser.add_argument("--fetch", action="store_true", help="Fetch study slice from live sources")
    parser.add_argument("--offline", action="store_true", help="Verify committed study slice offline")

    args = parser.parse_args()

    if args.fetch:
        fetch_slice()
    elif args.offline:
        validate_offline()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
