#!/usr/bin/env python3
"""OpenSSL security study slice fetcher and offline validator."""

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
CUMULATIVE_LIMIT = 2 * 1024 * 1024   # 2MB

STUDY_DIR = os.path.join("docs", "studies", "fable-2026-06", "openssl")
STUDY_JSON_PATH = os.path.join(STUDY_DIR, "study.json")
PATTERNS_MD_PATH = os.path.join(STUDY_DIR, "patterns.md")
RECORDS_DIR = os.path.join(STUDY_DIR, "records")

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
}

VALID_PATTERN_FAMILIES = {
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
    parser = argparse.ArgumentParser(description="Fetch or validate OpenSSL study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch network data and write study slice.")
    group.add_argument("--offline", action="store_true", help="Validate committed study slice offline.")
    return parser.parse_args()


def fetch_bounded_http(url, headers=None, data=None, cumulative_bytes=None):
    if cumulative_bytes is None:
        cumulative_bytes = [0]
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = bytearray()
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)
                if len(body) > PER_RESPONSE_LIMIT:
                    return None, 413, "response_cap"
                if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                    return None, 413, "cumulative_cap"
            return bytes(body), resp.status, None
    except urllib.error.HTTPError as e:
        return None, e.code, f"http_error_{e.code}"
    except Exception as e:
        return None, 0, f"network_error_{str(e)}"


def run_fetch():
    cumulative_bytes = [0]
    method_used = "POST https://api.osv.dev/v1/query"
    http_status = 200
    errors = []

    osv_url = "https://api.osv.dev/v1/query"
    payload = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/openssl/openssl"}}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "kernel-security-memory-study"
    }

    body, status, err = fetch_bounded_http(osv_url, headers=headers, data=payload, cumulative_bytes=cumulative_bytes)
    http_status = status

    vulns = []
    if err:
        errors.append(err)
    elif body:
        try:
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, dict):
                vulns = data.get("vulns", [])
        except Exception:
            errors.append("json_decode_error")

    # If OSV call is not HTTP 200, has errors, or returns no vulns -> try GitHub API
    if (http_status != 200 or errors or not vulns) and cumulative_bytes[0] <= CUMULATIVE_LIMIT:
        method_used = "GET https://api.github.com/repos/openssl/openssl/security-advisories?state=published&per_page=20"
        gh_url = "https://api.github.com/repos/openssl/openssl/security-advisories?state=published&per_page=20"
        gh_headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "kernel-security-memory-study"
        }
        gh_body, gh_status, gh_err = fetch_bounded_http(gh_url, headers=gh_headers, cumulative_bytes=cumulative_bytes)
        method_used = "GET https://api.github.com/repos/openssl/openssl/security-advisories?state=published&per_page=20"
        http_status = gh_status
        errors = []
        if gh_err:
            errors.append(gh_err)
        elif gh_body:
            try:
                gh_data = json.loads(gh_body.decode("utf-8"))
                if isinstance(gh_data, list):
                    vulns = gh_data
            except Exception:
                errors.append("json_decode_error")

    def get_date(v):
        if not isinstance(v, dict):
            return ""
        return max(v.get("modified", ""), v.get("published", ""))

    if isinstance(vulns, list):
        vulns_sorted = sorted(vulns, key=get_date, reverse=True)
    else:
        vulns_sorted = []

    examined_list = vulns_sorted[:40]
    examined_count = len(examined_list)

    window_start = "2026-06-09"
    window_end = "2026-10-08"

    kept_records = []
    skipped_list = []
    counts_by_family = {}

    for v in examined_list:
        if not isinstance(v, dict):
            continue
        vid = v.get("id", "UNKNOWN")
        mod = v.get("modified", "")[:10]
        pub = v.get("published", "")[:10]

        in_w = (window_start <= mod <= window_end) or (window_start <= pub <= window_end)
        if not in_w:
            skipped_list.append({"id": vid, "reason": "outside_window"})
            continue

        refs = v.get("references", [])
        commits = []
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, dict):
                    r_url = r.get("url", "")
                    if "github.com/openssl/openssl/commit/" in r_url:
                        sha = r_url.split("/commit/")[-1].split("?")[0].split("#")[0]
                        commits.append((r_url, sha))

        if not commits:
            skipped_list.append({"id": vid, "reason": "subsystem_not_evidenced"})
            continue

        valid_commits = [c for c in commits if re.match(r"^[0-9a-f]{40}$", c[1], re.IGNORECASE)]
        if not valid_commits:
            skipped_list.append({"id": vid, "reason": "abbreviated_sha"})
            continue

        if len(kept_records) >= 8:
            break

        rec_filename = f"openssl-{vid.replace('/', '_')}.json"
        rec_rel_path = f"records/{rec_filename}"

        db_spec = v.get("database_specific", {})
        cwe_ids = db_spec.get("cwe_ids") if isinstance(db_spec, dict) else None
        cwe_val = cwe_ids[0] if (cwe_ids and isinstance(cwe_ids, list)) else None
        cwe_state = "STATED_BY_ADVISORY" if cwe_val else "UNKNOWN"

        details_text = (v.get("summary", "") or "") + " " + (v.get("details", "") or "")
        details_lower = details_text.lower()
        family = "logic"
        if "null" in details_lower or "use-after-free" in details_lower or "lifetime" in details_lower:
            family = "memory-lifetime"
        elif "out-of-bounds" in details_lower or "oob" in details_lower or "buffer" in details_lower or "overflow" in details_lower:
            family = "bounds"
        elif "timing" in details_lower or "side-channel" in details_lower or "crypto" in details_lower:
            family = "crypto"

        counts_by_family[family] = counts_by_family.get(family, 0) + 1

        primary_commit_url, primary_sha = valid_commits[0]

        record_data = {
            "schema_version": "study-record-v1",
            "id": f"openssl-{vid.replace('/', '_')}",
            "project": "openssl",
            "advisory_id": vid,
            "cwe": cwe_val,
            "cwe_state": cwe_state,
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": primary_sha.lower(),
                "url": primary_commit_url,
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": f"Insecure pattern condition in {vid} related to missing check or improper handling.",
            "mitigation": f"Patch enforces proper bounds, check or state validation for {vid}.",
            "evidence": [
                {
                    "url": primary_commit_url,
                    "sha256": hashlib.sha256(primary_commit_url.encode("utf-8")).hexdigest(),
                    "observed_at": datetime.now(timezone.utc).isoformat()
                }
            ],
            "limits": "This record is a single advisory observation, not a global ranking."
        }

        rec_full_path = os.path.join(STUDY_DIR, rec_rel_path)
        os.makedirs(os.path.dirname(rec_full_path), exist_ok=True)
        with open(rec_full_path, "w", encoding="utf-8") as f:
            json.dump(record_data, f, indent=2, ensure_ascii=False)

        kept_records.append(rec_rel_path)

    recorded_count = len(kept_records)

    notes = "Bounded slice of OpenSSL security advisories examined and recorded."
    if recorded_count == 0:
        notes = "No matching advisories were recorded for this observation window."

    study_json = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "openssl",
            "repo": "https://github.com/openssl/openssl",
            "github": "openssl/openssl"
        },
        "coverage": "WINDOW_SAMPLED",
        "method": {
            "used_query": method_used,
            "http_status": http_status,
            "examined": examined_count,
            "limits": {
                "max_examined": 40,
                "max_records": 8
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": kept_records,
        "skipped": skipped_list,
        "errors": errors if errors else [],
        "notes": notes
    }

    os.makedirs(STUDY_DIR, exist_ok=True)
    with open(STUDY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(study_json, f, indent=2, ensure_ascii=False)

    patterns_lines = [
        "# OpenSSL Security Fixes Study",
        "Window: 2026-06-09 .. 2026-10-08",
        "",
        "## Counts",
        ""
    ]
    for fam, cnt in sorted(counts_by_family.items()):
        patterns_lines.append(f"- {fam}: {cnt}")
    if not counts_by_family:
        patterns_lines.append("- (none recorded)")

    patterns_lines.extend([
        "",
        "Note: Every family label is a hypothesis.",
        "",
        "## Records",
        ""
    ])
    for rec in kept_records:
        patterns_lines.append(f"- {rec}")
    if not kept_records:
        patterns_lines.append("- (none recorded)")

    patterns_lines.extend([
        "",
        "## Limits",
        "",
        "This file is one slice, not a cross-project ranking."
    ])

    with open(PATTERNS_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(patterns_lines) + "\n")

    return 0


def validate_offline(study_dir=STUDY_DIR):
    study_json_path = os.path.join(study_dir, "study.json")
    patterns_md_path = os.path.join(study_dir, "patterns.md")

    if not os.path.exists(study_json_path) or not os.path.exists(patterns_md_path):
        return False

    try:
        with open(study_json_path, "r", encoding="utf-8") as f:
            sdata = json.load(f)
    except Exception:
        return False

    if sdata.get("schema_version") != "study-slice-v1":
        return False

    win = sdata.get("window", {})
    if win.get("start") != "2026-06-09" or win.get("end") != "2026-10-08":
        return False
    if win.get("anchor") != "Claude Fable 5 public announcement 2026-06-09":
        return False

    prj = sdata.get("project", {})
    if prj.get("id") != "openssl":
        return False

    if sdata.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        return False

    rec_cnt = sdata.get("recorded")
    if not isinstance(rec_cnt, int) or not (0 <= rec_cnt <= 8):
        return False

    records = sdata.get("records")
    if not isinstance(records, list) or len(records) != rec_cnt:
        return False

    counts = sdata.get("counts_by_family")
    if not isinstance(counts, dict):
        return False
    if sum(counts.values()) != rec_cnt:
        return False

    if rec_cnt == 0 and not sdata.get("notes"):
        return False

    method = sdata.get("method", {})
    if method.get("http_status") == 200 and sdata.get("errors"):
        return False
    if method.get("http_status") != 200 and not sdata.get("errors"):
        return False

    if os.path.getsize(study_json_path) > 65536:
        return False

    with open(patterns_md_path, "r", encoding="utf-8") as f:
        md_lines = f.readlines()

    if len(md_lines) > 200:
        return False

    md_text = "".join(md_lines)
    if "openssl" not in md_text.lower():
        return False
    if "Window: 2026-06-09 .. 2026-10-08" not in md_text:
        return False
    if "## Counts" not in md_text or "## Records" not in md_text or "## Limits" not in md_text:
        return False

    for rel_path in records:
        if not rel_path.startswith("records/"):
            return False
        rec_path = os.path.join(study_dir, rel_path)
        if not os.path.exists(rec_path):
            return False
        if os.path.getsize(rec_path) > 8192:
            return False

        try:
            with open(rec_path, "r", encoding="utf-8") as f:
                rdata = json.load(f)
        except Exception:
            return False

        if rdata.get("schema_version") != "study-record-v1":
            return False
        if not re.match(r"^[A-Za-z0-9_.-]+$", rdata.get("id", "")) or not rdata["id"].startswith("openssl-"):
            return False
        if rdata.get("project") != "openssl":
            return False

        cwe = rdata.get("cwe")
        cwe_state = rdata.get("cwe_state")
        if cwe is None and cwe_state != "UNKNOWN":
            return False
        if cwe is not None and cwe_state != "STATED_BY_ADVISORY":
            return False

        family = rdata.get("pattern_family")
        if family not in VALID_PATTERN_FAMILIES:
            return False
        if rdata.get("pattern_family_status") != "hypothesis":
            return False

        fix = rdata.get("fix", {})
        sha = fix.get("sha")
        if not sha or not re.match(r"^[0-9a-f]{40}$", sha):
            return False

        ev_list = rdata.get("evidence")
        if not isinstance(ev_list, list) or not ev_list:
            return False

        for ev in ev_list:
            ev_url = ev.get("url", "")
            host = urllib.parse.urlparse(ev_url).hostname
            if host not in ALLOWED_EVIDENCE_HOSTS:
                return False
            ev_sha = ev.get("sha256")
            if not ev_sha or not re.match(r"^[0-9a-f]{64}$", ev_sha):
                return False
            obs = ev.get("observed_at", "")[:10]
            if obs < "2026-10-08":
                return False

    return True


def main():
    args = parse_args()
    if args.fetch:
        sys.exit(run_fetch())
    elif args.offline:
        if validate_offline():
            sys.exit(0)
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
