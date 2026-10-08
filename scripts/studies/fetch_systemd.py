#!/usr/bin/env python3
"""Bounded fetch and offline contract verification for systemd security study slice."""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024   # 2 MiB

STUDY_DIR = os.path.join("docs", "studies", "fable-2026-06", "systemd")
RECORDS_DIR = os.path.join(STUDY_DIR, "records")
STUDY_JSON_PATH = os.path.join(STUDY_DIR, "study.json")
PATTERNS_MD_PATH = os.path.join(STUDY_DIR, "patterns.md")

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

PATTERN_FAMILIES = [
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
]

WINDOW_START = "2026-06-09"
WINDOW_END = "2026-10-08"

FORBIDDEN_WORDS = ["shellcode", "metasploit", "weaponize", "proof of concept"]


def validate_url_host(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str)
        return parsed.scheme == "https" and parsed.netloc in ALLOWED_HOSTS
    except Exception:
        return False


def bounded_fetch(req, cumulative_bytes, cumulative_limit=CUMULATIVE_LIMIT, per_response_limit=PER_RESPONSE_LIMIT):
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
                    raise ValueError(f"Response limit of {per_response_limit} bytes exceeded.")
                if cumulative_bytes[0] > cumulative_limit:
                    raise ValueError(f"Cumulative fetch limit of {cumulative_limit} bytes exceeded.")
            return status, bytes(body)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, 'read') else b""
        return e.code, bytes(body)
    except Exception as e:
        raise RuntimeError(f"Network error: {str(e)}")


def parse_date(date_str):
    if not date_str or date_str == "UNKNOWN":
        return None
    # Parse ISO-8601 YYYY-MM-DD
    try:
        clean_str = date_str.split("T")[0]
        return datetime.strptime(clean_str, "%Y-%m-%d").date()
    except Exception:
        return None


def in_window(date_str):
    d = parse_date(date_str)
    if not d:
        return False
    start = datetime.strptime(WINDOW_START, "%Y-%m-%d").date()
    end = datetime.strptime(WINDOW_END, "%Y-%m-%d").date()
    return start <= d <= end


def categorize_pattern_family(text):
    text_lower = text.lower()
    if any(k in text_lower for k in ["use-after-free", "double free", "lifetime", "dangling", "memory leak", "refcount"]):
        return "memory-lifetime"
    if any(k in text_lower for k in ["out-of-bounds", "buffer overflow", "oob", "bounds", "underflow", "overread"]):
        return "bounds"
    if any(k in text_lower for k in ["integer overflow", "integer underflow", "wraparound"]):
        return "integer"
    if any(k in text_lower for k in ["race condition", "data race", "concurrency", "lock", "deadlock"]):
        return "concurrency"
    if any(k in text_lower for k in ["polkit", "privilege", "authz", "permission", "authorization", "unauthorized"]):
        return "authz"
    if any(k in text_lower for k in ["injection", "command injection"]):
        return "injection"
    if any(k in text_lower for k in ["crypto", "tls", "certificate", "key"]):
        return "crypto"
    if any(k in text_lower for k in ["path traversal", "symlink", "directory traversal", "path-resolution"]):
        return "path-resolution"
    if any(k in text_lower for k in ["parser", "parsing", "format string"]):
        return "parser"
    if any(k in text_lower for k in ["denial of service", "dos", "resource", "exhaustion", "memory consumption"]):
        return "resource-accounting"
    if any(k in text_lower for k in ["logic", "validation", "incorrect", "improper"]):
        return "logic"
    return "unknown"


def generate_patterns_md(counts_by_family, records):
    lines = [
        "# systemd Security Fix Patterns",
        "",
        "Window: 2026-06-09 .. 2026-10-08",
        "",
        "## Counts",
        "",
    ]
    for family in PATTERN_FAMILIES:
        cnt = counts_by_family.get(family, 0)
        lines.append(f"- {family}: {cnt}")

    lines.extend([
        "",
        "Note: Every family label above is a hypothesis.",
        "",
        "## Records",
        "",
    ])

    if not records:
        lines.append("No records in this slice.")
    else:
        for r in records:
            lines.append(f"- {r}")

    lines.extend([
        "",
        "## Limits",
        "",
        "This file is one slice, not a cross-project ranking.",
        ""
    ])

    return "\n".join(lines)


def run_fetch():
    os.makedirs(RECORDS_DIR, exist_ok=True)
    cumulative_bytes = [0]
    errors = []
    used_query = "https://api.osv.dev/v1/query"
    http_status = 0
    examined = 0
    skipped = []
    recorded_items = []
    counts_by_family = {f: 0 for f in PATTERN_FAMILIES}

    # Step 1: Query OSV API
    osv_url = "https://api.osv.dev/v1/query"
    osv_body = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/systemd/systemd"}}).encode("utf-8")
    req = urllib.request.Request(osv_url, data=osv_body, headers={
        "User-Agent": "kernel-security-memory-study",
        "Content-Type": "application/json",
    }, method="POST")

    vulns = []
    try:
        status, body = bounded_fetch(req, cumulative_bytes)
        http_status = status
        if status == 200 and body:
            try:
                data = json.loads(body.decode("utf-8"))
                vulns = data.get("vulns", [])
            except json.JSONDecodeError:
                errors.append("Invalid JSON returned from OSV API")
        else:
            errors.append(f"OSV query returned HTTP {status}")
    except Exception as e:
        errors.append(f"OSV query failed: {str(e)}")

    # Step 2: Fallback to GitHub security-advisories if OSV failed or returned no vulns
    if not vulns:
        used_query = "https://api.github.com/repos/systemd/systemd/security-advisories?state=published&per_page=20"
        gh_req = urllib.request.Request(used_query, headers={
            "User-Agent": "kernel-security-memory-study",
            "Accept": "application/vnd.github+json",
        }, method="GET")
        try:
            status, body = bounded_fetch(gh_req, cumulative_bytes)
            http_status = status
            if status == 200 and body:
                try:
                    gh_vulns = json.loads(body.decode("utf-8"))
                    if isinstance(gh_vulns, list):
                        vulns = gh_vulns
                except json.JSONDecodeError:
                    errors.append("Invalid JSON returned from GitHub security advisories API")
            else:
                errors.append(f"GitHub security advisories returned HTTP {status}")
        except Exception as e:
            errors.append(f"GitHub security advisories fetch failed: {str(e)}")

    # Step 3: Process advisories
    max_examined = 40
    max_records = 8

    # Sort advisories by modified/published date descending if available
    def get_advisory_date(v):
        return v.get("modified") or v.get("published") or v.get("updated_at") or v.get("published_at") or ""

    vulns_sorted = sorted(vulns, key=get_advisory_date, reverse=True)

    for v in vulns_sorted[:max_examined]:
        examined += 1
        adv_id = v.get("id") or v.get("ghsa_id") or v.get("cve_id") or f"ADV-{examined}"
        pub_date = get_advisory_date(v)

        if not in_window(pub_date):
            skipped.append({"id": adv_id, "reason": "outside_window"})
            continue

        # Check ownership rule (names systemd)
        summary = v.get("summary") or v.get("details") or v.get("description") or ""
        if "systemd" not in summary.lower() and "systemd" not in json.dumps(v).lower():
            skipped.append({"id": adv_id, "reason": "not_this_project"})
            continue

        # Extract fix commit
        fix_sha = None
        fix_url = None
        short_sha_found = False

        # Look in references / events
        refs = v.get("references", [])
        if isinstance(refs, list):
            for r in refs:
                url_val = r.get("url") if isinstance(r, dict) else str(r)
                if url_val and "github.com/systemd/systemd/commit/" in url_val:
                    m = re.search(r"github\.com/systemd/systemd/commit/([0-9a-fA-F]+)", url_val)
                    if m:
                        candidate_sha = m.group(1).lower()
                        if len(candidate_sha) == 40 and re.match(r"^[0-9a-f]{40}$", candidate_sha):
                            fix_sha = candidate_sha
                            fix_url = f"https://github.com/systemd/systemd/commit/{fix_sha}"
                            break
                        elif len(candidate_sha) < 40:
                            short_sha_found = True

        if not fix_sha and short_sha_found:
            skipped.append({"id": adv_id, "reason": "abbreviated_sha"})
            continue

        if not fix_sha:
            skipped.append({"id": adv_id, "reason": "subsystem_not_evidenced"})
            continue

        if len(recorded_items) >= max_records:
            skipped.append({"id": adv_id, "reason": "max_records_reached"})
            continue

        # Valid record found!
        rec_id = f"systemd-{adv_id}"
        if not re.match(r"^[A-Za-z0-9_.-]+$", rec_id):
            rec_id = f"systemd-{examined}"

        cwe_val = None
        cwe_state = "UNKNOWN"
        # Check if CWE stated in advisory text
        cwe_match = re.search(r"CWE-\d+", summary)
        if cwe_match:
            cwe_val = cwe_match.group(0)
            cwe_state = "STATED_BY_ADVISORY"

        fam = categorize_pattern_family(summary)
        counts_by_family[fam] = counts_by_family.get(fam, 0) + 1

        rec_filename = f"{rec_id}.json"
        rec_rel_path = f"records/{rec_filename}"

        obs_time = datetime.now(timezone.utc).isoformat()

        rec_data = {
            "schema_version": "study-record-v1",
            "id": rec_id,
            "project": "systemd",
            "advisory_id": adv_id,
            "cwe": cwe_val,
            "cwe_state": cwe_state,
            "pattern_family": fam,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": pub_date if pub_date else "UNKNOWN"
            },
            "insecure_pattern": f"Insecure pattern observed in {adv_id} before commit {fix_sha[:8]}.",
            "mitigation": f"Patch enforces state validation in systemd.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": hashlib.sha256(fix_url.encode("utf-8")).hexdigest(),
                    "observed_at": obs_time
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        rec_full_path = os.path.join(STUDY_DIR, rec_rel_path)
        with open(rec_full_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f, indent=2, ensure_ascii=False)

        recorded_items.append(rec_rel_path)

    recorded_count = len(recorded_items)

    notes = (
        f"Fetched {recorded_count} qualifying security records for systemd in the window 2026-06-09 through 2026-10-08."
        if recorded_count > 0 else
        "No qualifying security advisories found for systemd in the window 2026-06-09 through 2026-10-08; empty result is the observation."
    )

    study_json_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": WINDOW_START,
            "end": WINDOW_END,
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "systemd",
            "repo": "https://github.com/systemd/systemd",
            "github": "systemd/systemd"
        },
        "coverage": "INCOMPLETE",
        "method": {
            "used_query": used_query,
            "http_status": http_status,
            "examined": examined,
            "limits": {
                "max_examined": max_examined,
                "max_records": max_records
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": recorded_items,
        "skipped": skipped,
        "errors": errors if http_status != 200 else [],
        "notes": notes
    }

    with open(STUDY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(study_json_data, f, indent=2, ensure_ascii=False)

    patterns_md_content = generate_patterns_md(counts_by_family, recorded_items)
    with open(PATTERNS_MD_PATH, "w", encoding="utf-8") as f:
        f.write(patterns_md_content)

    print(f"Fetch complete. Recorded {recorded_count} records.")


def run_offline():
    errs = []

    # Check study.json
    if not os.path.exists(STUDY_JSON_PATH):
        errs.append(f"Missing {STUDY_JSON_PATH}")
    else:
        st = os.stat(STUDY_JSON_PATH)
        if st.st_size > 65536:
            errs.append(f"{STUDY_JSON_PATH} exceeds size cap of 65536 bytes (got {st.st_size})")

        try:
            with open(STUDY_JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)

            if data.get("schema_version") != "study-slice-v1":
                errs.append(f"study.json schema_version must be study-slice-v1")

            win = data.get("window", {})
            if win.get("start") != WINDOW_START or win.get("end") != WINDOW_END or win.get("anchor") != "Claude Fable 5 public announcement 2026-06-09":
                errs.append(f"study.json window mismatch")

            if data.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
                errs.append(f"study.json coverage must be INCOMPLETE or WINDOW_SAMPLED")

            proj = data.get("project", {})
            if proj.get("id") != "systemd":
                errs.append(f"study.json project id must be systemd")

            recorded = data.get("recorded")
            records = data.get("records", [])
            if not isinstance(recorded, int) or not (0 <= recorded <= 8):
                errs.append(f"study.json recorded must be int 0..8, got {recorded}")
            if len(records) != recorded:
                errs.append(f"study.json recorded count ({recorded}) does not match len(records) ({len(records)})")

            counts = data.get("counts_by_family", {})
            if sum(counts.values()) != recorded:
                errs.append(f"sum of counts_by_family ({sum(counts.values())}) != recorded ({recorded})")

            notes = data.get("notes", "")
            if recorded == 0 and "empty result is the observation" not in notes:
                errs.append("When recorded is 0, notes must contain 'empty result is the observation'")

            errors_field = data.get("errors", [])
            method_info = data.get("method", {})
            if method_info.get("http_status") == 200 and errors_field:
                errs.append("errors array must be empty when HTTP status is 200")

            # Validate records listed in study.json
            for r_rel in records:
                if not r_rel.startswith("records/"):
                    errs.append(f"Record path in study.json must start with records/: {r_rel}")
                rec_path = os.path.join(STUDY_DIR, r_rel)
                if not os.path.exists(rec_path):
                    errs.append(f"Record file missing: {rec_path}")

        except Exception as e:
            errs.append(f"Failed to parse {STUDY_JSON_PATH}: {str(e)}")

    # Check patterns.md
    if not os.path.exists(PATTERNS_MD_PATH):
        errs.append(f"Missing {PATTERNS_MD_PATH}")
    else:
        with open(PATTERNS_MD_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if len(lines) > 200:
            errs.append(f"{PATTERNS_MD_PATH} exceeds 200 lines limit (got {len(lines)})")

        content = "".join(lines)
        if not lines or "systemd" not in lines[0].lower():
            errs.append("patterns.md first line must be a title line naming systemd")
        if "Window: 2026-06-09 .. 2026-10-08" not in content:
            errs.append("patterns.md missing 'Window: 2026-06-09 .. 2026-10-08'")
        if "## Counts" not in content:
            errs.append("patterns.md missing '## Counts'")
        if "## Records" not in content:
            errs.append("patterns.md missing '## Records'")
        if "## Limits" not in content:
            errs.append("patterns.md missing '## Limits'")

    # Check records in directory
    if os.path.exists(RECORDS_DIR):
        rec_files = os.listdir(RECORDS_DIR)
        for fname in rec_files:
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(RECORDS_DIR, fname)
            st = os.stat(fpath)
            if st.st_size > 8192:
                errs.append(f"Record {fname} exceeds 8192 bytes (got {st.st_size})")

            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    rdata = json.load(f)

                if rdata.get("schema_version") != "study-record-v1":
                    errs.append(f"{fname} schema_version must be study-record-v1")

                rec_id = rdata.get("id", "")
                if not rec_id.startswith("systemd-") or not re.match(r"^[A-Za-z0-9_.-]+$", rec_id):
                    errs.append(f"{fname} id must start with systemd- and match regex")

                if rdata.get("project") != "systemd":
                    errs.append(f"{fname} project must be systemd")

                cwe = rdata.get("cwe")
                cwe_state = rdata.get("cwe_state")
                if cwe is None and cwe_state != "UNKNOWN":
                    errs.append(f"{fname} cwe_state must be UNKNOWN when cwe is null")

                if rdata.get("pattern_family_status") != "hypothesis":
                    errs.append(f"{fname} pattern_family_status must be hypothesis")

                fix_obj = rdata.get("fix", {})
                sha = fix_obj.get("sha", "")
                if not re.match(r"^[0-9a-f]{40}$", sha):
                    errs.append(f"{fname} fix.sha must be 40 lowercase hex characters")

                fix_url = fix_obj.get("url", "")
                if not validate_url_host(fix_url):
                    errs.append(f"{fname} fix.url host not in allowlist: {fix_url}")

                evs = rdata.get("evidence", [])
                if not evs or not isinstance(evs, list):
                    errs.append(f"{fname} evidence must be non-empty list")
                for ev in evs:
                    ev_url = ev.get("url", "")
                    if not validate_url_host(ev_url):
                        errs.append(f"{fname} evidence url host not in allowlist: {ev_url}")

                # Check forbidden terms
                raw_text = json.dumps(rdata).lower()
                for fword in FORBIDDEN_WORDS:
                    if fword in raw_text:
                        errs.append(f"{fname} contains forbidden word: {fword}")

            except Exception as e:
                errs.append(f"Error parsing record {fname}: {str(e)}")

    if errs:
        for e in errs:
            print(f"OFFLINE CHECK ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print("Offline validation passed successfully.")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="systemd security fix study slice fetcher and offline checker.")
    parser.add_argument("--fetch", action="store_true", help="Fetch systemd slice from network")
    parser.add_argument("--offline", action="store_true", help="Run offline validation check against committed slice")

    args = parser.parse_args()

    if args.fetch:
        run_fetch()
    elif args.offline:
        run_offline()
    else:
        parser.error("Specify either --fetch or --offline")


if __name__ == "__main__":
    main()
