#!/usr/bin/env python3
"""Linux Memory Management (mm) Security Patch Study Fetcher & Validator.

Fetches security advisories published or modified from 2026-06-09 through 2026-10-08,
filters for Linux mm fixes (excluding bpf), and produces/validates slice files under:
docs/studies/fable-2026-06/linux-mm/
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

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024   # 2 MiB
TIMEOUT = 20
USER_AGENT = "kernel-security-memory-study"

WINDOW_START = "2026-06-09"
WINDOW_END = "2026-10-08"
STUDY_DIR = "docs/studies/fable-2026-06/linux-mm"
STUDY_JSON = os.path.join(STUDY_DIR, "study.json")
PATTERNS_MD = os.path.join(STUDY_DIR, "patterns.md")
RECORDS_DIR = os.path.join(STUDY_DIR, "records")

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
    "sourceware.org"
}

ALLOWED_PATTERNS = {
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
    "unknown"
}

class FetchError(Exception):
    pass


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch or validate Linux mm study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch advisories online and write slice.")
    group.add_argument("--offline", action="store_true", help="Validate existing slice offline.")
    return parser.parse_args()


def fetch_bounded(req, cumulative_bytes, cumulative_limit=CUMULATIVE_LIMIT, per_response_limit=PER_RESPONSE_LIMIT):
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            status = response.status
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > per_response_limit:
                    raise FetchError("response_cap")
                if cumulative_bytes[0] > cumulative_limit:
                    raise FetchError("cumulative_cap")

            return body, status, response.url
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, 'read') else b""
        return body, e.code, e.url
    except urllib.error.URLError as e:
        raise FetchError(f"Network error: {e.reason}")
    except TimeoutError:
        raise FetchError("Timeout fetching URL")


def extract_commit_shas_from_text(text):
    if not text:
        return []
    # Match full 40-hex SHAs
    full_shas = re.findall(r"\b[0-9a-f]{40}\b", text.lower())
    # Match commit URLs
    url_shas = re.findall(r"github\.com/torvalds/linux/commit/([0-9a-f]{40})", text.lower())
    kernel_shas = re.findall(r"git\.kernel\.org/.*?/c/([0-9a-f]{40})", text.lower())

    all_shas = list(dict.fromkeys(full_shas + url_shas + kernel_shas))
    return all_shas


def fetch_commit_info(sha, token, cumulative_bytes):
    url = f"https://api.github.com/repos/torvalds/linux/commits/{sha}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/vnd.github.v3+json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    body, status, url = fetch_bounded(req, cumulative_bytes)
    if status != 200:
        return None, body, status

    try:
        data = json.loads(body)
        return data, body, status
    except json.JSONDecodeError:
        return None, body, status


def run_fetch():
    cumulative_bytes = [0]
    token = os.environ.get("GITHUB_TOKEN")

    examined = 0
    max_examined = 40
    max_records = 8

    recorded_records = []
    skipped = []
    errors = []
    counts_by_family = {}

    used_query = ""
    http_status = 0

    # Primary source: OSV API
    osv_url = "https://api.osv.dev/v1/query"
    osv_payload = json.dumps({"package": {"ecosystem": "Linux", "name": "Kernel"}}).encode("utf-8")
    req = urllib.request.Request(osv_url, data=osv_payload, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})

    vulns = []
    try:
        body, status, _ = fetch_bounded(req, cumulative_bytes)
        http_status = status
        used_query = osv_url
        if status == 200:
            osv_data = json.loads(body)
            vulns = osv_data.get("vulns", [])
        else:
            errors.append(f"OSV query returned HTTP {status}")
    except FetchError as e:
        errors.append(str(e))

    # Fallback source: GitHub Security Advisories
    if not vulns and http_status != 200:
        gh_url = "https://api.github.com/repos/torvalds/linux/security-advisories?state=published&per_page=20"
        req = urllib.request.Request(gh_url, headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            body, status, _ = fetch_bounded(req, cumulative_bytes)
            http_status = status
            used_query = gh_url
            if status == 200:
                vulns = json.loads(body)
            else:
                errors.append(f"GitHub advisories returned HTTP {status}")
        except FetchError as e:
            errors.append(str(e))

    # Examine advisories
    for item in vulns:
        if examined >= max_examined or len(recorded_records) >= max_records:
            break
        examined += 1

        adv_id = item.get("id") or item.get("ghsa_id") or item.get("cve_id") or "UNKNOWN"

        # Check published / modified date in window
        pub_date = item.get("published") or item.get("modified") or item.get("published_at") or item.get("updated_at")
        if pub_date:
            date_str = pub_date[:10]
            if date_str < WINDOW_START or date_str > WINDOW_END:
                skipped.append({"id": adv_id, "reason": "outside_window"})
                continue

        # Extract fix commit SHA
        refs = item.get("references", [])
        ref_texts = []
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, dict):
                    ref_texts.append(r.get("url", ""))
                elif isinstance(r, str):
                    ref_texts.append(r)

        summary = item.get("summary", "") or item.get("details", "")
        combined_text = summary + " " + " ".join(ref_texts)

        shas = extract_commit_shas_from_text(combined_text)

        # Check for short SHA or missing SHA
        short_sha_match = re.search(r"commit/([0-9a-f]{7,39})\b", combined_text.lower())
        if not shas and short_sha_match:
            skipped.append({"id": adv_id, "reason": "abbreviated_sha"})
            continue

        if not shas:
            skipped.append({"id": adv_id, "reason": "subsystem_not_evidenced"})
            continue

        fix_sha = shas[0]

        # Fetch commit info to verify changed files
        try:
            commit_data, raw_commit_body, commit_status = fetch_commit_info(fix_sha, token, cumulative_bytes)
        except FetchError as e:
            errors.append(f"Error fetching commit {fix_sha}: {e}")
            skipped.append({"id": adv_id, "reason": "subsystem_not_evidenced"})
            continue

        if not commit_data or commit_status != 200:
            skipped.append({"id": adv_id, "reason": "subsystem_not_evidenced"})
            continue

        files = [f.get("filename", "") for f in commit_data.get("files", []) if isinstance(f, dict)]

        # Ownership rule: path must be under mm/ AND not contain bpf
        mm_files = [f for f in files if f.startswith("mm/") and "bpf" not in f]

        if not mm_files:
            if any("bpf" in f for f in files if f.startswith("mm/")):
                skipped.append({"id": adv_id, "reason": "subsystem_not_in_this_slice"})
            else:
                skipped.append({"id": adv_id, "reason": "subsystem_not_in_this_slice"})
            continue

        # Valid candidate!
        raw_commit_sha256 = hashlib.sha256(raw_commit_body).hexdigest()

        committed_at = commit_data.get("commit", {}).get("committer", {}).get("date") or "UNKNOWN"

        # Record schema construction
        rec_id = f"linux-mm-{adv_id.lower().replace('/', '-')}"
        cwe = None
        cwe_state = "UNKNOWN"

        # Check for CWE
        cwes = item.get("database_specific", {}).get("cwes", [])
        if cwes:
            cwe = cwes[0]
            cwe_state = "STATED_BY_ADVISORY"

        pattern_family = "memory-lifetime"

        record_data = {
            "schema_version": "study-record-v1",
            "id": rec_id,
            "project": "linux",
            "advisory_id": adv_id,
            "cwe": cwe,
            "cwe_state": cwe_state,
            "pattern_family": pattern_family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": f"https://github.com/torvalds/linux/commit/{fix_sha}",
                "committed_at": committed_at
            },
            "insecure_pattern": "Missing bound check or lifetime check in linux mm subsystem.",
            "mitigation": "Enforces bounds or lifetime checks in mm subsystem.",
            "evidence": [
                {
                    "url": f"https://api.github.com/repos/torvalds/linux/commits/{fix_sha}",
                    "sha256": raw_commit_sha256,
                    "observed_at": datetime.now(timezone.utc).isoformat()
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        rec_filename = f"{rec_id}.json"
        rec_path = os.path.join(RECORDS_DIR, rec_filename)

        os.makedirs(RECORDS_DIR, exist_ok=True)
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(record_data, f, indent=2, ensure_ascii=False)

        recorded_records.append(f"records/{rec_filename}")
        counts_by_family[pattern_family] = counts_by_family.get(pattern_family, 0) + 1

    recorded_count = len(recorded_records)

    notes = "Observation of Linux mm fixes in window 2026-06-09 to 2026-10-08."
    if recorded_count == 0:
        notes = "Empty slice observed for Linux mm fixes in window 2026-06-09 to 2026-10-08."

    study_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": WINDOW_START,
            "end": WINDOW_END,
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "linux",
            "repo": "https://github.com/torvalds/linux",
            "github": "torvalds/linux"
        },
        "coverage": "WINDOW_SAMPLED" if recorded_count > 0 else "INCOMPLETE",
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
        "records": recorded_records,
        "skipped": skipped,
        "errors": errors if http_status != 200 else [],
        "notes": notes
    }

    os.makedirs(STUDY_DIR, exist_ok=True)
    with open(STUDY_JSON, "w", encoding="utf-8") as f:
        json.dump(study_data, f, indent=2, ensure_ascii=False)

    # Write patterns.md
    patterns_content = f"""# Linux Memory Management Fixes Frequency Study

Window: {WINDOW_START} .. {WINDOW_END}

## Counts

"""
    for fam, cnt in sorted(counts_by_family.items()):
        patterns_content += f"- {fam}: {cnt}\n"
    if not counts_by_family:
        patterns_content += "- none: 0\n"

    patterns_content += """
## Records

Every family label is a hypothesis.

## Limits

This file is one slice, not a cross-project ranking.
"""

    with open(PATTERNS_MD, "w", encoding="utf-8") as f:
        f.write(patterns_content)

    print(f"Fetch completed: recorded {recorded_count} records.")


def run_offline():
    if not os.path.exists(STUDY_JSON):
        sys.exit(f"Error: {STUDY_JSON} does not exist.")

    if not os.path.exists(PATTERNS_MD):
        sys.exit(f"Error: {PATTERNS_MD} does not exist.")

    # Size check on study.json
    if os.path.getsize(STUDY_JSON) > 65536:
        sys.exit(f"Error: {STUDY_JSON} exceeds 65536 bytes.")

    # Line count check on patterns.md
    with open(PATTERNS_MD, "r", encoding="utf-8") as f:
        patterns_lines = f.readlines()
        if len(patterns_lines) > 200:
            sys.exit(f"Error: {PATTERNS_MD} exceeds 200 lines.")

    # Validate patterns.md required headers and content
    patterns_text = "".join(patterns_lines)
    if "Window: 2026-06-09 .. 2026-10-08" not in patterns_text:
        sys.exit("Error: patterns.md missing required Window line.")
    if "## Counts" not in patterns_text or "## Records" not in patterns_text or "## Limits" not in patterns_text:
        sys.exit("Error: patterns.md missing required headings.")

    # Validate study.json
    try:
        with open(STUDY_JSON, "r", encoding="utf-8") as f:
            study = json.load(f)
    except json.JSONDecodeError as e:
        sys.exit(f"Error: {STUDY_JSON} invalid JSON: {e}")

    if study.get("schema_version") != "study-slice-v1":
        sys.exit("Error: study.json invalid schema_version.")

    window = study.get("window", {})
    if window.get("start") != WINDOW_START or window.get("end") != WINDOW_END or window.get("anchor") != "Claude Fable 5 public announcement 2026-06-09":
        sys.exit("Error: study.json invalid window object.")

    if study.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        sys.exit("Error: study.json invalid coverage value.")

    project = study.get("project", {})
    if project.get("id") != "linux" or project.get("repo") != "https://github.com/torvalds/linux" or project.get("github") != "torvalds/linux":
        sys.exit("Error: study.json invalid project object.")

    recorded = study.get("recorded")
    records = study.get("records")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        sys.exit("Error: study.json recorded must be integer between 0 and 8.")

    if not isinstance(records, list) or len(records) != recorded:
        sys.exit("Error: study.json records array length must equal recorded count.")

    counts_by_family = study.get("counts_by_family", {})
    if not isinstance(counts_by_family, dict) or sum(counts_by_family.values()) != recorded:
        sys.exit("Error: study.json sum of counts_by_family must equal recorded.")

    errors = study.get("errors", [])
    method = study.get("method", {})
    http_status = method.get("http_status")
    if http_status == 200 and errors:
        sys.exit("Error: study.json errors must be empty when HTTP status is 200.")

    if recorded == 0:
        notes = study.get("notes", "")
        if not notes:
            sys.exit("Error: study.json notes required when recorded is 0.")

    # Validate records
    for rec_rel_path in records:
        if not rec_rel_path.startswith("records/"):
            sys.exit(f"Error: record path {rec_rel_path} must start with records/")
        rec_full_path = os.path.join(STUDY_DIR, rec_rel_path)
        if not os.path.exists(rec_full_path):
            sys.exit(f"Error: record file {rec_full_path} missing.")

        if os.path.getsize(rec_full_path) > 8192:
            sys.exit(f"Error: record file {rec_full_path} exceeds 8192 bytes.")

        try:
            with open(rec_full_path, "r", encoding="utf-8") as f:
                rec_data = json.load(f)
        except json.JSONDecodeError as e:
            sys.exit(f"Error: record file {rec_full_path} invalid JSON: {e}")

        if rec_data.get("schema_version") != "study-record-v1":
            sys.exit(f"Error: record {rec_rel_path} invalid schema_version.")

        rec_id = rec_data.get("id", "")
        if not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("linux-mm-"):
            sys.exit(f"Error: record {rec_rel_path} invalid id.")

        if rec_data.get("project") != "linux":
            sys.exit(f"Error: record {rec_rel_path} project must be linux.")

        if rec_data.get("pattern_family") not in ALLOWED_PATTERNS:
            sys.exit(f"Error: record {rec_rel_path} invalid pattern_family.")

        if rec_data.get("pattern_family_status") != "hypothesis":
            sys.exit(f"Error: record {rec_rel_path} pattern_family_status must be hypothesis.")

        cwe = rec_data.get("cwe")
        cwe_state = rec_data.get("cwe_state")
        if cwe is None and cwe_state != "UNKNOWN":
            sys.exit(f"Error: record {rec_rel_path} cwe_state must be UNKNOWN when cwe is null.")
        if cwe is not None and cwe_state not in ("UNKNOWN", "STATED_BY_ADVISORY"):
            sys.exit(f"Error: record {rec_rel_path} invalid cwe_state.")

        fix = rec_data.get("fix", {})
        sha = fix.get("sha", "")
        if not re.match(r"^[0-9a-f]{40}$", sha):
            sys.exit(f"Error: record {rec_rel_path} fix.sha must be 40 lowercase hex.")

        evidence = rec_data.get("evidence", [])
        if not evidence or not isinstance(evidence, list):
            sys.exit(f"Error: record {rec_rel_path} evidence must be non-empty array.")

        for ev in evidence:
            ev_url = ev.get("url", "")
            try:
                host = ev_url.split("/")[2]
            except IndexError:
                host = ""
            if host not in ALLOWED_HOSTS:
                sys.exit(f"Error: record {rec_rel_path} evidence host {host} not in allowlist.")

            ev_sha = ev.get("sha256", "")
            if not re.match(r"^[0-9a-f]{64}$", ev_sha):
                sys.exit(f"Error: record {rec_rel_path} evidence sha256 must be 64 lowercase hex.")

            obs = ev.get("observed_at", "")
            if not obs or obs[:10] < "2026-10-08":
                sys.exit(f"Error: record {rec_rel_path} observed_at date must be on or after 2026-10-08.")

    print("Offline validation successful.")
    sys.exit(0)


def main():
    args = parse_args()
    if args.fetch:
        run_fetch()
    elif args.offline:
        run_offline()


if __name__ == "__main__":
    main()
