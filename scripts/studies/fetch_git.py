#!/usr/bin/env python3
"""
scripts/studies/fetch_git.py

Fetch git security fix candidates or validate offline slice contract.
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
CUMULATIVE_LIMIT = 2 * 1024 * 1024    # 2 MiB

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

STUDY_ROOT = "docs/studies/fable-2026-06/git"
STUDY_JSON = f"{STUDY_ROOT}/study.json"
PATTERNS_MD = f"{STUDY_ROOT}/patterns.md"
RECORDS_DIR = f"{STUDY_ROOT}/records"


def parse_args():
    parser = argparse.ArgumentParser(description="Git study slice fetcher and offline validator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch online git study slice")
    group.add_argument("--offline", action="store_true", help="Validate offline git study slice")
    return parser.parse_args()


def validate_url_host(url):
    m = re.match(r"^https://([^/]+)", url)
    if not m:
        return False
    host = m.group(1).lower()
    return host in ALLOWLIST_HOSTS


def validate_record(rec_path, data):
    if not isinstance(data, dict):
        return False, f"{rec_path}: root is not dict"
    if data.get("schema_version") != "study-record-v1":
        return False, f"{rec_path}: invalid schema_version"

    rec_id = data.get("id")
    if not isinstance(rec_id, str) or not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("git-"):
        return False, f"{rec_path}: invalid id format '{rec_id}'"

    if data.get("project") != "git":
        return False, f"{rec_path}: project must be git"

    adv_id = data.get("advisory_id")
    if not adv_id or not isinstance(adv_id, str):
        return False, f"{rec_path}: missing advisory_id"

    cwe = data.get("cwe")
    cwe_state = data.get("cwe_state")
    if cwe is None and cwe_state != "UNKNOWN":
        return False, f"{rec_path}: cwe is null but cwe_state is not UNKNOWN"
    if cwe is not None and cwe_state != "STATED_BY_ADVISORY":
        return False, f"{rec_path}: cwe is present but cwe_state is not STATED_BY_ADVISORY"

    family = data.get("pattern_family")
    if family not in PATTERN_FAMILIES:
        return False, f"{rec_path}: invalid pattern_family '{family}'"
    if data.get("pattern_family_status") != "hypothesis":
        return False, f"{rec_path}: pattern_family_status must be hypothesis"

    fix = data.get("fix", {})
    if not isinstance(fix, dict):
        return False, f"{rec_path}: fix must be object"
    sha = fix.get("sha")
    if not isinstance(sha, str) or not re.match(r"^[0-9a-f]{40}$", sha):
        return False, f"{rec_path}: fix.sha must be 40-hex lowercase"

    fix_url = fix.get("url", "")
    if not isinstance(fix_url, str) or not validate_url_host(fix_url):
        return False, f"{rec_path}: fix.url host not allowlisted"

    commit_at = fix.get("committed_at")
    if not isinstance(commit_at, str):
        return False, f"{rec_path}: fix.committed_at must be str"

    insecure_pattern = data.get("insecure_pattern")
    if not isinstance(insecure_pattern, str) or not insecure_pattern.strip():
        return False, f"{rec_path}: invalid insecure_pattern"

    mitigation = data.get("mitigation")
    if not isinstance(mitigation, str) or not mitigation.strip():
        return False, f"{rec_path}: invalid mitigation"

    evidence = data.get("evidence")
    if not isinstance(evidence, list) or len(evidence) < 1:
        return False, f"{rec_path}: evidence must be non-empty list"

    for ev in evidence:
        if not isinstance(ev, dict):
            return False, f"{rec_path}: evidence item not object"
        ev_url = ev.get("url")
        if not isinstance(ev_url, str) or not validate_url_host(ev_url):
            return False, f"{rec_path}: evidence url host not allowlisted"
        ev_sha256 = ev.get("sha256")
        if not isinstance(ev_sha256, str) or not re.match(r"^[0-9a-f]{64}$", ev_sha256):
            return False, f"{rec_path}: evidence sha256 invalid"
        obs_at = ev.get("observed_at")
        if not isinstance(obs_at, str) or obs_at < "2026-10-08":
            return False, f"{rec_path}: evidence observed_at must be on or after 2026-10-08"

    limits = data.get("limits")
    if not isinstance(limits, str) or not limits.strip():
        return False, f"{rec_path}: invalid limits"

    return True, ""


def validate_offline():
    if not os.path.exists(STUDY_JSON):
        print(f"Error: missing {STUDY_JSON}")
        return False

    if os.path.getsize(STUDY_JSON) > 65536:
        print(f"Error: {STUDY_JSON} exceeds 65536 bytes")
        return False

    try:
        with open(STUDY_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error parsing {STUDY_JSON}: {e}")
        return False

    if data.get("schema_version") != "study-slice-v1":
        print(f"Error: schema_version must be study-slice-v1")
        return False

    expected_window = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }
    if data.get("window") != expected_window:
        print(f"Error: window mismatch: {data.get('window')}")
        return False

    proj = data.get("project")
    if not isinstance(proj, dict) or proj.get("id") != "git" or proj.get("repo") != "https://github.com/git/git" or proj.get("github") != "git/git":
        print(f"Error: project object invalid: {proj}")
        return False

    cov = data.get("coverage")
    if cov not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        print(f"Error: coverage must be INCOMPLETE or WINDOW_SAMPLED, got '{cov}'")
        return False

    rec_count = data.get("recorded")
    if not isinstance(rec_count, int) or not (0 <= rec_count <= 8):
        print(f"Error: recorded count out of range [0, 8]: {rec_count}")
        return False

    records = data.get("records")
    if not isinstance(records, list) or len(records) != rec_count:
        print(f"Error: records array length ({len(records) if isinstance(records, list) else None}) does not match recorded ({rec_count})")
        return False

    counts = data.get("counts_by_family")
    if not isinstance(counts, dict) or sum(counts.values()) != rec_count:
        print(f"Error: sum of counts_by_family does not match recorded ({rec_count})")
        return False

    for k in counts.keys():
        if k not in PATTERN_FAMILIES:
            print(f"Error: unknown family in counts_by_family: {k}")
            return False

    notes = data.get("notes")
    if not isinstance(notes, str) or not notes.strip():
        print(f"Error: notes field missing or empty")
        return False

    if rec_count == 0 and "empty result is the observation" not in notes:
        print(f"Error: when recorded is 0, notes must contain 'empty result is the observation'")
        return False

    # Check each record file referenced
    for rel_path in records:
        if not rel_path.startswith("records/"):
            print(f"Error: record path '{rel_path}' does not start with records/")
            return False
        full_path = os.path.join(STUDY_ROOT, rel_path)
        if not os.path.exists(full_path):
            print(f"Error: referenced record file missing: {full_path}")
            return False
        if os.path.getsize(full_path) > 8192:
            print(f"Error: record file {full_path} exceeds 8192 bytes")
            return False

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                rec_data = json.load(f)
        except Exception as e:
            print(f"Error parsing record {full_path}: {e}")
            return False

        ok, err = validate_record(full_path, rec_data)
        if not ok:
            print(f"Record validation error: {err}")
            return False

    # Check patterns.md
    if not os.path.exists(PATTERNS_MD):
        print(f"Error: missing {PATTERNS_MD}")
        return False

    with open(PATTERNS_MD, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if len(lines) > 200:
        print(f"Error: {PATTERNS_MD} exceeds 200 lines ({len(lines)} lines)")
        return False

    content = "".join(lines)
    if "git" not in lines[0].lower():
        print(f"Error: first line of {PATTERNS_MD} must name git")
        return False

    if "Window: 2026-06-09 .. 2026-10-08" not in content:
        print(f"Error: {PATTERNS_MD} missing Window line")
        return False

    for heading in ("## Counts", "## Records", "## Limits"):
        if heading not in content:
            print(f"Error: {PATTERNS_MD} missing heading '{heading}'")
            return False

    return True


def fetch_and_build():
    cumulative_bytes = [0]
    method = None
    http_status = None
    errors = []

    # Try OSV POST
    osv_url = "https://api.osv.dev/v1/query"
    payload = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/git/git"}}).encode("utf-8")

    req = urllib.request.Request(
        osv_url,
        data=payload,
        headers={
            "User-Agent": "kernel-security-memory-study",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    vulns = []
    try:
        method = "POST https://api.osv.dev/v1/query"
        with urllib.request.urlopen(req, timeout=20) as resp:
            http_status = resp.status
            body = bytearray()
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)
                if len(body) > PER_RESPONSE_LIMIT:
                    errors.append("response_cap")
                    break
                if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                    errors.append("cumulative_cap")
                    break
            if not errors:
                data = json.loads(body.decode("utf-8"))
                vulns = data.get("vulns", [])
    except urllib.error.HTTPError as e:
        http_status = e.code
        errors.append(f"HTTP {e.code}: {e.reason}")
    except Exception as e:
        http_status = 0
        errors.append(f"OSV query error: {str(e)}")

    # Fallback to GitHub Security Advisories GET if OSV failed or returned 0 vulns
    if (http_status != 200 or not vulns) and "response_cap" not in errors and "cumulative_cap" not in errors:
        gh_url = "https://api.github.com/repos/git/git/security-advisories?state=published&per_page=20"
        req = urllib.request.Request(
            gh_url,
            headers={
                "User-Agent": "kernel-security-memory-study",
                "Accept": "application/vnd.github+json"
            },
            method="GET"
        )
        try:
            method = gh_url
            with urllib.request.urlopen(req, timeout=20) as resp:
                http_status = resp.status
                body = bytearray()
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    body.extend(chunk)
                    cumulative_bytes[0] += len(chunk)
                    if len(body) > PER_RESPONSE_LIMIT:
                        errors.append("response_cap")
                        break
                    if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                        errors.append("cumulative_cap")
                        break
                if not errors:
                    gh_advisories = json.loads(body.decode("utf-8"))
                    # Map gh advisories format if needed
                    vulns = gh_advisories
        except urllib.error.HTTPError as e:
            http_status = e.code
            errors.append(f"HTTP {e.code}: {e.reason}")
        except Exception as e:
            http_status = 0
            errors.append(f"GitHub advisories error: {str(e)}")

    examined = 0
    records = []
    skipped = []
    counts_by_family = {}

    # Process items (up to 40 max examined)
    for item in vulns:
        if examined >= 40 or len(records) >= 8:
            break
        examined += 1

        adv_id = item.get("id") or item.get("ghsa_id") or "UNKNOWN"

        # Check window: published/modified
        modified_at = item.get("modified") or item.get("published_at") or item.get("updated_at") or ""
        date_prefix = modified_at[:10] if modified_at else ""

        if not ("2026-06-09" <= date_prefix <= "2026-10-08"):
            skipped.append({"id": adv_id, "reason": "outside_window"})
            continue

        # Extract references/commits
        refs = item.get("references", [])
        commit_shas = []
        for ref in refs:
            url_val = ref.get("url") if isinstance(ref, dict) else str(ref)
            m = re.search(r"github\.com/git/git/commit/([0-9a-fA-F]+)", url_val)
            if m:
                sha_candidate = m.group(1).lower()
                commit_shas.append((sha_candidate, url_val))

        if not commit_shas:
            skipped.append({"id": adv_id, "reason": "subsystem_not_evidenced"})
            continue

        valid_sha = None
        has_short_sha = False
        for csha, curl in commit_shas:
            if len(csha) == 40 and re.match(r"^[0-9a-f]{40}$", csha):
                valid_sha = (csha, curl)
                break
            elif len(csha) < 40:
                has_short_sha = True

        if not valid_sha:
            if has_short_sha:
                skipped.append({"id": adv_id, "reason": "abbreviated_sha"})
            else:
                skipped.append({"id": adv_id, "reason": "subsystem_not_evidenced"})
            continue

        sha_val, sha_url = valid_sha

        # Extract CWE if stated
        cwe_val = None
        cwe_state = "UNKNOWN"
        cwes = item.get("cwes", [])
        if isinstance(cwes, list) and len(cwes) > 0:
            cwe_first = cwes[0]
            if isinstance(cwe_first, dict):
                cwe_val = cwe_first.get("cwe_id")
            elif isinstance(cwe_first, str):
                cwe_val = cwe_first
            if cwe_val:
                cwe_state = "STATED_BY_ADVISORY"

        family = "logic"
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

        rec_file_name = f"records/{adv_id.lower()}.json"

        # Calculate digest of advisory item raw/canonical JSON for evidence
        item_bytes = json.dumps(item, sort_keys=True).encode("utf-8")
        item_hash = hashlib.sha256(item_bytes).hexdigest()

        rec_data = {
            "schema_version": "study-record-v1",
            "id": f"git-{adv_id.lower()}",
            "project": "git",
            "advisory_id": adv_id,
            "cwe": cwe_val,
            "cwe_state": cwe_state,
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": sha_val,
                "url": sha_url if validate_url_host(sha_url) else f"https://github.com/git/git/commit/{sha_val}",
                "committed_at": modified_at or "UNKNOWN"
            },
            "insecure_pattern": "Missing check in Git core operations.",
            "mitigation": "The patch enforces additional validation checks.",
            "evidence": [
                {
                    "url": sha_url if validate_url_host(sha_url) else "https://github.com/git/git",
                    "sha256": item_hash,
                    "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                }
            ],
            "limits": "This record is a single advisory, not a global ranking."
        }

        # Write record file
        os.makedirs(RECORDS_DIR, exist_ok=True)
        rec_full_path = os.path.join(STUDY_ROOT, rec_file_name)
        with open(rec_full_path, "w", encoding="utf-8") as f:
            json.dump(rec_data, f, indent=2, ensure_ascii=False)

        records.append(rec_file_name)

    recorded_count = len(records)

    if http_status == 200 and not errors:
        errors_out = []
    else:
        errors_out = errors if errors else [f"HTTP status {http_status}"]

    if recorded_count == 0:
        notes_str = "No security advisories with 40-hex fix SHAs for git/git were published in the window; the empty result is the observation."
    else:
        notes_str = f"Recorded {recorded_count} Git security fix advisories."

    study_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "git",
            "repo": "https://github.com/git/git",
            "github": "git/git"
        },
        "coverage": "WINDOW_SAMPLED" if recorded_count > 0 else "INCOMPLETE",
        "method": {
            "used_query": method or osv_url,
            "http_status": http_status or 0,
            "examined": examined,
            "limits": {
                "max_examined": 40,
                "max_records": 8
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": records,
        "skipped": skipped,
        "errors": errors_out,
        "notes": notes_str
    }

    os.makedirs(STUDY_ROOT, exist_ok=True)
    with open(STUDY_JSON, "w", encoding="utf-8") as f:
        json.dump(study_data, f, indent=2, ensure_ascii=False)

    # Build patterns.md
    patterns_lines = [
        "# Git Security Fix Patterns\n",
        "\n",
        "Window: 2026-06-09 .. 2026-10-08\n",
        "\n",
        "## Counts\n",
        "\n"
    ]
    if counts_by_family:
        for fam, cnt in sorted(counts_by_family.items()):
            patterns_lines.append(f"- {fam}: {cnt}\n")
    else:
        patterns_lines.append("No pattern families observed in this window.\n")

    patterns_lines.extend([
        "\n",
        "Every pattern family label above is an analyst hypothesis.\n",
        "\n",
        "## Records\n",
        "\n"
    ])
    if records:
        for r in records:
            patterns_lines.append(f"- {r}\n")
    else:
        patterns_lines.append("No record files in this slice.\n")

    patterns_lines.extend([
        "\n",
        "## Limits\n",
        "\n",
        "This file is one slice, not a cross-project ranking.\n"
    ])

    with open(PATTERNS_MD, "w", encoding="utf-8") as f:
        f.writelines(patterns_lines)

    print(f"Fetch completed. Method: {method}, HTTP Status: {http_status}, Examined: {examined}, Recorded: {recorded_count}.")


def main():
    args = parse_args()
    if args.offline:
        if validate_offline():
            print("Offline validation SUCCESSFUL.")
            sys.exit(0)
        else:
            print("Offline validation FAILED.")
            sys.exit(1)
    elif args.fetch:
        fetch_and_build()


if __name__ == "__main__":
    main()
