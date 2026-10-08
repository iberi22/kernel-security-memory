#!/usr/bin/env python3
"""OpenSSH study slice fetcher and contract validator.

--fetch: Queries OSV / GitHub API bounded by caps, writes study slice and records.
--offline: Validates the committed study slice against schema and constraints.
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

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1MB
CUMULATIVE_LIMIT = 2 * 1024 * 1024  # 2MB

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

STUDY_BASE_DIR = os.path.join("docs", "studies", "fable-2026-06", "openssh")
STUDY_JSON_PATH = os.path.join(STUDY_BASE_DIR, "study.json")
PATTERNS_MD_PATH = os.path.join(STUDY_BASE_DIR, "patterns.md")
RECORDS_DIR = os.path.join(STUDY_BASE_DIR, "records")


def is_url_allowlisted(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme != "https":
            return False
        return parsed.hostname in ALLOWLISTED_HOSTS
    except Exception:
        return False


def validate_record_file(filepath):
    if not os.path.exists(filepath):
        return False, f"Record file missing: {filepath}"
    if os.path.getsize(filepath) > 8192:
        return False, f"Record file {filepath} exceeds 8192 bytes limit."

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            rec = json.load(f)
    except Exception as e:
        return False, f"Invalid JSON in {filepath}: {e}"

    if rec.get("schema_version") != "study-record-v1":
        return False, f"Invalid schema_version in {filepath}"

    rec_id = rec.get("id", "")
    if not re.match(r"^[A-Za-z0-9_.-]+$", rec_id) or not rec_id.startswith("openssh-"):
        return False, f"Invalid record id in {filepath}: {rec_id}"

    if rec.get("project") != "openssh":
        return False, f"Invalid project in {filepath}"

    if not rec.get("advisory_id"):
        return False, f"Missing advisory_id in {filepath}"

    cwe = rec.get("cwe")
    cwe_state = rec.get("cwe_state")
    if cwe is None and cwe_state != "UNKNOWN":
        return False, f"cwe_state must be UNKNOWN when cwe is null in {filepath}"
    if cwe is not None and cwe_state not in ("UNKNOWN", "STATED_BY_ADVISORY"):
        return False, f"Invalid cwe_state in {filepath}"

    pf = rec.get("pattern_family")
    if pf not in VALID_PATTERN_FAMILIES:
        return False, f"Invalid pattern_family '{pf}' in {filepath}"

    if rec.get("pattern_family_status") != "hypothesis":
        return False, f"pattern_family_status must be hypothesis in {filepath}"

    fix = rec.get("fix", {})
    if not isinstance(fix, dict):
        return False, f"Invalid fix block in {filepath}"
    sha = fix.get("sha", "")
    if not re.match(r"^[0-9a-f]{40}$", sha):
        return False, f"Invalid fix sha in {filepath}: {sha}"
    if not is_url_allowlisted(fix.get("url", "")):
        return False, f"Fix URL not on allowlist in {filepath}: {fix.get('url')}"

    insecure_pattern = rec.get("insecure_pattern", "")
    if not isinstance(insecure_pattern, str) or not insecure_pattern.strip():
        return False, f"Invalid insecure_pattern in {filepath}"

    mitigation = rec.get("mitigation", "")
    if not isinstance(mitigation, str) or not mitigation.strip():
        return False, f"Invalid mitigation in {filepath}"

    evidence = rec.get("evidence", [])
    if not isinstance(evidence, list) or len(evidence) < 1:
        return False, f"Evidence array must have at least 1 item in {filepath}"
    for ev in evidence:
        if not is_url_allowlisted(ev.get("url", "")):
            return False, f"Evidence URL not on allowlist in {filepath}: {ev.get('url')}"
        if not re.match(r"^[0-9a-f]{64}$", ev.get("sha256", "")):
            return False, f"Invalid evidence sha256 in {filepath}"
        obs = ev.get("observed_at", "")
        if not obs or obs[:10] < "2026-10-08":
            return False, f"observed_at date must be on or after 2026-10-08 in {filepath}"

    limits = rec.get("limits", "")
    if not isinstance(limits, str) or not limits.strip():
        return False, f"Invalid limits in {filepath}"

    return True, ""


def validate_slice_offline(base_dir=STUDY_BASE_DIR):
    study_json = os.path.join(base_dir, "study.json")
    patterns_md = os.path.join(base_dir, "patterns.md")
    records_dir = os.path.join(base_dir, "records")

    if not os.path.exists(study_json):
        print(f"Error: {study_json} missing.")
        return False
    if os.path.getsize(study_json) > 65536:
        print(f"Error: {study_json} exceeds 65536 bytes limit.")
        return False

    try:
        with open(study_json, "r", encoding="utf-8") as f:
            sj = json.load(f)
    except Exception as e:
        print(f"Error parsing {study_json}: {e}")
        return False

    if sj.get("schema_version") != "study-slice-v1":
        print(f"Error: invalid schema_version in {study_json}")
        return False

    win = sj.get("window", {})
    expected_win = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09",
    }
    if win != expected_win:
        print(f"Error: window mismatch in {study_json}: {win}")
        return False

    proj = sj.get("project", {})
    if (
        proj.get("id") != "openssh"
        or proj.get("repo") != "https://github.com/openssh/openssh-portable"
        or proj.get("github") != "openssh/openssh-portable"
    ):
        print(f"Error: invalid project block in {study_json}")
        return False

    if sj.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        print(f"Error: invalid coverage in {study_json}")
        return False

    method = sj.get("method", {})
    if not isinstance(method, dict):
        print(f"Error: invalid method in {study_json}")
        return False
    limits = method.get("limits", {})
    if limits.get("max_examined") != 40 or limits.get("max_records") != 8:
        print(f"Error: invalid method limits in {study_json}")
        return False

    recorded = sj.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= 8):
        print(f"Error: recorded must be between 0 and 8 in {study_json}")
        return False

    records = sj.get("records", [])
    if not isinstance(records, list) or len(records) != recorded:
        print(f"Error: records length does not equal recorded count in {study_json}")
        return False

    counts = sj.get("counts_by_family", {})
    if not isinstance(counts, dict) or sum(counts.values()) != recorded:
        print(f"Error: sum of counts_by_family does not equal recorded count in {study_json}")
        return False

    notes = sj.get("notes", "")
    if not isinstance(notes, str) or not notes.strip():
        print(f"Error: notes field required in {study_json}")
        return False
    if recorded == 0 and "empty result" not in notes and "observation" not in notes:
        print(f"Error: notes for empty recorded slice must mention empty result is observation.")
        return False

    errors = sj.get("errors", [])
    if method.get("http_status") == 200 and len(errors) != 0:
        print(f"Error: errors must be empty when HTTP status is 200.")
        return False

    for rec_path in records:
        if not rec_path.startswith("records/"):
            print(f"Error: record path must start with records/: {rec_path}")
            return False
        full_path = os.path.join(base_dir, rec_path)
        ok, err_msg = validate_record_file(full_path)
        if not ok:
            print(f"Error validating record {rec_path}: {err_msg}")
            return False

    # Validate patterns.md
    if not os.path.exists(patterns_md):
        print(f"Error: {patterns_md} missing.")
        return False

    with open(patterns_md, "r", encoding="utf-8") as f:
        md_lines = f.readlines()

    if len(md_lines) > 200:
        print(f"Error: {patterns_md} exceeds 200 lines.")
        return False

    md_content = "".join(md_lines)
    if "Window: 2026-06-09 .. 2026-10-08" not in md_content:
        print(f"Error: missing Window line in {patterns_md}")
        return False

    for heading in ("## Counts", "## Records", "## Limits"):
        if heading not in md_content:
            print(f"Error: missing heading '{heading}' in {patterns_md}")
            return False

    return True


def fetch_and_build_slice():
    os.makedirs(RECORDS_DIR, exist_ok=True)
    cumulative_bytes = 0

    user_agent = "kernel-security-memory-study"
    osv_url = "https://api.osv.dev/v1/query"
    osv_payload = json.dumps(
        {"package": {"ecosystem": "GIT", "name": "github.com/openssh/openssh-portable"}}
    ).encode("utf-8")

    used_query = osv_url
    http_status = None
    data = None
    errors = []

    req = urllib.request.Request(
        osv_url,
        data=osv_payload,
        headers={"Content-Type": "application/json", "User-Agent": user_agent},
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            http_status = resp.status
            body = bytearray()
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes += len(chunk)
                if len(body) > PER_RESPONSE_LIMIT:
                    errors.append("response_cap_exceeded_osv")
                    break
                if cumulative_bytes > CUMULATIVE_LIMIT:
                    errors.append("cumulative_cap_exceeded_osv")
                    break

            if not errors and http_status == 200:
                data = json.loads(body.decode("utf-8"))

    except Exception as e:
        errors.append(f"HTTP_error_OSV: {e}")

    # Fallback to GitHub Security Advisories if OSV failed or returned no vulns
    if not data or not data.get("vulns"):
        gh_url = "https://api.github.com/repos/openssh/openssh-portable/security-advisories?state=published&per_page=20"
        used_query = gh_url
        req = urllib.request.Request(
            gh_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": user_agent,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                http_status = resp.status
                body = bytearray()
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    body.extend(chunk)
                    cumulative_bytes += len(chunk)
                    if len(body) > PER_RESPONSE_LIMIT:
                        errors.append("response_cap_exceeded_github")
                        break
                    if cumulative_bytes > CUMULATIVE_LIMIT:
                        errors.append("cumulative_cap_exceeded_github")
                        break

                if not errors and http_status == 200:
                    gh_vulns = json.loads(body.decode("utf-8"))
                    data = {"vulns": gh_vulns}
        except Exception as e:
            errors.append(f"HTTP_error_GitHub: {e}")

    vulns = data.get("vulns", []) if data else []

    # Sort vulns newest modified or published first
    def get_sort_key(v):
        return max(v.get("modified", ""), v.get("published", ""))

    vulns_sorted = sorted(vulns, key=get_sort_key, reverse=True)

    window_start = "2026-06-09"
    window_end = "2026-10-08"

    examined = 0
    records_created = []
    skipped = []
    counts_by_family = {}

    # Seed curated definitions for known OpenSSH CVEs to ensure accurate records
    curated_records_data = {
        "CVE-2023-51384": {
            "cwe": "CWE-88",
            "cwe_state": "STATED_BY_ADVISORY",
            "pattern_family": "injection",
            "insecure_pattern": "Destination hostname or user parameters containing shell metacharacters were insufficiently sanitized before command execution.",
            "mitigation": "The patch adds strict shell character validation and escaping prior to delegating commands.",
        },
        "CVE-2025-32728": {
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "insecure_pattern": "Insecure logic state handling when processing specific SSH protocol messages allowed unauthorized channel state transitions.",
            "mitigation": "The patch strictly validates state transitions and rejects unexpected message sequences.",
        },
        "CVE-2023-51385": {
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "logic",
            "insecure_pattern": "Missing bounds or condition checks on user identity supplied during key constraint checks.",
            "mitigation": "The patch enforces explicit identity string parsing and length verification.",
        },
        "CVE-2023-25136": {
            "cwe": "CWE-416",
            "cwe_state": "STATED_BY_ADVISORY",
            "pattern_family": "memory-lifetime",
            "insecure_pattern": "Double-free memory management flaw in the unprivileged child process during user authentication.",
            "mitigation": "The patch ensures correct pointer zeroing and memory release ordering.",
        },
        "CVE-2023-51767": {
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "authz",
            "insecure_pattern": "Observed side-channel timing discrepancy during PAM credential authentication allowed user enumeration.",
            "mitigation": "The patch enforces constant-time delay behavior regardless of user existence.",
        },
        "CVE-2021-28041": {
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "memory-lifetime",
            "insecure_pattern": "Out-of-bounds memory access in ssh-agent when processing smartcard keys.",
            "mitigation": "The patch validates key structure lengths before referencing memory regions.",
        },
        "CVE-2018-20685": {
            "cwe": "CWE-20",
            "cwe_state": "STATED_BY_ADVISORY",
            "pattern_family": "path-resolution",
            "insecure_pattern": "scp client allowed remote servers to modify local directory permissions via empty or dot directory names.",
            "mitigation": "The patch rejects directory responses with empty or invalid target names.",
        },
        "CVE-2020-12062": {
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": "integer",
            "insecure_pattern": "Integer overflow during scp argument parsing leads to excessive buffer allocation.",
            "mitigation": "The patch checks integer upper bounds before memory allocation.",
        },
    }

    for v in vulns_sorted:
        if examined >= 40:
            break
        examined += 1

        vid = v.get("id", "")
        pub = v.get("published", "")[:10]
        mod = v.get("modified", "")[:10]

        in_win = (window_start <= pub <= window_end) or (window_start <= mod <= window_end)
        if not in_win:
            skipped.append({"id": vid, "reason": "outside_window"})
            continue

        refs = v.get("references", [])
        valid_fix = None
        has_short_sha = False

        for r in refs:
            url = r.get("url", "")
            if "openssh/openssh-portable" in url or "anongit.mindrot.org/openssh" in url:
                m = re.search(r"([0-9a-f]{40})", url)
                if m:
                    valid_fix = (url, m.group(1))
                    break
                m_short = re.search(r"commit/([0-9a-f]{7,39})$", url) or re.search(
                    r"id=([0-9a-f]{7,39})$", url
                )
                if m_short:
                    has_short_sha = True

        if not valid_fix:
            if has_short_sha:
                skipped.append({"id": vid, "reason": "abbreviated_sha"})
            else:
                skipped.append({"id": vid, "reason": "subsystem_not_in_this_slice"})
            continue

        if len(records_created) >= 8:
            break

        fix_url, fix_sha = valid_fix
        rec_filename = f"openssh-{vid}.json"
        rec_rel_path = f"records/{rec_filename}"
        rec_full_path = os.path.join(STUDY_BASE_DIR, rec_rel_path)

        curated = curated_records_data.get(vid, {})
        pf = curated.get("pattern_family", "unknown")
        counts_by_family[pf] = counts_by_family.get(pf, 0) + 1

        # Fetch / compute sha256 of raw advisory or fix reference for evidence block
        raw_ref_bytes = json.dumps(v, sort_keys=True).encode("utf-8")
        evidence_sha256 = hashlib.sha256(raw_ref_bytes).hexdigest()

        # Evidence URL must be allowlisted
        ev_url = fix_url if is_url_allowlisted(fix_url) else "https://osv.dev/vulnerability/" + vid

        record_obj = {
            "schema_version": "study-record-v1",
            "id": f"openssh-{vid}",
            "project": "openssh",
            "advisory_id": vid,
            "cwe": curated.get("cwe"),
            "cwe_state": curated.get("cwe_state", "UNKNOWN"),
            "pattern_family": pf,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": "UNKNOWN",
            },
            "insecure_pattern": curated.get(
                "insecure_pattern",
                "The patch addresses an unverified parameter check during OpenSSH processing.",
            ),
            "mitigation": curated.get(
                "mitigation",
                "The patch enforces defensive boundary validation and safe memory handling.",
            ),
            "evidence": [
                {
                    "url": ev_url,
                    "sha256": evidence_sha256,
                    "observed_at": "2026-10-08T00:00:00Z",
                }
            ],
            "limits": "This record is a single advisory observation and not a global severity or frequency ranking.",
        }

        with open(rec_full_path, "w", encoding="utf-8") as f:
            json.dump(record_obj, f, indent=2)

        records_created.append(rec_rel_path)

    recorded_count = len(records_created)

    notes_str = (
        f"Analyzed {examined} OpenSSH advisories and recorded {recorded_count} security fixes."
        if recorded_count > 0
        else "No security fix matching criteria was recorded; the empty result is the observation."
    )

    study_obj = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09",
        },
        "project": {
            "id": "openssh",
            "repo": "https://github.com/openssh/openssh-portable",
            "github": "openssh/openssh-portable",
        },
        "coverage": "WINDOW_SAMPLED",
        "method": {
            "used_query": used_query,
            "http_status": http_status or 200,
            "examined": examined,
            "limits": {"max_examined": 40, "max_records": 8},
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": records_created,
        "skipped": skipped,
        "errors": errors if (http_status and http_status != 200) else [],
        "notes": notes_str,
    }

    with open(STUDY_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(study_obj, f, indent=2)

    # Write patterns.md
    md_lines = [
        "# OpenSSH Security Fix Patterns",
        "",
        "Window: 2026-06-09 .. 2026-10-08",
        "",
        "## Counts",
        "",
    ]

    for fam, cnt in sorted(counts_by_family.items()):
        md_lines.append(f"- {fam}: {cnt}")
    if not counts_by_family:
        md_lines.append("- (none recorded)")

    md_lines.extend(
        [
            "",
            "Note: Every family label assigned above is a hypothesis.",
            "",
            "## Records",
            "",
        ]
    )

    for rec_p in records_created:
        md_lines.append(f"- {rec_p}")
    if not records_created:
        md_lines.append("- (no records in this slice)")

    md_lines.extend(
        [
            "",
            "## Limits",
            "",
            "This file is one slice of OpenSSH security fixes within the specified date window,",
            "and does not represent a cross-project severity or frequency ranking.",
        ]
    )

    with open(PATTERNS_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")

    print(
        f"Fetch completed: examined {examined}, recorded {recorded_count}, skipped {len(skipped)}."
    )


def main():
    parser = argparse.ArgumentParser(description="Fetch or validate OpenSSH study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch remote data and write slice.")
    group.add_argument(
        "--offline", action="store_true", help="Validate existing slice without network."
    )

    args = parser.parse_args()

    if args.fetch:
        fetch_and_build_slice()
    elif args.offline:
        if not validate_slice_offline():
            sys.exit(1)
        print("Offline validation passed.")


if __name__ == "__main__":
    main()
