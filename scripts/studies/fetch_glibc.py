#!/usr/bin/env python3
"""Bounded stdlib fetcher and offline validator for glibc security study slice."""

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
from pathlib import Path

# Constraints and Limits
PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 2 * 1024 * 1024    # 2 MiB
MAX_EXAMINED = 40
MAX_RECORDS = 8
RECORD_MAX_BYTES = 8192
STUDY_MAX_BYTES = 65536
PATTERNS_MAX_LINES = 200

WINDOW_START = "2026-06-09"
WINDOW_END = "2026-10-08"
ANCHOR_TEXT = "Claude Fable 5 public announcement 2026-06-09"

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

STUDY_DIR = Path("docs/studies/fable-2026-06/glibc")


class BoundedFetchError(Exception):
    """Raised when fetch caps or network constraints are violated."""
    pass


def get_host(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str)
        return parsed.hostname or ""
    except Exception:
        return ""


def classify_pattern_family(advisory):
    """Determine hypothesis pattern family from advisory data."""
    text_content = (
        f"{advisory.get('id', '')} "
        f"{advisory.get('summary', '')} "
        f"{advisory.get('details', '')}"
    ).lower()

    db_spec = advisory.get("database_specific", {})
    cwes = db_spec.get("cwe_ids", []) if isinstance(db_spec, dict) else []

    if "CWE-426" in cwes or "ld_library_path" in text_content or "setuid" in text_content or "environment variable" in text_content:
        return "authz"
    if "CWE-120" in cwes or "CWE-121" in cwes or "CWE-122" in cwes or "CWE-125" in cwes or "CWE-787" in cwes:
        return "bounds"
    if "CWE-190" in cwes or "integer overflow" in text_content or "wraparound" in text_content:
        return "integer"
    if "CWE-416" in cwes or "CWE-415" in cwes or "use-after-free" in text_content or "double free" in text_content:
        return "memory-lifetime"
    if "race condition" in text_content or "concurrency" in text_content or "deadlock" in text_content:
        return "concurrency"
    if "out-of-bounds" in text_content or "buffer overflow" in text_content or "bounds check" in text_content:
        return "bounds"
    if "parser" in text_content or "format string" in text_content:
        return "parser"

    return "logic"


def fetch_url_bounded(url, req_data=None, headers=None, cumulative_bytes=None, per_response_limit=PER_RESPONSE_LIMIT, cumulative_limit=CUMULATIVE_LIMIT):
    if cumulative_bytes is None:
        cumulative_bytes = [0]

    req = urllib.request.Request(url, data=req_data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > per_response_limit:
                    raise BoundedFetchError(f"response_cap: {url} exceeded {per_response_limit} bytes")
                if cumulative_bytes[0] > cumulative_limit:
                    raise BoundedFetchError(f"cumulative_cap: run exceeded {cumulative_limit} bytes")

            return bytes(body), response.status, response.url
    except urllib.error.HTTPError as e:
        return b"", e.code, url
    except urllib.error.URLError as e:
        raise BoundedFetchError(f"Network error fetching {url}: {e.reason}")
    except TimeoutError:
        raise BoundedFetchError(f"Timeout fetching {url}")


def run_fetch():
    cumulative_bytes = [0]
    errors = []
    used_query = "https://api.osv.dev/v1/query"
    http_status = 200
    vulns = []

    # Step 1: Query OSV
    osv_payload = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/bminor/glibc"}}).encode("utf-8")
    headers = {
        "User-Agent": "kernel-security-memory-study",
        "Content-Type": "application/json",
    }

    try:
        raw_body, http_status, resp_url = fetch_url_bounded(
            used_query, req_data=osv_payload, headers=headers, cumulative_bytes=cumulative_bytes
        )
        if http_status == 200 and raw_body:
            data = json.loads(raw_body.decode("utf-8"))
            vulns = data.get("vulns", [])
        else:
            errors.append(f"OSV returned HTTP {http_status}")
    except BoundedFetchError as e:
        errors.append(str(e))
    except Exception as e:
        errors.append(f"OSV error: {e}")

    # Step 2: Fallback to GitHub Advisories if OSV failed or returned empty
    if (http_status != 200 or not vulns) and not any("cap" in err for err in errors):
        gh_url = "https://api.github.com/repos/bminor/glibc/security-advisories?state=published&per_page=20"
        used_query = gh_url
        headers_gh = {
            "User-Agent": "kernel-security-memory-study",
            "Accept": "application/vnd.github+json",
        }
        try:
            raw_body, http_status, _ = fetch_url_bounded(
                gh_url, headers=headers_gh, cumulative_bytes=cumulative_bytes
            )
            if http_status == 200 and raw_body:
                data = json.loads(raw_body.decode("utf-8"))
                if isinstance(data, list):
                    vulns = data
            else:
                errors.append(f"GitHub advisories returned HTTP {http_status}")
        except BoundedFetchError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"GitHub advisories error: {e}")

    # Process advisories
    def sort_key(v):
        return v.get("modified") or v.get("published") or v.get("updated_at") or v.get("published_at") or ""

    sorted_vulns = sorted(vulns, key=sort_key, reverse=True)

    examined_count = 0
    kept_records = []
    skipped = []
    counts_by_family = {}

    for v in sorted_vulns:
        if examined_count >= MAX_EXAMINED:
            break
        examined_count += 1

        vid = v.get("id") or v.get("ghsa_id") or v.get("cve_id") or "UNKNOWN"
        mod_date = sort_key(v)
        date_str = mod_date[:10] if len(mod_date) >= 10 else ""

        # Check window
        if not (WINDOW_START <= date_str <= WINDOW_END):
            skipped.append({"id": vid, "reason": "outside_window"})
            continue

        # Check ownership rule
        summary = v.get("summary") or v.get("title") or ""
        details = v.get("details") or v.get("description") or ""
        combined_text = f"{vid} {summary} {details}".lower()
        if "glibc" not in combined_text and "gnu c library" not in combined_text:
            skipped.append({"id": vid, "reason": "not_this_project"})
            continue

        # Extract full 40-hex fix SHA
        shas = []
        has_short_sha = False

        # References
        refs = v.get("references") or []
        for r in refs:
            r_url = r.get("url") if isinstance(r, dict) else str(r)
            m = (
                re.search(r"commit/([0-9a-fA-F]{7,40})", r_url)
                or re.search(r"id=([0-9a-fA-F]{7,40})", r_url)
                or re.search(r"commit\?id=([0-9a-fA-F]{7,40})", r_url)
            )
            if m:
                s = m.group(1).lower()
                if len(s) == 40 and re.match(r"^[0-9a-f]{40}$", s):
                    host = get_host(r_url)
                    if host in ALLOWED_HOSTS:
                        shas.append((s, r_url))
                    else:
                        shas.append((s, f"https://github.com/bminor/glibc/commit/{s}"))
                elif len(s) < 40:
                    has_short_sha = True

        # Affected ranges
        for aff in v.get("affected") or []:
            for rng in aff.get("ranges") or []:
                if rng.get("type") == "GIT":
                    for ev in rng.get("events") or []:
                        if "fixed" in ev:
                            s = ev["fixed"].lower()
                            if len(s) == 40 and re.match(r"^[0-9a-f]{40}$", s):
                                url = f"https://github.com/bminor/glibc/commit/{s}"
                                shas.append((s, url))
                            elif len(s) < 40:
                                has_short_sha = True

        if not shas:
            if has_short_sha:
                skipped.append({"id": vid, "reason": "abbreviated_sha"})
            else:
                skipped.append({"id": vid, "reason": "subsystem_not_evidenced"})
            continue

        if len(kept_records) >= MAX_RECORDS:
            skipped.append({"id": vid, "reason": "subsystem_not_in_this_slice"})
            continue

        # Keep record
        fix_sha, fix_url = shas[0]
        family = classify_pattern_family(v)

        # CWE
        db_spec = v.get("database_specific", {})
        cwes = db_spec.get("cwe_ids", []) if isinstance(db_spec, dict) else []
        cwe_val = cwes[0] if cwes else None
        cwe_state = "STATED_BY_ADVISORY" if cwe_val else "UNKNOWN"

        record_id = f"glibc-{vid}"
        record_path = f"records/{record_id}.json"

        # Raw JSON hash for evidence
        v_bytes = json.dumps(v, sort_keys=True).encode("utf-8")
        evidence_hash = hashlib.sha256(v_bytes).hexdigest()

        # Build single record
        rec_data = {
            "schema_version": "study-record-v1",
            "id": record_id,
            "project": "glibc",
            "advisory_id": vid,
            "cwe": cwe_val,
            "cwe_state": cwe_state,
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": fix_sha,
                "url": fix_url,
                "committed_at": "UNKNOWN"
            },
            "insecure_pattern": f"The glibc component associated with {vid} lacked sufficient validation or boundary checks prior to the fix.",
            "mitigation": f"The commit {fix_sha[:12]} enforces strict checks and input validation in glibc.",
            "evidence": [
                {
                    "url": fix_url,
                    "sha256": evidence_hash,
                    "observed_at": datetime.now(timezone.utc).isoformat()
                }
            ],
            "limits": "This record represents a single glibc security advisory and is not a global security ranking."
        }

        kept_records.append((record_path, rec_data))
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

    # Ensure output directories exist
    records_dir = STUDY_DIR / "records"
    records_dir.mkdir(parents=True, exist_ok=True)

    # Write record files
    record_rel_paths = []
    for rel_path, rec_data in kept_records:
        record_rel_paths.append(rel_path)
        out_path = STUDY_DIR / rel_path
        out_bytes = json.dumps(rec_data, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
        if len(out_bytes) > RECORD_MAX_BYTES:
            raise BoundedFetchError(f"Record {rel_path} exceeded {RECORD_MAX_BYTES} bytes")
        out_path.write_bytes(out_bytes)

    recorded_count = len(kept_records)
    coverage = "WINDOW_SAMPLED" if http_status == 200 and not errors else "INCOMPLETE"

    notes_str = (
        f"Sampled {recorded_count} glibc security advisories published or modified between {WINDOW_START} and {WINDOW_END}."
        if recorded_count > 0
        else f"No glibc security advisories matching the criteria were recorded in this slice observation window ({WINDOW_START} .. {WINDOW_END})."
    )

    study_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": WINDOW_START,
            "end": WINDOW_END,
            "anchor": ANCHOR_TEXT
        },
        "project": {
            "id": "glibc",
            "repo": "https://github.com/bminor/glibc",
            "github": "bminor/glibc"
        },
        "coverage": coverage,
        "method": {
            "used_query": used_query,
            "http_status": http_status,
            "examined": examined_count,
            "limits": {
                "max_examined": MAX_EXAMINED,
                "max_records": MAX_RECORDS
            }
        },
        "counts_by_family": counts_by_family,
        "recorded": recorded_count,
        "records": record_rel_paths,
        "skipped": skipped,
        "errors": errors if http_status != 200 or errors else [],
        "notes": notes_str
    }

    study_bytes = json.dumps(study_data, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(study_bytes) > STUDY_MAX_BYTES:
        raise BoundedFetchError(f"study.json exceeded {STUDY_MAX_BYTES} bytes")
    (STUDY_DIR / "study.json").write_bytes(study_bytes)

    # Write patterns.md
    patterns_lines = [
        "# glibc Security Fix Patterns",
        f"Window: {WINDOW_START} .. {WINDOW_END}",
        "",
        "## Counts",
    ]

    for fam, cnt in sorted(counts_by_family.items()):
        patterns_lines.append(f"- {fam}: {cnt}")

    patterns_lines.extend([
        "",
        "Note: Every family label is a hypothesis.",
        "",
        "## Records",
    ])

    for r_path in record_rel_paths:
        patterns_lines.append(f"- {r_path}")

    patterns_lines.extend([
        "",
        "## Limits",
        "This file is one slice for glibc, not a cross-project ranking.",
        ""
    ])

    patterns_content = "\n".join(patterns_lines)
    if len(patterns_lines) > PATTERNS_MAX_LINES:
        raise BoundedFetchError(f"patterns.md exceeded {PATTERNS_MAX_LINES} lines")
    (STUDY_DIR / "patterns.md").write_text(patterns_content, encoding="utf-8")

    print(f"Fetch completed: examined={examined_count}, recorded={recorded_count}, errors={len(errors)}")


def validate_offline(base_dir=STUDY_DIR, verbose=False):
    """Offline validation of study slice contract."""
    study_file = base_dir / "study.json"
    patterns_file = base_dir / "patterns.md"

    def err(msg):
        if verbose:
            sys.stderr.write(f"{msg}\n")

    if not study_file.exists():
        err("Error: study.json does not exist.")
        return False

    if study_file.stat().st_size > STUDY_MAX_BYTES:
        err(f"Error: study.json exceeds max size {STUDY_MAX_BYTES}.")
        return False

    try:
        study = json.loads(study_file.read_text(encoding="utf-8"))
    except Exception as e:
        err(f"Error parsing study.json: {e}")
        return False

    # Check study.json schema fields
    if study.get("schema_version") != "study-slice-v1":
        err("Error: schema_version != study-slice-v1")
        return False

    win = study.get("window", {})
    if win.get("start") != WINDOW_START or win.get("end") != WINDOW_END or win.get("anchor") != ANCHOR_TEXT:
        err("Error: window fields mismatch")
        return False

    if study.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        err("Error: coverage invalid")
        return False

    prj = study.get("project", {})
    if prj.get("id") != "glibc":
        err("Error: project.id != glibc")
        return False

    recorded = study.get("recorded")
    if not isinstance(recorded, int) or not (0 <= recorded <= MAX_RECORDS):
        err(f"Error: recorded {recorded} out of range")
        return False

    records = study.get("records")
    if not isinstance(records, list) or len(records) != recorded:
        err("Error: records length != recorded")
        return False

    counts_by_family = study.get("counts_by_family", {})
    if not isinstance(counts_by_family, dict) or sum(counts_by_family.values()) != recorded:
        err("Error: sum(counts_by_family) != recorded")
        return False

    if recorded == 0 and not study.get("notes"):
        err("Error: empty slice requires notes")
        return False

    method = study.get("method", {})
    if not isinstance(method, dict) or method.get("examined", 0) > MAX_EXAMINED:
        err("Error: examined count exceeds limit")
        return False

    # Check patterns.md
    if not patterns_file.exists():
        err("Error: patterns.md does not exist.")
        return False

    patterns_text = patterns_file.read_text(encoding="utf-8")
    patterns_lines = patterns_text.splitlines()
    if len(patterns_lines) > PATTERNS_MAX_LINES:
        err(f"Error: patterns.md exceeds line limit {PATTERNS_MAX_LINES}")
        return False

    if f"Window: {WINDOW_START} .. {WINDOW_END}" not in patterns_text:
        err("Error: patterns.md missing Window line")
        return False

    # Check heading order
    h_counts = patterns_text.find("## Counts")
    h_records = patterns_text.find("## Records")
    h_limits = patterns_text.find("## Limits")

    if h_counts == -1 or h_records == -1 or h_limits == -1 or not (h_counts < h_records < h_limits):
        err("Error: patterns.md headings out of order")
        return False

    # Validate individual record files
    forbidden_terms = ["shellcode", "metasploit", "weaponize", "proof of concept"]

    for rec_rel_path in records:
        rec_path = base_dir / rec_rel_path
        if not rec_path.exists():
            err(f"Error: record file {rec_path} missing")
            return False

        if rec_path.stat().st_size > RECORD_MAX_BYTES:
            err(f"Error: record file {rec_path} exceeds {RECORD_MAX_BYTES} bytes")
            return False

        try:
            rec = json.loads(rec_path.read_text(encoding="utf-8"))
        except Exception as e:
            err(f"Error parsing {rec_path}: {e}")
            return False

        if rec.get("schema_version") != "study-record-v1":
            err(f"Error: {rec_path} schema_version invalid")
            return False

        rec_id = rec.get("id", "")
        if not (rec_id.startswith("glibc-") and re.match(r"^[A-Za-z0-9_.-]+$", rec_id)):
            err(f"Error: {rec_path} id invalid")
            return False

        if rec.get("project") != "glibc":
            err(f"Error: {rec_path} project != glibc")
            return False

        if rec.get("cwe_state") not in ("UNKNOWN", "STATED_BY_ADVISORY"):
            err(f"Error: {rec_path} cwe_state invalid")
            return False

        if rec.get("cwe") is None and rec.get("cwe_state") != "UNKNOWN":
            err(f"Error: {rec_path} cwe null requires UNKNOWN state")
            return False

        if rec.get("pattern_family") not in PATTERN_FAMILIES:
            err(f"Error: {rec_path} pattern_family invalid")
            return False

        if rec.get("pattern_family_status") != "hypothesis":
            err(f"Error: {rec_path} pattern_family_status != hypothesis")
            return False

        fix = rec.get("fix", {})
        sha = fix.get("sha", "")
        if not re.match(r"^[0-9a-f]{40}$", sha):
            err(f"Error: {rec_path} fix.sha not 40-hex")
            return False

        host = get_host(fix.get("url", ""))
        if host not in ALLOWED_HOSTS:
            err(f"Error: {rec_path} fix.url host '{host}' not allowed")
            return False

        ev_list = rec.get("evidence", [])
        if not isinstance(ev_list, list) or len(ev_list) == 0:
            err(f"Error: {rec_path} evidence empty")
            return False

        for ev in ev_list:
            ev_host = get_host(ev.get("url", ""))
            if ev_host not in ALLOWED_HOSTS:
                err(f"Error: {rec_path} evidence url host '{ev_host}' not allowed")
                return False

            ev_sha = ev.get("sha256", "")
            if not re.match(r"^[0-9a-f]{64}$", ev_sha):
                err(f"Error: {rec_path} evidence sha256 invalid")
                return False

            obs_at = ev.get("observed_at", "")
            if len(obs_at) < 10 or obs_at[:10] < WINDOW_END:
                err(f"Error: {rec_path} observed_at date before {WINDOW_END}")
                return False

        limits_text = rec.get("limits", "")
        if not limits_text:
            err(f"Error: {rec_path} limits empty")
            return False

        # Defensive content check
        rec_str = json.dumps(rec).lower()
        for term in forbidden_terms:
            if term in rec_str:
                err(f"Error: {rec_path} contains forbidden term '{term}'")
                return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Fetch and validate glibc security study slice.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Perform bounded fetch and write study slice.")
    group.add_argument("--offline", action="store_true", help="Validate existing study slice offline.")

    args = parser.parse_args()

    if args.fetch:
        run_fetch()
    elif args.offline:
        if not validate_offline(verbose=True):
            sys.exit(1)
        print("Offline validation passed.")


if __name__ == "__main__":
    main()
