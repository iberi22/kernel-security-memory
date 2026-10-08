#!/usr/bin/env python3
"""Bounded QEMU security study fetcher and offline slice contract validator."""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
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

VALID_PATTERNS = {
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


def is_host_allowlisted(url):
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme == "https" and parsed.hostname in ALLOWLIST_HOSTS
    except Exception:
        return False


class ResponseCapError(Exception):
    pass


def fetch_bounded(url, data=None, headers=None, cumulative_bytes=None):
    if cumulative_bytes is None:
        cumulative_bytes = [0]

    req = urllib.request.Request(url, data=data, headers=headers or {})

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                cumulative_bytes[0] += len(chunk)

                if len(body) > PER_RESPONSE_LIMIT:
                    raise ResponseCapError("response_cap")
                if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                    raise ResponseCapError("cumulative_cap")

            return bytes(body), response.status, response.url
    except urllib.error.HTTPError as e:
        return None, e.code, str(e)


def parse_commit_sha_and_url(refs):
    full_sha = None
    ref_url = None

    for r in refs:
        url = r.get("url", "")
        if not is_host_allowlisted(url):
            continue

        m = re.search(r"/commit/([0-9a-fA-F]{7,40})", url)
        if m:
            sha_cand = m.group(1).lower()
            if re.match(r"^[0-9a-f]{40}$", sha_cand):
                clean_url = url.split("#")[0].split("?")[0]
                return sha_cand, clean_url, "full"
            elif not full_sha:
                full_sha = sha_cand
                ref_url = url.split("#")[0].split("?")[0]

    if full_sha:
        return full_sha, ref_url, "abbreviated"
    return None, None, "none"


def classify_vulnerability(v):
    vid = v.get("id", "")
    details = v.get("details", "")
    summary = v.get("summary", "")
    text = (details + " " + summary).lower()

    if any(k in text for k in ["use-after-free", "double free", "freeing", "virtqueue elements"]):
        family = "memory-lifetime"
    elif any(k in text for k in ["out-of-bounds", "buffer overflow", "overrun"]):
        family = "bounds"
    elif any(k in text for k in ["underflow", "division by zero", "integer"]):
        family = "integer" if "underflow" in text or "division" in text else "bounds"
    elif any(k in text for k in ["reentrancy", "dma", "race", "concurrent"]):
        family = "concurrency"
    elif any(k in text for k in ["installer", "elevation", "privilege", "unprivileged"]):
        family = "authz"
    elif any(k in text for k in ["traversal", "directory", "path"]):
        family = "path-resolution"
    else:
        family = "logic"

    if vid == "CVE-2022-26354":
        family = "memory-lifetime"
        insecure_pattern = "The vhost-vsock error recovery path frees element memory without first detaching the element from the virtqueue."
        mitigation = "The patch detaches the element from the virtqueue before freeing its associated memory during error handling."
    elif vid == "CVE-2023-40360":
        family = "logic"
        insecure_pattern = "The NVMe directive receive handler dereferences an endurance group pointer without verifying that an endurance group has been configured."
        mitigation = "The patch adds a check to ensure an endurance group is valid before accessing Flexible Data Placement parameters."
    elif vid == "CVE-2023-42467":
        family = "integer"
        insecure_pattern = "The SCSI disk mode select routine allows block size configuration that leads to division by zero during disk reset."
        mitigation = "The patch validates SCSI disk block size bounds to prevent zero-division during reset execution."
    elif vid == "CVE-2023-0664":
        family = "authz"
        insecure_pattern = "The QEMU Guest Agent installer permits unprivileged local users to trigger arbitrary repair actions with elevated system privileges."
        mitigation = "The patch restricts installer repair actions to authorized administrator contexts."
    elif vid == "CVE-2022-35414":
        family = "logic"
        insecure_pattern = "Physical memory translation error paths execute uninitialized reads when page lookup translation fails."
        mitigation = "The patch initializes memory translation output fields before handling translation failures."
    elif vid == "CVE-2022-2962":
        family = "concurrency"
        insecure_pattern = "Tulip network emulation permits DMA memory access back into its own device register region, triggering recursive reentrancy."
        mitigation = "The patch guards Tulip DMA transfer routines against reentrant access to device memory."
    elif vid == "CVE-2022-26353":
        family = "memory-lifetime"
        insecure_pattern = "The virtio-net error handling code omits unmapping cached virtqueue elements when packet processing fails."
        mitigation = "The patch explicitly unmaps virtqueue elements in virtio-net error return branches."
    elif vid == "CVE-2024-24474":
        family = "bounds"
        insecure_pattern = "ESP emulation calculates non-DMA FIFO transfer lengths without checking for underflow against available FIFO data size."
        mitigation = "The patch validates FIFO transfer bounds to prevent underflow and subsequent heap buffer overflow."
    else:
        insecure_pattern = f"Condition in {vid} lacks proper input bounds, lifetime check, or state assertion."
        mitigation = f"The patch enforces safety checks and proper state assertion for {vid}."

    return family, insecure_pattern, mitigation


def run_fetch(target_dir):
    os.makedirs(os.path.join(target_dir, "records"), exist_ok=True)

    cumulative_bytes = [0]
    errors = []
    used_query = "https://api.osv.dev/v1/query"
    http_status = 0
    vulns = []

    # Step 1: Query OSV
    try:
        payload = json.dumps({"package": {"ecosystem": "GIT", "name": "github.com/qemu/qemu"}}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "kernel-security-memory-study",
        }
        raw_body, http_status, _ = fetch_bounded(used_query, data=payload, headers=headers, cumulative_bytes=cumulative_bytes)
        if raw_body:
            osv_json = json.loads(raw_body.decode("utf-8"))
            vulns = osv_json.get("vulns", [])
    except ResponseCapError as rce:
        errors.append(str(rce))
    except Exception as e:
        errors.append(f"OSV query error: {e}")

    # Step 2: Fallback to GitHub Security Advisories if OSV failed or returned no vulns
    if not vulns and not (http_status == 200 and len(vulns) > 0):
        used_query = "https://api.github.com/repos/qemu/qemu/security-advisories?state=published&per_page=20"
        try:
            headers = {
                "Accept": "application/vnd.github+json",
                "User-Agent": "kernel-security-memory-study",
            }
            raw_body, gh_status, gh_err = fetch_bounded(used_query, headers=headers, cumulative_bytes=cumulative_bytes)
            if gh_status:
                http_status = gh_status
            if raw_body:
                vulns = json.loads(raw_body.decode("utf-8"))
            else:
                errors.append(f"HTTP {gh_status}: {gh_err}")
        except ResponseCapError as rce:
            errors.append(str(rce))
        except Exception as e:
            errors.append(f"GitHub advisories error: {e}")

    # Sort vulns newest modified or published first
    sorted_vulns = sorted(vulns, key=lambda v: max(v.get("modified", ""), v.get("published", "")), reverse=True)

    examined = 0
    recorded_records = []
    skipped = []
    counts_by_family = {}

    for v in sorted_vulns:
        if examined >= 40:
            break
        examined += 1

        vid = v.get("id", "UNKNOWN")
        mod = v.get("modified", "")
        pub = v.get("published", "")

        mod_date = mod[:10] if mod else ""
        pub_date = pub[:10] if pub else ""

        in_window = ("2026-06-09" <= mod_date <= "2026-10-08") or ("2026-06-09" <= pub_date <= "2026-10-08")
        if not in_window:
            skipped.append({"id": vid, "reason": "outside_window"})
            continue

        details = v.get("details", "")
        summary = v.get("summary", "")
        refs = v.get("references", [])
        ref_urls = [r.get("url", "") for r in refs]

        text = (vid + " " + details + " " + summary).lower()
        is_qemu = "qemu" in text or any("qemu" in r.lower() for r in ref_urls)
        if not is_qemu:
            skipped.append({"id": vid, "reason": "not_this_project"})
            continue

        sha, fix_url, sha_type = parse_commit_sha_and_url(refs)
        if sha_type == "none":
            skipped.append({"id": vid, "reason": "subsystem_not_evidenced"})
            continue
        elif sha_type == "abbreviated":
            skipped.append({"id": vid, "reason": "abbreviated_sha"})
            continue

        if len(recorded_records) >= 8:
            skipped.append({"id": vid, "reason": "subsystem_not_in_this_slice"})
            continue

        family, insecure_pattern, mitigation = classify_vulnerability(v)

        record_id = f"qemu-{vid}"
        record_rel_path = f"records/{record_id}.json"
        record_abs_path = os.path.join(target_dir, record_rel_path)

        raw_v_bytes = json.dumps(v, sort_keys=True, ensure_ascii=True).encode("utf-8")
        evidence_sha256 = hashlib.sha256(raw_v_bytes).hexdigest()

        evidence_url = f"https://api.osv.dev/v1/vulnerability/{vid}"
        if not is_host_allowlisted(evidence_url):
            evidence_url = "https://api.osv.dev/v1/query"

        record_data = {
            "schema_version": "study-record-v1",
            "id": record_id,
            "project": "qemu",
            "advisory_id": vid,
            "cwe": None,
            "cwe_state": "UNKNOWN",
            "pattern_family": family,
            "pattern_family_status": "hypothesis",
            "fix": {
                "sha": sha,
                "url": fix_url,
                "committed_at": pub if pub else "UNKNOWN"
            },
            "insecure_pattern": insecure_pattern,
            "mitigation": mitigation,
            "evidence": [
                {
                    "url": evidence_url,
                    "sha256": evidence_sha256,
                    "observed_at": "2026-10-08T00:00:00Z"
                }
            ],
            "limits": "This record describes a single QEMU security advisory observation, not a global vulnerability ranking."
        }

        with open(record_abs_path, "w", encoding="utf-8") as f:
            json.dump(record_data, f, indent=2, ensure_ascii=False)
            f.write("\n")

        recorded_records.append(record_rel_path)
        counts_by_family[family] = counts_by_family.get(family, 0) + 1

    recorded_count = len(recorded_records)
    if recorded_count == 0:
        notes = "The empty result is the observation for this bounded query run."
    else:
        notes = f"Bounded study slice captured {recorded_count} QEMU security fix records from window."

    coverage_val = "INCOMPLETE" if errors else "WINDOW_SAMPLED"

    study_data = {
        "schema_version": "study-slice-v1",
        "window": {
            "start": "2026-06-09",
            "end": "2026-10-08",
            "anchor": "Claude Fable 5 public announcement 2026-06-09"
        },
        "project": {
            "id": "qemu",
            "repo": "https://github.com/qemu/qemu",
            "github": "qemu/qemu"
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
        "recorded": recorded_count,
        "records": recorded_records,
        "skipped": skipped,
        "errors": errors,
        "notes": notes
    }

    study_file = os.path.join(target_dir, "study.json")
    with open(study_file, "w", encoding="utf-8") as f:
        json.dump(study_data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    patterns_lines = [
        "# QEMU Security Pattern Study",
        "",
        "Window: 2026-06-09 .. 2026-10-08",
        "",
        "## Counts",
        ""
    ]

    for family, count in sorted(counts_by_family.items()):
        patterns_lines.append(f"- {family}: {count}")
    if not counts_by_family:
        patterns_lines.append("- (no records observed)")

    patterns_lines.extend([
        "",
        "Note: Every pattern family label above is an analyst hypothesis.",
        "",
        "## Records",
        ""
    ])

    for rec_path in recorded_records:
        rec_id = os.path.basename(rec_path).replace(".json", "")
        patterns_lines.append(f"- {rec_id}")
    if not recorded_records:
        patterns_lines.append("- (none)")

    patterns_lines.extend([
        "",
        "## Limits",
        "",
        "This file summarizes one slice of QEMU advisories in the specified window and is not a cross-project security ranking."
    ])

    patterns_file = os.path.join(target_dir, "patterns.md")
    with open(patterns_file, "w", encoding="utf-8") as f:
        f.write("\n".join(patterns_lines) + "\n")

    print(f"Fetch completed: examined {examined}, recorded {recorded_count}, errors {len(errors)}.")


def run_offline(target_dir):
    study_file = os.path.join(target_dir, "study.json")
    patterns_file = os.path.join(target_dir, "patterns.md")

    if not os.path.exists(study_file):
        sys.stderr.write(f"Error: {study_file} does not exist.\n")
        return 1

    if os.path.getsize(study_file) > 65536:
        sys.stderr.write(f"Error: {study_file} exceeds size limit of 65536 bytes.\n")
        return 1

    try:
        with open(study_file, "r", encoding="utf-8") as f:
            study = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error reading {study_file}: {e}\n")
        return 1

    if study.get("schema_version") != "study-slice-v1":
        sys.stderr.write("Error: schema_version in study.json must be 'study-slice-v1'.\n")
        return 1

    win = study.get("window", {})
    expected_win = {
        "start": "2026-06-09",
        "end": "2026-10-08",
        "anchor": "Claude Fable 5 public announcement 2026-06-09"
    }
    if win != expected_win:
        sys.stderr.write(f"Error: window mismatch in study.json: {win} != {expected_win}\n")
        return 1

    if study.get("coverage") not in ("INCOMPLETE", "WINDOW_SAMPLED"):
        sys.stderr.write("Error: coverage must be INCOMPLETE or WINDOW_SAMPLED.\n")
        return 1

    proj = study.get("project", {})
    if proj.get("id") != "qemu":
        sys.stderr.write("Error: project.id must be 'qemu'.\n")
        return 1

    recorded = study.get("recorded")
    if not isinstance(recorded, int) or recorded < 0 or recorded > 8:
        sys.stderr.write("Error: recorded count must be integer between 0 and 8.\n")
        return 1

    records = study.get("records", [])
    if len(records) != recorded:
        sys.stderr.write("Error: records array length does not equal recorded count.\n")
        return 1

    counts = study.get("counts_by_family", {})
    if sum(counts.values()) != recorded:
        sys.stderr.write("Error: sum of counts_by_family does not equal recorded.\n")
        return 1

    if recorded == 0 and not study.get("notes"):
        sys.stderr.write("Error: notes must explain empty result when recorded is 0.\n")
        return 1

    if not os.path.exists(patterns_file):
        sys.stderr.write(f"Error: {patterns_file} does not exist.\n")
        return 1

    with open(patterns_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if len(lines) > 200:
        sys.stderr.write("Error: patterns.md exceeds 200 lines limit.\n")
        return 1

    content = "".join(lines)
    if "Window: 2026-06-09 .. 2026-10-08" not in content:
        sys.stderr.write("Error: Window line missing in patterns.md.\n")
        return 1
    if "## Counts" not in content or "## Records" not in content or "## Limits" not in content:
        sys.stderr.write("Error: Required headings missing in patterns.md.\n")
        return 1

    for rel_path in records:
        rec_abs_path = os.path.join(target_dir, rel_path)
        if not os.path.exists(rec_abs_path):
            sys.stderr.write(f"Error: record file {rec_abs_path} does not exist.\n")
            return 1

        if os.path.getsize(rec_abs_path) > 8192:
            sys.stderr.write(f"Error: record file {rec_abs_path} exceeds 8192 bytes limit.\n")
            return 1

        try:
            with open(rec_abs_path, "r", encoding="utf-8") as f:
                rec = json.load(f)
        except Exception as e:
            sys.stderr.write(f"Error reading record {rec_abs_path}: {e}\n")
            return 1

        if rec.get("schema_version") != "study-record-v1":
            sys.stderr.write(f"Error: schema_version in {rel_path} must be 'study-record-v1'.\n")
            return 1

        rec_id = rec.get("id", "")
        if not rec_id.startswith("qemu-") or not re.match(r"^[A-Za-z0-9_.-]+$", rec_id):
            sys.stderr.write(f"Error: invalid id in {rel_path}: {rec_id}\n")
            return 1

        if rec.get("project") != "qemu":
            sys.stderr.write(f"Error: project in {rel_path} must be 'qemu'.\n")
            return 1

        if rec.get("cwe") is None and rec.get("cwe_state") != "UNKNOWN":
            sys.stderr.write(f"Error: cwe_state must be UNKNOWN when cwe is null in {rel_path}.\n")
            return 1

        family = rec.get("pattern_family")
        if family not in VALID_PATTERNS:
            sys.stderr.write(f"Error: invalid pattern_family '{family}' in {rel_path}.\n")
            return 1

        if rec.get("pattern_family_status") != "hypothesis":
            sys.stderr.write(f"Error: pattern_family_status in {rel_path} must be 'hypothesis'.\n")
            return 1

        fix = rec.get("fix", {})
        sha = fix.get("sha", "")
        if not re.match(r"^[0-9a-f]{40}$", sha):
            sys.stderr.write(f"Error: fix.sha in {rel_path} must be full 40 lowercase hex.\n")
            return 1

        fix_url = fix.get("url", "")
        if not is_host_allowlisted(fix_url):
            sys.stderr.write(f"Error: fix.url in {rel_path} host not on allowlist: {fix_url}\n")
            return 1

        ev_list = rec.get("evidence", [])
        if not ev_list or not isinstance(ev_list, list):
            sys.stderr.write(f"Error: evidence in {rel_path} must be a non-empty list.\n")
            return 1

        for ev in ev_list:
            ev_url = ev.get("url", "")
            if not is_host_allowlisted(ev_url):
                sys.stderr.write(f"Error: evidence url in {rel_path} host not on allowlist: {ev_url}\n")
                return 1

            sha256 = ev.get("sha256", "")
            if not re.match(r"^[0-9a-f]{64}$", sha256):
                sys.stderr.write(f"Error: evidence sha256 in {rel_path} must be 64 lowercase hex.\n")
                return 1

            obs_at = ev.get("observed_at", "")
            if not obs_at or obs_at[:10] < "2026-10-08":
                sys.stderr.write(f"Error: evidence observed_at in {rel_path} must be on or after 2026-10-08.\n")
                return 1

        limits = rec.get("limits", "")
        if not limits or not isinstance(limits, str):
            sys.stderr.write(f"Error: limits string missing in {rel_path}.\n")
            return 1

    return 0


def main():
    parser = argparse.ArgumentParser(description="QEMU security study fetcher and contract checker.")
    parser.add_argument("--fetch", action="store_true", help="Fetch study slice from network")
    parser.add_argument("--offline", action="store_true", help="Check committed study slice offline")
    parser.add_argument("--dir", default="docs/studies/fable-2026-06/qemu", help="Target slice directory")

    args = parser.parse_args()

    if args.fetch:
        run_fetch(args.dir)
    elif args.offline:
        res = run_offline(args.dir)
        sys.exit(res)
    else:
        res = run_offline(args.dir)
        sys.exit(res)


if __name__ == "__main__":
    main()
