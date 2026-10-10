#!/usr/bin/env python3
"""CVE Patch Catalog fetcher and validator for Linux kernel.

Fetch history from NVD API 2.0 or perform offline validation of committed catalog.
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

INDEX_PATH = "docs/studies/cve-history/linux/index.json"
CATALOG_PATH = "docs/studies/cve-history/linux/catalog.jsonl"

PER_RESPONSE_LIMIT = 1 * 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 8 * 1024 * 1024    # 8 MiB
MAX_REQUESTS = 400

CWE_PATTERN = re.compile(r"^CWE-\d+$")
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def extract_cwe(weaknesses):
    if not weaknesses or not isinstance(weaknesses, list):
        return None, "UNKNOWN"
    for w in weaknesses:
        descs = w.get("description", [])
        if isinstance(descs, list):
            for d in descs:
                val = d.get("value", "")
                if val and CWE_PATTERN.match(val):
                    return val, "STATED_BY_ADVISORY"
    return None, "UNKNOWN"


def extract_subsystem(patch_urls):
    for url in patch_urls:
        url_lower = url.lower()
        path = urllib.parse.urlparse(url_lower).path
        if "/net/" in path or "/net/" in url_lower:
            return "net"
        if "/fs/" in path or "/fs/" in url_lower:
            return "fs"
        if "/mm/" in path or "/mm/" in url_lower:
            return "mm"
        if "bpf" in path or "bpf" in url_lower:
            return "bpf"
    return "unassigned"


def extract_shas(urls):
    shas = []
    for url in urls:
        found = re.findall(r"\b([0-9a-f]{40})\b", url.lower())
        for sha in found:
            if sha not in shas:
                shas.append(sha)
    return shas


def parse_nvd_item(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id or not CVE_PATTERN.match(cve_id):
        return None

    published_raw = cve.get("published", "")
    published = published_raw[:10] if published_raw else ""
    if not DATE_PATTERN.match(published):
        return None

    cwe, cwe_state = extract_cwe(cve.get("weaknesses", []))

    refs = cve.get("references", [])
    raw_urls = []
    if isinstance(refs, list):
        for ref in refs:
            u = ref.get("url", "")
            if u and u.startswith("https://") and u not in raw_urls:
                raw_urls.append(u)

    patch_urls = raw_urls[:3]
    fix_shas = extract_shas(patch_urls)
    subsystem = extract_subsystem(patch_urls)

    record = {
        "advisory_id": cve_id,
        "published": published,
        "cwe": cwe,
        "cwe_state": cwe_state,
        "patch_urls": patch_urls,
        "fix_shas": fix_shas,
        "subsystem": subsystem
    }

    # Ensure line byte size <= 500 bytes
    encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")
    while len(encoded) > 500 and record["patch_urls"]:
        record["patch_urls"].pop()
        record["fix_shas"] = extract_shas(record["patch_urls"])
        record["subsystem"] = extract_subsystem(record["patch_urls"])
        encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")

    if len(encoded) > 500:
        return None

    return record


def validate_offline():
    if not os.path.exists(INDEX_PATH):
        print(f"Error: Index file '{INDEX_PATH}' does not exist.", file=sys.stderr)
        return False
    if not os.path.exists(CATALOG_PATH):
        print(f"Error: Catalog file '{CATALOG_PATH}' does not exist.", file=sys.stderr)
        return False

    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            idx = json.load(f)
    except Exception as e:
        print(f"Error reading index file: {e}", file=sys.stderr)
        return False

    required_idx_keys = {
        "schema_version", "project", "repo", "window", "keyword",
        "coverage", "entry_count", "with_fix_sha", "requests",
        "resume", "errors", "notes"
    }
    if not required_idx_keys.issubset(set(idx.keys())):
        print(f"Index missing required keys.", file=sys.stderr)
        return False

    if idx.get("schema_version") != "cve-history-v1":
        print(f"Invalid schema_version in index.", file=sys.stderr)
        return False
    if idx.get("project") != "linux":
        print(f"Invalid project in index.", file=sys.stderr)
        return False
    if idx.get("repo") != "https://github.com/torvalds/linux":
        print(f"Invalid repo in index.", file=sys.stderr)
        return False
    if idx.get("window") != {"start": "1999-01-01", "end": "2026-10-08"}:
        print(f"Invalid window in index.", file=sys.stderr)
        return False
    if idx.get("keyword") != "linux kernel":
        print(f"Invalid keyword in index.", file=sys.stderr)
        return False
    if idx.get("coverage") not in ("COMPLETE", "INCOMPLETE"):
        print(f"Invalid coverage in index.", file=sys.stderr)
        return False
    if idx.get("coverage") == "COMPLETE" and idx.get("resume") is not None:
        print(f"Resume must be null when coverage is COMPLETE.", file=sys.stderr)
        return False
    if idx.get("coverage") == "INCOMPLETE":
        res = idx.get("resume")
        if not isinstance(res, dict) or "next_start_date" not in res:
            print(f"Resume must contain next_start_date when coverage is INCOMPLETE.", file=sys.stderr)
            return False

    catalog_lines = []
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        for line_num, raw_line in enumerate(f, 1):
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            encoded_bytes = raw_line.rstrip("\r\n").encode("utf-8")
            if len(encoded_bytes) > 500:
                print(f"Line {line_num} in catalog exceeds 500 bytes ({len(encoded_bytes)} bytes).", file=sys.stderr)
                return False

            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Line {line_num} is not valid JSON: {e}", file=sys.stderr)
                return False

            if "description" in rec:
                print(f"Line {line_num} contains forbidden key 'description'.", file=sys.stderr)
                return False

            allowed_keys = {"advisory_id", "published", "cwe", "cwe_state", "patch_urls", "fix_shas", "subsystem"}
            # Optional provenance keys written by the enrichers.
            optional_keys = {"fix_sha_source", "cwe_source", "fix_repo"}
            if not allowed_keys <= set(rec.keys()) <= allowed_keys | optional_keys:
                print(f"Line {line_num} keys do not match expected schema: {set(rec.keys())}", file=sys.stderr)
                return False

            if not CVE_PATTERN.match(rec["advisory_id"]):
                print(f"Line {line_num} invalid advisory_id: {rec['advisory_id']}", file=sys.stderr)
                return False
            if not DATE_PATTERN.match(rec["published"]):
                print(f"Line {line_num} invalid published date: {rec['published']}", file=sys.stderr)
                return False

            if rec["cwe"] is not None and not CWE_PATTERN.match(rec["cwe"]):
                print(f"Line {line_num} invalid cwe format: {rec['cwe']}", file=sys.stderr)
                return False
            if rec["cwe_state"] not in ("STATED_BY_ADVISORY", "UNKNOWN"):
                print(f"Line {line_num} invalid cwe_state: {rec['cwe_state']}", file=sys.stderr)
                return False
            if rec["cwe"] is None and rec["cwe_state"] != "UNKNOWN":
                print(f"Line {line_num} null cwe must have cwe_state UNKNOWN", file=sys.stderr)
                return False

            if not isinstance(rec["patch_urls"], list) or len(rec["patch_urls"]) > 3:
                print(f"Line {line_num} patch_urls invalid.", file=sys.stderr)
                return False
            for u in rec["patch_urls"]:
                if not u.startswith("https://"):
                    print(f"Line {line_num} url does not start with https://: {u}", file=sys.stderr)
                    return False

            if not isinstance(rec["fix_shas"], list):
                print(f"Line {line_num} fix_shas invalid.", file=sys.stderr)
                return False
            for sha in rec["fix_shas"]:
                if not SHA_PATTERN.match(sha):
                    print(f"Line {line_num} fix_sha invalid: {sha}", file=sys.stderr)
                    return False

            valid_subsystems = {"net", "fs", "mm", "bpf", "other", "unassigned"}
            if rec["subsystem"] not in valid_subsystems:
                print(f"Line {line_num} subsystem invalid: {rec['subsystem']}", file=sys.stderr)
                return False

            catalog_lines.append(rec)

    if idx["entry_count"] != len(catalog_lines):
        print(f"Index entry_count ({idx['entry_count']}) does not match catalog line count ({len(catalog_lines)}).", file=sys.stderr)
        return False

    with_sha_count = sum(1 for r in catalog_lines if r["fix_shas"])
    if idx["with_fix_sha"] != with_sha_count:
        print(f"Index with_fix_sha ({idx['with_fix_sha']}) does not match actual sha count ({with_sha_count}).", file=sys.stderr)
        return False

    return True


def save_state(catalog_records, total_requests, coverage, resume_obj, errors):
    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    sorted_records = sorted(catalog_records.values(), key=lambda x: (x["published"], x["advisory_id"]))

    with open(CATALOG_PATH, "w", encoding="utf-8") as f:
        for rec in sorted_records:
            line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
            f.write(line + "\n")

    with_sha_count = sum(1 for r in sorted_records if r["fix_shas"])

    index_data = {
        "schema_version": "cve-history-v1",
        "project": "linux",
        "repo": "https://github.com/torvalds/linux",
        "window": {"start": "1999-01-01", "end": "2026-10-08"},
        "keyword": "linux kernel",
        "coverage": coverage,
        "entry_count": len(sorted_records),
        "with_fix_sha": with_sha_count,
        "requests": total_requests,
        "resume": resume_obj if coverage == "INCOMPLETE" else None,
        "errors": errors,
        "notes": "Descriptions were not stored."
    }

    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def fetch_history(max_calls=None):
    catalog_records = {}
    total_requests = 0
    cumulative_bytes = 0
    errors = []

    start_date_str = "1999-01-01"
    end_date_str = "2026-10-08"

    if os.path.exists(INDEX_PATH):
        try:
            with open(INDEX_PATH, "r", encoding="utf-8") as f:
                old_idx = json.load(f)
                total_requests = old_idx.get("requests", 0)
                if old_idx.get("errors"):
                    errors = old_idx.get("errors", [])
                if old_idx.get("resume") and isinstance(old_idx["resume"], dict):
                    start_date_str = old_idx["resume"].get("next_start_date", start_date_str)
        except Exception:
            pass

    if os.path.exists(CATALOG_PATH):
        try:
            with open(CATALOG_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rec = json.loads(line)
                        catalog_records[rec["advisory_id"]] = rec
        except Exception:
            pass

    start_dt = datetime.datetime.strptime(start_date_str, "%Y-%m-%d").date()
    end_dt = datetime.datetime.strptime(end_date_str, "%Y-%m-%d").date()

    curr_start = start_dt
    coverage = "COMPLETE"
    resume_obj = None

    calls_this_run = 0
    call_limit = MAX_REQUESTS if max_calls is None else min(MAX_REQUESTS, max_calls)

    save_state(catalog_records, total_requests, "INCOMPLETE", {"next_start_date": curr_start.strftime("%Y-%m-%d")}, errors)

    while curr_start <= end_dt:
        if total_requests >= MAX_REQUESTS or cumulative_bytes >= CUMULATIVE_LIMIT or calls_this_run >= call_limit:
            coverage = "INCOMPLETE"
            resume_obj = {"next_start_date": curr_start.strftime("%Y-%m-%d")}
            break

        curr_end = min(curr_start + datetime.timedelta(days=90), end_dt)

        start_iso = f"{curr_start.strftime('%Y-%m-%d')}T00:00:00.000"
        end_iso = f"{curr_end.strftime('%Y-%m-%d')}T23:59:59.999"

        start_index = 0
        window_consumed = False

        while not window_consumed:
            if total_requests >= MAX_REQUESTS or cumulative_bytes >= CUMULATIVE_LIMIT or calls_this_run >= call_limit:
                coverage = "INCOMPLETE"
                resume_obj = {"next_start_date": curr_start.strftime("%Y-%m-%d")}
                break

            time.sleep(15)

            params = {
                "resultsPerPage": 200,
                "keywordSearch": "linux kernel",
                "pubStartDate": start_iso,
                "pubEndDate": end_iso,
                "startIndex": start_index
            }
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(url, headers={"User-Agent": "kernel-security-memory-study"})

            resp_data = None
            status_code = None

            try:
                with urllib.request.urlopen(req, timeout=25) as resp:
                    status_code = resp.status
                    body = bytearray()
                    while True:
                        chunk = resp.read(8192)
                        if not chunk:
                            break
                        body.extend(chunk)
                        if len(body) > PER_RESPONSE_LIMIT:
                            raise Exception("Response limit exceeded 1 MiB")
                    resp_data = bytes(body)
            except urllib.error.HTTPError as e:
                status_code = e.code
                if status_code in (403, 429):
                    time.sleep(40)
                    try:
                        with urllib.request.urlopen(req, timeout=25) as resp:
                            status_code = resp.status
                            body = bytearray()
                            while True:
                                chunk = resp.read(8192)
                                if not chunk:
                                    break
                                body.extend(chunk)
                                if len(body) > PER_RESPONSE_LIMIT:
                                    raise Exception("Response limit exceeded 1 MiB")
                            resp_data = bytes(body)
                    except Exception as retry_e:
                        errors.append(f"HTTP {status_code} retry failed for window {curr_start}: {retry_e}")
                else:
                    errors.append(f"HTTP {status_code} for window {curr_start}: {e}")
            except Exception as e:
                errors.append(f"Error fetching window {curr_start}: {e}")

            calls_this_run += 1

            if resp_data and status_code == 200:
                total_requests += 1
                cumulative_bytes += len(resp_data)

                try:
                    data = json.loads(resp_data.decode("utf-8"))
                    vulns = data.get("vulnerabilities", [])
                    total_results = data.get("totalResults", len(vulns))

                    for item in vulns:
                        rec = parse_nvd_item(item)
                        if rec:
                            catalog_records[rec["advisory_id"]] = rec

                    start_index += len(vulns)
                    if start_index >= total_results or len(vulns) == 0:
                        window_consumed = True
                except Exception as parse_e:
                    errors.append(f"JSON parse error for window {curr_start}: {parse_e}")
                    coverage = "INCOMPLETE"
                    resume_obj = {"next_start_date": curr_start.strftime("%Y-%m-%d")}
                    window_consumed = True
                    break
            else:
                coverage = "INCOMPLETE"
                resume_obj = {"next_start_date": curr_start.strftime("%Y-%m-%d")}
                window_consumed = True
                break

            save_state(catalog_records, total_requests, "INCOMPLETE", {"next_start_date": curr_start.strftime("%Y-%m-%d")}, errors)

        if coverage == "INCOMPLETE":
            break

        curr_start = curr_end + datetime.timedelta(days=1)
        if curr_start > end_dt and not errors and total_requests > 0:
            coverage = "COMPLETE"
            resume_obj = None

        save_state(catalog_records, total_requests, coverage, resume_obj, errors)

    save_state(catalog_records, total_requests, coverage, resume_obj, errors)
    print(f"Fetch iteration finished. Coverage: {coverage}, Entries: {len(catalog_records)}, Requests: {total_requests}")


def main():
    parser = argparse.ArgumentParser(description="Linux CVE history fetcher and validator.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch history from NVD.")
    group.add_argument("--offline", action="store_true", help="Validate committed catalog offline.")
    parser.add_argument("--max-calls", type=int, default=None, help="Maximum NVD API calls for this run.")

    args = parser.parse_args()

    if args.offline:
        if validate_offline():
            print("Offline validation SUCCESS.")
            sys.exit(0)
        else:
            print("Offline validation FAILED.", file=sys.stderr)
            sys.exit(1)
    elif args.fetch:
        fetch_history(max_calls=args.max_calls)


if __name__ == "__main__":
    main()
