"""Fetch and validate OpenSSH CVE patch catalog from NVD API 2.0.

Standard library only. Supports --fetch and --offline modes.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT_DIR = BASE_DIR / "docs" / "studies" / "cve-history" / "openssh"
INDEX_FILE = DEFAULT_OUT_DIR / "index.json"
CATALOG_FILE = DEFAULT_OUT_DIR / "catalog.jsonl"

PER_RESPONSE_LIMIT = 1024 * 1024  # 1 MiB
CUMULATIVE_LIMIT = 8 * 1024 * 1024  # 8 MiB
MAX_CALLS = 400
USER_AGENT = "kernel-security-memory-study"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch or validate OpenSSH CVE patch catalog.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch CVE catalog from NVD API 2.0")
    group.add_argument("--offline", action="store_true", help="Validate catalog offline")
    parser.add_argument("--out-dir", type=str, default=str(DEFAULT_OUT_DIR), help="Output directory")
    parser.add_argument("--max-time", type=int, default=180, help="Max execution time in seconds per fetch run")
    return parser.parse_args()


def is_openssh_owned(cve_item):
    """Check if CVE belongs to OpenSSH project via CPE configurations or reference hosts."""
    configs = cve_item.get("configurations")
    if configs:
        configs_str = json.dumps(configs).lower()
        if "openssh" in configs_str:
            return True

    references = cve_item.get("references", [])
    for ref in references:
        url = ref.get("url", "").lower()
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc
        path = parsed.path
        if "openssh.com" in netloc or "mindrot.org" in netloc:
            return True
        if "github.com" in netloc and ("openssh" in path or "openssh" in netloc):
            return True
        if "openbsd.org" in netloc and "openssh" in (path + url):
            return True

    return False


def extract_cwe(cve_item):
    """Extract CWE id (e.g. CWE-119) if stated, else None."""
    weaknesses = cve_item.get("weaknesses", [])
    for w in weaknesses:
        descriptions = w.get("description", [])
        for d in descriptions:
            val = d.get("value", "")
            match = re.search(r"\b(CWE-\d+)\b", val, re.IGNORECASE)
            if match:
                return match.group(1).upper()
    return None


def extract_patch_urls_and_shas(cve_item):
    """Extract up to 3 https:// patch URLs and any 40-hex lowercase SHAs inside them."""
    references = cve_item.get("references", [])
    https_urls = []

    for ref in references:
        url = ref.get("url", "")
        if url.startswith("https://") and url not in https_urls:
            https_urls.append(url)

    commit_urls = [u for u in https_urls if "/commit" in u or ".patch" in u or "mindrot.org" in u or "openssh" in u]
    other_urls = [u for u in https_urls if u not in commit_urls]

    ordered_urls = commit_urls + other_urls
    selected_urls = ordered_urls[:3]

    shas = []
    sha_pattern = re.compile(r"\b([0-9a-fA-F]{40})\b")
    for u in selected_urls:
        matches = sha_pattern.findall(u)
        for m in matches:
            m_lower = m.lower()
            if m_lower not in shas:
                shas.append(m_lower)

    return selected_urls, shas


def transform_cve_item(cve_item):
    """Transform NVD CVE item dict into catalog record dict or None if filtered out."""
    if not is_openssh_owned(cve_item):
        return None

    cve_id = cve_item.get("id")
    if not cve_id or not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", cve_id):
        return None

    pub_raw = cve_item.get("published", "")
    published = pub_raw[:10] if len(pub_raw) >= 10 else ""
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", published):
        return None

    cwe = extract_cwe(cve_item)
    cwe_state = "STATED_BY_ADVISORY" if cwe is not None else "UNKNOWN"
    patch_urls, fix_shas = extract_patch_urls_and_shas(cve_item)

    record = {
        "advisory_id": cve_id,
        "published": published,
        "cwe": cwe,
        "cwe_state": cwe_state,
        "patch_urls": patch_urls,
        "fix_shas": fix_shas,
        "subsystem": None,
    }

    while len(json.dumps(record, separators=(",", ":")).encode("utf-8")) > 480 and record["patch_urls"]:
        record["patch_urls"].pop()

    return record


def make_nvd_request(url, cumulative_bytes):
    """Perform a single HTTP request to NVD with timeout and byte limit."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=25) as response:
        body = bytearray()
        while True:
            chunk = response.read(8192)
            if not chunk:
                break
            body.extend(chunk)
            cumulative_bytes[0] += len(chunk)
            if len(body) > PER_RESPONSE_LIMIT:
                raise RuntimeError(f"Response limit {PER_RESPONSE_LIMIT} bytes exceeded")
            if cumulative_bytes[0] > CUMULATIVE_LIMIT:
                raise RuntimeError(f"Cumulative limit {CUMULATIVE_LIMIT} bytes exceeded")
        return json.loads(body.decode("utf-8"))


def fetch_nvd_data(out_dir=DEFAULT_OUT_DIR, max_time_seconds=180):
    start_time = time.time()
    out_dir_path = pathlib.Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    index_path = out_dir_path / "index.json"
    catalog_path = out_dir_path / "catalog.jsonl"

    start_date_default = datetime.date(1999, 1, 1)
    end_date_limit = datetime.date(2026, 10, 8)

    cumulative_bytes = [0]
    requests_count = 0
    errors = []
    kept_records = {}

    current_start = start_date_default

    # Resume if existing index.json is present
    if index_path.is_file():
        try:
            with open(index_path, "r", encoding="utf-8") as f:
                prev_index = json.load(f)
                requests_count = prev_index.get("requests", 0)
                errors = prev_index.get("errors", [])
                if prev_index.get("resume") and "next_start_date" in prev_index["resume"]:
                    current_start = datetime.date.fromisoformat(prev_index["resume"]["next_start_date"])
                elif prev_index.get("coverage") == "COMPLETE":
                    print("Catalog is already COMPLETE.")
                    return
        except Exception:
            pass

    if catalog_path.is_file():
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        rec = json.loads(line.strip())
                        kept_records[rec["advisory_id"]] = rec
        except Exception:
            pass

    coverage = "INCOMPLETE"
    resume = None

    while current_start <= end_date_limit:
        if time.time() - start_time > max_time_seconds:
            resume = {"next_start_date": current_start.isoformat()}
            print(f"Time limit reached ({max_time_seconds}s). Saving progress...")
            break

        if requests_count >= MAX_CALLS or cumulative_bytes[0] >= CUMULATIVE_LIMIT:
            resume = {"next_start_date": current_start.isoformat()}
            print("Request or byte cap reached. Saving progress...")
            break

        current_end = min(current_start + datetime.timedelta(days=89), end_date_limit)
        start_str = f"{current_start.isoformat()}T00:00:00.000"
        end_str = f"{current_end.isoformat()}T23:59:59.999"

        start_index = 0
        window_finished = False

        while True:
            if time.time() - start_time > max_time_seconds or requests_count >= MAX_CALLS or cumulative_bytes[0] >= CUMULATIVE_LIMIT:
                resume = {"next_start_date": current_start.isoformat()}
                window_finished = False
                break

            params = {
                "resultsPerPage": 200,
                "startIndex": start_index,
                "keywordSearch": "openssh",
                "pubStartDate": start_str,
                "pubEndDate": end_str,
            }
            query_str = urllib.parse.urlencode(params)
            url = f"{NVD_API_URL}?{query_str}"

            time.sleep(15)  # Sleep 15s before every call

            data = None
            try:
                data = make_nvd_request(url, cumulative_bytes)
                requests_count += 1
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    time.sleep(40)
                    try:
                        data = make_nvd_request(url, cumulative_bytes)
                        requests_count += 1
                    except Exception as retry_e:
                        err_msg = f"HTTP {e.code} on {start_str} to {end_str}: {retry_e}"
                        errors.append(err_msg)
                        resume = {"next_start_date": current_start.isoformat()}
                        break
                else:
                    err_msg = f"HTTP {e.code} on {start_str} to {end_str}: {e.reason}"
                    errors.append(err_msg)
                    resume = {"next_start_date": current_start.isoformat()}
                    break
            except Exception as e:
                err_msg = f"Error fetching {start_str} to {end_str}: {e}"
                errors.append(err_msg)
                resume = {"next_start_date": current_start.isoformat()}
                break

            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            for vuln in vulnerabilities:
                cve_item = vuln.get("cve", {})
                rec = transform_cve_item(cve_item)
                if rec:
                    kept_records[rec["advisory_id"]] = rec

            start_index += len(vulnerabilities)
            if start_index >= total_results or len(vulnerabilities) == 0:
                window_finished = True
                break

        if not window_finished or errors:
            if resume is None:
                resume = {"next_start_date": current_start.isoformat()}
            break

        current_start = current_end + datetime.timedelta(days=1)

    if current_start > end_date_limit and not errors and resume is None:
        coverage = "COMPLETE"
        resume = None

    # Write catalog.jsonl (sorted by published, then advisory_id)
    sorted_records = sorted(kept_records.values(), key=lambda r: (r["published"], r["advisory_id"]))
    with open(catalog_path, "w", encoding="utf-8") as f:
        for rec in sorted_records:
            line = json.dumps(rec, separators=(",", ":"))
            f.write(line + "\n")

    entry_count = len(sorted_records)
    with_fix_sha = sum(1 for r in sorted_records if len(r["fix_shas"]) > 0)

    index_data = {
        "schema_version": "cve-history-v1",
        "project": "openssh",
        "repo": "https://github.com/openssh/openssh-portable",
        "window": {"start": "1999-01-01", "end": "2026-10-08"},
        "keyword": "openssh",
        "coverage": coverage,
        "entry_count": entry_count,
        "with_fix_sha": with_fix_sha,
        "requests": requests_count,
        "resume": resume,
        "errors": errors,
        "notes": "Descriptions were omitted per policy.",
    }

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2)
        f.write("\n")

    print(f"Fetch run completed: {entry_count} entries ({with_fix_sha} with fix SHAs), {requests_count} total requests.")
    print(f"Coverage: {coverage}, resume: {resume}")


def validate_offline(out_dir=DEFAULT_OUT_DIR):
    out_dir_path = pathlib.Path(out_dir)
    index_path = out_dir_path / "index.json"
    catalog_path = out_dir_path / "catalog.jsonl"

    if not index_path.is_file():
        print(f"Error: missing index file at {index_path}", file=sys.stderr)
        return False

    if not catalog_path.is_file():
        print(f"Error: missing catalog file at {catalog_path}", file=sys.stderr)
        return False

    try:
        with open(index_path, "r", encoding="utf-8") as f:
            index_data = json.load(f)
    except Exception as e:
        print(f"Error reading index.json: {e}", file=sys.stderr)
        return False

    required_index_keys = {
        "schema_version", "project", "repo", "window", "keyword",
        "coverage", "entry_count", "with_fix_sha", "requests", "resume",
        "errors", "notes"
    }
    if not required_index_keys.issubset(index_data.keys()):
        print(f"Error: index.json missing keys: {required_index_keys - index_data.keys()}", file=sys.stderr)
        return False

    if index_data["schema_version"] != "cve-history-v1":
        print(f"Error: schema_version mismatch", file=sys.stderr)
        return False

    if index_data["project"] != "openssh":
        print(f"Error: project mismatch", file=sys.stderr)
        return False

    if index_data["repo"] != "https://github.com/openssh/openssh-portable":
        print(f"Error: repo mismatch", file=sys.stderr)
        return False

    if index_data["window"] != {"start": "1999-01-01", "end": "2026-10-08"}:
        print(f"Error: window mismatch", file=sys.stderr)
        return False

    if index_data["coverage"] not in ("COMPLETE", "INCOMPLETE"):
        print(f"Error: invalid coverage state", file=sys.stderr)
        return False

    if (index_data["coverage"] == "COMPLETE") != (index_data["resume"] is None):
        print(f"Error: coverage / resume state mismatch", file=sys.stderr)
        return False

    line_count = 0
    with_fix_sha_count = 0

    with open(catalog_path, "r", encoding="utf-8") as f:
        for idx, raw_line in enumerate(f, 1):
            if not raw_line:
                continue
            line = raw_line.rstrip("\r\n")
            if not line:
                continue

            if len(raw_line.encode("utf-8")) > 500:
                print(f"Error: catalog line {idx} exceeds 500 bytes", file=sys.stderr)
                return False

            try:
                rec = json.loads(line)
            except Exception as e:
                print(f"Error parsing catalog line {idx}: {e}", file=sys.stderr)
                return False

            if "description" in rec:
                print(f"Error: catalog line {idx} contains forbidden 'description' key", file=sys.stderr)
                return False

            required_rec_keys = {
                "advisory_id", "published", "cwe", "cwe_state", "patch_urls", "fix_shas", "subsystem"
            }
            if set(rec.keys()) != required_rec_keys:
                print(f"Error: catalog line {idx} has invalid keys: {rec.keys()}", file=sys.stderr)
                return False

            if not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", rec["advisory_id"]):
                print(f"Error: catalog line {idx} advisory_id invalid: {rec['advisory_id']}", file=sys.stderr)
                return False

            if not re.match(r"^\d{4}-\d{2}-\d{2}$", rec["published"]):
                print(f"Error: catalog line {idx} published invalid: {rec['published']}", file=sys.stderr)
                return False

            if rec["cwe"] is not None and not re.match(r"^CWE-\d+$", rec["cwe"]):
                print(f"Error: catalog line {idx} cwe invalid: {rec['cwe']}", file=sys.stderr)
                return False

            if rec["cwe"] is None and rec["cwe_state"] != "UNKNOWN":
                print(f"Error: catalog line {idx} cwe_state must be UNKNOWN for null cwe", file=sys.stderr)
                return False

            if rec["cwe"] is not None and rec["cwe_state"] != "STATED_BY_ADVISORY":
                print(f"Error: catalog line {idx} cwe_state must be STATED_BY_ADVISORY for non-null cwe", file=sys.stderr)
                return False

            if len(rec["patch_urls"]) > 3:
                print(f"Error: catalog line {idx} exceeds 3 patch_urls", file=sys.stderr)
                return False

            for url in rec["patch_urls"]:
                if not url.startswith("https://"):
                    print(f"Error: catalog line {idx} patch_url not https: {url}", file=sys.stderr)
                    return False

            for sha in rec["fix_shas"]:
                if not re.match(r"^[0-9a-f]{40}$", sha):
                    print(f"Error: catalog line {idx} fix_sha invalid: {sha}", file=sys.stderr)
                    return False

            line_count += 1
            if len(rec["fix_shas"]) > 0:
                with_fix_sha_count += 1

    if line_count != index_data["entry_count"]:
        print(f"Error: entry_count mismatch ({line_count} vs {index_data['entry_count']})", file=sys.stderr)
        return False

    if with_fix_sha_count != index_data["with_fix_sha"]:
        print(f"Error: with_fix_sha mismatch ({with_fix_sha_count} vs {index_data['with_fix_sha']})", file=sys.stderr)
        return False

    print(f"Validation successful: {line_count} catalog entries verified.")
    return True


def main():
    args = parse_args()

    if args.offline:
        ok = validate_offline(args.out_dir)
        sys.exit(0 if ok else 1)

    if args.fetch:
        fetch_nvd_data(args.out_dir, max_time_seconds=args.max_time)


if __name__ == "__main__":
    main()
