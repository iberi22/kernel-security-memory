"""Fetch and validate PostgreSQL CVE patch catalog from NVD API 2.0.

Standard library only. Supports --fetch and --offline modes.
"""

import argparse
import datetime
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # importable as a script, as scripts.studies.fetch_history_x and top-level
    from . import fetcher_io
except ImportError:  # direct execution / sys.path import
    import fetcher_io

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT_DIR = BASE_DIR / "docs" / "studies" / "cve-history" / "postgresql"
PER_RESPONSE_LIMIT = 1024 * 1024
CUMULATIVE_LIMIT = 8 * 1024 * 1024
MAX_CALLS = 400
USER_AGENT = "kernel-security-memory-study"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch or validate PostgreSQL CVE patch catalog.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch CVE catalog from NVD API 2.0")
    group.add_argument("--offline", action="store_true", help="Validate catalog offline")
    parser.add_argument("--out-dir", type=str, default=str(DEFAULT_OUT_DIR), help="Output directory")
    parser.add_argument("--max-time", type=int, default=180, help="Max execution time in seconds")
    return parser.parse_args()


def is_postgresql_owned(cve_item):
    """Check if CVE belongs to PostgreSQL project via CPE configurations or reference hosts."""
    configs = cve_item.get("configurations")
    if configs and any(k in json.dumps(configs).lower() for k in ("postgresql", "postgres")):
        return True
    for ref in cve_item.get("references", []):
        url = ref.get("url", "").lower()
        parsed = urllib.parse.urlparse(url)
        if "postgresql.org" in parsed.netloc:
            return True
        if "github.com" in parsed.netloc and ("postgres" in parsed.path or "postgresql" in parsed.path):
            return True
    return False


def extract_cwe(cve_item):
    """Extract CWE id (e.g. CWE-119) if stated, else None."""
    for w in cve_item.get("weaknesses", []):
        for d in w.get("description", []):
            m = re.search(r"\b(CWE-\d+)\b", d.get("value", ""), re.IGNORECASE)
            if m:
                return m.group(1).upper()
    return None


def extract_patch_urls_and_shas(cve_item):
    """Extract up to 3 https:// patch URLs and any 40-hex lowercase SHAs inside them."""
    https_urls = []
    for ref in cve_item.get("references", []):
        url = ref.get("url", "")
        if url.startswith("https://") and url not in https_urls:
            https_urls.append(url)

    commit_urls = [u for u in https_urls if any(k in u for k in ("/commit", ".patch", "git.postgresql.org", "github.com/postgres"))]
    ordered_urls = commit_urls + [u for u in https_urls if u not in commit_urls]
    selected_urls = ordered_urls[:3]

    shas = []
    sha_pattern = re.compile(r"\b([0-9a-fA-F]{40})\b")
    for u in selected_urls:
        for m in sha_pattern.findall(u):
            m_lower = m.lower()
            if m_lower not in shas:
                shas.append(m_lower)
    return selected_urls, shas


def transform_cve_item(cve_item):
    """Transform NVD CVE item dict into catalog record dict or None if filtered out."""
    if not is_postgresql_owned(cve_item):
        return None
    cve_id = cve_item.get("id")
    if not cve_id or not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", cve_id):
        return None
    pub_raw = cve_item.get("published", "")
    published = pub_raw[:10] if len(pub_raw) >= 10 else ""
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", published):
        return None

    cwe = extract_cwe(cve_item)
    patch_urls, fix_shas = extract_patch_urls_and_shas(cve_item)
    record = {
        "advisory_id": cve_id,
        "published": published,
        "cwe": cwe,
        "cwe_state": "STATED_BY_ADVISORY" if cwe is not None else "UNKNOWN",
        "patch_urls": patch_urls,
        "fix_shas": fix_shas,
        "subsystem": None,
    }

    encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")
    sha_pattern = re.compile(r"\b([0-9a-fA-F]{40})\b")
    while len(encoded) > 500 and record["patch_urls"]:
        record["patch_urls"].pop()
        shas = []
        for u in record["patch_urls"]:
            for m in sha_pattern.findall(u):
                m_lower = m.lower()
                if m_lower not in shas:
                    shas.append(m_lower)
        record["fix_shas"] = shas
        encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")
    return record


def make_nvd_request(url, cumulative_bytes):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=25) as response:
        body = bytearray()
        while True:
            chunk = response.read(8192)
            if not chunk:
                break
            body.extend(chunk)
            cumulative_bytes[0] += len(chunk)
            if len(body) > PER_RESPONSE_LIMIT or cumulative_bytes[0] > CUMULATIVE_LIMIT:
                raise RuntimeError("Response or cumulative limit exceeded")
        return json.loads(body.decode("utf-8"))


def determine_status(entry_count, coverage, resume, requests, window_start):
    """Derive the honest catalog state (status, cursor_date, window_closed).

    Mirrors determine_status() in scripts/studies/build_catalog_manifest.py so a fetch
    run can never write an index state that the manifest would contradict.
    """
    if coverage == "COMPLETE":
        return ("OBSERVED_EMPTY", None, True) if entry_count == 0 else ("COMPLETE", None, True)
    cursor = resume.get("next_start_date") if resume else None
    if cursor and (entry_count > 0 or (cursor != window_start and requests > 0)):
        return ("CURSOR_PAUSED", cursor, False)
    return ("NOT_FETCHED", None, False)


def index_notes(status, cursor_date):
    """Note that states the observed window state instead of implying completion."""
    base = "Descriptions were omitted per policy."
    if status == "CURSOR_PAUSED":
        return f"{base} Cursor paused at {cursor_date}; window remains open (not closed)."
    if status == "OBSERVED_EMPTY":
        return f"{base} Completed scan over 1999-01-01..{fetcher_io.window_end_iso()} yielded 0 entries."
    if status == "NOT_FETCHED":
        return f"{base} Scaffold not yet fetched."
    return base


def fetch_nvd_data(out_dir, max_time_seconds=180):
    start_time = time.time()
    out_path = pathlib.Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    index_path, catalog_path = out_path / "index.json", out_path / "catalog.jsonl"

    start_date_default, end_date_limit = datetime.date(1999, 1, 1), fetcher_io.resolve_run_date()
    cumulative_bytes, requests_count, errors, kept_records = [0], 0, [], {}
    current_start = start_date_default

    # Resume from the persisted cursor. A corrupt file is fatal: the old loader
    # swallowed the error and rewrote the truncated catalog as a shorter
    # "valid" one. Errors from earlier runs are history, not a reason to stop:
    # only this run's failures may gate progress (see fetcher_io).
    errors, error_history = [], []
    prev_index = fetcher_io.read_index(index_path)
    if prev_index is not None:
        requests_count = prev_index.get("requests", 0)
        errors, error_history = fetcher_io.load_error_history(prev_index)
        if prev_index.get("resume") and "next_start_date" in prev_index["resume"]:
            current_start = datetime.date.fromisoformat(prev_index["resume"]["next_start_date"])
        elif prev_index.get("coverage") == "COMPLETE":
            print("Catalog is already COMPLETE.")
            return

    # A corrupt catalog line is fatal too (fetcher_io.read_catalog).
    kept_records = fetcher_io.read_catalog(catalog_path)

    coverage, resume = "INCOMPLETE", None

    # The cap is per run; the persisted lifetime total is only bookkeeping.
    run_start_requests = requests_count
    while current_start <= end_date_limit:
        if time.time() - start_time > max_time_seconds or requests_count - run_start_requests >= MAX_CALLS or cumulative_bytes[0] >= CUMULATIVE_LIMIT:
            resume = {"next_start_date": current_start.isoformat()}
            break

        current_end = min(current_start + datetime.timedelta(days=89), end_date_limit)
        start_str, end_str = f"{current_start.isoformat()}T00:00:00.000", f"{current_end.isoformat()}T23:59:59.999"
        start_index, window_finished = 0, False

        while True:
            if time.time() - start_time > max_time_seconds or requests_count - run_start_requests >= MAX_CALLS or cumulative_bytes[0] >= CUMULATIVE_LIMIT:
                resume = {"next_start_date": current_start.isoformat()}
                break

            params = {"resultsPerPage": 200, "startIndex": start_index, "keywordSearch": "postgresql", "pubStartDate": start_str, "pubEndDate": end_str}
            url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
            time.sleep(15)

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
                        errors.append(f"HTTP {e.code}: {retry_e}")
                        resume = {"next_start_date": current_start.isoformat()}
                        break
                else:
                    errors.append(f"HTTP {e.code}: {e.reason}")
                    resume = {"next_start_date": current_start.isoformat()}
                    break
            except Exception as e:
                errors.append(f"Error {start_str}: {e}")
                resume = {"next_start_date": current_start.isoformat()}
                break

            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                rec = transform_cve_item(v.get("cve", {}))
                if rec:
                    kept_records[rec["advisory_id"]] = rec

            start_index += len(vulns)
            if start_index >= data.get("totalResults", 0) or not vulns:
                window_finished = True
                break

        # `errors` holds this run's failures only; the ones from earlier
        # runs live in error_history and must not block new progress.
        if not window_finished or errors:
            resume = resume or {"next_start_date": current_start.isoformat()}
            break
        current_start = current_end + datetime.timedelta(days=1)

    if current_start > end_date_limit and not errors and resume is None:
        coverage, resume = "COMPLETE", None

    sorted_records = sorted(kept_records.values(), key=lambda r: (r["published"], r["advisory_id"]))
    fetcher_io.write_catalog_atomic(catalog_path, sorted_records)

    entry_count = len(sorted_records)
    with_fix_sha = sum(1 for r in sorted_records if len(r["fix_shas"]) > 0)
    status, cursor_date, window_closed = determine_status(
        entry_count, coverage, resume, requests_count, "1999-01-01")
    index_data = {
        "schema_version": "cve-history-v1",
        "project": "postgresql",
        "repo": "https://github.com/postgres/postgres",
        "window": fetcher_io.expected_window(),
        "keyword": "postgresql",
        "coverage": coverage,
        "status": status,
        "cursor_date": cursor_date,
        "window_closed": window_closed,
        "entry_count": entry_count,
        "with_fix_sha": with_fix_sha,
        "requests": requests_count,
        "resume": resume,
        "errors": errors,
        "error_history": fetcher_io.merge_error_history(error_history, errors),
        "notes": index_notes(status, cursor_date),
    }
    fetcher_io.write_index_atomic(index_path, index_data)
    print(f"Fetch completed: {entry_count} entries, {requests_count} requests. Coverage: {coverage}")


def validate_offline(out_dir):
    out_path = pathlib.Path(out_dir)
    index_path, catalog_path = out_path / "index.json", out_path / "catalog.jsonl"
    if not index_path.is_file() or not catalog_path.is_file():
        print(f"Error: missing files in {out_dir}", file=sys.stderr)
        return False

    try:
        with open(index_path, "r", encoding="utf-8") as f:
            idx = json.load(f)
    except Exception as e:
        print(f"Error reading index.json: {e}", file=sys.stderr)
        return False

    required_keys = {"schema_version", "project", "repo", "window", "keyword", "coverage", "entry_count", "with_fix_sha", "requests", "resume", "errors", "notes"}
    if not required_keys.issubset(idx.keys()) or idx["schema_version"] != "cve-history-v1" or idx["project"] != "postgresql":
        return False
    if idx["repo"] not in ("https://github.com/postgres/postgres", "https://git.postgresql.org/git/postgresql.git"):
        return False
    if idx["keyword"] not in ("postgresql", "postgres"):
        return False
    window_ok, window_reason = fetcher_io.check_window(idx.get("window"))
    if not window_ok:
        print(f"Error: invalid window: {window_reason}", file=sys.stderr)
        return False
    if idx["coverage"] not in ("COMPLETE", "INCOMPLETE") or ((idx["coverage"] == "COMPLETE") != (idx["resume"] is None)):
        return False

    line_count, with_fix_sha_count = 0, 0
    with open(catalog_path, "r", encoding="utf-8") as f:
        for line_num, raw in enumerate(f, 1):
            line = raw.rstrip("\r\n")
            if not line:
                continue
            if len(raw.encode("utf-8")) > 500:
                print(f"Line {line_num} exceeds 500 bytes", file=sys.stderr)
                return False
            try:
                rec = json.loads(line)
            except Exception:
                return False
            if "description" in rec or set(rec.keys()) != {"advisory_id", "published", "cwe", "cwe_state", "patch_urls", "fix_shas", "subsystem"}:
                return False
            if not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", rec["advisory_id"]) or not re.match(r"^\d{4}-\d{2}-\d{2}$", rec["published"]):
                return False
            if rec["cwe"] is not None and not re.match(r"^CWE-\d+$", rec["cwe"]):
                return False
            if (rec["cwe"] is None and rec["cwe_state"] != "UNKNOWN") or (rec["cwe"] is not None and rec["cwe_state"] != "STATED_BY_ADVISORY"):
                return False
            if len(rec["patch_urls"]) > 3 or any(not u.startswith("https://") for u in rec["patch_urls"]):
                return False
            if any(not re.match(r"^[0-9a-f]{40}$", s) for s in rec["fix_shas"]):
                return False
            line_count += 1
            if rec["fix_shas"]:
                with_fix_sha_count += 1

    if line_count != idx["entry_count"] or with_fix_sha_count != idx["with_fix_sha"]:
        print(f"Mismatch: count {line_count}/{idx['entry_count']}, shas {with_fix_sha_count}/{idx['with_fix_sha']}", file=sys.stderr)
        return False
    print(f"Validation successful: {line_count} catalog entries verified.")
    return True


def main():
    args = parse_args()
    if args.offline:
        sys.exit(0 if validate_offline(args.out_dir) else 1)
    if args.fetch:
        try:
            fetch_nvd_data(args.out_dir, max_time_seconds=args.max_time)
        except fetcher_io.CorruptStateError as err:
            print(f"Error: {err}", file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    main()
