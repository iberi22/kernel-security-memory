"""Fetch and validate Unbound CVE patch catalog from NVD API 2.0. Standard library only."""

import argparse, datetime, json, pathlib, re, sys, time
import urllib.error, urllib.parse, urllib.request

try:  # importable as a script, as scripts.studies.fetch_history_x and top-level
    from . import fetcher_io
except ImportError:  # direct execution / sys.path import
    import fetcher_io

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT_DIR = BASE_DIR / "docs" / "studies" / "cve-history" / "unbound"
INDEX_FILE, CATALOG_FILE = DEFAULT_OUT_DIR / "index.json", DEFAULT_OUT_DIR / "catalog.jsonl"
PER_RESPONSE_LIMIT, CUMULATIVE_LIMIT, MAX_CALLS = 1024 * 1024, 8 * 1024 * 1024, 400
USER_AGENT, NVD_API_URL = "kernel-security-memory-study", "https://services.nvd.nist.gov/rest/json/cves/2.0"
REPO_URL = "https://github.com/NLnetLabs/unbound"


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch or validate Unbound CVE patch catalog.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fetch", action="store_true", help="Fetch CVE catalog from NVD API 2.0")
    group.add_argument("--offline", action="store_true", help="Validate catalog offline")
    parser.add_argument("--out-dir", type=str, default=str(DEFAULT_OUT_DIR), help="Output directory")
    parser.add_argument("--max-time", type=int, default=180, help="Max execution time in seconds")
    return parser.parse_args()


def is_unbound_owned(cve_item):
    """Check if CVE belongs to Unbound project via CPE configurations or reference hosts."""
    if "unbound" in json.dumps(cve_item.get("configurations", [])).lower():
        return True
    for ref in cve_item.get("references", []):
        p = urllib.parse.urlparse(ref.get("url", "").lower())
        if ("github.com" in p.netloc and ("unbound" in (p.path + p.netloc) or "nlnetlabs" in (p.path + p.netloc))) or \
           ("nlnetlabs.nl" in p.netloc and "unbound" in (p.path + ref.get("url", "").lower())) or \
           ("unbound.net" in p.netloc):
            return True
    return False


def extract_cwe(cve_item):
    """Extract CWE id (e.g. CWE-119) if stated, else None."""
    for w in cve_item.get("weaknesses", []):
        for d in w.get("description", []):
            m = re.search(r"\b(CWE-\d+)\b", d.get("value", ""), re.IGNORECASE)
            if m: return m.group(1).upper()
    return None


def extract_patch_urls_and_shas(cve_item):
    """Extract up to 3 https:// patch URLs and any 40-hex lowercase SHAs inside them."""
    urls, seen = [], set()
    for r in cve_item.get("references", []):
        u = r.get("url", "")
        if u.startswith("https://") and u not in seen:
            seen.add(u); urls.append(u)
    commits = [u for u in urls if any(k in u for k in ("/commit", ".patch", "nlnetlabs", "unbound"))]
    selected = (commits + [u for u in urls if u not in commits])[:3]
    shas = []
    for u in selected:
        for m in re.findall(r"\b([0-9a-fA-F]{40})\b", u):
            if m.lower() not in shas: shas.append(m.lower())
    return selected, shas


def transform_cve_item(cve_item):
    """Transform NVD CVE item dict into catalog record dict or None if filtered out."""
    if not is_unbound_owned(cve_item): return None
    cve_id, pub_raw = cve_item.get("id", ""), cve_item.get("published", "")
    published = pub_raw[:10] if len(pub_raw) >= 10 else ""
    if not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", cve_id) or not re.match(r"^\d{4}-\d{2}-\d{2}$", published):
        return None
    cwe = extract_cwe(cve_item)
    patch_urls, fix_shas = extract_patch_urls_and_shas(cve_item)
    record = {
        "advisory_id": cve_id, "published": published, "cwe": cwe,
        "cwe_state": "STATED_BY_ADVISORY" if cwe is not None else "UNKNOWN",
        "patch_urls": patch_urls, "fix_shas": fix_shas, "subsystem": None,
    }
    encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")
    while len(encoded) > 500 and record["patch_urls"]:
        record["patch_urls"].pop()
        shas = []
        for u in record["patch_urls"]:
            for m in re.findall(r"\b([0-9a-fA-F]{40})\b", u):
                if m.lower() not in shas: shas.append(m.lower())
        record["fix_shas"] = shas
        encoded = json.dumps(record, separators=(",", ":")).encode("utf-8")
    return record


def make_nvd_request(url, cumulative_bytes):
    """Perform a single HTTP request to NVD with timeout and byte limit."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=25) as response:
        body = response.read(PER_RESPONSE_LIMIT + 1)
        if len(body) > PER_RESPONSE_LIMIT or cumulative_bytes[0] + len(body) > CUMULATIVE_LIMIT:
            raise RuntimeError("Response or cumulative limit exceeded")
        cumulative_bytes[0] += len(body)
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
    out_dir_path = pathlib.Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    index_path, catalog_path = out_dir_path / "index.json", out_dir_path / "catalog.jsonl"
    current_start, end_date_limit = datetime.date(1999, 1, 1), fetcher_io.resolve_run_date()
    cumulative_bytes, requests_count, errors, kept_records = [0], 0, [], {}

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
            resume = {"next_start_date": current_start.isoformat()}; break
        current_end = min(current_start + datetime.timedelta(days=89), end_date_limit)
        start_str, end_str = f"{current_start.isoformat()}T00:00:00.000", f"{current_end.isoformat()}T23:59:59.999"
        start_index, window_finished = 0, False

        while True:
            if time.time() - start_time > max_time_seconds or requests_count - run_start_requests >= MAX_CALLS or cumulative_bytes[0] >= CUMULATIVE_LIMIT:
                resume = {"next_start_date": current_start.isoformat()}; window_finished = False; break
            params = {"resultsPerPage": 200, "startIndex": start_index, "keywordSearch": "unbound",
                      "pubStartDate": start_str, "pubEndDate": end_str}
            url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
            time.sleep(15)
            try:
                data = make_nvd_request(url, cumulative_bytes); requests_count += 1
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    time.sleep(40)
                    try:
                        data = make_nvd_request(url, cumulative_bytes); requests_count += 1
                    except Exception as retry_e:
                        errors.append(f"HTTP {e.code} retry error: {retry_e}")
                        resume = {"next_start_date": current_start.isoformat()}; break
                else:
                    errors.append(f"HTTP {e.code}: {e.reason}")
                    resume = {"next_start_date": current_start.isoformat()}; break
            except Exception as e:
                errors.append(f"Fetch error: {e}")
                resume = {"next_start_date": current_start.isoformat()}; break

            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                rec = transform_cve_item(vuln.get("cve", {}))
                if rec: kept_records[rec["advisory_id"]] = rec

            start_index += len(vulns)
            if start_index >= data.get("totalResults", 0) or len(vulns) == 0:
                window_finished = True; break

        # `errors` holds this run's failures only; the ones from earlier
        # runs live in error_history and must not block new progress.
        if not window_finished or errors:
            if resume is None: resume = {"next_start_date": current_start.isoformat()}
            break
        current_start = current_end + datetime.timedelta(days=1)

    if current_start > end_date_limit and not errors and resume is None:
        coverage, resume = "COMPLETE", None

    sorted_records = sorted(kept_records.values(), key=lambda r: (r["published"], r["advisory_id"]))
    fetcher_io.write_catalog_atomic(catalog_path, sorted_records)

    status, cursor_date, window_closed = determine_status(
        len(sorted_records), coverage, resume, requests_count, "1999-01-01")
    index_data = {
        "schema_version": "cve-history-v1", "project": "unbound", "repo": REPO_URL,
        "window": fetcher_io.expected_window(), "keyword": "unbound",
        "coverage": coverage, "status": status, "cursor_date": cursor_date, "window_closed": window_closed,
        "entry_count": len(sorted_records),
        "with_fix_sha": sum(1 for r in sorted_records if len(r["fix_shas"]) > 0),
        "requests": requests_count, "resume": resume, "errors": errors, "error_history": fetcher_io.merge_error_history(error_history, errors), "notes": index_notes(status, cursor_date),
    }
    fetcher_io.write_index_atomic(index_path, index_data)
    print(f"Fetch completed: {len(sorted_records)} entries, {requests_count} requests. Coverage: {coverage}")


def validate_offline(out_dir=DEFAULT_OUT_DIR):
    out_dir_path = pathlib.Path(out_dir)
    index_path, catalog_path = out_dir_path / "index.json", out_dir_path / "catalog.jsonl"
    if not index_path.is_file() or not catalog_path.is_file():
        print(f"Error: missing files in {out_dir}", file=sys.stderr); return False
    try:
        with open(index_path, "r", encoding="utf-8") as f: idx = json.load(f)
    except Exception as e:
        print(f"Error reading index.json: {e}", file=sys.stderr); return False

    for k, v in [("schema_version", "cve-history-v1"), ("project", "unbound"),
                 ("repo", REPO_URL), ("keyword", "unbound")]:
        if idx.get(k) != v:
            print(f"Error: {k} mismatch", file=sys.stderr); return False

    window_ok, window_reason = fetcher_io.check_window(idx.get("window"))
    if not window_ok:
        print("Error: invalid window: " + window_reason, file=sys.stderr); return False
    cov = idx.get("coverage")
    if cov not in ("COMPLETE", "INCOMPLETE") or (cov == "COMPLETE") != (idx.get("resume") is None):
        print("Error: invalid coverage / resume state", file=sys.stderr); return False

    line_count, with_fix_sha_count = 0, 0
    req_keys = {"advisory_id", "published", "cwe", "cwe_state", "patch_urls", "fix_shas", "subsystem"}
    with open(catalog_path, "r", encoding="utf-8") as f:
        for num, raw in enumerate(f, 1):
            line = raw.rstrip("\r\n")
            if not line: continue
            if len(raw.encode("utf-8")) > 500:
                print(f"Error: line {num} > 500 bytes", file=sys.stderr); return False
            try: rec = json.loads(line)
            except Exception as e:
                print(f"Error parsing line {num}: {e}", file=sys.stderr); return False
            if "description" in rec or set(rec.keys()) != req_keys or \
               not re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", rec["advisory_id"]) or \
               not re.match(r"^\d{4}-\d{2}-\d{2}$", rec["published"]):
                print(f"Error: line {num} invalid schema", file=sys.stderr); return False
            cwe, cwe_state = rec["cwe"], rec["cwe_state"]
            if (cwe is not None and not re.match(r"^CWE-\d+$", cwe)) or \
               (cwe is None and cwe_state != "UNKNOWN") or \
               (cwe is not None and cwe_state != "STATED_BY_ADVISORY"):
                print(f"Error: line {num} cwe format or state invalid", file=sys.stderr); return False
            if len(rec["patch_urls"]) > 3 or any(not u.startswith("https://") for u in rec["patch_urls"]) or \
               any(not re.match(r"^[0-9a-f]{40}$", s) for s in rec["fix_shas"]):
                print(f"Error: line {num} patch_urls/shas invalid", file=sys.stderr); return False
            line_count += 1
            if len(rec["fix_shas"]) > 0: with_fix_sha_count += 1

    if line_count != idx.get("entry_count") or with_fix_sha_count != idx.get("with_fix_sha"):
        print("Error: entry_count or with_fix_sha mismatch", file=sys.stderr); return False
    print(f"Validation successful: {line_count} catalog entries verified.")
    return True


def main():
    args = parse_args()
    if args.offline: sys.exit(0 if validate_offline(args.out_dir) else 1)
    if args.fetch:
        try:
            fetch_nvd_data(args.out_dir, max_time_seconds=args.max_time)
        except fetcher_io.CorruptStateError as err:
            print(f"Error: {err}", file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    main()
