#!/usr/bin/env python3
"""Common parameterized base class for CVE patch history fetchers and offline validators.

Provides robust NVD API 2.0 window slicing, cursor resumption, pagination,
stream byte caps, timeout controls, and non-silent network error preservation.
"""

import datetime
import json
from pathlib import Path
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # importable as a script, as scripts.studies.base_history_fetcher and top-level
    from . import fetcher_io
except ImportError:  # direct execution / sys.path import
    import fetcher_io

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class BaseHistoryFetcher:
    """Reusable, parameterized history fetcher and validator for open-source CVE catalogs."""

    def __init__(
        self,
        project: str,
        repo: str,
        keyword: str,
        out_dir: Path | str,
        window_start: str = "1999-01-01",
        window_end: Optional[str] = None,
        slice_days: int = 90,
        results_per_page: int = 200,
        max_calls: int = 400,
        max_time_seconds: int = 180,
        rate_limit_sleep: float = 15.0,
        retry_sleep: float = 40.0,
        per_response_limit: int = 1 * 1024 * 1024,  # 1 MiB
        cumulative_limit: int = 8 * 1024 * 1024,    # 8 MiB
        request_timeout: float = 25.0,
        user_agent: str = "kernel-security-memory-study",
        max_line_bytes: int = 500,
        ownership_filter: Optional[Callable[[Dict[str, Any]], bool]] = None,
        subsystem_extractor: Optional[Callable[[List[str]], str]] = None,
        notes: str = "Descriptions were omitted per policy.",
    ):
        self.project = project
        self.repo = repo
        self.keyword = keyword
        self.out_dir = Path(out_dir)
        self.index_path = self.out_dir / "index.json"
        self.catalog_path = self.out_dir / "catalog.jsonl"

        self.window_start = window_start
        # window.end is the run date (UTC today, or KSM_TODAY), never a frozen
        # literal: a frozen end stopped the refresh from scanning new CVEs.
        self.window_end = window_end or fetcher_io.window_end_iso()
        self.slice_days = slice_days
        self.results_per_page = results_per_page
        self.max_calls = max_calls
        self.max_time_seconds = max_time_seconds
        self.rate_limit_sleep = rate_limit_sleep
        self.retry_sleep = retry_sleep
        self.per_response_limit = per_response_limit
        self.cumulative_limit = cumulative_limit
        self.request_timeout = request_timeout
        self.user_agent = user_agent
        self.max_line_bytes = max_line_bytes
        self.notes = notes

        self.ownership_filter = ownership_filter
        self.subsystem_extractor = subsystem_extractor

        # Internal state
        self.kept_records: Dict[str, Dict[str, Any]] = {}
        self.requests_count: int = 0
        self.cumulative_bytes: int = 0
        self.errors: List[str] = []
        self.coverage: str = "INCOMPLETE"
        self.status: str = "NOT_FETCHED"
        self.cursor_date: Optional[str] = None
        self.window_closed: bool = False
        # resume_present records whether a cursor was actually loaded, so the
        # in-progress pre-save can never rewind (or overwrite) a COMPLETE state.
        self.resume_present: bool = False
        # errors holds this run's failures only; older ones are kept as capped
        # history in error_history and never gate a later run.
        self.error_history: List[str] = []
        self.current_start: datetime.date = datetime.date.fromisoformat(self.window_start)
        self.end_date_limit: datetime.date = datetime.date.fromisoformat(self.window_end)

        self.load_state()

    def load_state(self) -> None:
        """Load persistent cursor and catalog state from disk if present.

        Corrupt files are fatal (``fetcher_io.CorruptStateError``): the previous
        version appended a warning and kept going, so a truncated file was
        rewritten as a shorter "valid" catalog.
        """
        self.kept_records = fetcher_io.read_catalog(self.catalog_path)

        data = fetcher_io.read_index(self.index_path)
        if data is None:
            return

        self.requests_count = data.get("requests", 0)
        self.errors, self.error_history = fetcher_io.load_error_history(data)
        self.coverage = data.get("coverage", "INCOMPLETE")
        self.status = data.get("status", "NOT_FETCHED")
        self.cursor_date = data.get("cursor_date")
        self.window_closed = data.get("window_closed", False)

        resume = data.get("resume")
        if resume and isinstance(resume, dict) and "next_start_date" in resume:
            next_date_str = resume["next_start_date"]
            self.current_start = datetime.date.fromisoformat(next_date_str)
            self.cursor_date = next_date_str
            self.resume_present = True

    def determine_status(self, entry_count: int, coverage: str, cursor_date: Optional[str]) -> Tuple[str, Optional[str], bool]:
        """Compute status, cursor date, and window_closed flag."""
        start_date = self.window_start

        if coverage == "COMPLETE":
            if entry_count == 0:
                return "OBSERVED_EMPTY", None, True
            return "COMPLETE", None, True

        # Coverage is INCOMPLETE:
        cursor_has_advanced = bool(cursor_date and cursor_date != start_date and self.requests_count > 0)
        if (entry_count > 0 or cursor_has_advanced) and cursor_date:
            return "CURSOR_PAUSED", cursor_date, False

        return "NOT_FETCHED", None, False

    def save_state(self, coverage: str, resume_obj: Optional[Dict[str, str]]) -> None:
        """Persist catalog.jsonl and index.json atomically, index last.

        ``fetcher_io.write_catalog_atomic`` replaces ``catalog.jsonl`` through a
        temp file, then ``write_index_atomic`` replaces ``index.json`` the same
        way, so a run killed mid-write keeps the previous committed pair instead
        of leaving a half-written file, and the index can never describe a
        catalog that does not exist.
        """
        self.out_dir.mkdir(parents=True, exist_ok=True)
        sorted_records = sorted(
            self.kept_records.values(),
            key=lambda r: (r.get("published", ""), r.get("advisory_id", ""))
        )

        entry_count = len(sorted_records)
        with_fix_sha = sum(1 for r in sorted_records if r.get("fix_shas"))

        cursor_date = resume_obj.get("next_start_date") if resume_obj else None
        status, determined_cursor, window_closed = self.determine_status(entry_count, coverage, cursor_date)

        notes = self.notes
        if status == "CURSOR_PAUSED":
            notes = f"{self.notes} Cursor paused at {determined_cursor}; window remains open (not closed)."
        elif status == "NOT_FETCHED":
            notes = f"{self.notes} Scaffold not yet fetched."
        elif status == "OBSERVED_EMPTY":
            notes = f"{self.notes} Completed scan over {self.window_start}..{self.window_end} yielded 0 entries."

        index_data = {
            "schema_version": "cve-history-v1",
            "project": self.project,
            "repo": self.repo,
            "window": {
                "start": self.window_start,
                "end": self.window_end,
            },
            "keyword": self.keyword,
            "coverage": coverage,
            "status": status,
            "cursor_date": determined_cursor,
            "window_closed": window_closed,
            "entry_count": entry_count,
            "with_fix_sha": with_fix_sha,
            "requests": self.requests_count,
            "resume": resume_obj if coverage == "INCOMPLETE" else None,
            "errors": self.errors,
            "error_history": fetcher_io.merge_error_history(self.error_history, self.errors),
            "notes": notes,
        }

        fetcher_io.write_catalog_atomic(self.catalog_path, sorted_records)
        fetcher_io.write_index_atomic(self.index_path, index_data)
        self.coverage = coverage
        self.status = status
        self.cursor_date = determined_cursor
        self.window_closed = window_closed

    def _read_bounded_response(self, resp: Any) -> Dict[str, Any]:
        """Read one response body, enforcing the per-response and cumulative byte caps."""
        body = bytearray()
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            body.extend(chunk)
            self.cumulative_bytes += len(chunk)
            if len(body) > self.per_response_limit:
                raise RuntimeError(f"Response limit {self.per_response_limit} bytes exceeded")
            if self.cumulative_bytes > self.cumulative_limit:
                raise RuntimeError(f"Cumulative limit {self.cumulative_limit} bytes exceeded")
        self.requests_count += 1
        return json.loads(body.decode("utf-8"))

    def make_nvd_request(self, url: str) -> Optional[Dict[str, Any]]:
        """Perform a single HTTP request to NVD with timeout, limits, and error preservation."""
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})

        try:
            with urllib.request.urlopen(req, timeout=self.request_timeout) as resp:
                return self._read_bounded_response(resp)

        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                time.sleep(self.retry_sleep)
                try:
                    with urllib.request.urlopen(req, timeout=self.request_timeout) as retry_resp:
                        return self._read_bounded_response(retry_resp)
                except Exception as retry_err:
                    err_msg = f"HTTP {e.code} on {url}: retry failed after {self.retry_sleep}s: {retry_err}"
                    self.errors.append(err_msg)
                    return None
            else:
                err_msg = f"HTTP {e.code} on {url}: {e.reason}"
                self.errors.append(err_msg)
                return None

        except (urllib.error.URLError, TimeoutError, socket.timeout) as net_err:
            err_msg = f"Network timeout/error on {url}: {net_err}"
            self.errors.append(err_msg)
            return None

        except Exception as exc:
            err_msg = f"Unexpected error on {url}: {exc}"
            self.errors.append(err_msg)
            return None

    def extract_cwe(self, cve_item: Dict[str, Any]) -> Tuple[Optional[str], str]:
        """Extract CWE id (e.g. CWE-119) and state."""
        weaknesses = cve_item.get("weaknesses", [])
        if not isinstance(weaknesses, list):
            return None, "UNKNOWN"

        for w in weaknesses:
            descriptions = w.get("description", [])
            if isinstance(descriptions, list):
                for d in descriptions:
                    val = d.get("value", "")
                    if val and CWE_PATTERN.match(val):
                        return val.upper(), "STATED_BY_ADVISORY"
        return None, "UNKNOWN"

    def extract_patch_urls_and_shas(self, cve_item: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Extract up to 3 https:// patch URLs and 40-hex commit SHAs."""
        references = cve_item.get("references", [])
        raw_urls = []
        if isinstance(references, list):
            for ref in references:
                u = ref.get("url", "")
                if u and u.startswith("https://") and u not in raw_urls:
                    raw_urls.append(u)

        patch_urls = raw_urls[:3]
        shas = []
        for u in patch_urls:
            found = SHA_PATTERN.findall(u.lower())
            # also regex pattern in URL path
            url_matches = re.findall(r"\b([0-9a-f]{40})\b", u.lower())
            for s in found + url_matches:
                if s not in shas:
                    shas.append(s)

        return patch_urls, shas

    def transform_cve_item(self, cve_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Standard transformation of NVD CVE item into catalog record."""
        if self.ownership_filter and not self.ownership_filter(cve_item):
            return None

        cve_id = cve_item.get("id", "")
        if not cve_id or not CVE_PATTERN.match(cve_id):
            return None

        pub_raw = cve_item.get("published", "")
        published = pub_raw[:10] if pub_raw else ""
        if not DATE_PATTERN.match(published):
            return None

        cwe, cwe_state = self.extract_cwe(cve_item)
        patch_urls, fix_shas = self.extract_patch_urls_and_shas(cve_item)
        subsystem = self.subsystem_extractor(patch_urls) if self.subsystem_extractor else "unassigned"

        record = {
            "advisory_id": cve_id,
            "published": published,
            "cwe": cwe,
            "cwe_state": cwe_state,
            "patch_urls": patch_urls,
            "fix_shas": fix_shas,
            "subsystem": subsystem,
        }

        # Truncate patch_urls if needed to fit under byte limit
        encoded = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        while len(encoded) > self.max_line_bytes and record["patch_urls"]:
            record["patch_urls"].pop()
            record["fix_shas"] = [s for s in record["fix_shas"] if any(s in u for u in record["patch_urls"])]
            encoded = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        if len(encoded) > self.max_line_bytes:
            return None

        return record

    def fetch_history(self, max_calls: Optional[int] = None, max_time_seconds: Optional[int] = None) -> bool:
        """Run iterative fetch loop with window slicing, resuming from cursor."""
        start_wall_time = time.time()
        time_limit = max_time_seconds or self.max_time_seconds
        call_limit = max_calls or self.max_calls
        calls_this_run = 0

        if self.coverage == "COMPLETE":
            # The window is closed: return instead of re-fetching it, and above
            # all without writing an INCOMPLETE cursor first (that used to rewind
            # a COMPLETE catalog to window_start and lose its status).
            print(f"Catalog is already COMPLETE ({self.status}); nothing to fetch.")
            return True

        curr_start = self.current_start

        # Pre-save the carried cursor so a crash mid-run keeps the previous
        # position. Only ever written when a cursor was actually loaded: with no
        # resume it would record an INCOMPLETE state at window_start, which is
        # both a rewind and an overwrite of a COMPLETE catalog.
        if self.resume_present:
            self.save_state("INCOMPLETE", {"next_start_date": curr_start.isoformat()})

        while curr_start <= self.end_date_limit:
            if time.time() - start_wall_time > time_limit:
                print(f"Time limit reached ({time_limit}s). Pausing at {curr_start.isoformat()}...")
                self.save_state("INCOMPLETE", {"next_start_date": curr_start.isoformat()})
                return False

            # Only calls_this_run bounds the run: self.requests_count is a lifetime
            # counter persisted across runs, so comparing it against max_calls would
            # pause every later run before it issues a single request.
            if calls_this_run >= call_limit:
                print(f"Request cap reached. Pausing at {curr_start.isoformat()}...")
                self.save_state("INCOMPLETE", {"next_start_date": curr_start.isoformat()})
                return False

            if self.cumulative_bytes >= self.cumulative_limit:
                print("Cumulative byte cap reached. Pausing...")
                self.save_state("INCOMPLETE", {"next_start_date": curr_start.isoformat()})
                return False

            curr_end = min(curr_start + datetime.timedelta(days=self.slice_days - 1), self.end_date_limit)
            start_iso = f"{curr_start.isoformat()}T00:00:00.000"
            end_iso = f"{curr_end.isoformat()}T23:59:59.999"

            start_index = 0
            slice_done = False

            while not slice_done:
                if time.time() - start_wall_time > time_limit or calls_this_run >= call_limit:
                    self.save_state("INCOMPLETE", {"next_start_date": curr_start.isoformat()})
                    return False

                time.sleep(self.rate_limit_sleep)

                params = {
                    "resultsPerPage": self.results_per_page,
                    "startIndex": start_index,
                    "keywordSearch": self.keyword,
                    "pubStartDate": start_iso,
                    "pubEndDate": end_iso,
                }
                query_str = urllib.parse.urlencode(params)
                url = f"{NVD_API_URL}?{query_str}"

                data = self.make_nvd_request(url)
                calls_this_run += 1

                if data is None:
                    # Network error occurred and was preserved in self.errors
                    print(f"Network error on slice {curr_start}..{curr_end}. Pausing cursor.")
                    self.save_state("INCOMPLETE", {"next_start_date": curr_start.isoformat()})
                    return False

                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                for vuln in vulnerabilities:
                    cve_item = vuln.get("cve", {})
                    rec = self.transform_cve_item(cve_item)
                    if rec:
                        self.kept_records[rec["advisory_id"]] = rec

                start_index += len(vulnerabilities)
                if start_index >= total_results or len(vulnerabilities) == 0:
                    slice_done = True

            curr_start = curr_end + datetime.timedelta(days=1)

            if curr_start > self.end_date_limit:
                # Coverage is COMPLETE: stop instead of looping on.
                break

        # Window completed without interruption
        self.save_state("COMPLETE", None)
        print(f"Fetch completed across full window. Total records: {len(self.kept_records)}")
        return True

    def validate_offline(self) -> bool:
        """Perform offline validation of catalog and index files against schema and invariants."""
        if not self.index_path.is_file():
            print(f"Error: missing index file at {self.index_path}", file=sys.stderr)
            return False

        if not self.catalog_path.is_file():
            print(f"Error: missing catalog file at {self.catalog_path}", file=sys.stderr)
            return False

        try:
            index_data = json.loads(self.index_path.read_text(encoding="utf-8"))
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
            print("Error: schema_version mismatch in index.json", file=sys.stderr)
            return False

        if index_data["project"] != self.project:
            print(f"Error: project mismatch: {index_data['project']} != {self.project}", file=sys.stderr)
            return False

        coverage = index_data.get("coverage")
        if coverage not in ("COMPLETE", "INCOMPLETE"):
            print("Error: invalid coverage in index.json", file=sys.stderr)
            return False

        if coverage == "COMPLETE" and index_data.get("resume") is not None:
            print("Error: resume must be null when coverage is COMPLETE", file=sys.stderr)
            return False

        window_ok, window_reason = fetcher_io.check_window(index_data.get("window"))
        if not window_ok:
            print(f"Error: invalid window: {window_reason}", file=sys.stderr)
            return False

        catalog_lines = []
        for line_idx, raw_line in enumerate(self.catalog_path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw_line.strip()
            if not line:
                continue

            raw_bytes = raw_line.encode("utf-8")
            if len(raw_bytes) > self.max_line_bytes:
                print(f"Error: Line {line_idx} exceeds {self.max_line_bytes} bytes ({len(raw_bytes)} bytes)", file=sys.stderr)
                return False

            try:
                rec = json.loads(line)
            except Exception as e:
                print(f"Error: Line {line_idx} invalid JSON: {e}", file=sys.stderr)
                return False

            if "description" in rec:
                print(f"Error: Line {line_idx} contains forbidden 'description' key", file=sys.stderr)
                return False

            if not CVE_PATTERN.match(rec.get("advisory_id", "")):
                print(f"Error: Line {line_idx} invalid advisory_id: {rec.get('advisory_id')}", file=sys.stderr)
                return False

            if not DATE_PATTERN.match(rec.get("published", "")):
                print(f"Error: Line {line_idx} invalid published date: {rec.get('published')}", file=sys.stderr)
                return False

            if rec.get("cwe") is not None and not CWE_PATTERN.match(rec["cwe"]):
                print(f"Error: Line {line_idx} invalid CWE: {rec['cwe']}", file=sys.stderr)
                return False

            for u in rec.get("patch_urls", []):
                if not u.startswith("https://"):
                    print(f"Error: Line {line_idx} URL not https://: {u}", file=sys.stderr)
                    return False

            for s in rec.get("fix_shas", []):
                if not SHA_PATTERN.match(s):
                    print(f"Error: Line {line_idx} invalid SHA: {s}", file=sys.stderr)
                    return False

            catalog_lines.append(rec)

        if index_data["entry_count"] != len(catalog_lines):
            print(f"Error: index entry_count ({index_data['entry_count']}) != catalog lines ({len(catalog_lines)})", file=sys.stderr)
            return False

        with_sha = sum(1 for r in catalog_lines if r.get("fix_shas"))
        if index_data["with_fix_sha"] != with_sha:
            print(f"Error: index with_fix_sha ({index_data['with_fix_sha']}) != actual ({with_sha})", file=sys.stderr)
            return False

        return True
