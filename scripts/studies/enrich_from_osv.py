#!/usr/bin/env python3
"""Enrich CVE catalogs with fix commit SHAs and CWE ids from the OSV.dev API.

Deterministic and LLM-free: every value written into a catalog row comes from a
raw OSV response cached under docs/studies/cve-history/osv-cache/<ID>.json, so
reruns and --offline reproduce the same output byte-for-byte.

Data mapping (verified against https://api.osv.dev/v1/vulns/<CVE-ID>):
  * fix SHAs  <- affected[].ranges[] with type == "GIT", events {"fixed": <sha>}
                (strict 40-hex, reusing enrich_fix_shas.SHA_RE)
  * CWE ids   <- database_specific.cwe_ids
  * aliases listed by a response are queried too and merged into the same facts.

KSM_CVE_HISTORY_DIR overrides the catalog root (used by tests/test_enrich_from_osv.py).

Existing non-empty values are never overwritten and nothing is invented: a value
is written only when OSV actually provides it, and provenance is recorded with
"fix_sha_source"/"cwe_source" == "osv".
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# KSM_CVE_HISTORY_DIR lets the offline tests point the script at a temp tree.
CVE_HISTORY_DIR = Path(os.environ.get("KSM_CVE_HISTORY_DIR") or ROOT / "docs/studies/cve-history")
CACHE_DIRNAME = "osv-cache"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
DEFAULT_PROJECTS = ("openssl", "curl", "glibc", "openssh")
USER_AGENT = "ksm-osv-enrich/1.0 (+https://github.com/iberi22/kernel-security-memory)"
MIN_DELAY_S = 0.25  # polite rate limit (spec: >= 0.2s between requests)
MAX_ATTEMPTS = 5
REQUEST_TIMEOUT_S = 30
CWE_RE = re.compile(r"^CWE-\d+$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from enrich_fix_shas import SHA_RE  # noqa: E402  reuse the canonical 40-hex rule


def normalize_repo(url):
    """Normalize a git repo URL for comparison (case, .git suffix, trailing /)."""
    if not isinstance(url, str) or not url.strip():
        return ""
    value = url.strip().lower().rstrip("/")
    if value.endswith(".git"):
        value = value[: -len(".git")]
    return value


def is_osv_vuln(doc):
    """True when a cached body is an OSV vulnerability record, not an error."""
    return isinstance(doc, dict) and bool(doc.get("id")) and "code" not in doc


def extract_fix_events(doc):
    """Return [(sha, repo_url|None)] from GIT ranges 'fixed' events of an OSV doc."""
    fixes = []
    for affected in doc.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") != "GIT":
                continue
            repo = rng.get("repo")
            repo = repo.strip() if isinstance(repo, str) and repo.strip() else None
            for event in rng.get("events") or []:
                if not isinstance(event, dict) or "fixed" not in event:
                    continue
                sha = str(event["fixed"]).strip().lower()
                if SHA_RE.fullmatch(sha):
                    fixes.append((sha, repo))
    return fixes


def extract_cwe_ids(doc):
    """Return CWE ids from database_specific.cwe_ids, normalized and de-duplicated."""
    cwe_ids = []
    database_specific = doc.get("database_specific")
    if not isinstance(database_specific, dict):
        return cwe_ids
    for raw in database_specific.get("cwe_ids") or []:
        if not isinstance(raw, str):
            continue
        value = raw.strip().upper()
        if CWE_RE.fullmatch(value) and value not in cwe_ids:
            cwe_ids.append(value)
    return cwe_ids


class OsvClient:
    """Cache-first OSV.dev client; --offline never touches the network."""

    def __init__(self, cache_dir, offline=False, delay_s=MIN_DELAY_S):
        self.cache_dir = Path(cache_dir)
        self.offline = offline
        self.delay_s = max(float(delay_s), 0.2)
        self._last_request = 0.0
        self.network_calls = 0

    def cache_path(self, vuln_id):
        return self.cache_dir / f"{vuln_id}.json"

    def _read_cache(self, vuln_id):
        path = self.cache_path(vuln_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None

    def _throttle(self):
        elapsed = time.monotonic() - self._last_request
        if self._last_request and elapsed < self.delay_s:
            time.sleep(self.delay_s - elapsed)

    def _fetch(self, vuln_id):
        """Return (http_status|None, raw_bytes). None status means transport error."""
        url = OSV_VULN_URL.format(vuln_id=vuln_id)
        for attempt in range(MAX_ATTEMPTS):
            self._throttle()
            self._last_request = time.monotonic()
            self.network_calls += 1
            request = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            })
            try:
                with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_S) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as err:
                body = b""
                try:
                    body = err.read()
                except Exception:
                    pass
                if err.code == 429:
                    retry_after = err.headers.get("Retry-After") if err.headers else None
                    wait = float(retry_after) if retry_after and retry_after.strip().isdigit() else 2.0 ** attempt
                    time.sleep(max(wait, self.delay_s))
                    continue
                return err.code, body
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
                # Transport failure (including a read timeout mid-body): back off and retry.
                time.sleep(2.0 ** attempt)
        return None, b""

    def get(self, vuln_id):
        """Return the OSV document for vuln_id, or None when unavailable."""
        if not SAFE_ID_RE.fullmatch(vuln_id):
            return None
        cached = self._read_cache(vuln_id)
        if cached is not None:
            return cached
        if self.offline:
            return None
        status, body = self._fetch(vuln_id)
        if status is None:
            print(f"Warning: OSV request failed for {vuln_id}", file=sys.stderr)
            return None
        try:
            doc = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            doc = {"code": status, "message": "non-JSON response body"}
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path(vuln_id).write_text(
            json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return doc


def collect_osv_facts(client, advisory_id):
    """Merge fix SHAs and CWE ids from the advisory and the aliases OSV lists."""
    facts = {"fixes": [], "cwes": [], "queried": [], "missing": []}
    pending = [(advisory_id, 0)]
    seen = set()
    while pending:
        vuln_id, depth = pending.pop(0)
        if vuln_id in seen or not SAFE_ID_RE.fullmatch(vuln_id):
            continue
        seen.add(vuln_id)
        doc = client.get(vuln_id)
        if not is_osv_vuln(doc):
            facts["missing"].append(vuln_id)
            continue
        facts["queried"].append(vuln_id)
        for fix in extract_fix_events(doc):
            if fix not in facts["fixes"]:
                facts["fixes"].append(fix)
        for cwe in extract_cwe_ids(doc):
            if cwe not in facts["cwes"]:
                facts["cwes"].append(cwe)
        if depth == 0:
            for alias in doc.get("aliases") or []:
                if isinstance(alias, str) and alias not in seen:
                    pending.append((alias, depth + 1))
    return facts


def enrich_row(row, facts, upstream_repo):
    """Fill fix_shas/cwe from OSV facts without ever overwriting existing values."""
    upstream = normalize_repo(upstream_repo)

    current = [s for s in (row.get("fix_shas") or []) if isinstance(s, str)]
    foreign_repos = []
    added_sha = False
    for sha, repo in facts["fixes"]:
        if sha not in current:
            current.append(sha)
            added_sha = True
        if repo and normalize_repo(repo) != upstream and repo not in foreign_repos:
            foreign_repos.append(repo)
    if added_sha:
        row["fix_shas"] = current
        row["fix_sha_source"] = "osv"
        if foreign_repos and not (isinstance(row.get("fix_repo"), str) and row["fix_repo"].strip()):
            row["fix_repo"] = foreign_repos[0] if len(foreign_repos) == 1 else sorted(foreign_repos)

    cwe = row.get("cwe")
    if not (isinstance(cwe, str) and cwe.strip()) and facts["cwes"]:
        row["cwe"] = facts["cwes"][0]
        row["cwe_state"] = "STATED_BY_OSV"
        row["cwe_source"] = "osv"


def read_catalog(catalog_file):
    return [json.loads(line) for line in catalog_file.read_text(encoding="utf-8").splitlines() if line.strip()]


def catalog_text(rows):
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


def enrich_project(project_dir, client):
    """Recompute the enriched catalog/index for one project in memory."""
    project_dir = Path(project_dir)
    catalog_file = project_dir / "catalog.jsonl"
    index_file = project_dir / "index.json"
    index_data = json.loads(index_file.read_text(encoding="utf-8"))
    rows = read_catalog(catalog_file)
    upstream_repo = index_data.get("repo")

    stats = {
        "project": index_data.get("project", project_dir.name),
        "rows": len(rows),
        "with_fix_sha_before": 0,
        "with_cwe_before": 0,
        "not_in_osv": 0,
    }

    def count(predicate):
        return sum(1 for row in rows if predicate(row))

    # "before" is the pre-enrichment baseline: recorded once and never recomputed,
    # so a rerun (and --check) reproduces byte-identical output.
    baseline_fix_sha = count(lambda row: bool(row.get("fix_shas")))
    baseline_cwe = count(lambda row: isinstance(row.get("cwe"), str) and row["cwe"].strip())

    for row in rows:
        advisory_id = row.get("advisory_id")
        if not advisory_id:
            stats["not_in_osv"] += 1
            continue
        facts = collect_osv_facts(client, str(advisory_id))
        if not facts["queried"]:
            stats["not_in_osv"] += 1
        enrich_row(row, facts, upstream_repo)

    stats["with_fix_sha_before"] = index_data.get("with_fix_sha_before", baseline_fix_sha)
    stats["with_fix_sha"] = count(lambda row: bool(row.get("fix_shas")))
    stats["with_cwe_before"] = index_data.get("with_cwe_before", baseline_cwe)
    stats["with_cwe"] = count(lambda row: isinstance(row.get("cwe"), str) and row["cwe"].strip())

    index_data["entry_count"] = len(rows)
    index_data["rows"] = len(rows)
    index_data["with_fix_sha_before"] = stats["with_fix_sha_before"]
    index_data["with_fix_sha"] = stats["with_fix_sha"]
    index_data["with_cwe_before"] = stats["with_cwe_before"]
    index_data["with_cwe"] = stats["with_cwe"]
    index_data["not_in_osv"] = stats["not_in_osv"]
    return catalog_text(rows), json.dumps(index_data, indent=2, ensure_ascii=False) + "\n", stats


def resolve_projects(names):
    projects = []
    for name in names:
        project_dir = CVE_HISTORY_DIR / name
        if not (project_dir / "catalog.jsonl").exists() or not (project_dir / "index.json").exists():
            raise SystemExit(f"Error: no catalog/index for project {name!r} at {project_dir}")
        projects.append(project_dir)
    return projects


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects", default=",".join(DEFAULT_PROJECTS),
                        help="Comma-separated project names (default: %(default)s)")
    parser.add_argument("--offline", action="store_true", help="Use only the OSV cache; never open a connection")
    parser.add_argument("--check", action="store_true", help="Recompute and exit non-zero if the tree differs")
    args = parser.parse_args(argv)

    names = [p.strip() for p in args.projects.split(",") if p.strip()]
    if not names:
        raise SystemExit("Error: --projects is empty")
    projects = resolve_projects(names)
    client = OsvClient(CVE_HISTORY_DIR / CACHE_DIRNAME, offline=args.offline)

    failed = False
    for project_dir in projects:
        expected_catalog, expected_index, stats = enrich_project(project_dir, client)
        label = stats["project"]
        if args.check:
            catalog_file = project_dir / "catalog.jsonl"
            index_file = project_dir / "index.json"
            if catalog_file.read_text(encoding="utf-8") != expected_catalog:
                print(f"Error: {label}/catalog.jsonl differs from OSV-enriched recomputation", file=sys.stderr)
                failed = True
            if index_file.read_text(encoding="utf-8") != expected_index:
                print(f"Error: {label}/index.json differs from OSV-enriched recomputation", file=sys.stderr)
                failed = True
        else:
            (project_dir / "catalog.jsonl").write_text(expected_catalog, encoding="utf-8")
            (project_dir / "index.json").write_text(expected_index, encoding="utf-8")
        print(f"{label}: rows={stats['rows']} with_fix_sha {stats['with_fix_sha_before']}->{stats['with_fix_sha']} "
              f"with_cwe {stats['with_cwe_before']}->{stats['with_cwe']} not_in_osv={stats['not_in_osv']}")

    if failed:
        raise SystemExit(1)
    print(f"OSV enrichment {'checked' if args.check else 'written'} for {len(projects)} project(s) "
          f"({'offline' if args.offline else 'online'}, {client.network_calls} network request(s)).")


if __name__ == "__main__":
    main()
