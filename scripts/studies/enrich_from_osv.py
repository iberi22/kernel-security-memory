#!/usr/bin/env python3
"""Enrich CVE catalogs with fix commit SHAs and CWE ids from the OSV.dev API.

Deterministic and LLM-free: every value written into a catalog row comes from a
raw OSV response cached under docs/studies/cve-history/osv-cache/<ID>.json, so
reruns and --offline reproduce the same output byte-for-byte.

Data mapping (verified against https://api.osv.dev/v1/vulns/<CVE-ID>):
  * fix SHAs  <- references typed FIX (or PATCH) whose URL is a 40-hex commit
                in the project's own repository. Only those commits are the
                fix: the advisory itself points at them.
  * CWE ids   <- database_specific.cwe_ids
  * aliases listed by a response are queried too and merged into the same facts.

Deliberately NOT written: the GIT-range boundary commits (``fixed`` /
``last_affected`` events). OSV derives those from the affected version range, so
they are the first commit that contains the fix - usually a merge, a release
stamp or a version bump, and sometimes in another repository the CVE record also
lists. They delimit a version range; they are not the fix, and writing them into
fix_shas is what round 1 of the upstream catalogs did and had to undo.

KSM_CVE_HISTORY_DIR overrides the catalog root (used by tests/test_enrich_from_osv.py).

Existing non-empty values are never overwritten and nothing is invented: a value
is written only when OSV actually provides it, and provenance is recorded with
"fix_sha_source"/"cwe_source" == "osv".
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# KSM_CVE_HISTORY_DIR lets the offline tests point the script at a temp tree.
CVE_HISTORY_DIR = Path(os.environ.get("KSM_CVE_HISTORY_DIR") or ROOT / "docs/studies/cve-history")
CACHE_DIRNAME = "osv-cache"
# Committed sidecar: one row per (repo, sha) fix-sha candidate with its GitHub
# parent count. Parents == 1 is a real fix commit; parents != 1 is a merge and is
# not written into fix_shas. Refreshed only by --fetch-commit-parents.
COMMIT_PARENTS_PATH = CVE_HISTORY_DIR / "commit-parents.jsonl"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
DEFAULT_PROJECTS = ("openssl", "curl", "glibc", "openssh")
USER_AGENT = "ksm-osv-enrich/1.0 (+https://github.com/iberi22/kernel-security-memory)"
MIN_DELAY_S = 0.25  # polite rate limit (spec: >= 0.2s between requests)
MAX_ATTEMPTS = 5
REQUEST_TIMEOUT_S = 30
# Reference types an advisory uses to point at the commit that fixes it.
# "PATCH" is the CVE 5.x spelling; OSV itself emits "FIX".
FIX_REFERENCE_TYPES = ("FIX", "PATCH")
HEX40_URL_RE = re.compile(r"[0-9a-f]{40}")
HEX_CHARS = "0123456789abcdef"
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


def repo_path(url):
    """The host/path part of a repository URL, e.g. github.com/curl/curl.

    Used with a trailing "/" to match links inside that repository, so that
    github.com/systemd/systemd never matches github.com/systemd/systemd-stable.
    """
    value = normalize_repo(url)
    return value.split("://", 1)[-1] if value else ""


def extract_fix_reference_shas(doc, upstream_repo):
    """Return the commit SHAs the advisory itself types as FIX/PATCH.

    Only links that are a 40-hex commit inside ``upstream_repo`` qualify. GIT
    range events are not consulted: they are version boundaries, not fix
    commits (see the module docstring).
    """
    marker = repo_path(upstream_repo)
    if not marker:
        return []
    marker += "/"
    shas = []
    for reference in doc.get("references") or []:
        if not isinstance(reference, dict) or reference.get("type") not in FIX_REFERENCE_TYPES:
            continue
        url = reference.get("url")
        if not isinstance(url, str) or marker not in url:
            continue
        for match in HEX40_URL_RE.finditer(url):
            begin, end = match.span()
            if begin > 0 and url[begin - 1] in HEX_CHARS:
                continue
            if end < len(url) and url[end] in HEX_CHARS:
                continue
            sha = match.group(0)
            if SHA_RE.fullmatch(sha) and sha not in shas:
                shas.append(sha)
    return shas


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


def _github_slug(url):
    """owner/name for a github.com repo URL, or None for another host."""
    normalized = normalize_repo(url).split("://", 1)[-1]
    if not normalized.startswith("github.com/"):
        return None
    parts = normalized[len("github.com/"):].split("/")
    if len(parts) != 2 or not all(parts):
        return None
    return f"{parts[0]}/{parts[1]}"


def load_commit_parents(path=None):
    """Read commit-parents.jsonl into {(normalized_repo, sha): parents}."""
    path = Path(path) if path else COMMIT_PARENTS_PATH
    index = {}
    if not path.exists():
        return index
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        index[(normalize_repo(row["repo"]), row["sha"])] = row["parents"]
    return index


def apply_parent_policy(fixes, upstream_repo, parents_index):
    """Keep single-parent fix shas; drop merges. This catalog has no fixed_in
    column, so a demoted sha is excluded from fix_shas and counted.

    Every candidate must be in ``parents_index``: the sidecar is the only
    permitted source, so a candidate absent from it fails loudly (naming the
    sha) instead of being kept or guessed. Returns (kept_shas, demoted_count).
    """
    normalized = normalize_repo(upstream_repo)
    kept, demoted = [], 0
    for sha in fixes:
        parents = parents_index.get((normalized, sha))
        if parents is None:
            raise ValueError(
                f"fix sha {sha} for {upstream_repo} is absent from {COMMIT_PARENTS_PATH.name}; "
                "refresh it with --fetch-commit-parents"
            )
        if parents == 1:
            kept.append(sha)
        else:
            demoted += 1
    return kept, demoted


def _gh_commit_parents(slug, sha):
    result = subprocess.run(
        ["gh", "api", f"repos/{slug}/commits/{sha}", "--jq", ".parents|length"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise ValueError(f"gh api repos/{slug}/commits/{sha} failed: {result.stderr.strip()}")
    try:
        return int(result.stdout.strip())
    except ValueError as exc:
        raise ValueError(f"gh api repos/{slug}/commits/{sha}: non-integer parents") from exc


def fetch_commit_parents(projects, client):
    """Refresh commit-parents.jsonl from GitHub for every OSV fix-sha candidate.

    Enumerates the raw candidates (FIX/PATCH shas inside each project's repo
    from the OSV cache) and asks GitHub for each parent count, preserving rows
    for other repos. Returns the sorted rows written.
    """
    collected = load_commit_parents()
    for project_dir in projects:
        index_data = json.loads((project_dir / "index.json").read_text(encoding="utf-8"))
        repo = index_data.get("repo")
        slug = _github_slug(repo)
        for row in read_catalog(project_dir / "catalog.jsonl"):
            advisory_id = row.get("advisory_id")
            if not advisory_id:
                continue
            facts = collect_osv_facts(client, str(advisory_id), repo)
            for sha in facts["fixes"]:
                if slug is None:
                    raise ValueError(
                        f"{repo} is not a github.com repository; gh api cannot count parents for {sha}"
                    )
                collected[(normalize_repo(repo), sha)] = {
                    "repo": repo,
                    "sha": sha,
                    "parents": _gh_commit_parents(slug, sha),
                    "fetched_via": f"gh api repos/{slug}/commits/{sha}",
                }
    rows_sorted = sorted(collected.values(), key=lambda r: (normalize_repo(r["repo"]), r["sha"]))
    text = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows_sorted)
    if not (COMMIT_PARENTS_PATH.exists() and COMMIT_PARENTS_PATH.read_text(encoding="utf-8") == text):
        COMMIT_PARENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        COMMIT_PARENTS_PATH.write_text(text, encoding="utf-8")
    return rows_sorted


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


def collect_osv_facts(client, advisory_id, upstream_repo):
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
        for sha in extract_fix_reference_shas(doc, upstream_repo):
            if sha not in facts["fixes"]:
                facts["fixes"].append(sha)
        for cwe in extract_cwe_ids(doc):
            if cwe not in facts["cwes"]:
                facts["cwes"].append(cwe)
        if depth == 0:
            for alias in doc.get("aliases") or []:
                if isinstance(alias, str) and alias not in seen:
                    pending.append((alias, depth + 1))
    return facts


def enrich_row(row, facts):
    """Fill fix_shas/cwe from OSV facts without ever overwriting existing values."""
    current = [s for s in (row.get("fix_shas") or []) if isinstance(s, str)]
    added_sha = False
    for sha in facts["fixes"]:
        if sha not in current:
            current.append(sha)
            added_sha = True
    if added_sha:
        row["fix_shas"] = current
        row["fix_sha_source"] = "osv"

    cwe = row.get("cwe")
    if not (isinstance(cwe, str) and cwe.strip()) and facts["cwes"]:
        row["cwe"] = facts["cwes"][0]
        # OSV is an advisory source: same state vocabulary as the NVD fetchers
        # validate; the provenance is recorded separately in cwe_source.
        row["cwe_state"] = "STATED_BY_ADVISORY"
        row["cwe_source"] = "osv"


def read_catalog(catalog_file):
    return [json.loads(line) for line in catalog_file.read_text(encoding="utf-8").splitlines() if line.strip()]


def catalog_text(rows):
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


def enrich_project(project_dir, client, parents_index=None):
    """Recompute the enriched catalog/index for one project in memory.

    When ``parents_index`` is given (the commit-parents sidecar was present), OSV
    fix shas are verified against it: only single-parent commits stay in fix_shas
    and merges are dropped and counted. When it is None there is no sidecar, so
    no verification happens and the output is byte-identical to before.
    """
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

    demoted = 0
    for row in rows:
        advisory_id = row.get("advisory_id")
        if not advisory_id:
            stats["not_in_osv"] += 1
            continue
        facts = collect_osv_facts(client, str(advisory_id), upstream_repo)
        if not facts["queried"]:
            stats["not_in_osv"] += 1
        if parents_index is not None:
            facts["fixes"], row_demoted = apply_parent_policy(facts["fixes"], upstream_repo, parents_index)
            demoted += row_demoted
        enrich_row(row, facts)

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
    if parents_index is not None:
        stats["merge_fix_refs_demoted"] = demoted
        if demoted:
            # Recorded only when it moves, so a project with no demotions keeps
            # byte-identical output for --check.
            index_data["merge_fix_refs_demoted"] = demoted
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
    parser.add_argument("--fetch-commit-parents", action="store_true",
                        help="Network refresh: query GitHub for each OSV fix-sha candidate's parent count and write commit-parents.jsonl")
    args = parser.parse_args(argv)

    names = [p.strip() for p in args.projects.split(",") if p.strip()]
    if not names:
        raise SystemExit("Error: --projects is empty")
    projects = resolve_projects(names)

    if args.fetch_commit_parents:
        client = OsvClient(CVE_HISTORY_DIR / CACHE_DIRNAME, offline=True)
        try:
            rows = fetch_commit_parents(projects, client)
        except (ValueError, OSError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        merges = sum(1 for r in rows if r["parents"] != 1)
        print(f"Wrote {COMMIT_PARENTS_PATH}: {len(rows)} commit-parent record(s), {merges} with parents != 1")
        raise SystemExit(0)

    client = OsvClient(CVE_HISTORY_DIR / CACHE_DIRNAME, offline=args.offline)
    # The commit-parents policy is active only when the sidecar is present; when
    # it is absent there are no fix-sha facts to verify against and the output
    # stays byte-identical to the pre-sidecar behavior.
    parents_index = load_commit_parents() if COMMIT_PARENTS_PATH.exists() else None

    failed = False
    for project_dir in projects:
        try:
            expected_catalog, expected_index, stats = enrich_project(project_dir, client, parents_index)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1)
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
