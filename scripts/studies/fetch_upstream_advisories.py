#!/usr/bin/env python3
"""Fetch authoritative upstream advisory catalogs for several projects.

Every catalog is built from a machine-readable source the project (or OSV.dev)
runs, deterministically and with no LLM:

  curl    https://curl.se/docs/vuln.json                       (OSV-format array)
  openssl https://openssl-library.org/news/secjson/            (CVE 5.x records)
  git / systemd / sqlite / postgres
          https://api.osv.dev/v1/query  (OSV.dev, ecosystem GIT, package = repo URL)

The OSV.dev query is precise (scoped to the repository), never an NVD keyword
match; it aggregates the project's own GitHub Security Advisories and the CVE
records (cvelistV5). Advisory descriptions are never copied (docs/DATA-POLICY.md).

Two different meanings are kept apart for every OSV-sourced row:

  fix_shas        commits the advisory itself identifies as the fix, i.e.
                  references typed FIX or PATCH whose URL is a 40-hex commit
                  in this project's repository.
  fixed_in_shas   the GIT-range boundary commits (``fixed`` / ``last_affected``
                  events) of the ranges that name this project's repository.
                  OSV derives those from the affected version range, so they
                  mark where the range ends - usually a merge, a release stamp
                  or a version bump, and sometimes in a different repository
                  the CVE record also lists. They are kept because they delimit
                  a version range, and they are never treated as fix commits.

The curl feed keeps its single "fix_shas" column: curl documents the GIT
``fixed`` commit of each advisory as the commit that fixed it, and a sample of
ten of those commits verified that claim (see _curl_rows).

Every output can be rebuilt byte-for-byte from the committed snapshot
(``source.json``) with ``--offline --check``, so no network access is needed to
verify the delivery. Descriptions are never copied (docs/DATA-POLICY.md).
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

SNAPSHOT_LIMIT_BYTES = 5 * 1024 * 1024
SNAPSHOT_SCHEMA = "upstream-advisory-snapshot-v1"
HTTP_TIMEOUT = 30
USER_AGENT = "swal-ksm-upstream-advisories/1.0"

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX40_URL_RE = re.compile(r"[0-9a-f]{40}")
HEX_CHARS = "0123456789abcdef"

CURL_FEED_URL = "https://curl.se/docs/vuln.json"
CURL_REPO = "https://github.com/curl/curl"
OPENSSL_INDEX_URL = "https://openssl-library.org/news/secjson/"
OPENSSL_REPO = "https://github.com/openssl/openssl"

# --- Projects whose advisories are sourced from the OSV.dev API --------------
# git, systemd, sqlite and postgres publish no single project-hosted feed, but
# OSV.dev (run by Google, ecosystem GIT) exposes their GitHub Security
# Advisories and CVE records as OSV-format data scoped to the repository URL.
# openssh/nginx/qemu/unbound/glibc were checked and have no comparable in-repo
# source (see the study notes); they are skipped.
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_GIT_ECOSYSTEM = "GIT"
OSV_HTTP_TIMEOUT = 180  # OSV can be slow to assemble a large repo's records
GIT_REPO = "https://github.com/git/git"
SYSTEMD_REPO = "https://github.com/systemd/systemd"
SQLITE_REPO = "https://github.com/sqlite/sqlite"
POSTGRES_REPO = "https://github.com/postgres/postgres"
GIT_PACKAGE = "github.com/git/git"
SYSTEMD_PACKAGE = "github.com/systemd/systemd"
SQLITE_PACKAGE = "github.com/sqlite/sqlite"
POSTGRES_PACKAGE = "github.com/postgres/postgres"
OSV_PROJECTS = ("git", "systemd", "sqlite", "postgres")
# Reference types an advisory uses to point at the commit that fixes it.
# "PATCH" is the CVE 5.x spelling; OSV itself emits "FIX".
OSV_FIX_REFERENCE_TYPES = ("FIX", "PATCH")
# GIT-range keys that delimit an affected version range. They are boundaries,
# not fix commits: "fixed" is the first commit that contains the fix (often a
# merge or a release stamp) and "last_affected" is the last affected commit.
OSV_BOUNDARY_EVENT_KEYS = ("fixed", "last_affected")
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")

# The catalog directory name is the project name, so an upstream catalog never
# collides with the NVD-derived catalog of the same project in one manifest.
PROJECT_META = {
    "curl": {"name": "curl-upstream", "repo": CURL_REPO, "feed": CURL_FEED_URL},
    "openssl": {"name": "openssl-upstream", "repo": OPENSSL_REPO, "feed": OPENSSL_INDEX_URL},
    "git": {"name": "git-upstream", "repo": GIT_REPO, "feed": OSV_API_URL,
            "package": GIT_PACKAGE, "ecosystem": OSV_GIT_ECOSYSTEM},
    "systemd": {"name": "systemd-upstream", "repo": SYSTEMD_REPO, "feed": OSV_API_URL,
                "package": SYSTEMD_PACKAGE, "ecosystem": OSV_GIT_ECOSYSTEM},
    "sqlite": {"name": "sqlite-upstream", "repo": SQLITE_REPO, "feed": OSV_API_URL,
               "package": SQLITE_PACKAGE, "ecosystem": OSV_GIT_ECOSYSTEM},
    "postgres": {"name": "postgres-upstream", "repo": POSTGRES_REPO, "feed": OSV_API_URL,
                 "package": POSTGRES_PACKAGE, "ecosystem": OSV_GIT_ECOSYSTEM},
}

OPENSSL_ENTRY_RE = re.compile(r'href="(cve-\d{4}-\d+\.json)"')
OPENSSL_CVE_RE = re.compile(r"^\d{4}-\d+$")
# Fix commits published by OpenSSL for the main repository, in either URL form.
OPENSSL_COMMIT_PATTERNS = (
    re.compile(r"https://github\.com/openssl/openssl/commit/([0-9a-f]{40})"),
    re.compile(r"https://git\.openssl\.org/gitweb/\?p=openssl\.git;a=commitdiff;h=([0-9a-f]{40})"),
)
OPENSSL_EXTENDED_RE = re.compile(r"github\.openssl\.org/openssl/extended-releases/commit/")


class FetchError(RuntimeError):
    """A feed could not be fetched or parsed."""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Build a complete advisory catalog (curl, openssl, or an OSV.dev GIT repo) from the source's own feed."
    )
    parser.add_argument("--project", required=True, choices=("curl", "openssl", *OSV_PROJECTS))
    parser.add_argument("--out-dir", required=True, help="Catalog directory (holds source.json).")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Rebuild from the committed snapshot instead of hitting the network.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="With --offline: verify catalog.jsonl and index.json match the snapshot.",
    )
    parser.add_argument(
        "--source",
        help="Snapshot path (default: <out-dir>/source.json).",
    )
    return parser.parse_args(argv)


# --------------------------------------------------------------------------- io


def _http_get(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read(SNAPSHOT_LIMIT_BYTES + 1)
    except urllib.error.URLError as exc:
        raise FetchError(f"{url}: {exc}") from exc
    if len(body) > SNAPSHOT_LIMIT_BYTES:
        raise FetchError(
            f"{url}: snapshot exceeds {SNAPSHOT_LIMIT_BYTES} bytes; stop and report"
        )
    return bytes(body)


def _http_post_json(url, payload_text):
    """POST a JSON body (OSV.dev query) and return the raw response bytes."""
    request = urllib.request.Request(
        url,
        data=payload_text.encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=OSV_HTTP_TIMEOUT) as response:
            body = response.read(SNAPSHOT_LIMIT_BYTES + 1)
    except OSError as exc:
        # URLError and a mid-stream TimeoutError are both OSError subclasses;
        # OSV.dev occasionally resets or stalls on a large repo's records.
        raise FetchError(f"{url}: {exc}") from exc
    if len(body) > SNAPSHOT_LIMIT_BYTES:
        raise FetchError(
            f"{url}: snapshot exceeds {SNAPSHOT_LIMIT_BYTES} bytes; stop and report"
        )
    return bytes(body)


def _dump(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _write_if_changed(path, text):
    """Write only when the content differs, so reruns never touch unchanged files."""
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return
    path.write_text(text, encoding="utf-8")


# ----------------------------------------------------------------- extractors


def _normalize_repo_url(url):
    """Canonical form of a repository URL for comparison (case, .git, trailing /)."""
    if not isinstance(url, str):
        return ""
    value = url.strip().lower().rstrip("/")
    if value.endswith(".git"):
        value = value[: -len(".git")]
    return value


def _standalone_hex40(text, start=0):
    """Return the 40-hex run in ``text`` at/after ``start``, or None.

    A commit id is exactly 40 hex characters, so a run embedded in a longer hex
    run (41 or more characters) is not a commit id.
    """
    for match in HEX40_URL_RE.finditer(text, start):
        begin, end = match.span()
        if begin > 0 and text[begin - 1] in HEX_CHARS:
            continue
        if end < len(text) and text[end] in HEX_CHARS:
            continue
        return match.group(0)
    return None


def _first_sha(url):
    """Return the main-repo 40-hex commit id in ``url``, or None."""
    for pattern in OPENSSL_COMMIT_PATTERNS:
        match = pattern.search(url)
        if not match:
            continue
        # Reject 41+ hex runs: a commit id is exactly 40 hex characters.
        sha = _standalone_hex40(url, match.start(1))
        if sha:
            return sha
    return None


def _commit_sha_in_repo(url, repo_path):
    """Return the 40-hex commit id when ``url`` links a commit inside ``repo_path``.

    ``repo_path`` must be followed by "/" so that, for example,
    github.com/systemd/systemd never matches .../systemd-stable, and a link to
    an issue tracker, a pull request page or a blog post yields None.
    """
    if repo_path + "/" not in url:
        return None
    return _standalone_hex40(url)


def _curl_rows(records):
    """Rows from curl's own vuln.json (OSV format).

    curl documents the GIT ``fixed`` commit of each advisory as the commit that
    fixed it, so for this feed the GIT range events ARE the fix commits and the
    boundary split used for the OSV.dev projects is deliberately not applied.
    Ten of those commits were sampled against the GitHub API (2026-10-09) and
    all ten are real fix commits in their own subsystem, e.g. "http2: fix
    incorrect trailer buffer size" (fa3dbb9a) for CVE-2018-1000005.
    """
    rows = []
    for record in records:
        specific = record.get("database_specific") or {}
        cwe = (specific.get("CWE") or {}).get("id")
        advisory_id = next(
            (a for a in record.get("aliases") or [] if a.startswith("CVE-")),
            record.get("id"),
        )
        shas = []
        for affected in record.get("affected") or []:
            for advisory_range in affected.get("ranges") or []:
                if advisory_range.get("type") != "GIT":
                    continue
                for event in advisory_range.get("events") or []:
                    fixed = event.get("fixed")
                    if fixed and HEX40_RE.match(fixed) and fixed not in shas:
                        shas.append(fixed)
        page = specific.get("www") or specific.get("URL")
        rows.append(
            {
                "advisory_id": advisory_id,
                "published": (record.get("published") or "")[:10],
                "cwe": cwe,
                "cwe_state": "STATED_BY_ADVISORY" if cwe else "UNKNOWN",
                "patch_urls": [page] if page else [],
                "fix_shas": shas,
                "subsystem": None,
                "fix_sha_source": PROJECT_META["curl"]["name"],
            }
        )
    return rows, {}


def _openssl_rows(records):
    rows = []
    excluded_extended = 0
    excluded_short = 0
    extra_cwe = 0
    for record in records:
        cna = (record.get("containers") or {}).get("cna") or {}
        cwes = [
            entry.get("cweId")
            for problem in cna.get("problemTypes") or []
            for entry in problem.get("descriptions") or []
            if entry.get("cweId")
        ]
        if len(cwes) > 1:
            extra_cwe += 1
        shas = []
        urls = []
        for reference in cna.get("references") or []:
            url = reference.get("url") or ""
            tags = reference.get("tags") or []
            if "vendor-advisory" in tags:
                if url and url not in urls:
                    urls.append(url)
            elif "patch" in tags:
                if OPENSSL_EXTENDED_RE.search(url):
                    excluded_extended += 1
                    continue
                sha = _first_sha(url)
                if sha:
                    if sha not in shas:
                        shas.append(sha)
                else:
                    excluded_short += 1
        rows.append(
            {
                "advisory_id": (record.get("cveMetadata") or {}).get("cveId"),
                "published": (cna.get("datePublic") or "")[:10],
                "cwe": cwes[0] if cwes else None,
                "cwe_state": "STATED_BY_ADVISORY" if cwes else "UNKNOWN",
                "patch_urls": sorted(urls),
                "fix_shas": shas,
                "subsystem": None,
                "fix_sha_source": PROJECT_META["openssl"]["name"],
            }
        )
    stats = {
        "excluded_extended": excluded_extended,
        "excluded_short": excluded_short,
        "extra_cwe": extra_cwe,
    }
    return rows, stats


def _osv_advisory_id(record):
    """Prefer a CVE id: the record id when it is a CVE, else the first CVE alias."""
    record_id = record.get("id") or ""
    if CVE_RE.match(record_id):
        return record_id
    for alias in record.get("aliases") or []:
        if CVE_RE.match(alias):
            return alias
    return record_id


def _osv_rows(records, meta):
    """Rows from OSV.dev GIT-ecosystem records (same OSV shape as the curl feed).

    The advisory's own fix references and the version-range boundaries are two
    different facts, so they land in two different columns:

    * ``fix_shas`` only holds commits the advisory identifies as the fix
      (FIX/PATCH references that link a 40-hex commit in this repository).
    * ``fixed_in_shas`` holds the GIT-range boundary commits (``fixed`` /
      ``last_affected`` events) of the ranges naming this repository. They are
      useful to delimit a version range and are never promoted to fix commits.

    References that are not such a commit (issue trackers, blogs, a fork's or a
    stable-branch mirror's commits, a fossil check-in id) and boundary events
    from a range that names another repository are counted in the stats and
    reported in index.json instead of being silently dropped.
    """
    repo = meta["repo"]
    repo_path = repo.split("https://", 1)[-1]  # e.g. github.com/git/git
    rows = []
    excluded_fix_refs = 0
    foreign_boundaries = 0
    for record in records:
        specific = record.get("database_specific") or {}
        cwe_ids = specific.get("cwe_ids") or []
        cwe = cwe_ids[0] if cwe_ids else None
        fix_shas = []
        for reference in record.get("references") or []:
            if reference.get("type") not in OSV_FIX_REFERENCE_TYPES:
                continue
            sha = _commit_sha_in_repo(reference.get("url") or "", repo_path)
            if sha is None:
                excluded_fix_refs += 1
                continue
            if sha not in fix_shas:
                fix_shas.append(sha)
        boundary_shas = []
        for affected in record.get("affected") or []:
            for advisory_range in affected.get("ranges") or []:
                if advisory_range.get("type") != "GIT":
                    continue
                range_repo = advisory_range.get("repo")
                if range_repo is not None and _normalize_repo_url(range_repo) != _normalize_repo_url(repo):
                    # The CVE record also lists another product (a fork, a
                    # stable-branch mirror, an unrelated project). Its range
                    # boundaries say nothing about this project's versions.
                    foreign_boundaries += sum(
                        1
                        for event in advisory_range.get("events") or []
                        for key in OSV_BOUNDARY_EVENT_KEYS
                        if event.get(key) and HEX40_RE.match(event.get(key))
                    )
                    continue
                for event in advisory_range.get("events") or []:
                    for key in OSV_BOUNDARY_EVENT_KEYS:
                        sha = event.get(key)
                        if sha and HEX40_RE.match(sha) and sha not in boundary_shas:
                            boundary_shas.append(sha)
        patch_urls = []
        for reference in record.get("references") or []:
            url = reference.get("url") or ""
            # Only links that live in the project's own repo (GHSA page, commit,
            # blob); otherwise fall back to the canonical CVE record OSV cites.
            if repo_path in url and url not in patch_urls:
                patch_urls.append(url)
        if not patch_urls:
            generated_from = specific.get("osv_generated_from")
            if generated_from:
                patch_urls.append(generated_from)
        rows.append(
            {
                "advisory_id": _osv_advisory_id(record),
                "published": (record.get("published") or "")[:10],
                "cwe": cwe,
                "cwe_state": "STATED_BY_ADVISORY" if cwe else "UNKNOWN",
                "patch_urls": sorted(patch_urls),
                "fix_shas": fix_shas,
                "fixed_in_shas": boundary_shas,
                "subsystem": None,
                "fix_sha_source": meta["name"],
            }
        )
    stats = {
        "excluded_fix_refs": excluded_fix_refs,
        "foreign_boundaries": foreign_boundaries,
    }
    return rows, stats


ROW_BUILDERS = {"curl": _curl_rows, "openssl": _openssl_rows}
ROW_BUILDERS.update(
    {project: (lambda records, _meta=PROJECT_META[project]: _osv_rows(records, _meta))
     for project in OSV_PROJECTS}
)


# --------------------------------------------------------------------- fetching


def fetch_curl_snapshot():
    body = _http_get(CURL_FEED_URL)
    records = json.loads(body.decode("utf-8"))
    if not isinstance(records, list) or not records:
        raise FetchError(f"{CURL_FEED_URL}: expected a non-empty JSON array of advisories")
    # The feed is already one machine-readable file: keep the bytes verbatim.
    return body


def fetch_openssl_snapshot():
    index = _http_get(OPENSSL_INDEX_URL).decode("utf-8")
    names = sorted(set(OPENSSL_ENTRY_RE.findall(index)))
    if not names:
        raise FetchError(f"{OPENSSL_INDEX_URL}: no advisory entries listed")
    records = []
    for name in names:
        if not OPENSSL_CVE_RE.match(name[len("cve-"):-len(".json")]):
            raise FetchError(f"{OPENSSL_INDEX_URL}: unexpected entry name {name!r}")
        body = _http_get(OPENSSL_INDEX_URL + name)
        records.append(json.loads(body.decode("utf-8")))
    records.sort(key=lambda r: (r.get("cveMetadata") or {}).get("cveId") or "")
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "project": "openssl",
        "source_url": OPENSSL_INDEX_URL,
        "records": records,
    }
    body = _dump(snapshot).encode("utf-8")
    if len(body) > SNAPSHOT_LIMIT_BYTES:
        raise FetchError(
            f"aggregated OpenSSL snapshot exceeds {SNAPSHOT_LIMIT_BYTES} bytes; stop and report"
        )
    return body


def fetch_osv_snapshot(project):
    """Query OSV.dev for every GIT-ecosystem advisory scoped to the repo URL."""
    meta = PROJECT_META[project]
    payload = _dump({"package": {"name": meta["package"], "ecosystem": meta["ecosystem"]}})
    body = _http_post_json(OSV_API_URL, payload)
    data = json.loads(body.decode("utf-8"))
    records = data.get("vulns")
    if not isinstance(records, list) or not records:
        raise FetchError(f"{OSV_API_URL}: no advisories for package {meta['package']}")
    # OSV returns records in an unspecified order; sort by id so the snapshot
    # (and therefore the committed catalog) is deterministic.
    records = sorted(records, key=lambda r: r.get("id") or "")
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "project": project,
        "source_url": OSV_API_URL,
        "package": meta["package"],
        "ecosystem": meta["ecosystem"],
        "records": records,
    }
    body = _dump(snapshot).encode("utf-8")
    if len(body) > SNAPSHOT_LIMIT_BYTES:
        raise FetchError(
            f"aggregated OSV snapshot for {project} exceeds {SNAPSHOT_LIMIT_BYTES} bytes; stop and report"
        )
    return body


FETCHERS = {"curl": fetch_curl_snapshot, "openssl": fetch_openssl_snapshot}
FETCHERS.update({project: (lambda _p=project: fetch_osv_snapshot(_p)) for project in OSV_PROJECTS})


def load_snapshot_records(project, snapshot_bytes):
    data = json.loads(snapshot_bytes.decode("utf-8"))
    if project == "curl":
        if not isinstance(data, list) or not data:
            raise FetchError("curl snapshot: expected a non-empty JSON array of advisories")
        return data
    records = (data or {}).get("records")
    if not isinstance(records, list) or not records:
        raise FetchError(f"{project} snapshot: expected a non-empty records list")
    return records


# ---------------------------------------------------------------------- output


def build_catalog(project, snapshot_bytes):
    records = load_snapshot_records(project, snapshot_bytes)
    built = ROW_BUILDERS[project](records)
    rows, stats = built
    rows.sort(key=lambda row: row["advisory_id"])
    catalog_text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    index_text = json.dumps(
        _build_index(project, snapshot_bytes, rows, stats), indent=2, ensure_ascii=False
    ) + "\n"
    return catalog_text, index_text, rows


def _build_index(project, snapshot_bytes, rows, stats):
    if project in OSV_PROJECTS:
        return _build_osv_index(project, snapshot_bytes, rows, stats)
    meta = PROJECT_META[project]
    fetcher_note = (
        "the newest timestamp present in the snapshot (curl: max 'modified'; "
        "openssl: max 'datePublic'), never the wall clock"
    )
    notes = [
        (
            f"Complete snapshot of the {meta['name']} advisory feed; "
            f"{sum(1 for r in rows if r['fix_shas'])} of {len(rows)} advisories publish a "
            "40-hex fix commit."
        ),
        f"fetched_at is {fetcher_note}, so reruns are byte-identical.",
        "Descriptions were not copied (docs/DATA-POLICY.md).",
    ]
    if project == "curl":
        notes.append(
            "advisory_id is the CVE alias of each OSV record; rows with an empty fix_shas "
            "have no GIT range in the feed."
        )
    else:
        notes.append(
            f"{stats['excluded_extended']} patch reference(s) point at "
            "openssl/extended-releases, which has no public GitHub mirror, and "
            f"{stats['excluded_short']} publish a short (non-40-hex) commit id; both are "
            "excluded from fix_shas and reported here instead of in errors."
        )
        if stats["extra_cwe"]:
            notes.append(
                f"{stats['extra_cwe']} advisory(ies) declare a second CWE; the single-value "
                "column keeps the first in feed order."
            )
    return {
        "schema_version": "cve-history-v1",
        "project": meta["name"],
        "repo": meta["repo"],
        "source_url": meta["feed"],
        "source_snapshot": "source.json",
        "source_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        "source_bytes": len(snapshot_bytes),
        "fetched_at": _newest_timestamp(project, snapshot_bytes),
        "coverage": "COMPLETE_AT_SNAPSHOT",
        "status": "FETCHED",
        "entry_count": len(rows),
        "with_fix_sha": sum(1 for r in rows if r["fix_shas"]),
        "with_cwe": sum(1 for r in rows if r["cwe"]),
        "errors": [],
        "notes": " ".join(notes),
    }


def _newest_timestamp(project, snapshot_bytes):
    records = load_snapshot_records(project, snapshot_bytes)
    if project == "curl" or project in OSV_PROJECTS:
        return max((r.get("modified") or "" for r in records), default="")
    return max(
        (((r.get("containers") or {}).get("cna") or {}).get("datePublic") or "" for r in records),
        default="",
    )


def _build_osv_index(project, snapshot_bytes, rows, stats):
    meta = PROJECT_META[project]
    with_fix_sha = sum(1 for r in rows if r["fix_shas"])
    with_fixed_in = sum(1 for r in rows if r["fixed_in_shas"])
    notes = " ".join(
        [
            f"Complete snapshot from the OSV.dev advisory API ({OSV_API_URL}, ecosystem "
            f"{meta['ecosystem']}, package {meta['package']}) for {meta['repo']}; "
            f"{with_fix_sha} of {len(rows)} advisories name a 40-hex fix commit in "
            f"the repository and {with_fixed_in} publish a GIT range boundary.",
            "fetched_at is the newest record 'modified' timestamp in the snapshot, never "
            "the wall clock, so reruns are byte-identical.",
            "Descriptions were not copied (docs/DATA-POLICY.md).",
            "advisory_id is the CVE (record id or first CVE alias); cwe is the first of "
            "database_specific.cwe_ids.",
            f"fix_shas are only the commits the advisory itself identifies as the fix: "
            f"references typed FIX or PATCH whose URL is a 40-hex commit in {meta['repo']}. "
            f"{stats['excluded_fix_refs']} such reference(s) point somewhere else (an issue "
            "tracker, a blog, a fork or a stable-branch mirror, a fossil check-in id) and "
            "contribute no fix sha.",
            f"fixed_in_shas are the GIT range boundary commits ('fixed' / 'last_affected' "
            f"events) of the ranges that name {meta['repo']}. They delimit the affected "
            "version range and are never fix commits: OSV derives them from the range, so "
            f"they are usually a merge, a release stamp or a version bump. "
            f"{stats['foreign_boundaries']} boundary event(s) belong to a range that names "
            "another repository the CVE record also lists and are excluded.",
        ]
    )
    return {
        "schema_version": "cve-history-v1",
        "project": meta["name"],
        "repo": meta["repo"],
        "source_url": OSV_API_URL,
        "source_snapshot": "source.json",
        "source_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        "source_bytes": len(snapshot_bytes),
        "fetched_at": _newest_timestamp(project, snapshot_bytes),
        "coverage": "COMPLETE_AT_SNAPSHOT",
        "status": "FETCHED",
        "entry_count": len(rows),
        "with_fix_sha": with_fix_sha,
        "with_fixed_in": with_fixed_in,
        "with_cwe": sum(1 for r in rows if r["cwe"]),
        "errors": [],
        "notes": notes,
    }


def main(argv=None):
    args = parse_args(argv)
    out_dir = Path(args.out_dir)
    snapshot_path = Path(args.source) if args.source else out_dir / "source.json"

    if args.offline:
        if not snapshot_path.exists():
            print(f"Error: snapshot {snapshot_path} not found", file=sys.stderr)
            return 1
        snapshot_bytes = snapshot_path.read_bytes()
    else:
        try:
            snapshot_bytes = FETCHERS[args.project]()
        except (FetchError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        out_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_bytes(snapshot_bytes)

    try:
        catalog_text, index_text, rows = build_catalog(args.project, snapshot_bytes)
    except (ValueError, FetchError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    catalog_path = out_dir / "catalog.jsonl"
    index_path = out_dir / "index.json"

    if args.check:
        problems = []
        if not catalog_path.exists():
            problems.append(f"{catalog_path} missing")
        elif catalog_path.read_text(encoding="utf-8") != catalog_text:
            problems.append(f"{catalog_path} does not match snapshot")
        if not index_path.exists():
            problems.append(f"{index_path} missing")
        elif index_path.read_text(encoding="utf-8") != index_text:
            problems.append(f"{index_path} does not match snapshot")
        if problems:
            for problem in problems:
                print(f"Error: {problem}", file=sys.stderr)
            return 1
        print(
            f"OK {args.project}: {len(rows)} entries, "
            f"{sum(1 for r in rows if r['fix_shas'])} with fix sha, "
            f"{sum(1 for r in rows if r.get('fixed_in_shas'))} with fixed_in, "
            f"{sum(1 for r in rows if r['cwe'])} with cwe (offline --check)"
        )
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_if_changed(catalog_path, catalog_text)
    _write_if_changed(index_path, index_text)
    print(
        f"Wrote {args.project}: {len(rows)} entries, "
        f"{sum(1 for r in rows if r['fix_shas'])} with fix sha, "
        f"{sum(1 for r in rows if r.get('fixed_in_shas'))} with fixed_in, "
        f"{sum(1 for r in rows if r['cwe'])} with cwe, "
        f"snapshot {len(snapshot_bytes)} bytes -> {snapshot_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
