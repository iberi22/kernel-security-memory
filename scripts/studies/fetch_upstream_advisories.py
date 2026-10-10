#!/usr/bin/env python3
"""Fetch authoritative upstream advisory catalogs for curl and OpenSSL.

Both catalogs are built from the projects' OWN machine-readable advisory feeds,
deterministically and with no LLM:

  curl    https://curl.se/docs/vuln.json                       (OSV-format array)
  openssl https://openssl-library.org/news/secjson/            (CVE 5.x records)

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
HEX_CHARS = "0123456789abcdef"

CURL_FEED_URL = "https://curl.se/docs/vuln.json"
CURL_REPO = "https://github.com/curl/curl"
OPENSSL_INDEX_URL = "https://openssl-library.org/news/secjson/"
OPENSSL_REPO = "https://github.com/openssl/openssl"

# The catalog directory name is the project name, so an upstream catalog never
# collides with the NVD-derived catalog of the same project in one manifest.
PROJECT_META = {
    "curl": {"name": "curl-upstream", "repo": CURL_REPO, "feed": CURL_FEED_URL},
    "openssl": {"name": "openssl-upstream", "repo": OPENSSL_REPO, "feed": OPENSSL_INDEX_URL},
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
        description="Build a complete curl/OpenSSL advisory catalog from the project's own feed."
    )
    parser.add_argument("--project", required=True, choices=("curl", "openssl"))
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


def _dump(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _write_if_changed(path, text):
    """Write only when the content differs, so reruns never touch unchanged files."""
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return
    path.write_text(text, encoding="utf-8")


# ----------------------------------------------------------------- extractors


def _first_sha(url):
    """Return the main-repo 40-hex commit id in ``url``, or None."""
    for pattern in OPENSSL_COMMIT_PATTERNS:
        match = pattern.search(url)
        if not match:
            continue
        # Reject 41+ hex runs: a commit id is exactly 40 hex characters.
        if match.end(1) < len(url) and url[match.end(1)] in HEX_CHARS:
            continue
        return match.group(1)
    return None


def _curl_rows(records):
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


ROW_BUILDERS = {"curl": _curl_rows, "openssl": _openssl_rows}


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


FETCHERS = {"curl": fetch_curl_snapshot, "openssl": fetch_openssl_snapshot}


def load_snapshot_records(project, snapshot_bytes):
    data = json.loads(snapshot_bytes.decode("utf-8"))
    if project == "curl":
        if not isinstance(data, list) or not data:
            raise FetchError("curl snapshot: expected a non-empty JSON array of advisories")
        return data
    records = (data or {}).get("records")
    if not isinstance(records, list) or not records:
        raise FetchError("openssl snapshot: expected a non-empty {'records': [...]}")
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
    if project == "curl":
        return max((r.get("modified") or "" for r in records), default="")
    return max(
        (((r.get("containers") or {}).get("cna") or {}).get("datePublic") or "" for r in records),
        default="",
    )


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
            f"{sum(1 for r in rows if r['cwe'])} with cwe (offline --check)"
        )
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_if_changed(catalog_path, catalog_text)
    _write_if_changed(index_path, index_text)
    print(
        f"Wrote {args.project}: {len(rows)} entries, "
        f"{sum(1 for r in rows if r['fix_shas'])} with fix sha, "
        f"{sum(1 for r in rows if r['cwe'])} with cwe, "
        f"snapshot {len(snapshot_bytes)} bytes -> {snapshot_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
