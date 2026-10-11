#!/usr/bin/env python3
"""Fetch and process OSV crates.io bulk export for RustSec catalog."""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
import zipfile

OSV_CRATES_IO_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"

HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
GITHUB_FIX_COMMIT_RE = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)/commit/([0-9a-fA-F]{40})(?:/|\.patch|\.diff)?$"
)


def _extract_package(record):
    pkg = record.get("package")
    if isinstance(pkg, str):
        return pkg
    if isinstance(pkg, dict) and pkg.get("name"):
        return pkg["name"]
    for aff in record.get("affected") or []:
        p = aff.get("package")
        if isinstance(p, dict) and p.get("name"):
            return p["name"]
        if isinstance(p, str):
            return p
    return None


def _extract_cwe(record):
    db_spec = record.get("database_specific") or {}
    cwe_ids = db_spec.get("cwe_ids") or []
    if cwe_ids and isinstance(cwe_ids, list):
        return cwe_ids[0]
    if "CWE" in db_spec:
        cwe_obj = db_spec["CWE"]
        if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
            return cwe_obj["id"]
        if isinstance(cwe_obj, str):
            return cwe_obj
    if "cwe" in record:
        cwe_val = record["cwe"]
        if isinstance(cwe_val, list) and cwe_val:
            return cwe_val[0]
        if isinstance(cwe_val, str):
            return cwe_val
    return None


def parse_records_from_zip(zip_bytes):
    records = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name).decode("utf-8"))
                records.append(data)
            except Exception:
                continue
    return records


def build_catalog_and_index(zip_bytes, records):
    rows = []
    for record in records:
        adv_id = record.get("id")
        if not adv_id:
            continue
        aliases = sorted(set(record.get("aliases") or []))
        package = _extract_package(record)
        published = (record.get("published") or "")[:10] or None
        cwe = _extract_cwe(record)
        cwe_state = "STATED_BY_ADVISORY" if cwe else "UNKNOWN"

        patch_urls = []
        fix_shas = []
        first_repo = None
        # RustSec never types a link as FIX; commit links come as WEB. They are
        # kept apart as reference commits: candidates, not verified fixes.
        reference_commit_shas = []
        reference_repo = None

        for ref in record.get("references") or []:
            ref_type = ref.get("type") or ""
            url = ref.get("url") or ""
            if not url:
                continue
            # patch_urls: references of type FIX/WEB that point to commits/PRs
            if ref_type in ("FIX", "WEB"):
                if ("/commit/" in url or "/pull/" in url) and url not in patch_urls:
                    patch_urls.append(url)
            # fix_shas: ONLY from references of type FIX whose URL is https://github.com/<owner>/<repo>/commit/<40-hex>
            if ref_type == "FIX":
                m = GITHUB_FIX_COMMIT_RE.match(url)
                if m:
                    repo_cand = m.group(1)
                    sha = m.group(2)
                    if sha not in fix_shas:
                        fix_shas.append(sha)
                    if first_repo is None:
                        first_repo = repo_cand
            elif ref_type == "WEB":
                m = GITHUB_FIX_COMMIT_RE.match(url)
                if m and m.group(2).lower() not in reference_commit_shas:
                    reference_commit_shas.append(m.group(2).lower())
                    if reference_repo is None:
                        reference_repo = m.group(1)

        repo = first_repo if fix_shas else (reference_repo if reference_commit_shas else None)

        row = {
            "advisory_id": adv_id,
            "aliases": aliases,
            "cwe": cwe,
            "cwe_state": cwe_state,
            "fix_sha_source": "rustsec",
            "fix_shas": fix_shas,
            "package": package,
            "patch_urls": patch_urls,
            "published": published,
            "reference_commit_shas": reference_commit_shas,
            "repo": repo,
            "subsystem": None,
        }
        rows.append(row)

    rows.sort(key=lambda r: r["advisory_id"])

    newest_modified = max((r.get("modified") or "" for r in records), default="")
    fetched_at = newest_modified if newest_modified else datetime.now(timezone.utc).isoformat()

    with_fix = sum(1 for r in rows if r["fix_shas"])
    with_cwe = sum(1 for r in rows if r["cwe"])

    notes = (
        f"Complete snapshot from the OSV crates.io bulk export ({OSV_CRATES_IO_ZIP_URL}); "
        f"{with_fix} of {len(rows)} advisories name a 40-hex fix commit (FIX reference) in a GitHub repository; "
        f"{sum(1 for r in rows if r['reference_commit_shas'])} link a GitHub commit as a WEB reference "
        "(reference_commit_shas: fix candidates, not verified fixes). "
        f"fetched_at is the newest record 'modified' timestamp in the snapshot, never the wall clock, "
        f"so reruns are byte-identical. Descriptions were not copied (docs/DATA-POLICY.md)."
    )

    index_data = {
        "coverage": "COMPLETE_AT_SNAPSHOT",
        "entry_count": len(rows),
        "errors": [],
        "fetched_at": fetched_at,
        "notes": notes,
        "project": "rustsec",
        "repo": None,
        "schema_version": "cve-history-v1",
        "source_bytes": len(zip_bytes),
        "source_sha256": hashlib.sha256(zip_bytes).hexdigest(),
        "source_snapshot": "all.zip",
        "source_url": OSV_CRATES_IO_ZIP_URL,
        "status": "SNAPSHOT_COMPLETE",
        "with_cwe": with_cwe,
        "with_fix_sha": with_fix,
    }

    catalog_lines = [json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows]
    catalog_text = "".join(catalog_lines)
    index_text = json.dumps(index_data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return catalog_text, index_text, rows


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=None, help="Directory for catalog.jsonl and index.json")
    parser.add_argument("--cache", default=None, help="Path to cached all.zip")
    parser.add_argument("--offline", action="store_true", help="Rebuild from cache without network fetch")
    parser.add_argument("--check", action="store_true", help="Verify generated files match disk")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[2]
    out_dir = Path(args.out_dir) if args.out_dir else repo_root / "docs" / "studies" / "cve-history" / "rustsec"
    cache_path = Path(args.cache) if args.cache else out_dir / ".cache" / "all.zip"

    if args.offline:
        if not cache_path.is_file():
            print(f"Error: cache {cache_path} not found", file=sys.stderr)
            return 1
        zip_bytes = cache_path.read_bytes()
    else:
        try:
            req = urllib.request.Request(OSV_CRATES_IO_ZIP_URL, headers={"User-Agent": "ksm-rustsec"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                zip_bytes = resp.read()
        except Exception as exc:
            print(f"Error fetching {OSV_CRATES_IO_ZIP_URL}: {exc}", file=sys.stderr)
            return 1
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(zip_bytes)

    records = parse_records_from_zip(zip_bytes)
    catalog_text, index_text, rows = build_catalog_and_index(zip_bytes, records)

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
            f"OK rustsec: {len(rows)} entries, "
            f"{sum(1 for r in rows if r['fix_shas'])} with fix sha, "
            f"{sum(1 for r in rows if r['cwe'])} with cwe (offline --check)"
        )
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    catalog_path.write_text(catalog_text, encoding="utf-8")
    index_path.write_text(index_text, encoding="utf-8")
    print(
        f"Wrote rustsec: {len(rows)} entries, "
        f"{sum(1 for r in rows if r['fix_shas'])} with fix sha, "
        f"{sum(1 for r in rows if r['cwe'])} with cwe, "
        f"snapshot {len(zip_bytes)} bytes -> {cache_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
