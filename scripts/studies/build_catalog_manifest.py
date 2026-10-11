#!/usr/bin/env python3
"""Build and verify unified manifest for all CVE history catalogs.

Aggregates project metadata, record counts, SHA coverage, honest fetch statuses,
cursor positions, and cryptographic hashes across all canonical open-source
project catalogs in docs/studies/cve-history/.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
CVE_HISTORY_DIR = ROOT / "docs/studies/cve-history"
MANIFEST_FILE = CVE_HISTORY_DIR / "manifest.json"

# Explicit index.json statuses that claim a manifest status of their own. Any other
# value (e.g. the snapshot catalogs' "FETCHED") carries no manifest status, so the
# evidence-derived status stands.
EXPLICIT_STATUSES = ("NOT_FETCHED", "OBSERVED_EMPTY", "CURSOR_PAUSED", "COMPLETE")


class CatalogStatusError(ValueError):
    """An index.json status contradicts the evidence recorded next to it."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _derive_status(index_data: dict, entries: int) -> tuple[str, str | None, bool]:
    """Derive status, cursor date and window_closed from the recorded evidence only."""
    coverage = index_data.get("coverage", "INCOMPLETE")
    if str(coverage).startswith("COMPLETE_AT_"):
        return "SNAPSHOT_COMPLETE", None, True

    if coverage == "COMPLETE":
        if entries == 0:
            return "OBSERVED_EMPTY", None, True
        return "COMPLETE", None, True

    # Coverage is INCOMPLETE:
    cursor_date = None
    resume = index_data.get("resume")
    if resume and isinstance(resume, dict):
        cursor_date = resume.get("next_start_date")
    if not cursor_date and index_data.get("cursor_date"):
        cursor_date = index_data.get("cursor_date")

    window = index_data.get("window", {})
    start_date = window.get("start", "1999-01-01")
    requests = index_data.get("requests", 0)

    cursor_has_moved = bool(cursor_date and cursor_date != start_date and requests > 0)
    if (entries > 0 or cursor_has_moved) and cursor_date:
        return "CURSOR_PAUSED", cursor_date, False

    return "NOT_FETCHED", None, False


def determine_status(index_data: dict, entries: int, catalog_bytes: int) -> tuple[str, str | None, bool]:
    """Determine honest catalog status and cursor tracking.

    The status is derived from the evidence (coverage, entries, cursor, requests).
    An explicit ``status`` in index.json is accepted only when it agrees with that
    derivation; a disagreement raises :class:`CatalogStatusError` instead of letting
    the index override the evidence.

    Returns:
        (status, cursor_date, window_closed)
        where status is one of:
          - "NOT_FETCHED": scaffold not downloaded (0 entries, 0 bytes, no cursor progress)
          - "OBSERVED_EMPTY": window fully queried yielding genuinely 0 entries (COMPLETE coverage)
          - "CURSOR_PAUSED": partial fetch paused at cursor date; window remains OPEN (not closed)
          - "COMPLETE": window fully queried with entries > 0
          - "SNAPSHOT_COMPLETE": catalog built from a complete upstream snapshot
            (coverage COMPLETE_AT_COMMIT / COMPLETE_AT_SNAPSHOT)
    """
    status, cursor_date, window_closed = _derive_status(index_data, entries)

    explicit_status = index_data.get("status")
    if explicit_status in EXPLICIT_STATUSES and explicit_status != status:
        raise CatalogStatusError(
            f"index status {explicit_status!r} contradicts the evidence "
            f"(coverage={index_data.get('coverage')!r}, entries={entries}, "
            f"requests={index_data.get('requests', 0)}), which derives {status!r}"
        )

    return status, cursor_date, window_closed


def generate_manifest() -> dict:
    projects = []
    total_entries = 0
    total_with_fix_sha = 0
    total_requests = 0

    for project_dir in sorted(CVE_HISTORY_DIR.glob("*")):
        if not project_dir.is_dir() or project_dir.name.startswith("."):
            continue
        index_path = project_dir / "index.json"
        catalog_path = project_dir / "catalog.jsonl"
        if not index_path.exists() or not catalog_path.exists():
            continue

        index_data = json.loads(index_path.read_text(encoding="utf-8"))
        catalog_bytes = catalog_path.stat().st_size
        entries = len([line for line in catalog_path.read_text(encoding="utf-8").splitlines() if line.strip()])
        with_sha = index_data.get("with_fix_sha", 0)
        reqs = index_data.get("requests", 0)

        status, cursor_date, window_closed = determine_status(index_data, entries, catalog_bytes)

        total_entries += entries
        total_with_fix_sha += with_sha
        total_requests += reqs

        project_entry = {
            "name": index_data.get("project", project_dir.name),
            "repo": index_data.get("repo"),
            "keyword": index_data.get("keyword"),
            "coverage": index_data.get("coverage"),
            "status": status,
            "cursor_date": cursor_date,
            "window_closed": window_closed,
            "entry_count": entries,
            "with_fix_sha": with_sha,
            "requests": reqs,
            "files": {
                "index_json": {
                    "path": f"{project_dir.name}/index.json",
                    "sha256": sha256_file(index_path),
                    "bytes": index_path.stat().st_size,
                },
                "catalog_jsonl": {
                    "path": f"{project_dir.name}/catalog.jsonl",
                    "sha256": sha256_file(catalog_path),
                    "bytes": catalog_bytes,
                },
            },
        }
        projects.append(project_entry)

    manifest = {
        "schema_version": "cve-catalog-manifest-v1",
        "description": "Unified manifest of canonical CVE patch catalogs",
        "project_count": len(projects),
        "total_entries": total_entries,
        "total_with_fix_sha": total_with_fix_sha,
        "total_requests": total_requests,
        "status_summary": {
            "CURSOR_PAUSED": sum(1 for p in projects if p["status"] == "CURSOR_PAUSED"),
            "NOT_FETCHED": sum(1 for p in projects if p["status"] == "NOT_FETCHED"),
            "OBSERVED_EMPTY": sum(1 for p in projects if p["status"] == "OBSERVED_EMPTY"),
            "COMPLETE": sum(1 for p in projects if p["status"] == "COMPLETE"),
            "SNAPSHOT_COMPLETE": sum(1 for p in projects if p["status"] == "SNAPSHOT_COMPLETE"),
        },
        "projects": projects,
    }
    return manifest


def verify_manifest() -> bool:
    if not MANIFEST_FILE.exists():
        print("Error: manifest.json does not exist", file=sys.stderr)
        return False

    current = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    try:
        expected = generate_manifest()
    except CatalogStatusError as err:
        print(f"Error: {err}", file=sys.stderr)
        return False

    if current["schema_version"] != expected["schema_version"]:
        print("Error: schema_version mismatch", file=sys.stderr)
        return False
    if current["project_count"] != expected["project_count"]:
        print(f"Error: project_count mismatch: {current['project_count']} != {expected['project_count']}", file=sys.stderr)
        return False
    if current["total_entries"] != expected["total_entries"]:
        print(f"Error: total_entries mismatch: {current['total_entries']} != {expected['total_entries']}", file=sys.stderr)
        return False

    if current.get("total_with_fix_sha") != expected["total_with_fix_sha"]:
        print(f"Error: total_with_fix_sha mismatch: {current.get('total_with_fix_sha')} != {expected['total_with_fix_sha']}", file=sys.stderr)
        return False

    # Check status integrity
    for p in expected["projects"]:
        matching = [cp for cp in current.get("projects", []) if cp.get("name") == p["name"]]
        if not matching:
            print(f"Error: project {p['name']} missing from manifest.json", file=sys.stderr)
            return False
        curr_p = matching[0]
        if curr_p.get("status") != p["status"]:
            print(f"Error: status mismatch for {p['name']}: {curr_p.get('status')} != {p['status']}", file=sys.stderr)
            return False
        if curr_p.get("files") != p["files"]:
            print(f"Error: file hashes changed for {p['name']}; regenerate manifest.json", file=sys.stderr)
            return False
        if curr_p.get("cursor_date") != p["cursor_date"]:
            print(f"Error: cursor_date mismatch for {p['name']}: {curr_p.get('cursor_date')} != {p['cursor_date']}", file=sys.stderr)
            return False

    print(f"Verification successful: {current['project_count']} projects, {current['total_entries']} total CVE entries validated.")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify existing manifest against disk state")
    parser.add_argument("--offline", action="store_true", help="Run offline validation")
    args = parser.parse_args()

    if args.check or args.offline:
        if not verify_manifest():
            sys.exit(1)
        return

    manifest = generate_manifest()
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Generated {MANIFEST_FILE}: {manifest['project_count']} projects, {manifest['total_entries']} entries.")


if __name__ == "__main__":
    main()
