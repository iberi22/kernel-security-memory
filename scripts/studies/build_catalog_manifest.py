#!/usr/bin/env python3
"""Build and verify unified manifest for all CVE history catalogs.

Aggregates project metadata, record counts, SHA coverage, and cryptographic
hashes across all canonical open-source project catalogs in docs/studies/cve-history/.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
CVE_HISTORY_DIR = ROOT / "docs/studies/cve-history"
MANIFEST_FILE = CVE_HISTORY_DIR / "manifest.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


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

        index_data = json.loads(index_path.read_text())
        entries = len([l for l in catalog_path.read_text().splitlines() if l.strip()])
        with_sha = index_data.get("with_fix_sha", 0)
        reqs = index_data.get("requests", 0)

        total_entries += entries
        total_with_fix_sha += with_sha
        total_requests += reqs

        projects.append({
            "name": index_data.get("project", project_dir.name),
            "repo": index_data.get("repo"),
            "keyword": index_data.get("keyword"),
            "coverage": index_data.get("coverage"),
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
                    "bytes": catalog_path.stat().st_size,
                },
            },
        })

    manifest = {
        "schema_version": "cve-catalog-manifest-v1",
        "description": "Unified manifest of canonical CVE patch catalogs",
        "project_count": len(projects),
        "total_entries": total_entries,
        "total_with_fix_sha": total_with_fix_sha,
        "total_requests": total_requests,
        "projects": projects,
    }
    return manifest


def verify_manifest() -> bool:
    if not MANIFEST_FILE.exists():
        print("Error: manifest.json does not exist", file=sys.stderr)
        return False

    current = json.loads(MANIFEST_FILE.read_text())
    expected = generate_manifest()

    if current["schema_version"] != expected["schema_version"]:
        print("Error: schema_version mismatch", file=sys.stderr)
        return False
    if current["project_count"] != expected["project_count"]:
        print(f"Error: project_count mismatch: {current['project_count']} != {expected['project_count']}", file=sys.stderr)
        return False
    if current["total_entries"] != expected["total_entries"]:
        print(f"Error: total_entries mismatch: {current['total_entries']} != {expected['total_entries']}", file=sys.stderr)
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
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"Generated {MANIFEST_FILE}: {manifest['project_count']} projects, {manifest['total_entries']} entries.")


if __name__ == "__main__":
    main()
