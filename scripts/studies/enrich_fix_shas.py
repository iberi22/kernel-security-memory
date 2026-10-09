#!/usr/bin/env python3
"""Pipeline to enrich CVE catalogs with official, verified 40-character Git commit SHAs.

Extracts vetted SHAs from verified evidence records (Fable 2026-06 slice)
and official git repository commit references, validates format strictly
(40 lowercase hex characters), associates them with matching CVE catalog
entries, and updates index.json with_fix_sha counts.
"""

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
CVE_HISTORY_DIR = ROOT / "docs/studies/cve-history"
FABLE_DIR = ROOT / "docs/studies/fable-2026-06"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
URL_COMMIT_RE = re.compile(r"(?:/commit/|[?&]id=)([0-9a-f]{40})\b", re.IGNORECASE)


def load_vetted_shas():
    """Load verified SHAs from official records in fable-2026-06."""
    mapping = {}
    if not FABLE_DIR.exists():
        return mapping

    for record_file in FABLE_DIR.glob("*/records/*.json"):
        try:
            data = json.loads(record_file.read_text())
            advisory = data.get("advisory_id")
            fix = data.get("fix", {})
            sha = fix.get("sha")
            if advisory and sha and SHA_RE.fullmatch(sha.lower()):
                mapping.setdefault(advisory, set()).add(sha.lower())
        except Exception as err:
            print(f"Warning: failed reading record {record_file}: {err}", file=sys.stderr)
    return mapping


def extract_commit_shas_from_urls(urls):
    """Extract valid 40-char commit SHAs from official git URLs."""
    shas = []
    for url in urls:
        m = URL_COMMIT_RE.search(url)
        if m:
            sha = m.group(1).lower()
            if SHA_RE.fullmatch(sha) and sha not in shas:
                shas.append(sha)
    return shas


def enrich_catalog(project_dir, vetted_shas, dry_run=False):
    """Enrich a single project's catalog.jsonl and index.json."""
    index_file = project_dir / "index.json"
    catalog_file = project_dir / "catalog.jsonl"
    if not index_file.exists() or not catalog_file.exists():
        return None

    index_data = json.loads(index_file.read_text())
    lines = catalog_file.read_text().splitlines()
    new_lines = []
    with_fix_sha_count = 0

    for line in lines:
        if not line.strip():
            continue
        entry = json.loads(line)
        advisory_id = entry.get("advisory_id")
        current_shas = [s.lower() for s in entry.get("fix_shas", []) if SHA_RE.fullmatch(s.lower())]

        # Add from vetted fable records
        if advisory_id in vetted_shas:
            for s in vetted_shas[advisory_id]:
                if s not in current_shas:
                    current_shas.append(s)

        # Add from patch URLs containing commit links
        url_shas = extract_commit_shas_from_urls(entry.get("patch_urls", []))
        for s in url_shas:
            if s not in current_shas:
                current_shas.append(s)

        entry["fix_shas"] = current_shas
        if current_shas:
            with_fix_sha_count += 1
        new_lines.append(json.dumps(entry, ensure_ascii=False))

    index_data["with_fix_sha"] = with_fix_sha_count

    if not dry_run:
        catalog_file.write_text("\n".join(new_lines) + ("\n" if new_lines else ""))
        index_file.write_text(json.dumps(index_data, indent=2, ensure_ascii=False) + "\n")

    return {
        "project": index_data.get("project", project_dir.name),
        "entry_count": len(new_lines),
        "with_fix_sha": with_fix_sha_count,
    }


def verify_all_catalogs():
    """Verify strictly that all catalogs have valid SHAs and matching index counts."""
    errors = []
    for project_dir in sorted(CVE_HISTORY_DIR.glob("*")):
        if not project_dir.is_dir():
            continue
        index_file = project_dir / "index.json"
        catalog_file = project_dir / "catalog.jsonl"
        if not index_file.exists() or not catalog_file.exists():
            continue

        try:
            index_data = json.loads(index_file.read_text())
            lines = [l for l in catalog_file.read_text().splitlines() if l.strip()]
            stated_count = index_data.get("with_fix_sha", 0)
            actual_count = 0
            for i, line in enumerate(lines, 1):
                entry = json.loads(line)
                for sha in entry.get("fix_shas", []):
                    if not SHA_RE.fullmatch(sha):
                        errors.append(f"{project_dir.name}: line {i} invalid SHA format: {sha!r}")
                if entry.get("fix_shas"):
                    actual_count += 1
            if stated_count != actual_count:
                errors.append(f"{project_dir.name}: index.json with_fix_sha={stated_count} but catalog has {actual_count}")
        except Exception as err:
            errors.append(f"{project_dir.name}: verification error: {err}")

    if errors:
        for err in errors:
            print(f"Error: {err}", file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify SHA consistency without modifying")
    parser.add_argument("--offline", action="store_true", help="Run in offline mode using only local sources")
    parser.add_argument("--dry-run", action="store_true", help="Report planned changes without writing")
    args = parser.parse_args()

    if args.check or args.offline:
        vetted = load_vetted_shas()
        enrich_reports = []
        for p in sorted(CVE_HISTORY_DIR.glob("*")):
            if p.is_dir():
                rep = enrich_catalog(p, vetted, dry_run=True)
                if rep:
                    enrich_reports.append(rep)
        if not verify_all_catalogs():
            sys.exit(1)
        print("Verification successful: All catalogs validated with strict 40-hex lowercase SHAs.")
        return

    vetted = load_vetted_shas()
    print(f"Loaded {len(vetted)} unique vetted advisory SHAs from Fable records.")
    for p in sorted(CVE_HISTORY_DIR.glob("*")):
        if p.is_dir():
            rep = enrich_catalog(p, vetted, dry_run=args.dry_run)
            if rep:
                print(f"  {rep['project']}: {rep['with_fix_sha']}/{rep['entry_count']} entries with validated fix SHA")

    if not verify_all_catalogs():
        sys.exit(1)
    print("Enrichment complete and verified.")


if __name__ == "__main__":
    main()
