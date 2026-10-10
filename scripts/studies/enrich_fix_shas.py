#!/usr/bin/env python3
"""Pipeline to enrich CVE catalogs with official, verified 40-character Git commit SHAs.

Extracts vetted SHAs from verified evidence records (Fable 2026-06 slice)
and official git repository commit references, validates format strictly
(40 lowercase hex characters), associates them with matching CVE catalog
entries, checks against local git mirrors when configured, and updates
index.json with_fix_sha counts.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CVE_HISTORY_DIR = ROOT / "docs/studies/cve-history"
FABLE_DIR = ROOT / "docs/studies/fable-2026-06"
VETTED_SHAS_SIDECAR = ROOT / "docs/studies/vetted-shas.jsonl"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
URL_COMMIT_RE = re.compile(r"(?:/commit/|[?&]id=)([0-9a-f]{40})\b", re.IGNORECASE)
# Catalog lines must stay within the byte budget that
# BaseHistoryFetcher.validate_offline enforces (BaseHistoryFetcher.max_line_bytes).
MAX_LINE_BYTES = 500
GIT_TIMEOUT_SECONDS = 30


def git_env() -> dict:
    """Child environment for git, with inherited GIT_* variables removed.

    GIT_OBJECT_DIRECTORY and GIT_ALTERNATE_OBJECT_DIRECTORIES silently redirect
    object lookups to another repository, so an inherited value can make a foreign
    object look present (reproduced 2026-10-09 with two throwaway repositories).
    """
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def resolve_git_dir(base_git_dir, project_name=None):
    """Resolve git directory for a specific project or single repo."""
    if not base_git_dir:
        return None
    p = Path(base_git_dir).resolve()
    if not p.exists():
        return None
    if project_name:
        for candidate in [p / project_name, p / f"{project_name}.git", p / f"{project_name}/.git"]:
            if candidate.exists() and ((candidate / "objects").is_dir() or (candidate / ".git").is_dir()):
                return candidate / ".git" if (candidate / ".git").is_dir() else candidate
    if (p / ".git").is_dir():
        return p / ".git"
    return p


def check_sha_in_mirror(git_dir, sha: str) -> bool:
    """Check if 40-hex commit SHA exists in the local git repository as a commit."""
    if not git_dir:
        return False
    git_dir_path = resolve_git_dir(git_dir)
    if not git_dir_path or not git_dir_path.exists():
        return False
    try:
        res = subprocess.run(
            ["git", "--git-dir", str(git_dir_path), "cat-file", "-e", f"{sha}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
            env=git_env(),
        )
        # Only the commit-specific lookup counts: `cat-file -e <sha>` also succeeds
        # for a blob or tree sharing that hash.
        return res.returncode == 0
    except Exception:
        return False


def extract_vetted_shas_records(fable_dir=FABLE_DIR, root=ROOT):
    """Extract clean unique vetted SHAs from Fable records."""
    records = []
    if not fable_dir.exists():
        return records

    for rf in sorted(fable_dir.glob("*/records/*.json")):
        try:
            data = json.loads(rf.read_text())
            adv = data.get("advisory_id")
            proj = data.get("project", rf.parent.parent.name)
            fix = data.get("fix", {})
            sha = fix.get("sha")
            if adv and sha and SHA_RE.fullmatch(sha.lower()):
                sha_clean = sha.lower()
                rel_path = str(rf.relative_to(root)) if rf.is_relative_to(root) else str(rf)
                records.append({
                    "advisory_id": adv,
                    "fix_sha": sha_clean,
                    "project": proj,
                    "record_file": rel_path,
                })
        except Exception as err:
            print(f"Warning: failed reading record {rf}: {err}", file=sys.stderr)

    records.sort(key=lambda r: (r["project"], r["advisory_id"]))
    return records


def generate_vetted_shas_sidecar(output_path=VETTED_SHAS_SIDECAR, fable_dir=FABLE_DIR, root=ROOT):
    """Generate deterministic sidecar JSONL with clean vetted SHAs."""
    records = extract_vetted_shas_records(fable_dir=fable_dir, root=root)
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(r, ensure_ascii=False) for r in records]
        out.write_text("\n".join(lines) + ("\n" if lines else ""))
    return records


def load_vetted_shas(sidecar_path=VETTED_SHAS_SIDECAR, fable_dir=FABLE_DIR):
    """Load verified SHAs from official records in fable-2026-06 or sidecar."""
    mapping = {}
    if sidecar_path and Path(sidecar_path).exists():
        try:
            for line in Path(sidecar_path).read_text().splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                adv = row.get("advisory_id")
                sha = row.get("fix_sha")
                if adv and sha and SHA_RE.fullmatch(sha.lower()):
                    mapping.setdefault(adv, set()).add(sha.lower())
            if mapping:
                return mapping
        except Exception as err:
            print(f"Warning: failed reading sidecar {sidecar_path}: {err}", file=sys.stderr)

    if not fable_dir.exists():
        return mapping

    for record_file in sorted(fable_dir.glob("*/records/*.json")):
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


def _warn_over_limit(report: dict) -> None:
    """Report entries whose derived status fields had to be dropped."""
    if report.get("over_limit"):
        print(
            f"  warning: {report['project']}: {report['over_limit']} entries exceed "
            f"{MAX_LINE_BYTES} bytes; derived status fields omitted",
            file=sys.stderr,
        )


def enrich_catalog(project_dir, vetted_shas, dry_run=False, git_dir=None):
    """Enrich a single project's catalog.jsonl and index.json."""
    index_file = project_dir / "index.json"
    catalog_file = project_dir / "catalog.jsonl"
    if not index_file.exists() or not catalog_file.exists():
        return None

    if git_dir is None:
        env_mirror = os.environ.get("KSM_GIT_MIRROR")
        if env_mirror:
            git_dir = Path(env_mirror)

    resolved_git = resolve_git_dir(git_dir, project_dir.name) if git_dir else None

    index_data = json.loads(index_file.read_text())
    lines = catalog_file.read_text().splitlines()
    new_lines = []
    with_fix_sha_count = 0
    overlap_count = 0
    over_limit_count = 0

    for line in lines:
        if not line.strip():
            continue
        entry = json.loads(line)
        advisory_id = entry.get("advisory_id")
        current_shas = [s.lower() for s in entry.get("fix_shas", []) if SHA_RE.fullmatch(s.lower())]

        # Add from vetted fable records
        matched_vetted = False
        if advisory_id in vetted_shas:
            matched_vetted = True
            for s in vetted_shas[advisory_id]:
                if s not in current_shas:
                    current_shas.append(s)

        if matched_vetted:
            overlap_count += 1

        # Add from patch URLs containing commit links
        url_shas = extract_commit_shas_from_urls(entry.get("patch_urls", []))
        for s in url_shas:
            if s not in current_shas:
                current_shas.append(s)

        entry["fix_shas"] = current_shas

        # Check mirror status for candidates
        if not current_shas:
            sha_status = "NOT_JOINED"
            statuses = {}
        elif resolved_git is None:
            sha_status = "MIRROR_UNCHECKED"
            statuses = {s: "MIRROR_UNCHECKED" for s in current_shas}
        else:
            statuses = {}
            for s in current_shas:
                if check_sha_in_mirror(resolved_git, s):
                    statuses[s] = "VERIFIED_IN_MIRROR"
                else:
                    statuses[s] = "NOT_IN_MIRROR"
            if any(st == "NOT_IN_MIRROR" for st in statuses.values()):
                sha_status = "NOT_IN_MIRROR"
            else:
                sha_status = "VERIFIED_IN_MIRROR"

        entry["sha_status"] = sha_status
        entry["mirror_status"] = sha_status
        entry["sha_statuses"] = statuses

        if current_shas:
            with_fix_sha_count += 1

        # Compact separators match BaseHistoryFetcher.save_state, so an already
        # enriched line is rewritten byte-for-byte instead of being inflated.
        line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            # Status fields are derived metadata: never trade a catalog line that
            # validate_offline accepts for them.
            for key in ("sha_status", "mirror_status", "sha_statuses"):
                entry.pop(key, None)
            line = json.dumps(entry, separators=(",", ":"), ensure_ascii=False)
            over_limit_count += 1
        new_lines.append(line)

    index_data["with_fix_sha"] = with_fix_sha_count

    if not dry_run:
        catalog_file.write_text("\n".join(new_lines) + ("\n" if new_lines else ""))
        index_file.write_text(json.dumps(index_data, indent=2, ensure_ascii=False) + "\n")

    return {
        "project": index_data.get("project", project_dir.name),
        "entry_count": len(new_lines),
        "with_fix_sha": with_fix_sha_count,
        "overlap": overlap_count,
        "matches": overlap_count,
        "over_limit": over_limit_count,
    }


def verify_all_catalogs(history_dir=CVE_HISTORY_DIR):
    """Verify strictly that all catalogs have valid SHAs and matching index counts."""
    errors = []
    for project_dir in sorted(history_dir.glob("*")):
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
    parser.add_argument("--git-dir", type=Path, default=None, help="Path to local git mirror")
    parser.add_argument("--cve-history-dir", type=Path, default=None,
                        help="Catalog root to process (default: docs/studies/cve-history)")
    parser.add_argument("--generate-sidecar", action="store_true", help="Generate vetted-shas.jsonl sidecar file")
    args = parser.parse_args()

    history_dir = args.cve_history_dir or CVE_HISTORY_DIR
    git_dir = args.git_dir or os.environ.get("KSM_GIT_MIRROR")
    if git_dir:
        git_dir = Path(git_dir)

    if args.generate_sidecar:
        recs = generate_vetted_shas_sidecar()
        print(f"Generated sidecar with {len(recs)} vetted records at {VETTED_SHAS_SIDECAR}")
        if not (args.check or args.offline or args.dry_run):
            return

    if args.check or args.offline:
        vetted = load_vetted_shas()
        enrich_reports = []
        for p in sorted(history_dir.glob("*")):
            if p.is_dir():
                rep = enrich_catalog(p, vetted, dry_run=True, git_dir=git_dir)
                if rep:
                    enrich_reports.append(rep)
                    _warn_over_limit(rep)
        if not verify_all_catalogs(history_dir):
            sys.exit(1)
        total_overlap = sum(r.get("overlap", 0) for r in enrich_reports)
        total_entries = sum(r.get("entry_count", 0) for r in enrich_reports)
        total_with_sha = sum(r.get("with_fix_sha", 0) for r in enrich_reports)

        if total_overlap == 0 and total_with_sha == 0:
            print(f"Catalog scanned: 0 overlaps found with vetted records (overlap: 0, 0 matches across {total_entries} entries).")
        elif total_overlap == 0:
            print(f"Catalog scanned: 0 overlaps found with vetted records (overlap: 0, 0 matches; {total_with_sha} entries with fix SHA).")
        else:
            print(f"Verification successful: All catalogs validated with strict 40-hex lowercase SHAs (overlap: {total_overlap}).")
        return

    # Normal execution
    if not VETTED_SHAS_SIDECAR.exists():
        generate_vetted_shas_sidecar()

    vetted = load_vetted_shas()
    print(f"Loaded {len(vetted)} unique vetted advisory SHAs from Fable records.")
    enrich_reports = []
    for p in sorted(history_dir.glob("*")):
        if p.is_dir():
            rep = enrich_catalog(p, vetted, dry_run=args.dry_run, git_dir=git_dir)
            if rep:
                enrich_reports.append(rep)
                print(f"  {rep['project']}: {rep['with_fix_sha']}/{rep['entry_count']} entries with validated fix SHA (overlap: {rep.get('overlap', 0)})")
                _warn_over_limit(rep)

    if not verify_all_catalogs(history_dir):
        sys.exit(1)

    total_overlap = sum(r.get("overlap", 0) for r in enrich_reports)
    total_with_sha = sum(r.get("with_fix_sha", 0) for r in enrich_reports)
    total_entries = sum(r.get("entry_count", 0) for r in enrich_reports)

    if total_overlap == 0 and total_with_sha == 0:
        print(f"Catalog scanned: 0 overlaps found with vetted records (overlap: 0, 0 matches across {total_entries} entries).")
    elif total_overlap == 0:
        print(f"Catalog scanned: 0 overlaps found with vetted records (overlap: 0, 0 matches; {total_with_sha} entries enriched from patch URLs).")
    else:
        print("Enrichment complete and verified.")


if __name__ == "__main__":
    main()
