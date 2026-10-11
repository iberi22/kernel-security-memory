"""CLI interface for Kernel Security Memory (ksm)."""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Optional, Sequence

from ksm.data import (
    DEFAULT_UPDATE_URL,
    find_cve_project,
    get_fingerprints_dir,
    get_pattern_clusters_path,
    load_cve,
    load_cwe,
    load_index,
    load_search,
    resolve_data_dir,
    update,
)

SUPPORTED_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".hpp",
    ".rs", ".py", ".go", ".java",
    ".ts", ".tsx", ".js", ".mjs",
}

SKIP_DIRS = {".git", "target", "node_modules", "vendor", "build", "dist"}
MAX_FILE_SIZE = 1024 * 1024  # 1 MB


def _get_auditor_module():
    """The regex auditor: the repo checkout's script, else the installed module."""
    repo_script = Path(__file__).resolve().parent.parent / "scripts" / "defensive_auditor.py"
    if repo_script.is_file():
        spec = importlib.util.spec_from_file_location("ksm_defensive_auditor", repo_script)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["ksm_defensive_auditor"] = mod
            spec.loader.exec_module(mod)
            return mod
    import defensive_auditor  # installed by pyproject.toml (py-modules)
    return defensive_auditor


def _cmd_update(args: argparse.Namespace) -> int:
    dest = update(url=args.url, dest=args.data_dir)
    if args.json:
        print(json.dumps({"status": "ok", "data_dir": str(dest)}, indent=2))
    else:
        print(f"Updated KSM data in {dest}")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    data = load_index(args.data_dir)
    totals = data.get("totals", {})
    projects = data.get("projects", [])

    if args.json:
        payload = {
            "schema": data.get("schema"),
            "ksm_commit": data.get("ksm_commit"),
            "generated": data.get("generated"),
            "totals": totals,
            "projects": projects,
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"KSM Commit:  {data.get('ksm_commit', 'unknown')}")
    print(f"Generated:   {data.get('generated', 'unknown')}")
    print("Totals:")
    print(f"  CVEs:              {totals.get('cves', 0)}")
    print(f"  With Fix:          {totals.get('with_fix', 0)}")
    print(f"  With Fragments:    {totals.get('with_fragments', 0)}")
    print(f"  With Fingerprint:  {totals.get('with_fingerprint', 0)}")
    print(f"  Projects:          {totals.get('projects', 0)}")
    if projects:
        print(f"Projects ({len(projects)}):")
        for p in projects:
            p_name = p.get("name", "unknown")
            p_cves = p.get("cves", 0)
            p_fixes = p.get("with_fix", 0)
            p_frags = p.get("with_fragments", 0)
            p_fps = p.get("with_fingerprint", 0)
            print(f"  {p_name:<16} {p_cves:>5} CVEs (fixes: {p_fixes}, frags: {p_frags}, fps: {p_fps})")
    return 0


def _cmd_tree(args: argparse.Namespace) -> int:
    data = load_index(args.data_dir)

    if args.by == "cwe":
        groups = data.get("groups", [])
        filtered_groups = []
        for g in groups:
            cwes = g.get("cwes", [])
            matching_cwes = []
            for cwe in cwes:
                if args.cwe and cwe.get("id", "").upper() != args.cwe.upper():
                    continue
                if args.project:
                    projects_map = cwe.get("projects", {})
                    if args.project not in projects_map:
                        continue
                matching_cwes.append(cwe)

            if args.limit is not None and args.limit >= 0:
                matching_cwes = matching_cwes[: args.limit]

            if matching_cwes:
                filtered_groups.append({
                    "name": g.get("name"),
                    "cves": sum(c.get("cves", 0) for c in matching_cwes),
                    "cwes": matching_cwes,
                })

        if args.json:
            print(json.dumps(filtered_groups, indent=2))
            return 0

        if not filtered_groups:
            print("No matching CWEs found.")
            return 0

        for i, g in enumerate(filtered_groups):
            print(f"{g['name']} ({g['cves']} CVEs)")
            cwes = g.get("cwes", [])
            for j, cwe in enumerate(cwes):
                is_last_cwe = (j == len(cwes) - 1)
                prefix_cwe = "  └── " if is_last_cwe else "  ├── "
                pipe = "      " if is_last_cwe else "  │   "
                print(f"{prefix_cwe}{cwe.get('id')}: {cwe.get('name')} ({cwe.get('cves', 0)} CVEs)")
                projects_map = cwe.get("projects", {})
                if projects_map:
                    proj_str = ", ".join(f"{k}: {v}" for k, v in sorted(projects_map.items()))
                    print(f"{pipe}└── {proj_str}")
        return 0

    elif args.by == "project":
        projects = data.get("projects", [])
        if args.project:
            projects = [p for p in projects if p.get("name", "").lower() == args.project.lower()]

        if args.limit is not None and args.limit >= 0:
            projects = projects[: args.limit]

        if args.json:
            print(json.dumps(projects, indent=2))
            return 0

        if not projects:
            print("No matching projects found.")
            return 0

        print("Projects:")
        for i, p in enumerate(projects):
            is_last = (i == len(projects) - 1)
            prefix = "└── " if is_last else "├── "
            pipe = "    " if is_last else "│   "
            print(f"  {prefix}{p.get('name')} (repo: {p.get('repo', '-')}) - {p.get('cves', 0)} CVEs")
            years = p.get("years", {})
            if years:
                years_str = ", ".join(f"{k}: {v}" for k, v in sorted(years.items()))
                print(f"  {pipe}└── Years: {years_str}")
        return 0

    return 2


def _cmd_show(args: argparse.Namespace) -> int:
    project = args.project
    if not project:
        project = find_cve_project(args.cve, args.data_dir)
        if not project:
            sys.stderr.write(f"Error: could not find project for CVE {args.cve}\n")
            return 2

    cve_data = load_cve(project, args.cve, args.data_dir)
    if args.json:
        print(json.dumps(cve_data, indent=2))
        return 0

    print(f"CVE:          {cve_data.get('id')}")
    print(f"Project:      {cve_data.get('project')} (repo: {cve_data.get('repo', '-')})")
    print(f"Published:    {cve_data.get('published', '-')}")
    cwe_id = cve_data.get("cwe", "-")
    cwe_name = cve_data.get("cwe_name", "-")
    group = cve_data.get("group", "-")
    cwe_source = cve_data.get("cwe_source", "-")
    print(f"CWE:          {cwe_id} ({cwe_name}) [Group: {group}, Source: {cwe_source}]")
    print(f"Subsystem:    {cve_data.get('subsystem') or '-'}")

    fixes = cve_data.get("fixes", [])
    if fixes:
        print("Fixes:")
        for fix in fixes:
            sha = fix.get("sha", "")[:12]
            url = fix.get("url", "")
            print(f"  - {sha} {url}")
    else:
        print("Fixes:        None")

    fragments = cve_data.get("fragments")
    if fragments and isinstance(fragments, dict):
        files = fragments.get("files", [])
        print(f"Fragments:    {fragments.get('coverage', 'OK')} ({len(files)} files)")
        for f in files:
            funcs = ", ".join(fn.get("name", "") for fn in f.get("functions", []))
            print(f"  - {f.get('path')} ({funcs})")
    else:
        print("Fragments:    None")

    fingerprint = cve_data.get("fingerprint")
    if fingerprint and isinstance(fingerprint, dict):
        fns = fingerprint.get("functions", [])
        print(f"Fingerprint:  Available ({len(fns)} functions)")
        for fn in fns:
            guards = len(fn.get("added_guards", []))
            calls = len(fn.get("added_calls", []))
            print(f"  - {fn.get('path', '')}:{fn.get('name', '')} ({guards} guards, {calls} calls added)")
    else:
        print("Fingerprint:  None")

    related = cve_data.get("related", [])
    if related:
        print("Related:")
        for rel in related:
            shared = ", ".join(rel.get("shared", []))
            print(f"  - {rel.get('id')} ({rel.get('project')}) score={rel.get('score')} [{shared}]")
    else:
        print("Related:      None")

    return 0


def _cmd_related(args: argparse.Namespace) -> int:
    project = args.project
    if not project:
        project = find_cve_project(args.cve, args.data_dir)
        if not project:
            sys.stderr.write(f"Error: could not find project for CVE {args.cve}\n")
            return 2

    cve_data = load_cve(project, args.cve, args.data_dir)
    related = cve_data.get("related", [])

    if args.json:
        print(json.dumps(related, indent=2))
        return 0

    if not related:
        print("No related CVEs found.")
        return 0

    print(f"{'ID':<18} {'Project':<12} {'Score':<8} {'Shared'}")
    for r in related:
        r_id = r.get("id", "-")
        r_proj = r.get("project", "-")
        r_score = str(r.get("score", "-"))
        r_shared = ", ".join(r.get("shared", []))
        print(f"{r_id:<18} {r_proj:<12} {r_score:<8} {r_shared}")
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    search_rows = load_search(args.data_dir)
    q = args.query.strip().lower()

    matches = []
    for row in search_rows:
        if not row:
            continue
        cve_id = str(row[0]) if len(row) > 0 and row[0] is not None else ""
        project = str(row[1]) if len(row) > 1 and row[1] is not None else ""
        cwe = str(row[2]) if len(row) > 2 and row[2] is not None else ""
        subsystem = str(row[3]) if len(row) > 3 and row[3] is not None else ""
        funcs = str(row[4]) if len(row) > 4 and row[4] is not None else ""

        haystack = f"{cve_id} {project} {cwe} {subsystem} {funcs}".lower()
        if q in haystack:
            matches.append({
                "id": cve_id,
                "project": project,
                "cwe": cwe or None,
                "subsystem": subsystem or None,
                "functions": funcs or None,
            })

    if args.limit is not None and args.limit >= 0:
        matches = matches[: args.limit]

    if args.json:
        print(json.dumps(matches, indent=2))
        return 0

    if not matches:
        print("No matches found.")
        return 0

    print(f"{'ID':<18} {'Project':<12} {'CWE':<12} {'Subsystem':<12} {'Functions'}")
    for m in matches:
        m_id = m.get("id") or "-"
        m_proj = m.get("project") or "-"
        m_cwe = m.get("cwe") or "-"
        m_sub = m.get("subsystem") or "-"
        m_fn = m.get("functions") or "-"
        print(f"{m_id:<18} {m_proj:<12} {m_cwe:<12} {m_sub:<12} {m_fn}")
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    try:
        auditor = _get_auditor_module()
    except Exception as exc:
        sys.stderr.write(f"Error loading defensive auditor: {exc}\n")
        return 2

    clusters_path = get_pattern_clusters_path(args.data_dir)
    cluster_map = {}
    if clusters_path and clusters_path.is_file():
        try:
            cluster_map = auditor.load_pattern_clusters(str(clusters_path))
        except Exception as exc:
            sys.stderr.write(f"Error loading pattern clusters from {clusters_path}: {exc}\n")
            return 2

    try:
        files_audited, findings, file_digests = auditor.audit_path(args.path, cluster_map=cluster_map)
        evidence = auditor.build_evidence_chain(args.path, files_audited, findings, file_digests=file_digests)
    except Exception as exc:
        sys.stderr.write(f"Error during audit traversal: {exc}\n")
        return 2

    if args.json:
        print(json.dumps(evidence, indent=2, ensure_ascii=False))
    else:
        print(f"Audit Target: {args.path}")
        print(f"Files Audited: {len(files_audited)}")
        print(f"Findings: {len(findings)}")
        print(f"Verdict: {evidence['audit']['verdict']}")
        print(f"Evidence Chain Hash (SHA256): {evidence['evidence_chain_hash']}")

    if args.strict and (evidence["audit"]["verdict"] in ("FAIL", "INCOMPLETE") or len(findings) > 0):
        return 1
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        sys.stderr.write(f"Error: target path does not exist: {target_path}\n")
        return 2

    # Discover files
    collected_files = []
    if target_path.is_file():
        if target_path.suffix.lower() in SUPPORTED_EXTENSIONS and target_path.stat().st_size <= MAX_FILE_SIZE:
            collected_files.append(target_path)
    elif target_path.is_dir():
        for root, dirs, files in os.walk(target_path):
            dirs[:] = sorted([d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")])
            for f in sorted(files):
                ext = Path(f).suffix.lower()
                if ext in SUPPORTED_EXTENSIONS:
                    fp = Path(root) / f
                    try:
                        if fp.is_file() and fp.stat().st_size <= MAX_FILE_SIZE:
                            collected_files.append(fp)
                    except OSError:
                        continue

    if not collected_files:
        sys.stderr.write(f"Error: no supported source files under {target_path} "
                         f"({', '.join(sorted(SUPPORTED_EXTENSIONS))}).\n")
        return 2
    if args.max_files is not None and 0 <= args.max_files < len(collected_files):
        sys.stderr.write(f"Warning: scanning the first {args.max_files} of "
                         f"{len(collected_files)} files (--max-files).\n")
        collected_files = collected_files[: args.max_files]

    # Resolve code-graph binary
    from ksm.scanner import resolve_code_graph_bin, verify_code_graph_bin

    code_graph_bin = resolve_code_graph_bin(args.data_dir)
    if not code_graph_bin:
        sys.stderr.write(
            "Error: 'code-graph' executable not found.\n"
            "Please install code-graph or set KSM_CODE_GRAPH to its location.\n"
            "Prebuilt Linux binary: https://github.com/iberi22/kernel-security-memory/releases "
            "(asset code-graph-x86_64-linux.tar.gz)\n"
            "Or build from source via the cargo command in README.\n"
        )
        return 2

    if not verify_code_graph_bin(code_graph_bin):
        sys.stderr.write(
            f"Error: {code_graph_bin} produced no ksm-sfp/1 output. "
            f"It needs the `fingerprint` subcommand "
            "(Xavier code-graph, see docs/design/VULN-ATLAS.md); set KSM_CODE_GRAPH.\n"
        )
        return 2

    target_docs = []
    failed = 0
    for fp in collected_files:
        try:
            res = subprocess.run(
                [code_graph_bin, "fingerprint", str(fp)],
                capture_output=True, text=True, check=False, timeout=300,
            )
            doc = json.loads(res.stdout) if res.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            doc = None
        if isinstance(doc, dict) and doc.get("schema") == "ksm-sfp/1":
            target_docs.append(doc)
        else:
            failed += 1
    if collected_files and failed == len(collected_files):
        # Every file failed: wrong binary (an old code-graph without the
        # `fingerprint` subcommand) rather than a clean result.
        sys.stderr.write(
            f"Error: {code_graph_bin} produced no ksm-sfp/1 output for any of "
            f"{len(collected_files)} files. It needs the `fingerprint` subcommand "
            "(Xavier code-graph, see docs/design/VULN-ATLAS.md); set KSM_CODE_GRAPH.\n")
        return 2
    if failed:
        sys.stderr.write(f"Warning: {failed} of {len(collected_files)} files could not be fingerprinted.\n")

    # Lazy import ksm.match
    try:
        from ksm.match import load_corpus, match_documents, render_markdown
    except ImportError as exc:
        sys.stderr.write(f"Error: failed to import ksm.match: {exc}\n")
        return 2

    fingerprints_dir = get_fingerprints_dir(args.data_dir)
    try:
        corpus = load_corpus(str(fingerprints_dir))
        if not corpus:
            sys.stderr.write(f"Error: no fix fingerprints in {fingerprints_dir}; run `ksm update`.\n")
            return 2
        findings = match_documents(target_docs, corpus)
    except Exception as exc:
        sys.stderr.write(f"Error during fingerprint matching: {exc}\n")
        return 2

    if args.json:
        out_content = json.dumps(findings, indent=2)
    else:
        out_content = render_markdown(findings)

    if args.out:
        Path(args.out).write_text(out_content, encoding="utf-8")
    else:
        print(out_content)

    if args.strict and findings:
        return 1
    return 0




def _cmd_setup(args: argparse.Namespace) -> int:
    from ksm.setup import cmd_setup
    return cmd_setup(args)


def _cmd_doctor(args: argparse.Namespace) -> int:
    from ksm.setup import cmd_doctor
    return cmd_doctor(args)

def build_parser() -> argparse.ArgumentParser:
    """Construct top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="ksm",
        description="Kernel Security Memory (KSM) CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # update
    p_update = subparsers.add_parser("update", help="Download and verify bundle from Pages")
    p_update.add_argument("--url", default=DEFAULT_UPDATE_URL, help="Base URL or directory for data bundle")
    p_update.add_argument("--data-dir", help="Destination data directory")
    p_update.add_argument("--json", action="store_true", help="Output status as JSON")

    # stats
    p_stats = subparsers.add_parser("stats", help="Print corpus and catalog summary statistics")
    p_stats.add_argument("--data-dir", help="Path to KSM data directory")
    p_stats.add_argument("--json", action="store_true", help="Output statistics as JSON")

    # tree
    p_tree = subparsers.add_parser("tree", help="Display hierarchy tree by CWE or project")
    p_tree.add_argument("--by", choices=["cwe", "project"], default="cwe", help="Hierarchy mode (default: cwe)")
    p_tree.add_argument("--project", help="Filter by project name")
    p_tree.add_argument("--cwe", help="Filter by CWE ID")
    p_tree.add_argument("--limit", type=int, help="Limit entries per group/level")
    p_tree.add_argument("--data-dir", help="Path to KSM data directory")
    p_tree.add_argument("--json", action="store_true", help="Output tree as JSON")

    # show
    p_show = subparsers.add_parser("show", help="Display detailed record for a CVE")
    p_show.add_argument("cve", help="CVE ID to show (e.g. CVE-2023-38545)")
    p_show.add_argument("--project", help="Project name (auto-detected via search.json if omitted)")
    p_show.add_argument("--data-dir", help="Path to KSM data directory")
    p_show.add_argument("--json", action="store_true", help="Output record as JSON")

    # related
    p_related = subparsers.add_parser("related", help="Show related CVEs for a given advisory")
    p_related.add_argument("cve", help="CVE ID to inspect")
    p_related.add_argument("--project", help="Project name (auto-detected if omitted)")
    p_related.add_argument("--data-dir", help="Path to KSM data directory")
    p_related.add_argument("--json", action="store_true", help="Output related CVEs as JSON")

    # search
    p_search = subparsers.add_parser("search", help="Search CVE index by substring")
    p_search.add_argument("query", help="Search string")
    p_search.add_argument("--limit", type=int, help="Limit matching results")
    p_search.add_argument("--data-dir", help="Path to KSM data directory")
    p_search.add_argument("--json", action="store_true", help="Output matches as JSON")

    # audit
    p_audit = subparsers.add_parser("audit", help="Run defensive pattern audit on path")
    p_audit.add_argument("path", help="Path to file or directory to audit")
    p_audit.add_argument("--strict", action="store_true", help="Exit 1 on findings")
    p_audit.add_argument("--data-dir", help="Path to KSM data directory")
    p_audit.add_argument("--json", action="store_true", help="Output evidence chain as JSON")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan code files with code-graph and match fingerprints")
    p_scan.add_argument("path", help="Path to scan")
    p_scan.add_argument("--strict", action="store_true", help="Exit 1 on findings")
    p_scan.add_argument("--out", help="Write output to file")
    p_scan.add_argument("--max-files", type=int, help="Maximum number of files to process")
    p_scan.add_argument("--data-dir", help="Path to KSM data directory")
    p_scan.add_argument("--json", action="store_true", help="Output findings as JSON")


    # setup
    p_setup = subparsers.add_parser("setup", help="Install code-graph scanner binary")
    p_setup.add_argument("--from-cargo", action="store_true", help="Build code-graph from source using cargo")
    p_setup.add_argument("--data-dir", help="Destination data directory")

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Check KSM data and scanner readiness")
    p_doctor.add_argument("--data-dir", help="Path to KSM data directory")
    p_doctor.add_argument("--json", action="store_true", help="Output status as JSON")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main entry point for ksm CLI."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    dispatch = {
        "update": _cmd_update,
        "stats": _cmd_stats,
        "tree": _cmd_tree,
        "show": _cmd_show,
        "related": _cmd_related,
        "search": _cmd_search,
        "audit": _cmd_audit,
        "scan": _cmd_scan,
        "setup": _cmd_setup,
        "doctor": _cmd_doctor,
    }

    handler = dispatch.get(args.subcommand)
    if not handler:
        sys.stderr.write(f"Unknown subcommand: {args.subcommand}\n")
        return 2

    try:
        return handler(args)
    except FileNotFoundError as exc:
        sys.stderr.write(f"Data error: {exc}\n")
        return 2
    except ValueError as exc:
        sys.stderr.write(f"Value error: {exc}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2
