#!/usr/bin/env python3
"""Build fix fingerprints (ksm-fixfp/1) from catalog fix commits."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ksm.fixfp import build_all, code_graph_bin_default


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Build ksm-fixfp/1 fingerprints from catalogs.")
    p.add_argument("--catalog-dir", default="docs/studies/cve-history")
    p.add_argument("--out", default="docs/studies/fingerprints")
    p.add_argument("--max-commits", type=int, default=300)
    p.add_argument("--code-graph", default=None,
                   help="path to code-graph binary (default $KSM_CODE_GRAPH or 'code-graph')")
    p.add_argument("--only-project", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--retry-failed", action="store_true",
                   help="retry index entries recorded as failed")
    p.add_argument("--tool", default="code-graph@unknown")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    code_graph = args.code_graph or code_graph_bin_default()
    summary = build_all(args.catalog_dir, args.out, max_commits=args.max_commits,
                        code_graph_bin=code_graph, only_project=args.only_project,
                        dry_run=args.dry_run, retry_failed=args.retry_failed,
                        tool=args.tool)
    if args.dry_run:
        for c in summary["candidates"]:
            print(f"{c['project']} {c['advisory_id']} {c['fix_sha']}")
        print(f"dry-run: {len(summary['candidates'])} candidates", file=sys.stderr)
    else:
        print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
