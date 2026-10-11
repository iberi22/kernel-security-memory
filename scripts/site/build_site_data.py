#!/usr/bin/env python3
"""CLI entry point for Vulnerability Atlas site data builder."""

import argparse
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ksm.sitedata import build_site_data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build site data for Vulnerability Atlas.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Root path of the repository (default: .)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "site" / "data",
        help="Output directory for site data (default: site/data)",
    )
    parser.add_argument(
        "--no-bundle",
        action="store_true",
        help="Skip building bundle.tar.gz and bundle.sha256",
    )

    args = parser.parse_args(argv)
    build_site_data(
        repo_root=args.repo_root,
        out_dir=args.out,
        no_bundle=args.no_bundle,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
