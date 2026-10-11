#!/usr/bin/env python3
"""CWE id -> name table from MITRE's CWE list (Research Concepts view, CSV).

Only ids and names are kept, with MITRE's copyright and license as its terms
require. Run with --fetch to download; without it the cached zip is reused.
"""
import argparse
import csv
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CACHE = ROOT / "docs/studies/cwe-cache/1000.csv.zip"
OUT = ROOT / "docs/studies/cwe-names.json"
NOTICE = (
    "CWE names from the CWE List, Copyright (c) 2006-2026, The MITRE Corporation. "
    "CWE and the CWE logo are trademarks of The MITRE Corporation. Used under the CWE "
    "Terms of Use (https://cwe.mitre.org/about/termsofuse.html): MITRE grants a "
    "non-exclusive, royalty-free license to use CWE for research, development, and "
    "commercial purposes, on the condition that MITRE's copyright designation and "
    "this license are reproduced in any copy."
)


def build(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        text = zf.read(name).decode("utf-8")
    names = {}
    for row in csv.DictReader(io.StringIO(text)):
        cwe_id = (row.get("CWE-ID") or "").strip()
        title = (row.get("Name") or "").strip()
        if cwe_id.isdigit() and title:
            names[f"CWE-{cwe_id}"] = title
    return {
        "notice": NOTICE,
        "source": URL,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "names": dict(sorted(names.items(), key=lambda kv: int(kv[0][4:]))),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fetch", action="store_true", help="download the CSV zip first")
    args = p.parse_args(argv)
    if args.fetch:
        req = urllib.request.Request(URL, headers={"User-Agent": "ksm-cwe-names"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_bytes(raw)
    elif CACHE.exists():
        raw = CACHE.read_bytes()
    else:
        print("no cached CSV zip; run with --fetch", file=sys.stderr)
        return 2
    doc = build(raw)
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    print(f"{len(doc['names'])} CWE names -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
