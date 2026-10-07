#!/usr/bin/env python3
"""Build an independent, hash-described evidence bundle for remote distribution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from build_pack import artifacts, load_records
from query_pack import query_database


def export_bundle(output, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be a full lowercase Git SHA")
    output = Path(output)
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output must be absent or an empty directory")
    files = artifacts(load_records())
    output.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    database = output / "memory.sqlite3"
    db = sqlite3.connect(database)
    try:
        # SQL comes from our trusted builder, not from a downloaded pack.
        db.executescript(files["kernel-security-memory.sql"].decode())
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("bundle SQLite integrity failure")
        if db.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("bundle foreign-key failure")
        counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                  for table in ("records", "nodes", "edges", "claims", "evidence")}
    finally:
        db.close()
    if not query_database(database, "interval garbage collection"):
        raise ValueError("seed retrieval smoke failed")
    if query_database(database, "unrelated_astronomical_sentinel_987"):
        raise ValueError("negative retrieval smoke failed")
    manifest = {
        "bundle_schema": "0.1.0", "source_revision": revision,
        "coverage": "SOURCE_LINKED_SEED_ONLY", "counts": counts,
        "indexes": {"lexical": "SQLite FTS5", "graph": "typed SQL tables",
                    "vectors": "NOT_BUILT", "ast": "NOT_BUILT"},
        "sqlite_version": sqlite3.sqlite_version,
        "files": [{"path": str(path.relative_to(output)),
                   "bytes": path.stat().st_size,
                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                  for path in sorted(output.rglob("*")) if path.is_file()],
    }
    (output / "distribution.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    result = export_bundle(args.output, args.source_revision)
    print(json.dumps({"coverage": result["coverage"], "counts": result["counts"],
                      "indexes": result["indexes"]}))


if __name__ == "__main__":
    main()
