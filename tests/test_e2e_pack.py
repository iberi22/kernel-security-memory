"""End-to-end offline suite: seed pack -> bundle -> local reader -> baseline.

Every stage runs in temporary directories, uses only the standard library
plus the repo scripts, and performs zero network I/O.
"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_pack import artifacts, build_sql, load_records
from export_bundle import export_bundle
from measure_baseline import measure
from open_pack import PackReader

REPO = Path(__file__).resolve().parents[1]
SEED_ID = "linux-CVE-2024-26581-mainline"
REVISION = "a" * 40
QRELS = REPO / "experiments" / "qrels-v1.json"


class PackEndToEndTests(unittest.TestCase):
    def test_01_build_pack_deterministic_sql(self):
        records = load_records()
        self.assertTrue(any(r["id"] == SEED_ID for r in records))
        first = build_sql(records).encode()
        second = build_sql(load_records()).encode()
        self.assertEqual(first, second, "SQL export must be deterministic")
        self.assertIn(SEED_ID.encode(), first)
        files = artifacts(records)
        self.assertIn("kernel-security-memory.sql", files)
        self.assertEqual(files["kernel-security-memory.sql"], first)

    def test_02_export_bundle_hashes_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"
            manifest = export_bundle(root, REVISION)
            self.assertEqual(manifest["source_revision"], REVISION)
            self.assertEqual(manifest["coverage"], "SOURCE_LINKED_SEED_ONLY")
            self.assertEqual(manifest["indexes"]["vectors"], "NOT_BUILT")
            self.assertGreater(len(manifest["files"]), 0)
            for entry in manifest["files"]:
                body = (root / entry["path"]).read_bytes()
                self.assertEqual(len(body), entry["bytes"], entry["path"])
                self.assertEqual(hashlib.sha256(body).hexdigest(),
                                 entry["sha256"], entry["path"])
            stored = json.loads((root / "distribution.json").read_text())
            self.assertEqual(stored, manifest)

    def test_03_pack_reader_local_query_hits(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_bundle(Path(tmp) / "bundle", REVISION)
            before = {(p.relative_to(tmp)).as_posix(): p.read_bytes()
                      for p in sorted((Path(tmp) / "bundle").rglob("*"))
                      if p.is_file() and p.name != "memory.sqlite3"}
            with tempfile.TemporaryDirectory() as cache:
                with PackReader(str(Path(tmp) / "bundle"), cache) as reader:
                    hits = reader.query("interval garbage collection")
            self.assertTrue(hits, "seed query must return hits offline")
            self.assertTrue(any(h.get("id") == SEED_ID for h in hits))
            for rel, body in before.items():
                self.assertEqual((Path(tmp) / rel).read_bytes(), body,
                                 f"reader mutated bundle file {rel}")

    def test_04_baseline_recall_and_abstention(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_bundle(Path(tmp) / "bundle", REVISION)
            sql_path = Path(tmp) / "bundle" / "kernel-security-memory.sql"
            report = measure(QRELS, sql_path)
        summary = report["summary"]
        self.assertEqual(summary["n_not_measured"], 0,
                         f"unmeasured: {summary['not_measured_ids']}")
        pos = summary["positive_recall"]
        neg = summary["negative_abstention"]
        self.assertEqual((pos["hits"], pos["denominator"]), (6, 6))
        self.assertEqual((neg["correct"], neg["denominator"]), (2, 3))


if __name__ == "__main__":
    unittest.main()
