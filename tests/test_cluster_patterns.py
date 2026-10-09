#!/usr/bin/env python3
"""Unit tests for cluster_patterns script."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from cluster_patterns import cluster_families, build_graph_db


class TestClusterPatterns(unittest.TestCase):
    def test_cluster_families(self):
        sample = {
            "CVE-2020-0001": {"advisory_id": "CVE-2020-0001", "project": "linux", "cwe": "CWE-119", "fix_shas": ["a"*40]},
            "CVE-2020-0002": {"advisory_id": "CVE-2020-0002", "project": "linux", "cwe": "CWE-119", "fix_shas": []},
            "CVE-2020-0003": {"advisory_id": "CVE-2020-0003", "project": "git", "cwe": "CWE-416", "fix_shas": ["b"*40]},
        }
        clusters = cluster_families(sample)
        self.assertEqual(len(clusters), 2)
        cwe_119 = next(c for c in clusters if c["cwe_id"] == "CWE-119")
        self.assertEqual(cwe_119["count"], 2)
        self.assertEqual(cwe_119["with_fix_sha"], 1)

    def test_build_graph_db(self):
        sample = {
            "CVE-2020-0001": {"advisory_id": "CVE-2020-0001", "project": "linux", "cwe": "CWE-119", "fix_shas": ["a"*40]},
        }
        clusters = cluster_families(sample)
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test_graph.sqlite3"
            build_graph_db(sample, clusters, db_path)

            conn = sqlite3.connect(db_path)
            kinds = {row[0] for row in conn.execute("SELECT DISTINCT kind FROM nodes").fetchall()}
            self.assertIn("CVE", kinds)
            self.assertIn("CWE", kinds)
            self.assertIn("Component", kinds)
            self.assertIn("Commit", kinds)

            edges = conn.execute("SELECT relation FROM edges").fetchall()
            relations = {r[0] for r in edges}
            self.assertIn("affects", relations)
            self.assertIn("categorized_as", relations)
            self.assertIn("fixes", relations)
            conn.close()


if __name__ == "__main__":
    unittest.main()
