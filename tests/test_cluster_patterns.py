#!/usr/bin/env python3
"""Unit tests for cluster_patterns script."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from cluster_patterns import cluster_families, build_graph_db, apply_overlay, effective_cwe, load_overlay


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


class TestCweOverlay(unittest.TestCase):
    def _corpus(self):
        return {
            "CVE-2020-0001": {"advisory_id": "CVE-2020-0001", "project": "linux-cna",
                               "cwe": None, "catalogs": ["linux-cna"], "fix_shas": []},
            "CVE-2020-0002": {"advisory_id": "CVE-2020-0002", "project": "curl",
                               "cwe": None, "catalogs": ["curl"], "fix_shas": []},
            "CVE-2020-0003": {"advisory_id": "CVE-2020-0003", "project": "linux",
                               "cwe": "CWE-119", "catalogs": ["linux"], "fix_shas": []},
            "CVE-2020-0004": {"advisory_id": "CVE-2020-0004", "project": "git",
                               "cwe": None, "catalogs": ["git"], "fix_shas": []},
        }

    def test_effective_cwe_prefers_then_falls_back(self):
        self.assertEqual(effective_cwe({"effective_cwe": "CWE-787", "cwe": None}), "CWE-787")
        self.assertEqual(effective_cwe({"cwe": "CWE-119"}), "CWE-119")
        self.assertEqual(effective_cwe({"cwe": None}), "UNKNOWN")

    def test_overlay_fills_only_missing_and_records_source(self):
        cves = self._corpus()
        overlay = {
            "CVE-2020-0001": {"cwe": "CWE-401", "cwe_source": "nvd-primary"},
            "CVE-2020-0002": {"cwe": "CWE-416", "cwe_source": "nvd-secondary"},
            # advisory 0003 already has a catalog CWE: must be ignored.
            "CVE-2020-0003": {"cwe": "CWE-690", "cwe_source": "nvd-primary"},
        }
        summary = apply_overlay(cves, overlay)
        self.assertEqual(summary["cwe_from_catalog"], 1)
        self.assertEqual(summary["cwe_from_overlay_by_source"],
                         {"cisa-adp": 0, "nvd-primary": 1, "nvd-secondary": 1})
        # 0004 has no catalog CWE and no overlay entry -> still UNKNOWN.
        self.assertEqual(summary["unknown"], 1)
        # catalog value wins and is not overwritten by an overlay row.
        self.assertEqual(cves["CVE-2020-0003"]["cwe"], "CWE-119")
        self.assertNotIn("effective_cwe", cves["CVE-2020-0003"])
        self.assertEqual(effective_cwe(cves["CVE-2020-0001"]), "CWE-401")
        self.assertEqual(effective_cwe(cves["CVE-2020-0004"]), "UNKNOWN")

    def test_cluster_families_uses_overlay_cwe(self):
        cves = self._corpus()
        apply_overlay(cves, {"CVE-2020-0001": {"cwe": "CWE-401", "cwe_source": "nvd-primary"}})
        clusters = cluster_families(cves)
        ids = {c["cwe_id"] for c in clusters}
        self.assertIn("CWE-401", ids)   # came from the overlay
        self.assertIn("CWE-119", ids)   # catalog
        self.assertIn("UNKNOWN", ids)   # 0002 and 0004


if __name__ == "__main__":
    unittest.main()
