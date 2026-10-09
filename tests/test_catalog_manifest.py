#!/usr/bin/env python3
"""Unit tests for build_catalog_manifest."""

from pathlib import Path
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from build_catalog_manifest import generate_manifest


class TestCatalogManifest(unittest.TestCase):
    def test_generate_manifest_structure(self):
        manifest = generate_manifest()
        self.assertEqual(manifest["schema_version"], "cve-catalog-manifest-v1")
        self.assertGreaterEqual(manifest["project_count"], 12)
        self.assertGreaterEqual(manifest["total_entries"], 400)
        self.assertIn("projects", manifest)
        for proj in manifest["projects"]:
            self.assertIn("name", proj)
            self.assertIn("entry_count", proj)
            self.assertIn("files", proj)
            self.assertIn("index_json", proj["files"])
            self.assertIn("catalog_jsonl", proj["files"])
            self.assertEqual(len(proj["files"]["catalog_jsonl"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
