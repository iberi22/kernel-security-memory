#!/usr/bin/env python3
"""Unit tests for enrich_fix_shas script and SHA validation rules."""

import json
from pathlib import Path
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/studies"))
from enrich_fix_shas import (
    SHA_RE,
    extract_commit_shas_from_urls,
    enrich_catalog,
)


class TestEnrichFixShas(unittest.TestCase):
    def test_sha_regex(self):
        valid = "34fa79a6cde56d6d428ab0d3160cb094ebad3305"
        self.assertTrue(SHA_RE.fullmatch(valid))
        self.assertFalse(SHA_RE.fullmatch("34fa79a6"))
        self.assertFalse(SHA_RE.fullmatch("34FA79A6CDE56D6D428AB0D3160CB094EBAD3305"))
        self.assertFalse(SHA_RE.fullmatch(valid + "g"))

    def test_extract_commit_shas_from_urls(self):
        urls = [
            "https://github.com/git/git/commit/34fa79a6cde56d6d428ab0d3160cb094ebad3305",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a66268f1f8c5f3ca4ede7f2d0093249924ab3a96",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
        ]
        shas = extract_commit_shas_from_urls(urls)
        self.assertEqual(len(shas), 2)
        self.assertIn("34fa79a6cde56d6d428ab0d3160cb094ebad3305", shas)
        self.assertIn("a66268f1f8c5f3ca4ede7f2d0093249924ab3a96", shas)

    def test_enrich_catalog_integration(self):
        with tempfile.TemporaryDirectory() as td:
            pdir = Path(td)
            index_file = pdir / "index.json"
            catalog_file = pdir / "catalog.jsonl"

            index_file.write_text(json.dumps({
                "schema_version": "cve-history-v1",
                "project": "sample",
                "entry_count": 2,
                "with_fix_sha": 0,
            }))

            catalog_file.write_text(
                json.dumps({
                    "advisory_id": "CVE-2021-1111",
                    "published": "2021-01-01",
                    "cwe": None,
                    "cwe_state": "UNKNOWN",
                    "patch_urls": ["https://github.com/sample/sample/commit/1111111111111111111111111111111111111111"],
                    "fix_shas": [],
                }) + "\n" +
                json.dumps({
                    "advisory_id": "CVE-2021-2222",
                    "published": "2021-02-01",
                    "cwe": "CWE-119",
                    "cwe_state": "STATED_BY_ADVISORY",
                    "patch_urls": ["https://example.com/advisory"],
                    "fix_shas": [],
                }) + "\n"
            )

            vetted = {
                "CVE-2021-2222": {"2222222222222222222222222222222222222222"}
            }

            rep = enrich_catalog(pdir, vetted, dry_run=False)
            self.assertEqual(rep["with_fix_sha"], 2)

            updated_index = json.loads(index_file.read_text())
            self.assertEqual(updated_index["with_fix_sha"], 2)

            updated_lines = [json.loads(l) for l in catalog_file.read_text().splitlines()]
            self.assertEqual(updated_lines[0]["fix_shas"], ["1111111111111111111111111111111111111111"])
            self.assertEqual(updated_lines[1]["fix_shas"], ["2222222222222222222222222222222222222222"])


if __name__ == "__main__":
    unittest.main()
