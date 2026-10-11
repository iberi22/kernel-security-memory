#!/usr/bin/env python3
"""NVD fetcher validators accept enricher provenance keys and nothing else."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
import io

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/studies"))
import fetch_history_curl  # noqa: E402


class TestCatalogOptionalKeys(unittest.TestCase):
    def _validate_with_extra(self, extra: dict) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "curl"
            shutil.copytree(ROOT / "docs/studies/cve-history/curl", out)
            catalog = out / "catalog.jsonl"
            rows = [json.loads(line) for line in catalog.read_text().splitlines() if line.strip()]
            for key in ("fix_sha_source", "cwe_source", "fix_repo"):
                for row in rows:
                    row.pop(key, None)
            rows[0].update(extra)
            catalog.write_text("".join(json.dumps(r) + "\n" for r in rows))
            with redirect_stderr(io.StringIO()):
                return fetch_history_curl.validate_offline(str(out))

    def test_plain_rows_validate(self):
        self.assertTrue(self._validate_with_extra({}))

    def test_enricher_provenance_keys_validate(self):
        self.assertTrue(self._validate_with_extra({"fix_sha_source": "osv", "cwe_source": "osv"}))

    def test_unknown_key_is_rejected(self):
        self.assertFalse(self._validate_with_extra({"description": "copied advisory text"}))


if __name__ == "__main__":
    unittest.main()
