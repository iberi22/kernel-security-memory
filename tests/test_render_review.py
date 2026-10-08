import json
import tempfile
import unittest
from pathlib import Path

from scripts.render_review import build_html, load_json, main as render_main


def fixture_seed():
    return {
        "schema_version": "0.1.0",
        "id": "linux-CVE-2024-26581-mainline",
        "project": "linux",
        "title": "Interval garbage-collection generation-state fix",
        "status": "observed",
    }


def fixture_batch():
    evil = "<script>alert(1)</script>\n\nFixes: abcdef123456 (\"x\")"
    return {
        "schema_version": "0.1.0",
        "coverage": "INCOMPLETE",
        "count": 2,
        "errors": ["HTTP 404 fetching deadbeef"],
        "commits": [
            {
                "sha": "60c0c230c6f046da536d3df8b39a20b9a9fd6af0",
                "source_url": "https://api.github.com/repos/torvalds/linux/commits/60c0c230c6f046da536d3df8b39a20b9a9fd6af0",
                "raw_response_sha256": "0" * 64,
                "observed_at": "2026-10-08T00:00:00+00:00",
                "parents": ["f82777e8ce6c039cdcacbcf1eb8619b99a20c06d"],
                "sole_parent": True,
                "message": evil,
                "changed_files": ["net/netfilter/nft_set_rbtree.c"],
                "candidate_signals": [
                    {"type": "fixes_trailer", "target": "abcdef123456", "status": "NOT_CONFIRMED",
                     "reason": "explicit fixes trailer found, not causal proof"}
                ],
                "cve_id": "CVE-2024-26581",
            },
            {
                "sha": "9d2c56cfe02b4e1b3fd837cc4a5b134a876681f3",
                "source_url": "https://api.github.com/repos/torvalds/linux/commits/9d2c56cfe02b4e1b3fd837cc4a5b134a876681f3",
                "raw_response_sha256": "1" * 64,
                "observed_at": "2026-10-08T00:00:00+00:00",
                "parents": [],
                "sole_parent": False,
                "message": "pipe: fix pipe buffer handling",
                "changed_files": [],
                "candidate_signals": [],
                "cve_id": None,
            },
        ],
    }


class TestRenderReview(unittest.TestCase):
    def test_row_ids_and_paths(self):
        page = build_html(fixture_seed(), fixture_batch())
        # one row id per candidate (short sha)
        self.assertIn('id="cand-60c0c230c6f0"', page)
        self.assertIn('id="cand-9d2c56cfe02b"', page)
        # approve/reject checkbox ids carry the full sha
        self.assertIn('id="approve-60c0c230c6f046da536d3df8b39a20b9a9fd6af0"', page)
        self.assertIn('id="reject-60c0c230c6f046da536d3df8b39a20b9a9fd6af0"', page)
        # export button + decisions textarea ids
        self.assertIn('id="export-btn"', page)
        self.assertIn('id="decisions"', page)
        # CVE binding and NOT_CONFIRMED signal rendered
        self.assertIn("CVE-2024-26581", page)
        self.assertIn("NOT_CONFIRMED", page)
        self.assertIn("UNBOUND", page)
        # honest coverage + error surfaced
        self.assertIn("INCOMPLETE", page)
        self.assertIn("HTTP 404 fetching deadbeef", page)

    def test_html_escaping(self):
        page = build_html(fixture_seed(), fixture_batch())
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)", page)

    def test_self_contained_no_cdn(self):
        page = build_html(fixture_seed(), fixture_batch())
        self.assertNotIn("http://", page.replace("https://api.github.com", ""))
        self.assertNotIn("cdn", page.lower())
        self.assertIn("<style>", page)
        self.assertIn("<script>", page)

    def test_cli_writes_output_file(self):
        with tempfile.TemporaryDirectory() as td:
            seed_p = Path(td) / "seed.json"
            batch_p = Path(td) / "batch.json"
            out_p = Path(td) / "sub" / "review.html"
            seed_p.write_text(json.dumps(fixture_seed()), encoding="utf-8")
            batch_p.write_text(json.dumps(fixture_batch()), encoding="utf-8")
            import sys
            argv = sys.argv
            sys.argv = ["render_review.py", "--seed", str(seed_p),
                        "--batch", str(batch_p), "--output", str(out_p)]
            try:
                render_main()
            finally:
                sys.argv = argv
            self.assertTrue(out_p.exists())
            content = out_p.read_text(encoding="utf-8")
            self.assertIn('id="cand-60c0c230c6f0"', content)


if __name__ == "__main__":
    unittest.main()
