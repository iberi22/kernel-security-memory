import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.check_qrels_review import check_review, cohens_kappa, main


def row(item_id="q1", reviewer="alice", expect="FOUND"):
    return {"id": item_id, "reviewer": reviewer,
            "reviewed_at": "2026-11-02T12:00:00Z", "expect": expect}


class CheckQrelsReviewTests(unittest.TestCase):
    def run_cli(self, data, *args):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qrels.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([str(path), *args])
            return status, json.loads(output.getvalue())

    def test_valid_file(self):
        items = [row("q1", name) for name in ("alice", "bob")]
        items += [row("q2", name, "ABSTAIN") for name in ("alice", "bob")]
        status, report = self.run_cli({"items": items}, "--reviewers", "alice", "bob")
        self.assertEqual(status, 0)
        self.assertEqual(report["reviewer_counts"], {"alice": 2, "bob": 2})
        self.assertEqual(report["kappa"], 1)
        self.assertEqual(report["single_reviewer_items"], [])

    def test_missing_reviewer(self):
        for value in (None, "", "  ", 3):
            item = row()
            item["reviewer"] = value
            status, report = self.run_cli({"items": [item]})
            self.assertEqual(status, 1)
            self.assertIn("reviewer", report["errors"][0])
            self.assertIsNone(report["kappa"])

    def test_kappa_computation(self):
        # Marginals 3/1 and 2/2: po=.75, pe=.5, kappa=.5.
        a = ["FOUND", "FOUND", "FOUND", "ABSTAIN"]
        b = ["FOUND", "FOUND", "ABSTAIN", "ABSTAIN"]
        self.assertAlmostEqual(cohens_kappa(a, b), 0.5)
        items = [row(str(i), name, labels[i]) for i in range(4)
                 for name, labels in (("alice", a), ("bob", b))]
        items += [row("unpaired", "alice"), row("extra", "carol")]
        report = check_review({"items": items}, ("alice", "bob"))
        self.assertEqual(report["paired_items"], 4)
        self.assertEqual(report["kappa"], 0.5)

    def test_single_reviewer_flag(self):
        status, report = self.run_cli({"items": [row()]})
        self.assertEqual(status, 0)  # Incomplete coverage is a warning.
        self.assertEqual(report["single_reviewer_items"], ["q1"])
        self.assertEqual(report["kappa_status"], "UNAVAILABLE_NO_PAIRED_REVIEWS")

    def test_missing_timestamp_and_duplicate_review(self):
        item = row()
        del item["reviewed_at"]
        status, report = self.run_cli({"items": [item, row()]})
        self.assertEqual(status, 1)
        self.assertEqual(len(report["errors"]), 2)

    def test_undefined_kappa(self):
        self.assertIsNone(cohens_kappa([], []))
        self.assertIsNone(cohens_kappa(["FOUND"], ["FOUND"]))
        self.assertEqual(cohens_kappa(["FOUND"], ["ABSTAIN"]), 0)
        with self.assertRaises(ValueError):
            cohens_kappa(["FOUND"], [])

    def test_invalid_file_shape(self):
        status, report = self.run_cli({"items": "bad"})
        self.assertEqual(status, 1)
        self.assertTrue(report["errors"])


if __name__ == "__main__":
    unittest.main()
