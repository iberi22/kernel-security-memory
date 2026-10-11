"""evaluate_release: same-project dating and cross-project alarms on hand-written fingerprints."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "fingerprints"))

from evaluate_release import evaluate  # noqa: E402


def fn(name, kgrams, mh):
    return {"name": name, "start_line": 1, "end_line": 50, "node_count": 100,
            "kgrams": dict(kgrams), "minhash": [mh] * 64, "calls": [], "guards": [], "vars": []}


def pair(adv, project, before, after):
    return {"schema": "ksm-fixfp/1", "advisory_id": adv, "project": project, "repo": "o/r",
            "fix_sha": "a" * 40, "cwe": None,
            "files": [{"path": "x.c", "functions": [{"name": before["name"], "before": before,
                                                       "after": after, "delta": {}}]}]}


class TestEvaluate(unittest.TestCase):
    def test_same_project_dating_and_cross_project_alarms(self):
        corpus = [
            pair("CVE-2030-0001", "curl-upstream", fn("f", {"aa": 4}, 1), fn("f", {"zz": 4}, 1)),
            pair("CVE-2001-0001", "curl", fn("g", {"bb": 4}, 2), fn("g", {"yy": 4}, 2)),
            pair("CVE-2030-0002", "openssl", fn("h", {"cc": 4}, 3), fn("h", {"xx": 4}, 3)),
        ]
        docs = [{"schema": "ksm-sfp/1", "file": "src/a.c",
                 "functions": [fn("f", {"aa": 4}, 1), fn("g", {"bb": 4}, 2), fn("k", {"cc": 4}, 3)]}]
        dates = {("curl", "CVE-2030-0001"): "2030-01-01", ("curl", "CVE-2001-0001"): "2001-01-01"}
        r = evaluate(docs, corpus, "curl", "2016-07-21", dates)
        self.assertEqual((r["corpus_own_fixes"], r["corpus_other_fixes"]), (2, 1))
        self.assertEqual(r["same_project_strong"], 2)
        self.assertEqual(r["same_project_strong_fixed_after_release"], 1)
        self.assertEqual(r["cross_project_strong"], 1)
        self.assertEqual(r["cross_project_examples"][0]["advisory_id"], "CVE-2030-0002")
        self.assertEqual(r["cross_project_strong_per_1000_functions"], 333.333)


if __name__ == "__main__":
    unittest.main()
