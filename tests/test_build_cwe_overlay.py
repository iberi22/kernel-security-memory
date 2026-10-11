#!/usr/bin/env python3
"""Offline unit + end-to-end tests for build_cwe_overlay (inline fixtures).

No network: every feed is a tiny gzipped fixture the test writes itself, the
CISA feed is a real throwaway git repository in a temp directory laid out like
cisagov/vulnrichment (<year>/<block>xxx/<CVE-ID>.json), and the end-to-end cases
run the real script with --offline against a temp tree via the KSM_*_DIR env
overrides, exercising write -> check -> drift -> missing-feed exactly like the
repository acceptance gate.
"""

import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts" / "studies"))
import build_cwe_overlay as m  # noqa: E402

SCRIPT = REPO / "scripts" / "studies" / "build_cwe_overlay.py"

GIT_ENV = dict(os.environ,
               GIT_AUTHOR_NAME="test", GIT_AUTHOR_EMAIL="test@example.invalid",
               GIT_COMMITTER_NAME="test", GIT_COMMITTER_EMAIL="test@example.invalid",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)


def nvd_item(cve, primary=(), secondary=(), sentinels=()):
    """Build an NVD 2.0 CVE item shaped exactly like the real feeds."""
    weaknesses = []
    if primary:
        weaknesses.append({"source": "nvd@nist.gov", "type": "Primary",
                           "description": [{"lang": "en", "value": v} for v in primary]})
    if secondary:
        weaknesses.append({"source": "cve@mitre.org", "type": "Secondary",
                           "description": [{"lang": "en", "value": v} for v in secondary]})
    if sentinels:
        weaknesses.append({"source": "nvd@nist.gov", "type": "Primary",
                           "description": [{"lang": "en", "value": v} for v in sentinels]})
    return {"id": cve, "weaknesses": weaknesses}


def cisa_record(cve, cwe_ids=(), noinfo=False):
    """A vulnrichment CVE Record with the keys the real files carry.

    Mirrors a cisagov/vulnrichment file: the ADP list holds the mirrored
    "CVE Program Container" plus "CISA ADP Vulnrichment", and the CWE lives in
    the problemTypes description's "cweId" key.  The CNA container, as in the
    real records, only carries a text problemType and is not read.
    """
    descriptions = [{"lang": "en", "type": "CWE", "cweId": c, "description": f"{c} classification"}
                    for c in cwe_ids]
    if noinfo:
        descriptions.append({"lang": "en", "type": "text",
                             "description": "CWE-noinfo Not enough information"})
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {"cveId": cve, "state": "PUBLISHED"},
        "containers": {
            "cna": {"providerMetadata": {"shortName": "mitre"},
                    "problemTypes": [{"descriptions": [{"lang": "en", "type": "text",
                                                         "description": "n/a"}]}]},
            "adp": [
                {"title": "CVE Program Container",
                 "providerMetadata": {"shortName": "CVE"}},
                {"title": "CISA ADP Vulnrichment",
                 "providerMetadata": {"shortName": "CISA-ADP"},
                 "problemTypes": [{"descriptions": descriptions}]},
            ],
        },
    }


class TestExtractNvdCwes(unittest.TestCase):
    def test_primary_and_secondary_split_and_dedup(self):
        item = nvd_item("CVE-2021-0001", primary=["CWE-125", "CWE-787"],
                        secondary=["CWE-787"], sentinels=["NVD-CWE-Other"])
        primary, secondary, sentinels_n, distinct = m.extract_nvd_cwes(item)
        self.assertEqual(primary, ["CWE-125", "CWE-787"])
        self.assertEqual(secondary, ["CWE-787"])
        self.assertEqual(sentinels_n, 1)
        self.assertEqual(distinct, ["CWE-125", "CWE-787"])

    def test_secondary_only(self):
        item = nvd_item("CVE-2021-0002", secondary=["CWE-787"])
        primary, secondary, sentinels_n, distinct = m.extract_nvd_cwes(item)
        self.assertEqual(primary, [])
        self.assertEqual(secondary, ["CWE-787"])
        self.assertEqual(distinct, ["CWE-787"])

    def test_sentinel_only_is_no_cwe(self):
        item = nvd_item("CVE-1999-0095", sentinels=["NVD-CWE-Other"])
        primary, secondary, sentinels_n, distinct = m.extract_nvd_cwes(item)
        self.assertEqual((primary, secondary, distinct), ([], [], []))
        self.assertEqual(sentinels_n, 1)

    def test_no_weaknesses_and_junk(self):
        self.assertEqual(m.extract_nvd_cwes({})[:2], ([], []))
        junk = {"id": "CVE-X", "weaknesses": [{"type": "Primary", "description": [{"value": "nope"}, {"value": 5}]}]}
        self.assertEqual(m.extract_nvd_cwes(junk)[:2], ([], []))


class TestCisaRepoLayout(unittest.TestCase):
    """Paths match the real cisagov/vulnrichment tree (<year>/<block>xxx/)."""

    def test_relpath_matches_real_layout(self):
        # verified against `git ls-tree -r HEAD -- 2021/1999/2026` in the clone
        self.assertEqual(m.cisa_relpath("CVE-2021-3156"), "2021/3xxx/CVE-2021-3156.json")
        self.assertEqual(m.cisa_relpath("CVE-1999-0006"), "1999/0xxx/CVE-1999-0006.json")
        self.assertEqual(m.cisa_relpath("CVE-2026-9999"), "2026/9xxx/CVE-2026-9999.json")

    def test_bad_ids_have_no_path(self):
        self.assertIsNone(m.cisa_relpath("not-a-cve"))
        self.assertIsNone(m.cisa_relpath("CVE-21-1"))


class TestExtractCisaCwes(unittest.TestCase):
    def test_adp_problem_types_use_cwe_id(self):
        doc = cisa_record("CVE-2021-3156", ["CWE-193"])
        self.assertEqual(m.extract_cisa_cwes(doc), ["CWE-193"])

    def test_noinfo_text_is_not_a_cwe(self):
        doc = cisa_record("CVE-2021-3156", noinfo=True)
        self.assertEqual(m.extract_cisa_cwes(doc), [])

    def test_real_record_keeps_cwe_alongside_noinfo(self):
        doc = cisa_record("CVE-2021-3156", ["CWE-787", "CWE-125"], noinfo=True)
        self.assertEqual(m.extract_cisa_cwes(doc), ["CWE-787", "CWE-125"])

    def test_missing_or_junk(self):
        self.assertEqual(m.extract_cisa_cwes({}), [])
        self.assertEqual(m.extract_cisa_cwes({"containers": {}}), [])
        self.assertEqual(m.extract_cisa_cwes("not-a-dict"), [])
        # the real CNA-only shape (no adp container) yields nothing
        self.assertEqual(m.extract_cisa_cwes({"containers": {"cna": {"problemTypes": [
            {"descriptions": [{"lang": "en", "type": "text", "description": "n/a"}]}]}}}), [])


class TestCisaRecordCwes(unittest.TestCase):
    def test_record_for_another_id_is_rejected(self):
        doc = cisa_record("CVE-2021-3156", ["CWE-193"])
        self.assertIsNone(m.cisa_record_cwes(doc, "CVE-2021-9999"))

    def test_record_without_metadata_is_rejected(self):
        self.assertIsNone(m.cisa_record_cwes({"containers": {"adp": []}}, "CVE-2021-3156"))
        self.assertIsNone(m.cisa_record_cwes(None, "CVE-2021-3156"))

    def test_real_shaped_record_is_accepted(self):
        doc = cisa_record("CVE-2021-3156", ["CWE-193"])
        self.assertEqual(m.cisa_record_cwes(doc, "CVE-2021-3156"), ["CWE-193"])


class TestAssembleOverlayPrecedence(unittest.TestCase):
    def _targets(self):
        return {
            "CVE-2021-0001": {"year": 2021, "projects": {"linux-cna"}, "catalog_cwe": False},
            "CVE-2021-0002": {"year": 2021, "projects": {"curl"}, "catalog_cwe": False},
            "CVE-2021-0003": {"year": 2021, "projects": {"git"}, "catalog_cwe": False},
            "CVE-2021-0004": {"year": 2021, "projects": {"curl"}, "catalog_cwe": True},
        }

    def test_precedence_and_alternates(self):
        targets = self._targets()
        nvd_index = {
            "CVE-2021-0001": (["CWE-125", "CWE-787"], [], 0, ["CWE-125", "CWE-787"]),
            "CVE-2021-0002": ([], ["CWE-416"], 0, ["CWE-416"]),
        }
        # CWE-2021-0003: only secondary; CISA should win over nvd-secondary.
        cisa_index = {"CVE-2021-0003": (["CWE-20"], "cisacommit")}
        nvd_index["CVE-2021-0003"] = ([], ["CWE-476"], 0, ["CWE-476"])
        rows, by_source, resolved = m.assemble_overlay(
            targets, nvd_index, {2021: "feedsha"}, cisa_index, "cisacommit")
        by_id = {r["advisory_id"]: r for r in rows}
        self.assertEqual(by_source, {"nvd-primary": 1, "cisa-adp": 1, "nvd-secondary": 1})
        self.assertEqual(by_id["CVE-2021-0001"]["cwe"], "CWE-125")
        self.assertEqual(by_id["CVE-2021-0001"]["alternates"], 1)
        self.assertEqual(by_id["CVE-2021-0003"]["cwe"], "CWE-20")
        self.assertEqual(by_id["CVE-2021-0003"]["cwe_source"], "cisa-adp")
        # cisa-adp provenance is the vulnrichment commit SHA, not a file hash
        self.assertEqual(by_id["CVE-2021-0003"]["feed"], m.CISA_REPO_URL)
        self.assertEqual(by_id["CVE-2021-0003"]["feed_ref"], "cisacommit")
        # NVD rows keep the sha256 of the cached gz
        self.assertEqual(by_id["CVE-2021-0001"]["feed_ref"], "feedsha")
        # catalog-stated id is never overlaid
        self.assertNotIn("CVE-2021-0004", resolved)
        self.assertNotIn("CVE-2021-0004", by_id)
        # secondary-only with no CISA falls through to nvd-secondary
        rows2, by_source2, _ = m.assemble_overlay(
            targets, {**nvd_index, "CVE-2021-0002": ([], ["CWE-416"], 0, ["CWE-416"])},
            {2021: "feedsha"}, {}, "cisacommit")
        by_id2 = {r["advisory_id"]: r for r in rows2}
        self.assertEqual(by_id2["CVE-2021-0002"]["cwe_source"], "nvd-secondary")
        self.assertIn("nvd-secondary", by_source2)

    def test_cisa_loses_to_nvd_primary(self):
        targets = {"CVE-2021-0001": {"year": 2021, "projects": set(), "catalog_cwe": False}}
        nvd_index = {"CVE-2021-0001": (["CWE-125"], [], 0, ["CWE-125"])}
        cisa_index = {"CVE-2021-0001": (["CWE-193"], "cisacommit")}
        rows, by_source, _ = m.assemble_overlay(targets, nvd_index, {2021: "s"}, cisa_index, "cisacommit")
        self.assertEqual(by_source, {"nvd-primary": 1})
        self.assertEqual(rows[0]["feed_ref"], "s")

    def test_rows_sorted_and_render_roundtrips(self):
        targets = {
            "CVE-2021-0009": {"year": 2021, "projects": set(), "catalog_cwe": False},
            "CVE-2021-0002": {"year": 2021, "projects": set(), "catalog_cwe": False},
        }
        nvd_index = {"CVE-2021-0009": (["CWE-125"], [], 0, ["CWE-125"]),
                     "CVE-2021-0002": (["CWE-787"], [], 0, ["CWE-787"])}
        rows, _, _ = m.assemble_overlay(targets, nvd_index, {2021: "s"}, {}, None)
        self.assertEqual([r["advisory_id"] for r in rows], ["CVE-2021-0002", "CVE-2021-0009"])
        text = m.render_overlay(rows)
        self.assertEqual(text.count("\n"), 2)
        self.assertEqual(json.loads(text.splitlines()[0])["advisory_id"], "CVE-2021-0002")


class CisaCloneFixture(unittest.TestCase):
    """Shared temp tree: catalogs, an NVD feed fixture and a vulnrichment clone."""

    CATALOG_IDS = ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004"]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved_cisa_dir = m.CISA_CACHE_DIR
        m.CISA_CACHE_DIR = Path(self.tmp.name) / "cisa-cache"
        self.addCleanup(setattr, m, "CISA_CACHE_DIR", self._saved_cisa_dir)
        root = Path(self.tmp.name)
        self.history = root / "cve-history"
        self.cache = root / "nvd-cache"
        self.cisa_cache = m.CISA_CACHE_DIR
        self.overlay = root / "cwe-overlay.jsonl"
        self.cache.mkdir()
        proj = self.history / "linux-cna"
        proj.mkdir(parents=True)
        rows = [
            {"advisory_id": cid, "published": None, "cwe": None,
             "cwe_state": "UNKNOWN", "patch_urls": [], "fix_shas": [], "subsystem": "net"}
            for cid in self.CATALOG_IDS
        ]
        rows.append({"advisory_id": "CVE-2021-0005", "published": "2021-01-01", "cwe": "CWE-119",
                     "cwe_state": "STATED_BY_ADVISORY", "patch_urls": [], "fix_shas": [],
                     "subsystem": "net"})
        (proj / "catalog.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        feed = {"resultsPerPage": 5, "totalResults": 5, "vulnerabilities": [
            {"cve": nvd_item("CVE-2021-0001", primary=["CWE-125", "CWE-787"])},
            {"cve": nvd_item("CVE-2021-0002", secondary=["CWE-416"])},
            {"cve": nvd_item("CVE-2021-0003", sentinels=["NVD-CWE-Other"])},
            {"cve": nvd_item("CVE-2021-0004", secondary=["CWE-476"])},
            {"cve": nvd_item("CVE-2021-0005", primary=["CWE-119"])},
        ]}
        with gzip.open(self.cache / "nvdcve-2.0-2021.json.gz", "wt", encoding="utf-8") as fh:
            json.dump(feed, fh)
        self.commit = self._make_clone()

    def _make_clone(self):
        """A throwaway git repo laid out like cisagov/vulnrichment."""
        repo = self.cisa_cache / m.CISA_REPO_DIRNAME
        repo.mkdir(parents=True)
        records = {
            "CVE-2021-0002": cisa_record("CVE-2021-0002", ["CWE-415", "CWE-125"]),
            "CVE-2021-0003": cisa_record("CVE-2021-0003", noinfo=True),
            "CVE-2021-0004": cisa_record("CVE-2021-0004", ["CWE-190"]),
        }
        for cve, doc in records.items():
            rel = m.cisa_relpath(cve)
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(json.dumps(doc), encoding="utf-8")
        for args in (("init", "-q"), ("add", "-A"), ("commit", "-q", "-m", "fixture")):
            res = subprocess.run(["git", "-C", str(repo), *args], env=GIT_ENV,
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], env=GIT_ENV,
                              capture_output=True, text=True)
        return head.stdout.strip()

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args, cisa_cache=None, nvd_cache=None):
        env = dict(os.environ,
                   KSM_CVE_HISTORY_DIR=str(self.history),
                   KSM_NVD_CACHE_DIR=str(nvd_cache or self.cache),
                   KSM_CISA_CACHE_DIR=str(cisa_cache or self.cisa_cache),
                   KSM_OVERLAY_PATH=str(self.overlay))
        return subprocess.run([sys.executable, str(SCRIPT), "--offline", *args],
                              capture_output=True, text=True, env=env, cwd=self.tmp.name)

    def _rows(self):
        return [json.loads(l) for l in self.overlay.read_text().splitlines()]


class TestEndToEndOffline(CisaCloneFixture):
    """Execute the real script against a temp tree (no network)."""

    def test_check_without_nvd_cache_fails_with_message(self):
        empty = Path(self.tmp.name) / "empty-cache"
        empty.mkdir()
        # an overlay that does carry nvd rows, so the missing feed really blocks
        written = self._run()
        self.assertEqual(written.returncode, 0, written.stderr)
        run = self._run("--check", nvd_cache=empty)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn("NVD feeds", run.stderr)

    def test_check_without_cisa_clone_names_the_missing_source(self):
        empty = Path(self.tmp.name) / "empty-cisa"
        empty.mkdir()
        # first write an overlay that does contain cisa-adp rows
        written = self._run()
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertTrue(any(r["cwe_source"] == "cisa-adp" for r in self._rows()))
        run = self._run("--check", cisa_cache=empty)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn("cisa-adp", run.stderr)
        self.assertIn("vulnrichment", run.stderr)

    def test_write_then_check_then_drift(self):
        stale = self._run("--check")
        self.assertEqual(stale.returncode, 1, stale.stdout + stale.stderr)

        written = self._run()
        self.assertEqual(written.returncode, 0, written.stderr)
        rows = self._rows()
        by_id = {r["advisory_id"]: r for r in rows}
        # CVE-2021-0001 -> nvd-primary CWE-125 with 1 alternate
        self.assertEqual(by_id["CVE-2021-0001"]["cwe"], "CWE-125")
        self.assertEqual(by_id["CVE-2021-0001"]["cwe_source"], "nvd-primary")
        self.assertEqual(by_id["CVE-2021-0001"]["alternates"], 1)
        # feed_ref is the sha of the cached gz (verify independently).
        import hashlib
        expect = hashlib.sha256((self.cache / "nvdcve-2.0-2021.json.gz").read_bytes()).hexdigest()
        self.assertEqual(by_id["CVE-2021-0001"]["feed_ref"], expect)
        # CVE-2021-0002 had only nvd-secondary -> CISA ADP wins over it
        self.assertEqual(by_id["CVE-2021-0002"]["cwe"], "CWE-415")
        self.assertEqual(by_id["CVE-2021-0002"]["cwe_source"], "cisa-adp")
        self.assertEqual(by_id["CVE-2021-0002"]["feed_ref"], self.commit)
        self.assertEqual(by_id["CVE-2021-0002"]["feed"], m.CISA_REPO_URL)
        # CVE-2021-0003: NVD sentinel and CISA "CWE-noinfo" -> no row
        self.assertNotIn("CVE-2021-0003", by_id)
        # CVE-2021-0004: NVD secondary only, CISA has a CWE -> cisa-adp
        self.assertEqual(by_id["CVE-2021-0004"]["cwe"], "CWE-190")
        self.assertEqual(by_id["CVE-2021-0004"]["cwe_source"], "cisa-adp")
        # CVE-2021-0005: catalog-stated -> excluded
        self.assertNotIn("CVE-2021-0005", by_id)

        checked = self._run("--check")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("1 CVEs still UNKNOWN", checked.stdout)

        # drift: tamper with the committed overlay -> check fails
        self.overlay.write_text("", encoding="utf-8")
        drift = self._run("--check")
        self.assertEqual(drift.returncode, 1)

    def test_deterministic_two_runs_identical(self):
        self._run()
        first = self.overlay.read_text()
        self._run()
        self.assertEqual(self.overlay.read_text(), first)

    def test_no_cisa_disables_the_source_loudly(self):
        run = self._run("--no-cisa")
        self.assertEqual(run.returncode, 0, run.stderr)
        by_source = {}
        for row in self._rows():
            by_source[row["cwe_source"]] = by_source.get(row["cwe_source"], 0) + 1
        self.assertEqual(by_source, {"nvd-primary": 1, "nvd-secondary": 2})
        self.assertIn("disabled=3", run.stdout)

    def test_summary_always_names_the_cisa_source(self):
        run = self._run()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("vulnrichment", run.stdout)
        self.assertIn(f"commit={self.commit}", run.stdout)
        self.assertIn("in_repo=3", run.stdout)
        self.assertIn("rows=2", run.stdout)
        self.assertIn("no_cwe=1", run.stdout)  # CVE-2021-0003 is CWE-noinfo only


class TestBuildCisaIndexOffline(CisaCloneFixture):
    """The index builder over the fixture clone (no script subprocess)."""

    def test_index_reads_records_and_records_the_commit(self):
        index, commit, stats = m.build_cisa_index(
            ["CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004", "CVE-2021-9999"],
            offline=True, enabled=True)
        self.assertEqual(commit, self.commit)
        self.assertEqual(index["CVE-2021-0002"][0], ["CWE-415", "CWE-125"])
        self.assertEqual(index["CVE-2021-0002"][1], self.commit)
        self.assertNotIn("CVE-2021-0003", index)  # CWE-noinfo only
        self.assertEqual(index["CVE-2021-0004"][0], ["CWE-190"])
        self.assertEqual(stats["in_repo"], 3)
        self.assertEqual(stats["not_in_repo"], 1)
        self.assertEqual(stats["rows"], 2)
        self.assertEqual(stats["no_cwe"], 1)

    def test_disabled_source_is_reported_not_silent(self):
        index, commit, stats = m.build_cisa_index(
            ["CVE-2021-0002"], offline=True, enabled=False)
        self.assertEqual((index, commit), ({}, None))
        self.assertEqual(stats["disabled"], 1)
        self.assertEqual(stats["rows"], 0)

    def test_missing_clone_is_reported_not_silent(self):
        index, commit, stats = m.build_cisa_index(
            ["CVE-2021-0002"], offline=True, enabled=True)
        self.assertEqual(commit, self.commit)
        self.assertEqual(stats["rows"], 1)
        import shutil
        shutil.rmtree(self.cisa_cache)
        index, commit, stats = m.build_cisa_index(
            ["CVE-2021-0002"], offline=True, enabled=True)
        self.assertEqual((index, commit), ({}, None))
        self.assertIn("no clone at", stats["clone_error"])
        self.assertEqual(stats["not_in_repo"], 1)


if __name__ == "__main__":
    unittest.main()
