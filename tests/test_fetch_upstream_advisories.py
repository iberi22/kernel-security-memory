#!/usr/bin/env python3
"""Offline tests for fetch_upstream_advisories (curl + OpenSSL upstream feeds).

Everything runs against small inline fixtures written to a temp dir; no network
access. The CLI itself is executed as a subprocess so the tests exercise the real
artifact, not a reimplementation of it.

Not covered (no network in this suite): the HTTP fetch path and its 5 MB snapshot
guard. Those run only when the script is invoked without --offline.
"""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts/studies"))

from fetch_upstream_advisories import (  # noqa: E402
    OPENSSL_CVE_RE,
    OPENSSL_ENTRY_RE,
    OPENSSL_INDEX_URL,
    SNAPSHOT_LIMIT_BYTES,
    SNAPSHOT_SCHEMA,
    FetchError,
    _curl_rows,
    _first_sha,
    _http_get,
    _openssl_rows,
    build_catalog,
    _dump,
)

SCRIPT = REPO_ROOT / "scripts/studies/fetch_upstream_advisories.py"
ROW_KEYS = [
    "advisory_id",
    "published",
    "cwe",
    "cwe_state",
    "patch_urls",
    "fix_shas",
    "subsystem",
    "fix_sha_source",
]


def curl_fixture():
    """Three OSV records: duplicate GIT fixed, two distinct GIT ranges, SEMVER-only."""
    return [
        {
            "id": "CURL-CVE-2026-0002",
            "aliases": ["CVE-2026-0002"],
            "published": "2026-01-02T00:00:00.00Z",
            "modified": "2026-02-02T00:00:00.00Z",
            "database_specific": {
                "CWE": {"id": "CWE-125"},
                "www": "https://curl.se/docs/CVE-2026-0002.html",
            },
            "affected": [
                {"ranges": [{"type": "GIT", "events": [{"introduced": "0" * 40}, {"fixed": "a" * 40}]}]}
            ],
        },
        {
            "id": "CURL-CVE-1999-0001",
            "aliases": ["CVE-1999-0001"],
            "published": "1999-01-01T00:00:00.00Z",
            "modified": "1999-01-02T00:00:00.00Z",
            "database_specific": {
                "CWE": {"id": "CWE-119"},
                "www": "https://curl.se/docs/CVE-1999-0001.html",
            },
            "affected": [{"ranges": [{"type": "SEMVER", "events": [{"fixed": "2.0"}]}]}],
        },
        {
            "id": "CURL-CVE-2020-0003",
            "aliases": ["CVE-2020-0003"],
            "published": "2020-03-03T00:00:00.00Z",
            "modified": "2020-03-04T00:00:00.00Z",
            "database_specific": {
                "CWE": {"id": "CWE-200"},
                "www": "https://curl.se/docs/CVE-2020-0003.html",
            },
            "affected": [
                {
                    "ranges": [
                        {"type": "GIT", "events": [{"fixed": "b" * 40}]},
                        {"type": "GIT", "events": [{"fixed": "b" * 40}, {"fixed": "c" * 40}]},
                        {"type": "GIT", "events": [{"introduced": "0" * 40}]},
                    ]
                }
            ],
        },
    ]


def openssl_record(cve_id, date_public, references, problem_types=None):
    return {
        "cveMetadata": {"cveId": cve_id},
        "containers": {
            "cna": {"datePublic": date_public, "references": references, "problemTypes": problem_types}
        },
    }


def openssl_fixture_records():
    """Covers every reference shape the real OpenSSL feed publishes."""
    return [
        openssl_record(
            "CVE-2024-0001",
            "2024-05-05T10:00:00.000Z",
            [
                {"url": "https://www.openssl.org/news/secadv/20240505.txt", "tags": ["vendor-advisory"]},
                {"url": "https://github.com/openssl/openssl/commit/" + "1" * 40, "tags": ["patch"]},
            ],
            [
                {
                    "descriptions": [
                        {"cweId": "CWE-125", "description": "CWE-125"},
                        {"cweId": "CWE-787", "description": "CWE-787"},
                    ]
                }
            ],
        ),
        openssl_record(
            "CVE-2018-0003",
            "2018-11-02T00:00:00Z",
            [
                {"url": "https://www.openssl.org/news/secadv/20181112.txt", "tags": ["vendor-advisory"]},
                # real CVE-2018-5407 shape: 40 hex chars plus a stray trailing "q"
                {
                    "url": "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=" + "d" * 40 + "q",
                    "tags": ["patch"],
                },
            ],
        ),
        openssl_record(
            "CVE-2016-0006",
            "2016-06-06T00:00:00Z",
            [
                {"url": "https://www.openssl.org/news/secadv/x.txt", "tags": ["vendor-advisory"]},
                # 41 hex characters must NOT be accepted as a 40-hex commit id
                {"url": "https://github.com/openssl/openssl/commit/" + "e" * 41, "tags": ["patch"]},
            ],
        ),
        openssl_record(
            "CVE-2013-0004",
            "2013-12-14T00:00:00Z",
            [
                {
                    "url": "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ca98926",
                    "tags": ["patch"],
                },
            ],
        ),
        openssl_record(
            "CVE-2015-0005",
            "2015-05-05T00:00:00Z",
            [
                {
                    "url": "https://github.openssl.org/openssl/extended-releases/commit/" + "f" * 40,
                    "tags": ["patch"],
                },
            ],
        ),
        openssl_record(
            "CVE-2002-0002",
            "2002-07-30T00:00:00Z",
            [
                {"url": "https://www.openssl.org/news/secadv/20020730.txt", "tags": ["vendor-advisory"]},
                {"url": "https://www.openssl.org/news/secadv/20020730.txt", "tags": ["vendor-advisory"]},
                {
                    "url": "https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=" + "a" * 40,
                    "tags": ["patch"],
                },
            ],
            [{"descriptions": [{"description": "Excessive Iteration"}]}],
        ),
    ]


def openssl_snapshot_bytes(records):
    return _dump(
        {
            "schema": SNAPSHOT_SCHEMA,
            "project": "openssl",
            "source_url": OPENSSL_INDEX_URL,
            "records": records,
        }
    ).encode("utf-8")


def write_snapshot(directory, project, records):
    directory.mkdir(parents=True, exist_ok=True)
    if project == "curl":
        (directory / "source.json").write_text(json.dumps(records), encoding="utf-8")
    else:
        (directory / "source.json").write_bytes(openssl_snapshot_bytes(records))
    return directory


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


class TestCurlRows(unittest.TestCase):
    def setUp(self):
        self.rows, self.stats = _curl_rows(curl_fixture())
        self.by_id = {r["advisory_id"]: r for r in self.rows}

    def test_row_keys_and_source(self):
        for row in self.rows:
            self.assertEqual(list(row.keys()), ROW_KEYS)
            self.assertEqual(row["fix_sha_source"], "curl-upstream")
            self.assertIsNone(row["subsystem"])
            self.assertEqual(row["cwe_state"], "STATED_BY_ADVISORY")

    def test_published_is_date_only(self):
        self.assertEqual(self.by_id["CVE-1999-0001"]["published"], "1999-01-01")
        self.assertEqual(self.by_id["CVE-2026-0002"]["published"], "2026-01-02")

    def test_advisory_id_is_the_cve_alias(self):
        self.assertNotIn("CURL-CVE-2026-0002", self.by_id)
        self.assertIn("CVE-2026-0002", self.by_id)

    def test_semver_only_entry_has_no_fix_sha(self):
        row = self.by_id["CVE-1999-0001"]
        self.assertEqual(row["fix_shas"], [])
        self.assertEqual(row["patch_urls"], ["https://curl.se/docs/CVE-1999-0001.html"])

    def test_git_fixed_events_deduped_and_kept_in_feed_order(self):
        self.assertEqual(self.by_id["CVE-2020-0003"]["fix_shas"], ["b" * 40, "c" * 40])

    def test_introduced_without_fixed_is_not_a_fix(self):
        self.assertNotIn("0" * 40, self.by_id["CVE-2026-0002"]["fix_shas"])


class TestOpensslRows(unittest.TestCase):
    def setUp(self):
        self.rows, self.stats = _openssl_rows(openssl_fixture_records())
        self.by_id = {r["advisory_id"]: r for r in self.rows}

    def test_row_keys_and_source(self):
        for row in self.rows:
            self.assertEqual(list(row.keys()), ROW_KEYS)
            self.assertEqual(row["fix_sha_source"], "openssl-upstream")
            self.assertIsNone(row["subsystem"])

    def test_both_commit_url_forms_extracted(self):
        self.assertEqual(self.by_id["CVE-2002-0002"]["fix_shas"], ["a" * 40])
        # a stray character after the 40 hex characters is tolerated (CVE-2018-5407 shape)
        self.assertEqual(self.by_id["CVE-2018-0003"]["fix_shas"], ["d" * 40])

    def test_41_hex_run_rejected(self):
        self.assertEqual(self.by_id["CVE-2016-0006"]["fix_shas"], [])
        # the 41-hex id and the ca98926 short id are both dropped
        self.assertEqual(self.stats["excluded_short"], 2)

    def test_extended_releases_commit_excluded(self):
        self.assertEqual(self.by_id["CVE-2015-0005"]["fix_shas"], [])
        self.assertEqual(self.stats["excluded_extended"], 1)

    def test_short_commit_id_yields_no_row_data(self):
        row = self.by_id["CVE-2013-0004"]
        self.assertEqual(row["fix_shas"], [])
        self.assertEqual(row["patch_urls"], [])

    def test_patch_urls_deduped_and_sorted(self):
        self.assertEqual(
            self.by_id["CVE-2002-0002"]["patch_urls"],
            ["https://www.openssl.org/news/secadv/20020730.txt"],
        )

    def test_cwe_first_in_feed_order_and_multi_cwe_counted(self):
        self.assertEqual(self.by_id["CVE-2024-0001"]["cwe"], "CWE-125")
        self.assertEqual(self.by_id["CVE-2024-0001"]["cwe_state"], "STATED_BY_ADVISORY")
        self.assertIsNone(self.by_id["CVE-2002-0002"]["cwe"])
        self.assertEqual(self.by_id["CVE-2002-0002"]["cwe_state"], "UNKNOWN")
        self.assertEqual(self.stats["extra_cwe"], 1)

    def test_only_40_hex_shas_emitted(self):
        hex40 = re.compile(r"^[0-9a-f]{40}$")
        for row in self.rows:
            for sha in row["fix_shas"]:
                self.assertRegex(sha, hex40)


class TestFirstSha(unittest.TestCase):
    def test_exact_40_hex_accepted(self):
        self.assertEqual(_first_sha("https://github.com/openssl/openssl/commit/" + "a" * 40), "a" * 40)

    def test_41_hex_rejected_everywhere(self):
        self.assertIsNone(_first_sha("https://github.com/openssl/openssl/commit/" + "a" * 41))
        self.assertIsNone(
            _first_sha("https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=" + "a" * 41)
        )

    def test_non_commit_url_rejected(self):
        self.assertIsNone(_first_sha("https://www.openssl.org/news/secadv/20020730.txt"))
        self.assertIsNone(_first_sha("https://example.com/" + "a" * 40))


class TestOpensslIndexListing(unittest.TestCase):
    def test_entry_names_are_parsed(self):
        html = '<a href="cve-2002-0655.json">x</a><a href="cve-2024-9143.json">y</a>'
        self.assertEqual(sorted(set(OPENSSL_ENTRY_RE.findall(html))), ["cve-2002-0655.json", "cve-2024-9143.json"])

    def test_unexpected_entry_names_rejected(self):
        for name in ("../cve-2002-0655.json", "cve-2.json", "notes.txt", "cve-2002-0655.json.bak"):
            self.assertIsNone(OPENSSL_ENTRY_RE.fullmatch('href="' + name + '"'), name)
        self.assertFalse(OPENSSL_CVE_RE.match("not-a-year"))


class TestCatalogContract(unittest.TestCase):
    """The catalog-level guarantees that live in build_catalog, not the row builders."""

    def _catalog(self, project, records):
        directory = write_snapshot(Path(tempfile.mkdtemp()), project, records)
        snapshot = (directory / "source.json").read_bytes()
        catalog_text, index_text, rows = build_catalog(project, snapshot)
        return directory, catalog_text, index_text, rows

    def test_curl_rows_sorted_by_advisory_id(self):
        _, catalog_text, _, rows = self._catalog("curl", curl_fixture())
        self.assertEqual([r["advisory_id"] for r in rows], ["CVE-1999-0001", "CVE-2020-0003", "CVE-2026-0002"])
        self.assertEqual(
            [json.loads(line)["advisory_id"] for line in catalog_text.splitlines()],
            ["CVE-1999-0001", "CVE-2020-0003", "CVE-2026-0002"],
        )

    def test_openssl_rows_sorted_by_advisory_id(self):
        _, _, _, rows = self._catalog("openssl", openssl_fixture_records())
        self.assertEqual(
            [r["advisory_id"] for r in rows],
            ["CVE-2002-0002", "CVE-2013-0004", "CVE-2015-0005", "CVE-2016-0006", "CVE-2018-0003", "CVE-2024-0001"],
        )

    def test_index_has_required_fields_and_no_wall_clock(self):
        directory, _, index_text, rows = self._catalog("openssl", openssl_fixture_records())
        snapshot = (directory / "source.json").read_bytes()
        index = json.loads(index_text)
        self.assertEqual(index["project"], "openssl-upstream")
        self.assertEqual(index["source_url"], OPENSSL_INDEX_URL)
        self.assertEqual(index["source_snapshot"], "source.json")
        self.assertEqual(index["source_sha256"], hashlib.sha256(snapshot).hexdigest())
        self.assertEqual(index["source_bytes"], len(snapshot))
        self.assertEqual(index["fetched_at"], "2024-05-05T10:00:00.000Z")
        self.assertEqual(index["coverage"], "COMPLETE_AT_SNAPSHOT")
        self.assertEqual(index["status"], "FETCHED")
        self.assertEqual(index["entry_count"], len(rows))
        self.assertEqual(index["with_fix_sha"], 3)
        self.assertEqual(index["with_cwe"], 1)
        self.assertEqual(index["errors"], [])
        self.assertIn("docs/DATA-POLICY.md", index["notes"])

    def test_catalog_bytes_are_identical_across_rebuilds(self):
        for project, records in (("curl", curl_fixture()), ("openssl", openssl_fixture_records())):
            with self.subTest(project=project):
                directory = write_snapshot(Path(tempfile.mkdtemp()), project, records)
                snapshot = (directory / "source.json").read_bytes()
                first, first_index, _ = build_catalog(project, snapshot)
                second, second_index, _ = build_catalog(project, snapshot)
                self.assertEqual(first, second)
                self.assertEqual(first_index, second_index)

    def test_empty_snapshot_is_rejected(self):
        for project in ("curl", "openssl"):
            with self.subTest(project=project):
                directory = write_snapshot(Path(tempfile.mkdtemp()), project, [])
                with self.assertRaises(FetchError):
                    build_catalog(project, (directory / "source.json").read_bytes())

    def test_snapshot_schema_is_the_one_the_fetcher_writes(self):
        records = openssl_fixture_records()
        snapshot = openssl_snapshot_bytes(records)
        parsed = json.loads(snapshot)
        self.assertEqual(parsed["schema"], SNAPSHOT_SCHEMA)
        self.assertEqual(parsed["project"], "openssl")
        self.assertEqual(json.loads(openssl_snapshot_bytes(records))["project"], "openssl")
        self.assertEqual(parsed["source_url"], OPENSSL_INDEX_URL)
        self.assertEqual(len(parsed["records"]), len(records))


class TestCliOffline(unittest.TestCase):
    def _prepare(self, project, records):
        directory = write_snapshot(Path(tempfile.mkdtemp()) / project, project, records)
        build = run_cli("--project", project, "--out-dir", str(directory), "--offline")
        self.assertEqual(build.returncode, 0, build.stderr)
        self.assertTrue((directory / "catalog.jsonl").exists())
        self.assertTrue((directory / "index.json").exists())
        return directory

    def test_check_passes_after_build(self):
        directory = self._prepare("curl", curl_fixture())
        check = run_cli("--project", "curl", "--out-dir", str(directory), "--offline", "--check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("3 entries, 2 with fix sha, 3 with cwe", check.stdout)

    def test_check_fails_when_catalog_is_tampered(self):
        directory = self._prepare("curl", curl_fixture())
        rows = (directory / "catalog.jsonl").read_text(encoding="utf-8").splitlines()
        rows[0] = json.dumps({**json.loads(rows[0]), "cwe": "CWE-999"})
        (directory / "catalog.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
        check = run_cli("--project", "curl", "--out-dir", str(directory), "--offline", "--check")
        self.assertEqual(check.returncode, 1)
        self.assertIn("does not match snapshot", check.stderr)

    def test_check_fails_when_index_is_tampered(self):
        directory = self._prepare("openssl", openssl_fixture_records())
        index = json.loads((directory / "index.json").read_text(encoding="utf-8"))
        index["status"] = "PARTIAL"
        (directory / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        check = run_cli("--project", "openssl", "--out-dir", str(directory), "--offline", "--check")
        self.assertEqual(check.returncode, 1)
        self.assertIn("does not match snapshot", check.stderr)

    def test_check_fails_when_catalog_is_missing(self):
        directory = self._prepare("openssl", openssl_fixture_records())
        (directory / "catalog.jsonl").unlink()
        check = run_cli("--project", "openssl", "--out-dir", str(directory), "--offline", "--check")
        self.assertEqual(check.returncode, 1)
        self.assertIn("missing", check.stderr)

    def test_missing_snapshot_fails(self):
        check = run_cli(
            "--project", "curl", "--out-dir", str(Path(tempfile.mkdtemp()) / "nope"), "--offline", "--check"
        )
        self.assertEqual(check.returncode, 1)
        self.assertIn("not found", check.stderr)

    def test_source_override(self):
        source = write_snapshot(Path(tempfile.mkdtemp()) / "snapshots", "curl", curl_fixture()) / "source.json"
        out = Path(tempfile.mkdtemp()) / "out"
        out.mkdir()
        build = run_cli("--project", "curl", "--out-dir", str(out), "--offline", "--source", str(source))
        self.assertEqual(build.returncode, 0, build.stderr)
        check = run_cli(
            "--project", "curl", "--out-dir", str(out), "--offline", "--source", str(source), "--check"
        )
        self.assertEqual(check.returncode, 0, check.stderr)


class TestSnapshotGuard(unittest.TestCase):
    """The 5 MB cap is enforced on the socket read, not by trusting the header."""

    def test_oversized_response_rejected(self):
        oversized = b"x" * (SNAPSHOT_LIMIT_BYTES + 1)

        class FakeResponse:
            def read(self, size=-1):
                return oversized[:size]

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        original = urllib.request.urlopen
        urllib.request.urlopen = lambda *args, **kwargs: FakeResponse()
        try:
            with self.assertRaises(FetchError) as caught:
                _http_get("https://curl.se/docs/vuln.json")
        finally:
            urllib.request.urlopen = original
        self.assertIn("exceeds", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
