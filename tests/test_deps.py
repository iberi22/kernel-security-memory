"""Tests for `ksm deps`: lockfile parsing, OSV batching/caching, CLI wiring.

No network: every test injects a fake OSV HTTP function.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from ksm.cli import main
from ksm.deps import (
    MAX_QUERIES_PER_REQUEST,
    Dependency,
    OsvClient,
    _build_finding,
    _select_fixed,
    discover_lockfiles,
    format_human,
    parse_cargo_lock,
    parse_go_sum,
    parse_package_lock,
    parse_pnpm_lock,
    parse_requirements,
    run_deps,
)

FIXTURES = Path(__file__).parent / "fixtures" / "deps"

VULN_STUB = {
    "id": "GHSA-cargo-leftpad-0001",
    "aliases": ["CVE-2024-0001"],
    "summary": "leftpad pads too much (test fixture)",
}

VULN_DETAIL = {
    "id": "GHSA-cargo-leftpad-0001",
    "aliases": ["CVE-2024-0001"],
    "summary": "leftpad pads too much (test fixture)",
    "affected": [
        {
            "package": {"name": "leftpad", "ecosystem": "crates.io"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.3.2"}]}
            ],
        }
    ],
}


class FakeOsv:
    """Canned OSV HTTP: querybatch answered from a (ecosystem, name, version)
    map, /v1/vulns/<id> from an id map. Records every request."""

    def __init__(self, vulns_by_query=None, details=None):
        self.vulns_by_query = vulns_by_query or {}
        self.details = details or {}
        self.posts = []
        self.gets = []

    def post_json(self, url, payload):
        self.posts.append(payload)
        results = []
        for query in payload.get("queries", []):
            pkg = query.get("package", {})
            key = (pkg.get("ecosystem"), pkg.get("name"), query.get("version"))
            results.append({"vulns": [dict(v) for v in self.vulns_by_query.get(key, [])]})
        return {"results": results}

    def get_json(self, url):
        self.gets.append(url)
        vid = url.rsplit("/", 1)[-1]
        return self.details.get(vid, {"id": vid})

    @property
    def query_count(self):
        return sum(len(p.get("queries", [])) for p in self.posts)


def leftpad_vuln_fake():
    return FakeOsv(
        vulns_by_query={("crates.io", "leftpad", "0.3.1"): [VULN_STUB]},
        details={"GHSA-cargo-leftpad-0001": VULN_DETAIL},
    )


class TestParseLockfiles(unittest.TestCase):
    def test_cargo_lock_registry_only(self):
        deps = parse_cargo_lock((FIXTURES / "cargo_app" / "Cargo.lock").read_text())
        self.assertEqual(
            deps,
            [
                Dependency("crates.io", "leftpad", "0.3.1"),
                Dependency("crates.io", "tiny-tools", "1.0.0"),
            ],
        )

    def test_package_lock_v3(self):
        data = json.loads((FIXTURES / "npm_app" / "package-lock.json").read_text())
        deps = parse_package_lock(data)
        self.assertEqual(
            deps,
            [
                Dependency("npm", "tiny-pkg", "1.2.3"),
                Dependency("npm", "@scope/inner", "2.0.0"),
            ],
        )

    def test_package_lock_v1_nested(self):
        data = {
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "outer": {
                    "version": "1.0.0",
                    "dependencies": {"inner": {"version": "2.0.0"}},
                },
                "solo": {"version": "3.0.0"},
            },
        }
        deps = parse_package_lock(data)
        self.assertEqual(
            deps,
            [
                Dependency("npm", "inner", "2.0.0"),
                Dependency("npm", "outer", "1.0.0"),
                Dependency("npm", "solo", "3.0.0"),
            ],
        )

    def test_pnpm_lock_v9(self):
        deps = parse_pnpm_lock((FIXTURES / "pnpm_app" / "pnpm-lock.yaml").read_text())
        self.assertEqual(
            deps,
            [
                Dependency("npm", "@scope/ui-kit", "2.1.0"),
                Dependency("npm", "leftpad", "0.3.1"),
                Dependency("npm", "react", "19.2.3"),
                Dependency("npm", "react-dom", "19.2.3"),
                Dependency("npm", "only-peer", "1.0.0"),
            ],
        )

    def test_pnpm_lock_v6_column_zero_keys(self):
        text = (
            "lockfileVersion: '6.0'\n"
            "\n"
            "packages:\n"
            "\n"
            "  leftpad@0.3.1:\n"
            "    resolution: {integrity: sha512-xxx}\n"
            "\n"
            "snapshots:\n"
            "\n"
            "  leftpad@0.3.1: {}\n"
        )
        deps = parse_pnpm_lock(text)
        self.assertEqual(deps, [Dependency("npm", "leftpad", "0.3.1")])

    def test_requirements_exact_pins_only(self):
        deps = parse_requirements((FIXTURES / "pypi_app" / "requirements.txt").read_text())
        self.assertEqual(
            deps,
            [
                Dependency("PyPI", "leftpad", "0.3.1"),
                Dependency("PyPI", "some-pkg-name", "2.0"),
                Dependency("PyPI", "uvicorn", "0.30.0"),
            ],
        )

    def test_go_sum(self):
        deps = parse_go_sum((FIXTURES / "go_app" / "go.sum").read_text())
        self.assertEqual(
            deps,
            [
                Dependency("Go", "example.com/mod", "v1.2.3"),
                Dependency("Go", "example.com/legacy", "v1.0.0"),
                Dependency("Go", "github.com/foo/bar", "v0.0.0-20200101000000-abcdef1234567890"),
            ],
        )

    def test_discover_lockfiles_skips_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for d in ("node_modules", "target", "vendor", ".git", "dist", "build"):
                (root / d).mkdir()
                (root / d / "Cargo.lock").write_text("")
            (root / "Cargo.lock").write_text("")
            self.assertEqual(discover_lockfiles(root), [root / "Cargo.lock"])

    def test_discover_lockfiles_finds_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sub").mkdir()
            (root / "requirements.txt").write_text("leftpad==0.3.1\n")
            (root / "sub" / "requirements-dev.txt").write_text("pytest==8.0.0\n")
            found = discover_lockfiles(root)
            self.assertEqual(
                found,
                [root / "requirements.txt", root / "sub" / "requirements-dev.txt"],
            )


class TestOsvClient(unittest.TestCase):
    def test_batching_over_1000(self):
        queries = [
            {"package": {"name": f"pkg-{i}", "ecosystem": "crates.io"}, "version": "1.0.0"}
            for i in range(2500)
        ]
        fake = FakeOsv()
        client = OsvClient(post_json=fake.post_json, get_json=fake.get_json)
        results = client.querybatch(queries)
        self.assertEqual(len(results), 2500)
        self.assertEqual([len(r) for r in results], [0] * 2500)
        self.assertEqual(len(fake.posts), 3)
        sizes = [len(p["queries"]) for p in fake.posts]
        self.assertEqual(sizes, [1000, 1000, 500])
        self.assertTrue(all(s <= MAX_QUERIES_PER_REQUEST for s in sizes))

    def test_pagination_token(self):
        class PagingFake:
            def __init__(self):
                self.calls = 0

            def post_json(self, url, payload):
                self.calls += 1
                results = []
                for query in payload["queries"]:
                    if query.get("page_token") == "page-2":
                        results.append({"vulns": [{"id": "VULN-2"}]})
                    else:
                        results.append({"vulns": [{"id": "VULN-1"}], "next_page_token": "page-2"})
                return {"results": results}

            def get_json(self, url):
                return {"id": url.rsplit("/", 1)[-1]}

        fake = PagingFake()
        client = OsvClient(post_json=fake.post_json, get_json=fake.get_json)
        query = {"package": {"name": "leftpad", "ecosystem": "crates.io"}, "version": "0.3.1"}
        results = client.querybatch([query])
        self.assertEqual(results, [[{"id": "VULN-1"}, {"id": "VULN-2"}]])
        self.assertEqual(fake.calls, 2)

    def test_cache_hit_and_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "osv-cache"
            fake = FakeOsv()
            query = [{"package": {"name": "leftpad", "ecosystem": "crates.io"}, "version": "0.3.1"}]
            client = OsvClient(cache_dir=cache_dir, post_json=fake.post_json, get_json=fake.get_json)
            client.querybatch(query)
            client.querybatch(query)
            self.assertEqual(len(fake.posts), 1)
            self.assertEqual(client.cache_hits, 1)
            refresh_client = OsvClient(
                cache_dir=cache_dir, refresh=True, post_json=fake.post_json, get_json=fake.get_json
            )
            refresh_client.querybatch(query)
            self.assertEqual(len(fake.posts), 2)


class TestFindings(unittest.TestCase):
    def test_fixed_version_selection_smallest_greater(self):
        self.assertEqual(_select_fixed(["0.3.2", "0.4.0", "0.2.9"], "0.3.1"), "0.3.2")

    def test_fixed_version_selection_fallback_list(self):
        self.assertEqual(_select_fixed(["0.2.0", "0.1.0"], "9.9.9"), ["0.1.0", "0.2.0"])

    def test_fixed_version_selection_none(self):
        self.assertEqual(_select_fixed([], "1.0.0"), [])

    def test_build_finding_fields(self):
        finding = _build_finding(
            Path("/repo/Cargo.lock"),
            Dependency("crates.io", "leftpad", "0.3.1"),
            VULN_STUB,
            VULN_DETAIL,
        )
        self.assertEqual(finding["id"], "GHSA-cargo-leftpad-0001")
        self.assertEqual(finding["lockfile"], "/repo/Cargo.lock")
        self.assertEqual(finding["ecosystem"], "crates.io")
        self.assertEqual(finding["package"], "leftpad")
        self.assertEqual(finding["version"], "0.3.1")
        self.assertEqual(finding["aliases"], ["CVE-2024-0001"])
        self.assertEqual(finding["summary"], VULN_DETAIL["summary"])
        self.assertEqual(finding["url"], "https://osv.dev/vulnerability/GHSA-cargo-leftpad-0001")
        self.assertEqual(finding["fixed_version"], "0.3.2")
        self.assertNotIn("severity", finding)

    def test_same_dep_in_two_lockfiles_queried_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            lock = (FIXTURES / "cargo_app" / "Cargo.lock").read_text()
            (root / "a" / "Cargo.lock").write_text(lock)
            (root / "b" / "Cargo.lock").write_text(lock)
            fake = leftpad_vuln_fake()
            findings = run_deps(root, client=fake)
            self.assertEqual(fake.query_count, 2)
            self.assertEqual(len(findings), 2)
            self.assertEqual(
                {f["lockfile"] for f in findings},
                {str(root / "a" / "Cargo.lock"), str(root / "b" / "Cargo.lock")},
            )

    def test_format_human_empty(self):
        self.assertEqual(
            format_human([]), "No known vulnerabilities found in locked dependencies."
        )


class TestCliDeps(unittest.TestCase):
    def run_cli(self, args):
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(args)
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_no_lockfile_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self.run_cli(["deps", tmp, "--data-dir", tmp])
            self.assertEqual(code, 2)
            self.assertIn("Cargo.lock", err)
            self.assertIn("go.sum", err)
            self.assertIn("requirements", err)

    def test_missing_path_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self.run_cli(
                ["deps", str(Path(tmp) / "does-not-exist"), "--data-dir", tmp]
            )
            self.assertEqual(code, 2)
            self.assertIn("does not exist", err)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = leftpad_vuln_fake()
            with mock.patch("ksm.deps._default_post_json", fake.post_json), \
                 mock.patch("ksm.deps._default_get_json", fake.get_json):
                code, out, err = self.run_cli(
                    ["deps", str(FIXTURES / "cargo_app"), "--data-dir", tmp, "--json"]
                )
            self.assertEqual(code, 0)
            data = json.loads(out)
            self.assertEqual(len(data), 1)
            finding = data[0]
            self.assertEqual(finding["id"], "GHSA-cargo-leftpad-0001")
            self.assertEqual(finding["package"], "leftpad")
            self.assertEqual(finding["version"], "0.3.1")
            self.assertEqual(finding["ecosystem"], "crates.io")
            self.assertEqual(finding["url"], "https://osv.dev/vulnerability/GHSA-cargo-leftpad-0001")
            self.assertEqual(finding["fixed_version"], "0.3.2")
            self.assertEqual(finding["aliases"], ["CVE-2024-0001"])

    def test_human_output_grouped_with_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = leftpad_vuln_fake()
            with mock.patch("ksm.deps._default_post_json", fake.post_json), \
                 mock.patch("ksm.deps._default_get_json", fake.get_json):
                code, out, err = self.run_cli(
                    ["deps", str(FIXTURES / "cargo_app"), "--data-dir", tmp]
                )
            self.assertEqual(code, 0)
            self.assertIn("leftpad", out)
            self.assertIn("0.3.1", out)
            self.assertIn("GHSA-cargo-leftpad-0001", out)
            self.assertIn("1 finding(s)", out)

    def test_strict_exit_1_with_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = leftpad_vuln_fake()
            with mock.patch("ksm.deps._default_post_json", fake.post_json), \
                 mock.patch("ksm.deps._default_get_json", fake.get_json):
                code, out, err = self.run_cli(
                    ["deps", str(FIXTURES / "cargo_app"), "--data-dir", tmp, "--strict"]
                )
            self.assertEqual(code, 1)

    def test_strict_exit_0_without_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeOsv()
            with mock.patch("ksm.deps._default_post_json", fake.post_json), \
                 mock.patch("ksm.deps._default_get_json", fake.get_json):
                code, out, err = self.run_cli(
                    ["deps", str(FIXTURES / "cargo_app"), "--data-dir", tmp, "--strict"]
                )
            self.assertEqual(code, 0)

    def test_refresh_bypasses_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = leftpad_vuln_fake()
            with mock.patch("ksm.deps._default_post_json", fake.post_json), \
                 mock.patch("ksm.deps._default_get_json", fake.get_json):
                self.run_cli(["deps", str(FIXTURES / "cargo_app"), "--data-dir", tmp])
                self.assertEqual(len(fake.posts), 1)
                self.run_cli(["deps", str(FIXTURES / "cargo_app"), "--data-dir", tmp])
                self.assertEqual(len(fake.posts), 1)  # cache hit, no new request
                self.run_cli(["deps", str(FIXTURES / "cargo_app"), "--data-dir", tmp, "--refresh"])
                self.assertEqual(len(fake.posts), 2)


class TestAliasMerge(unittest.TestCase):
    def test_rustsec_and_ghsa_twins_become_one_finding(self):
        from ksm.deps import merge_aliases
        base = {"lockfile": "Cargo.lock", "ecosystem": "crates.io", "package": "w", "version": "1.0.0",
                "summary": "", "url": ""}
        findings = [
            dict(base, id="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2031-1", "RUSTSEC-2031-0001"],
                 fixed_versions=["1.0.2"], fixed_version="1.0.2", severity="CVSS:3.1/AV:N"),
            dict(base, id="RUSTSEC-2031-0001", aliases=["CVE-2031-1", "GHSA-aaaa-bbbb-cccc"],
                 fixed_versions=["1.0.1"], fixed_version="1.0.1"),
            dict(base, id="RUSTSEC-2031-0002", aliases=[], fixed_versions=[], fixed_version=None),
        ]
        merged = sorted(merge_aliases(findings), key=lambda f: f["id"])
        self.assertEqual([f["id"] for f in merged], ["RUSTSEC-2031-0001", "RUSTSEC-2031-0002"])
        self.assertEqual(merged[0]["aliases"], ["CVE-2031-1", "GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(merged[0]["fixed_version"], "1.0.1")
        self.assertEqual(merged[0]["severity"], "CVSS:3.1/AV:N")


if __name__ == "__main__":
    unittest.main()
