#!/usr/bin/env python3
"""Regression tests for the four defects found in the 12 NVD history fetchers.

Each test below fails on the pre-fix code:

1. ``window.end`` was the frozen literal ``2026-10-08`` -> ``test_window_end``.
2. ``catalog.jsonl`` / ``index.json`` were written with ``open(path, "w")`` and
   a truncated file was silently loaded as an empty catalog ->
   ``test_writes_are_atomic``, ``test_corrupt_state_is_fatal``,
   ``test_cli_exits_non_zero_on_corrupt_state``.
3. ``fetch_history_linux.py`` re-fetched a COMPLETE window and wrote an
   INCOMPLETE cursor at 1999-01-01 before its first call ->
   ``test_complete_window_is_not_re_fetched``.
4. An error recorded by a previous run blocked every later one ->
   ``test_previous_run_errors_do_not_block`` (with
   ``test_this_run_errors_still_pause`` proving the fix did not simply drop
   error reporting).

No test touches the network: NVD responses are faked and ``time.sleep`` is
patched.
"""

import builtins
import contextlib
import datetime
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "studies"))

import fetcher_io  # noqa: E402  (needs the sys.path tweak above)

PROJECTS = ("curl", "git", "glibc", "linux", "nginx", "openssh",
            "openssl", "postgresql", "qemu", "sqlite", "systemd", "unbound")

RUN_DATE = "2027-03-04"          # injected through KSM_TODAY
LAST_SLICE_START = "2026-10-12"  # last 90-day slice before RUN_DATE is 2026-10-12
CARRIED_ERROR = "Fetch error: The read operation timed out"
EMPTY_PAGE = {"vulnerabilities": [], "totalResults": 0}


class FakeNvdResponse:
    """Minimal context manager for fetcher_io-free code paths (linux)."""

    def __init__(self, payload=b'{"vulnerabilities": [], "totalResults": 0}'):
        self._payload = payload
        self.status = 200

    def read(self, _size=-1):
        chunk, self._payload = self._payload, b""
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def fetch_module(project):
    return importlib.import_module(f"fetch_history_{project}")


def is_linux(module):
    """fetch_history_linux.py keeps its paths in module globals, not in a parameter."""
    return module.__name__.endswith("linux")


def path_patches(module, out_dir):
    """Patches that pin a fetcher's output directory to ``out_dir``."""
    out = Path(out_dir)
    if is_linux(module):
        return [
            mock.patch.object(module, "INDEX_PATH", str(out / "index.json")),
            mock.patch.object(module, "CATALOG_PATH", str(out / "catalog.jsonl")),
        ]
    return []  # the other 11 take --out-dir / an out_dir argument


def run_fetch(project, out_dir, *, error=None, max_calls=None):
    """Run one fetch with faked NVD responses and no sleeping.

    Returns (index dict, list of requested URLs).
    """
    module = fetch_module(project)
    urls = []
    out = Path(out_dir)
    index_path, catalog_path = out / "index.json", out / "catalog.jsonl"

    def fake_request(url, cumulative_bytes):
        urls.append(url)
        if error is not None:
            raise error
        return dict(EMPTY_PAGE)

    def fake_urlopen(_req, timeout=None):
        urls.append("linux-slice")
        if error is not None:
            raise error
        return FakeNvdResponse()

    with contextlib.ExitStack() as stack:
        for patch in path_patches(module, out):
            stack.enter_context(patch)
        if not is_linux(module):
            stack.enter_context(mock.patch.object(module, "make_nvd_request", side_effect=fake_request))
        stack.enter_context(mock.patch("urllib.request.urlopen", side_effect=fake_urlopen))
        stack.enter_context(mock.patch("time.sleep"))
        stack.enter_context(redirect_stdout(io.StringIO()))
        if is_linux(module):
            module.fetch_history(max_calls=max_calls if max_calls is not None else 1000)
        else:
            module.fetch_nvd_data(str(out), max_time_seconds=10 ** 6)
    return json.loads(index_path.read_text(encoding="utf-8")), urls


def write_index(out_dir, **overrides):
    payload = {
        "schema_version": "cve-history-v1",
        "project": "stub",
        "window": {"start": "1999-01-01", "end": "2026-10-08"},
        "coverage": "INCOMPLETE",
        "status": "CURSOR_PAUSED",
        "cursor_date": LAST_SLICE_START,
        "window_closed": False,
        "entry_count": 0,
        "with_fix_sha": 0,
        "requests": 19,
        "resume": {"next_start_date": LAST_SLICE_START},
        "errors": [],
        "notes": "stub",
    }
    payload.update(overrides)
    path = Path(out_dir) / "index.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


class FetcherHardeningTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"KSM_TODAY": RUN_DATE})
        patcher.start()
        self.addCleanup(patcher.stop)

    def fetch(self, project, **kwargs):
        return run_fetch(project, self.out_dir, **kwargs)


class TestWindowEndIsTheRunDate(FetcherHardeningTestBase):
    def test_window_end_is_the_run_date_and_the_scan_reaches_it(self):
        for project in PROJECTS:
            with self.subTest(project=project):
                with tempfile.TemporaryDirectory() as tmp:
                    index, urls = run_fetch(project, tmp)
                    self.assertEqual(index["window"],
                                     {"start": "1999-01-01", "end": RUN_DATE})
                    # The scan really reached the run date, not a frozen end.
                    self.assertGreater(len(urls), 0)
                    last = urls[-1]
                    if last != "linux-slice":
                        query = urllib.parse.parse_qs(urllib.parse.urlparse(last).query)
                        self.assertEqual(query["pubEndDate"], [f"{RUN_DATE}T23:59:59.999"])
                    self.assertEqual(index["coverage"], "COMPLETE")
                    # The committed catalogs record the date they were built on,
                    # so an older value must stay valid.
                    self.assertTrue(fetcher_io.check_window(index["window"])[0])


class TestAtomicWrites(FetcherHardeningTestBase):
    def test_no_fetcher_ever_truncates_a_committed_file(self):
        for project in PROJECTS:
            with self.subTest(project=project):
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp)
                    opened_for_write, replaced = [], []
                    real_open, real_replace = builtins.open, os.replace

                    committed = {"index.json", "catalog.jsonl"}

                    def spy_open(file, mode="r", *args, **kwargs):
                        if any(flag in mode for flag in ("w", "a", "x", "+")):
                            name = Path(file).name
                            if name in committed:
                                opened_for_write.append(name)
                        return real_open(file, mode, *args, **kwargs)

                    def spy_replace(src, dst):
                        replaced.append((Path(src).name, Path(dst).name))
                        return real_replace(src, dst)

                    with mock.patch("builtins.open", side_effect=spy_open), \
                         mock.patch("os.replace", side_effect=spy_replace):
                        run_fetch(project, tmp)

                    self.assertEqual(opened_for_write, [],
                                     f"{project} opened a committed file for writing")
                    destinations = [dst for _, dst in replaced]
                    self.assertTrue(destinations, f"{project} wrote nothing")
                    self.assertEqual(destinations[0], "catalog.jsonl")
                    # Every index.json is published after (and only after) the
                    # catalog it describes, however many times the run persists.
                    for position, destination in enumerate(destinations):
                        if destination == "index.json":
                            self.assertEqual(destinations[position - 1], "catalog.jsonl",
                                             f"{project} published the index before the catalog")
                    # Every replace moved a temp sibling, never the target itself.
                    self.assertTrue(all(src != dst for src, dst in replaced), replaced)
                    leftovers = sorted(p.name for p in out.iterdir()
                                       if p.name not in ("index.json", "catalog.jsonl"))
                    self.assertEqual(leftovers, [], f"{project} left temp files behind")
                    self.assertTrue((out / "catalog.jsonl").is_file())
                    self.assertTrue((out / "index.json").is_file())

    def test_helper_leaves_the_previous_file_intact_when_the_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "index.json"
            fetcher_io.write_text_atomic(index, '{"kept": 1}\n')
            with mock.patch("os.replace", side_effect=OSError("no space left on device")):
                with self.assertRaises(OSError):
                    fetcher_io.write_text_atomic(index, '{"kept": 2}\n')
            self.assertEqual(index.read_text(encoding="utf-8"), '{"kept": 1}\n')
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["index.json"])


class TestCorruptStateIsFatal(FetcherHardeningTestBase):
    def test_truncated_index_is_fatal_instead_of_being_rewritten(self):
        for project in PROJECTS:
            with self.subTest(project=project):
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp)
                    out.mkdir(parents=True, exist_ok=True)
                    (out / "index.json").write_text('{"schema_version": "cve-history-v1", "requ', encoding="utf-8")
                    (out / "catalog.jsonl").write_text("", encoding="utf-8")
                    module = fetch_module(project)
                    with self.assertRaises(fetcher_io.CorruptStateError):
                        with contextlib.ExitStack() as stack:
                            for patch in path_patches(module, out):
                                stack.enter_context(patch)
                            stack.enter_context(mock.patch("time.sleep"))
                            if is_linux(module):
                                module.fetch_history(max_calls=1)
                            else:
                                module.fetch_nvd_data(str(out), max_time_seconds=60)

    def test_truncated_catalog_line_is_fatal_instead_of_being_rewritten(self):
        for project in PROJECTS:
            with self.subTest(project=project):
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp)
                    out.mkdir(parents=True, exist_ok=True)
                    write_index(out)
                    (out / "catalog.jsonl").write_text(
                        '{"advisory_id": "CVE-2020-0001", "published": "2020-01-01"}\n'
                        '{"advisory_id": "CVE-2020-0002", "pub',
                        encoding="utf-8",
                    )
                    module = fetch_module(project)
                    with self.assertRaises(fetcher_io.CorruptStateError):
                        with contextlib.ExitStack() as stack:
                            for patch in path_patches(module, out):
                                stack.enter_context(patch)
                            stack.enter_context(mock.patch("time.sleep"))
                            if is_linux(module):
                                module.fetch_history(max_calls=1)
                            else:
                                module.fetch_nvd_data(str(out), max_time_seconds=60)

    def test_cli_exits_non_zero_with_the_file_named(self):
        studies = ROOT / "scripts" / "studies"
        for project in PROJECTS:
            with self.subTest(project=project):
                with tempfile.TemporaryDirectory() as tmp:
                    if project == "linux":
                        target = Path(tmp) / "docs" / "studies" / "cve-history" / "linux"
                        target.mkdir(parents=True)
                        (target / "index.json").write_text('{"project": "linux", "window"', encoding="utf-8")
                        (target / "catalog.jsonl").write_text("", encoding="utf-8")
                        argv = [sys.executable, str(studies / "fetch_history_linux.py"),
                                "--fetch", "--max-calls", "1"]
                        cwd = tmp
                    else:
                        target = Path(tmp)
                        (target / "index.json").write_text('{"project": "x", "requ', encoding="utf-8")
                        argv = [sys.executable, str(studies / f"fetch_history_{project}.py"),
                                "--fetch", "--out-dir", str(target), "--max-time", "5"]
                        cwd = ROOT
                    proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=120)
                    self.assertNotEqual(proc.returncode, 0, f"{project} accepted a corrupt index")
                    self.assertIn("corrupt", (proc.stdout + proc.stderr).lower())
                    self.assertIn("index.json", proc.stdout + proc.stderr)


class TestErrorsDoNotBlockLaterRuns(FetcherHardeningTestBase):
    def test_previous_run_errors_do_not_block(self):
        for project in PROJECTS:
            with self.subTest(project=project):
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp)
                    write_index(out, errors=[CARRIED_ERROR])
                    (out / "catalog.jsonl").write_text("", encoding="utf-8")
                    index, urls = run_fetch(project, tmp)

                    self.assertGreater(len(urls), 0, f"{project} fetched nothing")
                    self.assertEqual(index["coverage"], "COMPLETE",
                                     f"{project} stalled on a previous run's error")
                    self.assertEqual(index["errors"], [], "this run had no error")
                    self.assertIn(CARRIED_ERROR, index["error_history"],
                                  "the old error was silently dropped")

    def test_this_run_errors_still_pause_and_are_recorded(self):
        for project in PROJECTS:
            with self.subTest(project=project):
                with tempfile.TemporaryDirectory() as tmp:
                    index, urls = run_fetch(project, tmp, error=RuntimeError("simulated NVD outage"))

                    self.assertGreater(len(urls), 0)
                    self.assertEqual(index["coverage"], "INCOMPLETE")
                    self.assertTrue(index["errors"], "this run's error must be reported")
                    self.assertTrue(any("simulated NVD outage" in e for e in index["errors"]),
                                    index["errors"])
                    self.assertTrue(any("simulated NVD outage" in e for e in index["error_history"]),
                                    index["error_history"])
                    self.assertIsNotNone(index["resume"])


class TestLinuxCompleteWindow(unittest.TestCase):
    """fetch_history_linux.py is the one fetcher with its own loop."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"KSM_TODAY": "2026-10-12"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, module):
        with mock.patch.object(module, "INDEX_PATH", str(self.out_dir / "index.json")), \
             mock.patch.object(module, "CATALOG_PATH", str(self.out_dir / "catalog.jsonl")), \
             mock.patch("urllib.request.urlopen", side_effect=FakeNvdResponse()), \
             mock.patch("time.sleep"), \
             redirect_stdout(io.StringIO()) as out:
            result = module.fetch_history(max_calls=1000)
        return result, out.getvalue()

    def test_complete_window_is_not_re_fetched_or_rewound(self):
        module = fetch_module("linux")
        record = {"advisory_id": "CVE-2020-1234", "published": "2020-01-01"}
        (self.out_dir / "catalog.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
        index_path = write_index(
            self.out_dir,
            project="linux",
            coverage="COMPLETE",
            status="COMPLETE",
            cursor_date=None,
            window_closed=True,
            entry_count=1,
            requests=113,
            resume=None,
        )
        before = index_path.read_text(encoding="utf-8")

        with mock.patch("urllib.request.urlopen") as urlopen:
            result, output = self._run(module)

        urlopen.assert_not_called()
        self.assertTrue(result)
        self.assertIn("already COMPLETE", output)
        # The recorded state survives untouched: no INCOMPLETE cursor at
        # 1999-01-01, no reset of the lifetime request counter.
        after = json.loads(index_path.read_text(encoding="utf-8"))
        self.assertEqual(after["coverage"], "COMPLETE")
        self.assertIsNone(after["resume"])
        self.assertEqual(after["requests"], 113)
        self.assertEqual(after["entry_count"], 1)
        self.assertEqual(before, index_path.read_text(encoding="utf-8"))


class TestFetcherIoHelpers(unittest.TestCase):
    def test_resolve_run_date_prefers_the_injected_date(self):
        self.assertEqual(fetcher_io.resolve_run_date("2031-02-03"), datetime.date(2031, 2, 3))
        with mock.patch.dict(os.environ, {"KSM_TODAY": "2031-02-04"}):
            self.assertEqual(fetcher_io.window_end_iso(), "2031-02-04")
        with self.assertRaises(fetcher_io.CorruptStateError):
            fetcher_io.resolve_run_date("not-a-date")

    def test_check_window_rejects_only_impossible_windows(self):
        ok, reason = fetcher_io.check_window({"start": "1999-01-01", "end": "2026-10-08"}, today="2026-10-10")
        self.assertTrue(ok, reason)
        ok, reason = fetcher_io.check_window({"start": "1999-01-01", "end": "2026-10-11"}, today="2026-10-10")
        self.assertFalse(ok)
        self.assertIn("future", reason)
        ok, reason = fetcher_io.check_window({"start": "2000-01-01", "end": "2026-10-08"}, today="2026-10-10")
        self.assertFalse(ok)
        ok, reason = fetcher_io.check_window({"start": "1999-01-01", "end": "08/10/2026"}, today="2026-10-10")
        self.assertFalse(ok)

    def test_error_history_is_capped_deduped_and_never_empty(self):
        history = fetcher_io.load_error_history({"errors": ["a", "a", "b"]})[1]
        self.assertEqual(history, ["a", "b"])
        self.assertEqual(fetcher_io.load_error_history(None), ([], []))
        merged = fetcher_io.merge_error_history(["a"], ["b", "a"])
        self.assertEqual(merged, ["a", "b"])
        many = [f"error-{i}" for i in range(fetcher_io.MAX_ERROR_HISTORY + 10)]
        self.assertEqual(len(fetcher_io.merge_error_history([], many)), fetcher_io.MAX_ERROR_HISTORY)
        self.assertEqual(fetcher_io.merge_error_history([], many)[-1], many[-1])

    def test_catalog_write_is_atomic_for_every_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog.jsonl"
            written = fetcher_io.write_catalog_atomic(catalog, [
                {"advisory_id": "CVE-2020-0002", "published": "2020-01-02"},
                {"advisory_id": "CVE-2020-0001", "published": "2020-01-01"},
            ])
            self.assertEqual(written, 2)
            self.assertEqual(catalog.read_text(encoding="utf-8"),
                             '{"advisory_id":"CVE-2020-0002","published":"2020-01-02"}\n'
                             '{"advisory_id":"CVE-2020-0001","published":"2020-01-01"}\n')


class TestCommittedCatalogsStillValidate(unittest.TestCase):
    def test_every_committed_catalog_passes_offline_validation(self):
        studies = ROOT / "scripts" / "studies"
        for project in PROJECTS:
            with self.subTest(project=project):
                proc = subprocess.run(
                    [sys.executable, str(studies / f"fetch_history_{project}.py"), "--offline"],
                    cwd=str(ROOT), capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(proc.returncode, 0, f"{project}: {proc.stderr}")


if __name__ == "__main__":
    unittest.main()
