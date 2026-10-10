"""Offline tests for scripts/studies/refresh_all.py.

Every invoked step is a stub script that records its own argv and exits with a
code looked up by a "script + flag" key, so plan building, --dry-run and
failure aggregation are covered without any network access. The stubs also:

* answer ``--help`` with the flags declared in their own ``# flags:`` header,
  exactly like the real fetchers advertise them through argparse, so
  budget planning exercises the same code path as production;
* can be told to sleep (to trip the wall clock), and to write a project's
  ``index.json`` (to simulate what a fetcher leaves behind).

The behaviours that mattered in review are pinned here so the old false greens
cannot come back: a total outage must exit EXIT_FETCH_OUTAGE (not 0), a fetch
that records errors but advances its cursor is PARTIAL (exit 0), and a fetch
that exceeds its wall clock ends TIMED_OUT or REVERTED. The budget flags the
planner derives are additionally checked against the real fetchers'
``--help`` output, offline.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts" / "studies"))

import refresh_all  # noqa: E402

WORKFLOW = REPO / ".github" / "workflows" / "refresh-catalogs.yml"

# The stub's --help must advertise flags, like a real argparse program. The
# header is read back by the stub itself when refresh_all parses --help.
STUB = '''#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if "--help" in sys.argv[1:]:
    for line in Path(__file__).read_text(encoding="utf-8").splitlines():
        if line.startswith("# flags:"):
            print(line.split(":", 1)[1].strip())
    sys.exit(0)

name = Path(sys.argv[0]).name
key = name
for flag in ("--fetch", "--offline", "--check"):
    if flag in sys.argv[1:]:
        key += " " + flag
        break

log = Path(os.environ["KSM_TEST_STUB_LOG"])
exits = json.loads(os.environ.get("KSM_TEST_STUB_EXITS", "{}"))
sleeps = json.loads(os.environ.get("KSM_TEST_STUB_SLEEP", "{}"))
writes = json.loads(os.environ.get("KSM_TEST_STUB_INDEX", "{}"))
with log.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps([key] + sys.argv[1:]) + "\\n")

if key in sleeps:
    time.sleep(float(sleeps[key]))
if key in writes:
    project = name[len("fetch_history_"):-len(".py")]
    out = Path("docs/studies/cve-history") / project / "index.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(writes[key]), encoding="utf-8")
sys.exit(int(exits.get(key, 0)))
'''

TIME_BUDGET_HEADER = "# flags: --fetch --offline --max-time\n"
CALL_BUDGET_HEADER = "# flags: --fetch --offline --max-calls\n"

# Names the snapshot rebuilders have on disk, and the CNA records subdirectory
# of a kernel security-vulns clone. Kept literal (not read from refresh_all)
# so the tests still run against an entrypoint without those steps.
KERNEL_CNA_SCRIPT = "fetch_kernel_cna_shas.py"
UPSTREAM_SCRIPT = "fetch_upstream_advisories.py"
CNA_RECORDS_DIR = Path("cve") / "published"


def index_payload(cursor=None, errors=(), entry_count=0, window_start="1999-01-01"):
    """A fetcher-style index.json: what refresh_all snapshots before/after."""
    return {
        "schema_version": "cve-history-v1",
        "project": "stub",
        "window": {"start": window_start, "end": "2026-10-08"},
        "coverage": "INCOMPLETE",
        "entry_count": entry_count,
        "resume": {"next_start_date": cursor} if cursor else None,
        "errors": list(errors),
    }


def _validator_accepts_optional_keys(script: Path) -> bool:
    """True when the fetcher's validator tolerates the enrichers' extra keys.

    The relaxations are named ``optional_rec_keys`` / ``optional_keys`` in the
    validators; a fetcher without one compares the whole key set, so the
    enrichers' rows are rejected there.
    """
    text = script.read_text(encoding="utf-8")
    return "optional_rec_keys" in text or "optional_keys" in text


def _env_blocks(text: str):
    """Every workflow/job-level ``env:`` map body in the workflow YAML.

    Only these levels restrict the expression contexts (no ``runner`` there),
    which is what made the refresh workflow invalid; a step-level ``env:`` is
    indented deeper and is skipped on purpose.
    """
    lines = text.splitlines()
    blocks = []
    for index, line in enumerate(lines):
        if line.strip() != "env:":
            continue
        indent = len(line) - len(line.lstrip())
        if indent > 4:  # a step-level env: map
            continue
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if (candidate.strip()
                    and not candidate.lstrip().startswith("#")
                    and len(candidate) - len(candidate.lstrip()) <= indent):
                break
            end += 1
        blocks.append("\n".join(lines[index + 1:end]))
    return blocks


def write_fetchers(studies: Path) -> None:
    """Fetcher stubs whose --help declares the budget flag each real script has."""
    studies.mkdir(parents=True, exist_ok=True)
    for project in refresh_all.PROJECTS:
        header = CALL_BUDGET_HEADER if project == "linux" else TIME_BUDGET_HEADER
        (studies / f"fetch_history_{project}.py").write_text(STUB + header, encoding="utf-8")


def write_stub_repo(root: Path, enrichers=(), snapshots=False) -> Path:
    studies = root / "scripts" / "studies"
    write_fetchers(studies)
    for name in ("build_catalog_manifest.py", "cluster_patterns.py"):
        (studies / name).write_text(STUB, encoding="utf-8")
    for name in enrichers:
        (studies / name).write_text(STUB, encoding="utf-8")
    if snapshots:
        for name in (KERNEL_CNA_SCRIPT, UPSTREAM_SCRIPT):
            (studies / name).write_text(STUB, encoding="utf-8")
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "build_pack.py").write_text(STUB, encoding="utf-8")
    tests = root / "tests"
    tests.mkdir(parents=True, exist_ok=True)
    (tests / "test_ok.py").write_text(
        "import unittest\n\n\nclass Ok(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
        encoding="utf-8",
    )
    return root


class StubRepo:
    """Run refresh_all against a stub repo, capturing stdout and stub invocations."""

    def __init__(self, exits=None, enrichers=(), sleeps=None, indexes=None, snapshots=False):
        self.exits = dict(exits or {})
        self.enrichers = list(enrichers)
        self.sleeps = dict(sleeps or {})
        self.indexes = dict(indexes or {})
        self.snapshots = snapshots

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = write_stub_repo(Path(self._tmp.name), self.enrichers, self.snapshots)
        self.log = self.root / "invocations.log"
        os.environ["KSM_TEST_STUB_LOG"] = str(self.log)
        os.environ["KSM_TEST_STUB_EXITS"] = json.dumps(self.exits)
        os.environ["KSM_TEST_STUB_SLEEP"] = json.dumps(self.sleeps)
        os.environ["KSM_TEST_STUB_INDEX"] = json.dumps(self.indexes)
        os.environ[refresh_all.VULNS_DIR_ENV] = str(self.root / "vulns")
        self._old_root = refresh_all.ROOT
        refresh_all.ROOT = self.root
        self._old_help_cache = dict(refresh_all._HELP_CACHE)
        self._stdout = io.StringIO()
        self._redirect = contextlib.redirect_stdout(self._stdout)
        self._redirect.__enter__()
        return self

    def __exit__(self, *exc):
        self._redirect.__exit__(*exc)
        refresh_all.ROOT = self._old_root
        refresh_all._HELP_CACHE.clear()
        refresh_all._HELP_CACHE.update(self._old_help_cache)
        for key in ("KSM_TEST_STUB_LOG", "KSM_TEST_STUB_EXITS", "KSM_TEST_STUB_SLEEP",
                    "KSM_TEST_STUB_INDEX", refresh_all.VULNS_DIR_ENV):
            os.environ.pop(key, None)
        self._tmp.cleanup()
        return False

    @property
    def stdout(self) -> str:
        return self._stdout.getvalue()

    def invocations(self):
        """Stub invocations so far; safe to call while the repo is alive."""
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]


def plan_of(root: Path, projects, budget_seconds, offline_only):
    with contextlib.redirect_stdout(io.StringIO()):
        return refresh_all.build_plan(
            projects, budget_seconds, offline_only,
            studies_dir=root / "scripts" / "studies", root=root,
        )


class PlanBuildingTest(unittest.TestCase):
    def test_network_plan_runs_in_order_with_per_project_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_fetchers(Path(tmp) / "scripts" / "studies")
            plan = plan_of(Path(tmp), list(refresh_all.PROJECTS), 600, False)

        labels = [step.label for step in plan]
        self.assertEqual(labels[:12], [f"fetch:{p}" for p in refresh_all.PROJECTS])
        self.assertEqual(labels[12:14], ["manifest", "cluster"])
        self.assertEqual(labels[14:26], [f"offline:{p}" for p in refresh_all.PROJECTS])
        self.assertEqual(labels[26:], ["unittest", "build-pack"])

        for step, project in zip(plan[:12], refresh_all.PROJECTS):
            self.assertEqual(step.kind, refresh_all.NETWORK)
            self.assertIn("--fetch", step.argv)
            if project == "linux":
                # fetch_history_linux.py exposes --max-calls only. The count is
                # derived from the wall clock, not hardcoded: 600 s budget at
                # NVD_CALL_SECONDS (>= 20) per call covers the 15 s pacing
                # sleep plus HTTP time.
                self.assertGreaterEqual(refresh_all.NVD_CALL_SECONDS, 20)
                self.assertIn("--max-calls", step.argv)
                self.assertIn(str(600 // refresh_all.NVD_CALL_SECONDS), step.argv)
                self.assertNotIn("--max-time", step.argv)
            else:
                self.assertIn("--max-time", step.argv)
                self.assertIn("600", step.argv)
        for step in plan[12:]:
            self.assertEqual(step.kind, refresh_all.STEP)

    def test_offline_only_plan_is_validation_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_fetchers(Path(tmp) / "scripts" / "studies")
            plan = plan_of(Path(tmp), list(refresh_all.PROJECTS), 600, True)

        labels = [step.label for step in plan]
        self.assertEqual(labels, ["manifest", "cluster"] +
                         [f"offline:{p}" for p in refresh_all.PROJECTS] + ["unittest", "build-pack"])
        for step in plan:
            self.assertNotIn("--fetch", step.argv)
        self.assertIn("--check", plan[0].argv)
        self.assertIn("--check", plan[1].argv)

    def test_project_subset_and_budget_are_honoured(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_fetchers(Path(tmp) / "scripts" / "studies")
            plan = plan_of(Path(tmp), ["curl", "sqlite"], 90, False)
        self.assertEqual([s.label for s in plan],
                         ["fetch:curl", "fetch:sqlite", "manifest", "cluster",
                          "offline:curl", "offline:sqlite", "unittest", "build-pack"])
        self.assertIn("--max-time", plan[0].argv)
        self.assertIn("90", plan[0].argv)

    def test_optional_enrichers_used_only_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            studies = root / "scripts" / "studies"
            write_fetchers(studies)
            (studies / refresh_all.FETCH_KERNEL_CNA).write_text(STUB, encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                plan = refresh_all.build_plan(
                    list(refresh_all.PROJECTS), 600, False, studies_dir=studies, root=root
                )

            labels = [step.label for step in plan]
            self.assertIn(f"enrich:{refresh_all.FETCH_KERNEL_CNA}", labels)
            self.assertNotIn(f"enrich:{refresh_all.ENRICH_FROM_OSV}", labels)
            self.assertIn(f"skipping optional enricher (not present yet): {refresh_all.ENRICH_FROM_OSV}",
                          out.getvalue())

            cna = plan[labels.index(f"enrich:{refresh_all.FETCH_KERNEL_CNA}")]
            self.assertIn("--vulns-dir", cna.argv)
            self.assertIn("--catalog", cna.argv)
            # compute() requires a catalog.jsonl file, never its directory.
            self.assertIn(str(root / "docs" / "studies" / "cve-history" / "linux" / "catalog.jsonl"),
                          cna.argv)
            self.assertNotIn(str(root / "docs" / "studies" / "cve-history" / "linux"), cna.argv)

    def test_osv_enricher_skips_projects_whose_validator_rejects_its_keys(self):
        # The enricher writes fix_sha_source / cwe_source / fix_repo and
        # rewrites cwe_state; git, postgresql, qemu, sqlite, systemd and
        # unbound still require the exact seven-key row, so enriching them
        # fails their own --offline step and would abort the refresh.
        with StubRepo([], enrichers=[refresh_all.ENRICH_FROM_OSV]) as repo:
            with contextlib.redirect_stdout(io.StringIO()):
                plan = plan_of(repo.root, list(refresh_all.PROJECTS), 600, False)
            osv = plan[[s.label for s in plan].index(f"enrich:{refresh_all.ENRICH_FROM_OSV}")]
            received = osv.argv[osv.argv.index("--projects") + 1].split(",")
            self.assertNotIn("git", received)
            self.assertNotIn("postgresql", received)
            self.assertNotIn("qemu", received)
            self.assertNotIn("sqlite", received)
            self.assertNotIn("systemd", received)
            self.assertNotIn("unbound", received)
            # ... and exactly the set the real validators accept, so the
            # protection is neither narrower nor stale. This is the same set
            # the allowlist must declare; tests/test_catalog_optional_keys.py
            # checks one of the validators empirically, this covers all.
            studies = REPO / "scripts" / "studies"
            expected = [project for project in refresh_all.PROJECTS
                        if _validator_accepts_optional_keys(studies / f"fetch_history_{project}.py")]
            self.assertEqual(received, expected)
            self.assertEqual(list(refresh_all.OSV_ENRICHABLE_PROJECTS), expected,
                             "OSV_ENRICHABLE_PROJECTS drifted from the fetchers' validators")

    def test_osv_enricher_is_skipped_when_no_selected_project_accepts_its_keys(self):
        with StubRepo([], enrichers=[refresh_all.ENRICH_FROM_OSV]) as repo:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                plan = refresh_all.build_plan(
                    ["git"], 600, False, studies_dir=repo.root / "scripts" / "studies",
                    root=repo.root,
                )
            labels = [step.label for step in plan]
            self.assertNotIn(f"enrich:{refresh_all.ENRICH_FROM_OSV}", labels)
            self.assertIn(f"skipping {refresh_all.ENRICH_FROM_OSV}", out.getvalue())

    def test_budget_argv_reads_the_scripts_help(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = Path(tmp) / "fetch_history_linux.py"
            calls.write_text(STUB + CALL_BUDGET_HEADER, encoding="utf-8")
            self.assertEqual(refresh_all.budget_argv(calls, 600),
                             ["--max-calls", str(600 // refresh_all.NVD_CALL_SECONDS)])
            timed = Path(tmp) / "fetch_history_curl.py"
            timed.write_text(STUB + TIME_BUDGET_HEADER, encoding="utf-8")
            self.assertEqual(refresh_all.budget_argv(timed, 600), ["--max-time", "600"])
            none = Path(tmp) / "fetch_history_git.py"
            none.write_text(STUB, encoding="utf-8")
            self.assertEqual(refresh_all.budget_argv(none, 600), [])
        # The same reader against the real fetchers (offline --help only).
        studies = REPO / "scripts" / "studies"
        self.assertEqual(refresh_all.budget_argv(studies / "fetch_history_linux.py", 600),
                         ["--max-calls", str(600 // refresh_all.NVD_CALL_SECONDS)])
        self.assertEqual(refresh_all.budget_argv(studies / "fetch_history_curl.py", 600),
                         ["--max-time", "600"])

    def test_unknown_project_is_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            refresh_all.main(["--projects", "nope", "--dry-run"])
        self.assertIn("unknown project(s): nope", str(ctx.exception.code))


class RealFetcherFlagsTest(unittest.TestCase):
    """The real fetchers must advertise what the planner derives from --help."""

    def test_every_real_fetcher_exposes_fetch_offline_and_a_budget(self):
        studies = REPO / "scripts" / "studies"
        for project in refresh_all.PROJECTS:
            script = studies / f"fetch_history_{project}.py"
            self.assertTrue(script.is_file(), script)
            proc = subprocess.run(
                [sys.executable, str(script), "--help"],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, f"{project} --help must exit 0")
            help_text = proc.stdout + proc.stderr
            self.assertIn("--fetch", help_text, project)
            self.assertIn("--offline", help_text, project)
            self.assertTrue("--max-time" in help_text or "--max-calls" in help_text,
                            f"{project} must expose a wall-clock budget")
            self.assertTrue(refresh_all.budget_argv(script, 600),
                            f"{project} must yield a budget flag")

        linux_help = subprocess.run(
            [sys.executable, str(studies / "fetch_history_linux.py"), "--help"],
            capture_output=True, text=True, timeout=60,
        ).stdout
        self.assertIn("--max-calls", linux_help)
        self.assertNotIn("--max-time", linux_help)


class ExecutionTest(unittest.TestCase):
    def test_dry_run_prints_plan_and_runs_nothing(self):
        with StubRepo() as repo:
            code = refresh_all.main(["--dry-run", "--budget-seconds", "120"])
            invocations = repo.invocations()
        self.assertEqual(code, 0)
        self.assertEqual(invocations, [])
        self.assertIn("dry-run: nothing executed", repo.stdout)
        self.assertIn("fetch:curl", repo.stdout)
        self.assertIn("--max-time 120", repo.stdout)

    def test_total_outage_exits_with_fetch_outage_code(self):
        # Every fetcher exits non-zero and leaves an error behind with the
        # cursor still at the window start: nothing was refreshed anywhere.
        indexes = {
            f"fetch_history_{p}.py --fetch": index_payload(errors=["Network timeout on NVD"])
            for p in ("curl", "git")
        }
        with StubRepo({f"fetch_history_{p}.py --fetch": 1 for p in ("curl", "git")},
                      indexes=indexes) as repo:
            code = refresh_all.main(["--projects", "curl,git", "--budget-seconds", "600"])
            invocations = repo.invocations()
        self.assertEqual(code, refresh_all.EXIT_FETCH_OUTAGE)
        self.assertEqual(refresh_all.EXIT_FETCH_OUTAGE, 3)
        self.assertIn("NETWORK_FAILED", repo.stdout)
        self.assertIn("RESULT: FETCH OUTAGE (all 2 attempted project(s) failed)", repo.stdout)
        # The outage is per project: curl's own offline validation still ran.
        self.assertIn("fetch_history_curl.py --offline", [inv[0] for inv in invocations])

    def test_total_outage_with_exit_zero_is_still_detected(self):
        # The real fetchers store NVD errors and exit 0; the outage must be
        # detected from index.json, never from the return code.
        indexes = {
            f"fetch_history_{p}.py --fetch": index_payload(errors=["Network timeout on NVD"])
            for p in ("curl", "git")
        }
        with StubRepo({f"fetch_history_{p}.py --fetch": 0 for p in ("curl", "git")},
                      indexes=indexes) as repo:
            code = refresh_all.main(["--projects", "curl,git", "--budget-seconds", "600"])
        self.assertEqual(code, refresh_all.EXIT_FETCH_OUTAGE)
        self.assertIn("NETWORK_FAILED", repo.stdout)

    def test_cursor_advanced_with_error_is_partial_and_exits_zero(self):
        # curl advanced its cursor and then recorded an error: progress was
        # made, so the run stays green but the project is listed as PARTIAL.
        with StubRepo({"fetch_history_curl.py --fetch": 1},
                     indexes={"fetch_history_curl.py --fetch":
                              index_payload(cursor="2010-01-01",
                                            errors=["HTTP 500 on window 2010-01-01"],
                                            entry_count=42)}) as repo:
            code = refresh_all.main(["--projects", "curl", "--budget-seconds", "600"])
        self.assertEqual(code, 0)
        self.assertIn("PARTIAL", repo.stdout)
        self.assertIn("partial (errors recorded, cursor advanced): curl", repo.stdout)
        self.assertIn("RESULT: OK (1 partial)", repo.stdout)

    def test_timeout_keeps_state_when_offline_passes(self):
        # curl sleeps past its wall clock (budget 1 s + grace 2 s) and is
        # killed; its last written state validates, so it is TIMED_OUT and the
        # only attempted project failed -> fetch-outage exit code.
        with StubRepo(sleeps={"fetch_history_curl.py --fetch": 30}) as repo:
            code = refresh_all.main(["--projects", "curl",
                                     "--budget-seconds", "1", "--grace-seconds", "2"])
            invocations = repo.invocations()
        self.assertEqual(code, refresh_all.EXIT_FETCH_OUTAGE)
        self.assertIn("TIMED_OUT", repo.stdout)
        self.assertIn("last written state kept", repo.stdout)
        # The fetch process is gone: later steps still ran.
        self.assertIn("fetch_history_curl.py --offline", [inv[0] for inv in invocations])

    def test_timeout_reverts_when_offline_fails(self):
        # The killed fetcher's partial state fails offline validation, so the
        # committed files are restored (REVERTED). The stub repo is not a git
        # checkout, so the restore warns and the later offline step still
        # fails -> validation exit code 1, not 0.
        with StubRepo(sleeps={"fetch_history_curl.py --fetch": 30},
                      exits={"fetch_history_curl.py --offline": 1}) as repo:
            code = refresh_all.main(["--projects", "curl",
                                     "--budget-seconds", "1", "--grace-seconds", "2"])
        self.assertEqual(code, 1)
        self.assertIn("REVERTED", repo.stdout)
        self.assertIn("offline:curl", repo.stdout)
        self.assertIn("RESULT: FAILED (1 validation step(s) failed)", repo.stdout)

    def test_deadline_skips_fetches_that_cannot_finish(self):
        # A 1 s deadline is less than MIN_FETCH_SECONDS, so no fetcher starts.
        with StubRepo() as repo:
            code = refresh_all.main(["--projects", "curl,git", "--deadline-seconds", "1"])
        self.assertEqual(code, refresh_all.EXIT_FETCH_OUTAGE)
        self.assertIn("SKIPPED", repo.stdout)

    def test_validation_failure_is_fatal_and_aggregated(self):
        with StubRepo({"fetch_history_git.py --offline": 1, "build_pack.py --check": 2}) as repo:
            plan = plan_of(repo.root, list(refresh_all.PROJECTS), 600, True)
            code = refresh_all.main(["--offline-only"])
            invocations = repo.invocations()
        self.assertEqual(code, 1)
        self.assertIn("validation failures:", repo.stdout)
        self.assertIn("  - offline:git", repo.stdout)
        self.assertIn("  - build-pack", repo.stdout)
        self.assertIn("RESULT: FAILED (2 validation step(s) failed)", repo.stdout)
        # A validation failure does not stop the remaining steps.
        self.assertEqual(len(invocations), len(plan) - 1)  # minus the unittest step

    def test_offline_only_succeeds_against_stub_repo(self):
        with StubRepo() as repo:
            code = refresh_all.main(["--offline-only"])
            invocations = repo.invocations()
        self.assertEqual(code, 0)
        self.assertIn("RESULT: OK", repo.stdout)
        self.assertEqual(len(invocations), 15)  # manifest, cluster, 12 offline, build-pack
        self.assertIn("--offline", " ".join(key for key, *_ in invocations))
        self.assertIn("Ran 1 test", repo.stdout)  # unittest step really ran

    def test_bad_deadline_and_grace_are_rejected(self):
        for flag in ("--deadline-seconds", "--grace-seconds", "--budget-seconds"):
            with self.assertRaises(SystemExit):
                refresh_all.main(["--projects", "curl", "--dry-run", flag, "0"])


class WorkflowContextsTest(unittest.TestCase):
    """The workflow must only use expression contexts GitHub allows there.

    ``runner.temp`` is not available in a job-level ``env:`` map, so the
    scheduled run failed before any step executed. actionlint reports it as
    "context \"runner\" is not allowed here".
    """

    def test_no_expression_in_job_or_workflow_level_env(self):
        blocks = _env_blocks(WORKFLOW.read_text(encoding="utf-8"))
        self.assertTrue(blocks, "expected a workflow- or job-level env: map")
        for block in blocks:
            for line in block.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    self.assertNotIn(
                        "${{", line,
                        "job/workflow-level env allows only github, inputs, matrix, "
                        "needs, secrets, strategy and vars; move runner.* into a step",
                    )

    def test_vulns_dir_is_exported_by_a_step(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r'echo\s+"KSM_VULNS_DIR=\$RUNNER_TEMP[^"]*"\s+>>\s+"\$GITHUB_ENV"')


class SnapshotCatalogStepsTest(unittest.TestCase):
    """The snapshot catalogs must be rebuilt before the manifest.

    No ``fetch_history_*.py`` fetcher writes ``linux-cna``,
    ``curl-upstream`` or ``openssl-upstream``, so without these steps the
    refresh could never pick up a new CNA release or upstream advisory while
    the manifest kept counting the stale files.
    """

    def _plan(self, root, offline_only):
        return plan_of(root, list(refresh_all.PROJECTS), 600, offline_only)

    def test_network_plan_rebuilds_the_snapshot_catalogs_before_the_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            studies = root / "scripts" / "studies"
            write_fetchers(studies)
            for name in (KERNEL_CNA_SCRIPT, UPSTREAM_SCRIPT):
                (studies / name).write_text(STUB, encoding="utf-8")
            plan = self._plan(root, False)

        labels = [step.label for step in plan]
        by_label = {step.label: step for step in plan}
        cna = by_label.get("snapshot:linux-cna")
        self.assertIsNotNone(cna, "the linux-cna snapshot catalog is never rebuilt")
        self.assertEqual(cna.kind, refresh_all.NETWORK)
        self.assertIn("--build-catalog", cna.argv)
        self.assertIn(str(root / "docs" / "studies" / "cve-history" / "linux-cna"), cna.argv)
        for label, project, subdir in (("snapshot:curl-upstream", "curl", "curl-upstream"),
                                       ("snapshot:openssl-upstream", "openssl", "openssl-upstream")):
            step = by_label.get(label)
            self.assertIsNotNone(step, f"{label} is never rebuilt")
            self.assertEqual(step.kind, refresh_all.NETWORK)
            self.assertIn(project, step.argv)
            self.assertIn(str(root / "docs" / "studies" / "cve-history" / subdir), step.argv)
            self.assertNotIn("--offline", step.argv)
        for label in ("snapshot:linux-cna", "snapshot:curl-upstream", "snapshot:openssl-upstream"):
            self.assertIn(label, labels)
            self.assertLess(labels.index(label), labels.index("manifest"))

    def test_offline_only_skips_snapshot_checks_without_a_local_cache(self):
        # The raw advisory snapshots are gitignored and the CNA clone is made
        # by the workflow, so a plain checkout has neither: nothing to check.
        with StubRepo([], snapshots=True) as repo:
            code = refresh_all.main(["--offline-only"])
            invocations = [inv[0] for inv in repo.invocations()]
        self.assertEqual(code, 0)
        self.assertNotIn(f"{KERNEL_CNA_SCRIPT} --check", invocations)
        self.assertNotIn(f"{UPSTREAM_SCRIPT} --offline", invocations)

    def test_offline_only_checks_snapshots_when_the_cache_exists(self):
        with StubRepo([], snapshots=True) as repo:
            (repo.root / "vulns" / CNA_RECORDS_DIR).mkdir(parents=True)
            for subdir in ("curl-upstream", "openssl-upstream"):
                snapshot = repo.root / "docs" / "studies" / "cve-history" / subdir / "source.json"
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                snapshot.write_text("{}\n", encoding="utf-8")
            code = refresh_all.main(["--offline-only"])
            invocations = repo.invocations()
        self.assertEqual(code, 0)
        keys = [inv[0] for inv in invocations]
        self.assertIn(f"{KERNEL_CNA_SCRIPT} --check", keys)
        self.assertIn(f"{UPSTREAM_SCRIPT} --offline", keys)
        self.assertEqual(keys.count(f"{UPSTREAM_SCRIPT} --offline"), 2)
        cna = [args for args in invocations if args[0] == f"{KERNEL_CNA_SCRIPT} --check"][0]
        self.assertIn("--build-catalog", cna)
        self.assertIn(str(repo.root / "docs" / "studies" / "cve-history" / "linux-cna"), cna)
        self.assertIn("--vulns-dir", cna)
        for args in invocations:
            if args[0] == f"{UPSTREAM_SCRIPT} --offline":
                self.assertIn("--check", args)

    def test_offline_snapshot_check_failure_is_fatal(self):
        # A network failure of a rebuild is non-fatal, but its offline check is
        # not: the committed catalog no longer matches its source.
        with StubRepo({f"{KERNEL_CNA_SCRIPT} --check": 1}, snapshots=True) as repo:
            (repo.root / "vulns" / CNA_RECORDS_DIR).mkdir(parents=True)
            code = refresh_all.main(["--offline-only"])
        self.assertEqual(code, 1)
        self.assertIn("snapshot:linux-cna", repo.stdout)
        self.assertIn("RESULT: FAILED (1 validation step(s) failed)", repo.stdout)

    def test_network_snapshot_rebuild_failure_is_not_fatal(self):
        with StubRepo({UPSTREAM_SCRIPT: 1}, snapshots=True) as repo:
            code = refresh_all.main(["--budget-seconds", "600"])
        self.assertEqual(code, 0)
        self.assertIn("snapshot:curl-upstream", repo.stdout)
        self.assertIn("optional enricher failures", repo.stdout)


if __name__ == "__main__":
    unittest.main()
