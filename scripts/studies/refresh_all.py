#!/usr/bin/env python3
"""Single entrypoint for a full CVE catalog refresh: fetch, enrich, build, validate.

This module is the only command humans and CI need in order to refresh
``docs/studies/cve-history/``. It runs, in order:

1. every ``fetch_history_<project>.py --fetch`` under a wall clock. Cursor
   resumption is the fetcher's own job: it reloads ``index.json``/
   ``catalog.jsonl`` and continues from ``resume.next_start_date``, so the
   refresh is incremental and re-runnable. The fetchers exit 0 even when NVD
   failed (they preserve the error in that catalog's ``index.json``
   ``errors`` list), so this entrypoint snapshots each project's
   ``index.json`` (cursor, entry_count, errors) before and after its fetch and
   classifies the outcome itself:

   * ``OK``             exit 0 and no new errors;
   * ``PARTIAL``        new errors recorded, but the cursor advanced (progress
                        was made before the failure); still exit 0 overall;
   * ``NETWORK_FAILED`` new errors and the cursor did not advance;
   * ``FAILED``         non-zero exit without any error recorded;
   * ``TIMED_OUT``      killed at the wall clock; its last written state was
                        kept because offline validation passed;
   * ``REVERTED``       killed at the wall clock and its last written state
                        failed offline validation, so ``git checkout --``
                        restored the committed files;
   * ``SKIPPED``        the global deadline ran out before this project.

   If every attempted project failed (a total NVD outage) the process exits 3,
   so the workflow fails and opens no pull request. Partial failures are still
   exit 0 and are listed per project in the summary the workflow pastes into
   the pull request body.
2. the optional enrichers, but only when their script is already in the tree
   (``scripts/studies/enrich_from_osv.py`` and
   ``scripts/studies/fetch_kernel_cna_shas.py`` are written in parallel).
   An enricher failure is recorded and never fatal.
3. ``build_catalog_manifest.py`` and ``cluster_patterns.py`` (regeneration).
4. validation: every fetcher with ``--offline``, the unit tests and
   ``build_pack.py --check``.

Rules encoded here:

* A per-project network failure does not abort the other projects.
* Any validation step that fails makes the process exit 1, after every step
  has run, so one run reports all problems.
* ``--offline-only`` performs no network access: only the validation steps.
* ``--dry-run`` prints the plan and exits without running anything.
* No git operation happens here. Publishing is the workflow's job
  (``.github/workflows/refresh-catalogs.yml`` resumes the automation branch,
  merges main into it and opens a PR with a plain fast-forward push; main is
  never pushed and no push is ever forced).

Exit codes: 0 ok (possibly with partial projects), 1 validation failure,
3 every attempted project failed to fetch.

Python 3 standard library only.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]

PROJECTS: Tuple[str, ...] = (
    "curl", "git", "glibc", "linux", "nginx", "openssh",
    "openssl", "postgresql", "qemu", "sqlite", "systemd", "unbound",
)

# Enrichers owned by parallel work; used only once the script exists.
ENRICH_FROM_OSV = "enrich_from_osv.py"
FETCH_KERNEL_CNA = "fetch_kernel_cna_shas.py"
OPTIONAL_ENRICHERS: Tuple[str, ...] = (ENRICH_FROM_OSV, FETCH_KERNEL_CNA)

DEFAULT_BUDGET_SECONDS = 600
# Global wall clock for the fetch phase. The workflow allows 50 minutes; 35
# minutes of fetching leaves room for validation and the pull request.
DEFAULT_DEADLINE_SECONDS = 2100
# Slack over a fetcher's own --max-time/--max-calls budget before it is
# killed: one in-flight request (25 s socket timeout), or the 403/429 retry
# path (15 s pacing + 40 s retry sleep + 25 s), can overrun the internal
# budget by about a minute.
DEFAULT_GRACE_SECONDS = 120
# fetch_history_linux.py exposes --max-calls, not --max-time: one NVD call
# costs the fetcher's fixed 15 s pacing sleep plus the HTTP time, so the time
# budget is converted at 25 s per call.
NVD_CALL_SECONDS = 25
# Never start another fetcher with less than this much of the deadline left.
MIN_FETCH_SECONDS = 60
# Exit code for "every attempted project failed to fetch" (distinct from 1,
# which is reserved for validation failures).
EXIT_FETCH_OUTAGE = 3

VULNS_DIR_ENV = "KSM_VULNS_DIR"
DEFAULT_VULNS_DIR = Path(tempfile.gettempdir()) / "linux-security-vulns"
CATALOGS_SUBDIR = Path("docs") / "studies" / "cve-history"
HELP_TIMEOUT_SECONDS = 60
OFFLINE_TIMEOUT_SECONDS = 120

NETWORK = "network"
STEP = "step"

# Per-project fetch states.
OK = "OK"
PARTIAL = "PARTIAL"                 # new errors, but the cursor advanced
NETWORK_FAILED = "NETWORK_FAILED"   # new errors, cursor did not advance
FAILED = "FAILED"                   # non-zero exit, no error recorded
TIMED_OUT = "TIMED_OUT"             # killed; last state kept (offline passed)
REVERTED = "REVERTED"               # killed; last state failed offline, restored from git
SKIPPED = "SKIPPED"                 # deadline ran out before this project
FAILED_STATES = frozenset({NETWORK_FAILED, FAILED, TIMED_OUT, REVERTED, SKIPPED})

_HELP_CACHE: Dict[str, str] = {}


class Step(NamedTuple):
    label: str
    argv: List[str]
    kind: str  # NETWORK: recorded, never fatal. STEP: must pass.


class Snapshot(NamedTuple):
    """The parts of a project's index.json needed to judge a fetch."""

    cursor: Optional[str]           # resume.next_start_date
    window_start: Optional[str]
    entry_count: Optional[int]
    error_count: int

    @classmethod
    def read(cls, project: str, root: Optional[Path] = None) -> "Snapshot":
        base = Path(root) if root is not None else ROOT
        index = base / CATALOGS_SUBDIR / project / "index.json"
        try:
            data = json.loads(index.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls(None, None, None, 0)
        resume = data.get("resume")
        cursor = resume.get("next_start_date") if isinstance(resume, dict) else None
        window = data.get("window")
        errors = data.get("errors")
        return cls(
            cursor=cursor if isinstance(cursor, str) else None,
            window_start=window.get("start") if isinstance(window, dict) else None,
            entry_count=data.get("entry_count") if isinstance(data.get("entry_count"), int) else None,
            error_count=len(errors) if isinstance(errors, list) else 0,
        )


def vulns_dir() -> Path:
    """Location of the shallow https://git.kernel.org/pub/scm/linux/security/vulns.git clone."""
    return Path(os.environ.get(VULNS_DIR_ENV) or DEFAULT_VULNS_DIR)


def fetcher_script(studies_dir: Path, project: str) -> Path:
    return studies_dir / f"fetch_history_{project}.py"


def fetcher_help(script: Path) -> str:
    """The fetcher's own ``--help`` text (offline); empty if it cannot be read."""
    key = str(script)
    if key not in _HELP_CACHE:
        try:
            proc = subprocess.run(
                [sys.executable, str(script), "--help"],
                capture_output=True, text=True, check=False,
                timeout=HELP_TIMEOUT_SECONDS,
            )
            _HELP_CACHE[key] = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        except (OSError, subprocess.SubprocessError):
            _HELP_CACHE[key] = ""
    return _HELP_CACHE[key]


def budget_argv(script: Path, budget_seconds: int) -> List[str]:
    """Budget flags the fetcher's argparse advertises, read from its --help.

    Most fetchers take ``--max-time <seconds>``. ``fetch_history_linux.py``
    only takes ``--max-calls``, so the time budget is converted at
    NVD_CALL_SECONDS per call instead of being dropped.
    """
    help_text = fetcher_help(script)
    if "--max-time" in help_text:
        return ["--max-time", str(budget_seconds)]
    if "--max-calls" in help_text:
        return ["--max-calls", str(max(1, budget_seconds // NVD_CALL_SECONDS))]
    return []


def build_plan(
    projects: Sequence[str],
    budget_seconds: int,
    offline_only: bool,
    *,
    studies_dir: Optional[Path] = None,
    root: Optional[Path] = None,
) -> List[Step]:
    """Return the ordered plan. It only inspects the filesystem and --help."""
    root = Path(root) if root is not None else ROOT
    studies = Path(studies_dir) if studies_dir is not None else root / "scripts" / "studies"
    py = sys.executable
    steps: List[Step] = []

    if not offline_only:
        for project in projects:
            script = fetcher_script(studies, project)
            steps.append(Step(
                f"fetch:{project}",
                [py, str(script), "--fetch", *budget_argv(script, budget_seconds)],
                NETWORK,
            ))
        for name in OPTIONAL_ENRICHERS:
            script = studies / name
            if not script.is_file():
                print(f"skipping optional enricher (not present yet): {name}")
                continue
            if name == ENRICH_FROM_OSV:
                argv = [py, str(script), "--projects", ",".join(projects)]
            else:
                argv = [
                    py, str(script),
                    "--vulns-dir", str(vulns_dir()),
                    "--catalog", str(root / CATALOGS_SUBDIR / "linux"),
                ]
            steps.append(Step(f"enrich:{name}", argv, NETWORK))

    steps.append(Step(
        "manifest",
        [py, str(studies / "build_catalog_manifest.py"), *(["--check"] if offline_only else [])],
        STEP,
    ))
    steps.append(Step(
        "cluster",
        [py, str(studies / "cluster_patterns.py"), *(["--check"] if offline_only else [])],
        STEP,
    ))
    for project in projects:
        steps.append(Step(f"offline:{project}", [py, str(fetcher_script(studies, project)), "--offline"], STEP))
    steps.append(Step("unittest", [py, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"], STEP))
    steps.append(Step("build-pack", [py, str(root / "scripts" / "build_pack.py"), "--check"], STEP))
    return steps


def echo_output(label: str, argv: Sequence[str], streams: Sequence[Optional[str]]) -> None:
    print(f"\n=== {label} ===")
    print(" ".join(argv))
    for stream in streams:
        if stream:
            print(stream.rstrip())


def run_step(step: Step, cwd: Optional[Path] = None) -> bool:
    """Run one validation step, echo its output, and report success."""
    proc = subprocess.run(
        step.argv,
        cwd=str(cwd) if cwd is not None else str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    echo_output(step.label, step.argv, (proc.stdout, proc.stderr))
    if proc.returncode == 0:
        print(f"--- {step.label}: ok")
        return True
    print(f"--- {step.label}: FAILED (exit {proc.returncode})")
    return False


def run_with_timeout(argv: Sequence[str], timeout: float) -> Tuple[Optional[int], str, str, bool]:
    """Run a command, killing it after ``timeout`` seconds.

    Returns (returncode, stdout, stderr, timed_out); returncode is None when
    the command was killed.
    """
    proc = subprocess.Popen(
        list(argv),
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        out, err = proc.communicate(timeout=max(1, int(timeout)))
        return proc.returncode, out or "", err or "", False
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return None, out or "", err or "", True


def offline_ok(script: Path, timeout: float) -> bool:
    rc, _out, _err, timed_out = run_with_timeout([sys.executable, str(script), "--offline"], timeout)
    return rc == 0 and not timed_out


def git_restore(project: str) -> bool:
    """Undo a killed fetcher's partial writes by restoring the committed files."""
    target = CATALOGS_SUBDIR / project
    proc = subprocess.run(
        ["git", "checkout", "--", str(target)],
        cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        print(f"warning: 'git checkout -- {target}' failed: {(proc.stderr or proc.stdout or '').strip()}")
    return proc.returncode == 0


def cursor_advanced(before: Snapshot, after: Snapshot) -> bool:
    if after.cursor is None or after.cursor == before.cursor:
        return False
    # A cursor still at the window start means no window was ever completed.
    return after.cursor != after.window_start


def classify(before: Snapshot, after: Snapshot, returncode: Optional[int]) -> str:
    new_errors = after.error_count > before.error_count
    if new_errors:
        return PARTIAL if cursor_advanced(before, after) else NETWORK_FAILED
    if returncode not in (0, None):
        return FAILED
    return OK


def run_fetch(
    step: Step,
    *,
    budget_seconds: int,
    grace_seconds: int,
    deadline_seconds: float,
    started: float,
) -> Tuple[str, Snapshot, Snapshot]:
    """Fetch one project under its wall clock and classify the outcome."""
    project = step.label.split(":", 1)[1]
    before = Snapshot.read(project)
    echo_output(f"{step.label} (network)", step.argv, ())
    remaining = deadline_seconds - (time.monotonic() - started)
    if remaining < MIN_FETCH_SECONDS:
        print(f"--- {step.label}: {SKIPPED} "
              f"(only {remaining:.0f}s of the {deadline_seconds:.0f}s deadline left)")
        return SKIPPED, before, before

    timeout = min(budget_seconds + grace_seconds, remaining)
    rc, out, err, timed_out = run_with_timeout(step.argv, timeout)
    for stream in (out, err):
        if stream:
            print(stream.rstrip())
    if timed_out:
        print(f"--- {step.label}: killed after {timeout:.0f}s")
        if offline_ok(Path(step.argv[1]), min(OFFLINE_TIMEOUT_SECONDS, max(30, remaining))):
            print(f"--- {step.label}: {TIMED_OUT} (last written state kept: offline validation passed)")
            return TIMED_OUT, before, Snapshot.read(project)
        git_restore(project)
        print(f"--- {step.label}: {REVERTED} "
              f"(partial state failed offline validation; committed files restored)")
        return REVERTED, before, before

    after = Snapshot.read(project)
    state = classify(before, after, rc)
    print(f"--- {step.label}: {state} (exit {rc})")
    return state, before, after


def run_enricher(step: Step, *, timeout_budget: float, deadline_seconds: float, started: float) -> bool:
    """Optional enricher: recorded on failure, never fatal."""
    remaining = deadline_seconds - (time.monotonic() - started)
    echo_output(f"{step.label} (network)", step.argv, ())
    if remaining < MIN_FETCH_SECONDS:
        print(f"--- {step.label}: FAILED (skipped: deadline)")
        return False
    timeout = min(timeout_budget, remaining)
    rc, out, err, timed_out = run_with_timeout(step.argv, timeout)
    for stream in (out, err):
        if stream:
            print(stream.rstrip())
    if timed_out:
        print(f"--- {step.label}: FAILED (killed after {timeout:.0f}s)")
        return False
    if rc == 0:
        print(f"--- {step.label}: ok")
        return True
    print(f"--- {step.label}: FAILED (exit {rc})")
    return False


def parse_projects(value: Optional[str]) -> List[str]:
    if not value:
        return list(PROJECTS)
    requested = [name.strip() for name in value.split(",") if name.strip()]
    unknown = [name for name in requested if name not in PROJECTS]
    if unknown or not requested:
        raise SystemExit(
            f"error: unknown project(s): {', '.join(unknown) or '(none given)'}; "
            f"valid: {', '.join(PROJECTS)}"
        )
    return requested


def _fmt(value: Optional[object]) -> str:
    return "-" if value is None else str(value)


def report(
    states: Sequence[Tuple[str, str, Snapshot, Snapshot]],
    failures: Sequence[str],
    network_failures: Sequence[str],
) -> None:
    """Per-project table plus the final verdict (start of the PR-body block)."""
    print("\n=== refresh summary ===")
    if states:
        print(f"{'project':<12} {'state':<14} {'entries':<15} {'cursor':<29} new errors")
        for project, state, before, after in states:
            entries = f"{_fmt(before.entry_count)} -> {_fmt(after.entry_count)}"
            cursor = f"{_fmt(before.cursor)} -> {_fmt(after.cursor)}"
            print(f"{project:<12} {state:<14} {entries:<15} {cursor:<29} "
                  f"{after.error_count - before.error_count}")
    failed = [p for p, state, _, _ in states if state in FAILED_STATES]
    partial = [p for p, state, _, _ in states if state == PARTIAL]
    if not states:
        print("fetch phase: none (offline-only)")
    elif failed:
        print(f"projects that failed to fetch: {len(failed)}/{len(states)} "
              f"({', '.join(failed)})")
    else:
        print("fetch failures: none")
    if partial:
        print(f"partial (errors recorded, cursor advanced): {', '.join(partial)}")
    if network_failures:
        print("optional enricher failures (other work continued):")
        for label in network_failures:
            print(f"  - {label}")
    if failures:
        print("validation failures:")
        for label in failures:
            print(f"  - {label}")
        print(f"RESULT: FAILED ({len(failures)} validation step(s) failed)")
    elif states and len(failed) == len(states):
        print(f"RESULT: FETCH OUTAGE (all {len(states)} attempted project(s) failed)")
    else:
        suffix = f" ({len(partial)} partial)" if partial else ""
        print(f"RESULT: OK{suffix}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects", default=None,
                        help=f"Comma-separated subset to refresh (default: all {len(PROJECTS)})")
    parser.add_argument("--budget-seconds", type=int, default=DEFAULT_BUDGET_SECONDS,
                        help=f"Wall-clock budget per project fetch (default: {DEFAULT_BUDGET_SECONDS})")
    parser.add_argument("--grace-seconds", type=int, default=DEFAULT_GRACE_SECONDS,
                        help=f"Slack over a fetch's budget before it is killed "
                             f"(default: {DEFAULT_GRACE_SECONDS})")
    parser.add_argument("--deadline-seconds", type=int, default=DEFAULT_DEADLINE_SECONDS,
                        help=f"Global wall clock for the whole fetch phase "
                             f"(default: {DEFAULT_DEADLINE_SECONDS})")
    parser.add_argument("--offline-only", action="store_true",
                        help="No network: run only the validation steps")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan and exit")
    args = parser.parse_args(argv)

    projects = parse_projects(args.projects)
    if args.budget_seconds < 1:
        raise SystemExit("error: --budget-seconds must be >= 1")
    if args.grace_seconds < 1:
        raise SystemExit("error: --grace-seconds must be >= 1")
    if args.deadline_seconds < 1:
        raise SystemExit("error: --deadline-seconds must be >= 1")

    studies = ROOT / "scripts" / "studies"
    missing = [p for p in projects if not fetcher_script(studies, p).is_file()]
    if missing:
        raise SystemExit(f"error: missing fetcher script(s) for: {', '.join(missing)}")

    mode = "offline-only" if args.offline_only else "network+validation"
    print(f"refresh plan [{mode}] projects={len(projects)} "
          f"budget={args.budget_seconds}s+{args.grace_seconds}s/project "
          f"deadline={args.deadline_seconds}s root={ROOT}")
    plan = build_plan(projects, args.budget_seconds, args.offline_only, studies_dir=studies, root=ROOT)
    print(f"steps={len(plan)}")

    if args.dry_run:
        for step in plan:
            print(f"  {step.label:<24} {step.kind:<8} {' '.join(step.argv)}")
        print("dry-run: nothing executed")
        return 0

    failures: List[str] = []
    network_failures: List[str] = []
    states: List[Tuple[str, str, Snapshot, Snapshot]] = []
    started = time.monotonic()
    for step in plan:
        if step.kind == NETWORK and step.label.startswith("fetch:"):
            state, before, after = run_fetch(
                step,
                budget_seconds=args.budget_seconds,
                grace_seconds=args.grace_seconds,
                deadline_seconds=args.deadline_seconds,
                started=started,
            )
            states.append((step.label.split(":", 1)[1], state, before, after))
        elif step.kind == NETWORK:
            ok = run_enricher(
                step,
                timeout_budget=args.budget_seconds + args.grace_seconds,
                deadline_seconds=args.deadline_seconds,
                started=started,
            )
            if not ok:
                network_failures.append(step.label)
        elif not run_step(step, cwd=ROOT):
            failures.append(step.label)

    report(states, failures, network_failures)
    if failures:
        return 1
    if states and all(state in FAILED_STATES for _, state, _, _ in states):
        return EXIT_FETCH_OUTAGE
    return 0


if __name__ == "__main__":
    sys.exit(main())
