#!/usr/bin/env python3
"""Shared hardening helpers for the ``fetch_history_*.py`` NVD fetchers.

The twelve NVD keyword fetchers are near-identical copies of the same loop, so
the invariants that were broken in all of them live here once instead of twelve
times. Everything in this module is offline and network-free.

The invariants:

1. **``window.end`` is the run date.** It used to be the frozen literal
   ``2026-10-08``, so every refresh stopped scanning the most recent CVEs and
   every catalog disagreed with the date it was actually built on.
   :func:`resolve_run_date` returns UTC today and honours ``KSM_TODAY`` so a
   test (or a replay) can pin the date.

2. **Writes are atomic, catalog first and index last.** ``catalog.jsonl`` and
   ``index.json`` are written through a sibling temp file and ``os.replace``.
   A run killed mid-write can therefore leave the *previous* committed state,
   never a half-written one; and because the index is replaced after the
   catalog, an interrupted run can never publish an index that describes a
   catalog that does not exist.

3. **Corrupt state is fatal, not ignored.** The old loaders wrapped
   ``json.load`` in ``except Exception: pass``, so a truncated file was
   silently loaded as an empty catalog and then rewritten as a shorter "valid"
   one. :func:`read_index` / :func:`read_catalog` raise
   :class:`CorruptStateError` instead, and the fetchers' ``main()`` turns that
   into a non-zero exit with the offending file named.

4. **An error recorded by a previous run never blocks the next one.** The old
   loop guarded progress with ``if not window_finished or errors: break`` while
   ``errors`` was seeded from the persisted index, so one timeout parked a
   catalog forever (unbound stopped at cursor 2003-06-09). ``errors`` now holds
   only the current run's failures and the older ones are kept as capped
   ``error_history``: history is never silently dropped and never gates a run.
"""

import datetime
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ISO date injected by tests/replays to pin "today" without touching the clock.
TODAY_ENV = "KSM_TODAY"
# The start of the CVE-era scan window; unchanged by this module.
WINDOW_START = "1999-01-01"
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# How many distinct past errors an index keeps. Capped so a flaky network
# cannot grow the file without bound.
MAX_ERROR_HISTORY = 50


class CorruptStateError(RuntimeError):
    """A persisted catalog/index is unreadable: refuse to rewrite it."""


# ----------------------------------------------------------------------------
# 1. Run date / window
# ---------------------------------------------------------------------------

def resolve_run_date(today: Optional[str] = None) -> datetime.date:
    """The date that bounds ``window.end``: UTC today, or ``KSM_TODAY``.

    ``today`` is an explicit override (ISO date); when omitted the
    ``KSM_TODAY`` environment variable is consulted, then the real UTC clock.
    """
    raw = today if today is not None else os.environ.get(TODAY_ENV)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return datetime.datetime.now(datetime.timezone.utc).date()
    text = str(raw).strip()
    if not ISO_DATE.match(text):
        raise CorruptStateError(f"{TODAY_ENV} must be an ISO date (YYYY-MM-DD), got {text!r}")
    try:
        return datetime.date.fromisoformat(text)
    except ValueError as exc:
        raise CorruptStateError(f"{TODAY_ENV} is not a real date: {text!r}") from exc


def window_end_iso(today: Optional[str] = None) -> str:
    """``window.end`` for a run: the run date as an ISO string."""
    return resolve_run_date(today).isoformat()


def expected_window(today: Optional[str] = None) -> Dict[str, str]:
    """The ``window`` object a fetcher records for a run."""
    return {"start": WINDOW_START, "end": window_end_iso(today)}


def check_window(window: Any, today: Optional[str] = None) -> Tuple[bool, str]:
    """Validate an ``index.json`` window for ``--offline``.

    ``window.end`` records the date the scan ran on, so an older committed
    value stays valid (it is the truth about that scan) while a date in the
    future is impossible and is rejected.
    """
    if not isinstance(window, dict):
        return False, f"window must be an object with start={WINDOW_START}"
    if window.get("start") != WINDOW_START:
        return False, f"window.start must be {WINDOW_START}"
    end = window.get("end")
    if not isinstance(end, str) or not ISO_DATE.match(end):
        return False, f"window.end must be an ISO date (YYYY-MM-DD), got {end!r}"
    try:
        end_date = datetime.date.fromisoformat(end)
    except ValueError:
        return False, f"window.end is not a real date: {end!r}"
    run_date = resolve_run_date(today)
    if end_date > run_date:
        return False, f"window.end {end} is in the future (run date {run_date.isoformat()})"
    return True, ""


# --------------------------------------------------------------------------
# 2. Atomic writes
# --------------------------------------------------------------------------

def write_text_atomic(path: Path | str, text: str) -> None:
    """Write ``text`` to ``path`` through a temp file + ``os.replace``.

    The committed file is only ever replaced by a complete one, so a crash
    (kill, ENOSPC, disk full) leaves the previous content in place. The temp
    file is removed on any failure.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        with open(temp, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def write_catalog_atomic(catalog_path: Path | str, records: Iterable[Dict[str, Any]]) -> int:
    """Write ``catalog.jsonl`` atomically; returns the number of lines."""
    lines = "".join(
        json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n" for rec in records
    )
    write_text_atomic(catalog_path, lines)
    return lines.count("\n")


def write_index_atomic(index_path: Path | str, index_data: Dict[str, Any]) -> None:
    """Write ``index.json`` atomically. Call this *after* the catalog."""
    write_text_atomic(index_path, json.dumps(index_data, indent=2, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------
# 3. Loud loading
# --------------------------------------------------------------------------

def read_index(index_path: Path | str) -> Optional[Dict[str, Any]]:
    """Load ``index.json``; ``None`` when absent, :class:`CorruptStateError` when broken."""
    path = Path(index_path)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CorruptStateError(
            f"corrupt index {path}: {exc}. Refusing to rewrite it as a fresh catalog: "
            f"restore the file (git checkout --) or delete it deliberately."
        ) from exc
    if not isinstance(data, dict):
        raise CorruptStateError(
            f"corrupt index {path}: expected a JSON object, got {type(data).__name__}"
        )
    return data


def read_catalog(catalog_path: Path | str) -> Dict[str, Dict[str, Any]]:
    """Load ``catalog.jsonl`` into an ``advisory_id`` keyed dict.

    A line that is not valid JSON is fatal: the old loader swallowed it and the
    run then rewrote the remaining records as a shorter "valid" catalog, losing
    every record below the damage.
    """
    path = Path(catalog_path)
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CorruptStateError(f"unreadable catalog {path}: {exc}") from exc

    records: Dict[str, Dict[str, Any]] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise CorruptStateError(
                f"corrupt catalog {path}: line {line_number} is not valid JSON ({exc}). "
                f"Refusing to rewrite it as a shorter catalog: restore the file "
                f"(git checkout --) or delete it deliberately."
            ) from exc
        if not isinstance(record, dict) or "advisory_id" not in record:
            raise CorruptStateError(
                f"corrupt catalog {path}: line {line_number} has no advisory_id"
            )
        records[record["advisory_id"]] = record
    return records


# --------------------------------------------------------------------------
# 4. Run-scoped errors + capped history
# --------------------------------------------------------------------------

def _cap(errors: List[str]) -> List[str]:
    """Keep the most recent ``MAX_ERROR_HISTORY`` errors."""
    return errors[-MAX_ERROR_HISTORY:]


def load_error_history(prev_index: Optional[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """Split a persisted index into ``(this run's errors, kept history)``.

    The returned error list is always empty: errors are per run, so a failure
    recorded by an earlier run can never stop this one. Nothing is dropped --
    both ``error_history`` and the older ``errors`` list are merged (deduped,
    capped) into the history the index carries forward.
    """
    history: List[str] = []
    if prev_index:
        for source in (prev_index.get("error_history"), prev_index.get("errors")):
            if isinstance(source, list):
                for item in source:
                    if isinstance(item, str) and item and item not in history:
                        history.append(item)
    return [], _cap(history)


def merge_error_history(history: Iterable[str], run_errors: Iterable[str]) -> List[str]:
    """History plus this run's errors, deduped and capped, newest last."""
    merged: List[str] = []
    for item in list(history) + list(run_errors):
        if isinstance(item, str) and item and item not in merged:
            merged.append(item)
    return _cap(merged)
