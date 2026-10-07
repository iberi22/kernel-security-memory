#!/usr/bin/env python3
"""Measure qrels-v1 baseline against lexical/graph retrieval (stdlib only).

Builds the SQLite pack from the deterministic SQL text export inside a
temporary directory, runs every qrels-v1 item read-only
(`query_pack.query_database` for ``lexical`` mode,
`query_graph.query_graph` for ``graph`` mode), and reports one verdict per
item plus two bounded summary rates:

- ``positive_recall`` = HIT / measurable FOUND items (lexical q1-q4 and
  graph q5-q6 are scored together; see experiments/QRELS.md).
- ``negative_abstention`` = ABSTAIN_CORRECT / measurable ABSTAIN items.

Verdicts: HIT (expected record + all expected evidence observed), MISS
(expected FOUND not retrieved, or expected ABSTAIN but results returned),
ABSTAIN_CORRECT (expected ABSTAIN and nothing returned), NOT_MEASURED
(item not scoreable: unknown mode, missing fields, or retrieval error).

Deliberately NO MRR / composite recall: qrels-v1 carries unranked
FOUND/ABSTAIN judgments only, so ranking metrics would be invented.
"""
import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import query_graph
import query_pack

MODES = ("lexical", "graph")
VERDICTS = ("HIT", "MISS", "ABSTAIN_CORRECT", "NOT_MEASURED")


def load_qrels(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("items")
    if not isinstance(items, list):
        raise ValueError("qrels file must contain an 'items' list")
    return items


def build_database(directory, sql_path):
    """Build the pack SQLite from the SQL text export; returns the db path."""
    db_path = Path(directory) / "baseline.sqlite3"
    db = sqlite3.connect(db_path)
    try:
        db.executescript(Path(sql_path).read_text(encoding="utf-8"))
    finally:
        db.close()
    return db_path


def observed_by_record(results):
    """Map record id -> set of observed evidence ids."""
    observed = {}
    for res in results or []:
        rid = res.get("id")
        if not rid:
            continue
        ev_ids = {e.get("id") for e in res.get("evidence", []) if e.get("id")}
        observed.setdefault(rid, set()).update(ev_ids)
    return observed


def run_item(db_path, item, limit=5):
    """Run one qrels item read-only; returns (results, status, error)."""
    mode = item.get("mode")
    query = item.get("query")
    if mode == "lexical":
        results = query_pack.query_database(db_path, query, limit)
        status = "EVIDENCE_FOUND" if results else "ABSTAIN_NO_MATCH"
        return results, status, None
    if mode == "graph":
        outcome = query_graph.query_graph(db_path, query)
        return outcome.get("results", []), outcome.get("status"), None
    return None, None, "unsupported mode %r" % (mode,)


def score_item(db_path, item, limit=5):
    """Score one qrels item; never raises for scoreable-shape problems."""
    item_id = item.get("id", "<missing-id>")
    base = {
        "id": item_id,
        "mode": item.get("mode"),
        "expect": item.get("expect"),
        "query": item.get("query"),
    }
    if not item.get("mode") or not isinstance(item.get("query"), str) or not item["query"].strip():
        base.update(verdict="NOT_MEASURED", reason="missing or empty mode/query",
                    observed_record_ids=[], observed_evidence_ids=[])
        return base
    if item.get("mode") not in MODES:
        base.update(verdict="NOT_MEASURED", reason="unsupported mode %r" % (item.get("mode"),),
                    observed_record_ids=[], observed_evidence_ids=[])
        return base
    if item.get("expect") not in ("FOUND", "ABSTAIN"):
        base.update(verdict="NOT_MEASURED", reason="unsupported expect %r" % (item.get("expect"),),
                    observed_record_ids=[], observed_evidence_ids=[])
        return base
    try:
        results, status, error = run_item(db_path, item, limit)
    except Exception as exc:  # retrieval failure => not measurable, not a MISS
        base.update(verdict="NOT_MEASURED", reason="retrieval error: %s: %s" % (type(exc).__name__, exc),
                    observed_record_ids=[], observed_evidence_ids=[])
        return base
    if error is not None:
        base.update(verdict="NOT_MEASURED", reason=error,
                    observed_record_ids=[], observed_evidence_ids=[])
        return base

    observed = observed_by_record(results)
    base["status"] = status
    base["observed_record_ids"] = sorted(observed)
    base["observed_evidence_ids"] = sorted({e for ev in observed.values() for e in ev})

    if item["expect"] == "ABSTAIN":
        if not observed:
            base.update(verdict="ABSTAIN_CORRECT", reason="no results, as expected")
        else:
            base.update(verdict="MISS",
                        reason="expected abstention but %d record(s) returned" % len(observed))
        return base

    # expect == FOUND
    expected_records = item.get("expected_record_ids") or []
    expected_evidence = set(item.get("expected_evidence_ids") or [])
    if not expected_records:
        base.update(verdict="NOT_MEASURED", reason="FOUND item without expected_record_ids")
        return base
    hits = [rid for rid in expected_records
            if rid in observed and expected_evidence <= observed[rid]]
    if hits:
        base.update(verdict="HIT", reason="record %s with all %d expected evidence id(s)"
                     % (hits[0], len(expected_evidence)))
    else:
        base.update(verdict="MISS", reason="expected record/evidence not observed")
    return base


def summarize(scored):
    """Bounded summary rates over measurable items only (no composites)."""
    pos = [s for s in scored if s.get("expect") == "FOUND" and s.get("verdict") in ("HIT", "MISS")]
    neg = [s for s in scored if s.get("expect") == "ABSTAIN" and s.get("verdict") in ("ABSTAIN_CORRECT", "MISS")]
    not_measured = [s["id"] for s in scored if s.get("verdict") == "NOT_MEASURED"]
    pos_hits = sum(1 for s in pos if s["verdict"] == "HIT")
    neg_ok = sum(1 for s in neg if s["verdict"] == "ABSTAIN_CORRECT")

    def rate(ok, total):
        return ok / total if total else None

    return {
        "n_items": len(scored),
        "n_measured": len(pos) + len(neg),
        "n_not_measured": len(not_measured),
        "not_measured_ids": not_measured,
        "positive_recall": {"hits": pos_hits, "denominator": len(pos), "value": rate(pos_hits, len(pos))},
        "negative_abstention": {"correct": neg_ok, "denominator": len(neg), "value": rate(neg_ok, len(neg))},
    }


def measure(qrels_path, sql_path, limit=5):
    items = load_qrels(qrels_path)
    with tempfile.TemporaryDirectory() as td:
        db_path = build_database(td, sql_path)
        scored = [score_item(db_path, item, limit) for item in items]
    return {"items": scored, "summary": summarize(scored)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qrels", type=Path, default=ROOT / "experiments" / "qrels-v1.json")
    p.add_argument("--sql", type=Path, default=ROOT / "docs" / "memory" / "kernel-security-memory.sql")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--json-out", type=Path, default=None)
    a = p.parse_args()
    report = measure(a.qrels, a.sql, a.limit)
    s = report["summary"]
    lines = ["baseline qrels-v1: %d items (%d measured, %d NOT_MEASURED)"
             % (s["n_items"], s["n_measured"], s["n_not_measured"])]
    for item in report["items"]:
        lines.append("  %-28s %-8s %-15s %s" % (item["id"], item.get("mode"), item["verdict"], item.get("reason")))
    pr = s["positive_recall"]
    na = s["negative_abstention"]
    lines.append("positive_recall: %s/%s%s" % (pr["hits"], pr["denominator"],
                 " = %.3f" % pr["value"] if pr["value"] is not None else " (NOT_MEASURED: empty denominator)"))
    lines.append("negative_abstention: %s/%s%s" % (na["correct"], na["denominator"],
                 " = %.3f" % na["value"] if na["value"] is not None else " (NOT_MEASURED: empty denominator)"))
    print("\n".join(lines))
    if a.json_out:
        a.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
