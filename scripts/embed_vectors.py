#!/usr/bin/env python3
"""Derived vector index builder (DISPOSABLE derived view; corpus JSON/SQL rules).

Contract implemented here is pinned in ``experiments/VECTORS.md``. Read it
first. Summary of the two execution paths:

- ``fixture`` (default): deterministic stdlib-only hashed trigram projection.
  Offline, CPU-trivial, for CI/tests/scaffolding. NOT a neural measurement.
- ``st`` (MANUAL): ``sentence-transformers/all-MiniLM-L6-v2``. Requires
  network (model download) + ``torch`` + ``sentence-transformers``; never
  runs in CI. The exact HF revision must be recorded in the output manifest.

``sqlite-vec`` (pinned ``SQLITE_VEC_VERSION``) is required only to materialize
the ``vec0`` table. If it is not importable this module raises a clear
``RuntimeError``; everything else (contract, format, offline comparison)
works without it and without network.
"""
import argparse
import hashlib
import json
import math
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

# ---- Pinned contract (must match experiments/VECTORS.md) ----
MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = None  # pinned at MANUAL generation time, recorded in manifest
TOKENIZER = "bert-base-uncased WordPiece, max_seq_length=256, truncation+padding"
DIMS = 384
METRIC = "cosine"
NORMALIZATION = "l2"
TEMPLATE_VERSION = "vectors-v1"
SQLITE_VEC_VERSION = "0.1.9"
ST_VERSION = "6.1.0"  # pinned at contract time (pip index, 2026-10-07)
VERDICTS = ("HIT", "MISS", "ABSTAIN_CORRECT", "NOT_MEASURED")


def build_text(record):
    """Deterministic embed template vectors-v1 for one JSON record dict.

    Template: title + one line per node label + one line per claim text
    (same source fields as the FTS index in ``build_pack.py``).
    """
    lines = [record.get("title", "")]
    lines.extend(n.get("label", "") for n in record.get("nodes", []))
    lines.extend(c.get("text", "") for c in record.get("claims", []))
    return "\n".join(s for s in lines if isinstance(s, str) and s.strip())


def l2_normalize(vec):
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        raise ValueError("cannot normalize zero vector")
    return [v / norm for v in vec]


def cosine(a, b):
    if len(a) != len(b):
        raise ValueError("dimension mismatch %d vs %d" % (len(a), len(b)))
    return sum(x * y for x, y in zip(a, b))  # inputs are L2-normalized


def fixture_embed(text, dims=DIMS):
    """Deterministic offline stand-in embedding (hashed char trigrams).

    Stable across runs/machines (sha256, no ``hash()`` seed dependence),
    L2-normalized, ``dims`` floats. For tests/scaffolding ONLY: it carries
    no semantic signal and its qrels numbers are NOT a benchmark.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("fixture_embed needs non-empty text")
    vec = [0.0] * dims
    padded = "  " + text.lower() + "  "
    for i in range(len(padded) - 2):
        tri = padded[i:i + 3]
        idx = int(hashlib.sha256(tri.encode()).hexdigest(), 16) % dims
        sign = 1.0 if int(hashlib.sha256(b"s" + tri.encode()).hexdigest(), 16) % 2 else -1.0
        vec[idx] += sign
    return l2_normalize(vec)


def require_sqlite_vec():
    """Import sqlite-vec or raise a clear, actionable RuntimeError."""
    try:
        import sqlite_vec  # noqa: F401
        import sqlite_vec as mod
        return mod
    except ImportError:
        raise RuntimeError(
            "sqlite-vec is not installed (contract pins sqlite-vec==%s). "
                "Install it with: pip install 'sqlite-vec==%s'. "
            "Vector TABLE materialization is unavailable; offline contract, "
            "format and fixture-comparison functions in this module still work."
            % (SQLITE_VEC_VERSION, SQLITE_VEC_VERSION)
        )


def st_embed(texts):
    """MANUAL neural path: real model embeddings (needs network + torch)."""
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        raise RuntimeError(
            "sentence-transformers is not installed (contract pins %s; "
            "model %s). Neural generation is MANUAL-only: run on a machine "
            "with network + CPU torch, record the HF revision in the "
            "manifest, and never gate CI on it." % (ST_VERSION, MODEL_ID)
        )
    model = SentenceTransformer(MODEL_ID, revision=MODEL_REVISION)
    return [l2_normalize(list(map(float, v))) for v in
            model.encode(texts, normalize_embeddings=False)]


def write_vectors(items, path, provider, dims=DIMS):
    """Write the canonical vectors JSON file. ``items``: list of (id, vec)."""
    if provider not in ("fixture", "st"):
        raise ValueError("unknown provider %r" % (provider,))
    packed = []
    for rid, vec in items:
        if not isinstance(rid, str) or not rid.strip():
            raise ValueError("invalid record id %r" % (rid,))
        if len(vec) != dims or not all(isinstance(v, float) for v in vec):
            raise ValueError("record %s: vector must be %d floats" % (rid, dims))
        packed.append({"id": rid, "vector": list(vec)})
    doc = {"contract": {"model": MODEL_ID, "model_revision": MODEL_REVISION,
                        "tokenizer": TOKENIZER, "dims": dims, "metric": METRIC,
                        "normalization": NORMALIZATION,
                        "template": TEMPLATE_VERSION, "provider": provider,
                        "sqlite_vec": SQLITE_VEC_VERSION},
           "items": packed}
    Path(path).write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_vectors(path):
    """Load + strictly validate a vectors JSON file."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    contract = doc.get("contract")
    if not isinstance(contract, dict):
        raise ValueError("missing 'contract' object")
    dims = contract.get("dims")
    if dims != DIMS:
        raise ValueError("contract dims %r != pinned %d" % (dims, DIMS))
    if contract.get("metric") != METRIC or contract.get("normalization") != NORMALIZATION:
        raise ValueError("contract metric/normalization mismatch (want cosine/l2)")
    items = doc.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("'items' must be a non-empty list")
    out = {}
    for it in items:
        vec = it.get("vector")
        if (not isinstance(it.get("id"), str) or not isinstance(vec, list)
                or len(vec) != DIMS or not all(isinstance(v, (int, float)) for v in vec)):
            raise ValueError("malformed item %r" % (it.get("id"),))
        norm = math.sqrt(sum(v * v for v in vec))
        if abs(norm - 1.0) > 1e-3:
            raise ValueError("item %s not L2-normalized (norm=%.4f)" % (it["id"], norm))
        out[it["id"]] = [float(v) for v in vec]
    return contract, out


def rank_by_cosine(query_vec, vectors, limit=5):
    ranked = sorted(vectors, key=lambda rid: cosine(query_vec, vectors[rid]), reverse=True)
    return ranked[:limit]


def score_fixture_against_qrels(qrels_path, sql_path, limit=5):
    """Offline fixture-only comparison over qrels-v1 (no network, no model).

    Same verdict semantics as ``measure_baseline`` but top-``limit`` cosine
    ranking over fixture vectors. The summary is labeled
    ``provider="fixture"``: these numbers exercise the plumbing, they are
    NOT a vector measurement (see experiments/VECTORS.md -> NOT_MEASURED).
    """
    qrels = json.loads(Path(qrels_path).read_text(encoding="utf-8"))["items"]
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "vec.sqlite3"
        db = sqlite3.connect(db_path)
        try:
            db.executescript(Path(sql_path).read_text(encoding="utf-8"))
            rows = db.execute("SELECT id, payload FROM records").fetchall()
        finally:
            db.close()
        texts = {}
        for rid, payload in rows:
            texts[rid] = build_text(json.loads(payload))
    vectors = {rid: fixture_embed(t) for rid, t in texts.items()}
    scored = []
    for item in qrels:
        base = {"id": item.get("id"), "mode": item.get("mode"),
                "expect": item.get("expect"), "provider": "fixture"}
        if item.get("expect") not in ("FOUND", "ABSTAIN") or not isinstance(item.get("query"), str):
            base.update(verdict="NOT_MEASURED", reason="unscoreable item shape")
            scored.append(base)
            continue
        ranked = rank_by_cosine(fixture_embed(item["query"]), vectors, limit)
        if item["expect"] == "ABSTAIN":
            if not ranked:
                base.update(verdict="ABSTAIN_CORRECT", reason="no candidates, as expected")
            else:
                base.update(verdict="MISS",
                            reason="fixture ranking returned %d candidate(s)" % len(ranked))
        else:
            want = set(item.get("expected_record_ids") or [])
            if want & set(ranked):
                base.update(verdict="HIT",
                            reason="expected record in fixture top-%d" % len(ranked))
            else:
                base.update(verdict="MISS", reason="expected record absent from fixture top-%d"
                            % len(ranked))
        scored.append(base)
    pos = [s for s in scored if s["expect"] == "FOUND" and s["verdict"] in ("HIT", "MISS")]
    neg = [s for s in scored if s["expect"] == "ABSTAIN" and s["verdict"] in ("ABSTAIN_CORRECT", "MISS")]
    hits = sum(1 for s in pos if s["verdict"] == "HIT")
    oks = sum(1 for s in neg if s["verdict"] == "ABSTAIN_CORRECT")
    return {"items": scored,
            "summary": {"provider": "fixture",
                        "positive_recall": {"hits": hits, "denominator": len(pos),
                                            "value": hits / len(pos) if pos else None},
                        "negative_abstention": {"correct": oks, "denominator": len(neg),
                                                "value": oks / len(neg) if neg else None},
                        "warning": "fixture plumbing only; NOT a neural vector measurement"}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sql", type=Path, default=ROOT / "docs" / "memory" / "kernel-security-memory.sql")
    p.add_argument("--qrels", type=Path, default=ROOT / "experiments" / "qrels-v1.json")
    p.add_argument("--out", type=Path, default=None, help="write fixture vectors JSON here")
    p.add_argument("--provider", choices=("fixture", "st"), default="fixture")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--measure", action="store_true", help="run offline fixture comparison")
    p.add_argument("--check-sqlite-vec", action="store_true")
    a = p.parse_args()
    if a.check_sqlite_vec:
        mod = require_sqlite_vec()
        print("sqlite-vec OK: %s" % getattr(mod, "__version__", "unknown version"))
        return 0
    if a.provider == "st":
        print("MANUAL path: downloads %s (network + torch required, not CI)."
              % MODEL_ID)
    if a.measure:
        report = score_fixture_against_qrels(a.qrels, a.sql, a.limit)
        s = report["summary"]
        print("fixture comparison (NOT a neural measurement):")
        for it in report["items"]:
            print("  %-28s %-8s %-15s %s" % (it["id"], it.get("mode"), it["verdict"], it.get("reason")))
        print("positive_recall: %s/%s  negative_abstention: %s/%s  [%s]"
              % (s["positive_recall"]["hits"], s["positive_recall"]["denominator"],
                 s["negative_abstention"]["correct"], s["negative_abstention"]["denominator"],
                 s["warning"]))
    if a.out:
        if a.provider == "st":
            raise SystemExit("refusing: --provider st with --out needs MANUAL run; see experiments/VECTORS.md")
        db = sqlite3.connect(":memory:")
        try:
            db.executescript(a.sql.read_text(encoding="utf-8"))
            recs = [(r, build_text(json.loads(pl)))
                    for r, pl in db.execute("SELECT id, payload FROM records").fetchall()]
        finally:
            db.close()
        write_vectors([(r, fixture_embed(t)) for r, t in recs], a.out, "fixture")
        print("wrote %d fixture vectors -> %s" % (len(recs), a.out))
    if not a.measure and not a.out and not a.check_sqlite_vec:
        p.print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
