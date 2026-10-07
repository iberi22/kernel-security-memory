#!/usr/bin/env python3
"""Read an independent SQLite evidence pack; no Xavier database mutation."""
import argparse
import json
from pathlib import Path
import re
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def query_database(path, query, limit=5):
    if not 1 <= limit <= 50:
        raise ValueError('limit must be 1..50')
    terms = re.findall(r'\w+', query, flags=re.UNICODE)[:32]
    if not terms:
        return []
    # Quote terms so upstream/source data cannot inject FTS expressions.
    expression = ' OR '.join('"' + t.replace('"', '""') + '"' for t in terms)
    uri = Path(path).resolve().as_uri() + '?mode=ro'
    db = sqlite3.connect(uri, uri=True)
    try:
        found = db.execute('SELECT id,bm25(record_fts) FROM record_fts WHERE record_fts MATCH ? ORDER BY bm25(record_fts),id LIMIT ?', (expression, limit)).fetchall()
        results = []
        for rid, rank in found:
            payload = json.loads(db.execute('SELECT payload FROM records WHERE id=?', (rid,)).fetchone()[0])
            results.append({'id': rid, 'lexical_rank': rank, 'retrieval': 'lexical record search + within-record evidence graph', 'claims': payload['claims'], 'evidence': payload['evidence'], 'edges': payload['edges'], 'evolution': payload['evolution'], 'security_confirmation': 'NOT_ASSESSED'})
        return results
    finally:
        db.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', type=Path)
    p.add_argument('--query', required=True)
    p.add_argument('--limit', type=int, default=5)
    a = p.parse_args()
    if a.database:
        result = query_database(a.database, a.query, a.limit)
    else:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'memory.sqlite3'
            db = sqlite3.connect(path)
            try:
                db.executescript((ROOT / 'docs/memory/kernel-security-memory.sql').read_text())
            finally:
                db.close()
            result = query_database(path, a.query, a.limit)
    print(json.dumps({'results': result, 'status': 'EVIDENCE_FOUND' if result else 'ABSTAIN_NO_MATCH', 'detector': False}, indent=2))


if __name__ == '__main__':
    main()
