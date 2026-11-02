#!/usr/bin/env python3
"""Read an independent SQLite evidence pack; no Xavier database mutation."""
import argparse
import json
from pathlib import Path
import re
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CVE_ID = re.compile(r'\bCVE-\d{4}-\d+\b', re.IGNORECASE)
# FTS5 BM25 is negative (lower is better). This conservative pilot cutoff
# retains strong single-term searches; it is not a calibrated relevance score.
SINGLE_TERM_RANK_CUTOFF = -5.0


def query_database(path, query, limit=5):
    if not 1 <= limit <= 50:
        raise ValueError('limit must be 1..50')
    terms = list(dict.fromkeys(re.findall(r'\w+', query.casefold(), flags=re.UNICODE)))[:32]
    if not terms:
        return []
    # Quote terms so upstream/source data cannot inject FTS expressions.
    quoted_terms = ['"' + t.replace('"', '""') + '"' for t in terms]
    expression = ' OR '.join(quoted_terms)
    uri = Path(path).resolve().as_uri() + '?mode=ro'
    db = sqlite3.connect(uri, uri=True)
    try:
        cve_ids = {cve.upper() for cve in CVE_ID.findall(query)}
        if cve_ids:
            # An explicit identifier is authoritative: never substitute lexical
            # neighbours, partial numeric matches, or incidental payload mentions.
            found = [(rid, 0.0) for (rid,) in db.execute('SELECT id FROM records ORDER BY id')
                     if cve_ids <= {cve.upper() for cve in CVE_ID.findall(rid)}][:limit]
        else:
            # Count distinct query terms using FTS's own tokenization. Filter
            # before LIMIT so weak candidates cannot crowd out valid matches.
            matches = ' UNION ALL '.join(
                'SELECT id FROM record_fts WHERE record_fts MATCH ?'
                for _ in quoted_terms)
            found = db.execute(
                'WITH matches(id) AS (' + matches + ') '
                'SELECT id,bm25(record_fts) FROM record_fts '
                'WHERE record_fts MATCH ? AND (id IN '
                '(SELECT id FROM matches GROUP BY id HAVING count(*) >= 2) '
                'OR bm25(record_fts) <= ?) '
                'ORDER BY bm25(record_fts),id LIMIT ?',
                (*quoted_terms, expression, SINGLE_TERM_RANK_CUTOFF, limit)).fetchall()
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
