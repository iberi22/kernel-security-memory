#!/usr/bin/env python3
"""Exploratory, offline retrieval comparison over the trusted local SQL pack.

Binary record relevance supports Recall@5 and reciprocal rank without graded
labels. qrels-v1 graph probes are scored separately from lexical positives.
Evidence coverage measures returned citations, not their truth or correctness.
No qrels targets are used by retrieval. Timing excludes pack reconstruction.
"""
import argparse
from contextlib import closing
import hashlib
import json
import re
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure_baseline
import query_graph
import query_pack

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / 'docs/memory/kernel-security-memory.sql'
STRATEGIES = ('lexical_metadata', 'lexical_code_aware',
              'lexical_typed_graph', 'bounded_iterative_graph')
NOT_RUN = {
    'vector': 'No pinned embedding model or vector index; no model downloaded.',
    'llm': 'No LLM retrieval adapter configured; no model calls authorized or made.',
}
BUDGET = {'top_k': 5, 'candidate_limit': 50, 'max_hops': 2,
          'max_nodes_per_record': 10, 'additional_searches': 2}


def default_qrels():
    v2 = ROOT / 'experiments/qrels-v2.json'
    return v2 if v2.exists() else ROOT / 'experiments/qrels-v1.json'


def tokens(text):
    return set(re.findall(r'\w+', text.lower(), flags=re.UNICODE))


def code_aware(database, query):
    """Rerank the existing FTS pool: symbol token=4, path token=2.

    The metadata baseline already indexes node labels. This ablation adds
    structured pointer weights, not source bodies or an AST index.
    """
    candidates = query_pack.query_database(database, query, BUDGET['candidate_limit'])
    terms = tokens(' '.join(re.findall(r'\w+', query)[:32]))
    with closing(sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        weights = {}
        for result in candidates:
            payload = json.loads(db.execute('SELECT payload FROM records WHERE id=?',
                                            (result['id'],)).fetchone()[0])
            symbols, paths = set(), set()
            for node in payload.get('nodes', []):
                attrs = node.get('attributes', {})
                symbols.update(tokens(attrs.get('symbol', '')))
                paths.update(tokens(attrs.get('path', '')))
            weights[result['id']] = 4 * len(terms & symbols) + 2 * len(terms & paths)
    return sorted(candidates, key=lambda r: (-weights[r['id']],
                                            r['lexical_rank'], r['id']))[:5]


def graph_search(database, query):
    return query_graph.query_graph(database, query, max_hops=BUDGET['max_hops'],
                                   max_nodes=BUDGET['max_nodes_per_record'])['results'][:5]


def retrieve(database, query, strategy):
    if strategy == 'lexical_metadata':
        return query_pack.query_database(database, query, 5), 1
    if strategy == 'lexical_code_aware':
        return code_aware(database, query), 1
    if strategy not in STRATEGIES:
        raise ValueError('unsupported strategy: ' + strategy)
    results = graph_search(database, query)
    calls = 1
    if strategy == 'bounded_iterative_graph':
        # Only observed/validated paths returned by query_graph supply follow-ups.
        # Fixed initial frontier avoids self-reinforcing unlimited search.
        frontier = sorted({edge[endpoint].split(':', 1)[-1]
                           for result in results for edge in result.get('paths', [])
                           for endpoint in ('source', 'target')} - {query})[:2]
        by_id = {result['id']: result for result in results}
        for followup in frontier:
            extra = graph_search(database, followup)
            calls += 1
            for result in extra:
                if result['id'] not in by_id:
                    by_id[result['id']] = result
                else:
                    # Preserve initial ranking, union record-scoped citations/paths.
                    original = by_id[result['id']]
                    for field in ('evidence', 'paths', 'claims'):
                        combined = {v['id']: v for v in original.get(field, [])}
                        combined.update({v['id']: v for v in result.get(field, [])})
                        original[field] = [combined[key] for key in sorted(combined)]
        results = list(by_id.values())[:5]
    return results, calls


def score(item, results):
    expected = set(item['expected_record_ids'])
    ranked = list(dict.fromkeys(r['id'] for r in results))[:5]
    relevant = expected & set(ranked)
    required = set(item.get('expected_evidence_ids', []))
    # Evidence IDs are local to each record; unrelated records cannot satisfy them.
    citation_pairs = {(rid, eid) for rid in expected for eid in required}
    returned_pairs = {(r['id'], e['id']) for r in results[:5]
                      for e in r.get('evidence', []) if e.get('url') and e.get('sha256')}
    return {
        'recall_at_5': len(relevant) / len(expected) if expected else None,
        'mrr': next((1 / rank for rank, rid in enumerate(ranked, 1)
                     if rid in expected), 0.0) if expected else None,
        'citation_completeness': (len(citation_pairs & returned_pairs) / len(citation_pairs)
                                  if citation_pairs else None),
        'abstained': not ranked,
        'observed_record_ids': ranked,
        'observed_citations': [list(pair) for pair in sorted(returned_pairs)],
    }


def summarize(items):
    # Respect qrels-v1 graph-probe exclusions for primary ranking metrics.
    positives = [i for i in items if i['expect'] == 'FOUND' and i['mode'] == 'lexical']
    negatives = [i for i in items if i['expect'] == 'ABSTAIN']
    def mean(rows, key):
        values = [row[key] for row in rows if row[key] is not None]
        return sum(values) / len(values) if values else None
    return {'recall_at_5': mean(positives, 'recall_at_5'),
            'mrr': mean(positives, 'mrr'),
            'citation_completeness': mean(positives, 'citation_completeness'),
            'abstention_rate': mean(items, 'abstained'),
            'negative_abstention_rate': mean(negatives, 'abstained'),
            'elapsed_ms': sum(i['elapsed_ms'] for i in items),
            'ranking_queries': len(positives), 'negative_queries': len(negatives),
            'graph_probes': [i for i in items if i['mode'] == 'graph' and i['expect'] == 'FOUND']}


def measure(qrels_path=None, sql_path=SQL):
    qrels_path = Path(qrels_path) if qrels_path else default_qrels()
    qrels = json.loads(qrels_path.read_text(encoding='utf-8'))
    items = measure_baseline.load_qrels(qrels_path)
    if not items:
        raise ValueError('qrels must not be empty')
    for item in items:
        if (item.get('mode') not in ('lexical', 'graph')
                or item.get('expect') not in ('FOUND', 'ABSTAIN')
                or not isinstance(item.get('query'), str) or not item['query'].strip()
                or not isinstance(item.get('expected_record_ids'), list)
                or (item['expect'] == 'FOUND' and not item['expected_record_ids'])
                or (item['expect'] == 'ABSTAIN' and item['expected_record_ids'])):
            raise ValueError('unsupported qrels item: ' + str(item.get('id')))
    sql_path = Path(sql_path)
    report = {'corpus_sha256': hashlib.sha256(sql_path.read_bytes()).hexdigest(),
              'qrels_file': qrels_path.name, 'qrels_version': qrels.get('version'),
              'qrels_sha256': hashlib.sha256(qrels_path.read_bytes()).hexdigest(),
              'budget': BUDGET, 'strategies': {}}
    with tempfile.TemporaryDirectory() as td:
        database = measure_baseline.build_database(td, sql_path)
        with closing(sqlite3.connect(database)) as db:
            report['corpus_records'] = db.execute('SELECT count(*) FROM records').fetchone()[0]
        for strategy in STRATEGIES:
            scored = []
            for item in items:
                start = time.perf_counter()
                results, calls = retrieve(database, item['query'], strategy)
                elapsed = (time.perf_counter() - start) * 1000
                scored.append(dict(score(item, results), id=item['id'], mode=item['mode'],
                                   expect=item['expect'], elapsed_ms=elapsed, search_calls=calls))
            report['strategies'][strategy] = dict(status='MEASURED',
                                                  metrics=summarize(scored), items=scored)
    for name, reason in NOT_RUN.items():
        report['strategies'][name] = {'status': 'NOT_RUN', 'reason': reason, 'metrics': None}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qrels', type=Path, default=None)
    parser.add_argument('--sql', type=Path, default=SQL)
    parser.add_argument('--json-out', type=Path)
    args = parser.parse_args()
    report = measure(args.qrels, args.sql)
    serialized = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.json_out:
        args.json_out.write_text(serialized, encoding='utf-8')
    print(serialized, end='')


if __name__ == '__main__':
    main()
