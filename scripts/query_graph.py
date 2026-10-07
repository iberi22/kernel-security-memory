#!/usr/bin/env python3
"""Bounded evidence graph retrieval baseline."""
import argparse
import json
from pathlib import Path
import sqlite3
import tempfile
import sys
from collections import deque

import query_pack

ROOT = Path(__file__).resolve().parents[1]

def filter_temporal(item, as_of):
    if not as_of:
        return True

    # Exclude explicitly unknown time
    if 'known_at' in item:
        if not item['known_at']:
            return False
        if item['known_at'] > as_of:
            return False

    if 'observed_at' in item:
        if not item['observed_at']:
            return False
        if item['observed_at'] > as_of:
            return False

    return True

def query_graph(database_path, query, max_hops=2, max_nodes=10, as_of=None):
    td = None
    if database_path:
        lexical_results = query_pack.query_database(database_path, query)
    else:
        td = tempfile.TemporaryDirectory()
        path = Path(td.name) / 'memory.sqlite3'
        db = sqlite3.connect(path)
        try:
            db.executescript((ROOT / 'docs/memory/kernel-security-memory.sql').read_text())
        finally:
            db.close()
        lexical_results = query_pack.query_database(path, query)
        database_path = path

    if not lexical_results:
        if td:
            td.cleanup()
        return {'results': [], 'status': 'ABSTAIN_NO_MATCH'}

    db = sqlite3.connect(Path(database_path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        final_results = []
        for lex_res in lexical_results:
            rid = lex_res['id']
            rank = lex_res['lexical_rank']

            payload_str = db.execute('SELECT payload FROM records WHERE id=?', (rid,)).fetchone()
            if not payload_str:
                continue
            payload = json.loads(payload_str[0])

            nodes = payload.get('nodes', [])
            edges = payload.get('edges', [])
            claims = payload.get('claims', [])
            evidence = payload.get('evidence', [])
            evolution = payload.get('evolution', {'outcome': 'UNKNOWN', 'coverage': 'NOT_SCANNED', 'horizon_end': None, 'followups': []})

            evidence_by_id = {e['id']: e for e in evidence}

            valid_evidence_ids = set()
            for e in evidence:
                if filter_temporal(e, as_of):
                    valid_evidence_ids.add(e['id'])

            valid_claims = []
            for c in claims:
                if c.get('status') not in ('observed', 'validated'):
                    continue
                if not filter_temporal(c, as_of):
                    continue

                ev_ids = c.get('evidence_ids', [])
                if not all(eid in valid_evidence_ids for eid in ev_ids):
                    continue
                valid_claims.append(c)

            valid_edges = []
            adj = {}
            for e in edges:
                if e.get('status') not in ('observed', 'validated'):
                    continue
                if not filter_temporal(e, as_of):
                    continue

                ev_ids = e.get('evidence_ids', [])
                if not all(eid in valid_evidence_ids for eid in ev_ids):
                    continue

                valid_edges.append(e)
                s, t = e['source'], e['target']
                if s not in adj: adj[s] = []
                if t not in adj: adj[t] = []
                adj[s].append((e, t))
                adj[t].append((e, s))

            visited_nodes = set()
            visited_edges = set()
            queue = deque()

            # Start seeds from max_nodes bound
            for n in nodes:
                if len(visited_nodes) >= max_nodes:
                    break
                queue.append((n['id'], 0))
                visited_nodes.add(n['id'])

            truncated = len(visited_nodes) < len(nodes)

            while queue:
                curr, hop = queue.popleft()

                if curr in adj:
                    for edge, nxt in sorted(adj[curr], key=lambda x: x[1]):
                        if nxt not in visited_nodes:
                            if hop >= max_hops:
                                continue
                            if len(visited_nodes) >= max_nodes:
                                truncated = True
                                continue
                            visited_nodes.add(nxt)
                            queue.append((nxt, hop + 1))
                        # Only add edge if both endpoints are in visited_nodes
                        if curr in visited_nodes and nxt in visited_nodes:
                            visited_edges.add(edge['id'])

            visited_edges_list = [e for e in valid_edges if e['id'] in visited_edges]
            final_evidence_ids = set()
            for e in visited_edges_list:
                final_evidence_ids.update(e.get('evidence_ids', []))
            for c in valid_claims:
                final_evidence_ids.update(c.get('evidence_ids', []))

            final_evidence = [e for e in evidence if e['id'] in final_evidence_ids]

            res = {
                'id': rid,
                'seed_rank': rank,
                'paths': visited_edges_list,
                'evidence': final_evidence,
                'claims': valid_claims,
                'evolution': evolution,
                'truncated_nodes': truncated
            }
            final_results.append(res)

        return {'results': final_results, 'status': 'EVIDENCE_FOUND'}
    finally:
        db.close()
        if td:
            td.cleanup()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--database', type=Path)
    p.add_argument('--query', required=True)
    p.add_argument('--max-hops', type=int, default=2, choices=range(0, 3), metavar='[0-2]')
    p.add_argument('--max-nodes', type=int, default=10, metavar='[1-50]')
    p.add_argument('--as-of', type=str, help='ISO UTC optional')
    a = p.parse_args()

    if not 1 <= a.max_nodes <= 50:
        p.error("argument --max-nodes: invalid choice: {} (choose from 1 to 50)".format(a.max_nodes))

    res = query_graph(a.database, a.query, a.max_hops, a.max_nodes, a.as_of)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
