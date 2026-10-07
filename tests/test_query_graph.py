import unittest
import sqlite3
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import sys
import os

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))

from query_graph import query_graph
from build_pack import SCHEMA, canonical

class TestQueryGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.td.name) / 'test.sqlite3'

        # Build synthetic DB
        db = sqlite3.connect(cls.db_path)

        db.executescript(SCHEMA)

        # A synthetic record
        rid = 'test-record'
        record = {
            'id': rid,
            'schema_version': '0.1.0',
            'project': 'linux',
            'title': 'Test title',
            'status': 'observed',
            'nodes': [
                {'id': 'n1', 'type': 'commit', 'label': 'N1', 'attributes': {}},
                {'id': 'n2', 'type': 'commit', 'label': 'N2', 'attributes': {}},
                {'id': 'n3', 'type': 'commit', 'label': 'N3', 'attributes': {}},
                {'id': 'n4', 'type': 'commit', 'label': 'N4', 'attributes': {}},
                {'id': 'n5', 'type': 'commit', 'label': 'N5', 'attributes': {}},
                {'id': 'n6', 'type': 'commit', 'label': 'N6', 'attributes': {}}
            ],
            'evidence': [
                {'id': 'e1', 'sha256': 'a'*64, 'url': 'https://a', 'fetch_url': 'https://a', 'observed_at': '2023-01-01T00:00:00Z', 'hash_scope': 'a', 'source_license': 'a', 'extractor': 'a', 'canonicalization': 'a'},
                {'id': 'e2', 'sha256': 'b'*64, 'url': 'https://b', 'fetch_url': 'https://b', 'observed_at': '2025-01-01T00:00:00Z', 'hash_scope': 'b', 'source_license': 'b', 'extractor': 'b', 'canonicalization': 'b'},
                {'id': 'e3', 'sha256': 'c'*64, 'url': 'https://c', 'fetch_url': 'https://c', 'observed_at': '', 'hash_scope': 'c', 'source_license': 'c', 'extractor': 'c', 'canonicalization': 'c'}
            ],
            'claims': [
                {'id': 'c1', 'status': 'observed', 'text': 'Claim 1', 'evidence_ids': ['e1']},
                {'id': 'c2', 'status': 'observed', 'text': 'Claim 2', 'evidence_ids': ['e1', 'e2']}
            ],
            'edges': [
                {'id': 'edge1', 'source': 'n1', 'target': 'n2', 'relation': 'fixes', 'status': 'observed', 'evidence_ids': ['e1'], 'known_at': '2023-01-01T00:00:00Z'},
                {'id': 'edge2', 'source': 'n2', 'target': 'n3', 'relation': 'fixes', 'status': 'observed', 'evidence_ids': ['e1'], 'known_at': '2023-01-01T00:00:00Z'},
                {'id': 'edge3', 'source': 'n3', 'target': 'n4', 'relation': 'fixes', 'status': 'observed', 'evidence_ids': ['e1'], 'known_at': '2023-01-01T00:00:00Z'},
                # Cycle
                {'id': 'edge4', 'source': 'n4', 'target': 'n1', 'relation': 'fixes', 'status': 'observed', 'evidence_ids': ['e1'], 'known_at': '2023-01-01T00:00:00Z'},
                # Future edge
                {'id': 'edge5', 'source': 'n1', 'target': 'n5', 'relation': 'fixes', 'status': 'observed', 'evidence_ids': ['e2'], 'known_at': '2025-01-01T00:00:00Z'},
                # Dangling evidence
                {'id': 'edge6', 'source': 'n1', 'target': 'n6', 'relation': 'fixes', 'status': 'observed', 'evidence_ids': ['e99'], 'known_at': '2023-01-01T00:00:00Z'},
            ],
            'evolution': {'outcome': 'UNKNOWN', 'coverage': 'a', 'horizon_end': None, 'followups': []},
            'validation': {},
            'license': {}
        }

        db.execute('INSERT INTO records VALUES (?,?,?,?)', (rid, record['project'], record['title'], canonical(record)))
        db.execute('INSERT INTO record_fts VALUES (?,?)', (rid, "Test title N1 N2 N3 N4 N5 N6 Claim 1 Claim 2"))

        # A second record to check cross-record mixing
        rid2 = 'test-record-2'
        record2 = {
            'id': rid2,
            'schema_version': '0.1.0',
            'project': 'linux',
            'title': 'Other title',
            'status': 'observed',
            'nodes': [{'id': 'nx', 'type': 'commit', 'label': 'NX', 'attributes': {}}],
            'evidence': [],
            'claims': [],
            'edges': [],
            'evolution': {'outcome': 'UNKNOWN', 'coverage': 'a', 'horizon_end': None, 'followups': []},
            'validation': {},
            'license': {}
        }
        db.execute('INSERT INTO records VALUES (?,?,?,?)', (rid2, record2['project'], record2['title'], canonical(record2)))
        db.execute('INSERT INTO record_fts VALUES (?,?)', (rid2, "Other title NX"))

        db.commit()
        db.close()

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_max_hops_and_nodes_truncation(self):
        # With max_nodes=2, only 2 nodes (n1, n2) out of 6 are seeded, so it truncates immediately.
        # Since max_hops=2 but queue pops are bounds checked, no edges are explored.
        res = query_graph(self.db_path, "Test title", max_hops=2, max_nodes=2)
        self.assertEqual(res['status'], 'EVIDENCE_FOUND')
        rec = res['results'][0]
        self.assertTrue(rec['truncated_nodes'])
        self.assertEqual(len(rec['paths']), 1)

        # With max_nodes=10 (unbounded nodes list), all 6 nodes are seeded.
        res2 = query_graph(self.db_path, "Test title", max_hops=2, max_nodes=10)
        rec2 = res2['results'][0]
        self.assertFalse(rec2['truncated_nodes'])
        self.assertTrue(len(rec2['paths']) > 0)

    def test_cycles(self):
        res = query_graph(self.db_path, "Test title", max_hops=2, max_nodes=10)
        rec = res['results'][0]
        path_ids = {e['id'] for e in rec['paths']}
        # Graph is n1-n2-n3-n4-n1. All these edges should be included.
        self.assertTrue({'edge1', 'edge2', 'edge3', 'edge4'}.issubset(path_ids))
        self.assertFalse(rec['truncated_nodes'])

    def test_cross_record_isolation(self):
        res = query_graph(self.db_path, "Test title Other title", max_hops=2, max_nodes=10)
        # Should return both records. Neither should mix nodes/edges.
        self.assertEqual(len(res['results']), 2)
        r1 = next(r for r in res['results'] if r['id'] == 'test-record')
        r2 = next(r for r in res['results'] if r['id'] == 'test-record-2')
        self.assertTrue(len(r1['paths']) > 0)
        self.assertEqual(len(r2['paths']), 0)

    def test_dangling_evidence(self):
        res = query_graph(self.db_path, "Test title", max_hops=2, max_nodes=10)
        rec = res['results'][0]
        path_ids = {e['id'] for e in rec['paths']}
        # edge6 depends on e99 which is dangling
        self.assertNotIn('edge6', path_ids)

    def test_future_cutoff_as_of(self):
        # as_of 2024. e2 is 2025, edge5 is 2025. claim2 depends on e2.
        res = query_graph(self.db_path, "Test title", max_hops=2, max_nodes=10, as_of="2024-01-01T00:00:00Z")
        rec = res['results'][0]
        path_ids = {e['id'] for e in rec['paths']}
        claim_ids = {c['id'] for c in rec['claims']}

        # edge5 excluded due to its own known_at > as_of, and e2 > as_of
        self.assertNotIn('edge5', path_ids)
        # claim2 excluded due to dangling evidence e2 (e2 is filtered out due to as_of)
        self.assertNotIn('c2', claim_ids)

        # edge1 is 2023, should be kept
        self.assertIn('edge1', path_ids)
        self.assertIn('c1', claim_ids)

    def test_abstain_no_match(self):
        res = query_graph(self.db_path, "Nonexistent term", max_hops=2, max_nodes=10)
        self.assertEqual(res['status'], 'ABSTAIN_NO_MATCH')
        self.assertEqual(len(res['results']), 0)

    def test_real_bootstrap(self):
        res = query_graph(None, "garbage collection", max_hops=2, max_nodes=10)
        self.assertEqual(res['status'], 'EVIDENCE_FOUND')
        self.assertEqual(len(res['results']), 1)
        rec = res['results'][0]
        self.assertEqual(rec['id'], 'linux-CVE-2024-26581-mainline')
        self.assertIn('paths', rec)

if __name__ == '__main__':
    unittest.main()
