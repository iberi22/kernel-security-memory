"""Regression coverage for exact identifiers and lexical abstention gates."""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import measure_baseline
import query_graph
import query_pack

RID = 'linux-CVE-2024-26581-mainline'


class AbstentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.database = measure_baseline.build_database(
            cls.tempdir.name, ROOT / 'docs/memory/kernel-security-memory.sql')

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def test_unknown_cve_abstains_despite_strong_lexical_overlap(self):
        for query in (
            'CVE-2023-99999 nonexistent bluetooth driver use-after-free',
            'CVE-2024-265810 netfilter interval garbage collection',
            'cve-2023-99999 netfilter interval garbage collection',
            ' '.join(['netfilter'] * 33) + ' CVE-2023-99999',
        ):
            with self.subTest(query=query):
                self.assertEqual(query_pack.query_database(self.database, query), [])
                self.assertEqual(query_graph.query_graph(self.database, query),
                                 {'results': [], 'status': 'ABSTAIN_NO_MATCH'})

    def test_unrelated_subsystem_abstains(self):
        self.assertEqual(query_pack.query_database(
            self.database, 'eBPF verifier pruning logic selftest scale test'), [])

    def test_unrelated_driver_abstains(self):
        query = 'amdgpu firmware hang resume regression powerplay clocks'
        self.assertEqual(query_pack.query_database(self.database, query), [])
        self.assertEqual(query_graph.query_graph(self.database, query),
                         {'results': [], 'status': 'ABSTAIN_NO_MATCH'})

    def test_valid_paraphrase_hits_record_and_evidence(self):
        results = query_pack.query_database(
            self.database, 'skip end interval element generation mask removal garbage collection')
        record = next(result for result in results if result['id'] == RID)
        self.assertTrue({'e-commit', 'e-before', 'e-after'} <=
                        {e['id'] for e in record['evidence']})

    def test_exact_cve_found_without_lexical_context(self):
        for query in ('CVE-2024-26581', 'cve-2024-26581 unrelated wording'):
            with self.subTest(query=query):
                self.assertEqual([r['id'] for r in query_pack.query_database(
                    self.database, query)], [RID])

    def test_single_shared_token_and_repetition_abstain(self):
        for query in ('netfilter', 'netfilter astronomical_sentinel_987',
                      'netfilter NETFILTER netfilter'):
            with self.subTest(query=query):
                self.assertEqual(query_pack.query_database(self.database, query), [])

    def test_strong_single_term_query_remains_supported(self):
        self.assertEqual([r['id'] for r in query_pack.query_database(
            self.database, 'generation')], [RID])

    def test_graph_does_not_open_database_after_empty_lexical_seeds(self):
        with patch.object(query_pack, 'query_database', return_value=[]), \
                patch.object(sqlite3, 'connect', side_effect=AssertionError('graph spill')):
            self.assertEqual(query_graph.query_graph(self.database, 'unrelated driver'),
                             {'results': [], 'status': 'ABSTAIN_NO_MATCH'})


if __name__ == '__main__':
    unittest.main()
