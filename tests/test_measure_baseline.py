import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))

import measure_baseline as mb

RID = 'linux-CVE-2024-26581-mainline'


def lex_results(evidence_ids):
    return [{'id': RID, 'lexical_rank': -1.0,
             'evidence': [{'id': e} for e in evidence_ids]}]


def found_item(mode='lexical', evidence=('e-commit', 'e-before', 'e-after')):
    return {'id': 'qx', 'mode': mode, 'expect': 'FOUND', 'query': 'netfilter gc',
            'expected_record_ids': [RID], 'expected_evidence_ids': list(evidence)}


def abstain_item(mode='lexical'):
    return {'id': 'nx', 'mode': mode, 'expect': 'ABSTAIN', 'query': 'unrelated subsystem',
            'expected_record_ids': [], 'expected_evidence_ids': []}


class TestScoreItemSynthetic(unittest.TestCase):
    def test_found_hit_all_evidence_present(self):
        with patch.object(mb.query_pack, 'query_database',
                          return_value=lex_results(['e-commit', 'e-advisory', 'e-before', 'e-after'])):
            scored = mb.score_item(Path('/nonexistent'), found_item())
        self.assertEqual(scored['verdict'], 'HIT')

    def test_found_miss_no_results(self):
        with patch.object(mb.query_pack, 'query_database', return_value=[]):
            scored = mb.score_item(Path('/nonexistent'), found_item())
        self.assertEqual(scored['verdict'], 'MISS')

    def test_found_miss_partial_evidence(self):
        with patch.object(mb.query_pack, 'query_database',
                          return_value=lex_results(['e-commit'])):
            scored = mb.score_item(Path('/nonexistent'), found_item())
        self.assertEqual(scored['verdict'], 'MISS')

    def test_found_miss_wrong_record(self):
        with patch.object(mb.query_pack, 'query_database',
                          return_value=[{'id': 'other-record', 'evidence': [{'id': 'e-commit'}]}]):
            scored = mb.score_item(Path('/nonexistent'), found_item())
        self.assertEqual(scored['verdict'], 'MISS')

    def test_abstain_correct_on_empty(self):
        with patch.object(mb.query_pack, 'query_database', return_value=[]):
            scored = mb.score_item(Path('/nonexistent'), abstain_item())
        self.assertEqual(scored['verdict'], 'ABSTAIN_CORRECT')

    def test_abstain_failure_is_miss(self):
        with patch.object(mb.query_pack, 'query_database',
                          return_value=lex_results(['e-commit'])):
            scored = mb.score_item(Path('/nonexistent'), abstain_item())
        self.assertEqual(scored['verdict'], 'MISS')

    def test_graph_abstain_correct_on_no_match(self):
        with patch.object(mb.query_graph, 'query_graph',
                          return_value={'results': [], 'status': 'ABSTAIN_NO_MATCH'}):
            scored = mb.score_item(Path('/nonexistent'), abstain_item(mode='graph'))
        self.assertEqual(scored['verdict'], 'ABSTAIN_CORRECT')

    def test_graph_found_hit(self):
        with patch.object(mb.query_graph, 'query_graph',
                          return_value={'results': lex_results(['e-commit', 'e-advisory']),
                                        'status': 'EVIDENCE_FOUND'}):
            scored = mb.score_item(Path('/nonexistent'),
                                   found_item(mode='graph', evidence=('e-commit',)))
        self.assertEqual(scored['verdict'], 'HIT')

    def test_not_measured_unknown_mode(self):
        scored = mb.score_item(Path('/nonexistent'),
                               {'id': 'bad', 'mode': 'semantic', 'expect': 'FOUND', 'query': 'x'})
        self.assertEqual(scored['verdict'], 'NOT_MEASURED')

    def test_not_measured_missing_query(self):
        scored = mb.score_item(Path('/nonexistent'),
                               {'id': 'bad', 'mode': 'lexical', 'expect': 'FOUND'})
        self.assertEqual(scored['verdict'], 'NOT_MEASURED')

    def test_not_measured_retrieval_error(self):
        with patch.object(mb.query_pack, 'query_database', side_effect=sqlite3.Error('boom')):
            scored = mb.score_item(Path('/nonexistent'), found_item())
        self.assertEqual(scored['verdict'], 'NOT_MEASURED')


class TestSummarize(unittest.TestCase):
    def test_rates_exclude_not_measured(self):
        scored = [
            {'id': 'a', 'expect': 'FOUND', 'verdict': 'HIT'},
            {'id': 'b', 'expect': 'FOUND', 'verdict': 'MISS'},
            {'id': 'c', 'expect': 'FOUND', 'verdict': 'NOT_MEASURED'},
            {'id': 'd', 'expect': 'ABSTAIN', 'verdict': 'ABSTAIN_CORRECT'},
            {'id': 'e', 'expect': 'ABSTAIN', 'verdict': 'MISS'},
        ]
        s = mb.summarize(scored)
        self.assertEqual((s['positive_recall']['hits'], s['positive_recall']['denominator']), (1, 2))
        self.assertAlmostEqual(s['positive_recall']['value'], 0.5)
        self.assertEqual((s['negative_abstention']['correct'], s['negative_abstention']['denominator']), (1, 2))
        self.assertEqual(s['not_measured_ids'], ['c'])

    def test_empty_denominator_is_none_not_zero(self):
        s = mb.summarize([{'id': 'c', 'expect': 'FOUND', 'verdict': 'NOT_MEASURED'}])
        self.assertIsNone(s['positive_recall']['value'])
        self.assertIsNone(s['negative_abstention']['value'])


class TestRealSeedSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory()
        cls.db_path = mb.build_database(
            cls.td.name, ROOT / 'docs' / 'memory' / 'kernel-security-memory.sql')

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_q1_hits_real_seed(self):
        qrels = {i['id']: i for i in mb.load_qrels(ROOT / 'experiments' / 'qrels-v1.json')}
        scored = mb.score_item(self.db_path, qrels['q1-lex-interval-gc'])
        self.assertEqual(scored['verdict'], 'HIT')

    def test_n2_abstains_on_real_seed(self):
        qrels = {i['id']: i for i in mb.load_qrels(ROOT / 'experiments' / 'qrels-v1.json')}
        scored = mb.score_item(self.db_path, qrels['n2-unrelated-subsystem'])
        self.assertEqual(scored['verdict'], 'ABSTAIN_CORRECT')

    def test_full_measure_runs_without_not_measured(self):
        report = mb.measure(ROOT / 'experiments' / 'qrels-v1.json',
                            ROOT / 'docs' / 'memory' / 'kernel-security-memory.sql')
        self.assertEqual(len(report['items']), 9)
        self.assertEqual(report['summary']['n_not_measured'], 0)


if __name__ == '__main__':
    unittest.main()
