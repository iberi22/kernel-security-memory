import copy
from contextlib import closing
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import measure_retrieval as mr


class TestMeasuredRetrieval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = mr.measure()

    def test_runs_every_query_for_four_strategies(self):
        items = json.loads(mr.default_qrels().read_text())['items']
        for name in mr.STRATEGIES:
            strategy = self.report['strategies'][name]
            self.assertEqual(strategy['status'], 'MEASURED')
            self.assertEqual([i['id'] for i in strategy['items']], [i['id'] for i in items])
            self.assertTrue(all(i['search_calls'] <= 3 for i in strategy['items']))

    def test_metrics_are_bounded(self):
        for name in mr.STRATEGIES:
            metrics = self.report['strategies'][name]['metrics']
            for key in ('recall_at_5', 'mrr', 'citation_completeness',
                        'abstention_rate', 'negative_abstention_rate'):
                self.assertGreaterEqual(metrics[key], 0)
                self.assertLessEqual(metrics[key], 1)
            self.assertGreaterEqual(metrics['elapsed_ms'], 0)

    def test_not_run_has_reason_and_no_fabricated_metrics(self):
        for name in ('vector', 'llm'):
            result = self.report['strategies'][name]
            self.assertEqual(result['status'], 'NOT_RUN')
            self.assertTrue(result['reason'])
            self.assertIsNone(result['metrics'])

    def test_reproducible_hash_and_scores(self):
        second = mr.measure()
        self.assertEqual(second['corpus_sha256'], hashlib.sha256(mr.SQL.read_bytes()).hexdigest())
        self.assertEqual(second['corpus_sha256'], self.report['corpus_sha256'])
        self.assertEqual(second['qrels_sha256'], self.report['qrels_sha256'])
        def without_timing(report):
            result = copy.deepcopy(report)
            def scrub(value):
                if isinstance(value, dict):
                    value.pop('elapsed_ms', None)
                    for child in value.values():
                        scrub(child)
                elif isinstance(value, list):
                    for child in value:
                        scrub(child)
            scrub(result)
            return result
        self.assertEqual(without_timing(second), without_timing(self.report))

    def test_rank_and_record_scoped_citations(self):
        item = {'expected_record_ids': ['target'], 'expected_evidence_ids': ['e1', 'e2']}
        results = [{'id': 'other', 'evidence': [{'id': 'e2', 'url': 'u', 'sha256': 'h'}]},
                   {'id': 'target', 'evidence': [{'id': 'e1', 'url': 'u', 'sha256': 'h'}]}]
        scored = mr.score(item, results)
        self.assertEqual(scored['recall_at_5'], 1)
        self.assertEqual(scored['mrr'], 0.5)
        self.assertEqual(scored['citation_completeness'], 0.5)
        self.assertEqual(mr.score(item, [])['mrr'], 0)
        self.assertEqual(mr.score(item, results * 3)['mrr'], 0.5)

    def test_code_pointer_weight_changes_ranking(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE records (id TEXT, payload TEXT)')
                for rid, attrs in [('metadata', {}), ('code', {'symbol': 'target_func'})]:
                    db.execute('INSERT INTO records VALUES (?, ?)',
                               (rid, json.dumps({'nodes': [{'attributes': attrs}]})))
                db.commit()
            candidates = [{'id': 'metadata', 'lexical_rank': -10},
                          {'id': 'code', 'lexical_rank': -1}]
            with patch.object(mr.query_pack, 'query_database', return_value=candidates):
                result = mr.code_aware(path, 'target_func')
            self.assertEqual(result[0]['id'], 'code')

    def test_iteration_uses_at_most_two_evidence_followups(self):
        results = [{'id': 'seed', 'paths': [
            {'id': str(i), 'source': 'commit:' + str(i), 'target': 'commit:9'}
            for i in range(5)], 'evidence': [], 'claims': []}]
        with patch.object(mr, 'graph_search', return_value=results) as search:
            actual, calls = mr.retrieve('unused', 'original', 'bounded_iterative_graph')
        self.assertEqual(calls, 3)
        self.assertEqual([c.args[1] for c in search.call_args_list], ['original', '0', '1'])
        self.assertEqual(len(actual), 1)
        with patch.object(mr, 'graph_search', return_value=[]) as search:
            self.assertEqual(mr.retrieve('unused', 'original', 'bounded_iterative_graph'), ([], 1))
            self.assertEqual(search.call_count, 1)

    def test_graph_probes_excluded_from_primary_metrics(self):
        rows = [{'mode': 'lexical', 'expect': 'FOUND', 'recall_at_5': 0,
                 'mrr': 0, 'citation_completeness': 0, 'abstained': True, 'elapsed_ms': 1},
                {'mode': 'graph', 'expect': 'FOUND', 'recall_at_5': 1,
                 'mrr': 1, 'citation_completeness': 1, 'abstained': False, 'elapsed_ms': 1}]
        self.assertEqual(mr.summarize(rows)['mrr'], 0)


if __name__ == '__main__':
    unittest.main()
