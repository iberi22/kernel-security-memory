"""Corpus checks and rank-sensitive evaluation regression tests."""
import json
import subprocess
import sys
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import measure_baseline as mb

QRELS = ROOT / 'experiments/qrels-v2.json'
SQL = ROOT / 'docs/memory/kernel-security-memory.sql'


class TestQrelsV2(unittest.TestCase):
    def test_v2_loads_and_preserves_v1_judgments(self):
        items = mb.load_qrels(QRELS)
        self.assertGreaterEqual(len(items), 30)
        indexed = {i['id']: i for i in items}
        self.assertEqual(len(indexed), len(items))
        for old in mb.load_qrels(ROOT / 'experiments/qrels-v1.json'):
            new = indexed[old['id']]
            for key in ('query', 'mode', 'expect'):
                self.assertEqual(new[key], old[key])
            self.assertEqual(new['evidence'], old['expected_evidence_ids'])
            if old['expect'] == 'FOUND':
                self.assertEqual([new['record_id']], old['expected_record_ids'])
        for item in items:
            self.assertIn(item['mode'], mb.MODES)
            self.assertTrue(item['reviewer'])
            date.fromisoformat(item['reviewed_at'])
            self.assertIsInstance(item['evidence'], list)
            if item['expect'] == 'FOUND':
                record = json.loads((ROOT / 'docs/memory/records' /
                                     (item['record_id'] + '.json')).read_text())
                self.assertTrue(set(item['evidence']) <= {e['id'] for e in record['evidence']})
        added = [i for i in items if i['id'] not in
                 {old['id'] for old in mb.load_qrels(ROOT / 'experiments/qrels-v1.json')}]
        self.assertGreaterEqual(sum(i['expect'] == 'ABSTAIN' for i in added), 5)
        self.assertGreaterEqual(sum(i['mode'] == 'graph' for i in added), 5)
        self.assertGreaterEqual(sum(i['id'].startswith('p') for i in added), 5)
        self.assertGreaterEqual(len({i['record_id'] for i in added
                                    if i['id'].startswith('r')}), 6)

    def test_real_metrics_are_bounded(self):
        summary = mb.measure(QRELS, SQL)['summary']
        self.assertEqual(summary['n_not_measured'], 0)
        for name in ('mrr', 'recall_at_5', 'citation_completeness'):
            self.assertEqual(summary[name]['denominator'], 22)
            self.assertGreaterEqual(summary[name]['value'], 0)
            self.assertLessEqual(summary[name]['value'], 1)

    def test_cli_custom_qrels_runs(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/measure_baseline.py'),
                                 '--qrels', str(QRELS)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('baseline qrels-v2.json: 30 items', result.stdout)
        self.assertIn('mrr:', result.stdout)
        self.assertIn('recall_at_5:', result.stdout)
        self.assertIn('citation_completeness:', result.stdout)


class TestRankMetrics(unittest.TestCase):
    def score(self, results):
        item = {'id': 'test', 'mode': 'lexical', 'expect': 'FOUND', 'query': 'test',
                'record_id': 'target', 'evidence': ['e1', 'e2']}
        with patch.object(mb.query_pack, 'query_database', return_value=results):
            return mb.score_item(Path('/unused'), item, limit=10)

    def test_rank_and_citations_are_independent(self):
        scored = self.score([{'id': 'other', 'evidence': [{'id': 'e2'}]},
                             {'id': 'target', 'evidence': [{'id': 'e1'}]}])
        self.assertEqual(scored['observed_record_ids'], ['other', 'target'])
        self.assertEqual(scored['reciprocal_rank'], 0.5)
        self.assertEqual(scored['recall_at_5'], 1)
        self.assertEqual(scored['citation_completeness'], 0)
        self.assertEqual(scored['verdict'], 'MISS')

    def test_rank_six_is_outside_top_five(self):
        scored = self.score([{'id': str(i)} for i in range(5)] +
                             [{'id': 'target', 'evidence': [{'id': 'e1'}, {'id': 'e2'}]}])
        self.assertAlmostEqual(scored['reciprocal_rank'], 1 / 6)
        self.assertEqual(scored['recall_at_5'], 0)
        self.assertEqual(scored['citation_completeness'], 1)

    def test_empty_results_score_zero_without_crashing(self):
        for results in ([], None):
            scored = self.score(results)
            self.assertEqual(scored['verdict'], 'MISS')
            for metric in ('reciprocal_rank', 'recall_at_5', 'citation_completeness'):
                self.assertEqual(scored[metric], 0)

    def test_unmeasured_items_have_no_metrics(self):
        bad = mb.score_item(Path('/unused'), {'id': 'bad', 'expect': 'FOUND'})
        self.assertEqual(bad['verdict'], 'NOT_MEASURED')
        for name in ('mrr', 'recall_at_5', 'citation_completeness'):
            self.assertIsNone(mb.summarize([bad])[name]['value'])
            self.assertEqual(mb.summarize([bad])[name]['denominator'], 0)
        measured = self.score([])
        for name in ('mrr', 'recall_at_5', 'citation_completeness'):
            self.assertEqual(mb.summarize([bad, measured])[name]['denominator'], 1)


if __name__ == '__main__':
    unittest.main()
