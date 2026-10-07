import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / 'scripts'))

import embed_vectors as ev

VECTORS_MD = (ROOT / 'experiments' / 'VECTORS.md').read_text(encoding='utf-8')
SQL = ROOT / 'docs' / 'memory' / 'kernel-security-memory.sql'
QRELS = ROOT / 'experiments' / 'qrels-v1.json'


class ContractSyncTest(unittest.TestCase):
    def test_markdown_pins_match_module(self):
        for needle in (ev.MODEL_ID, str(ev.DIMS), ev.METRIC,
                       'sqlite-vec==%s' % ev.SQLITE_VEC_VERSION,
                       'NOT_MEASURED', 'MANUAL'):
            self.assertIn(needle, VECTORS_MD, 'VECTORS.md must pin %r' % needle)

    def test_template_version_documented(self):
        self.assertIn(ev.TEMPLATE_VERSION, VECTORS_MD)


class BuildTextTest(unittest.TestCase):
    def test_deterministic_and_covers_title_nodes_claims(self):
        rec = {'title': 'T', 'nodes': [{'label': 'N1'}, {'label': 'N2'}],
               'claims': [{'text': 'C1'}]}
        t1, t2 = ev.build_text(rec), ev.build_text(dict(rec))
        self.assertEqual(t1, t2)
        for s in ('T', 'N1', 'N2', 'C1'):
            self.assertIn(s, t1)


class FixtureEmbedTest(unittest.TestCase):
    def test_dims_normalized_deterministic(self):
        a = ev.fixture_embed('netfilter nft_set_rbtree garbage collection')
        b = ev.fixture_embed('netfilter nft_set_rbtree garbage collection')
        self.assertEqual(len(a), ev.DIMS)
        self.assertEqual(a, b)
        self.assertAlmostEqual(math.sqrt(sum(v * v for v in a)), 1.0, places=6)

    def test_different_texts_differ_and_empty_rejected(self):
        self.assertNotEqual(ev.fixture_embed('netfilter gc'),
                            ev.fixture_embed('amdgpu display driver'))
        with self.assertRaises(ValueError):
            ev.fixture_embed('   ')

    def test_zero_vector_rejected(self):
        with self.assertRaises(ValueError):
            ev.l2_normalize([0.0] * 8)

    def test_cosine_dim_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            ev.cosine([1.0], [1.0, 0.0])


class SqliteVecGateTest(unittest.TestCase):
    def test_missing_sqlite_vec_fails_loudly(self):
        with patch.dict(sys.modules, {'sqlite_vec': None}):
            with self.assertRaises(RuntimeError) as ctx:
                ev.require_sqlite_vec()
        self.assertIn(ev.SQLITE_VEC_VERSION, str(ctx.exception))
        self.assertIn('pip install', str(ctx.exception))


class FormatRoundtripTest(unittest.TestCase):
    def test_write_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'vec.json'
            ev.write_vectors([('r1', ev.fixture_embed('hello kernel')),
                              ('r2', ev.fixture_embed('unrelated driver'))],
                             out, 'fixture')
            contract, vecs = ev.load_vectors(out)
            self.assertEqual(contract['dims'], ev.DIMS)
            self.assertEqual(contract['provider'], 'fixture')
            self.assertEqual(set(vecs), {'r1', 'r2'})

    def test_bad_dims_and_bad_norm_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'vec.json'
            with self.assertRaises(ValueError):
                ev.write_vectors([('r1', [1.0, 2.0])], out, 'fixture')
            ev.write_vectors([('r1', ev.fixture_embed('x'))], out, 'fixture')
            doc = json.loads(out.read_text(encoding='utf-8'))
            doc['items'][0]['vector'] = [1.0] * ev.DIMS  # norm != 1
            out.write_text(json.dumps(doc), encoding='utf-8')
            with self.assertRaises(ValueError):
                ev.load_vectors(out)

    def test_unknown_provider_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                ev.write_vectors([], Path(td) / 'v.json', 'openai')


class OfflineComparisonTest(unittest.TestCase):
    def test_runs_without_network_model_or_sqlitevec(self):
        report = ev.score_fixture_against_qrels(QRELS, SQL, limit=5)
        self.assertEqual(report['summary']['provider'], 'fixture')
        self.assertIn('NOT a neural vector measurement',
                      report['summary']['warning'])
        self.assertEqual(len(report['items']), 9)
        for it in report['items']:
            self.assertIn(it['verdict'], ev.VERDICTS)
        s = report['summary']
        self.assertEqual(s['positive_recall']['denominator'], 6)
        self.assertEqual(s['negative_abstention']['denominator'], 3)

    def test_ranking_prefers_lexical_overlap(self):
        vecs = {'r1': ev.fixture_embed('netfilter garbage collection'),
                'r2': ev.fixture_embed('amdgpu display panel')}
        top = ev.rank_by_cosine(ev.fixture_embed('netfilter garbage collection'), vecs)
        self.assertEqual(top[0], 'r1')


if __name__ == '__main__':
    unittest.main()
