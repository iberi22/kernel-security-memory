import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from build_pack import artifacts, build_sql, load_records, validate
from query_pack import query_database


class PackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = load_records()

    def test_export_reproducible_and_restore_preserves_evidence(self):
        self.assertEqual(artifacts(self.records), artifacts(self.records))
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'pack.sqlite3'
            db = sqlite3.connect(p)
            db.executescript(build_sql(self.records))
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0], sum(len(r['evidence']) for r in self.records))
            payload = db.execute('SELECT payload FROM records ORDER BY id LIMIT 1').fetchone()[0]
            self.assertEqual(json.loads(payload), self.records[0])
            db.close()
            self.assertTrue(query_database(p, 'interval garbage collection'))
            self.assertEqual(query_database(p, 'unrelated_astronomical_sentinel_987'), [])
            self.assertEqual(query_database(p, '!!!'), [])
            # Query opens read-only and closes; storage bytes stay unchanged.
            before = p.read_bytes()
            result = query_database(p, 'generation-state OR " NEAR(')
            self.assertEqual(p.read_bytes(), before)
            self.assertEqual(result[0]['security_confirmation'], 'NOT_ASSESSED')
            self.assertEqual(result[0]['evolution']['outcome'], 'UNKNOWN')

    def test_reject_dangling_edges_and_evidence(self):
        r = copy.deepcopy(self.records[0])
        r['edges'][0]['target'] = 'missing'
        with self.assertRaises(ValueError):
            validate(r)
        r = copy.deepcopy(self.records[0])
        r['claims'][0]['evidence_ids'] = ['missing']
        with self.assertRaises(ValueError):
            validate(r)

    def test_reject_unsubstantiated_evolution_conclusion(self):
        r = copy.deepcopy(self.records[0])
        r['evolution']['outcome'] = 'TEST_SUPPORTED'
        with self.assertRaises(ValueError):
            validate(r)

    def test_reject_duplicate_evidence_and_bad_hash(self):
        r = copy.deepcopy(self.records[0])
        r['evidence'].append(copy.deepcopy(r['evidence'][0]))
        with self.assertRaises(ValueError):
            validate(r)
        r = copy.deepcopy(self.records[0])
        r['evidence'][0]['sha256'] = 'not-a-hash'
        with self.assertRaises(ValueError):
            validate(r)


if __name__ == '__main__':
    unittest.main()
