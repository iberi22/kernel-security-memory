"""Optional vector pack wiring, using offline fixtures only."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import build_pack
from embed_vectors import MODEL_ID, DIMS, build_text, fixture_embed, write_vectors
from open_pack import PackReader


class VectorWiringTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.cache = self.root / 'cache'
        self.records = build_pack.load_records()
        self.vector_path = self.root / 'input.json'
        self.query_vec = fixture_embed(build_text(self.records[0]))
        write_vectors([(r['id'], fixture_embed(build_text(r))) for r in self.records],
                      self.vector_path, 'fixture')

    def write_pack(self, vectors=True):
        outputs = build_pack.artifacts(self.records, self.vector_path if vectors else None)
        for name, body in outputs.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        return json.loads(outputs['manifest.json'])

    def test_build_cli_with_vectors(self):
        # Redirect only output root; load the real validated corpus.
        with patch.object(build_pack, 'ROOT', self.root), \
                patch.object(build_pack, 'load_records', return_value=self.records), \
                patch.object(sys, 'argv', ['build_pack.py', '--vectors', str(self.vector_path)]):
            build_pack.main()
        memory = self.root / 'docs/memory'
        manifest = json.loads((memory / 'manifest.json').read_text())
        info = manifest['vectors']
        body = self.vector_path.read_bytes()
        self.assertEqual(info, {
            'status': 'BUILT', 'model': MODEL_ID, 'revision': None, 'dims': DIMS,
            'provider': 'fixture', 'sha256': hashlib.sha256(body).hexdigest(),
            'bytes': len(body), 'path': 'vectors.json'})
        self.assertEqual((memory / 'vectors.json').read_bytes(), body)
        self.assertIn({k: info[k] for k in ('path', 'bytes', 'sha256')}, manifest['files'])
        with patch.object(build_pack, 'ROOT', self.root), \
                patch.object(build_pack, 'load_records', return_value=self.records), \
                patch.object(sys, 'argv', ['build_pack.py', '--check', '--vectors', str(self.vector_path)]):
            build_pack.main()

    def test_lexical_only(self):
        self.assertEqual(self.write_pack(vectors=False)['vectors'], 'NOT_BUILT')
        with PackReader(str(self.source), self.cache) as reader:
            self.assertIsNone(reader.vectors)
            self.assertEqual(reader.rank_by_cosine(self.query_vec), [])
            self.assertTrue(reader.query('interval garbage collection'))

    def test_built_vectors_are_optional(self):
        self.write_pack()
        (self.source / 'vectors.json').unlink()
        with PackReader(str(self.source), self.cache) as reader:
            self.assertIsNone(reader.vectors)
            self.assertTrue(reader.query('interval garbage collection'))

    def test_rank_and_lexical_query_with_vectors(self):
        self.write_pack()
        with PackReader(str(self.source), self.cache, vectors_path=self.vector_path) as reader:
            self.assertEqual(reader.rank_by_cosine(self.query_vec, limit=1),
                             [self.records[0]['id']])
            self.assertEqual(len(reader.rank_by_cosine(self.query_vec, limit=3)), 3)
            self.assertTrue(reader.query('interval garbage collection'))
        self.assertIsNone(reader.vectors)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_invalid_vectors_sha_rejected(self):
        self.write_pack()
        body = self.vector_path.read_bytes().replace(b'fixture', b'fixturE')
        self.vector_path.write_bytes(body)
        with self.assertRaisesRegex(ValueError, 'Hash mismatch for vectors'):
            with PackReader(str(self.source), self.cache, vectors_path=self.vector_path):
                pass
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_invalid_vectors_size_rejected(self):
        self.write_pack()
        with self.vector_path.open('ab') as stream:
            stream.write(b' ')
        with self.assertRaisesRegex(ValueError, 'Size mismatch for vectors'):
            with PackReader(str(self.source), self.cache, vectors_path=self.vector_path):
                pass

    def test_vectors_require_manifest_declaration(self):
        self.write_pack(vectors=False)
        with self.assertRaisesRegex(ValueError, 'does not declare BUILT vectors'):
            with PackReader(str(self.source), self.cache, vectors_path=self.vector_path):
                pass

    def test_contract_mismatch_rejected(self):
        manifest = self.write_pack()
        manifest['vectors']['model'] = 'another-model'
        (self.source / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'Vectors contract mismatch: model'):
            with PackReader(str(self.source), self.cache, vectors_path=self.vector_path):
                pass

    def test_invalid_format_rejected_after_hash_validation(self):
        manifest = self.write_pack()
        doc = json.loads(self.vector_path.read_text())
        doc['items'][0]['vector'] = [0.0] * DIMS
        body = json.dumps(doc).encode()
        self.vector_path.write_bytes(body)
        manifest['vectors'].update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        (self.source / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'not L2-normalized'):
            with PackReader(str(self.source), self.cache, vectors_path=self.vector_path):
                pass

    def test_unknown_record_ids_rejected_by_builder(self):
        write_vectors([('unknown-record', self.query_vec)], self.vector_path, 'fixture')
        with self.assertRaisesRegex(ValueError, 'unknown record ids'):
            build_pack.artifacts(self.records, self.vector_path)


if __name__ == '__main__':
    unittest.main()
