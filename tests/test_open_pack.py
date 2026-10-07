import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from open_pack import PackReader, is_safe_path, validate_manifest_path
from build_pack import artifacts, load_records

class TestPackReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = load_records()
        cls.artifacts = artifacts(cls.records)
        cls.base_temp_dir = tempfile.mkdtemp()

        cls.source_dir = Path(cls.base_temp_dir) / 'source'
        cls.source_dir.mkdir()

        # Write valid artifacts to source dir
        for name, body in cls.artifacts.items():
            path = cls.source_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)

        cls.valid_manifest_path = cls.source_dir / 'manifest.json'
        cls.valid_manifest_bytes = cls.valid_manifest_path.read_bytes()
        cls.valid_manifest_sha256 = hashlib.sha256(cls.valid_manifest_bytes).hexdigest()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base_temp_dir)

    def test_offline_valid_roundtrip(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with PackReader(str(self.source_dir), cache_dir) as reader:
                results = reader.query("interval garbage collection")
                self.assertTrue(len(results) > 0)
                self.assertEqual(results[0]['security_confirmation'], 'NOT_ASSESSED')

            # Verify cache temp dirs are cleaned up, but the cache directory itself remains
            self.assertTrue(Path(cache_dir).exists())
            self.assertEqual(list(Path(cache_dir).iterdir()), [])

    def test_offline_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            # Modify a record file in a copy of the source
            bad_source = Path(cache_dir) / 'bad_source'
            shutil.copytree(self.source_dir, bad_source)

            record_files = list(bad_source.glob('records/*.json'))
            self.assertTrue(len(record_files) > 0)

            # Corrupt the data
            record_files[0].write_text("{ \"corrupted\": true }")

            with self.assertRaises(ValueError) as context:
                with PackReader(str(bad_source), cache_dir):
                    pass
            self.assertIn("Size mismatch for", str(context.exception))

    def test_offline_schema_mismatch(self):
         with tempfile.TemporaryDirectory() as cache_dir:
            bad_source = Path(cache_dir) / 'bad_source'
            shutil.copytree(self.source_dir, bad_source)

            manifest_path = bad_source / 'manifest.json'
            manifest = json.loads(manifest_path.read_bytes())
            manifest['schema_version'] = '99.0.0'
            manifest_path.write_text(json.dumps(manifest))

            with self.assertRaises(ValueError) as context:
                with PackReader(str(bad_source), cache_dir):
                    pass
            self.assertIn("Unknown schema version", str(context.exception))

    def test_path_traversal_manifest(self):
        with self.assertRaises(ValueError) as context:
            validate_manifest_path("../records/bad.json")
        self.assertIn("Invalid path in manifest", str(context.exception))

        with self.assertRaises(ValueError) as context:
            validate_manifest_path("/etc/passwd")
        self.assertIn("Invalid path in manifest", str(context.exception))

        with self.assertRaises(ValueError) as context:
            validate_manifest_path("records/bad.json?query=1")
        self.assertIn("Invalid path in manifest (contains URI components)", str(context.exception))

    def test_injected_sql_ignored(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            bad_source = Path(cache_dir) / 'bad_source'
            shutil.copytree(self.source_dir, bad_source)

            # The SQL file in the manifest should be skipped.
            # If we inject malicious SQL into it, it shouldn't affect anything
            # because PackReader uses build_sql(records) to generate its own DB.
            sql_path = bad_source / 'kernel-security-memory.sql'
            sql_path.write_text("DROP TABLE IF EXISTS records; CREATE TABLE malicious (id INT);")

            # We don't change the size or hash in the manifest, but since the reader
            # skips .sql files, it shouldn't even notice or care that the file is changed,
            # nor should it run the malicious SQL.

            with PackReader(str(bad_source), cache_dir) as reader:
                results = reader.query("interval garbage collection")
                self.assertTrue(len(results) > 0)

                # Verify that the malicious table doesn't exist but our tables do
                db = sqlite3.connect(reader.db_path)
                tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                self.assertNotIn("malicious", tables)
                self.assertIn("records", tables)
                db.close()

if __name__ == '__main__':
    unittest.main()
