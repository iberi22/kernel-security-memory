"""Tests for the multi-project pack manifest and export stability."""
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from build_pack import artifacts, load_records, pack_projects, source_scope

SEED_ID = 'linux-CVE-2024-26581-mainline'
SCOPE = ('fetched seed (1 record) plus the vetted fable-2026-06 slice (34 records converted '
         'offline from cited study records); not the full history of any upstream project')


class BuildPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = load_records()
        cls.seed = [r for r in cls.records if r['id'] == SEED_ID][0]
        cls.artifacts = artifacts(cls.records)

    def test_manifest_lists_every_project_and_record(self):
        manifest = json.loads(self.artifacts['manifest.json'].decode())
        self.assertEqual(manifest['projects'], sorted({r['project'] for r in self.records}))
        self.assertEqual(manifest['project'], pack_projects(self.records))
        self.assertEqual(manifest['record_count'], len(self.records))
        paths = [entry['path'] for entry in manifest['files']]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertIn('kernel-security-memory.sql', paths)
        for record in self.records:
            self.assertIn(f'records/{record["id"]}.json', paths)
        for entry in manifest['files']:
            body = self.artifacts[entry['path']]
            self.assertEqual(entry['bytes'], len(body))
            self.assertEqual(entry['sha256'], hashlib.sha256(body).hexdigest())

    def test_single_project_manifest_keeps_one_project_name(self):
        seed = [r for r in self.records if r['project'] == 'linux']
        self.assertEqual(pack_projects(seed), 'linux')
        manifest = json.loads(artifacts(seed)['manifest.json'].decode())
        self.assertEqual(manifest['project'], 'linux')
        self.assertEqual(manifest['projects'], ['linux'])

    def test_multi_project_manifest_joins_sorted_names(self):
        records = [copy.deepcopy(self.seed), copy.deepcopy(self.seed)]
        records[1]['project'] = 'git'
        records[1]['id'] = 'git-CVE-2016-2315'
        self.assertEqual(pack_projects(records), 'git,linux')
        manifest = json.loads(artifacts(records)['manifest.json'].decode())
        self.assertEqual(manifest['project'], 'git,linux')
        self.assertEqual(manifest['projects'], ['git', 'linux'])

    def test_existing_seed_record_is_byte_identical(self):
        seed = (ROOT / 'docs/memory/records' / f'{SEED_ID}.json').read_bytes()
        self.assertEqual(self.artifacts[f'records/{SEED_ID}.json'], seed)
        self.assertEqual(json.loads(seed), self.seed)

    def test_source_scope_describes_the_real_coverage(self):
        """Finding 7: the manifest describes the seed plus the vetted slice, not "full history"."""
        manifest = json.loads(self.artifacts['manifest.json'].decode())
        self.assertEqual(manifest['source_scope'], SCOPE)
        self.assertEqual(manifest['source_scope'], source_scope(self.records))
        self.assertNotEqual(manifest['source_scope'], 'source-linked seed; not full history')
        # The scope is computed from the records, so it cannot drift from the pack.
        trimmed = self.records[:-1]
        self.assertIn(f'fable-2026-06 slice ({len(trimmed) - 1} records', source_scope(trimmed))
        self.assertIn('not the full history', source_scope(trimmed))

    def test_export_is_deterministic(self):
        self.assertEqual(self.artifacts, artifacts(load_records()))


if __name__ == '__main__':
    unittest.main()
