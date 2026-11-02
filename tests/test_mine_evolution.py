"""Real local Git fixtures: no network, upstream code or third-party packages."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import mine_evolution as miner
from build_pack import validate


class EvolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.day = 0
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        self.commit('Initial', 'first')
        self.fix = self.commit('Fix', 'fixed')

    def git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env['GIT_CONFIG_GLOBAL'] = os.devnull
        if self.day:
            stamp = f'2025-01-{self.day:02d}T12:00:00+00:00'
            env.update(GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
        return subprocess.check_output(['git', '-C', str(self.repo), *args], env=env,
                                       stderr=subprocess.PIPE).decode().strip()

    def commit(self, message, content, path='file.c'):
        self.day += 1
        (self.repo / path).write_text(content)
        self.git('add', '--', path)
        self.git('-c', 'core.hooksPath=/dev/null', 'commit', '-q', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def mine(self, **kwargs):
        return miner.mine_evolution(self.repo, [self.fix],
                                    repository_url='https://example.invalid/kernel',
                                    observed_at='2025-02-01T00:00:00Z', **kwargs)[0]

    def test_revert_detected(self):
        sha = self.commit(f'Revert fix\n\nThis reverts commit {self.fix}.', 'reverted')
        r = self.mine()
        self.assertEqual(r['evolution']['outcome'], 'REVERTED')
        self.assertEqual(r['edges'][0]['relation'], 'reverts')
        self.assertEqual(r['evidence'][1]['commit_sha'], sha)
        self.assertEqual(r['evidence'][1]['files'], ['file.c'])

    def test_backport_detected(self):
        self.commit(f'Backport fix\n\n(cherry picked from commit {self.fix})', 'backported')
        self.assertEqual(self.mine()['evolution']['outcome'], 'BACKPORTED')

    def test_backport_trailer(self):
        self.commit(f'Apply\n\nBackport of commit {self.fix}', 'backported')
        self.assertEqual(self.mine()['edges'][0]['relation'], 'backport_of')

    def test_followup_detected(self):
        self.commit('Refactor', 'refined')
        r = self.mine()
        self.assertEqual(r['evolution']['followups'][0]['kind'], 'path_followup')
        self.assertEqual(r['claims'][0]['status'], 'hypothesis')
        self.assertEqual(r['evolution']['outcome'], 'UNKNOWN')
        self.assertEqual(r['evolution']['horizon_end'], '2025-01-03')

    def test_unknown_outcome(self):
        r = self.mine()
        self.assertEqual(r['evolution']['outcome'], 'UNKNOWN')
        self.assertEqual(r['evolution']['followups'], [])
        self.assertEqual(r['evolution']['horizon_end'], '2025-01-02')
        self.assertEqual(r['validation']['security_effectiveness'], 'UNKNOWN')

    def test_unlinked_revert_or_backport_is_only_candidate(self):
        self.commit('Revert unrelated change', 'changed')
        self.commit('Backport other fix', 'changed again')
        r = self.mine()
        self.assertEqual(r['evolution']['outcome'], 'UNKNOWN')
        self.assertEqual({f['message_signal'] for f in r['evolution']['followups']},
                         {'revert', 'backport'})

    def test_other_file_not_a_followup(self):
        self.commit(f'Revert\n\nThis reverts commit {self.fix}.', 'other', 'other.c')
        self.assertEqual(self.mine()['evolution']['followups'], [])

    def test_window_excludes_later_revert(self):
        self.commit(f'Revert\n\nThis reverts commit {self.fix}.', 'reverted')
        r = self.mine(until='2025-01-02')
        self.assertEqual(r['evolution']['followups'], [])
        self.assertEqual(r['evolution']['outcome'], 'UNKNOWN')

    def test_schema_validity_and_dangling_evidence_rejected(self):
        self.commit(f'Revert\n\nThis reverts commit {self.fix}.', 'reverted')
        r = self.mine()
        validate(r)
        schema = json.loads((Path(__file__).resolve().parents[1] /
                             'docs/schemas/memory-record.schema.json').read_text())
        props = schema['properties']['evolution']['properties']
        self.assertIn(r['evolution']['outcome'], props['outcome']['enum'])
        self.assertIn(r['evolution']['followups'][0]['kind'],
                      props['followups']['items']['properties']['kind']['enum'])
        bad = copy.deepcopy(r)
        bad['evolution']['followups'][0]['evidence_ids'] = ['missing']
        with self.assertRaises(ValueError):
            validate(bad)
        bad = copy.deepcopy(r)
        bad['edges'] = []
        with self.assertRaises(ValueError):
            validate(bad)

    def test_no_network_or_shell(self):
        self.commit('Followup', 'new')
        run = subprocess.run
        calls = []
        def offline(args, **kwargs):
            calls.append(args)
            self.assertIsInstance(args, list)
            self.assertEqual(args[0], 'git')
            self.assertFalse(kwargs.get('shell'))
            self.assertIn('protocol.allow=never', args)
            self.assertEqual(kwargs['env']['GIT_NO_LAZY_FETCH'], '1')
            self.assertFalse({'fetch', 'clone', 'pull', 'push'}.intersection(args))
            return run(args, **kwargs)
        with patch.object(miner.subprocess, 'run', side_effect=offline):
            self.mine()
        self.assertTrue(calls)

    def test_shallow_repository_remains_partial(self):
        (self.repo / '.git/shallow').write_text(self.fix + '\n')
        r = self.mine()
        self.assertTrue(r['validation']['shallow'])
        self.assertEqual(r['evolution']['coverage'], 'PARTIAL')

    def test_deterministic_and_multiple_fixes(self):
        self.assertEqual(self.mine(), self.mine())
        rows = miner.mine_evolution(self.repo, [self.fix, self.fix],
                                   repository_url='https://example.invalid/kernel')
        self.assertEqual(len(rows), 2)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            self.mine(until='2024-01-01')
        with self.assertRaises(ValueError):
            miner.mine_evolution(self.repo, ['--help'], repository_url='https://example.invalid')

    def test_branch_backport_with_explicit_scope(self):
        self.git('checkout', '-q', '-b', 'stable', self.fix + '^')
        self.commit(f'Backport {self.fix}\n\n(cherry picked from commit {self.fix})', 'stable')
        self.assertEqual(self.mine(refs=['HEAD'])['evolution']['outcome'], 'BACKPORTED')


if __name__ == '__main__':
    unittest.main()
