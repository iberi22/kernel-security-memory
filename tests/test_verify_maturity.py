import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import verify_maturity as maturity


class TestVerifyMaturity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'impl.py').touch()
        self.feature = {'implemented_in': 'impl.py', 'passes': True,
                        'tests': ['test_impl'], 'last_tested': '2026-07-01',
                        'notes': 'Complete bounded behavior.', 'status': 'stable',
                        'progress_pct': 100}

    def report(self, **features):
        return maturity.verify_maturity({'features': features}, self.root)

    def test_missing_feature_fields(self):
        report = self.report(missing={})
        self.assertEqual(report['features']['missing']['score_pct'], 0)
        self.assertFalse(report['assertable'])

    def test_missing_feature_collection(self):
        with self.assertRaises(ValueError):
            maturity.verify_maturity({}, self.root)
        self.assertFalse(self.report()['assertable'])
        self.assertIsNone(self.report()['aggregate']['real_pct'])

    def test_all_stable(self):
        report = self.report(first=self.feature, second=copy.deepcopy(self.feature))
        self.assertTrue(report['assertable'])
        self.assertEqual(report['aggregate']['real_pct'], 100)

    def test_partial_and_claim_cap(self):
        partial = dict(self.feature, status='partial', passes=False,
                       notes='Phase 1 MVP; optional polish. Missing: integration.',
                       progress_pct=40)
        report = self.report(stable=self.feature, partial=partial)
        self.assertEqual(report['features']['partial']['check_score_pct'], 60)
        self.assertEqual(report['features']['partial']['score_pct'], 40)
        self.assertEqual(report['aggregate']['real_pct'], 70)

    def test_lacks_tests_is_not_assertable(self):
        report = self.report(stable=self.feature, untested=dict(self.feature, tests=[]))
        self.assertFalse(report['assertable'])
        self.assertIsNone(report['aggregate']['real_pct'])
        self.assertEqual(report['aggregate']['diagnostic_average_pct'], 92.5)

    def test_stale_invalid_and_missing_dates(self):
        for value in ('2026-06-30', 'yesterday', None, ''):
            with self.subTest(value=value):
                report = self.report(feature=dict(self.feature, last_tested=value))
                self.assertFalse(report['assertable'])
                self.assertEqual(report['features']['feature']['score_pct'], 85)

    def test_missing_path_loses_only_path_credit(self):
        feature = dict(self.feature, implemented_in=['impl.py', 'missing.py'])
        score = self.report(feature=feature)['features']['feature']
        self.assertEqual(score['score_pct'], 80)
        self.assertEqual(score['missing_paths'], ['missing.py'])

    def test_cli_read_only_and_missing_file(self):
        command = [sys.executable, str(ROOT / 'scripts/verify_maturity.py'),
                   '--root', str(self.root)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)['assertable'])
        metadata = self.root / '.gitcore/features.json'
        metadata.parent.mkdir()
        content = json.dumps({'features': {'one': self.feature}})
        metadata.write_text(content)
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['assertable'])
        self.assertEqual(metadata.read_text(), content)
        self.assertEqual(sorted(p.relative_to(self.root).as_posix()
                                for p in self.root.rglob('*')),
                         ['.gitcore', '.gitcore/features.json', 'impl.py'])


if __name__ == '__main__':
    unittest.main()
