#!/usr/bin/env python3
"""Read-only maturity metadata audit; never executes recorded test commands."""

import argparse
from datetime import date
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CUTOFF = date(2026, 7, 1)
WEIGHTS = {
    'paths_exist': 20,
    'passes': 15,
    'tests_listed': 15,
    'recently_tested': 15,
    'no_caveats': 15,
    'implemented_in_declared': 10,
    'stable': 10,
}
CAVEATS = re.compile(r'\b(?:mvp|phase|optional|polish)\b|missing\s*:', re.I)


def entries(value):
    """Accept explicit path lists or the canonical comma-separated string."""
    if isinstance(value, str):
        value = value.split(',')
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def score_feature(feature, root):
    paths = entries(feature.get('implemented_in'))
    root = Path(root).resolve()
    missing = []
    for item in paths:
        path = (root / item).resolve()
        if not path.is_relative_to(root) or not path.exists():
            missing.append(item)
    try:
        recent = date.fromisoformat(feature.get('last_tested', '')) >= CUTOFF
    except (ValueError, TypeError):
        recent = False
    notes = feature.get('notes')
    tests = feature.get('tests')
    checks = {
        'paths_exist': bool(paths) and not missing,
        'passes': feature.get('passes') is True,
        'tests_listed': isinstance(tests, list) and any(
            isinstance(test, str) and test.strip() for test in tests),
        'recently_tested': recent,
        'no_caveats': isinstance(notes, str) and bool(notes.strip())
                      and CAVEATS.search(notes) is None,
        'implemented_in_declared': bool(paths),
        'stable': feature.get('status') == 'stable',
    }
    claimed = feature.get('progress_pct', 0)
    if isinstance(claimed, bool) or not isinstance(claimed, (int, float)):
        claimed = 0
    if not 0 <= claimed <= 100:
        claimed = 0
    raw = sum(WEIGHTS[key] for key, passed in checks.items() if passed)
    return {'checks': checks, 'missing_paths': missing, 'claimed_pct': claimed,
            'check_score_pct': raw, 'score_pct': min(raw, claimed)}


def verify_maturity(document, root):
    features = document.get('features')
    if not isinstance(features, dict):
        raise ValueError('features must be an object keyed by feature ID')
    if any(not isinstance(feature, dict) for feature in features.values()):
        raise ValueError('each feature must be an object')
    scores = {key: score_feature(feature, root) for key, feature in features.items()}
    assertable = bool(scores) and all(
        item['checks']['tests_listed'] and item['checks']['recently_tested']
        for item in scores.values())
    average = (round(sum(item['score_pct'] for item in scores.values()) / len(scores), 2)
               if scores else None)
    return {'cutoff': CUTOFF.isoformat(), 'weights_pct': WEIGHTS,
            'features': scores, 'aggregate': {
                'feature_count': len(scores), 'diagnostic_average_pct': average,
                'real_pct': average if assertable else None,
                'status': 'assertable' if assertable else 'not assertable'},
            'assertable': assertable}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT,
                        help='repository root (default: script repository)')
    args = parser.parse_args()
    try:
        document = json.loads((args.root / '.gitcore/features.json').read_text())
        report = verify_maturity(document, args.root)
    except (OSError, ValueError) as exc:
        print(json.dumps({'error': str(exc), 'assertable': False}))
        return 1
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
