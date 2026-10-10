"""Offline tests for the fable -> memory-record converter.

Every test runs without network and without mutating the pack: conversion output
is either compared against the files already in docs/memory/records or built in a
temporary directory from mutated copies of real source records, and the only
committed network artifact is read from
docs/studies/fable-2026-06/commit-meta.jsonl.
"""
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import convert_fable_records as cfr
from build_pack import build_sql, load_records, validate

VETTED = [row for _, row in cfr.load_vetted()]
RECORDS_DIR = cfr.RECORDS_DIR
COMMIT_META = cfr.COMMIT_META
ID_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
# Pinned against the live OSV advisory for git-cve-2016-2315 and the live GitHub
# API commit object for 34fa79a6cde56d6d428ab0d3160cb094ebad3305.
GIT_SHA = '34fa79a6cde56d6d428ab0d3160cb094ebad3305'
GIT_KEY = ('git/git', GIT_SHA)
GIT_DIGEST = 'f2e487cfbaf99fbb1c50c04e496e0e194d0e6c8b16174e6432c58d32eeda7ac5'
GIT_COMMITTER_DATE = '2015-10-05T18:08:05Z'
GIT_ADVISORY_TIME = '2026-08-07T14:49:20.663429Z'


def node_of(record, kind):
    return [n for n in record['nodes'] if n['type'] == kind][0]


def evidence_of(record, evidence_id):
    return [e for e in record['evidence'] if e['id'] == evidence_id][0]


def claim_of(record, claim_id):
    return [c for c in record['claims'] if c['id'] == claim_id][0]


def edge_of(record, edge_id):
    return [e for e in record['edges'] if e['id'] == edge_id][0]


def fix_url_repo(source):
    """The "<owner>/<repo>" slug parsed out of a study record fix URL."""
    match = cfr.FIX_URL_RE.match(source['fix']['url'])
    return f'{match.group(1)}/{match.group(2)}'


def study_record(project, name):
    return json.loads((ROOT / f'docs/studies/fable-2026-06/{project}/records/{name}.json').read_text())


def temp_row(td, source, name):
    """Write a study record into a temp root and return its vetted row."""
    path = Path(td) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(source))
    return {'advisory_id': source['advisory_id'], 'fix_sha': source['fix']['sha'],
            'project': source['project'], 'record_file': str(path.relative_to(Path(td)))}


def indexed_text(record):
    """The text build_pack puts into record_fts: title, node labels, claim texts."""
    return ' '.join([record['title']] + [n['label'] for n in record['nodes']]
                   + [c['text'] for c in record['claims']]).lower()


class ConverterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.converted, cls.skipped = cfr.expected_records()
        cls.records = [json.loads(body) for body in cls.converted.values()]
        cls.commit_meta = cfr.load_commit_meta()
        cls.meta_lines = {json.loads(line)['sha']: line for line in
                          COMMIT_META.read_text().splitlines() if line.strip()}

    def test_every_vetted_row_converts_or_reports_a_reason(self):
        self.assertEqual(len(VETTED), 34)
        self.assertEqual(len(self.converted), 34)
        self.assertEqual(self.skipped, [])
        for record in self.records:
            self.assertTrue(ID_RE.match(record['id']), record['id'])
            self.assertEqual((RECORDS_DIR / f"{record['id']}.json").name,
                             f"{record['id']}.json")

    def test_records_on_disk_match_the_converter(self):
        """--check passes on the committed tree: no stale or hand-edited record."""
        for record_id, body in self.converted.items():
            path = RECORDS_DIR / f'{record_id}.json'
            self.assertTrue(path.is_file(), path)
            self.assertEqual(path.read_bytes(), body, path)
        for record in self.records:
            validate(record)

    def test_conversion_is_deterministic(self):
        again, again_skipped = cfr.expected_records()
        self.assertEqual(self.converted, again)
        self.assertEqual(self.skipped, again_skipped)

    def test_source_prose_is_not_copied(self):
        """docs/DATA-POLICY.md: no copied advisory/commit descriptions in the pack."""
        for row in VETTED:
            source = json.loads((ROOT / row['record_file']).read_text())
            for field in ('insecure_pattern', 'mitigation'):
                text = source.get(field)
                if not isinstance(text, str) or len(text) < 12:
                    continue
                body = self.converted[f"{row['project']}-{row['advisory_id']}"]
                self.assertNotIn(text, body.decode(), (row['record_file'], field))

    def test_status_and_evolution_stay_hypothesis_or_unknown(self):
        observed_claims = {'claim-fix-link', 'claim-digest-scope'}
        for record in self.records:
            self.assertEqual(record['status'], 'unknown')
            self.assertEqual(record['evolution']['outcome'], 'UNKNOWN')
            self.assertEqual(record['evolution']['followups'], [])
            self.assertIsNone(record['evolution']['horizon_end'])
            self.assertEqual([c['id'] for c in record['claims']],
                             ['claim-fix-link', 'claim-digest-scope', 'claim-pattern-family',
                              'claim-cwe'], record['id'])
            for claim in record['claims']:
                if claim['id'] == 'claim-cwe':
                    # observed only when the fetched advisory states the CWE
                    expected = ('hypothesis'
                                if node_of(record, 'advisory')['attributes']['cwe_state']
                                == 'ASSIGNED_BY_STUDY' else 'observed')
                    self.assertEqual(claim['status'], expected, (record['id'], claim['id']))
                elif claim['id'] not in observed_claims:
                    self.assertEqual(claim['status'], 'hypothesis', (record['id'], claim['id']))
            for edge in record['edges']:
                if edge['id'] != 'edge-fixed-by':
                    self.assertEqual(edge['status'], 'hypothesis', (record['id'], edge['id']))
            self.assertFalse(record['validation']['pair_content_verified'])
            self.assertEqual(record['validation']['security_effectiveness'], 'UNKNOWN')

    def test_pattern_family_value_is_not_asserted_in_claim_text(self):
        """The family is data in node attributes, not an assertion in hypothesis prose."""
        for record in self.records:
            family = node_of(record, 'pattern')['attributes']['family']
            if family == 'unknown':
                continue
            for claim in record['claims']:
                if claim['status'] != 'hypothesis':
                    continue
                self.assertNotIn(family, claim['text'].lower().replace('-', ' '),
                                 (record['id'], claim['id']))

    def test_url_digest_projects_are_recomputed(self):
        checked = set()
        for record in self.records:
            evidence = evidence_of(record, 'e-commit')
            reproducible = record['validation']['digest_reproducible_from_url']
            self.assertEqual(reproducible, record['project'] in ('nginx', 'systemd'))
            checked.add(record['project'])
            if reproducible:
                self.assertEqual(hashlib.sha256(evidence['url'].encode('utf-8')).hexdigest(),
                                 evidence['sha256'], record['id'])
            else:
                # The advisory JSON is not stored in this pack, so the converter must not
                # claim it recomputes that digest; it must name what the digest covers.
                self.assertIn('does not recompute it', evidence['canonicalization'])
                self.assertIn('sort_keys=True', evidence['canonicalization'])
                self.assertTrue(evidence['url'].startswith(cfr.OSV_VULN_URL), record['id'])
        self.assertEqual(checked, {'git', 'nginx', 'openssh', 'sqlite', 'systemd'})

    def test_commit_digest_url_points_at_the_hashed_artifact(self):
        """Finding 2: url/fetch_url is the artifact the recorded digest covers."""
        for record in self.records:
            evidence = evidence_of(record, 'e-commit')
            source = json.loads((ROOT / record['validation']['source_record']).read_text())
            stored_url = source['evidence'][0]['url']
            self.assertEqual(evidence['url'], evidence['fetch_url'])
            self.assertEqual(evidence['sha256'], source['evidence'][0]['sha256'])
            if record['project'] in ('nginx', 'systemd'):
                self.assertEqual(evidence['url'], stored_url, record['id'])
                continue
            self.assertTrue(evidence['url'].startswith(cfr.OSV_VULN_URL), record['id'])
            self.assertEqual(evidence['url'], f"{cfr.OSV_VULN_URL}{record['id'].split('-', 1)[1]}")
            self.assertNotEqual(evidence['url'], stored_url, record['id'])
            # It is an artifact digest, never the hash of the URL it now points at.
            self.assertNotEqual(evidence['sha256'],
                                hashlib.sha256(evidence['url'].encode('utf-8')).hexdigest())
        pinned = json.loads(self.converted['git-CVE-2016-2315'])
        self.assertEqual(evidence_of(pinned, 'e-commit')['sha256'], GIT_DIGEST)
        self.assertEqual(evidence_of(pinned, 'e-commit')['url'],
                         'https://api.osv.dev/v1/vulns/CVE-2016-2315')
        digest_claim = claim_of(pinned, 'claim-digest-scope')
        self.assertEqual(digest_claim['status'], 'observed')
        self.assertIn('https://api.osv.dev/v1/vulns/CVE-2016-2315', digest_claim['text'])
        self.assertNotIn('stored by the upstream study', digest_claim['text'])
        self.assertIn('not stored in this pack', digest_claim['text'])

    def test_commit_meta_evidence_digest_pins_the_cached_line(self):
        """Finding 2: e-commit-meta digests the cached JSON line it is read from."""
        covered = set()
        for record in self.records:
            if 'e-commit-meta' not in [e['id'] for e in record['evidence']]:
                continue
            covered.add(record['id'])
            evidence = evidence_of(record, 'e-commit-meta')
            self.assertEqual(evidence['url'], evidence['fetch_url'])
            self.assertTrue(evidence['url'].startswith('https://api.github.com/repos/'))
            sha = node_of(record, 'commit')['attributes']['sha']
            self.assertIn(sha, self.meta_lines, record['id'])
            self.assertEqual(evidence['sha256'],
                             hashlib.sha256(self.meta_lines[sha].encode('utf-8')).hexdigest())
            meta = json.loads(self.meta_lines[sha])
            self.assertEqual(evidence['observed_at'], meta['fetched_at'])
            self.assertEqual(evidence['url'], meta['api_url'])
        self.assertEqual(covered, set(self.converted))

    def test_committed_at_is_the_real_committer_date(self):
        """Finding 1: committed_at comes from the API, never from the advisory stamp."""
        for row in VETTED:
            record_id = f"{row['project']}-{row['advisory_id']}"
            record = json.loads(self.converted[record_id])
            source = json.loads((ROOT / row['record_file']).read_text())
            attributes = node_of(record, 'commit')['attributes']
            meta = self.commit_meta[(fix_url_repo(source), source['fix']['sha'])]
            self.assertIsNotNone(meta, record_id)
            self.assertEqual(attributes['committed_at'], meta['committer_date'], record_id)
            # Guard the exact round-1 bug: the advisory stamp must never be copied.
            self.assertNotEqual(attributes['committed_at'], source['fix']['committed_at'], record_id)
            self.assertNotEqual(attributes['committed_at'], attributes['source_advisory_time'])
            self.assertEqual(node_of(record, 'commit')['attributes']['committed_at'],
                             cfr.load_commit_meta()[(fix_url_repo(source),
                                                    source['fix']['sha'])]['committer_date'])
        pinned = json.loads(self.converted['git-CVE-2016-2315'])
        attributes = node_of(pinned, 'commit')['attributes']
        self.assertEqual(attributes['committed_at'], GIT_COMMITTER_DATE)
        self.assertEqual(attributes['source_advisory_time'], GIT_ADVISORY_TIME)
        self.assertEqual(attributes['source_advisory_time_kind'], 'osv_modified')

    def test_advisory_time_kind_is_declared_for_every_project(self):
        """Finding 1: the preserved advisory stamp says which fetcher field produced it."""
        self.assertEqual(set(cfr.ADVISORY_TIME_KIND),
                         {'git', 'nginx', 'openssh', 'sqlite', 'systemd'})
        kinds = {}
        for record in self.records:
            attributes = node_of(record, 'commit')['attributes']
            if attributes['source_advisory_time'] is None:
                self.assertEqual(attributes['source_advisory_time_kind'], 'unknown', record['id'])
            else:
                self.assertIn(attributes['source_advisory_time_kind'],
                              ('osv_modified', 'osv_published'), record['id'])
            kinds[attributes['source_advisory_time_kind']] = \
                kinds.get(attributes['source_advisory_time_kind'], 0) + 1
        self.assertEqual(kinds, {'osv_modified': 16, 'osv_published': 8, 'unknown': 10})

    def test_commit_meta_cache_is_sorted_and_canonical(self):
        lines = [line for line in COMMIT_META.read_text().splitlines() if line.strip()]
        self.assertEqual(len(lines), 34)
        rows = [json.loads(line) for line in lines]
        self.assertEqual([(r['repo'], r['sha']) for r in rows],
                         sorted((r['repo'], r['sha']) for r in rows))
        self.assertEqual(set(self.commit_meta),
                         {(r['repo'], r['sha']) for r in rows})
        for line, row in zip(lines, rows):
            self.assertEqual(line, cfr.canonical_line(row))
            self.assertEqual(set(row), {'repo', 'sha', 'committer_date', 'author_date', 'parents',
                                        'files_changed', 'api_url', 'fetched_at'})
            self.assertIsInstance(row['files_changed'], int)
            self.assertIsInstance(row['parents'], list)

    def test_missing_commit_meta_degrades_to_hypothesis(self):
        """Findings 1 and 4: no cached meta -> null date, hypothesis edge, no evidence id."""
        for project, name in (('git', 'cve-2016-2315'), ('nginx', 'nginx-CVE-2017-20005'),
                              ('sqlite', 'sqlite-CVE-2019-19244'),
                              ('openssh', 'openssh-CVE-2020-12062')):
            source = study_record(project, name)
            with tempfile.TemporaryDirectory() as td:
                row = temp_row(td, source, f'records/{name}.json')
                record, skip = cfr.build_record(row, 1, root=Path(td), commit_meta={})
                self.assertIsNone(skip, (project, name))
                attributes = node_of(record, 'commit')['attributes']
                self.assertIsNone(attributes['committed_at'], (project, name))
                self.assertEqual(edge_of(record, 'edge-fixed-by')['status'], 'hypothesis')
                self.assertEqual(edge_of(record, 'edge-fixed-by')['evidence_ids'], ['e-study'])
                self.assertNotIn('e-commit-meta', [e['id'] for e in record['evidence']])
                self.assertEqual(attributes['source_advisory_time_kind'],
                                 cfr.ADVISORY_TIME_KIND[project])
                self.assertEqual(attributes['source_advisory_time'],
                                 cfr._timestamp(source['fix']['committed_at']))

    def test_cached_commit_meta_makes_fixed_by_observed(self):
        source = study_record('git', 'cve-2016-2315')
        with tempfile.TemporaryDirectory() as td:
            row = temp_row(td, source, 'records/cve-2016-2315.json')
            record, skip = cfr.build_record(row, 1, root=Path(td),
                                            commit_meta={GIT_KEY: self.commit_meta[GIT_KEY]})
            self.assertIsNone(skip)
            edge = edge_of(record, 'edge-fixed-by')
            self.assertEqual(edge['status'], 'observed')
            self.assertEqual(edge['evidence_ids'], ['e-study', 'e-commit-meta'])
            self.assertEqual(node_of(record, 'commit')['attributes']['committed_at'],
                             GIT_COMMITTER_DATE)
            self.assertEqual(evidence_of(record, 'e-commit-meta')['sha256'],
                             hashlib.sha256(self.meta_lines[GIT_SHA].encode('utf-8')).hexdigest())

    def test_commit_meta_loader_only_indexes_the_returned_sha(self):
        """Finding 4: a row claiming a different sha must not match the record's commit."""
        row = dict(self.commit_meta[GIT_KEY], sha='0' * 40)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'commit-meta.jsonl'
            path.write_text(json.dumps(row) + '\n')
            meta = cfr.load_commit_meta(path)
            self.assertIn(('git/git', '0' * 40), meta)
            self.assertNotIn(GIT_KEY, meta)
            self.assertEqual(cfr.load_commit_meta(Path(td) / 'absent.jsonl'), {})
            empty = Path(td) / 'empty.jsonl'
            empty.write_text('')
            self.assertEqual(cfr.load_commit_meta(empty), {})
            missing = Path(td) / 'malformed.jsonl'
            missing.write_text('{"repo": "git/git"}\n')
            self.assertRaises(SystemExit, cfr.load_commit_meta, missing)

    def test_absent_cache_degrades_the_whole_pack(self):
        """Finding 1/4: with no cache every record loses its date and its observed edge."""
        original = cfr.COMMIT_META
        cfr.COMMIT_META = Path('/nonexistent/fable-2026-06/commit-meta.jsonl')
        try:
            converted, skipped = cfr.expected_records()
        finally:
            cfr.COMMIT_META = original
        self.assertEqual(skipped, [])
        self.assertEqual(len(converted), 34)
        for record_id, body in converted.items():
            record = json.loads(body)
            attributes = node_of(record, 'commit')['attributes']
            self.assertIsNone(attributes['committed_at'], record_id)
            self.assertEqual(edge_of(record, 'edge-fixed-by')['status'], 'hypothesis', record_id)
            self.assertNotIn('e-commit-meta', [e['id'] for e in record['evidence']], record_id)

    def test_advisory_stated_cwe_survives_for_advisory_reading_fetchers(self):
        """Finding 3: only study-assigned CWEs are demoted; a real advisory CWE keeps observed."""
        source = copy.deepcopy(study_record('git', 'cve-2016-2315'))
        source['cwe'] = 'CWE-20'
        source['cwe_state'] = 'STATED_BY_ADVISORY'
        with tempfile.TemporaryDirectory() as td:
            row = temp_row(td, source, 'records/cve-2016-2315.json')
            record, skip = cfr.build_record(row, 1, root=Path(td))
            self.assertIsNone(skip)
            self.assertEqual(node_of(record, 'advisory')['attributes']['cwe_state'],
                             'STATED_BY_ADVISORY')
            self.assertEqual(claim_of(record, 'claim-cwe')['status'], 'observed')
            self.assertIn('read from the fetched advisory', claim_of(record, 'claim-cwe')['text'])
            # The same shape under openssh is a study assignment, not an advisory statement.
            source['project'] = 'openssh'
            row = temp_row(td, source, 'records/openssh-CVE-1.json')
            record, skip = cfr.build_record(row, 1, root=Path(td))
            self.assertIsNone(skip)
            self.assertEqual(node_of(record, 'advisory')['attributes']['cwe_state'],
                             'ASSIGNED_BY_STUDY')
            self.assertEqual(claim_of(record, 'claim-cwe')['status'], 'hypothesis')

    def test_openssh_hardcoded_cwe_is_not_observed(self):
        """Finding 3: the openssh CWE table lives in the fetcher, not in the advisory."""
        assigned = 0
        for row in VETTED:
            if row['project'] != 'openssh':
                continue
            record = json.loads(self.converted[f"{row['project']}-{row['advisory_id']}"])
            advisory = node_of(record, 'advisory')['attributes']
            claim = claim_of(record, 'claim-cwe')
            if advisory['cwe']:
                assigned += 1
                self.assertEqual(advisory['cwe_state'], 'ASSIGNED_BY_STUDY', record['id'])
                self.assertEqual(claim['status'], 'hypothesis', record['id'])
                self.assertIn('assigned', claim['text'])
                self.assertNotIn('states', claim['text'])
            else:
                self.assertEqual(advisory['cwe_state'], 'UNKNOWN', record['id'])
                self.assertEqual(claim['status'], 'observed', record['id'])
        self.assertEqual(assigned, 3)
        self.assertEqual(claim_of(json.loads(self.converted['openssh-CVE-2023-25136']),
                                 'claim-cwe')['text'],
                         'The cited source study assigned CWE-416 to CVE-2023-25136; the fetched '
                         'advisory does not state it, so the classification is an analyst '
                         'hypothesis (source cwe_state: ASSIGNED_BY_STUDY).')

    def test_advisory_stated_cwe_stays_observed(self):
        """Finding 3, inverse: STATED_BY_ADVISORY only survives where the advisory carries it."""
        for record in self.records:
            advisory = node_of(record, 'advisory')['attributes']
            claim = claim_of(record, 'claim-cwe')
            if advisory['cwe_state'] == 'ASSIGNED_BY_STUDY':
                self.assertEqual(record['project'], 'openssh', record['id'])
                continue
            self.assertEqual(claim['status'], 'observed', record['id'])
            self.assertIn('states', claim['text'])
            if advisory['cwe']:
                self.assertEqual(advisory['cwe_state'], 'STATED_BY_ADVISORY', record['id'])

    def test_fix_link_restates_the_source(self):
        for row in VETTED:
            record_id = f"{row['project']}-{row['advisory_id']}"
            record = json.loads(self.converted[record_id])
            source = json.loads((ROOT / row['record_file']).read_text())
            fix = source['fix']
            claim = claim_of(record, 'claim-fix-link')
            self.assertIn(row['advisory_id'], claim['text'])
            self.assertIn(fix['sha'], claim['text'])
            commit = node_of(record, 'commit')
            self.assertEqual(commit['attributes']['sha'], fix['sha'])
            self.assertEqual(commit['attributes']['url'], fix['url'])
            # The URL-string digest of nginx/systemd evidences nothing about the link.
            self.assertEqual(claim['evidence_ids'],
                             ['e-study'] if row['project'] in ('nginx', 'systemd') else
                             ['e-study', 'e-commit'])
            advisory = node_of(record, 'advisory')['attributes']
            self.assertEqual(advisory['cwe'], source['cwe'])
            if source['cwe'] and row['project'] == 'openssh':
                self.assertEqual(advisory['cwe_state'], 'ASSIGNED_BY_STUDY')
            else:
                self.assertEqual(advisory['cwe_state'], source['cwe_state'])

    def test_study_record_digest_pins_the_cited_bytes(self):
        for row in VETTED:
            record = json.loads(self.converted[f"{row['project']}-{row['advisory_id']}"])
            evidence = evidence_of(record, 'e-study')
            self.assertEqual(evidence['sha256'],
                             hashlib.sha256((ROOT / row['record_file']).read_bytes()).hexdigest())
            self.assertEqual(record['validation']['source_record'], row['record_file'])

    def test_skip_reasons(self):
        base = study_record('git', 'cve-2016-2315')

        def run(mutate):
            source = copy.deepcopy(base)
            mutate(source)
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / 'records' / 'cve-2016-2315.json'
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(source))
                row = {'advisory_id': 'CVE-2016-2315', 'fix_sha': source['fix']['sha'],
                       'project': 'git', 'record_file': str(path.relative_to(Path(td)))}
                return cfr.build_record(row, 1, root=Path(td))

        cases = {
            'no valid 40-hex fix SHA': lambda s: s['fix'].update(sha='34fa79a'),
            'no https fix URL': lambda s: s['fix'].update(url='http://github.com/git/git/commit/' + s['fix']['sha']),
            'fix URL is not a recognized GitHub commit/blob reference':
                lambda s: s['fix'].update(url='https://github.com/git/git/releases/tag/v2.8.0'),
            'fix SHA and fix URL disagree': lambda s: s['fix'].update(sha='0' * 40),
            'source record has no evidence entry': lambda s: s.update(evidence=[]),
            'source digest is not a sha256': lambda s: s['evidence'][0].update(sha256='nope'),
            'source record has no pattern family': lambda s: s.update(pattern_family=''),
            'source observed_at is missing': lambda s: s['evidence'][0].update(observed_at=''),
        }
        for reason, mutate in cases.items():
            record, skip = run(mutate)
            self.assertIsNone(record, reason)
            self.assertEqual(skip, reason)
        with tempfile.TemporaryDirectory() as td:
            broken = Path(td) / 'records' / 'cve-2016-2315.json'
            broken.parent.mkdir(parents=True)
            broken.write_text('{ not json')
            row = {'advisory_id': 'CVE-2016-2315', 'fix_sha': base['fix']['sha'], 'project': 'git',
                   'record_file': 'records/cve-2016-2315.json'}
            self.assertEqual(cfr.build_record(row, 1, root=Path(td))[1],
                             'source record is not valid JSON')
        unknown = {'project': 'unknownproj', 'advisory_id': 'CVE-1', 'fix_sha': base['fix']['sha'],
                   'record_file': 'docs/studies/fable-2026-06/git/records/cve-2016-2315.json'}
        self.assertIsNone(cfr.build_record(unknown, 1)[0])
        self.assertEqual(cfr.build_record(unknown, 1)[1],
                         'no declared digest provenance for project unknownproj')

    def test_url_digest_drift_is_rejected(self):
        source = study_record('systemd', 'systemd-CVE-2020-1712')
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'records' / 'systemd-CVE-2020-1712.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(source))
            row = {'advisory_id': 'CVE-2020-1712', 'fix_sha': source['fix']['sha'],
                   'project': 'systemd', 'record_file': 'records/systemd-CVE-2020-1712.json'}
            self.assertIsNone(cfr.build_record(row, 1, root=Path(td))[1])
            source['evidence'][0]['sha256'] = '0' * 64
            path.write_text(json.dumps(source))
            record, skip = cfr.build_record(row, 1, root=Path(td))
            self.assertIsNone(record)
            self.assertEqual(skip, 'recorded digest does not match the declared URL-string scope')

    def test_gh_api_timeout_becomes_clean_systemexit(self):
        """Finding: a stalled or auth-prompting gh must not hang --fetch-commit-meta;
        the timeout surfaces as a clean SystemExit and the cache is left unchanged."""
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / 'commit-meta.jsonl'
            seen = {}

            def fake_run(cmd, **kwargs):
                seen['timeout'] = kwargs.get('timeout')
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get('timeout'))

            with mock.patch.object(cfr.shutil, 'which', return_value='/usr/bin/gh'), \
                 mock.patch.object(cfr.subprocess, 'run', side_effect=fake_run):
                with self.assertRaises(SystemExit) as ctx:
                    cfr.fetch_commit_meta(path=cache)
            message = str(ctx.exception)
            self.assertIn('timed out', message)
            self.assertIn('cache left unchanged', message)
            # The timeout must actually be passed to the subprocess call.
            self.assertEqual(seen['timeout'], cfr.GH_API_TIMEOUT)
            self.assertFalse(cache.exists())

    def _run_main(self, argv_extra, converted, skipped, records):
        """Invoke cfr.main() against a temp records dir with patched expectations."""
        argv = sys.argv
        try:
            sys.argv = ['convert_fable_records.py'] + argv_extra
            with mock.patch.object(cfr, 'RECORDS_DIR', records), \
                 mock.patch.object(cfr, 'expected_records', return_value=(converted, skipped)):
                return cfr.main()
        finally:
            sys.argv = argv

    @staticmethod
    def _converter_body(record_id, source_record):
        record = {'id': record_id, 'validation': {'source_record': source_record}}
        return (json.dumps(record, indent=2) + '\n').encode()

    def test_check_fails_when_a_previously_converted_row_now_skips(self):
        """Finding: --check must fail if a row that used to convert now hits a skip
        reason, instead of exiting 0 while its stale record stays on disk."""
        rid = 'git-CVE-2016-2315'
        body = self._converter_body(rid, 'docs/studies/fable-2026-06/git/records/cve-2016-2315.json')
        skipped = [('CVE-2020-5260', 'recorded digest does not match the declared URL-string scope')]
        with tempfile.TemporaryDirectory() as td:
            records = Path(td)
            (records / f'{rid}.json').write_bytes(body)
            with self.assertRaises(SystemExit) as ctx:
                self._run_main(['--check'], {rid: body}, skipped, records)
        self.assertIn('skipped', str(ctx.exception))

    def test_check_fails_on_orphaned_converter_record(self):
        """Finding: --check must fail when an on-disk converter record's vetted row was
        removed, so build_pack cannot export a record the converter can no longer make."""
        rid = 'git-CVE-2016-2315'
        body = self._converter_body(rid, 'docs/studies/fable-2026-06/git/records/cve-2016-2315.json')
        orphan = {'id': 'git-CVE-9999-0001',
                  'validation': {'source_record': 'docs/studies/fable-2026-06/git/records/cve-9999-0001.json'}}
        with tempfile.TemporaryDirectory() as td:
            records = Path(td)
            (records / f'{rid}.json').write_bytes(body)
            (records / 'git-CVE-9999-0001.json').write_text(json.dumps(orphan, indent=2) + '\n')
            with self.assertRaises(SystemExit) as ctx:
                self._run_main(['--check'], {rid: body}, [], records)
            message = str(ctx.exception)
        self.assertIn('orphan', message)
        self.assertIn('git-CVE-9999-0001.json', message)

    def test_check_ignores_hand_authored_record_without_source_record(self):
        """Guard: a hand-authored record (no validation.source_record) is never orphaned,
        so --check does not flag records the converter was never responsible for."""
        rid = 'git-CVE-2016-2315'
        body = self._converter_body(rid, 'docs/studies/fable-2026-06/git/records/cve-2016-2315.json')
        with tempfile.TemporaryDirectory() as td:
            records = Path(td)
            (records / f'{rid}.json').write_bytes(body)
            (records / 'linux-CVE-2024-26581-mainline.json').write_text(json.dumps(
                {'id': 'linux-CVE-2024-26581-mainline', 'validation': {'method': 'manual'}}) + '\n')
            # No exception: the hand-authored record is not a converter orphan.
            self.assertIsNone(self._run_main(['--check'], {rid: body}, [], records))

    def test_write_mode_removes_orphan_but_keeps_hand_authored(self):
        """Finding: write mode drops converter orphans the converter cannot rebuild;
        hand-authored records (no source_record) must survive untouched."""
        rid = 'git-CVE-2016-2315'
        body = self._converter_body(rid, 'docs/studies/fable-2026-06/git/records/cve-2016-2315.json')
        with tempfile.TemporaryDirectory() as td:
            records = Path(td)
            (records / f'{rid}.json').write_bytes(b'stale bytes to be rewritten')
            orphan = records / 'git-CVE-9999-0001.json'
            orphan.write_text(json.dumps({'id': 'git-CVE-9999-0001', 'validation': {
                'source_record': 'docs/studies/fable-2026-06/git/records/cve-9999-0001.json'}}) + '\n')
            hand = records / 'linux-CVE-2024-26581-mainline.json'
            hand.write_text(json.dumps({'id': 'linux-CVE-2024-26581-mainline',
                                        'validation': {'method': 'manual'}}) + '\n')
            self._run_main([], {rid: body}, [], records)  # write mode
            self.assertFalse(orphan.exists(), 'orphan must be removed in write mode')
            self.assertEqual((records / f'{rid}.json').read_bytes(), body)
            self.assertTrue(hand.exists(), 'hand-authored record must be preserved')

    def test_qrels_abstention_probes_are_not_degraded(self):
        """Guard the text choices: qrels-v1 baseline must be unchanged by the new records."""
        from measure_baseline import measure
        qrels = ROOT / 'experiments' / 'qrels-v1.json'
        negatives = [i for i in json.loads(qrels.read_text())['items'] if i['expect'] == 'ABSTAIN']
        for item in negatives:
            self.assertEqual(indexed_text(self.records[0]).find(item['query'].split()[0].lower()), -1)
        with tempfile.TemporaryDirectory() as td:
            database = Path(td) / 'pack.sqlite3'
            database.write_text(build_sql(load_records()))
            report = measure(qrels, database)
        summary = report['summary']
        self.assertEqual(summary['n_not_measured'], 0)
        self.assertEqual((summary['positive_recall']['hits'], summary['positive_recall']['denominator']),
                         (6, 6))
        self.assertEqual((summary['negative_abstention']['correct'],
                          summary['negative_abstention']['denominator']), (2, 3))


if __name__ == '__main__':
    unittest.main()
