#!/usr/bin/env python3
"""Offline unit tests for fetch_kernel_cna_shas (tiny inline fixtures, no network)."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts' / 'studies'))
from fetch_kernel_cna_shas import (  # noqa: E402
    CVE_RE,
    MAX_CATALOG_BYTES,
    PROJECT,
    SHA_RE,
    build_catalog,
    compute,
    cwe_of,
    load_cna_shas,
    load_cna_meta,
    merge_shas,
    run,
    run_build,
    subsystem_of,
    vulns_head,
)

SCRIPT = REPO / 'scripts' / 'studies' / 'fetch_kernel_cna_shas.py'
SHA_A = '5578de4834fe0f2a34fedc7374be691443396d1f'
SHA_B = '446fda4f26822b2d42ab3396aafcedf38a9ff2b6'
SHA_C = '97bc3683c24999ee621d847c9348c75d2fe86272'
HEAD_SHA = '51d0a1628767051ef603dade82a45a24d8730b0c'


def make_vulns(root, records, head=HEAD_SHA):
    """Tiny stand-in for a vulns.git clone: cve/published/<year>/<CVE>.sha1 files."""
    published = root / 'cve' / 'published'
    for cve_id, shas in records.items():
        year = cve_id.split('-')[1]
        (published / year).mkdir(parents=True, exist_ok=True)
        (published / year / f'{cve_id}.sha1').write_text('\n'.join(shas) + '\n')
        # Files that must never be read as fix commits.
        (published / year / f'{cve_id}.vulnerable').write_text(SHA_B + '\n')
        (published / year / f'{cve_id}.mbox').write_text('Subject: no fix yet\n')
    git_dir = root / '.git'
    (git_dir / 'refs' / 'heads').mkdir(parents=True)
    (git_dir / 'HEAD').write_text('ref: refs/heads/master\n')
    (git_dir / 'refs' / 'heads' / 'master').write_text(head + '\n')
    return root


def write_records(root, records):
    """Add sibling CVE-*.json files: {cve_id: {published, cwe, program_files}}."""
    for cve_id, spec in records.items():
        year = cve_id.split('-')[1]
        directory = root / 'cve' / 'published' / year
        directory.mkdir(parents=True, exist_ok=True)
        cna = {'affected': [{'programFiles': spec.get('program_files') or ['net/core/x.c']}]}
        if 'published' in spec:
            cna['datePublished'] = spec['published']
        if 'cwe' in spec:
            cna['problemTypes'] = [{'descriptions': [
                {'lang': 'en', 'cweId': spec['cwe'],
                 'description': 'MUST NEVER BE COPIED INTO THE CATALOG'}]}]
        cna['descriptions'] = [{'lang': 'en', 'value': 'MUST NEVER BE COPIED INTO THE CATALOG'}]
        (directory / f'{cve_id}.json').write_text(json.dumps(
            {'containers': {'cna': cna}, 'cveMetadata': {'cveId': cve_id, 'state': 'PUBLISHED'},
             'dataVersion': '5.1.1'}))


def write_catalog(root, rows):
    linux = root / 'docs' / 'studies' / 'cve-history' / 'linux'
    linux.mkdir(parents=True, exist_ok=True)
    catalog = linux / 'catalog.jsonl'
    catalog.write_text(''.join(json.dumps(r) + '\n' for r in rows))
    index = linux / 'index.json'
    index.write_text(json.dumps({'schema_version': 'cve-history-v1', 'project': 'linux',
                                 'entry_count': len(rows), 'with_fix_sha': 0}, indent=2) + '\n')
    return catalog


def row(cve_id, published, fix_shas=None):
    return {'advisory_id': cve_id, 'published': published, 'cwe': None, 'cwe_state': 'UNKNOWN',
            'patch_urls': [], 'fix_shas': fix_shas or [], 'subsystem': 'unassigned'}


class TestPatterns(unittest.TestCase):
    def test_sha_and_cve_regex(self):
        self.assertTrue(SHA_RE.fullmatch(SHA_A))
        for bad in (SHA_A[:8], SHA_A.upper(), SHA_A + 'a', SHA_A[:-1] + 'g', '', ' ' + SHA_A):
            self.assertFalse(SHA_RE.fullmatch(bad), bad)
        for good in ('CVE-2024-26661', 'CVE-1999-0804'):
            self.assertTrue(CVE_RE.fullmatch(good))
        for bad in ('cve-2024-1', 'CVE-24-1', 'CVE-2024-1', 'linux-2024-26661'):
            self.assertFalse(CVE_RE.fullmatch(bad), bad)


class TestLoadCnaShas(unittest.TestCase):
    def test_reads_only_sha1_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_vulns(Path(td), {
                'CVE-2024-26661': [SHA_A, SHA_B],
                'CVE-2024-26954': [SHA_C],
                'CVE-2024-00000': [],
            })
            mapping = load_cna_shas(root)
            self.assertEqual(mapping, {'CVE-2024-26661': [SHA_A, SHA_B],
                                       'CVE-2024-26954': [SHA_C],
                                       'CVE-2024-00000': []})

    def test_deduplicates_and_ignores_blank_lines(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / 'cve' / 'published' / '2024'
            path.mkdir(parents=True)
            (path / 'CVE-2024-26661.sha1').write_text(f'\n{SHA_A}\n\n{SHA_A}\n\n')
            self.assertEqual(load_cna_shas(root), {'CVE-2024-26661': [SHA_A]})

    def test_rejects_non_40_hex_line(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / 'cve' / 'published' / '2024'
            path.mkdir(parents=True)
            (path / 'CVE-2024-26661.sha1').write_text(SHA_A[:12] + '\n')
            with self.assertRaises(SystemExit):
                load_cna_shas(root)

    def test_missing_published_dir_fails(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit):
                load_cna_shas(Path(td))

    def test_vulns_head_reads_git_dir_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(vulns_head(make_vulns(Path(td), {})), HEAD_SHA)

    def test_vulns_head_reads_detached_head(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / '.git').mkdir()
            (root / '.git' / 'HEAD').write_text(HEAD_SHA + '\n')
            self.assertEqual(vulns_head(root), HEAD_SHA)


class TestMergeShas(unittest.TestCase):
    def test_union_keeps_order_and_dedupes(self):
        self.assertEqual(merge_shas([SHA_A], [SHA_A, SHA_B]), [SHA_A, SHA_B])
        self.assertEqual(merge_shas(None, [SHA_B]), [SHA_B])
        self.assertEqual(merge_shas([], []), [])


class TestResolve(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vulns = make_vulns(self.root / 'vulns', {
            'CVE-2024-26661': [SHA_A, SHA_B],
            'CVE-2024-26954': [SHA_C],
        })
        self.rows = [row('CVE-2024-26661', '2024-02-21'),
                     row('CVE-2024-26954', '2024-05-14'),
                     row('CVE-1999-0804', '1999-06-01'),
                     row('CVE-2005-0189', '2005-05-10')]
        self.catalog = write_catalog(self.root, self.rows)

    def tearDown(self):
        self.tmp.cleanup()

    def read_outputs(self):
        linux = self.catalog.parent
        return ([json.loads(l) for l in (linux / 'catalog.jsonl').read_text().splitlines()],
                json.loads((linux / 'index.json').read_text()),
                [json.loads(l) for l in (linux / 'cna-fix-shas.jsonl').read_text().splitlines()])

    def test_compute_resolves_and_counts(self):
        outputs, summary = compute(self.vulns, self.catalog)
        self.assertEqual(summary['rows'], 4)
        self.assertEqual(summary['resolved'], 2)
        self.assertEqual(summary['not_in_cna'], 2)
        self.assertEqual(summary['sha_count'], 3)
        self.assertEqual(summary['vulns_commit'], HEAD_SHA)
        self.assertEqual(summary['cna_years'], '2024-2024')
        self.assertEqual(summary['catalog_years'], '1999-2024')
        bodies = {p.name: t for p, t in outputs}
        self.assertEqual(set(bodies), {'catalog.jsonl', 'index.json', 'cna-fix-shas.jsonl'})

    def test_only_catalog_ids_resolved_and_others_left_empty(self):
        run(self.vulns, self.catalog)
        rows, index, sidecar = self.read_outputs()
        by_id = {r['advisory_id']: r for r in rows}
        self.assertEqual(by_id['CVE-2024-26661']['fix_shas'], [SHA_A, SHA_B])
        self.assertEqual(by_id['CVE-2024-26954']['fix_shas'], [SHA_C])
        self.assertEqual(by_id['CVE-1999-0804']['fix_shas'], [])
        self.assertEqual(by_id['CVE-2005-0189']['fix_shas'], [])
        # Row count and unrelated fields are untouched.
        self.assertEqual(len(rows), 4)
        self.assertEqual([r['advisory_id'] for r in rows],
                         ['CVE-2024-26661', 'CVE-2024-26954', 'CVE-1999-0804', 'CVE-2005-0189'])
        self.assertEqual([r['published'] for r in rows], ['2024-02-21', '2024-05-14',
                                                          '1999-06-01', '2005-05-10'])
        self.assertEqual(index['with_fix_sha'], 2)
        self.assertEqual(index['entry_count'], 4)
        self.assertEqual([r['advisory_id'] for r in sidecar],
                         ['CVE-2024-26661', 'CVE-2024-26954'])
        self.assertEqual(sidecar[0], {'advisory_id': 'CVE-2024-26661', 'fix_shas': [SHA_A, SHA_B],
                                      'source': 'kernel-cna-vulns.git', 'vulns_commit': HEAD_SHA})

    def test_preexisting_shas_are_kept_not_replaced(self):
        self.catalog = write_catalog(self.root, [row('CVE-2024-26661', '2024-02-21',
                                                     fix_shas=[SHA_C])])
        run(self.vulns, self.catalog)
        rows, _, _ = self.read_outputs()
        self.assertEqual(rows[0]['fix_shas'], [SHA_C, SHA_A, SHA_B])

    def test_unresolved_catalog_is_byte_identical(self):
        unresolved = [row('CVE-1999-0804', '1999-06-01'),
                      row('CVE-2005-0189', '2005-05-10')]
        before = ''.join(json.dumps(r) + '\n' for r in unresolved)
        self.catalog = write_catalog(self.root, unresolved)
        summary = run(self.vulns, self.catalog)
        self.assertEqual(summary['resolved'], 0)
        self.assertEqual(summary['not_in_cna'], 2)
        self.assertEqual(summary['sha_count'], 0)
        # Not a single byte of the catalog changes when nothing resolves.
        self.assertEqual(self.catalog.read_text(), before)

    def test_check_is_idempotent_then_detects_drift(self):
        run(self.vulns, self.catalog)
        self.assertEqual(run(self.vulns, self.catalog, check=True)['resolved'], 2)
        rows = self.read_outputs()[0]
        dropped = [r for r in rows if r['advisory_id'] == 'CVE-2024-26661'][0]
        dropped['fix_shas'] = []
        self.catalog.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        with self.assertRaises(SystemExit):
            run(self.vulns, self.catalog, check=True)

    def test_missing_sidecar_is_detected_by_check(self):
        run(self.vulns, self.catalog)
        (self.catalog.parent / 'cna-fix-shas.jsonl').unlink()
        with self.assertRaises(SystemExit):
            run(self.vulns, self.catalog, check=True)

    def test_vulns_commit_change_is_detected_by_check(self):
        """Proves vulns_commit is really embedded in the sidecar, not silently ignored."""
        run(self.vulns, self.catalog)
        moved = make_vulns(self.root / 'vulns-moved', {'CVE-2024-26661': [SHA_A, SHA_B]},
                           head=HEAD_SHA.replace('0', 'a', 1))
        with self.assertRaises(SystemExit):
            run(moved, self.catalog, check=True)

    def test_index_with_fix_sha_recomputed_not_copied(self):
        run(self.vulns, self.catalog)
        _, index, _ = self.read_outputs()
        self.assertEqual(index['with_fix_sha'], 2)

    def test_missing_index_fails(self):
        (self.catalog.parent / 'index.json').unlink()
        with self.assertRaises(SystemExit):
            run(self.vulns, self.catalog)


class TestCli(unittest.TestCase):
    """Run the real script as a subprocess to exercise its own CLI and output."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vulns = make_vulns(self.root / 'vulns', {'CVE-2024-26661': [SHA_A, SHA_B]})
        self.catalog = write_catalog(self.root, [row('CVE-2024-26661', '2024-02-21'),
                                                row('CVE-1999-0804', '1999-06-01')])

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), '--vulns-dir', str(self.vulns),
                              '--catalog', str(self.catalog), *extra],
                             capture_output=True, text=True, check=False)

    def test_run_then_check_then_drift(self):
        first = self.cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn('rows=2 resolved=1 not_in_cna=1 shas=2', first.stdout)
        self.assertIn(f'vulns_commit={HEAD_SHA}', first.stdout)
        self.assertIn('absent from kernel CNA data', first.stdout)

        second = self.cli('--check')
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn('outputs verified', second.stdout)

        sidecar = self.catalog.parent / 'cna-fix-shas.jsonl'
        sidecar.unlink()
        third = self.cli('--check')
        self.assertNotEqual(third.returncode, 0)
        self.assertIn('stale outputs', third.stderr)

    def test_vulns_head_reported_from_fixture(self):
        out = self.cli()
        self.assertIn(HEAD_SHA, out.stdout)


class TestCnaMeta(unittest.TestCase):
    """published / cwe / subsystem must come from the CVE 5.x record, or stay empty."""

    def test_subsystem_is_leading_path_components(self):
        self.assertEqual(subsystem_of([{'programFiles': ['net/core/filter.c']}]), 'net')
        self.assertEqual(subsystem_of([{'programFiles': ['fs/f2fs/x.c']}]), 'fs')
        self.assertEqual(subsystem_of([{'programFiles': ['mm/memory.c']}]), 'mm')
        self.assertEqual(subsystem_of([{'programFiles': ['drivers/net/x/y.c']}]), 'drivers/net')
        self.assertEqual(subsystem_of([{'programFiles': ['kernel/bpf/x.c']}]), 'kernel')
        self.assertEqual(subsystem_of([{'programFiles': []}]), 'unassigned')
        self.assertEqual(subsystem_of([]), 'unassigned')
        self.assertEqual(subsystem_of(None), 'unassigned')
        self.assertEqual(subsystem_of([{'programFiles': ['net/core/filter.c']},
                                       {'programFiles': ['mm/memory.c']}]), 'net')

    def test_cwe_of_first_problem_type(self):
        types = [{'descriptions': [{'lang': 'en', 'cweId': 'CWE-416'}]},
                 {'descriptions': [{'lang': 'en', 'cweId': 'CWE-787'}]}]
        self.assertEqual(cwe_of(types), 'CWE-416')
        self.assertEqual(cwe_of([{'descriptions': [{'lang': 'en', 'description': 'no id'}]}]), None)
        self.assertEqual(cwe_of(None), None)
        self.assertEqual(cwe_of('nonsense'), None)

    def test_meta_reads_sibling_json_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_vulns(root, {'CVE-2024-26661': [SHA_A]})
            write_records(root, {'CVE-2024-26661': {
                'published': '2024-02-21T10:11:12', 'cwe': 'CWE-416',
                'program_files': ['drivers/net/ethernet/x.c']}})
            meta = load_cna_meta(root)
            self.assertEqual(meta, {'CVE-2024-26661': {'published': '2024-02-21',
                                                      'cwe': 'CWE-416',
                                                      'subsystem': 'drivers/net'}})
            self.assertNotIn('description', meta['CVE-2024-26661'])

    def test_meta_leaves_absent_fields_null(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_vulns(root, {'CVE-2024-26661': [SHA_A]})
            write_records(root, {'CVE-2024-26661': {}})
            meta = load_cna_meta(root)
            self.assertEqual(meta['CVE-2024-26661'],
                             {'published': None, 'cwe': None, 'subsystem': 'net'})


class TestBuildCatalog(unittest.TestCase):
    """--build-catalog: the authoritative kernel catalog, built offline."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vulns = make_vulns(self.root / 'vulns', {
            'CVE-2024-26954': [SHA_C],
            'CVE-2024-26661': [SHA_A, SHA_B],
            'CVE-2019-25160': [SHA_B],
        })
        write_records(self.vulns, {
            'CVE-2024-26661': {'published': '2024-02-21T00:00:00', 'cwe': 'CWE-416',
                               'program_files': ['drivers/net/ethernet/intel/igb/igb_main.c']},
            'CVE-2024-26954': {'program_files': ['fs/f2fs/x.c']},
            'CVE-2019-25160': {'published': 'not-a-date', 'program_files': ['net/ipv4/cipso_ipv4.c']},
        })
        self.out = self.root / 'docs' / 'studies' / 'cve-history' / 'linux-cna'

    def tearDown(self):
        self.tmp.cleanup()

    def read_outputs(self):
        rows = [json.loads(l) for l in (self.out / 'catalog.jsonl').read_text().splitlines()]
        return rows, json.loads((self.out / 'index.json').read_text())

    def test_rows_are_sorted_and_shaped_like_the_other_catalogs(self):
        run_build(self.vulns, self.out)
        rows, index = self.read_outputs()
        self.assertEqual([r['advisory_id'] for r in rows],
                         ['CVE-2019-25160', 'CVE-2024-26661', 'CVE-2024-26954'])
        for row in rows:
            self.assertEqual(list(row), ['advisory_id', 'published', 'cwe', 'cwe_state',
                                         'patch_urls', 'fix_shas', 'subsystem', 'fix_sha_source'])
            self.assertEqual(row['fix_sha_source'], 'kernel-cna')
            self.assertNotIn('description', row)
        self.assertEqual(index['entry_count'], 3)

    def test_fix_shas_and_patch_urls_come_from_the_sha1_files(self):
        run_build(self.vulns, self.out)
        rows, _ = self.read_outputs()
        by_id = {r['advisory_id']: r for r in rows}
        self.assertEqual(by_id['CVE-2024-26661']['fix_shas'], [SHA_A, SHA_B])
        self.assertEqual(by_id['CVE-2024-26661']['patch_urls'],
                         [f'https://git.kernel.org/stable/c/{SHA_A}',
                          f'https://git.kernel.org/stable/c/{SHA_B}'])
        self.assertEqual(by_id['CVE-2024-26954']['fix_shas'], [SHA_C])
        self.assertEqual(by_id['CVE-2024-26954']['patch_urls'],
                         [f'https://git.kernel.org/stable/c/{SHA_C}'])

    def test_present_meta_is_copied_absent_meta_stays_null(self):
        run_build(self.vulns, self.out)
        rows, index = self.read_outputs()
        by_id = {r['advisory_id']: r for r in rows}
        self.assertEqual(by_id['CVE-2024-26661']['published'], '2024-02-21')
        self.assertEqual(by_id['CVE-2024-26661']['cwe'], 'CWE-416')
        self.assertEqual(by_id['CVE-2024-26661']['cwe_state'], 'STATED_BY_ADVISORY')
        self.assertEqual(by_id['CVE-2024-26661']['subsystem'], 'drivers/net')
        # No datePublished, no problemTypes: nothing invented.
        self.assertIsNone(by_id['CVE-2024-26954']['published'])
        self.assertIsNone(by_id['CVE-2024-26954']['cwe'])
        self.assertEqual(by_id['CVE-2024-26954']['cwe_state'], 'UNKNOWN')
        self.assertEqual(by_id['CVE-2024-26954']['subsystem'], 'fs')
        # A malformed date is not a date.
        self.assertIsNone(by_id['CVE-2019-25160']['published'])
        self.assertEqual(by_id['CVE-2019-25160']['subsystem'], 'net')
        self.assertEqual(index['with_cwe'], 1)

    def test_index_mirrors_the_sibling_catalog_shape(self):
        run_build(self.vulns, self.out)
        _, index = self.read_outputs()
        self.assertEqual(index['schema_version'], 'cve-history-v1')
        self.assertEqual(index['project'], PROJECT)
        self.assertEqual(index['repo'], 'https://github.com/torvalds/linux')
        self.assertEqual(index['source'], 'https://git.kernel.org/pub/scm/linux/security/vulns.git')
        self.assertEqual(index['vulns_commit'], HEAD_SHA)
        self.assertEqual(index['entry_count'], 3)
        self.assertEqual(index['with_fix_sha'], 3)
        self.assertEqual(index['with_cwe'], 1)
        self.assertEqual(index['coverage'], 'COMPLETE_AT_COMMIT')
        self.assertEqual(index['status'], 'FETCHED')
        self.assertEqual(index['errors'], [])

    def test_missing_sibling_json_fails(self):
        (self.vulns / 'cve' / 'published' / '2024' / 'CVE-2024-26954.json').unlink()
        with self.assertRaises(SystemExit):
            build_catalog(self.vulns, self.out)
        self.assertFalse((self.out / 'catalog.jsonl').exists())

    def test_check_is_idempotent_then_detects_drift(self):
        run_build(self.vulns, self.out)
        first = (self.out / 'catalog.jsonl').read_bytes()
        run_build(self.vulns, self.out, check=True)
        self.assertEqual((self.out / 'catalog.jsonl').read_bytes(), first)
        rows = self.read_outputs()[0]
        rows[0]['fix_shas'] = []
        rows[0]['patch_urls'] = []
        (self.out / 'catalog.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
        with self.assertRaises(SystemExit):
            run_build(self.vulns, self.out, check=True)

    def test_size_guard_stops_before_writing(self):
        import fetch_kernel_cna_shas as script
        original = script.MAX_CATALOG_BYTES
        script.MAX_CATALOG_BYTES = 8
        try:
            with self.assertRaises(SystemExit) as caught:
                build_catalog(self.vulns, self.out)
        finally:
            script.MAX_CATALOG_BYTES = original
        self.assertIn('byte limit', str(caught.exception))
        self.assertFalse((self.out / 'catalog.jsonl').exists())
        self.assertFalse((self.out / 'index.json').exists())


class TestBuildCatalogCli(unittest.TestCase):
    """Run the real script to exercise --build-catalog end to end."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vulns = make_vulns(self.root / 'vulns', {
            'CVE-2024-26661': [SHA_A, SHA_B],
            'CVE-2024-26954': [SHA_C],
        })
        write_records(self.vulns, {
            'CVE-2024-26661': {'published': '2024-02-21', 'cwe': 'CWE-416',
                               'program_files': ['drivers/net/x/y.c']},
            'CVE-2024-26954': {'program_files': ['fs/f2fs/x.c']},
        })
        self.out = self.root / 'linux-cna'

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), '--vulns-dir', str(self.vulns),
                               *extra], capture_output=True, text=True, check=False)

    def test_build_then_check(self):
        first = self.cli('--build-catalog', str(self.out))
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn(f'project={PROJECT} entries=2 with_fix_sha=2 with_cwe=1 shas=3', first.stdout)
        self.assertIn(f'vulns_commit={HEAD_SHA}', first.stdout)
        self.assertIn('coverage=COMPLETE_AT_COMMIT status=FETCHED', first.stdout)
        self.assertIn('outputs written', first.stdout)

        second = self.cli('--build-catalog', str(self.out), '--check')
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn('outputs verified', second.stdout)

        (self.out / 'catalog.jsonl').unlink()
        third = self.cli('--build-catalog', str(self.out), '--check')
        self.assertNotEqual(third.returncode, 0)
        self.assertIn('stale outputs', third.stderr)

    def test_modes_are_mutually_exclusive(self):
        both = self.cli('--build-catalog', str(self.out), '--catalog', 'x.jsonl')
        self.assertNotEqual(both.returncode, 0)
        self.assertIn('mutually exclusive', both.stderr)
        neither = self.cli()
        self.assertNotEqual(neither.returncode, 0)
        self.assertIn('is required', neither.stderr)


if __name__ == '__main__':
    unittest.main()
