#!/usr/bin/env python3
"""Resolve upstream Linux kernel fix commits for CVE history rows using kernel CNA data.

The Linux kernel CNA publishes CVE -> fix-commit mappings in its vulnerability
repository, https://git.kernel.org/pub/scm/linux/security/vulns.git .  Verified
layout of that clone:

    cve/published/<year>/<CVE-ID>.sha1    one 40-hex fix commit per line
    cve/published/<year>/<CVE-ID>.json    CVE 5 record (affected versions with
                                          "version"/"lessThan" git commits)
    cve/published/<year>/<CVE-ID>.vulnerable, .mbox, .dyad, .cvss, .reference

This script reads only the .sha1 files for fix commits.  The
.vulnerable / .mbox / .dyad files are deliberately ignored so a "vulnerable
version" or an email address is never mistaken for a fix commit, and
.mbox / .message / descriptions are never read: no advisory text is copied.

Deterministic, stdlib-only, no network: point --vulns-dir at a local clone made
with

    git clone --depth 1 https://git.kernel.org/pub/scm/linux/security/vulns.git /tmp/ksm-vulns

Keep the clone outside the repository.  Two modes share the same loader:

--catalog PATH          enrich an existing catalog in place.  Outputs are written
                        next to --catalog:

    catalog.jsonl        fix_shas filled in for CVEs present in CNA data
    index.json           with_fix_sha recomputed
    cna-fix-shas.jsonl   one row per resolved CVE, with the vulns.git commit used

--build-catalog DIR     build a second, authoritative Linux kernel catalog
                        directly from the CNA data (no NVD keyword search, no LLM):

    catalog.jsonl        one row per published CVE, sorted by advisory_id
    index.json           counts, coverage COMPLETE_AT_COMMIT, status FETCHED

A catalog CVE that is absent from the CNA data keeps an empty fix_shas and is
counted as NOT_IN_CNA.  Nothing is ever inferred, guessed or carried over from
another source for those rows.

In --build-catalog mode the sibling CVE-*.json is read for published / cwe /
subsystem only, and only when the record carries them; see load_cna_meta.
Descriptions are never read, so no advisory text is copied.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path

SHA_RE = re.compile(r'^[0-9a-f]{40}$')
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
CWE_RE = re.compile(r'^CWE-\d+$')
SOURCE = 'kernel-cna-vulns.git'
INDEX_NAME = 'index.json'
SIDECAR_NAME = 'cna-fix-shas.jsonl'
CATALOG_NAME = 'catalog.jsonl'
PROJECT = 'linux-cna'
KERNEL_REPO = 'https://github.com/torvalds/linux'
VULNS_REPO = 'https://git.kernel.org/pub/scm/linux/security/vulns.git'
PATCH_URL_BASE = 'https://git.kernel.org/stable/c/'
MAX_CATALOG_BYTES = 8 * 1024 * 1024


def fail(message):
    raise SystemExit(f'fetch_kernel_cna_shas: {message}')


def vulns_head(vulns_dir):
    """HEAD commit of the vulns.git clone that supplied the SHAs."""
    vulns_dir = Path(vulns_dir)
    git_dir = vulns_dir / '.git'
    if git_dir.exists():
        done = subprocess.run(['git', '-C', str(vulns_dir), 'rev-parse', 'HEAD'],
                              capture_output=True, text=True, check=False)
        head = done.stdout.strip() if done.returncode == 0 else ''
        if SHA_RE.match(head):
            return head
        # No git binary, or git refused: read .git/HEAD directly.
        pointer = git_dir / 'HEAD'
        if pointer.is_file():
            text = pointer.read_text().strip()
            if text.startswith('ref: '):
                ref = git_dir / text[len('ref: '):].strip()
                if ref.is_file() and SHA_RE.match(ref.read_text().strip()):
                    return ref.read_text().strip()
            elif SHA_RE.match(text):
                return text
    fail(f'cannot determine the HEAD commit of the vulns clone {vulns_dir}')


def load_cna_shas(vulns_dir):
    """Map CVE id -> ordered fix SHAs, read from cve/published/<year>/*.sha1."""
    published = Path(vulns_dir) / 'cve' / 'published'
    if not published.is_dir():
        fail(f'{published} not found; --vulns-dir must be a vulns.git clone')
    mapping = {}
    for path in sorted(published.glob('*/*.sha1')):
        cve_id = path.stem
        if not CVE_RE.match(cve_id):
            fail(f'unexpected CNA record name: {path}')
        shas = []
        for line in path.read_text().splitlines():
            token = line.strip()
            if not token:
                continue
            if not SHA_RE.match(token):
                fail(f'non-40-hex SHA in {path}: {token!r}')
            if token not in shas:
                shas.append(token)
        if cve_id in mapping:
            fail(f'duplicate CNA record for {cve_id}')
        mapping[cve_id] = shas
    return mapping


def cwe_of(problem_types):
    """CWE id of the first problemTypes description that carries one, else None."""
    for entry in problem_types or []:
        if not isinstance(entry, dict):
            continue
        for desc in entry.get('descriptions') or []:
            if not isinstance(desc, dict):
                continue
            cwe = desc.get('cweId')
            if isinstance(cwe, str) and CWE_RE.match(cwe):
                return cwe
    return None


def subsystem_of(affected):
    """Leading path component(s) of the first affected programFiles entry.

    drivers/ carries no meaning on its own, so it takes two components
    (drivers/net/... -> drivers/net); every other tree takes one (net/, fs/, mm/).
    """
    for entry in affected or []:
        if not isinstance(entry, dict):
            continue
        for path in entry.get('programFiles') or []:
            if not isinstance(path, str):
                continue
            parts = [p for p in path.split('/') if p]
            if len(parts) >= 2 and parts[0] == 'drivers':
                return f'drivers/{parts[1]}'
            if parts:
                return parts[0]
    return 'unassigned'


def published_of(record):
    """datePublished of a CVE 5.x record as YYYY-MM-DD, or None when absent."""
    cna = record.get('containers', {}).get('cna', {})
    value = cna.get('datePublished')
    if isinstance(value, str) and DATE_RE.match(value[:10]):
        return value[:10]
    return None


def load_cna_meta(vulns_dir):
    """Map CVE id -> {published, cwe, subsystem} from the sibling CVE-*.json.

    The kernel CNA records are CVE 5.x and carry neither datePublished nor
    problemTypes, so published and cwe stay None unless a record supplies them.
    Descriptions are never read: no advisory text is copied into the catalog.
    """
    published_dir = Path(vulns_dir) / 'cve' / 'published'
    meta = {}
    for path in sorted(published_dir.glob('*/*.json')):
        cve_id = path.stem
        if not CVE_RE.match(cve_id):
            fail(f'unexpected CNA record name: {path}')
        record = json.loads(path.read_text(encoding='utf-8'))
        cna = record.get('containers', {}).get('cna', {})
        meta[cve_id] = {'published': published_of(record),
                        'cwe': cwe_of(cna.get('problemTypes')),
                        'subsystem': subsystem_of(cna.get('affected'))}
    return meta


def merge_shas(existing, extra):
    """Union two ordered SHA lists, preserving first-seen order."""
    merged = list(existing) if isinstance(existing, list) else []
    for sha in extra:
        if sha not in merged:
            merged.append(sha)
    return merged


def year_span(cve_ids):
    years = sorted({int(cve.split('-')[1]) for cve in cve_ids})
    return f'{years[0]}-{years[-1]}' if years else 'none'


def compute(vulns_dir, catalog_path):
    """Build the output files and the summary; returns (outputs, summary)."""
    head = vulns_head(vulns_dir)
    cna = load_cna_shas(vulns_dir)
    catalog_path = Path(catalog_path)
    if not catalog_path.is_file():
        fail(f'catalog not found: {catalog_path}')
    index_path = catalog_path.parent / INDEX_NAME
    if not index_path.is_file():
        fail(f'index not found: {index_path}')

    text = catalog_path.read_text(encoding='utf-8')
    lines = text.split('\n')
    trailing_newline = bool(lines) and lines[-1] == ''
    if trailing_newline:
        lines.pop()

    catalog_lines = []
    sidecar = []
    rows = resolved = not_in_cna = in_cna_without_shas = with_fix_sha = 0
    catalog_ids = []
    for line in lines:
        if not line.strip():
            fail(f'blank line in {catalog_path}')
        row = json.loads(line)
        cve_id = row.get('advisory_id')
        if not isinstance(cve_id, str) or not CVE_RE.match(cve_id):
            fail(f'catalog row without a valid advisory_id: {line[:120]}')
        rows += 1
        catalog_ids.append(cve_id)
        cna_shas = cna.get(cve_id)
        if cna_shas is None:
            not_in_cna += 1
            cna_shas = []
        elif not cna_shas:
            in_cna_without_shas += 1
        else:
            resolved += 1
            sidecar.append({'advisory_id': cve_id, 'fix_shas': cna_shas})
        merged = merge_shas(row.get('fix_shas'), cna_shas)
        if merged != row.get('fix_shas'):
            row['fix_shas'] = merged
            line = json.dumps(row, ensure_ascii=False)
        if merged:
            with_fix_sha += 1
        catalog_lines.append(line)

    catalog_text = '\n'.join(catalog_lines) + ('\n' if trailing_newline else '')
    sidecar_text = ''.join(
        json.dumps({'advisory_id': r['advisory_id'], 'fix_shas': r['fix_shas'],
                    'source': SOURCE, 'vulns_commit': head}, ensure_ascii=False) + '\n'
        for r in sorted(sidecar, key=lambda r: r['advisory_id']))
    index = json.loads(index_path.read_text(encoding='utf-8'))
    index['with_fix_sha'] = with_fix_sha
    index_text = json.dumps(index, indent=2, ensure_ascii=False) + '\n'

    outputs = [(catalog_path, catalog_text),
               (index_path, index_text),
               (catalog_path.parent / SIDECAR_NAME, sidecar_text)]
    summary = {'rows': rows, 'resolved': resolved, 'not_in_cna': not_in_cna,
               'sha_count': sum(len(json.loads(l)['fix_shas']) for l in catalog_lines),
               'in_cna_without_shas': in_cna_without_shas,
               'vulns_commit': head,
               'cna_years': year_span(cna), 'catalog_years': year_span(catalog_ids)}
    return outputs, summary


def catalog_row(cve_id, fix_shas, meta):
    """One catalog row; keys and order match the other cve-history catalogs."""
    fields = meta[cve_id]
    return {'advisory_id': cve_id,
            'published': fields['published'],
            'cwe': fields['cwe'],
            'cwe_state': 'STATED_BY_ADVISORY' if fields['cwe'] else 'UNKNOWN',
            'patch_urls': [PATCH_URL_BASE + sha for sha in fix_shas],
            'fix_shas': list(fix_shas),
            'subsystem': fields['subsystem'],
            'fix_sha_source': 'kernel-cna'}


def build_catalog(vulns_dir, out_dir):
    """Build the linux-cna catalog from the CNA data; returns (outputs, summary)."""
    head = vulns_head(vulns_dir)
    shas = load_cna_shas(vulns_dir)
    meta = load_cna_meta(vulns_dir)
    if set(meta) != set(shas):
        only_shas = sorted(set(shas) - set(meta))
        only_json = sorted(set(meta) - set(shas))
        fail('CNA .sha1 and .json records disagree: '
             f'{only_shas[:1] or only_json[:1]} (sha1-only={len(only_shas)}, json-only={len(only_json)})')

    rows = [catalog_row(cve_id, shas[cve_id], meta) for cve_id in sorted(shas)]
    catalog_text = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows)
    catalog_bytes = len(catalog_text.encode('utf-8'))
    if catalog_bytes > MAX_CATALOG_BYTES:
        fail(f'catalog.jsonl would be {catalog_bytes} bytes, over the '
             f'{MAX_CATALOG_BYTES} byte limit; nothing written')

    with_fix_sha = sum(1 for r in rows if r['fix_shas'])
    with_cwe = sum(1 for r in rows if r['cwe'])
    subsystems = {}
    for row in rows:
        subsystems[row['subsystem']] = subsystems.get(row['subsystem'], 0) + 1
    index = {'schema_version': 'cve-history-v1',
             'project': PROJECT,
             'repo': KERNEL_REPO,
             'source': VULNS_REPO,
             'vulns_commit': head,
             'entry_count': len(rows),
             'with_fix_sha': with_fix_sha,
             'with_cwe': with_cwe,
             'coverage': 'COMPLETE_AT_COMMIT',
             'status': 'FETCHED',
             'errors': [],
             'notes': ('Built offline from the kernel CNA clone at the vulns_commit above; no '
                       'NVD keyword search and no LLM. Descriptions omitted per policy. '
                       'published/cwe come from the CVE 5.x record and stay null when it does '
                       'not carry them; subsystem is the leading programFiles path.')}
    index_text = json.dumps(index, indent=2, ensure_ascii=False) + '\n'

    out_dir = Path(out_dir)
    outputs = [(out_dir / CATALOG_NAME, catalog_text), (out_dir / INDEX_NAME, index_text)]
    summary = {'entry_count': len(rows), 'with_fix_sha': with_fix_sha, 'with_cwe': with_cwe,
               'sha_count': sum(len(r['fix_shas']) for r in rows),
               'catalog_bytes': catalog_bytes, 'vulns_commit': head,
               'years': year_span(shas),
               'subsystems': sorted(subsystems.items(), key=lambda kv: (-kv[1], kv[0]))}
    return outputs, summary


def run_build(vulns_dir, out_dir, check=False):
    """Build (or verify) the linux-cna catalog and return the summary."""
    if not check:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
    outputs, summary = build_catalog(vulns_dir, out_dir)
    stale = write_outputs(outputs, check)
    if stale:
        fail('stale outputs: ' + ', '.join(str(p) for p in stale))
    return summary


def write_outputs(outputs, check):
    """Write changed outputs; in check mode only report them."""
    stale = []
    for path, body in outputs:
        current = path.read_text(encoding='utf-8') if path.is_file() else None
        if current == body:
            continue
        if check:
            stale.append(path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding='utf-8')
    return stale


def run(vulns_dir, catalog_path, check=False):
    """Resolve, write (or verify) the outputs and return the summary."""
    outputs, summary = compute(vulns_dir, catalog_path)
    stale = write_outputs(outputs, check)
    if stale:
        fail('stale outputs: ' + ', '.join(str(p) for p in stale))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--vulns-dir', required=True,
                        help='local clone of https://git.kernel.org/pub/scm/linux/security/vulns.git '
                             '(e.g. /tmp/ksm-vulns); never clone it inside the repo')
    parser.add_argument('--catalog',
                        help='catalog.jsonl to enrich; outputs land beside it')
    parser.add_argument('--build-catalog', dest='out_dir', metavar='OUT_DIR',
                        help='build the authoritative linux-cna catalog from the CNA data into '
                             'OUT_DIR (default docs/studies/cve-history/linux-cna)')
    parser.add_argument('--check', action='store_true',
                        help='recompute and exit non-zero if any output differs')
    args = parser.parse_args()
    if args.out_dir and args.catalog:
        parser.error('--build-catalog and --catalog are mutually exclusive')
    if not args.out_dir and not args.catalog:
        parser.error('one of --build-catalog OUT_DIR or --catalog PATH is required')
    if args.out_dir:
        summary = run_build(args.vulns_dir, args.out_dir, args.check)
        print(f"project={PROJECT} entries={summary['entry_count']} "
              f"with_fix_sha={summary['with_fix_sha']} with_cwe={summary['with_cwe']} "
              f"shas={summary['sha_count']} bytes={summary['catalog_bytes']}")
        print(f"vulns_commit={summary['vulns_commit']} source={VULNS_REPO} "
              f"cna_years={summary['years']} coverage=COMPLETE_AT_COMMIT status=FETCHED")
        print('top subsystems: ' + ', '.join(f'{name}={count}' for name, count
                                             in summary['subsystems'][:5]))
        print('outputs ' + ('verified' if args.check else 'written'))
        return
    summary = run(args.vulns_dir, args.catalog, args.check)
    print(f"rows={summary['rows']} resolved={summary['resolved']} "
          f"not_in_cna={summary['not_in_cna']} shas={summary['sha_count']} "
          f"in_cna_without_shas={summary['in_cna_without_shas']}")
    print(f"vulns_commit={summary['vulns_commit']} source={SOURCE}")
    print(f"cna_years={summary['cna_years']} catalog_years={summary['catalog_years']}")
    if summary['not_in_cna']:
        print(f"note: {summary['not_in_cna']}/{summary['rows']} catalog CVEs are absent from "
              "kernel CNA data (the catalog comes from an NVD keyword search and predates the "
              "kernel CNA); fix_shas left empty, nothing invented")
    print('outputs ' + ('verified' if args.check else 'written'))


if __name__ == '__main__':
    main()
