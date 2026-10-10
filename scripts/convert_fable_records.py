#!/usr/bin/env python3
"""Convert vetted fable-2026-06 study records into portable memory records.

Deterministic and offline by default: every generated field is derived from the
cited source study record (``docs/studies/vetted-shas.jsonl`` plus
``docs/studies/fable-2026-06/<project>/records/*.json``) and, for commit
timestamps and commit provenance, from the cached
``docs/studies/fable-2026-06/commit-meta.jsonl``. A claim either restates a
field of the source record or is marked ``hypothesis``; the source study's own
``insecure_pattern`` / ``mitigation`` prose is NOT copied into the pack (see
docs/DATA-POLICY.md), the source record is cited instead. Records that lack a
40-hex fix SHA, a recognized GitHub fix URL, usable evidence or declared digest
provenance are skipped and reported with a reason.

The upstream fetchers never fetched a fix commit: they filled
``fix.committed_at`` with an ADVISORY timestamp (OSV ``modified`` for
``git``/``systemd``, OSV ``published`` for ``sqlite``) and left it ``UNKNOWN``
for ``nginx``/``openssh``. The real commit date therefore needs one explicit,
separate network step that writes the cache; the converter itself (default and
``--check``) reads only that cache::

    python3 scripts/convert_fable_records.py --fetch-commit-meta   # network, once
    python3 scripts/convert_fable_records.py                       # write records

Without a cached row for a (repo, sha) the commit date is ``null`` and the
``fixed_by`` edge degrades to ``hypothesis``. The advisory timestamp the study
recorded is preserved as ``source_advisory_time`` together with
``source_advisory_time_kind``, so the substitution stays auditable.

Digest provenance differs per upstream fetcher, so it is declared per project
from the generating script instead of being guessed:

* ``git``/``openssh``/``sqlite``: the recorded digest covers the canonical JSON
  of the OSV advisory object that the fetcher read from
  ``https://api.osv.dev/v1/vulns/<advisory id>``
  (``scripts/studies/fetch_<project>.py``), so it does not cover commit content
  and the advisory JSON is not stored in this pack.
* ``nginx``/``systemd``: the recorded digest is the SHA-256 of the fix URL string
  itself (``scripts/studies/fetch_<project>.py``); no artifact content was
  fetched. This converter recomputes it and rejects the record on drift.

Hypothesis values (pattern family, defensive lesson) are kept out of record
titles, node labels and claim texts, because ``query_pack.query_database`` joins
terms with OR and the qrels-v1 abstention probes match generic tokens; the
values remain in node attributes, in the record payload and in the SQL ``nodes``
table.

Usage::

    python3 scripts/convert_fable_records.py --fetch-commit-meta   # network, once
    python3 scripts/convert_fable_records.py                       # write records
    python3 scripts/convert_fable_records.py --check               # verify, no writes

Stdlib only.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_pack import validate  # noqa: E402  (same validator the pack build uses)

ROOT = Path(__file__).resolve().parents[1]
VETTED = ROOT / 'docs/studies/vetted-shas.jsonl'
RECORDS_DIR = ROOT / 'docs/memory/records'
COMMIT_META = ROOT / 'docs/studies/fable-2026-06/commit-meta.jsonl'
OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/'
PACK_REPO = 'iberi22/kernel-security-memory'
PACK_REF = 'main'  # mutable discovery alias; the recorded digest pins the bytes read
SHA_RE = re.compile(r'^[0-9a-f]{40}$')
DIGEST_RE = re.compile(r'^[0-9a-f]{64}$')
FIX_URL_RE = re.compile(r'^https://github\.com/([^/]+)/([^/]+)/(?:commit|blob)/([0-9a-f]{40})(?:[/?#].*)?$')
ISO_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z?$')
# Per-call timeout for the --fetch-commit-meta gh api subprocess so a stalled or
# auth-prompting gh cannot hang a scripted refresh; raised as a clean SystemExit.
GH_API_TIMEOUT = 120

# Which advisory field each fetcher copied into fix.committed_at, read from the
# fetcher source rather than inferred from the value:
#   fetch_git.py:377      modified_at = item.get("modified") or item.get("published_at") ...
#   fetch_systemd.py:241  v.get("modified") or v.get("published") ...
#   fetch_sqlite.py:232   pub = v.get("published", "")
#   fetch_nginx.py:226    committed_at is the literal "UNKNOWN"
#   fetch_openssh.py:488  committed_at is the literal "UNKNOWN"
ADVISORY_TIME_KIND = {
    'git': 'osv_modified',
    'systemd': 'osv_modified',
    'sqlite': 'osv_published',
    'nginx': 'unknown',
    'openssh': 'unknown',
}

# Fetchers that read the CWE out of the advisory they fetched:
#   fetch_git.py:415 cwes = item.get("cwes", [])
#   fetch_sqlite.py:264 parse_cwe(details) over the advisory details/summary
#   fetch_systemd.py:301 re.search(r"CWE-\d+", summary)
# fetch_openssh.py instead takes cwe/cwe_state from the curated table at
# fetch_openssh.py:381-410, so its "STATED_BY_ADVISORY" is a study assignment.
CWE_FROM_ADVISORY = ('git', 'sqlite', 'systemd')

# Declared provenance of the digest each upstream fetcher stored, per project.
DIGESTS = {
    'git': {
        'extractor': 'fable-2026-06 slice; scripts/studies/fetch_git.py',
        'hash_scope': ('sha256 over the canonical JSON of the OSV advisory object at '
                       'https://api.osv.dev/v1/vulns/<advisory id>, as recorded by the upstream '
                       'study; commit content is not covered'),
        'canonicalization': ('upstream study canonicalization json.dumps(osv_vulnerability, '
                             'sort_keys=True) encoded UTF-8; the advisory JSON is not stored in '
                             'this pack, so the converter does not recompute it'),
        'source_license': ('OSV advisory metadata fetched by the upstream study from api.osv.dev; '
                           'dataset terms are not recorded by the source study'),
        'url_digest': False,
    },
    'nginx': {
        'extractor': 'fable-2026-06 slice; scripts/studies/fetch_nginx.py',
        'hash_scope': ('sha256 over the UTF-8 bytes of the fix commit URL string recorded by the '
                       'upstream study; no artifact content was fetched'),
        'canonicalization': ('upstream study canonicalization sha256(fix_url.encode("utf-8")); '
                             'recomputed by this converter from the URL in this record'),
        'source_license': ('no artifact content was fetched; only the fix URL string is hashed, so '
                           'no artifact license applies'),
        'url_digest': True,
    },
    'openssh': {
        'extractor': 'fable-2026-06 slice; scripts/studies/fetch_openssh.py',
        'hash_scope': ('sha256 over the canonical JSON of the OSV advisory object at '
                       'https://api.osv.dev/v1/vulns/<advisory id>, as recorded by the upstream '
                       'study; commit content is not covered'),
        'canonicalization': ('upstream study canonicalization json.dumps(osv_vulnerability, '
                             'sort_keys=True) encoded UTF-8; the advisory JSON is not stored in '
                             'this pack, so the converter does not recompute it'),
        'source_license': ('OSV advisory metadata fetched by the upstream study from api.osv.dev; '
                           'dataset terms are not recorded by the source study'),
        'url_digest': False,
    },
    'sqlite': {
        'extractor': 'fable-2026-06 slice; scripts/studies/fetch_sqlite.py',
        'hash_scope': ('sha256 over the canonical JSON of the OSV advisory object at '
                       'https://api.osv.dev/v1/vulns/<advisory id>, as recorded by the upstream '
                       'study; commit content is not covered'),
        'canonicalization': ('upstream study canonicalization json.dumps(osv_vulnerability, '
                             'sort_keys=True) encoded UTF-8; the advisory JSON is not stored in '
                             'this pack, so the converter does not recompute it'),
        'source_license': ('OSV advisory metadata fetched by the upstream study from api.osv.dev; '
                           'dataset terms are not recorded by the source study'),
        'url_digest': False,
    },
    'systemd': {
        'extractor': 'fable-2026-06 slice; scripts/studies/fetch_systemd.py',
        'hash_scope': ('sha256 over the UTF-8 bytes of the fix commit URL string recorded by the '
                       'upstream study; no artifact content was fetched'),
        'canonicalization': ('upstream study canonicalization sha256(fix_url.encode("utf-8")); '
                             'recomputed by this converter from the URL in this record'),
        'source_license': ('no artifact content was fetched; only the fix URL string is hashed, so '
                           'no artifact license applies'),
        'url_digest': True,
    },
}


def load_vetted(path=VETTED):
    """Return [(line number, row), ...] from the vetted sidecar."""
    rows = []
    for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
        if line.strip():
            rows.append((lineno, json.loads(line)))
    return rows


def _timestamp(value):
    return value if isinstance(value, str) and ISO_RE.match(value) else None


def canonical_line(row):
    """The canonical (sort_keys) JSON form of one commit-meta row."""
    return json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def load_commit_meta(path=None):
    """Index the cached commit metadata by (repo, returned sha).

    Indexing on the sha the API returned means a row is only found when the
    cached commit really is the commit the record asks for; a missing or
    mismatched cache entry yields ``None`` and the caller degrades to
    ``hypothesis`` instead of asserting an unfetched fact.
    """
    path = COMMIT_META if path is None else Path(path)
    if not path.is_file():
        return {}
    meta = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        repo, sha = row.get('repo'), row.get('sha')
        if not (isinstance(repo, str) and isinstance(sha, str) and repo and sha):
            raise SystemExit(f'Malformed commit-meta line in {path}: {line[:80]}')
        meta[(repo, sha)] = row
    return meta


def build_record(row, lineno, root=ROOT, commit_meta=None):
    """Convert one vetted row into (memory record, skip reason). Exactly one is None."""
    project = row.get('project')
    advisory = row.get('advisory_id')
    rel = row.get('record_file')
    if not (isinstance(project, str) and project.strip()):
        return None, 'missing project'
    if not (isinstance(advisory, str) and advisory.strip()):
        return None, 'missing advisory_id'
    if not (isinstance(rel, str) and rel.strip()):
        return None, 'missing record_file'
    src_path = Path(root) / rel
    if not src_path.is_file():
        return None, 'source record file not found'
    try:
        src = json.loads(src_path.read_text())
    except json.JSONDecodeError:
        return None, 'source record is not valid JSON'
    if not isinstance(src, dict):
        return None, 'source record is not an object'

    fix = src.get('fix') if isinstance(src.get('fix'), dict) else {}
    sha = fix.get('sha') if isinstance(fix.get('sha'), str) else ''
    url = fix.get('url') if isinstance(fix.get('url'), str) else ''
    if not SHA_RE.match(sha):
        return None, 'no valid 40-hex fix SHA'
    if not url.startswith('https://'):
        return None, 'no https fix URL'
    match = FIX_URL_RE.match(url)
    if not match:
        return None, 'fix URL is not a recognized GitHub commit/blob reference'
    if sha != match.group(3):
        return None, 'fix SHA and fix URL disagree'
    slug = f'{match.group(1)}/{match.group(2)}'

    provenance = DIGESTS.get(project)
    if provenance is None:
        return None, f'no declared digest provenance for project {project}'
    evidence = src.get('evidence')
    if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], dict):
        return None, 'source record has no evidence entry'
    source_evidence = evidence[0]
    digest = source_evidence.get('sha256')
    evidence_url = source_evidence.get('url')
    observed_at = source_evidence.get('observed_at')
    if not (isinstance(digest, str) and DIGEST_RE.match(digest)):
        return None, 'source digest is not a sha256'
    if not (isinstance(evidence_url, str) and evidence_url.startswith('https://')):
        return None, 'source evidence URL is missing or not https'
    if not (isinstance(observed_at, str) and observed_at.strip()):
        return None, 'source observed_at is missing'
    if provenance['url_digest']:
        if hashlib.sha256(evidence_url.encode('utf-8')).hexdigest() != digest:
            return None, 'recorded digest does not match the declared URL-string scope'

    family = src.get('pattern_family')
    if not (isinstance(family, str) and family.strip()):
        return None, 'source record has no pattern family'
    family_status = src.get('pattern_family_status')
    cwe = src.get('cwe') if isinstance(src.get('cwe'), str) and src.get('cwe').strip() else None
    cwe_state = src.get('cwe_state') if isinstance(src.get('cwe_state'), str) and src.get('cwe_state').strip() else 'UNKNOWN'
    if cwe and project not in CWE_FROM_ADVISORY:
        # The advisory carries no CWE for this project; the study assigned it.
        cwe_state = 'ASSIGNED_BY_STUDY'
    cwe_claim_status = 'hypothesis' if cwe_state == 'ASSIGNED_BY_STUDY' else 'observed'

    if commit_meta is None:
        commit_meta = load_commit_meta()
    meta = commit_meta.get((slug, sha))
    fix_observed = meta is not None
    committed_at = _timestamp(meta.get('committer_date')) if fix_observed else None
    advisory_time = _timestamp(fix.get('committed_at'))

    record_id = f'{project}-{advisory}'
    advisory_node = f'cve:{advisory}'
    commit_node = f'commit:{sha}'
    pattern_node = f'pattern:{family}'
    known_at = observed_at
    study_url = f'https://github.com/{PACK_REPO}/blob/{PACK_REF}/{rel}'
    study_fetch_url = f'https://raw.githubusercontent.com/{PACK_REPO}/{PACK_REF}/{rel}'
    # Point at the artifact the digest actually covers: the OSV advisory JSON for
    # the OSV-digest projects, the hashed URL string for the URL-digest ones.
    evidence_url = url if provenance['url_digest'] else f'{OSV_VULN_URL}{advisory}'

    record = {
        'schema_version': '0.1.0',
        'id': record_id,
        'project': project,
        'title': f'Advisory-linked fix reference for {advisory} in {project}',
        'status': 'unknown',
        'nodes': [
            {'id': advisory_node, 'type': 'advisory', 'label': advisory,
             'attributes': {'cwe': cwe, 'cwe_state': cwe_state}},
            {'id': commit_node, 'type': 'commit', 'label': f'Fix commit {sha[:12]}',
             'attributes': {'sha': sha, 'committed_at': committed_at,
                            'repository': slug, 'url': url,
                            'source_advisory_time': advisory_time,
                            'source_advisory_time_kind': ADVISORY_TIME_KIND.get(project, 'unknown')}},
            {'id': pattern_node, 'type': 'pattern',
             'label': 'Recorded pattern family (analyst hypothesis)',
             'attributes': {'family': family,
                            'status': family_status if isinstance(family_status, str) else 'hypothesis'}},
        ],
        'edges': [
            {'id': 'edge-fixed-by', 'source': advisory_node, 'target': commit_node,
             'relation': 'fixed_by',
             'status': 'observed' if fix_observed else 'hypothesis',
             'evidence_ids': ['e-study', 'e-commit-meta'] if fix_observed else ['e-study'],
             'known_at': known_at},
            {'id': 'edge-pattern-family', 'source': pattern_node, 'target': advisory_node,
             'relation': 'affects', 'status': 'hypothesis', 'evidence_ids': ['e-study'],
             'known_at': known_at},
        ],
        'evidence': [
            {'id': 'e-commit', 'url': evidence_url, 'fetch_url': evidence_url,
             'observed_at': observed_at, 'sha256': digest, 'hash_scope': provenance['hash_scope'],
             'source_license': provenance['source_license'],
             'extractor': provenance['extractor'], 'canonicalization': provenance['canonicalization']},
            {'id': 'e-study', 'url': study_url, 'fetch_url': study_fetch_url,
             'observed_at': observed_at, 'sha256': hashlib.sha256(src_path.read_bytes()).hexdigest(),
             'hash_scope': f'bytes of {rel} in this repository at conversion time',
             'source_license': 'MIT (this repository); referenced upstream content keeps its own terms',
             'extractor': 'scripts/convert_fable_records.py',
             'canonicalization': ('raw bytes, no transformation; the URL uses the mutable '
                                  f'{PACK_REF} alias for discovery while the digest pins the '
                                  'bytes read at conversion time')},
        ],
        'claims': [
            {'id': 'claim-fix-link', 'status': 'observed',
             'text': f'The cited source record associates {advisory} with fix commit {sha} in {slug}.',
             # The URL-digest projects only hash the URL string, so that digest does
             # not evidence the association; the advisory JSON does, for the others.
             'evidence_ids': ['e-study'] if provenance['url_digest'] else ['e-study', 'e-commit']},
            {'id': 'claim-digest-scope', 'status': 'observed',
             'text': ('The digest recorded for the fix reference is the SHA-256 of the fix URL '
                      'string itself, recomputed by the converter, and does not cover commit content.'
                      if provenance['url_digest'] else
                      'The digest recorded for the fix reference covers the advisory JSON fetched '
                      f'by the upstream study from {OSV_VULN_URL}{advisory}, not the commit content; '
                      'the advisory JSON is not stored in this pack.'),
             'evidence_ids': ['e-commit']},
            {'id': 'claim-pattern-family', 'status': 'hypothesis',
             'text': ('The pattern-family classification recorded by the cited source study is an '
                      'analyst hypothesis and was not verified against the fix content.'),
             'evidence_ids': ['e-study']},
            {'id': 'claim-cwe', 'status': cwe_claim_status,
             'text': (f'The cited source study assigned {cwe} to {advisory}; the fetched advisory '
                      f'does not state it, so the classification is an analyst hypothesis '
                      f'(source cwe_state: {cwe_state}).'
                      if cwe_state == 'ASSIGNED_BY_STUDY' else
                      f'The cited source record states {cwe} for {advisory}, read from the fetched '
                      f'advisory (source cwe_state: {cwe_state}).'
                      if cwe else
                      f'The cited source record states no CWE classification for {advisory} '
                      f'(source cwe_state: {cwe_state}).'),
             'evidence_ids': ['e-study']},
        ],
        'evolution': {'outcome': 'UNKNOWN', 'coverage': 'NOT_SCANNED', 'horizon_end': None,
                      'followups': []},
        'validation': {
            'method': ('Converted offline from the cited fable-2026-06 study record and from the '
                       'cached docs/studies/fable-2026-06/commit-meta.jsonl; no network fetch and '
                       'no fix-content inspection. Advisory/fix association, digest provenance, '
                       'pattern family and CWE state are restated from the source record. '
                       'committed_at is the GitHub API committer date when commit meta is cached '
                       'for the commit and is otherwise null, with the upstream advisory '
                       'timestamp kept as source_advisory_time plus its kind.'),
            'pair_content_verified': False,
            'security_effectiveness': 'UNKNOWN',
            'digest_reproducible_from_url': provenance['url_digest'],
            'source_record': rel,
        },
        'license': {'code_redistributed': False, 'original_annotations': 'MIT'},
    }
    if fix_observed:
        meta_line = canonical_line(meta)
        record['evidence'].append(
            {'id': 'e-commit-meta', 'url': meta['api_url'], 'fetch_url': meta['api_url'],
             'observed_at': meta['fetched_at'],
             'sha256': hashlib.sha256(meta_line.encode('utf-8')).hexdigest(),
             'hash_scope': ('sha256 over the canonical JSON line cached in '
                            'docs/studies/fable-2026-06/commit-meta.jsonl for this commit '
                            '(repo, sha, committer_date, author_date, parents, files_changed, '
                            'api_url, fetched_at); it covers the cached metadata, not the commit '
                            'tree or the patch'),
             'source_license': 'GitHub REST API commit metadata; the commit keeps its upstream license',
             'extractor': 'scripts/convert_fable_records.py --fetch-commit-meta',
             'canonicalization': ('json.dumps(row, sort_keys=True, separators=(",", ":")) encoded '
                                  'UTF-8 over the cached line, excluding its newline')})
    validate(record)
    return record, None


def expected_records(path=VETTED, root=ROOT):
    """Return ({record id: record bytes}, [(label, skip reason), ...])."""
    converted, skipped = {}, []
    commit_meta = load_commit_meta()
    for lineno, row in load_vetted(path):
        record, reason = build_record(row, lineno, root=root, commit_meta=commit_meta)
        if record is None:
            skipped.append((row.get('advisory_id', f'line {lineno}'), reason))
            continue
        body = (json.dumps(record, indent=2, ensure_ascii=False) + '\n').encode()
        converted[record['id']] = body
    return converted, skipped


def commit_targets():
    """[(repo, sha), ...] for every vetted fix reference, deduplicated and sorted."""
    targets = set()
    for _, row in load_vetted():
        src = json.loads((ROOT / row['record_file']).read_text())
        fix = src.get('fix') if isinstance(src.get('fix'), dict) else {}
        match = FIX_URL_RE.match(fix.get('url') or '')
        if match and match.group(3) == fix.get('sha'):
            targets.add((f'{match.group(1)}/{match.group(2)}', match.group(3)))
    return sorted(targets)


def fetch_commit_meta(path=COMMIT_META):
    """Write the commit-metadata cache with the GitHub REST API (the only network step)."""
    if shutil.which('gh') is None:
        raise SystemExit('--fetch-commit-meta needs the gh CLI on PATH; authenticate gh and '
                         'retry, or keep using the existing cache')
    path = Path(path)
    cached = load_commit_meta(path)
    rows = []
    for repo, sha in commit_targets():
        api_url = f'https://api.github.com/repos/{repo}/commits/{sha}'
        try:
            proc = subprocess.run(['gh', 'api', f'repos/{repo}/commits/{sha}'],
                                  capture_output=True, text=True, timeout=GH_API_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise SystemExit(f'gh api repos/{repo}/commits/{sha} timed out after '
                             f'{GH_API_TIMEOUT}s; cache left unchanged')
        if proc.returncode != 0:
            raise SystemExit(f'gh api repos/{repo}/commits/{sha} failed '
                             f'({proc.stderr.strip() or proc.returncode}); cache left unchanged')
        payload = json.loads(proc.stdout)
        row = {
            'api_url': api_url,
            'author_date': payload['commit']['author']['date'],
            'committer_date': payload['commit']['committer']['date'],
            'fetched_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'files_changed': len(payload.get('files') or []),
            'parents': [parent['sha'] for parent in payload.get('parents') or []],
            'repo': repo,
            'sha': payload['sha'],
        }
        previous = cached.get((repo, sha))
        if previous and all(previous.get(key) == row[key] for key in row if key != 'fetched_at'):
            row['fetched_at'] = previous['fetched_at']  # immutable commits: keep the fetch stable
        rows.append(row)
    body = ''.join(canonical_line(row) + '\n'
                   for row in sorted(rows, key=lambda item: (item['repo'], item['sha'])))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return rows


def _orphan_records(converted, records_dir):
    """On-disk records this converter can no longer reproduce: a converter-produced
    record (has validation.source_record) whose id is absent from `converted` because
    its vetted row was removed from vetted-shas.jsonl or now skips. Hand-authored
    records without validation.source_record are never returned."""
    orphans = []
    for path in sorted(records_dir.glob('*.json')):
        if path.stem in converted:
            continue
        try:
            record = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        validation = record.get('validation') if isinstance(record, dict) else None
        if isinstance(validation, dict) and validation.get('source_record'):
            orphans.append(path)
    return orphans


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true',
                        help='verify converted records without writing')
    parser.add_argument('--fetch-commit-meta', dest='fetch_commit_meta', action='store_true',
                        help='fetch GitHub commit metadata for every vetted fix commit into '
                             'docs/studies/fable-2026-06/commit-meta.jsonl (network; run once, '
                             'then run the converter)')
    args = parser.parse_args()

    if args.fetch_commit_meta:
        rows = fetch_commit_meta()
        print(f'{len(rows)} commit-meta rows fetched into '
              f'{COMMIT_META.relative_to(ROOT)}; rerun scripts/convert_fable_records.py')
        return

    converted, skipped = expected_records()
    orphans = _orphan_records(converted, RECORDS_DIR)
    if args.check:
        if skipped or orphans:
            raise SystemExit(
                f'Converter drift: {len(skipped)} row(s) skipped, '
                f'{len(orphans)} orphaned record(s) not reproducible by this converter '
                f'({", ".join(p.name for p in orphans)}); '
                'run scripts/convert_fable_records.py to refresh')
        for record_id, body in sorted(converted.items()):
            path = RECORDS_DIR / f'{record_id}.json'
            if not path.is_file() or path.read_bytes() != body:
                raise SystemExit(f'Stale/missing converted record: {path}; '
                                 'run scripts/convert_fable_records.py')
    else:
        for path in orphans:
            path.unlink()  # its vetted row was removed or now skips: drop the stale record
        for record_id, body in sorted(converted.items()):
            (RECORDS_DIR / f'{record_id}.json').write_bytes(body)
    for label, reason in skipped:
        print(f'skip {label}: {reason}')
    with_meta = sum(1 for record in converted.values()
                    if b'"e-commit-meta"' in record)
    print(f'{len(converted)} records {"verified" if args.check else "converted"}, '
          f'{len(skipped)} skipped, {with_meta} with cached commit meta')
    if not converted:
        raise SystemExit('No record could be converted honestly; nothing to do')


if __name__ == '__main__':
    main()
