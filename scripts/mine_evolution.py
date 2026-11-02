#!/usr/bin/env python3
"""Mine bounded patch evolution from local Git objects; never fetch or execute hooks.

Same-path edits and unlinked revert/backport messages remain hypotheses. Only an
explicit reference to the supplied fix can establish a revert/backport outcome.
No amount of quiet history establishes FIXED_STABLE.
"""
import argparse
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from build_pack import validate

SHA = re.compile(r'^[0-9a-fA-F]{40}$')


def git(repo, *args):
    # Ignore inherited repository redirection; missing partial-clone objects fail
    # locally instead of triggering Git's automatic promisor fetch.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    result = subprocess.run(
        ['git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
         '-c', 'protocol.allow=never', '-c', 'diff.external=', '-C', str(repo), *args],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError(f'git {args[0]} failed: {result.stderr.decode(errors="replace").strip()}')
    return result.stdout


def mine_evolution(repo, fixes, *, repository_url, project='linux', refs=None,
                   until=None, observed_at=None):
    """Return complete memory records for fixes, scoped to pinned local ref tips.

    The window starts at the fix committer time, ends at ``until`` (inclusive
    ISO date), and excludes the fix and its ancestors. COMPLETE_AT_HORIZON means
    complete local path-history enumeration only, never complete security review.
    ``horizon_end`` is the last observed commit date, not the requested cutoff.
    """
    if not repository_url.startswith('https://'):
        raise ValueError('repository_url must be an HTTPS provenance URL (never fetched)')
    if until is not None:
        date.fromisoformat(until)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', project):
        raise ValueError('project must be a record-id-safe name')
    observed_at = observed_at or datetime.now(timezone.utc).isoformat()
    fixes = list(fixes)
    if not all(SHA.fullmatch(s) for s in fixes):
        raise ValueError('fixes must be full 40-hex commit SHAs')
    tips = sorted({git(repo, 'rev-parse', '--verify', '--end-of-options',
                       ref + '^{commit}').decode().strip() for ref in (refs or ['HEAD'])})
    shallow = git(repo, 'rev-parse', '--is-shallow-repository').strip() == b'true'
    config = git(repo, 'config', '--local', '--list').decode(errors='replace').lower()
    partial = 'promisor=true' in config or 'extensions.partialclone=' in config
    records = []
    for supplied in fixes:
        fix = git(repo, 'rev-parse', '--verify', supplied + '^{commit}').decode().strip()
        fix_time = git(repo, 'show', '-s', '--format=%cI', fix).decode().strip()
        cutoff = until or max(git(repo, 'show', '-s', '--format=%cI', tip)
                             .decode().strip()[:10] for tip in tips)
        if cutoff < fix_time[:10]:
            raise ValueError('observation cutoff precedes fix')
        files = sorted(set(p.decode(errors='surrogateescape') for p in git(
            repo, 'diff-tree', '--root', '-m', '--no-commit-id', '--name-only',
            '-r', '-z', fix).split(b'\0') if p))
        record = {
            'schema_version': '0.1.0', 'id': f'{project}-evolution-{fix}',
            'project': project, 'title': f'Local patch evolution for {fix}',
            'status': 'unknown', 'nodes': [], 'edges': [], 'claims': [], 'evidence': [],
            'evolution': {'outcome': 'UNKNOWN', 'coverage': 'PARTIAL',
                          'horizon_end': fix_time[:10], 'followups': []},
            'validation': {'security_effectiveness': 'UNKNOWN', 'refs': tips,
                           'window_start': fix_time, 'requested_horizon': cutoff,
                           'scope': 'local reachable path history; no reviews or tests',
                           'shallow': shallow, 'partial_clone': partial,
                           'errors': [], 'commands': []},
            'license': {'original': 'MIT', 'upstream': 'Referenced upstream content retains its license'},
        }

        def node(sha, paths):
            nid = 'commit-' + sha
            if any(n['id'] == nid for n in record['nodes']):
                return nid, 'e-' + sha
            raw = git(repo, 'cat-file', 'commit', sha)
            eid = 'e-' + sha
            url = repository_url.rstrip('/') + '/commit/' + sha
            record['nodes'].append({'id': nid, 'type': 'commit', 'label': sha,
                                    'attributes': {'sha': sha, 'files': paths}})
            record['evidence'].append({
                'id': eid, 'url': url, 'fetch_url': url, 'observed_at': observed_at,
                'sha256': hashlib.sha256(raw).hexdigest(),
                'hash_scope': f'raw git cat-file commit {sha} bytes; files: {json.dumps(paths)}',
                'source_license': 'Upstream repository license; pointers and hashes only',
                'extractor': 'scripts/mine_evolution.py',
                'canonicalization': 'Raw local Git commit object payload; URL is discovery only',
                'commit_sha': sha, 'files': paths})
            return nid, eid

        fix_node, _ = node(fix, files)
        excluded = set(git(repo, 'rev-list', fix).decode().splitlines())
        candidates = set()
        for path in files:
            for tip in tips:
                args = ['log', '--follow', '--format=%H', tip, '--', ':(literal)' + path]
                record['validation']['commands'].append(['git', *args])
                try:
                    candidates.update(git(repo, *args).decode().splitlines())
                except ValueError as exc:
                    record['validation']['errors'].append(str(exc))
        observed = []
        for sha in sorted(candidates - excluded):
            stamp = git(repo, 'show', '-s', '--format=%cI', sha).decode().strip()
            if (datetime.fromisoformat(stamp) < datetime.fromisoformat(fix_time)
                    or stamp[:10] > cutoff):
                continue
            changed = set(p.decode(errors='surrogateescape') for p in git(
                repo, 'diff-tree', '--root', '-m', '--no-commit-id', '--name-only',
                '-r', '-z', sha).split(b'\0') if p)
            common = sorted(changed.intersection(files))
            if not common:
                continue
            nid, eid = node(sha, common)
            message = git(repo, 'show', '-s', '--format=%B', sha).decode(errors='replace')
            # Accept unambiguous abbreviated object IDs only in explicit trailers.
            def targets(pattern):
                for match in re.finditer(pattern, message, re.I | re.M):
                    token = match.group(1)
                    if len(token) < 7 or not fix.startswith(token.lower()):
                        continue
                    try:
                        if git(repo, 'rev-parse', '--verify', token + '^{commit}').decode().strip() == fix:
                            return True
                    except ValueError:
                        pass
                return False

            revert = targets(r'^\s*This reverts commit\s+([0-9a-f]{7,40})\b')
            backport = targets(r'^\s*(?:\(?cherry[ -]picked from commit|Backport(?: of)?(?: commit)?[: ]+)\s*([0-9a-f]{7,40})\b')
            kind = 'revert' if revert else 'backport' if backport else 'path_followup'
            signal = ('revert' if re.search(r'\brevert\b', message, re.I) else
                      'backport' if re.search(r'\bbackport\b|cherry[ -]pick', message, re.I) else 'same_path')
            status = 'observed' if revert or backport else 'hypothesis'
            relation = 'reverts' if revert else 'backport_of' if backport else 'changes'
            record['edges'].append({'id': 'edge-' + sha, 'source': nid, 'target': fix_node,
                                    'relation': relation, 'status': status,
                                    'known_at': observed_at, 'evidence_ids': [eid]})
            record['claims'].append({'id': 'claim-' + sha, 'status': status,
                                     'text': f'Commit {sha} has {kind} evidence relative to {fix} in files {json.dumps(common)}; message signal: {signal}. This does not establish security effectiveness.',
                                     'evidence_ids': [eid]})
            record['evolution']['followups'].append({'kind': kind, 'node_id': nid,
                                                     'evidence_ids': [eid], 'files': common,
                                                     'message_signal': signal})
            observed.append((stamp, kind))
        if observed:
            record['evolution']['horizon_end'] = max([fix_time[:10]] + [s[:10] for s, _ in observed])
        kinds = {k for _, k in observed}
        record['evolution']['outcome'] = ('REVERTED' if 'revert' in kinds else
                                           'BACKPORTED' if 'backport' in kinds else 'UNKNOWN')
        # --follow is a path heuristic: renames, merges and missing objects leave
        # uncertainty even in a non-shallow repository. Never overstate coverage.
        record['evolution']['coverage'] = 'PARTIAL' if files else 'UNKNOWN'
        validate(record)
        records.append(record)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repo', type=Path)
    parser.add_argument('fixes', nargs='+', help='Full fix commit SHAs')
    parser.add_argument('--repository-url', required=True, help='HTTPS provenance base; never fetched')
    parser.add_argument('--project', default='linux')
    parser.add_argument('--ref', action='append', dest='refs', help='Local ref in scope (default HEAD)')
    parser.add_argument('--until', help='Inclusive ISO observation cutoff date')
    parser.add_argument('--observed-at', help='Capture time for reproducible exports')
    args = parser.parse_args()
    try:
        records = mine_evolution(args.repo, args.fixes, repository_url=args.repository_url,
                                 project=args.project, refs=args.refs, until=args.until,
                                 observed_at=args.observed_at)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(records, indent=2, ensure_ascii=True))


if __name__ == '__main__':
    main()
