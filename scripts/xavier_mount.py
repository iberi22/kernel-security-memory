#!/usr/bin/env python3
"""Reversible HTTP import of verified packs; no live database access (stdlib only)."""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
from pathlib import Path

from pack_to_xavier import _opener, _url_allowed, mem_body, verify_pack, TIMEOUT
import urllib.request


def request(base, token, method, suffix='', body=None):
    req = urllib.request.Request(
        base + '/v1/memories' + suffix, method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with _opener().open(req, timeout=TIMEOUT) as response:
            if not 200 <= response.status < 300:
                raise ValueError('Unexpected HTTP response')
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        # Never expose response bodies, URLs, reason strings or headers.
        code = exc.code
        exc.close()
        if method == 'DELETE' and code == 404:
            return {}
        raise ValueError(f'HTTP {code}: {method} failed') from None
    except (urllib.error.URLError, OSError):
        raise ValueError(f'Network error: {method} failed') from None


def mounted(base, token, namespace):
    """Read every page, then enforce the namespace locally too."""
    found = {}
    offset, limit = 0, 100
    while True:
        query = urllib.parse.urlencode({'prefix': namespace + '/',
                                        'offset': offset, 'limit': limit})
        page = request(base, token, 'GET', '?' + query)
        if not isinstance(page, dict) or not isinstance(page.get('memories'), list):
            raise ValueError('Invalid memories listing')
        rows = page['memories']
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('path'), str):
                raise ValueError('Invalid memory in listing')
            if row['path'].startswith(namespace + '/'):
                identity = row.get('id', row['path'])
                if not isinstance(identity, str) or not identity:
                    raise ValueError('Invalid memory ID')
                if row['path'] in found:
                    raise ValueError('Repeated memory in listing')
                found[row['path']] = identity
        offset += len(rows)
        total = page.get('total')
        if total is not None:
            if type(total) is not int or total < offset:
                raise ValueError('Invalid listing total')
            if offset == total:
                break
            if not rows:
                raise ValueError('Incomplete memories listing')
        elif len(rows) < limit:
            if page.get('next') or page.get('next_cursor') or page.get('has_more'):
                raise ValueError('Unsupported listing pagination')
            break
        if offset > 1000000:
            raise ValueError('Listing exceeds safety bound')
    return found


def save_receipt(path, receipt):
    # Atomic replacement; persist the recovery plan before the first mutation.
    temporary = Path(str(path) + '.tmp')
    temporary.write_text(json.dumps(receipt, indent=2) + '\n')
    temporary.replace(path)


def validate_receipt(receipt):
    if (receipt.get('schema_version') != 1 or
            not isinstance(receipt.get('pack_id'), str) or
            not isinstance(receipt.get('revision'), str) or not receipt['revision'] or
            not re.fullmatch(r'[0-9a-f]{64}', receipt.get('manifest_sha256', ''))):
        raise ValueError('Invalid receipt identity')
    expected = namespace_for(receipt['pack_id'], receipt['manifest_sha256'])
    if receipt.get('namespace') != expected:
        raise ValueError('Invalid receipt namespace')
    records = receipt.get('records')
    if not isinstance(records, list) or not records:
        raise ValueError('Invalid receipt records')
    paths = set()
    for record in records:
        rid = record.get('record_id')
        if not isinstance(rid, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', rid):
            raise ValueError('Invalid receipt record ID')
        if record.get('path') != expected + '/' + rid or record['path'] in paths:
            raise ValueError('Receipt path outside namespace or duplicated')
        if not isinstance(record.get('id'), str) or not record['id']:
            raise ValueError('Invalid receipt memory ID')
        paths.add(record['path'])
    return receipt


def namespace_for(pack_id, digest):
    if not isinstance(pack_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', pack_id):
        raise ValueError('Invalid pack ID')
    return 'ksm-pack/' + pack_id + '/' + digest


def run(args):
    records = None
    if args.action != 'connect' and args.receipt:
        receipt = validate_receipt(json.loads(Path(args.receipt).read_text()))
    else:
        if not args.source:
            raise ValueError('--source is required without a receipt')
        digest = hashlib.sha256((Path(args.source) / 'manifest.json').read_bytes()).hexdigest()
        if args.manifest_sha256 and args.manifest_sha256 != digest:
            raise ValueError('Manifest hash mismatch')
        manifest, records = verify_pack(args.source, digest)
        namespace = namespace_for(manifest.get('pack_id'), digest)
        receipt = {'schema_version': 1, 'pack_id': manifest['pack_id'],
                   'revision': args.revision or manifest.get('revision') or 'UNKNOWN',
                   'manifest_sha256': digest, 'namespace': namespace,
                   'records': [{'record_id': r['id'], 'path': namespace + '/' + r['id'],
                                'id': namespace + '/' + r['id']} for r in records]}
        validate_receipt(receipt)
    if args.action == 'connect' and (not args.receipt or receipt['revision'] == 'UNKNOWN'):
        raise ValueError('connect requires --receipt and --revision (or manifest revision)')
    namespace = receipt['namespace']
    if args.dry_run:
        return {'dry_run': True, 'action': args.action, 'namespace': namespace,
                'record_ids': [r['record_id'] for r in receipt['records']]}
    base = os.environ.get('XAVIER_URL', '')
    parts = urllib.parse.urlsplit(base)
    if (not _url_allowed(base) or parts.username or parts.password or
            parts.query or parts.fragment):
        raise ValueError('XAVIER_URL requires HTTPS or loopback HTTP without credentials/query/fragment')
    token = os.environ.get('XAVIER_TOKEN', '')
    if not token:
        raise ValueError('XAVIER_TOKEN is required in the environment')
    base = base.rstrip('/')
    existing = mounted(base, token, namespace)
    if args.action == 'status':
        return {'namespace': namespace, 'record_ids': sorted(existing.values()),
                'paths': sorted(existing)}
    if args.action == 'connect':
        if Path(args.receipt).exists():
            raise ValueError('Receipt already exists; disconnect or choose a new receipt')
        if any(r['path'] in existing for r in receipt['records']):
            raise ValueError('Target memories already exist; refusing overwrite')
        save_receipt(args.receipt, receipt)
        for record, entry in zip(records, receipt['records']):
            body = mem_body(namespace, record)
            body['metadata']['import_receipt'] = {
                key: receipt[key] for key in ('pack_id', 'revision', 'manifest_sha256', 'namespace')}
            response = request(base, token, 'POST', body=body)
            if isinstance(response, dict) and isinstance(response.get('id'), str):
                entry['id'] = response['id']
            save_receipt(args.receipt, receipt)
        actual = mounted(base, token, namespace)
        if any(r['path'] not in actual for r in receipt['records']):
            raise ValueError('Import verification failed; retain receipt for recovery')
        for entry in receipt['records']:
            entry['id'] = actual[entry['path']]
        save_receipt(args.receipt, receipt)
    else:
        for entry in receipt['records']:
            # Resolve by exact receipt path, so an arbitrary receipt ID can never
            # direct deletion at an unrelated memory.
            if entry['path'] in existing:
                identity = existing[entry['path']]
                request(base, token, 'DELETE', '/' + urllib.parse.quote(identity, safe=''))
        remaining = mounted(base, token, namespace)
        if any(r['path'] in remaining for r in receipt['records']):
            raise ValueError('Disconnect verification failed: mounted records remain')
    return {'action': args.action, 'namespace': namespace,
            'record_ids': [r['id'] for r in receipt['records']], 'verified': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('connect', 'status', 'disconnect'))
    parser.add_argument('--source')
    parser.add_argument('--receipt')
    parser.add_argument('--revision', help='Pinned source revision recorded in the import receipt')
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = run(args)
        output = json.dumps(result, indent=2)
        for key in ('XAVIER_URL', 'XAVIER_TOKEN'):
            secret = os.environ.get(key)
            if secret:
                output = output.replace(secret, '<redacted>')
        print(output)
    except Exception as exc:
        # Only our controlled ValueError messages may reach logs. JSON/parser,
        # filesystem and transport errors may contain server data or secrets.
        message = str(exc) if type(exc) is ValueError else 'Mount operation failed'
        for key in ('XAVIER_URL', 'XAVIER_TOKEN'):
            secret = os.environ.get(key)
            if secret:
                message = message.replace(secret, '<redacted>')
        raise SystemExit('Error: ' + message) from None


if __name__ == '__main__':
    main()
