#!/usr/bin/env python3
"""Validate evidence records and build deterministic portable JSON/SQL exports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STATES = {'observed', 'hypothesis', 'validated', 'unknown'}
KINDS = {'repository', 'advisory', 'commit', 'code_version', 'pattern', 'test_observation', 'review_observation'}
RELATIONS = {'parent_of', 'fixes', 'fixed_by', 'changes', 'before', 'after', 'backport_of', 'reverts', 'supersedes', 'affects', 'supports', 'refutes'}
SCHEMA = '''PRAGMA foreign_keys=ON;
CREATE TABLE records(id TEXT PRIMARY KEY, project TEXT NOT NULL, title TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE nodes(record_id TEXT NOT NULL REFERENCES records(id), id TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL, attributes TEXT NOT NULL, PRIMARY KEY(record_id,id));
CREATE TABLE evidence(record_id TEXT NOT NULL REFERENCES records(id), id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(record_id,id));
CREATE TABLE claims(record_id TEXT NOT NULL REFERENCES records(id), id TEXT NOT NULL, status TEXT NOT NULL, text TEXT NOT NULL, evidence_ids TEXT NOT NULL, PRIMARY KEY(record_id,id));
CREATE TABLE edges(record_id TEXT NOT NULL REFERENCES records(id), id TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, relation TEXT NOT NULL, status TEXT NOT NULL, evidence_ids TEXT NOT NULL, known_at TEXT NOT NULL, PRIMARY KEY(record_id,id), FOREIGN KEY(record_id,source) REFERENCES nodes(record_id,id), FOREIGN KEY(record_id,target) REFERENCES nodes(record_id,id));
CREATE INDEX edge_source ON edges(record_id,source);
CREATE INDEX edge_target ON edges(record_id,target);
CREATE VIRTUAL TABLE record_fts USING fts5(id UNINDEXED, text);
'''


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def validate(record):
    required = {'schema_version', 'id', 'project', 'title', 'status', 'nodes', 'edges', 'evidence', 'claims', 'evolution', 'validation', 'license'}
    if not isinstance(record, dict) or not required <= record.keys():
        raise ValueError('Missing required record fields')
    if record['schema_version'] != '0.1.0' or not re.fullmatch(r'[A-Za-z0-9_.-]+', record['id']):
        raise ValueError('Invalid version or record id')
    if record['status'] not in STATES:
        raise ValueError('Invalid record status')
    for key in ('nodes', 'edges', 'evidence', 'claims'):
        if not isinstance(record[key], list):
            raise ValueError(f'{key} must be an array')
        ids = [x['id'] for x in record[key]]
        if len(ids) != len(set(ids)):
            raise ValueError(f'Duplicate {key} ids')
    if not record['nodes'] or not record['evidence']:
        raise ValueError('A record needs nodes and source evidence')
    node_ids = {n['id'] for n in record['nodes']}
    evidence_ids = {e['id'] for e in record['evidence']}
    for node in record['nodes']:
        if node['type'] not in KINDS or not isinstance(node['label'], str) or not isinstance(node['attributes'], dict):
            raise ValueError('Invalid node')
    for item in record['evidence']:
        if not re.fullmatch(r'[0-9a-f]{64}', item['sha256']) or not item['url'].startswith('https://'):
            raise ValueError('Invalid source hash or URL')
        for field in ('observed_at', 'hash_scope', 'source_license', 'extractor'):
            if not isinstance(item.get(field), str) or not item[field]:
                raise ValueError(f'Missing evidence {field}')
    for item in record['claims'] + record['edges']:
        if item['status'] not in STATES or not item['evidence_ids'] or not set(item['evidence_ids']) <= evidence_ids:
            raise ValueError('Unsupported claim/edge or dangling evidence')
    for claim in record['claims']:
        if not isinstance(claim.get('text'), str) or not claim['text']:
            raise ValueError('Missing claim text')
    for edge in record['edges']:
        if edge['source'] not in node_ids or edge['target'] not in node_ids:
            raise ValueError('Dangling edge endpoint')
        if edge['relation'] not in RELATIONS or not edge.get('known_at'):
            raise ValueError('Invalid relation or missing known time')
    if record['evolution'].get('outcome') not in {'UNKNOWN', 'REFINED', 'REVERTED', 'TEST_SUPPORTED', 'DISPUTED'}:
        raise ValueError('Invalid evolution outcome')
    if record['evolution']['outcome'] != 'UNKNOWN' and not record['evolution'].get('followups'):
        raise ValueError('Evolution conclusion requires observations')


def load_records(directory=ROOT / 'docs/memory/records'):
    records = []
    for path in sorted(directory.glob('*.json')):
        record = json.loads(path.read_text())
        validate(record)
        if path.stem != record['id']:
            raise ValueError('Filename/id mismatch')
        records.append(record)
    ids = [r['id'] for r in records]
    if len(ids) != len(set(ids)) or not ids:
        raise ValueError('Empty pack or duplicate record ids')
    return records


def build_sql(records):
    db = sqlite3.connect(':memory:')
    try:
        db.executescript(SCHEMA)
        for r in records:
            validate(r)
            rid = r['id']
            db.execute('INSERT INTO records VALUES (?,?,?,?)', (rid, r['project'], r['title'], canonical(r)))
            for n in r['nodes']:
                db.execute('INSERT INTO nodes VALUES (?,?,?,?,?)', (rid, n['id'], n['type'], n['label'], canonical(n['attributes'])))
            for e in r['evidence']:
                db.execute('INSERT INTO evidence VALUES (?,?,?)', (rid, e['id'], canonical(e)))
            for c in r['claims']:
                db.execute('INSERT INTO claims VALUES (?,?,?,?,?)', (rid, c['id'], c['status'], c['text'], canonical(c['evidence_ids'])))
            for e in r['edges']:
                db.execute('INSERT INTO edges VALUES (?,?,?,?,?,?,?,?)', (rid, e['id'], e['source'], e['target'], e['relation'], e['status'], canonical(e['evidence_ids']), e['known_at']))
            text = ' '.join([r['title']] + [n['label'] for n in r['nodes']] + [c['text'] for c in r['claims']])
            db.execute('INSERT INTO record_fts VALUES (?,?)', (rid, text))
        db.commit()
        # iterdump for FTS virtual tables requires writable_schema on restoration.
        # Export ordinary rows and recreate the virtual table explicitly instead.
        lines = ['PRAGMA foreign_keys=ON;', 'BEGIN;', SCHEMA]
        tables = ('records', 'nodes', 'evidence', 'claims', 'edges', 'record_fts')
        for table in tables:
            order = 'id' if table in {'records', 'record_fts'} else 'record_id,id'
            for row in db.execute(f'SELECT * FROM {table} ORDER BY {order}'):
                values = ["'" + str(v).replace("'", "''") + "'" for v in row]
                lines.append(f'INSERT INTO {table} VALUES ({",".join(values)});')
        lines.append('COMMIT;')
        return '\n'.join(lines) + '\n'
    finally:
        db.close()


def artifacts(records):
    files = {'kernel-security-memory.sql': build_sql(records).encode()}
    for r in records:
        files[f'records/{r["id"]}.json'] = (json.dumps(r, indent=2, ensure_ascii=False) + '\n').encode()
    manifest = {'schema_version': '0.1.0', 'pack_id': 'kernel-security-memory-bootstrap-v0', 'project': 'linux', 'record_count': len(records), 'source_scope': 'source-linked seed; not full history', 'vectors': 'NOT_BUILT', 'files': [{'path': p, 'sha256': hashlib.sha256(b).hexdigest(), 'bytes': len(b)} for p, b in sorted(files.items())]}
    files['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    records = load_records()
    outputs = artifacts(records)
    memory = ROOT / 'docs/memory'
    for name, body in outputs.items():
        path = memory / name
        if args.check:
            if not path.exists() or path.read_bytes() != body:
                raise SystemExit(f'Stale/missing export: {name}; run scripts/build_pack.py')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
    # Ensure the exported SQL restores with FK checking into an independent DB.
    with tempfile.TemporaryDirectory() as td:
        db = sqlite3.connect(str(Path(td) / 'pack.sqlite3'))
        try:
            db.executescript(outputs['kernel-security-memory.sql'].decode())
            if db.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('Invalid SQL foreign keys')
        finally:
            db.close()
    print(f'{len(records)} records validated; deterministic JSON/SQL pack {"checked" if args.check else "built"}')


if __name__ == '__main__':
    main()
