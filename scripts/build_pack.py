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


def fields(value, required, label):
    if not isinstance(value, dict) or not set(required) <= value.keys():
        raise ValueError(f'Missing/invalid {label} fields')


def text(value):
    return isinstance(value, str) and bool(value.strip())


def references(value, known):
    return (isinstance(value, list) and bool(value) and all(text(x) for x in value)
            and len(value) == len(set(value)) and set(value) <= known)


def validate(record):
    required = {'schema_version', 'id', 'project', 'title', 'status', 'nodes', 'edges', 'evidence', 'claims', 'evolution', 'validation', 'license'}
    fields(record, required, 'record')
    if record['schema_version'] != '0.1.0' or not text(record['id']) or not re.fullmatch(r'[A-Za-z0-9_.-]+', record['id']):
        raise ValueError('Invalid version or record id')
    if not text(record['project']) or not text(record['title']) or record['status'] not in STATES:
        raise ValueError('Invalid record text/status')
    for key in ('nodes', 'edges', 'evidence', 'claims'):
        if not isinstance(record[key], list):
            raise ValueError(f'{key} must be an array')
        for item in record[key]:
            fields(item, ['id'], key)
            if not text(item['id']):
                raise ValueError(f'Invalid {key} id')
        ids = [x['id'] for x in record[key]]
        if len(ids) != len(set(ids)):
            raise ValueError(f'Duplicate {key} ids')
    if not record['nodes'] or not record['evidence']:
        raise ValueError('A record needs nodes and source evidence')
    nodes = {n['id']: n for n in record['nodes']}
    evidence_ids = {e['id'] for e in record['evidence']}
    for node in record['nodes']:
        fields(node, ['type', 'label', 'attributes'], 'node')
        if node['type'] not in KINDS or not text(node['label']) or not isinstance(node['attributes'], dict):
            raise ValueError('Invalid node')
    for item in record['evidence']:
        fields(item, ['sha256', 'url', 'fetch_url', 'observed_at', 'hash_scope', 'source_license', 'extractor', 'canonicalization'], 'evidence')
        if not isinstance(item['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
            raise ValueError('Invalid source hash')
        for field in ('url', 'fetch_url'):
            if not text(item[field]) or not item[field].startswith('https://'):
                raise ValueError('Invalid source URL')
        for field in ('observed_at', 'hash_scope', 'source_license', 'extractor', 'canonicalization'):
            if not text(item[field]):
                raise ValueError(f'Missing evidence {field}')
    for item in record['claims'] + record['edges']:
        fields(item, ['status', 'evidence_ids'], 'claim/edge')
        if item['status'] not in STATES or not references(item['evidence_ids'], evidence_ids):
            raise ValueError('Unsupported claim/edge or dangling evidence')
    for claim in record['claims']:
        if not text(claim.get('text')):
            raise ValueError('Missing claim text')
    for edge in record['edges']:
        fields(edge, ['source', 'target', 'relation', 'known_at'], 'edge')
        if not text(edge['source']) or not text(edge['target']) or edge['source'] not in nodes or edge['target'] not in nodes:
            raise ValueError('Dangling edge endpoint')
        if edge['relation'] not in RELATIONS or not text(edge['known_at']):
            raise ValueError('Invalid relation or missing known time')
    evolution = record['evolution']
    fields(evolution, ['outcome', 'coverage', 'horizon_end', 'followups'], 'evolution')
    if not text(evolution['coverage']) or (evolution['horizon_end'] is not None and not text(evolution['horizon_end'])) or not isinstance(evolution['followups'], list):
        raise ValueError('Invalid evolution coverage/horizon/observations')
    outcome = evolution['outcome']
    if outcome not in {'UNKNOWN', 'REFINED', 'REVERTED', 'TEST_SUPPORTED', 'DISPUTED'}:
        raise ValueError('Invalid evolution outcome')
    kinds = set()
    for obs in evolution['followups']:
        fields(obs, ['kind', 'node_id', 'evidence_ids'], 'follow-up observation')
        if obs['kind'] not in {'test_result', 'revert', 'fix_followup', 'dispute'} or not text(obs['node_id']) or obs['node_id'] not in nodes or not references(obs['evidence_ids'], evidence_ids):
            raise ValueError('Unsubstantiated follow-up observation')
        node = nodes[obs['node_id']]
        if obs['kind'] == 'test_result':
            attrs = node['attributes']
            if node['type'] != 'test_observation' or attrs.get('outcome') != 'PASS' or not all(text(attrs.get(k)) for k in ['command', 'revision', 'environment']):
                raise ValueError('Test support needs a sourced passing test observation')
        elif obs['kind'] in {'revert', 'fix_followup'}:
            relations = {'reverts'} if obs['kind'] == 'revert' else {'fixes', 'supersedes'}
            if node['type'] != 'commit' or not any(e['source'] == obs['node_id'] and e['relation'] in relations and e['status'] in {'observed', 'validated'} and set(e['evidence_ids']) & set(obs['evidence_ids']) for e in record['edges']):
                raise ValueError('Patch evolution needs a source-supported typed edge')
        elif node['type'] != 'review_observation':
            raise ValueError('Dispute needs a review observation')
        kinds.add(obs['kind'])
    needs = {'TEST_SUPPORTED': 'test_result', 'REVERTED': 'revert', 'REFINED': 'fix_followup', 'DISPUTED': 'dispute'}
    if outcome in needs and needs[outcome] not in kinds:
        raise ValueError('Evolution conclusion requires the corresponding observation')
    if not isinstance(record['validation'], dict) or not isinstance(record['license'], dict):
        raise ValueError('Validation and license must be objects')


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


def pack_projects(records):
    """Sorted distinct projects in the pack; a single-project pack keeps one name."""
    projects = sorted({r['project'] for r in records})
    return projects[0] if len(projects) == 1 else ','.join(projects)


def source_scope(records):
    """What the pack actually covers, derived from the records themselves.

    The bootstrap seed was fetched reference by reference; the rest of the pack is
    the vetted fable-2026-06 slice converted offline from cited study records, so
    the manifest must not claim full upstream history.
    """
    seed = [r for r in records if not r['validation'].get('source_record')]
    vetted = [r for r in records if r['validation'].get('source_record')]
    return (f'fetched seed ({len(seed)} record) plus the vetted fable-2026-06 slice '
            f'({len(vetted)} records converted offline from cited study records); '
            'not the full history of any upstream project')


def artifacts(records):
    files = {'kernel-security-memory.sql': build_sql(records).encode()}
    for r in records:
        files[f'records/{r["id"]}.json'] = (json.dumps(r, indent=2, ensure_ascii=False) + '\n').encode()
    projects = sorted({r['project'] for r in records})
    manifest = {'schema_version': '0.1.0', 'pack_id': 'kernel-security-memory-bootstrap-v0', 'project': pack_projects(records), 'projects': projects, 'record_count': len(records), 'source_scope': source_scope(records), 'vectors': 'NOT_BUILT', 'files': [{'path': p, 'sha256': hashlib.sha256(b).hexdigest(), 'bytes': len(b)} for p, b in sorted(files.items())]}
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
