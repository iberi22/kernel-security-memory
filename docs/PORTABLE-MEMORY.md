# Portable memory contract

## HTTP without a server

GitHub raw URLs serve public JSON from `docs/memory/`. Pin an actual repository commit SHA in production; the `main` alias is mutable discovery only. GitHub Pages can serve the same directory. Neither endpoint executes SQL, vectors or agent workflows.

```
https://raw.githubusercontent.com/iberi22/kernel-security-memory/main/docs/memory/manifest.json
https://iberi22.github.io/kernel-security-memory/memory/manifest.json
```

Manifest: schema version, pack ID, project, record count, source scope, and `{path, sha256, bytes}` entries. Download a manifest from a trusted/pinned revision and verify each object before parsing. Hashes give integrity, not publisher authentication if both manifest and data come from an untrusted mutable source. Paths must remain inside the memory pack.

Records follow `schemas/memory-record.schema.json`. Edges and claims reference evidence within the record. UNKNOWN is a valid outcome. Pack-level splits and snapshot metadata are added with the miner. HTTP provides GET data; dynamic `/search` is not promised.

## SQL text snapshot

`kernel-security-memory.sql` creates normalized record, node, evidence, claim and edge tables plus FTS5. Restore a trusted pack into a NEW SQLite file:

```python
import pathlib, sqlite3
sql = pathlib.Path('docs/memory/kernel-security-memory.sql').read_text()
with sqlite3.connect('kernel-memory.sqlite3') as db:
    db.executescript(sql)
```

Only execute the export from a trusted pinned revision; arbitrary downloaded SQL is executable input. Prefer rebuilding from validated JSON when accepting untrusted publishers. Runtime `.sqlite3` files stay outside Git. Never restore this SQL into Xavier's existing memory DB.

Open the resulting database with `mode=ro` and close it after use. Independent pack readers can fan out and fuse ranked results without altering Xavier's schema. SQLite `ATTACH`/`DETACH` can also work on a consumer-owned connection, but this is not an implemented Xavier API. Closing the reader disconnects the local pack; it does not undo earlier copies imported into Xavier.

## Xavier integration stages

1. Agent fetches JSON evidence over HTTP and includes cited facts in its audit context. Works without modifying Xavier.
2. Planned optional adapter queries a read-only pack alongside Xavier and merges rankings. Native attach/detach is NOT implemented by the bootstrap.
3. Optional import must use a pack-specific namespace and import receipt with exact record IDs/revision/hash; removing only those IDs makes the import reversible. Do not claim import deletion exists until tested against Xavier's live API.

Vector artifacts are optional: model ID/revision, dimension, dtype, normalization, source-content hash and build version are mandatory. No compatibility with Xavier's embedding space is assumed from equal dimensions. Consumers may rebuild embeddings locally or operate lexically.

## Hosting limits and freshness

GitHub Pages is static and subject to [usage limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits). Large shard sets/derived indexes belong in release assets or a separately chosen store. No guarantee of unlimited free bandwidth, permanent availability or complete security coverage. Consumers cache pinned revisions and inspect pack freshness explicitly.
