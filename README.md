# Kernel Security Memory

Public, portable, evidence-linked memory of Linux security fixes: what changed, why, and what later evidence says about the fix.

**Bootstrap stage.** One real, source-linked seed case exercises JSON/SQL packaging. It is not a complete kernel scan or a validated vulnerability detector. The seven-method comparison is research; empirical ranking is pending a remote experiment.

## Read first

- [Requirements](docs/REQUIREMENTS.md) and [architecture](docs/ARCHITECTURE.md)
- [Seven retrieval approaches](docs/research/RAG-COMPARISON.md)
- [Linux acquisition and patch evolution](docs/LINUX-MINING.md)
- [Evaluation](experiments/PROTOCOL.md) and [provisional ADR](docs/adr/001-retrieval.md)
- [HTTP and SQL memory contract](docs/PORTABLE-MEMORY.md)
- [Current status](docs/STATUS.md) and [roadmap](docs/ROADMAP.md)

## Free static memory distribution

GitHub serves immutable JSON by repository revision. Start with `docs/memory/manifest.json`, verify SHA-256, then fetch referenced records. GitHub Pages also serves these files when enabled. Static hosting serves data; query execution and embeddings run in the consuming agent or its local runtime.

A generated `docs/memory/kernel-security-memory.sql` reconstructs an independent SQLite evidence graph with FTS5. A consumer can open the generated SQLite file read-only and close it after the audit. Runtime database files are not committed. Xavier can consume JSON over HTTP; a reversible native Xavier mount is a planned adapter, not an existing integration promised by this repository.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build_pack.py --check
python3 scripts/query_pack.py --query 'interval garbage collection' --limit 5
```

No third-party dependencies, model downloads or kernel clone are required for these commands. Optional vector indexes must declare model, dimensions and source-content hashes; the bootstrap does not contain embeddings.

## Licensing

Original tooling/docs are MIT. Upstream code, advisories and datasets retain their own terms. Code references do not relicense their targets. See [data policy](docs/DATA-POLICY.md).
