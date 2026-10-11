# Kernel Security Memory

Public, portable, evidence-linked memory of Linux security fixes: what changed, why, and what later evidence says about the fix.

It holds 18,434 CVEs from 12 projects, 17,744 with the fix commit, from official sources (Linux kernel CNA, curl and OpenSSL advisories, OSV, NVD, CISA Vulnrichment); see [status](docs/STATUS.md). No language model is used anywhere in the data.

## Vulnerability Atlas

A static UI (GitHub Pages) to browse vulnerabilities by CWE group, CWE, project and CVE: what the fix changed, related CVEs, and the before/after code of each changed function fetched live from GitHub (KSM stores no source code). Design: [VULN-ATLAS.md](docs/design/VULN-ATLAS.md).

The `ksm` CLI uses the same data locally:

```sh
pipx install git+https://github.com/iberi22/kernel-security-memory   # or: uv tool install git+...
ksm update                      # download the data bundle published with the site
ksm stats
ksm show CVE-2016-8619          # metadata, fix commits, what the fix changed, related CVEs
ksm search read_data
ksm audit path/to/code          # regex rules of the defensive auditor
ksm scan path/to/code           # structural match against fix fingerprints
```

`ksm scan` needs Xavier's `code-graph` with the `fingerprint` subcommand (`KSM_CODE_GRAPH` or `PATH`): `cargo install --locked --git https://github.com/iberi22/xavier --rev <XAVIER_REV from .github/workflows/fingerprints.yml> code-graph`. It reports functions that look more like the vulnerable version of a known fix than the fixed one, and calls missing a check that the fix added, with file, line and variable. Findings are hypotheses to review. On curl 7.50.0, 11 of 12 findings with score >= 0.9 matched fixes released after that version; matching across different projects is not measured yet.

Prebuilt Linux binary in the [releases page](https://github.com/iberi22/kernel-security-memory/releases) (`code-graph-<rev>` tags), verify with the .sha256 file.

The weekly `fingerprints` workflow fingerprints fix commits with `code-graph` and proposes them as a pull request; the `pages` workflow rebuilds the site and the bundle on every push to `main`.

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
