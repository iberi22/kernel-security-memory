# Pack Reader

The hash-verified portable memory reader (`scripts/open_pack.py`) securely downloads and mounts an independent offline dataset from a trusted manifest.

## Usage

You can use the pack reader script from the command line:

```bash
python3 scripts/open_pack.py \
    --source https://raw.githubusercontent.com/iberi22/kernel-security-memory/10aa1d6256e1b0cd721232f4b879048feab620a6/docs/memory \
    --manifest-sha256 [MANIFEST_SHA256_HERE] \
    --cache /tmp/pack_cache \
    --query "interval garbage collection"
```

If querying a local directory, `--manifest-sha256` is optional, and the source path should be a local folder that contains `manifest.json`.

```bash
python3 scripts/open_pack.py \
    --source docs/memory \
    --cache /tmp/pack_cache \
    --query "interval garbage collection"
```

## Security Guarantees
- **No SQL Execution:** Downloaded SQL files are skipped. The reader dynamically builds the database from trusted and schema-validated JSON records.
- **Hash Integrity:** Every requested file listed in the manifest is validated against its pre-declared SHA-256 hash and size bounds.
- **Confinement:** The script validates path restrictions, ensuring it never downloads files with absolute paths, `..` traversals, or URIs within paths.
- **Controlled Network:** Remote downloads only work with explicit allowed hosts (`raw.githubusercontent.com` and `iberi22.github.io`). Timeouts and strict stream bounds apply. No redirects are followed.
- **Clean Cleanup:** Database and file processing happens inside an isolated subdirectory within your provided `--cache`. This directory is strictly removed up on successful or failed completion without touching preexisting data in the cache dir.

## Concrete Immutable Example

Here is an example demonstrating a fetch using the `10aa1d6256e1b0cd721232f4b879048feab620a6` commit, which requires the proper manifest hash to ensure integrity:

```bash
# This uses the exact commit 10aa1d6256e1b0cd721232f4b879048feab620a6 and expected hash for manifest.json.
# (If you need the hash, you can download the manifest manually and compute it via `sha256sum`)

python3 scripts/open_pack.py \
    --source https://raw.githubusercontent.com/iberi22/kernel-security-memory/10aa1d6256e1b0cd721232f4b879048feab620a6/docs/memory \
    --cache /tmp/my_cache \
    --manifest-sha256 0c89ba7637cc9746f1cb5dfa70dc6c1a82e99d821213fbb5cc6af735dd2f45cc
```

(The exact sha256 of the manifest from that commit depends on the built pack artifact, please verify with `sha256sum docs/memory/manifest.json`).
