# AST unit mining (derived view)

`scripts/mine_ast.py` extracts C function-definition units (symbol, file,
line range, sha256 of the body) from **local** C files given as input.
Output JSON carries corpus identity: `repo` + `commit` + `blob` + `symbol`.

**Authority rule:** the JSON/SQL corpus is canonical. AST output is a
disposable derived view over pinned source blobs; it never creates facts,
CVE bindings, or causal edges.

## Usage

```sh
python3 scripts/mine_ast.py \
    --input path/to/nft_set_rbtree.c \
    --repo torvalds/linux \
    --commit 60c0c230c6f046da536d3df8b39a20b9a9fd6af0 \
    [--blob <blob-sha>] [--backend stdlib|tree-sitter] \
    --output ast_out/units.json
```

- `--commit` must be a full 40-hex SHA (same contract as `mine_candidates.py`).
- Prototypes (`;`-terminated declarations) are excluded; only definitions
  with bodies are emitted.
- `#define` macros are never emitted as units.
- Functions inside `#if`/`#ifdef`/`#ifndef`…`#endif` regions are extracted
  with `"conditional": true` (parse/configuration uncertainty is retained,
  not resolved).
- Unbalanced input is skipped, never hallucinated; missing files and
  backend errors yield `"coverage": "INCOMPLETE"` with `errors` listed.

## Dependency pin (tree-sitter backend)

Exact pins, verified against PyPI on 2026-10-07:

- `tree-sitter==0.26.0`
- `tree-sitter-c==0.24.2`

Install: `pip install "tree-sitter==0.26.0" "tree-sitter-c==0.24.2"`

- Default `--backend stdlib` needs no dependency and is what the offline
  test suite covers (`tests/test_mine_ast.py`, no network).
- `--backend tree-sitter` without the pinned packages installed fails fast
  with an `ASTError` carrying the exact install command above.
- Note: tree-sitter query wiring is not implemented in this revision; the
  backend raises a clear `ASTError` even when the packages are present.
  stdlib is the deterministic extraction path until that wiring lands.
