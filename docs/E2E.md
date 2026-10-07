# E2E suite — `tests/test_e2e_pack.py`

Offline end-to-end coverage of the portable-pack pipeline, in order:

1. **Build determinism** — `load_records` over the real seed +
   `build_sql` twice yields byte-identical SQL containing the seed id.
2. **Bundle export** — `export_bundle` to a temp dir with revision
   `a`*40; every file in `distribution.json` re-verified (size + sha256),
   manifest round-trips.
3. **Local reader** — `PackReader` over the local bundle dir (no network);
   query `interval garbage collection` returns hits including the seed
   record; bundle files byte-identical afterwards (read-only).
4. **Baseline** — `measure` over `experiments/qrels-v1.json` against the
   bundle SQL asserts recall 6/6 and abstention 2/3 with 0 NOT_MEASURED
   (matches `experiments/BASELINE.md`).

## Run

```sh
python3 -m unittest tests.test_e2e_pack -v
python3 -m unittest discover -s tests
python3 scripts/build_pack.py --check
```

## Limits

- Single seed (`linux-CVE-2024-26581-mainline`), qrels-v1 n=9:
  rates are illustrative, NOT generalizable.
- No neural vectors (`vectors: NOT_BUILT`), no AST index, no network —
  the reader path tested is local-directory only (URL branch untested).
- No honest skips needed: every stage is measurable offline today.
  If a stage ever requires network/vectors, skip with
  `unittest.skip` + reason instead of inventing numbers.
