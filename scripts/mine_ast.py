"""Derived AST unit extractor for local C sources (offline, stdlib-first).

Reads local C files given as input, extracts function-definition units
(name, file, line range, sha256 of the body) and emits JSON carrying the
corpus identity (repo + commit + blob + symbol). The JSON/SQL corpus is
authoritative; AST output is a disposable derived view.

Backends:
  - stdlib (default): heuristic brace-matching parser, no dependencies.
  - tree-sitter: exact pinned grammar (see docs/AST.md). If the pinned
    packages are not installed the script fails with a clear install
    message instead of silently falling back.
"""
import argparse
import hashlib
import json
import re
import sys

# Exact pins verified against PyPI on 2026-10-07. Keep in sync with docs/AST.md.
TREE_SITTER_PIN = "tree-sitter==0.26.0"
TREE_SITTER_C_PIN = "tree-sitter-c==0.24.2"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ASTError(Exception):
    """Deterministic extraction failure, safe to log."""


def _strip_comments_and_strings(src):
    """Replace comments/strings/chars with spaces (newlines preserved)."""
    out = []
    i, n = 0, len(src)
    state = "code"
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
            elif c == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
            elif c == '"':
                state = "str"
                out.append(" ")
                i += 1
            elif c == "'":
                state = "chr"
                out.append(" ")
                i += 1
            else:
                out.append(c)
                i += 1
        elif state == "line":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif state == "str":
            if c == "\\":
                out.append("  ")
                i += 2
            elif c == '"':
                state = "code"
                out.append(" ")
                i += 1
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif state == "chr":
            if c == "\\":
                out.append("  ")
                i += 2
            elif c == "'":
                state = "code"
                out.append(" ")
                i += 1
            else:
                out.append(" ")
                i += 1
    return "".join(out)


def _conditional_ranges(lines):
    """Line ranges (1-based, inclusive) guarded by #if/#ifdef/#ifndef."""
    ranges = []
    stack = []
    for idx, line in enumerate(lines, start=1):
        s = line.strip()
        if re.match(r"#\s*if(?:def|ndef)?\b", s):
            stack.append(idx)
        elif re.match(r"#\s*endif\b", s):
            if stack:
                ranges.append((stack.pop(), idx))
    depth_open = sorted(s for s, _ in ranges)
    _ = depth_open
    return ranges


def _in_conditional(line_no, ranges):
    return any(s <= line_no <= e for s, e in ranges)


FUNC_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}()]*\)\s*(?:__attribute__\s*\(\([^)]*\)\)\s*)?\{",
)


def extract_units_stdlib(source, path):
    """Heuristic function-definition extraction. Returns unit dicts."""
    cleaned = _strip_comments_and_strings(source)
    lines = source.splitlines()
    cond_ranges = _conditional_ranges(lines)
    line_starts = []
    off = 0
    for line in source.splitlines(keepends=True):
        line_starts.append(off)
        off += len(line)

    def offset_to_line(o):
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= o:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    units = []
    for m in FUNC_RE.finditer(cleaned):
        name = m.group("name")
        brace_open = m.end() - 1
        depth = 0
        i = brace_open
        n = len(cleaned)
        while i < n:
            if cleaned[i] == "{":
                depth += 1
            elif cleaned[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            continue  # unbalanced; skip rather than hallucinate
        # Reject prototypes/control statements misparsed: name must be followed
        # by '(' in the original and must not be a keyword.
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        start_line = offset_to_line(m.start("name"))
        end_line = offset_to_line(i)
        body = source[brace_open:i + 1]
        units.append({
            "symbol": name,
            "file": path,
            "start_line": start_line,
            "end_line": end_line,
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "conditional": _in_conditional(start_line, cond_ranges),
            "parser": "stdlib",
        })
    # Drop #define macro bodies masquerading as calls: macros live on
    # preprocessor lines; filter units whose declarator line starts with '#'.
    units = [u for u in units if not lines[u["start_line"] - 1].lstrip().startswith("#")]
    return units


def extract_units_treesitter(source, path):
    """Tree-sitter backend. Fails cleanly when the pinned deps are missing."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_c  # noqa: F401
    except ImportError:
        raise ASTError(
            "tree-sitter backend requires pinned packages "
            f"{TREE_SITTER_PIN} and {TREE_SITTER_C_PIN}; "
            f"install with: pip install \"{TREE_SITTER_PIN}\" \"{TREE_SITTER_C_PIN}\""
        )
    raise ASTError(
        "tree-sitter backend installed but query wiring for "
        f"{TREE_SITTER_C_PIN} is not implemented in this revision; "
        "use --backend stdlib for deterministic extraction"
    )


def mine_file(source_path, repo, commit, blob=None, backend="stdlib"):
    with open(source_path, "r", encoding="utf-8") as f:
        source = f.read()
    if backend == "tree-sitter":
        units = extract_units_treesitter(source, source_path)
        parser = f"tree-sitter-c ({TREE_SITTER_C_PIN})"
    elif backend == "stdlib":
        units = extract_units_stdlib(source, source_path)
        parser = "stdlib"
    else:
        raise ASTError(f"Unknown backend: {backend}")
    return {
        "repo": repo,
        "commit": commit,
        "blob": blob,
        "file": source_path,
        "parser": parser,
        "unit_count": len(units),
        "units": units,
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Extract C function units (offline).")
    p.add_argument("--input", action="append", required=True, help="Local C file")
    p.add_argument("--repo", required=True, help="Source repo, e.g. torvalds/linux")
    p.add_argument("--commit", required=True, help="Full 40-hex SHA the blob belongs to")
    p.add_argument("--blob", default=None, help="Optional blob SHA for the file")
    p.add_argument("--backend", default="stdlib", choices=["stdlib", "tree-sitter"])
    p.add_argument("--output", required=True, help="Output JSON file")
    args = p.parse_args(argv)
    if not SHA_RE.match(args.commit):
        p.error("Commit must be a full 40-hex SHA")
    return args


def main(argv=None):
    args = parse_args(argv)
    records = []
    errors = []
    for path in args.input:
        try:
            records.append(mine_file(path, args.repo, args.commit, args.blob, args.backend))
        except FileNotFoundError:
            errors.append(f"Missing input file: {path}")
        except ASTError as e:
            errors.append(str(e))
    payload = {
        "coverage": "COMPLETE_REQUESTED_INPUTS" if not errors else "INCOMPLETE",
        "count": sum(r["unit_count"] for r in records),
        "errors": errors,
        "files": records,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"AST mining: {payload['count']} units from {len(records)} files; {payload['coverage']}")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
