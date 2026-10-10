"""Derived AST unit extractor and before/after fragment contract for local sources (offline, stdlib-first).

Reads local source files given as input, extracts function-definition units
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
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys

# Exact pins verified against PyPI on 2026-10-07. Keep in sync with docs/AST.md.
TREE_SITTER_PIN = "tree-sitter==0.26.0"
TREE_SITTER_C_PIN = "tree-sitter-c==0.24.2"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BLOB_SHA_RE = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")

MAX_FRAGMENT_BODY_CHARS = 1048576

REQUIRED_FRAGMENT_FIELDS = (
    "repo",
    "commit_sha",
    "blob_sha",
    "symbol_name",
    "language",
    "role",
    "function_body",
    "lines_range",
    "truncated",
    "ast_indexed",
)

KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch"}


class ASTError(Exception):
    """Deterministic extraction failure, safe to log."""


def validate_fragment(fragment):
    """Formal validator for before/after fragment contracts (schemas/fragment.schema.json)."""
    if not isinstance(fragment, dict):
        raise ValueError("Fragment must be a dict")
    for field in REQUIRED_FRAGMENT_FIELDS:
        if field not in fragment:
            raise ValueError(f"Missing required fragment field: '{field}'")

    repo = fragment["repo"]
    if not isinstance(repo, str) or not repo.strip():
        raise ValueError("Invalid fragment repo")

    commit_sha = fragment["commit_sha"]
    if not isinstance(commit_sha, str) or not SHA_RE.match(commit_sha):
        raise ValueError("commit_sha must be a full 40-hex lowercase SHA")

    blob_sha = fragment["blob_sha"]
    if not isinstance(blob_sha, str) or not BLOB_SHA_RE.match(blob_sha):
        raise ValueError("blob_sha must be a 40-hex or 64-hex lowercase SHA")

    symbol_name = fragment["symbol_name"]
    if not isinstance(symbol_name, str) or not symbol_name.strip():
        raise ValueError("Invalid fragment symbol_name")

    language = fragment["language"]
    if not isinstance(language, str) or not language.strip():
        raise ValueError("Invalid fragment language")

    role = fragment["role"]
    if role not in ("before", "after"):
        raise ValueError(f"role must be 'before' or 'after', got {role!r}")

    body = fragment["function_body"]
    if not isinstance(body, str):
        raise ValueError("function_body must be a string")
    if len(body) > MAX_FRAGMENT_BODY_CHARS:
        raise ValueError(f"function_body exceeds max bounded length ({MAX_FRAGMENT_BODY_CHARS})")

    lines_range = fragment["lines_range"]
    if not isinstance(lines_range, (list, tuple)) or len(lines_range) != 2:
        raise ValueError("lines_range must be a 2-element [start, end] list")
    start, end = lines_range
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
        raise ValueError(f"Invalid lines_range: {lines_range}")

    truncated = fragment["truncated"]
    if not isinstance(truncated, bool):
        raise ValueError("truncated must be a boolean")

    ast_indexed = fragment["ast_indexed"]
    if not isinstance(ast_indexed, bool):
        raise ValueError("ast_indexed must be a boolean")


def compute_structural_diff(before_frag_or_body, after_frag_or_body):
    """Compute a deterministic unified diff between before and after fragments or bodies."""
    b_text = (
        before_frag_or_body["function_body"]
        if isinstance(before_frag_or_body, dict)
        else str(before_frag_or_body)
    )
    a_text = (
        after_frag_or_body["function_body"]
        if isinstance(after_frag_or_body, dict)
        else str(after_frag_or_body)
    )
    b_lines = b_text.splitlines(keepends=True)
    a_lines = a_text.splitlines(keepends=True)
    return "".join(difflib.unified_diff(b_lines, a_lines, fromfile="before", tofile="after"))


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


def extract_units_stdlib(source, path, return_skipped=False):
    """Heuristic function-definition extraction with audit for skipped functions."""
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

    matched_brace_offsets = set()
    unbalanced_offsets = set()
    units = []
    skipped = []

    for m in FUNC_RE.finditer(cleaned):
        name = m.group("name")
        brace_open = m.end() - 1
        if name in KEYWORDS:
            continue
        start_line = offset_to_line(m.start("name"))
        if lines[start_line - 1].lstrip().startswith("#"):
            continue

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
            unbalanced_offsets.add(brace_open)
            skipped.append({
                "symbol": name,
                "reason": "unbalanced_braces",
                "line": start_line,
            })
            continue

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
        matched_brace_offsets.add(brace_open)

    # Secondary audit pass: inspect top-level opening braces that were skipped
    n = len(cleaned)
    i = 0
    brace_depth = 0
    while i < n:
        c = cleaned[i]
        if c == "{":
            if brace_depth == 0:
                brace_idx = i
                if brace_idx not in matched_brace_offsets and brace_idx not in unbalanced_offsets:
                    prev = brace_idx - 1
                    while prev >= 0 and cleaned[prev] not in ";{}":
                        prev -= 1
                    header = cleaned[prev + 1:brace_idx].strip()
                    header_line = lines[offset_to_line(brace_idx) - 1].lstrip() if lines else ""
                    if not header_line.startswith("#") and not header.startswith("#"):
                        has_assign = False
                        p_depth = 0
                        for ch in header:
                            if ch == "(":
                                p_depth += 1
                            elif ch == ")":
                                p_depth = max(0, p_depth - 1)
                            elif ch == "=" and p_depth == 0:
                                has_assign = True
                                break
                        if not has_assign:
                            if not (re.search(r"\b(struct|union|enum|typedef)\b", header) and ")" not in header):
                                last_paren = header.rfind(")")
                                if last_paren != -1:
                                    pd = 0
                                    first_paren = -1
                                    for pj in range(last_paren, -1, -1):
                                        if header[pj] == ")":
                                            pd += 1
                                        elif header[pj] == "(":
                                            pd -= 1
                                            if pd == 0:
                                                first_paren = pj
                                                break
                                    if first_paren != -1:
                                        pre_paren = header[:first_paren].strip()
                                        m_name = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", pre_paren)
                                        if m_name and m_name.group(1) not in KEYWORDS:
                                            cand_name = m_name.group(1)
                                            cand_line = offset_to_line(prev + 1 + header.find(cand_name))
                                            params = header[first_paren + 1:last_paren]
                                            after_paren = header[last_paren + 1:].strip()
                                            reason = "unrecognized_signature"
                                            if "(" in params or ")" in params:
                                                reason = "nested_parentheses"
                                            elif after_paren and not re.fullmatch(r"__attribute__\s*\(\([^)]*\)\)", after_paren):
                                                reason = "unrecognized_macro"
                                            skipped.append({
                                                "symbol": cand_name,
                                                "reason": reason,
                                                "line": cand_line,
                                            })
            brace_depth += 1
        elif c == "}":
            if brace_depth > 0:
                brace_depth -= 1
        i += 1

    # Drop #define macro bodies masquerading as calls: macros live on
    # preprocessor lines; filter units whose declarator line starts with '#'.
    units = [u for u in units if not lines[u["start_line"] - 1].lstrip().startswith("#")]

    if return_skipped:
        return units, skipped
    return units


def extract_fragment(
    source,
    symbol_name,
    repo,
    commit_sha,
    blob_sha,
    role,
    path="<inline>",
    language="c",
    max_body_chars=65536,
    ast_indexed=True,
):
    """Extract a bounded before/after fragment and validate it against the schema."""
    units, skipped = extract_units_stdlib(source, path, return_skipped=True)
    matching = [u for u in units if u["symbol"] == symbol_name]
    if not matching:
        raise ASTError(f"Symbol '{symbol_name}' not found in {path}")
    unit = matching[0]

    lines = source.splitlines(keepends=True)
    start_line, end_line = unit["start_line"], unit["end_line"]
    raw_body = "".join(lines[start_line - 1:end_line])

    if len(raw_body) > max_body_chars:
        function_body = raw_body[:max_body_chars]
        truncated = True
    else:
        function_body = raw_body
        truncated = False

    fragment = {
        "repo": repo,
        "commit_sha": commit_sha,
        "blob_sha": blob_sha,
        "symbol_name": symbol_name,
        "language": language,
        "role": role,
        "function_body": function_body,
        "lines_range": [start_line, end_line],
        "truncated": truncated,
        "ast_indexed": ast_indexed,
        "file": path,
    }
    validate_fragment(fragment)
    return fragment


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
        skipped = []
        parser = f"tree-sitter-c ({TREE_SITTER_C_PIN})"
    elif backend == "stdlib":
        units, skipped = extract_units_stdlib(source, source_path, return_skipped=True)
        parser = "stdlib"
    else:
        raise ASTError(f"Unknown backend: {backend}")

    status = "PARSER_SKIPPED" if skipped else "COMPLETE"
    return {
        "repo": repo,
        "commit": commit,
        "blob": blob,
        "file": source_path,
        "parser": parser,
        "status": status,
        "unit_count": len(units),
        "parser_skipped_count": len(skipped),
        "skipped": skipped,
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

    total_skipped = sum(r.get("parser_skipped_count", 0) for r in records)
    if errors or total_skipped > 0:
        coverage = "INCOMPLETE"
    else:
        coverage = "COMPLETE_REQUESTED_INPUTS"

    if total_skipped > 0:
        status = "PARSER_SKIPPED"
        errors.append(f"Parser skipped {total_skipped} function definition(s)")
    elif errors:
        status = "INCOMPLETE"
    else:
        status = "COMPLETE"

    payload = {
        "coverage": coverage,
        "status": status,
        "count": sum(r["unit_count"] for r in records),
        "parser_skipped_count": total_skipped,
        "errors": errors,
        "files": records,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"AST mining: {payload['count']} units from {len(records)} files; {payload['coverage']}; skipped: {total_skipped}")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
