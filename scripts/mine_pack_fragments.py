#!/usr/bin/env python3
"""Mine per-record function-change features from a pack's verified fix commits.

For each evidence-pack record under ``docs/memory/records`` this tool fetches the
fix commit's file patches from the GitHub commit API into a *gitignored* cache
(``docs/studies/fragments-cache``) and writes a deterministic, code-free feature
file under ``docs/studies/fragments/<record-id>.json``.

Committed feature files store references and hashes only -- never code bodies,
patch text or commit-message quotations (see docs/DATA-POLICY.md). Per changed
file they record: path, language, status, additions, deletions, and the functions
touched. Per function: name, before/after line ranges, sha256 of the before/after
function bodies, lines added/removed inside it, and parser coverage.

C/C-header files are additionally mined with scripts/mine_ast.py over the parent
(before) and fix (after) full-file contents so function boundaries are exact; the
heuristic hunk-header funcname is kept only as an honest cross-reference. Non-C
languages are reported at hunk-header level only and are marked as such.

Deterministic and offline-capable:
  python3 scripts/mine_pack_fragments.py                 # fetch + write (network)
  python3 scripts/mine_pack_fragments.py --offline --check  # recompute from cache, verify
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Allow `python3 scripts/mine_pack_fragments.py` (sys.path[0]==scripts/) and
# `from scripts.mine_pack_fragments import ...` (tests) to resolve scripts.*.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.mine_ast import extract_units_stdlib

SCHEMA_VERSION = "0.1.0"
GENERATOR = "scripts/mine_pack_fragments.py"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
# Conservative funcname extraction: the first identifier directly followed by '('.
SYMBOL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch"}

# File extension -> language label. C and C-header get AST mining; the rest are
# reported at hunk-header level only.
LANG_BY_EXT = {
    ".c": "c",
    ".h": "c-header",
    ".sh": "shell",
    ".pl": "perl",
    ".test": "sqlite-test",
    ".spec": "rpm-spec",
    ".in": "c-template",
    ".sym": "version-script",
    ".uuid": "manifest-uuid",
}
AST_LANGUAGES = {"c", "c-header"}

_COVERAGE_RANK = {"OK": 1, "PARSER_SKIPPED": 2, "INCOMPLETE": 3}


def repo_root():
    return Path(__file__).resolve().parents[1]


ROOT = repo_root()
CACHE_DIR = ROOT / "docs" / "studies" / "fragments-cache"
OUT_DIR = ROOT / "docs" / "studies" / "fragments"
RECORDS_DIR = ROOT / "docs" / "memory" / "records"


# --------------------------------------------------------------------------- #
# Pure helpers (no I/O): language, hunk parsing, funcname extraction, attribution
# --------------------------------------------------------------------------- #
def language_for(path):
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1]
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    if base == "manifest":
        return "sqlite-manifest"
    if base.startswith("README"):
        return "text"
    return "other"


def extract_symbol(context):
    """Extract a conservative function name from a hunk-header context line.

    Returns None (file-scope) when the context carries no ``name (`` pattern, so
    no source text is ever copied into a committed feature file.
    """
    if not context:
        return None
    ctx = context.strip()
    m = SYMBOL_RE.search(ctx)
    if not m:
        return None
    name = m.group(1)
    if name in KEYWORDS:
        return None
    return name


def parse_patch(text):
    """Parse a unified diff into hunks with per-line old/new line numbers.

    Only changed (+/-) lines are kept as items with their (old|new) line numbers;
    no line text is retained. ``@`` and '\\ No newline' markers are skipped.
    """
    hunks = []
    cur = None
    old_ln = new_ln = None
    for raw in text.split("\n"):
        m = HUNK_RE.match(raw)
        if m:
            old_start = int(m.group(1))
            old_len = int(m.group(2)) if m.group(2) is not None else 1
            new_start = int(m.group(3))
            new_len = int(m.group(4)) if m.group(4) is not None else 1
            cur = {
                "old_start": old_start,
                "old_len": old_len,
                "new_start": new_start,
                "new_len": new_len,
                "symbol": extract_symbol(m.group(5)),
                "added": 0,
                "removed": 0,
                "items": [],
            }
            hunks.append(cur)
            old_ln, new_ln = old_start, new_start
            continue
        if cur is None:
            continue
        if raw.startswith("\\"):
            continue  # "\ No newline at end of file"
        if raw == "":
            continue  # terminal split artifact; blank context lines are ' '-prefixed
        if raw.startswith("+"):
            cur["items"].append(("add", None, new_ln))
            cur["added"] += 1
            new_ln += 1
        elif raw.startswith("-"):
            cur["items"].append(("del", old_ln, None))
            cur["removed"] += 1
            old_ln += 1
        elif raw.startswith(" "):
            old_ln += 1
            new_ln += 1
        # any other prefix is ignored
    return hunks


def _find_unit(units, line):
    for u in units:
        if u["start_line"] <= line <= u["end_line"]:
            return u
    return None


def _skipped_regions(skipped, total_lines, units):
    """Approximate [start,end] ranges for parser-skipped definitions.

    A skipped definition's end is the next unit/skip start boundary (or EOF). This
    lets a changed line be assigned PARSER_SKIPPED coverage only when it actually
    falls inside a definition the heuristic parser gave up on.
    """
    bounds = sorted({1, total_lines + 1} |
                    {u["start_line"] for u in units} |
                    {s["line"] for s in skipped})
    regions = []
    for s in skipped:
        start = s["line"]
        nxt = next((b for b in bounds if b > start), total_lines + 1)
        regions.append((start, nxt - 1, s["symbol"], s.get("reason")))
    return regions


def _worst(covs):
    rank = 0
    best = "OK"
    for c in covs:
        if _COVERAGE_RANK.get(c, 3) > rank:
            rank = _COVERAGE_RANK.get(c, 3)
            best = c
    return best


def attribute_c(path, lang, before_text, after_text, before_bytes, after_bytes, hunks):
    """AST-precise attribution for C / C-header files."""
    b_units, b_skip = extract_units_stdlib(before_text, path, return_skipped=True)
    a_units, a_skip = extract_units_stdlib(after_text, path, return_skipped=True)
    b_by = {}
    for u in b_units:
        b_by.setdefault(u["symbol"], u)
    a_by = {}
    for u in a_units:
        a_by.setdefault(u["symbol"], u)

    b_total = len(before_text.splitlines())
    a_total = len(after_text.splitlines())
    b_regions = _skipped_regions(b_skip, b_total, b_units)
    a_regions = _skipped_regions(a_skip, a_total, a_units)

    touched = {}

    def _touch(name, kind):
        e = touched.setdefault(name, {
            "added": 0, "removed": 0,
            "before_ok": False, "after_ok": False,
            "skip_add": set(), "skip_rem": set(),
        })
        e[kind] += 1

    unatt_add = unatt_rem = 0
    for h in hunks:
        for kind, ol, nl in h["items"]:
            if kind == "del":
                u = _find_unit(b_units, ol) if ol is not None else None
                if u is not None:
                    _touch(u["symbol"], "removed")
                    touched[u["symbol"]]["before_ok"] = True
                    continue
                reg = _in_region(b_regions, ol) if ol is not None else None
                if reg is not None:
                    _touch(reg[2], "removed")
                    touched[reg[2]]["skip_rem"].add(reg[3] or "unparsed")
                    continue
                unatt_rem += 1
            elif kind == "add":
                u = _find_unit(a_units, nl) if nl is not None else None
                if u is not None:
                    _touch(u["symbol"], "added")
                    touched[u["symbol"]]["after_ok"] = True
                    continue
                reg = _in_region(a_regions, nl) if nl is not None else None
                if reg is not None:
                    _touch(reg[2], "added")
                    touched[reg[2]]["skip_add"].add(reg[3] or "unparsed")
                    continue
                unatt_add += 1

    functions = []
    for name in sorted(touched):
        e = touched[name]
        b = b_by.get(name)
        a = a_by.get(name)
        state = "OK"
        note = None
        method = "ast"
        if e["skip_add"] or e["skip_rem"]:
            state = "PARSER_SKIPPED"
            method = "hunk_fallback"
            reasons = sorted(e["skip_add"] | e["skip_rem"])
            note = "parser could not delimit definition (" + ";".join(reasons) + "); hunk-level only"
        functions.append({
            "name": name,
            "method": method,
            "coverage": state,
            "lines_added": e["added"],
            "lines_removed": e["removed"],
            "before_range": [b["start_line"], b["end_line"]] if b else None,
            "after_range": [a["start_line"], a["end_line"]] if a else None,
            "before_body_sha256": b["body_sha256"] if b else None,
            "after_body_sha256": a["body_sha256"] if a else None,
            "conditional": bool((b or {}).get("conditional")) or bool((a or {}).get("conditional")),
            "note": note,
        })

    file_cov = _worst([f["coverage"] for f in functions]) if functions else "OK"
    return functions, {"added": unatt_add, "removed": unatt_rem,
                       "reason": "changed line outside any C definition body"}, file_cov


def _in_region(regions, line):
    for r in regions:
        if r[0] <= line <= r[1]:
            return r
    return None


def attribute_hunk(path, lang, hunks):
    """Hunk-header-level attribution for non-C languages (honest, best-effort)."""
    funcs = {}
    unatt = {"added": 0, "removed": 0}
    for h in hunks:
        sym = h["symbol"]
        br = [h["old_start"], h["old_start"] + h["old_len"] - 1] if h["old_len"] else None
        ar = [h["new_start"], h["new_start"] + h["new_len"] - 1] if h["new_len"] else None
        if sym is None:
            unatt["added"] += h["added"]
            unatt["removed"] += h["removed"]
            continue
        e = funcs.setdefault(sym, {"added": 0, "removed": 0, "hunks": []})
        e["added"] += h["added"]
        e["removed"] += h["removed"]
        e["hunks"].append({"before": br, "after": ar,
                           "added": h["added"], "removed": h["removed"]})

    functions = []
    for name in sorted(funcs):
        e = funcs[name]
        bstarts = [x["before"][0] for x in e["hunks"] if x["before"]]
        bends = [x["before"][1] for x in e["hunks"] if x["before"]]
        astarts = [x["after"][0] for x in e["hunks"] if x["after"]]
        aends = [x["after"][1] for x in e["hunks"] if x["after"]]
        functions.append({
            "name": name,
            "method": "hunk",
            "coverage": "OK",
            "lines_added": e["added"],
            "lines_removed": e["removed"],
            "before_range": [min(bstarts), max(bends)] if bstarts else None,
            "after_range": [min(astarts), max(aends)] if astarts else None,
            "before_body_sha256": None,
            "after_body_sha256": None,
            "conditional": False,
            "hunks": e["hunks"],
            "note": f"hunk-header attribution only for language '{lang}'; not AST-parsed",
        })
    return functions, {"added": unatt["added"], "removed": unatt["removed"],
                       "reason": "no function/scope name in hunk header"}, "OK"


def analyze_file(path, status, additions, deletions, patch, lang,
                 before_text, after_text, before_bytes, after_bytes):
    """Build the committed feature dict for one changed file (pure, no I/O)."""
    hunks = parse_patch(patch) if patch else []
    before_blob = git_blob_sha(before_bytes) if before_bytes is not None else None
    needs_ast = lang in AST_LANGUAGES
    covs = ["OK"]
    if needs_ast and before_text is not None and after_text is not None:
        functions, unatt, fcov = attribute_c(
            path, lang, before_text, after_text, before_bytes, after_bytes, hunks)
        covs.append(fcov)
    else:
        functions, unatt, fcov = attribute_hunk(path, lang, hunks)
        covs.append(fcov)
    return {
        "path": path,
        "language": lang,
        "status": status,
        "additions": additions,
        "deletions": deletions,
        "hunk_count": len(hunks),
        "before_blob_sha": before_blob,
        "coverage": _worst(covs),
        "functions": functions,
        "unattributed": unatt,
    }


# --------------------------------------------------------------------------- #
# git blob sha + dumps (deterministic)
# --------------------------------------------------------------------------- #
def git_blob_sha(data):
    if data is None:
        return None
    h = hashlib.sha1()
    h.update(b"blob " + str(len(data)).encode("ascii") + b"\0" + data)
    return h.hexdigest()


def dumps(obj):
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


# --------------------------------------------------------------------------- #
# Network + cache layer
# --------------------------------------------------------------------------- #
class OfflineCacheMiss(RuntimeError):
    """Offline run needs a cache entry that is absent; reproducibility is broken."""


def gh_json(api_path):
    r = subprocess.run(["gh", "api", api_path], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"gh api {api_path} failed (exit {r.returncode})")
    return json.loads(r.stdout)


def gh_raw(api_path):
    r = subprocess.run(
        ["gh", "api", api_path, "-H", "Accept: application/vnd.github.raw"],
        capture_output=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"gh api {api_path} failed (exit {r.returncode})")
    return r.stdout


def load_commit(record_dir, repo, sha, offline):
    fp = record_dir / "commit.json"
    if fp.exists():
        return json.loads(fp.read_text(encoding="utf-8"))
    if offline:
        raise OfflineCacheMiss(f"offline: missing cached commit {repo}@{sha}")
    data = gh_json(f"repos/{repo}/commits/{sha}")
    fp.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                  encoding="utf-8")
    return data


def load_content(record_dir, repo, path, ref, idx, side, offline):
    fp = record_dir / f"file-{idx}.{side}"
    if fp.exists():
        return fp.read_bytes()
    if offline:
        raise OfflineCacheMiss(f"offline: missing cached content {repo}:{path}@{ref} ({side})")
    data = gh_raw(f"repos/{repo}/contents/{path}?ref={ref}")
    fp.write_bytes(data)
    return data


# --------------------------------------------------------------------------- #
# Record resolution + per-record feature computation
# --------------------------------------------------------------------------- #
def resolve_pack_records(records_dir):
    """Yield (record_id, repo, fix_sha, parent_sha_or_None, error_or_None)."""
    out = []
    for fp in sorted(records_dir.glob("*.json")):
        rec_id = fp.stem
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - report deterministically
            out.append((rec_id, None, None, None, f"unreadable record: {exc}"))
            continue
        rec_id = d.get("id", rec_id)
        repo = fix = parent = None
        for n in d.get("nodes", []):
            if n.get("type") == "commit":
                a = n.get("attributes", {})
                if "repository" in a and "sha" in a and SHA_RE.match(a["sha"]):
                    repo, fix = a["repository"], a["sha"]
                    break
        if repo is None:
            before = after = None
            for n in d.get("nodes", []):
                if n.get("type") == "code_version":
                    a = n.get("attributes", {})
                    if a.get("role") == "before":
                        before = a
                    elif a.get("role") == "after":
                        after = a
            if after and SHA_RE.match(after.get("revision", "")):
                m = re.search(r"github\.com/([^/]+/[^/]+)/", after.get("url", ""))
                if m:
                    repo = m.group(1)
                fix = after["revision"]
                parent = before.get("revision") if before else None
        if repo is None or fix is None:
            out.append((rec_id, repo, fix, parent, "no resolvable fix commit (repo, sha)"))
        else:
            out.append((rec_id, repo, fix, parent, None))
    return out


def compute_record_feature(rec_id, repo, fix, parent_hint, offline):
    """Fetch (or read from cache) and compute a feature dict for one record."""
    record_dir = CACHE_DIR / rec_id
    record_dir.mkdir(parents=True, exist_ok=True)
    commit = load_commit(record_dir, repo, fix, offline)
    parents = [p["sha"] for p in commit.get("parents", [])]
    parent = parent_hint or (parents[0] if parents else None)
    files = sorted(commit.get("files", []), key=lambda f: f.get("filename", ""))

    out_files = []
    record_covs = ["OK"]
    for idx, f in enumerate(files):
        path = f["filename"]
        status = f.get("status", "modified")
        lang = language_for(path)
        after_blob = f.get("sha")
        prev_path = f.get("previous_filename") or path
        patch = f.get("patch")
        before_text = after_text = None
        before_bytes = after_bytes = None
        file_covs = ["OK"]
        fetch_reason = None
        try:
            if lang in AST_LANGUAGES:
                before_bytes = b"" if status == "added" else load_content(
                    record_dir, repo, prev_path, parent, idx, "before", offline)
                after_bytes = b"" if status == "removed" else load_content(
                    record_dir, repo, path, fix, idx, "after", offline)
                before_text = before_bytes.decode("utf-8", "replace")
                after_text = after_bytes.decode("utf-8", "replace")
        except OfflineCacheMiss:
            raise  # reproducibility failure: never silently downgrade in offline mode
        except Exception as exc:  # noqa: BLE001 - degrade online fetch failures to INCOMPLETE
            fetch_reason = str(exc)
            file_covs.append("INCOMPLETE")

        feat = analyze_file(
            path, status, f.get("additions", 0), f.get("deletions", 0),
            patch, lang, before_text, after_text, before_bytes, after_bytes,
        )
        # integrity: API after blob must equal git blob sha computed from content
        if after_bytes is not None and after_blob:
            calc = git_blob_sha(after_bytes)
            if calc != after_blob:
                file_covs.append("INCOMPLETE")
                fetch_reason = "after blob sha mismatch vs commit API"
        feat["after_blob_sha"] = after_blob
        feat["coverage"] = _worst(file_covs + [feat["coverage"]])
        if fetch_reason:
            feat["unattributed"]["reason"] = fetch_reason
        out_files.append(feat)
        record_covs.append(feat["coverage"])

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": rec_id,
        "repo": repo,
        "fix_commit": fix,
        "parent_commit": parent,
        "parent_count": len(parents),
        "generator": GENERATOR,
        "coverage": _worst(record_covs),
        "files": out_files,
    }


# --------------------------------------------------------------------------- #
# Stats + CLI
# --------------------------------------------------------------------------- #
def summarize(features, skipped):
    total_files = 0
    fn_cov = {"OK": 0, "PARSER_SKIPPED": 0, "INCOMPLETE": 0}
    fn_method = {"ast": 0, "hunk": 0, "hunk_fallback": 0}
    fn_total = 0
    rec_cov = {"OK": 0, "PARSER_SKIPPED": 0, "INCOMPLETE": 0}
    for feat in features.values():
        total_files += len(feat["files"])
        rec_cov[feat["coverage"]] = rec_cov.get(feat["coverage"], 0) + 1
        for f in feat["files"]:
            for fn in f["functions"]:
                fn_total += 1
                fn_cov[fn["coverage"]] = fn_cov.get(fn["coverage"], 0) + 1
                fn_method[fn["method"]] = fn_method.get(fn["method"], 0) + 1
    print("=== mine_pack_fragments summary ===")
    print(f"records processed: {len(features)}")
    print(f"records skipped:   {len(skipped)}")
    for rid, reason in skipped:
        print(f"  - {rid}: {reason}")
    print(f"files changed:     {total_files}")
    print(f"functions found:   {fn_total} (ast: {fn_method['ast']}, "
          f"hunk: {fn_method['hunk']}, hunk_fallback: {fn_method['hunk_fallback']})")
    print("function coverage by status:")
    for k in ("OK", "PARSER_SKIPPED", "INCOMPLETE"):
        print(f"  {k}: {fn_cov[k]}")
    print("record coverage by status:")
    for k in ("OK", "PARSER_SKIPPED", "INCOMPLETE"):
        print(f"  {k}: {rec_cov[k]}")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Mine function-change features from pack fix commits.")
    p.add_argument("--offline", action="store_true", help="never touch the network; use cache only")
    p.add_argument("--check", action="store_true",
                   help="recompute from cache and verify committed files match; write nothing")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records = resolve_pack_records(RECORDS_DIR)
    features = {}
    skipped = []
    mismatches = []
    errors = []

    for rec_id, repo, fix, parent, err in records:
        if err is not None:
            skipped.append((rec_id, err))
            continue
        try:
            feat = compute_record_feature(rec_id, repo, fix, parent, args.offline)
        except Exception as exc:  # noqa: BLE001 - offline-missing / gh failures
            skipped.append((rec_id, f"compute failed: {exc}"))
            continue
        features[rec_id] = feat
        text = dumps(feat)
        out_fp = OUT_DIR / f"{rec_id}.json"
        if args.check:
            if not out_fp.exists():
                mismatches.append((rec_id, "missing committed file"))
            elif out_fp.read_text(encoding="utf-8") != text:
                mismatches.append((rec_id, "content differs from recomputed feature"))
        else:
            out_fp.write_text(text, encoding="utf-8")

    summarize(features, skipped)

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2
    if skipped and not features:
        return 2
    if args.check:
        if mismatches:
            for rid, why in mismatches:
                print(f"MISMATCH {rid}: {why}", file=sys.stderr)
            return 1
        print(f"--check OK: {len(features)} committed feature files match cache-recomputed features")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
