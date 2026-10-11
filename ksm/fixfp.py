"""Build fix fingerprints (ksm-fixfp/1) from catalog fix commits.

Deterministic, stdlib only. Network and subprocess are injectable so tests
run offline: pass ``fetch_commit``, ``fetch_blob`` and ``run_fingerprint``
callables. Default implementations use urllib/subprocess with the token from
``$GITHUB_TOKEN`` (never logged).
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

SCHEMA = "ksm-fixfp/1"

# Contract section 2, exact repo map.
REPO_MAP = {
    "linux": "torvalds/linux",
    "linux-cna": "torvalds/linux",
    "curl": "curl/curl",
    "openssl": "openssl/openssl",
    "git": "git/git",
    "sqlite": "sqlite/sqlite",
    "systemd": "systemd/systemd",
    "postgres": "postgres/postgres",
}

# Catalog lookup order: one fix SHA per CVE per run, upstream catalogs first,
# linux-cna newest first. Each entry: (project label, catalog dirs to try).
CANDIDATE_SOURCES = [
    ("curl", ["curl-upstream", "curl"]),
    ("openssl", ["openssl-upstream", "openssl"]),
    ("git", ["git-upstream", "git"]),
    ("sqlite", ["sqlite-upstream", "sqlite"]),
    ("systemd", ["systemd-upstream", "systemd"]),
    ("postgres", ["postgres-upstream", "postgresql", "postgres"]),
    ("linux-cna", ["linux-cna"]),
]

STABLE_FALLBACK = "gregkh/linux"

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

EXT_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rs": "rust", ".py": "python", ".go": "go", ".java": "java",
    ".ts": "typescript", ".js": "javascript",
}


RATE_LIMIT_STATUSES = (403, 429)


class FetchError(RuntimeError):
    def __init__(self, reason, status=None):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def language_for_path(path):
    ext = os.path.splitext(os.path.basename(path))[1].lower()
    return EXT_TO_LANG.get(ext)


def parse_hunks(patch_text):
    """Parse unified diff into hunks with old/new changed line numbers.

    Returns a list of dicts with old_start/old_len/new_start/new_len plus
    ``old_changed`` (deleted old-side line numbers) and ``new_changed``
    (added new-side line numbers). No line text is retained.
    """
    hunks = []
    cur = None
    old_ln = new_ln = None
    for raw in (patch_text or "").split("\n"):
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
                "old_changed": [],
                "new_changed": [],
            }
            hunks.append(cur)
            old_ln, new_ln = old_start, new_start
            continue
        if cur is None:
            continue
        if raw.startswith("\\"):
            continue
        if raw == "":
            continue
        if raw.startswith("+"):
            cur["new_changed"].append(new_ln)
            new_ln += 1
        elif raw.startswith("-"):
            cur["old_changed"].append(old_ln)
            old_ln += 1
        elif raw.startswith(" "):
            old_ln += 1
            new_ln += 1
    return hunks


def _merge_ranges(nums):
    nums = sorted(set(nums))
    if not nums:
        return []
    out = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
        else:
            out.append((start, prev))
            start = prev = n
    out.append((start, prev))
    return out


def changed_ranges(hunks):
    """Return (old_ranges, new_ranges) as merged (start, end) inclusive lists."""
    old_nums = [ln for h in hunks for ln in h["old_changed"]]
    new_nums = [ln for h in hunks for ln in h["new_changed"]]
    return _merge_ranges(old_nums), _merge_ranges(new_nums)


def hunk_spans(hunks):
    """(old_spans, new_spans): each hunk's full extent on each side.

    A fix that only adds lines has no changed line on the old side, so the
    vulnerable function would never be fingerprinted from changed lines alone.
    The hunk span (changed lines plus context) locates it on both sides.
    """
    old, new = [], []
    for h in hunks:
        old.append((max(1, h["old_start"]), max(1, h["old_start"] + max(h["old_len"], 1) - 1)))
        new.append((max(1, h["new_start"]), max(1, h["new_start"] + max(h["new_len"], 1) - 1)))
    return _merge_ranges_pairs(old), _merge_ranges_pairs(new)


def _merge_ranges_pairs(pairs):
    out = []
    for a, b in sorted(pairs):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def _overlaps(fn, ranges):
    a, b = int(fn.get("start_line", 0)), int(fn.get("end_line", 0))
    return any(a <= e and s <= b for s, e in ranges)


TEST_DIRS = {"test", "tests", "testsuite", "unittests", "unit-tests"}


def is_test_path(path):
    return any(part in TEST_DIRS for part in path.split("/")[:-1])


def slim_function(fn):
    """Corpus copy of an sfp function: `vars` are only needed for target reports."""
    if fn is None:
        return None
    return {k: v for k, v in fn.items() if k != "vars"}


def format_ranges(ranges):
    return ",".join(f"{s}-{e}" for s, e in ranges)


def compute_delta(before_fn, after_fn):
    """Delta between paired sfp function objects (either may be None)."""
    b_kg = (before_fn or {}).get("kgrams", {}) or {}
    a_kg = (after_fn or {}).get("kgrams", {}) or {}
    added_kgrams, removed_kgrams = {}, {}
    for k in sorted(set(b_kg) | set(a_kg)):
        d = int(a_kg.get(k, 0)) - int(b_kg.get(k, 0))
        if d > 0:
            added_kgrams[k] = d
        elif d < 0:
            removed_kgrams[k] = -d
    b_calls = sorted({c.get("callee", "") for c in ((before_fn or {}).get("calls", []) or []) if c.get("callee")})
    a_calls = sorted({c.get("callee", "") for c in ((after_fn or {}).get("calls", []) or []) if c.get("callee")})
    b_set, a_set = set(b_calls), set(a_calls)
    b_guards = {(g.get("kind", ""), tuple(g.get("vars", []) or []))
                for g in ((before_fn or {}).get("guards", []) or [])}
    added_guards = []
    seen = set()
    for g in ((after_fn or {}).get("guards", []) or []):
        key = (g.get("kind", ""), tuple(g.get("vars", []) or []))
        if key not in b_guards and key not in seen:
            seen.add(key)
            added_guards.append({"kind": g.get("kind", ""), "vars": list(g.get("vars", []) or [])})
    added_guards.sort(key=lambda g: (g["kind"], g["vars"]))
    return {
        "added_kgrams": added_kgrams,
        "removed_kgrams": removed_kgrams,
        "added_calls": sorted(a_set - b_set),
        "removed_calls": sorted(b_set - a_set),
        "added_guards": added_guards,
    }


def dumps(obj, compact=False):
    if compact:
        return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def atomic_write_json(path, obj, compact=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(dumps(obj, compact=compact), encoding="utf-8")
    os.replace(tmp, path)


def load_candidates(catalog_dir, only_project=None):
    """Ordered candidates: one fix SHA per CVE.

    Upstream catalogs in contract order, linux-cna newest first
    (advisory id desc, published is null there).
    """
    catalog_dir = Path(catalog_dir)
    out = []
    for project, dirs in CANDIDATE_SOURCES:
        if only_project is not None and project != only_project:
            continue
        rows = None
        for d in dirs:
            fp = catalog_dir / d / "catalog.jsonl"
            if fp.exists():
                rows = []
                with fp.open(encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            rows.append(json.loads(line))
                break
        if not rows:
            continue
        if project == "linux-cna":
            rows = sorted(rows, key=lambda r: str(r.get("advisory_id", "")), reverse=True)
        for r in rows:
            shas = r.get("fix_shas", []) or []
            if not shas:
                continue
            out.append({
                "project": project,
                "advisory_id": r.get("advisory_id", ""),
                "fix_sha": shas[0],
                "cwe": r.get("cwe"),
                "published": r.get("published"),
            })
    return out


def index_path(out_dir):
    return Path(out_dir) / "index.json"


def load_index(out_dir):
    fp = index_path(out_dir)
    if not fp.exists():
        return {"done": [], "failed": []}
    try:
        d = json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        return {"done": [], "failed": []}
    d.setdefault("done", [])
    d.setdefault("failed", [])
    return d


def _index_key(e):
    return (str(e.get("project", "")), str(e.get("advisory_id", "")), str(e.get("fix_sha", "")))


def save_index(out_dir, index):
    index = {"done": sorted(index.get("done", []), key=_index_key),
             "failed": sorted(index.get("failed", []), key=_index_key)}
    atomic_write_json(index_path(out_dir), index)


# --------------------------------------------------------------------------- #
# Default network / subprocess adapters (stdlib only)
# --------------------------------------------------------------------------- #
def _gh_headers():
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ksm-fixfp",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def commit_try_order(repo):
    """Repos to try for the commit API: stable fallback on 404/422."""
    if repo == "torvalds/linux":
        return [repo, STABLE_FALLBACK]
    return [repo]


def fetch_commit_default(repo, sha):
    """Fetch commit JSON; stable fallback gregkh/linux on 404/422. Token never logged."""
    last_status = None
    for r in commit_try_order(repo):
        url = f"https://api.github.com/repos/{r}/commits/{sha}"
        req = urllib.request.Request(url, headers=_gh_headers())
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            data["_ksm_repo"] = r
            return data
        except urllib.error.HTTPError as exc:
            last_status = exc.code
            if r == "torvalds/linux" and exc.code in (404, 422):
                continue
            raise FetchError(f"commit API {exc.code} for {r}@{sha}", status=exc.code)
        except urllib.error.URLError as exc:
            raise FetchError(f"commit API network error for {r}@{sha}: {exc.reason}")
    raise FetchError(f"commit API {last_status} for {repo}@{sha} (stable fallback tried)",
                     status=last_status)


def fetch_blob_default(repo, sha, path):
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "ksm-fixfp"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise FetchError(f"blob fetch {exc.code} for {repo}@{sha}:{path}", status=exc.code)
    except urllib.error.URLError as exc:
        raise FetchError(f"blob fetch network error for {repo}@{sha}:{path}: {exc.reason}")


def code_graph_bin_default():
    return os.environ.get("KSM_CODE_GRAPH", "code-graph")


def run_fingerprint_default(code_graph_bin, file_path, language, ranges_str):
    cmd = [code_graph_bin, "fingerprint", str(file_path)]
    if language:
        cmd += ["--lang", language]
    if ranges_str:
        cmd += ["--ranges", ranges_str]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        raise FetchError(f"code-graph not found: {code_graph_bin}")
    except subprocess.TimeoutExpired:
        raise FetchError("code-graph timed out")
    if proc.returncode == 2:
        raise FetchError("code-graph unreadable file")
    if proc.returncode != 0:
        raise FetchError(f"code-graph exit {proc.returncode}")
    try:
        return json.loads(proc.stdout)
    except Exception as exc:
        raise FetchError(f"code-graph bad JSON: {exc}")


# --------------------------------------------------------------------------- #
# Per-candidate build
# --------------------------------------------------------------------------- #
def build_one(candidate, out_dir, code_graph_bin="code-graph", tool="code-graph@unknown",
              fetch_commit=None, fetch_blob=None, run_fingerprint=None):
    """Build one fingerprint doc. Returns (doc_or_None, repo_used).

    Raises FetchError on failure (caller records index failed with reason).
    """
    fetch_commit = fetch_commit or fetch_commit_default
    fetch_blob = fetch_blob or fetch_blob_default
    run_fingerprint = run_fingerprint or (lambda p, lang, rng: run_fingerprint_default(
        code_graph_bin, p, lang, rng))

    project = candidate["project"]
    fix_sha = candidate["fix_sha"]
    repo = REPO_MAP.get(project, project)

    try:
        commit = fetch_commit(repo, fix_sha)
    except FetchError:
        raise
    except Exception as exc:
        raise FetchError(f"commit fetch failed: {exc}")

    repo_used = commit.pop("_ksm_repo", repo) if isinstance(commit, dict) else repo
    parents = commit.get("parents", []) or []
    parent_sha = parents[0].get("sha") if parents else None
    if not parent_sha:
        raise FetchError("no parent commit")
    files = commit.get("files", []) or []

    doc_files = []
    skipped = 0
    parser_skipped = 0
    with tempfile.TemporaryDirectory(prefix="ksm-fixfp-") as tmp:
        tmpdir = Path(tmp)
        for f in sorted(files, key=lambda x: x.get("filename", "")):
            path = f.get("filename", "")
            status = f.get("status", "modified")
            lang = language_for_path(path)
            if not lang or is_test_path(path):
                skipped += 1
                continue
            patch = f.get("patch")
            if not patch:
                # The commit API omits patches for large or binary diffs; without
                # changed ranges the whole file would be fingerprinted.
                skipped += 1
                continue
            hunks = parse_hunks(patch)
            old_ranges, new_ranges = changed_ranges(hunks)
            old_spans, new_spans = hunk_spans(hunks)
            try:
                if status == "added":
                    before_bytes = None
                else:
                    before_bytes = fetch_blob(repo_used, parent_sha, path)
                if status == "removed":
                    after_bytes = None
                else:
                    after_bytes = fetch_blob(repo_used, fix_sha, path)
            except FetchError:
                raise
            except Exception as exc:
                raise FetchError(f"blob fetch failed for {path}: {exc}")
            if before_bytes is None and after_bytes is None and status not in ("added", "removed"):
                skipped += 1
                continue
            before_doc = after_doc = None
            try:
                if before_bytes is not None:
                    bf = tmpdir / ("before_" + path.replace("/", "_"))
                    bf.parent.mkdir(parents=True, exist_ok=True)
                    bf.write_bytes(before_bytes)
                    before_doc = run_fingerprint(str(bf), lang, format_ranges(old_spans))
                if after_bytes is not None:
                    af = tmpdir / ("after_" + path.replace("/", "_"))
                    af.parent.mkdir(parents=True, exist_ok=True)
                    af.write_bytes(after_bytes)
                    after_doc = run_fingerprint(str(af), lang, format_ranges(new_spans))
            except FetchError:
                raise
            except Exception as exc:
                raise FetchError(f"fingerprint failed for {path}: {exc}")
            b_cov = (before_doc or {}).get("coverage", "OK") if before_bytes is not None else "OK"
            a_cov = (after_doc or {}).get("coverage", "OK") if after_bytes is not None else "OK"
            if b_cov == "PARSER_SKIPPED" and a_cov == "PARSER_SKIPPED":
                parser_skipped += 1
            b_fns = {fn.get("name", ""): fn for fn in ((before_doc or {}).get("functions", []) or [])}
            a_fns = {fn.get("name", ""): fn for fn in ((after_doc or {}).get("functions", []) or [])}
            # Touched = a changed line falls inside the function on either side;
            # functions that only appear in the hunk context are dropped.
            touched = ({n for n, fn in b_fns.items() if _overlaps(fn, old_ranges)}
                       | {n for n, fn in a_fns.items() if _overlaps(fn, new_ranges)})
            names = sorted(touched)
            if not names:
                skipped += 1
                continue
            fns = []
            for name in names:
                bf, af = b_fns.get(name), a_fns.get(name)
                fns.append({
                    "name": name,
                    "before": slim_function(bf),
                    "after": slim_function(af),
                    "delta": compute_delta(bf, af),
                })
            fns.sort(key=lambda x: x["name"])
            doc_files.append({"path": path, "language": lang, "functions": fns})
        doc_files.sort(key=lambda x: x["path"])

    if not doc_files and skipped and not parser_skipped:
        coverage = "PARTIAL"
    elif not doc_files and parser_skipped:
        coverage = "PARSER_SKIPPED"
    elif not doc_files:
        coverage = "FETCH_FAILED"
    elif skipped or parser_skipped:
        coverage = "PARTIAL"
    else:
        coverage = "OK"
    # All parser-skipped but some files present.
    if doc_files and all(
            all(((fn.get("before") or {}).get("coverage", "OK") == "PARSER_SKIPPED"
                 if fn.get("before") else True) and
                ((fn.get("after") or {}).get("coverage", "OK") == "PARSER_SKIPPED"
                 if fn.get("after") else True)
                for fn in f["functions"]) for f in doc_files):
        coverage = "PARSER_SKIPPED"

    doc = {
        "schema": SCHEMA,
        "advisory_id": candidate["advisory_id"],
        "project": project,
        "repo": repo_used,
        "fix_sha": fix_sha,
        "parent_sha": parent_sha,
        "cwe": candidate.get("cwe"),
        "tool": tool,
        "coverage": coverage,
        "files": doc_files,
    }
    out_fp = Path(out_dir) / project / (candidate["advisory_id"] + ".json")
    atomic_write_json(out_fp, doc, compact=True)
    return doc, repo_used


def build_all(catalog_dir, out_dir, max_commits=300, code_graph_bin="code-graph",
              only_project=None, dry_run=False, retry_failed=False, tool="code-graph@unknown",
              fetch_commit=None, fetch_blob=None, run_fingerprint=None):
    """Run the builder over candidates. Returns summary dict."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates = load_candidates(catalog_dir, only_project=only_project)
    index = load_index(out_dir)
    done_keys = {(e.get("project"), e.get("advisory_id"), e.get("fix_sha")) for e in index["done"]}
    failed = {(e.get("project"), e.get("advisory_id"), e.get("fix_sha")): e for e in index["failed"]}

    todo = []
    for c in candidates:
        key = (c["project"], c["advisory_id"], c["fix_sha"])
        if key in done_keys:
            continue
        if key in failed and not retry_failed:
            continue
        todo.append(c)
    todo = todo[:max_commits]

    if dry_run:
        return {"candidates": todo, "processed": 0, "done": 0, "failed": 0}

    processed = ndone = nfail = 0
    summary_stop = None
    for c in todo:
        key = (c["project"], c["advisory_id"], c["fix_sha"])
        processed += 1
        try:
            build_one(c, out_dir, code_graph_bin=code_graph_bin, tool=tool,
                      fetch_commit=fetch_commit, fetch_blob=fetch_blob,
                      run_fingerprint=run_fingerprint)
        except FetchError as exc:
            if exc.status in RATE_LIMIT_STATUSES:
                processed -= 1
                summary_stop = f"stopped: {exc.reason}"
                break
            nfail += 1
            entry = {"project": c["project"], "advisory_id": c["advisory_id"],
                     "fix_sha": c["fix_sha"], "reason": exc.reason}
            failed[key] = entry
            index["failed"] = sorted(failed.values(), key=_index_key)
            save_index(out_dir, index)
            continue
        except Exception as exc:  # never crash a batch run
            nfail += 1
            entry = {"project": c["project"], "advisory_id": c["advisory_id"],
                     "fix_sha": c["fix_sha"], "reason": f"unexpected: {exc}"}
            failed[key] = entry
            index["failed"] = sorted(failed.values(), key=_index_key)
            save_index(out_dir, index)
            continue
        ndone += 1
        done_keys.add(key)
        failed.pop(key, None)
        index["done"] = sorted(
            [{"project": k[0], "advisory_id": k[1], "fix_sha": k[2]} for k in done_keys],
            key=_index_key)
        index["failed"] = sorted(failed.values(), key=_index_key)
        save_index(out_dir, index)
    return {"processed": processed, "done": ndone, "failed": nfail,
            "total_done": len(done_keys), "total_failed": len(failed), "stopped": summary_stop}
