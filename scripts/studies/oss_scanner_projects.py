#!/usr/bin/env python3
"""Selection manifest: enrolled OSS Scanner projects overlapped with KSM catalogs.

Reads ``projects/*/project.yaml`` either from a local clone (``--source``)
or from the GitHub API at a pinned commit (``--ref``), and writes
``docs/studies/selection/oss-scanner-projects.json``.

Privacy: only the repo URL/branch plus local-file presence leave this
script. Emails (primary_contact/auto_ccs) and PGP keys are never parsed
into the output.

OSV: ``osv_git_supported`` is true/false only when a single cached
``POST https://api.osv.dev/v1/query`` response per repo decides it
(``{"package": {"name": <repo>, "ecosystem": "GIT"}}`` has a non-empty
``vulns`` list or not). Responses live in a gitignored cache; without a
cached or fetchable answer the field is null. ``--no-osv`` forces null
(offline/tests). OSV input is pinned: builds use only the cache unless
``--refresh-osv`` explicitly allows live queries to fill misses, and the
manifest records ``osv_cache_digest`` (sha256 over the cache entries read)
so a ``--check`` compares the same input bytes, never a fresh network answer.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "docs" / "studies" / "selection" / "oss-scanner-projects.json"
DEFAULT_CATALOGS = ROOT / "docs" / "studies" / "cve-history"
DEFAULT_CACHE = ROOT / "docs" / "studies" / "selection" / ".osv-cache"
UPSTREAM = "https://github.com/anthropics/oss-scanner"
OSV_URL = "https://api.osv.dev/v1/query"


def _strip_inline_comment(value):
    """Cut a trailing ` # comment` that sits outside quoted scalars."""
    in_single = in_double = False
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and (in_single or in_double):
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and (
                i == 0 or value[i - 1] in (" ", "\t")):
            return value[:i].rstrip()
        i += 1
    return value.strip()


def _tiny_parse(text):
    """Minimal project.yaml reader: top-level scalar keys only.

    Prefers PyYAML when importable; otherwise falls back to a line scan
    that ignores comments, list items and the multiline pgp block.
    Only repo/branch/disabled-adjacent keys are ever read.
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None
    if yaml is not None:
        data = yaml.safe_load(text) or {}
        return {k: v for k, v in data.items() if isinstance(k, str)}
    out = {}
    in_block = False
    for line in text.splitlines():
        if in_block:
            if line[:1] in (" ", "\t"):
                continue
            in_block = False
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or line[:1] in (" ", "\t"):
            continue
        if stripped.startswith("- "):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+):\s*(.*?)\s*$", stripped)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        val = _strip_inline_comment(val)
        if val == "|":
            in_block = True
            continue
        if (len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"')):
            val = val[1:-1]
        out[key] = val
    return out


def _split_repo(raw):
    url, _, frag = (raw or "").strip().partition("#")
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[: -len(".git")]
    return url, (frag.strip() or None)


def _is_disabled(fields):
    val = fields.get("disabled", False)
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("true", "yes", "1")


def _catalog_dirs(catalogs_dir):
    try:
        entries = sorted(p.name for p in Path(catalogs_dir).iterdir() if p.is_dir())
    except FileNotFoundError:
        return []
    return entries


def _match_catalogs(name, repo, catalogs):
    base = repo.rsplit("/", 1)[-1].lower() if repo else ""
    want = {base, name.lower()}
    hits = []
    for entry in catalogs:
        stem = entry.lower()
        if stem.endswith("-upstream"):
            stem = stem[: -len("-upstream")]
        if stem in want:
            hits.append(entry)
    return sorted(hits)


def _git(args, cwd):
    proc = subprocess.run(
        ["git", "-C", str(cwd)] + args, capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _http_json(url, data=None, headers=None, timeout=30):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers or {})
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _read_source_projects(source):
    dirty = _git(["status", "--porcelain", "--", "projects"], source)
    if dirty:
        raise RuntimeError(
            f"refusing to build: uncommitted changes under {source}/projects "
            f"would be attributed to HEAD (commit or stash them first):\n{dirty}")
    projects = []
    for child in sorted(Path(source, "projects").iterdir()):
        spec = child / "project.yaml"
        if not child.is_dir() or not spec.is_file():
            continue
        fields = _tiny_parse(spec.read_text(encoding="utf-8"))
        if _is_disabled(fields):
            continue
        if "repo" not in fields:
            continue
        projects.append(
            {
                "name": child.name,
                "fields": fields,
                "has_threat_model": (child / "threat_model.md").is_file(),
                "has_dockerfile_here": (child / "Dockerfile").is_file(),
            }
        )
    commit = _git(["rev-parse", "HEAD"], source)
    fetched_at = _git(["log", "-1", "--format=%cI"], source)
    return projects, commit, fetched_at


def _read_ref_projects(ref):
    tree = _http_json(
        f"{UPSTREAM.replace('https://github.com/', 'https://api.github.com/repos/')}"
        f"/git/trees/{ref}?recursive=1",
        headers={"Accept": "application/vnd.github+json"},
    )
    paths = {item["path"] for item in tree.get("tree", []) if item.get("type") == "blob"}
    names = sorted(
        p.split("/")[1]
        for p in paths
        if p.startswith("projects/") and p.endswith("/project.yaml")
    )
    projects = []
    for name in names:
        raw = f"https://raw.githubusercontent.com/anthropics/oss-scanner/{ref}/projects/{name}/project.yaml"
        with urllib.request.urlopen(raw, timeout=30) as resp:
            text = resp.read().decode("utf-8")
        fields = _tiny_parse(text)
        if _is_disabled(fields) or "repo" not in fields:
            continue
        projects.append(
            {
                "name": name,
                "fields": fields,
                "has_threat_model": f"projects/{name}/threat_model.md" in paths,
                "has_dockerfile_here": f"projects/{name}/Dockerfile" in paths,
            }
        )
    commit_info = _http_json(
        f"{UPSTREAM.replace('https://github.com/', 'https://api.github.com/repos/')}"
        f"/commits/{ref}",
        headers={"Accept": "application/vnd.github+json"},
    )
    fetched_at = commit_info.get("commit", {}).get("committer", {}).get("date")
    return projects, ref, fetched_at


def _osv_supported(repo, cache_dir, no_osv, offline=False):
    if no_osv or offline:
        return _osv_from_cache(repo, cache_dir)
    cache_dir = Path(cache_dir)
    key = hashlib.sha1(repo.encode()).hexdigest() + ".json"
    cached = cache_dir / key
    if cached.is_file():
        return _osv_from_cache(repo, cache_dir)
    try:
        payload = _http_json(
            OSV_URL, {"package": {"name": repo, "ecosystem": "GIT"}}, timeout=15
        )
    except Exception:
        return None
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    except OSError:
        pass
    vulns = payload.get("vulns") if isinstance(payload, dict) else None
    return bool(vulns) if isinstance(vulns, list) else bool(vulns)


def _osv_from_cache(repo, cache_dir):
    cached = Path(cache_dir) / (hashlib.sha1(repo.encode()).hexdigest() + ".json")
    if not cached.is_file():
        return None
    try:
        payload = json.loads(cached.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    vulns = payload.get("vulns") if isinstance(payload, dict) else None
    return bool(vulns) if isinstance(vulns, list) else bool(vulns)


def _cache_digest(cache_dir):
    """sha256 over the sorted (name, bytes) cache entries; pins the OSV input."""
    digest = hashlib.sha256()
    try:
        entries = sorted(p for p in Path(cache_dir).iterdir() if p.is_file())
    except FileNotFoundError:
        entries = []
    for entry in entries:
        try:
            blob = entry.read_bytes()
        except OSError:
            continue
        digest.update(entry.name.encode())
        digest.update(b"\x00")
        digest.update(blob)
    return digest.hexdigest()


def build_manifest(*, source=None, ref=None, catalogs_dir, cache_dir, no_osv,
                   offline_osv=True):
    if (source is None) == (ref is None):
        raise SystemExit("pass exactly one of --source or --ref")
    if source is not None:
        raw_projects, commit, fetched_at = _read_source_projects(source)
    else:
        raw_projects, commit, fetched_at = _read_ref_projects(ref)
    catalogs = _catalog_dirs(catalogs_dir)
    projects = []
    for entry in raw_projects:
        repo, branch = _split_repo(str(entry["fields"].get("repo", "")))
        projects.append(
            {
                "name": entry["name"],
                "repo": repo,
                "branch": branch,
                "has_threat_model": entry["has_threat_model"],
                "has_dockerfile_here": entry["has_dockerfile_here"],
                "ksm_catalogs": _match_catalogs(entry["name"], repo, catalogs),
                "osv_git_supported": _osv_supported(repo, cache_dir, no_osv,
                                                     offline=offline_osv),
            }
        )
    projects.sort(key=lambda p: p["name"])
    return {
        "source_repo": UPSTREAM,
        "source_commit": commit,
        "fetched_at": fetched_at,
        "osv_cache_digest": (None if no_osv else _cache_digest(cache_dir)),
        "project_count": len(projects),
        "projects": projects,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the OSS Scanner selection manifest.")
    ap.add_argument("--source", default=None, help="local oss-scanner clone")
    ap.add_argument("--ref", default=None, help="pinned upstream commit SHA")
    ap.add_argument("--output", default=str(DEFAULT_OUTPUT))
    ap.add_argument("--catalogs-dir", default=str(DEFAULT_CATALOGS))
    ap.add_argument("--cache-dir", default=str(DEFAULT_CACHE))
    ap.add_argument("--no-osv", action="store_true", help="skip OSV queries (null fields)")
    ap.add_argument("--refresh-osv", action="store_true",
                    help="allow live OSV queries to fill cache misses "
                         "(default: cache only, so checks are reproducible)")
    ap.add_argument("--check", action="store_true", help="fail on drift")
    args = ap.parse_args(argv)

    try:
        manifest = build_manifest(
            source=args.source,
            ref=args.ref,
            catalogs_dir=args.catalogs_dir,
            cache_dir=args.cache_dir,
            no_osv=args.no_osv,
            offline_osv=not args.refresh_osv,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    output = Path(args.output)
    if args.check:
        try:
            current = output.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"missing {output}", file=sys.stderr)
            return 1
        if current != text:
            print(f"drift in {output}: regenerate without --check", file=sys.stderr)
            return 1
        print(f"OK: {output} matches source")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(f"wrote {output} ({manifest['project_count']} projects)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
