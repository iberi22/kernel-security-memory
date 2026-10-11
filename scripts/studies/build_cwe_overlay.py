#!/usr/bin/env python3
r"""Build a deterministic CWE overlay for the CVEs in our catalogs.

The kernel CNA (and several other advisories in ``docs/studies/cve-history``)
publish no CWE, so most merged catalog rows carry ``cwe = null``. This script
recovers a CWE for those ids from public, deterministic feeds and writes
``docs/studies/cwe-overlay.jsonl`` (a CVE -> CWE map with provenance) WITHOUT
ever touching the catalog files, which other scripts rebuild.

Sources, in the documented precedence (highest first) for an id whose merged
catalog row has no CWE:

    1. nvd-primary   NVD 2.0 data feed weakness with type "Primary" and a real
                      CWE-\d+ value (NVD's authoritative mapping).
    2. cisa-adp      CISA ADP container problemTypes with a real CWE
                      (github.com/cisagov/vulnrichment, default branch develop; only
                      used when the id has no NVD Primary CWE). In a real CVE Record
                      the ADP entries carry the CWE in the description's "cweId"
                      field ("value" is accepted too); the text form
                      "CWE-noinfo Not enough information" is not a CWE and is
                      ignored. Use --no-cisa to disable this source.
    3. nvd-secondary NVD 2.0 data feed weakness with type "Secondary" and a real
                      CWE-\d+ value (typically the CNA-stated mapping NVD kept).

Data policy (docs/DATA-POLICY.md): CWE ids are facts and may be stored;
vulnerability descriptions are never stored or printed. The sentinel values
``NVD-CWE-noinfo`` / ``NVD-CWE-Other`` are treated as UNKNOWN (no row emitted)
but counted for the report. No value is invented: a row is written only when a
feed actually provides a matching CWE for an id that appears in our catalogs.

Feeds are cached in gitignored directories (docs/studies/nvd-cache/,
docs/studies/cisa-cache/) and are never committed. The committed overlay records
only the feed and a single ``feed_ref`` per row -- the sha256 of the cached NVD
.gz, or the vulnrichment commit SHA the CISA record was read from -- so
``--offline --check`` recomputes byte-for-byte from the caches and exits non-zero
on drift.

The CISA feed is fetched as one shallow, blob-filtered git clone
(git clone --depth 1 --filter=blob:none --sparse) with a sparse checkout of only
the CVE files actually needed, instead of one HTTP request per CVE. A source
that is unavailable is always reported: the summary names the missing source and
the counts, and ``--offline --check`` refuses to claim a clean bill of health
while the committed overlay carries rows from a source it cannot read.
"""

import argparse
import gzip
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Env overrides (used by tests/test_build_cwe_overlay.py to point at a temp tree).
CVE_HISTORY_DIR = Path(os.environ.get("KSM_CVE_HISTORY_DIR") or ROOT / "docs/studies/cve-history")
CACHE_DIR = Path(os.environ.get("KSM_NVD_CACHE_DIR") or ROOT / "docs/studies/nvd-cache")
CISA_CACHE_DIR = Path(os.environ.get("KSM_CISA_CACHE_DIR") or ROOT / "docs/studies/cisa-cache")
OVERLAY_PATH = Path(os.environ.get("KSM_OVERLAY_PATH") or ROOT / "docs/studies/cwe-overlay.jsonl")

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
CISA_REPO_URL = "https://github.com/cisagov/vulnrichment"
CISA_REPO_DIRNAME = "vulnrichment"
USER_AGENT = "ksm-cwe-overlay/1.0 (+https://github.com/iberi22/kernel-security-memory)"

CWE_RE = re.compile(r"^CWE-\d+$")
CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
SENTINELS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}
MIN_DELAY_S = 0.4
MAX_ATTEMPTS = 6
REQUEST_TIMEOUT_S = 600  # yearly feeds run to ~30 MB gz on a slow link


# --- catalog targets ------------------------------------------------------

def load_catalog_targets():
    """Return {advisory_id: {"year", "projects": set, "catalog_cwe": bool}}.

    Mirrors cluster_patterns' merged view (union across catalogs): an id counts
    as having a catalog CWE when any catalog row for it states a real CWE.
    """
    targets = {}
    for pdir in sorted(CVE_HISTORY_DIR.glob("*")):
        catalog = pdir / "catalog.jsonl"
        if not catalog.exists():
            continue
        project = pdir.name
        for line in catalog.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            advisory_id = entry.get("advisory_id")
            if not isinstance(advisory_id, str):
                continue
            m = CVE_ID_RE.match(advisory_id)
            if not m:
                continue
            rec = targets.get(advisory_id)
            if rec is None:
                rec = {"year": int(m.group(1)), "projects": set(), "catalog_cwe": False}
                targets[advisory_id] = rec
            rec["projects"].add(project)
            cwe = entry.get("cwe")
            if isinstance(cwe, str) and CWE_RE.match(cwe.strip()):
                rec["catalog_cwe"] = True
    return targets


# --- NVD feed handling ----------------------------------------------------

def feed_filename(year):
    return f"nvdcve-2.0-{year}.json.gz"


def feed_path(year):
    return CACHE_DIR / feed_filename(year)


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download_feed(year):
    """Download one yearly NVD feed into the cache with retry + Range resume.

    Returns True when a valid gzip is present in the cache afterwards.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = feed_path(year)
    url = NVD_FEED_URL.format(year=year)
    last = 0.0
    for attempt in range(MAX_ATTEMPTS):
        # Resume a partial download when possible.
        resume_from = dest.stat().st_size if dest.exists() else 0
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        if resume_from:
            headers["Range"] = f"bytes={resume_from}-"
        req = urllib.request.Request(url, headers=headers)
        try:
            now = time.monotonic()
            if now - last < MIN_DELAY_S:
                time.sleep(MIN_DELAY_S - (now - last))
            last = time.monotonic()
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:
                mode = "ab" if resume_from and resp.status == 206 else "wb"
                with open(dest, mode) as out:
                    while True:
                        chunk = resp.read(1 << 20)
                        if not chunk:
                            break
                        out.write(chunk)
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return False  # no feed for this year (e.g. pre-2002)
            if err.code == 416:
                # Range past EOF: the file is already complete.
                if _gzip_ok(dest):
                    return True
            time.sleep(2.0 ** attempt)
            continue
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            time.sleep(2.0 ** attempt)
            continue
        if _gzip_ok(dest):
            return True
    return _gzip_ok(dest)


def _gzip_ok(path):
    if not path.exists():
        return False
    try:
        with gzip.open(path, "rb") as fh:
            fh.read(1)
        return True
    except (OSError, EOFError):
        return False


def extract_nvd_cwes(cve_item):
    """Classify an NVD CVE item's weaknesses.

    Returns (primary, secondary, sentinel_count, distinct) where primary /
    secondary are ordered de-duplicated lists of real CWE ids of that weakness
    type, sentinel_count counts NVD-CWE-noinfo/Other description occurrences,
    and distinct is the ordered union used to count alternates.
    """

    def collect(weakness_type):
        out = []
        for w in cve_item.get("weaknesses", []) or []:
            if not isinstance(w, dict) or w.get("type") != weakness_type:
                continue
            for d in w.get("description", []) or []:
                val = d.get("value", "") if isinstance(d, dict) else ""
                if isinstance(val, str):
                    val = val.strip().upper()
                    if CWE_RE.match(val) and val not in out:
                        out.append(val)
        return out

    primary = collect("Primary")
    secondary = collect("Secondary")

    sentinel_count = 0
    for w in cve_item.get("weaknesses", []) or []:
        if not isinstance(w, dict):
            continue
        for d in w.get("description", []) or []:
            val = d.get("value", "") if isinstance(d, dict) else ""
            if isinstance(val, str) and val in SENTINELS:
                sentinel_count += 1

    distinct = list(primary)
    for c in secondary:
        if c not in distinct:
            distinct.append(c)
    return primary, secondary, sentinel_count, distinct


def build_nvd_index(needed_years, target_ids, offline):
    """Return ({id: (primary, secondary, sentinel_count, distinct)}, feed_sha, stats)."""
    index = {}
    feed_sha = {}
    stats = {
        "feeds_used": [],
        "feeds_missing": [],
        "sentinel_noinfo_or_other": 0,
        "primary_rows": 0,
        "secondary_rows": 0,
        "no_real_cwe": 0,
        "network_downloads": 0,
    }
    seen_ids = set()
    for year in sorted(needed_years):
        path = feed_path(year)
        if not _gzip_ok(path):
            if offline:
                stats["feeds_missing"].append(year)
                continue
            if _download_feed(year):
                stats["network_downloads"] += 1
            else:
                stats["feeds_missing"].append(year)
                continue
        stats["feeds_used"].append(year)
        feed_sha[year] = sha256_file(path)
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        for vuln in data.get("vulnerabilities", []) or []:
            cve = vuln.get("cve", {}) if isinstance(vuln, dict) else {}
            advisory_id = cve.get("id")
            if advisory_id not in target_ids:
                continue
            if advisory_id in seen_ids:
                continue
            primary, secondary, sentinels, distinct = extract_nvd_cwes(cve)
            if sentinels:
                stats["sentinel_noinfo_or_other"] += 1
            if primary:
                stats["primary_rows"] += 1
            elif secondary:
                stats["secondary_rows"] += 1
            elif distinct or sentinels:
                stats["no_real_cwe"] += 1
            seen_ids.add(advisory_id)
            if primary or secondary:
                index[advisory_id] = (primary, secondary, sentinels, distinct)
    return index, feed_sha, stats


# --- CISA ADP (vulnrichment) --------------------------------------------
#
# The feed is fetched as one shallow, blob-filtered clone into the gitignored
# docs/studies/cisa-cache/vulnrichment.  A real record looks like:
#
#   {"dataType": "CVE_RECORD",
#    "cveMetadata": {"cveId": "CVE-2021-3156", ...},
#    "containers": {"cna": {...},
#                   "adp": [{"title": "CVE Program Container", ...},
#                            {"title": "CISA ADP Vulnrichment",
#                             "problemTypes": [{"descriptions": [{
#                                 "lang": "en", "type": "CWE",
#                                 "cweId": "CWE-193",
#                                 "description": "CWE-193 Off-by-one Error"}]}],
#                             "providerMetadata": {...}}]}}
#
# so the CWE lives in the description's "cweId" key, and the same entry may
# instead be a text-only description such as "CWE-noinfo Not enough
# information", which is not a CWE.  Files sit at <year>/<block>xxx/<CVE-ID>.json
# where <block> is the sequence number truncated to thousands (CVE-2021-3156 ->
# 2021/3xxx/), so only the blocks containing the ids we need are checked out.

def cisa_repo_dir():
    return CISA_CACHE_DIR / CISA_REPO_DIRNAME


def cisa_relpath(cve):
    """Repo-relative path of a CVE record (verified against the real repo tree)."""
    m = CVE_ID_RE.match(cve)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)[:-3]}xxx/{cve}.json"


def _git(repo, *args, stdin=None):
    return subprocess.run(["git", "-C", str(repo), *args], input=stdin,
                          capture_output=True, text=True)


def ensure_cisa_clone(offline):
    """Clone or refresh the vulnrichment checkout; return (commit_sha, error).

    The clone is shallow and blob-filtered: 23 MB of trees with no file contents,
    which are then fetched on demand by the sparse checkout of needed ids only.
    Never raises: an unreachable feed is reported through the returned error.
    """
    repo = cisa_repo_dir()
    note = None
    if not (repo / ".git").exists():
        if offline:
            return None, f"no clone at {repo} (run once with network access)"
        CISA_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(["git", "clone", "--quiet", "--depth", "1",
                              "--filter=blob:none", "--sparse",
                              CISA_REPO_URL, str(repo)],
                             capture_output=True, text=True)
        if res.returncode != 0:
            return None, f"clone failed: {res.stderr.strip()[:160] or res.stdout.strip()[:160]}"
    elif not offline:
        res = _git(repo, "fetch", "--quiet", "--depth", "1", "origin")
        if res.returncode == 0:
            _git(repo, "reset", "--quiet", "--hard", "FETCH_HEAD")
        else:
            # A failed refresh is not fatal: the existing checkout is still
            # usable data; the caller reports it as a warning.
            note = f"refresh failed: {res.stderr.strip()[:160]}"
    head = _git(repo, "rev-parse", "HEAD")
    if head.returncode != 0:
        return None, f"unreadable clone at {repo}"
    return head.stdout.strip(), note


def cisa_repo_ids(years):
    """{cve_id: repo-relative path} for every record the clone has in `years`.

    Reads the commit tree only (a blob-filtered clone keeps every tree object
    locally), so this costs no blob fetches and no HTTP requests.
    """
    repo = cisa_repo_dir()
    found = {}
    for year in sorted(years):
        res = _git(repo, "ls-tree", "-r", "--name-only", "HEAD", "--", str(year))
        if res.returncode != 0:
            return None, res.stderr.strip()[:160]
        for line in res.stdout.splitlines():
            cve = line.rsplit("/", 1)[-1][:-5] if line.endswith(".json") else ""
            if not cve or cisa_relpath(cve) != line:
                continue  # the path must agree with the id, or it is filed elsewhere
            found[cve] = line
    return found, None


def cisa_materialize(relpaths, offline):
    """Sparse-checkout the wanted paths; return (missing_paths, error)."""
    repo = cisa_repo_dir()
    wanted = sorted(set(relpaths))
    present = {p for p in wanted if (repo / p).exists()}
    missing = [p for p in wanted if p not in present]
    if not missing:
        return [], None
    if offline:
        return missing, None
    cone = _git(repo, "config", "--get", "core.sparseCheckoutCone").stdout.strip()
    patterns = "\n".join("/" + p for p in missing)
    if cone == "false":
        res = _git(repo, "sparse-checkout", "add", "--stdin", stdin=patterns)
    else:
        res = _git(repo, "sparse-checkout", "set", "--no-cone", "--stdin", stdin=patterns)
    if res.returncode != 0:
        return missing, res.stderr.strip()[:160]
    missing = [p for p in missing if not (repo / p).exists()]
    return missing, None


def extract_cisa_cwes(doc):
    """Ordered, de-duplicated real CWE ids from a vulnrichment ADP container."""
    out = []
    containers = doc.get("containers", {}) if isinstance(doc, dict) else {}
    for adp in containers.get("adp", []) or []:
        if not isinstance(adp, dict):
            continue
        for pt in adp.get("problemTypes", []) or []:
            if not isinstance(pt, dict):
                continue
            for d in pt.get("descriptions", []) or []:
                if not isinstance(d, dict):
                    continue
                val = d.get("cweId") or d.get("value") or ""
                if isinstance(val, str):
                    val = val.strip().upper()
                    if CWE_RE.match(val) and val not in out:
                        out.append(val)
    return out


def cisa_record_cwes(doc, cve):
    """CWEs for `cve` from a vulnrichment record, or None when unusable.

    Unusable means the file is not a CVE Record for this id: the cached file is
    never trusted to hold the id it is filed under.
    """
    if not isinstance(doc, dict):
        return None
    meta = doc.get("cveMetadata")
    if not isinstance(meta, dict) or meta.get("cveId") != cve:
        return None
    if not isinstance(doc.get("containers"), dict):
        return None
    return extract_cisa_cwes(doc)


def build_cisa_index(cves_needing_it, offline, enabled):
    """Return ({id: (cwes, commit_sha)}, commit_sha, stats) from the local clone."""
    index = {}
    stats = {"rows": 0, "in_repo": 0, "not_in_repo": 0, "unreadable": 0,
             "not_checked_out": 0, "id_mismatch": 0, "clone_error": None,
             "commit": None, "years": 0, "no_cwe": 0}
    if not enabled:
        stats["disabled"] = len(cves_needing_it)
        return index, None, stats

    commit, err = ensure_cisa_clone(offline)
    stats["commit"] = commit
    if commit is None:
        stats["clone_error"] = err
        stats["not_in_repo"] = len(cves_needing_it)
        return index, None, stats
    if err:  # refresh failed but the existing checkout was used
        stats["clone_error"] = err

    years = sorted({int(CVE_ID_RE.match(c).group(1)) for c in cves_needing_it
                    if CVE_ID_RE.match(c)})
    stats["years"] = len(years)
    if not years:
        return index, commit, stats
    ids, err = cisa_repo_ids(years)
    if ids is None:
        stats["clone_error"] = f"cannot list the clone: {err}"
        stats["not_in_repo"] = len(cves_needing_it)
        return index, commit, stats

    wanted = {}
    for cve in cves_needing_it:
        rel = ids.get(cve)
        if rel is None:
            stats["not_in_repo"] += 1
            continue
        wanted[cve] = rel
    stats["in_repo"] = len(wanted)

    missing, err = cisa_materialize(wanted.values(), offline)
    if err:
        stats["clone_error"] = f"sparse checkout failed: {err}"
    if missing:
        stats["not_checked_out"] = len(missing)

    repo = cisa_repo_dir()
    for cve, rel in sorted(wanted.items()):
        path = repo / rel
        if not path.exists():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            stats["unreadable"] += 1
            continue
        cwes = cisa_record_cwes(doc, cve)
        if cwes is None:
            stats["id_mismatch"] += 1
            continue
        if not cwes:
            stats["no_cwe"] += 1
            continue
        index[cve] = (cwes, commit)
        stats["rows"] += 1
    return index, commit, stats


def overlay_source_counts(path):
    """{cwe_source: rows} already committed in `path` ({} when absent)."""
    counts = {}
    if not path.exists():
        return counts
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        src = row.get("cwe_source")
        if isinstance(src, str):
            counts[src] = counts.get(src, 0) + 1
    return counts


def _cisa_report(stats):
    """Loud, always-printed CISA status line (never silent about a missing feed)."""
    commit = stats.get("commit") or "MISSING"
    err = f"; {stats['clone_error']}" if stats.get("clone_error") else ""
    print(f"CISA vulnrichment ({CISA_REPO_URL}): clone={cisa_repo_dir()} commit={commit} "
          f"years={stats.get('years', 0)} in_repo={stats.get('in_repo', 0)} "
          f"not_in_repo={stats.get('not_in_repo', 0)} rows={stats.get('rows', 0)} "
          f"no_cwe={stats.get('no_cwe', 0)} disabled={stats.get('disabled', 0)} "
          f"not_checked_out={stats.get('not_checked_out', 0)} "
          f"unreadable={stats.get('unreadable', 0)} "
          f"id_mismatch={stats.get('id_mismatch', 0)}{err}")


# --- overlay assembly -----------------------------------------------------

def assemble_overlay(targets, nvd_index, nvd_feed_sha, cisa_index, cisa_commit):
    """Apply precedence and return (rows, by_source, resolved_ids)."""
    rows = []
    by_source = {}
    resolved = set()
    for advisory_id in sorted(targets):
        rec = targets[advisory_id]
        if rec["catalog_cwe"]:
            continue  # overlay only fills ids with no catalog CWE
        year = rec["year"]
        primary, secondary, sentinels, distinct = (None, None, 0, None)
        if advisory_id in nvd_index:
            primary, secondary, sentinels, distinct = nvd_index[advisory_id]

        chosen = None
        source = None
        feed = None
        feed_ref = None
        if primary:
            chosen, source = primary[0], "nvd-primary"
            feed = NVD_FEED_URL.format(year=year)
            feed_ref = nvd_feed_sha.get(year)
        elif advisory_id in cisa_index:
            cwes, commit = cisa_index[advisory_id]
            chosen, source = cwes[0], "cisa-adp"
            feed = CISA_REPO_URL
            feed_ref = commit
        elif secondary:
            chosen, source = secondary[0], "nvd-secondary"
            feed = NVD_FEED_URL.format(year=year)
            feed_ref = nvd_feed_sha.get(year)

        if chosen is None:
            continue
        alternates = sum(1 for c in (distinct or []) if c != chosen)
        rows.append({
            "advisory_id": advisory_id,
            "cwe": chosen,
            "cwe_source": source,
            "feed": feed,
            # sha256 of the cached NVD .gz, or the vulnrichment commit SHA that
            # the cisa-adp record was read from (the clone has no per-file hash).
            "feed_ref": feed_ref,
            "alternates": alternates,
        })
        by_source[source] = by_source.get(source, 0) + 1
        resolved.add(advisory_id)
    return rows, by_source, resolved


def render_overlay(rows):
    return "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in rows
    )


def summarize(targets, resolved, rows):
    unknown_ids = [i for i, r in targets.items() if not r["catalog_cwe"]]
    before_total = len(unknown_ids)
    before_lcna = sum(1 for i in unknown_ids if "linux-cna" in targets[i]["projects"])
    resolved_lcna = sum(1 for i in resolved if "linux-cna" in targets[i]["projects"])
    return {
        "overlay_rows": len(rows),
        "unknown_before_total": before_total,
        "unknown_after_total": before_total - len(rows),
        "unknown_before_linux_cna": before_lcna,
        "unknown_after_linux_cna": before_lcna - resolved_lcna,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true",
                        help="Use only the feed caches; never open a connection")
    parser.add_argument("--check", action="store_true",
                        help="Recompute from the caches and exit non-zero if docs/studies/cwe-overlay.jsonl drifted")
    parser.add_argument("--no-cisa", action="store_true",
                        help="Do not consult the CISA ADP feed (docs/studies/cisa-cache/vulnrichment)")
    args = parser.parse_args(argv)
    use_cisa = not args.no_cisa

    targets = load_catalog_targets()
    unknown_ids = [i for i, r in targets.items() if not r["catalog_cwe"]]
    needed_years = sorted({targets[i]["year"] for i in unknown_ids})
    target_ids = set(unknown_ids)

    nvd_cache_present = any(CACHE_DIR.glob("nvdcve-2.0-*.json.gz"))
    cisa_clone_present = (cisa_repo_dir() / ".git").exists()
    missing_sources = []
    if not nvd_cache_present:
        missing_sources.append(f"nvd-primary/nvd-secondary NVD feeds in {CACHE_DIR}")
    if use_cisa and not cisa_clone_present:
        missing_sources.append(f"cisa-adp CISA vulnrichment clone in {cisa_repo_dir()}")

    if args.check and missing_sources:
        committed = overlay_source_counts(OVERLAY_PATH)
        blocked = []
        if not cisa_clone_present and "cisa-adp" in committed:
            blocked.append("cisa-adp")
        if not nvd_cache_present:
            blocked += [s for s in committed if s.startswith("nvd-")]
        for src in missing_sources:
            print(f"Error: --check cannot recompute from a missing feed: {src}. Run "
                  f"'python3 {Path(__file__).name}' once with network access to populate the "
                  f"cache, then re-run --check.", file=sys.stderr)
        if blocked:
            print("Refusing to report a clean check: docs/studies/cwe-overlay.jsonl carries "
                  "rows from " + ", ".join(f"{s}={committed[s]}" for s in sorted(blocked)) +
                  ", which cannot be read here.", file=sys.stderr)
            raise SystemExit(2)

    nvd_index, nvd_feed_sha, nvd_stats = build_nvd_index(needed_years, target_ids, args.offline)

    cisa_needing = [i for i in sorted(unknown_ids)
                    if i not in nvd_index or not nvd_index[i][0]]
    cisa_index, cisa_commit, cisa_stats = build_cisa_index(
        cisa_needing, args.offline, use_cisa)
    if cisa_stats.get("clone_error"):
        print(f"Warning: CISA vulnrichment ({CISA_REPO_URL}) not fully usable: "
              f"{cisa_stats['clone_error']}; cisa-adp contributes only what is already "
              f"checked out.", file=sys.stderr)
    if use_cisa and not cisa_index:
        print("Warning: CISA ADP contributed no rows although cisa-adp is enabled; "
              "the summary below says why (missing clone, no matching records, or no "
              "CWE in the ADP container).", file=sys.stderr)

    rows, by_source, resolved = assemble_overlay(targets, nvd_index, nvd_feed_sha,
                                                cisa_index, cisa_commit)
    content = render_overlay(rows)
    summary = summarize(targets, resolved, rows)

    if args.check:
        current = OVERLAY_PATH.read_text(encoding="utf-8") if OVERLAY_PATH.exists() else ""
        if current != content:
            print(f"Error: {OVERLAY_PATH.name} drifted from the cached feeds; "
                  f"run build_cwe_overlay.py (with network) to regenerate it.", file=sys.stderr)
            raise SystemExit(1)
        print(f"Overlay check OK: {summary['overlay_rows']} rows, "
              f"{summary['unknown_after_total']} CVEs still UNKNOWN "
              f"(linux-cna {summary['unknown_after_linux_cna']}).")
        _report(summary, by_source, nvd_stats, cisa_stats)
        return

    OVERLAY_PATH.parent.mkdir(parents=True, exist_ok=True)
    OVERLAY_PATH.write_text(content, encoding="utf-8")
    _report(summary, by_source, nvd_stats, cisa_stats)
    print(f"Wrote {OVERLAY_PATH} ({len(rows)} rows, "
          f"{'offline' if args.offline else 'network'} mode).")


def _report(summary, by_source, nvd_stats, cisa_stats):
    order = ["nvd-primary", "cisa-adp", "nvd-secondary"]
    parts = ", ".join(f"{s}={by_source.get(s, 0)}" for s in order)
    print(f"overlay rows by source: {parts} (total {summary['overlay_rows']})")
    print(f"NVD feeds used: {len(nvd_stats['feeds_used'])} year(s); "
          f"missing: {len(nvd_stats['feeds_missing'])}; "
          f"downloaded: {nvd_stats['network_downloads']}; "
          f"NVD-CWE-noinfo/Other count={nvd_stats['sentinel_noinfo_or_other']}")
    _cisa_report(cisa_stats)
    print(f"UNKNOWN before -> after (overall): "
          f"{summary['unknown_before_total']} -> {summary['unknown_after_total']}")
    print(f"UNKNOWN before -> after (linux-cna): "
          f"{summary['unknown_before_linux_cna']} -> {summary['unknown_after_linux_cna']}")


if __name__ == "__main__":
    main()
