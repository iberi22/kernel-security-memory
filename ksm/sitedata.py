"""Vulnerability Atlas site data builder."""

from collections import defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
from typing import Any, Dict, List, Optional, Set, Tuple

from ksm.cwe_groups import GROUP_NAMES, get_cwe_group
from ksm.related import compute_related_and_vectors

SAFE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Za-z0-9-]+$")

REPO_MAP: Dict[str, Optional[str]] = {
    "linux": "torvalds/linux",
    "curl": "curl/curl",
    "openssl": "openssl/openssl",
    "git": "git/git",
    "sqlite": "sqlite/sqlite",
    "systemd": "systemd/systemd",
    "postgresql": "postgres/postgres",
}


def project_from_catalog(cat_name: str) -> str:
    """Determine canonical project name from catalog name."""
    name = cat_name
    if name.endswith("-upstream"):
        name = name[:-len("-upstream")]
    elif name.endswith("-cna"):
        name = name[:-len("-cna")]
    if name == "postgres":
        name = "postgresql"
    return name


def fix_url_for_commit(project: str, sha: str, repo: Optional[str] = None) -> Optional[str]:
    """Return the commit URL for a fix SHA."""
    if project == "linux":
        return f"https://git.kernel.org/linus/{sha}"
    repo_used = repo or REPO_MAP.get(project)
    if repo_used:
        return f"https://github.com/{repo_used}/commit/{sha}"
    return None


def get_git_commit(repo_root: Path) -> str:
    """Get HEAD commit SHA of the repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "0" * 40


def get_generated_timestamp(repo_root: Path) -> str:
    """Get reproducible ISO-8601 timestamp."""
    if "SOURCE_DATE_EPOCH" in os.environ:
        try:
            epoch = int(os.environ["SOURCE_DATE_EPOCH"])
            return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        except ValueError:
            pass
    try:
        res = subprocess.run(
            ["git", "log", "-1", "--format=%cI"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        t = res.stdout.strip()
        if t:
            return t
    except Exception:
        pass
    return "1970-01-01T00:00:00+00:00"


def write_json(path: Path, data: Any) -> None:
    """Write deterministic formatted JSON with sort_keys and trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(content, encoding="utf-8")


def simplify_fragment(frag_raw: Dict[str, Any]) -> Dict[str, Any]:
    """Extract fragments shape matching VULN-ATLAS.md Section 5.1."""
    files = []
    for f in frag_raw.get("files", []):
        funcs = []
        for fn in f.get("functions", []):
            funcs.append({
                "after_range": fn.get("after_range", [0, 0]),
                "before_range": fn.get("before_range", [0, 0]),
                "lines_added": fn.get("lines_added", 0),
                "lines_removed": fn.get("lines_removed", 0),
                "name": fn.get("name", ""),
            })
        files.append({
            "after_blob_sha": f.get("after_blob_sha", ""),
            "before_blob_sha": f.get("before_blob_sha", ""),
            "functions": funcs,
            "language": f.get("language", ""),
            "path": f.get("path", ""),
            "status": f.get("status", "modified"),
        })
    return {
        "coverage": frag_raw.get("coverage", "OK"),
        "files": files,
    }


def simplify_fingerprint(fp_raw: Dict[str, Any]) -> Dict[str, Any]:
    """Extract fingerprint shape matching VULN-ATLAS.md Section 5.1."""
    functions = []
    # If already flat functions
    raw_funcs = fp_raw.get("functions", [])
    if raw_funcs:
        for fn in raw_funcs:
            delta = fn.get("delta", fn)
            functions.append({
                "added_calls": delta.get("added_calls", []),
                "added_guards": delta.get("added_guards", []),
                "name": fn.get("name", ""),
                "path": fn.get("path", ""),
                "removed_calls": delta.get("removed_calls", []),
            })
    elif "files" in fp_raw:
        for f in fp_raw.get("files", []):
            fpath = f.get("path", "")
            for fn in f.get("functions", []):
                delta = fn.get("delta", fn)
                before, after = fn.get("before") or {}, fn.get("after") or {}
                functions.append({
                    "added_calls": delta.get("added_calls", []),
                    "added_guards": delta.get("added_guards", []),
                    "after_range": [after["start_line"], after["end_line"]] if after else None,
                    "before_range": [before["start_line"], before["end_line"]] if before else None,
                    "name": fn.get("name", ""),
                    "path": fpath,
                    "removed_calls": delta.get("removed_calls", []),
                })

    return {
        "fix_sha": fp_raw.get("fix_sha", ""),
        "functions": functions,
        "parent_sha": fp_raw.get("parent_sha", ""),
    }


def build_site_data(
    repo_root: Path,
    out_dir: Path,
    no_bundle: bool = False,
) -> None:
    """Build all Vulnerability Atlas site data files."""
    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    studies_dir = repo_root / "docs" / "studies"
    cve_history_dir = studies_dir / "cve-history"

    # 1. Load pattern_clusters.json for CWE titles
    cluster_titles: Dict[str, str] = {}
    pattern_clusters_file = studies_dir / "pattern_clusters.json"
    if pattern_clusters_file.is_file():
        try:
            with open(pattern_clusters_file, encoding="utf-8") as f:
                p_data = json.load(f)
                for cl in p_data.get("clusters", []):
                    c_id = cl.get("cwe_id")
                    c_title = cl.get("title")
                    if c_id and c_title:
                        cluster_titles[c_id] = c_title
        except Exception:
            pass

    # Official MITRE names override cluster titles (which fall back to
    # "CWE Family CWE-n" when a cluster has no curated title).
    cwe_names_notice = None
    cwe_names_file = studies_dir / "cwe-names.json"
    if cwe_names_file.is_file():
        with open(cwe_names_file, encoding="utf-8") as f:
            names_doc = json.load(f)
        cluster_titles.update(names_doc.get("names", {}))
        cwe_names_notice = names_doc.get("notice")

    unknown_cwe_title = cluster_titles.get(
        "UNKNOWN",
        "Unstated or Legacy Advisory Without CWE Classification",
    )

    # 2. Load CWE overlay
    overlay: Dict[str, Tuple[str, str]] = {}
    overlay_file = studies_dir / "cwe-overlay.jsonl"
    if overlay_file.is_file():
        with open(overlay_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    adv_id = obj.get("advisory_id")
                    cwe_val = obj.get("cwe")
                    cwe_src = obj.get("cwe_source")
                    if adv_id and cwe_val:
                        overlay[adv_id] = (cwe_val, cwe_src or "overlay")
                except Exception:
                    pass

    # 3. Load Fragments
    fragments_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    fragments_dir = studies_dir / "fragments"
    if fragments_dir.is_dir():
        for frag_p in sorted(fragments_dir.glob("*.json")):
            try:
                with open(frag_p, encoding="utf-8") as f:
                    frag_json = json.load(f)
                stem = frag_p.stem
                m = re.match(r"^([a-zA-Z0-9_-]+)-(CVE-\d+-\d+)", stem)
                if m:
                    proj = m.group(1)
                    if proj == "postgres":
                        proj = "postgresql"
                    cid = m.group(2)
                    fragments_map[(proj, cid)] = frag_json
            except Exception:
                pass

    # 4. Load Fingerprints
    fingerprints_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    fingerprints_dir = studies_dir / "fingerprints"
    if fingerprints_dir.is_dir():
        for fp_file in sorted(fingerprints_dir.glob("*/*.json")):
            try:
                proj = project_from_catalog(fp_file.parent.name)
                cid = fp_file.stem
                with open(fp_file, encoding="utf-8") as f:
                    fp_json = json.load(f)
                fingerprints_map[(proj, cid)] = fp_json
            except Exception:
                pass

    # 5. Read and merge catalogs into projects
    merged_cves: Dict[Tuple[str, str], Dict[str, Any]] = {}
    catalogs_per_project: Dict[str, Set[str]] = defaultdict(set)

    catalog_dirs = sorted([d for d in cve_history_dir.glob("*") if d.is_dir()])
    for cdir in catalog_dirs:
        cat_file = cdir / "catalog.jsonl"
        if not cat_file.is_file():
            continue
        cat_name = cdir.name
        proj_name = project_from_catalog(cat_name)
        catalogs_per_project[proj_name].add(cat_name)
        is_upstream_or_cna = cat_name.endswith("-upstream") or cat_name.endswith("-cna")

        with open(cat_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                adv_id = row.get("advisory_id")
                # Ids become file names (cve/<project>/<id>.json): no separators.
                if not adv_id or not SAFE_ID_RE.match(adv_id):
                    continue
                key = (proj_name, adv_id)

                if key not in merged_cves:
                    cwe_val = row.get("cwe")
                    merged_cves[key] = {
                        "id": adv_id,
                        "project": proj_name,
                        "cwe": cwe_val,
                        "cwe_source": "catalog" if cwe_val else None,
                        "published": row.get("published"),
                        "subsystem": row.get("subsystem"),
                        "fix_shas": list(row.get("fix_shas") or []),
                        "patch_urls": list(row.get("patch_urls") or []),
                        "catalogs": [cat_name],
                        "repo": row.get("repo"),
                        "aliases": list(row.get("aliases") or []),
                    }
                else:
                    entry = merged_cves[key]
                    if cat_name not in entry["catalogs"]:
                        entry["catalogs"].append(cat_name)
                    # Union fix_shas preserving order
                    for s in (row.get("fix_shas") or []):
                        if s not in entry["fix_shas"]:
                            entry["fix_shas"].append(s)
                    # Union patch_urls preserving order
                    for u in (row.get("patch_urls") or []):
                        if u not in entry["patch_urls"]:
                            entry["patch_urls"].append(u)
                    # Union aliases preserving order
                    for a in (row.get("aliases") or []):
                        if a not in entry.setdefault("aliases", []):
                            entry["aliases"].append(a)
                    if row.get("repo") and not entry.get("repo"):
                        entry["repo"] = row["repo"]
                    # cwe/published from -upstream/-cna row when present
                    if is_upstream_or_cna:
                        if row.get("cwe") is not None:
                            entry["cwe"] = row.get("cwe")
                            entry["cwe_source"] = "catalog"
                        if row.get("published") is not None:
                            entry["published"] = row.get("published")
                        if row.get("subsystem") is not None:
                            entry["subsystem"] = row.get("subsystem")
                    else:
                        if entry["cwe"] is None and row.get("cwe") is not None:
                            entry["cwe"] = row.get("cwe")
                            entry["cwe_source"] = "catalog"
                        if entry["published"] is None and row.get("published") is not None:
                            entry["published"] = row.get("published")
                        if entry["subsystem"] is None and row.get("subsystem") is not None:
                            entry["subsystem"] = row.get("subsystem")

    # 5b. Evidence-pack CVEs (fragments) and fingerprinted CVEs that no catalog
    # lists still belong in the atlas; their fix commit comes from that evidence.
    for (proj_name, adv_id), ev in sorted(
            list(fragments_map.items()) + list(fingerprints_map.items()), key=lambda kv: kv[0]):
        key = (proj_name, adv_id)
        if key in merged_cves or not SAFE_ID_RE.match(adv_id):
            continue
        sha = ev.get("fix_commit") or ev.get("fix_sha")
        merged_cves[key] = {
            "id": adv_id,
            "project": proj_name,
            "cwe": ev.get("cwe"),
            "cwe_source": "catalog" if ev.get("cwe") else None,
            "published": None,
            "subsystem": None,
            "fix_shas": [sha] if sha else [],
            "patch_urls": [],
            "catalogs": ["pack" if key in fragments_map else "fingerprints"],
            "repo": ev.get("repo"),
            "aliases": list(ev.get("aliases") or []),
        }
        catalogs_per_project[proj_name].add(merged_cves[key]["catalogs"][0])

    # 6. Apply overlay where catalog CWE is null
    for key, entry in merged_cves.items():
        if entry["cwe"] is None and entry["id"] in overlay:
            entry["cwe"] = overlay[entry["id"]][0]
            entry["cwe_source"] = overlay[entry["id"]][1]

    # 7. Compute related neighbours and sparse feature vectors
    related_map, vectors_map = compute_related_and_vectors(
        merged_cves,
        fragments_map=fragments_map,
        fingerprints_map=fingerprints_map,
    )

    # 8. Build files
    # Output structure:
    # index.json
    # cwe/<id>.json
    # cve/<project>/<id>.json
    # search.json
    # vectors.jsonl
    # bundle.tar.gz + bundle.sha256

    search_rows: List[List[Any]] = []
    cwe_rows_map: Dict[str, List[List[Any]]] = defaultdict(list)
    project_stats: Dict[str, Dict[str, Any]] = {}

    for proj in sorted(catalogs_per_project.keys()):
        project_stats[proj] = {
            "name": proj,
            "repo": REPO_MAP.get(proj),
            "catalogs": sorted(catalogs_per_project[proj]),
            "cves": 0,
            "with_fix": 0,
            "with_fragments": 0,
            "with_fingerprint": 0,
            "years": defaultdict(int),
        }

    # Group counts
    group_cve_counts: Dict[str, int] = defaultdict(int)
    cwe_info_map: Dict[str, Dict[str, Any]] = {}

    for key in sorted(merged_cves.keys()):
        entry = merged_cves[key]
        proj = entry["project"]
        adv_id = entry["id"]
        cwe_id = entry["cwe"]

        # Fragments and fingerprint data
        raw_frag = fragments_map.get(key)
        raw_fp = fingerprints_map.get(key)
        frag_obj = simplify_fragment(raw_frag) if raw_frag else None
        fp_obj = simplify_fingerprint(raw_fp) if raw_fp else None

        has_fix = len(entry["fix_shas"]) > 0
        has_fragments = frag_obj is not None
        has_fingerprint = fp_obj is not None

        # Project stats update
        pstat = project_stats[proj]
        pstat["cves"] += 1
        if has_fix:
            pstat["with_fix"] += 1
        if has_fragments:
            pstat["with_fragments"] += 1
        if has_fingerprint:
            pstat["with_fingerprint"] += 1

        pub = entry["published"]
        if pub and len(pub) >= 4 and pub[:4].isdigit():
            pstat["years"][pub[:4]] += 1

        # CWE ID and Group
        cwe_key = cwe_id if (cwe_id and re.match(r"^CWE-\d+$", cwe_id)) else "UNKNOWN"
        cwe_grp = get_cwe_group(cwe_key)
        group_cve_counts[cwe_grp] += 1

        if cwe_key not in cwe_info_map:
            cwe_name = cluster_titles.get(cwe_key, cwe_key) if cwe_key != "UNKNOWN" else unknown_cwe_title
            cwe_info_map[cwe_key] = {
                "id": cwe_key,
                "name": cwe_name,
                "group": cwe_grp,
                "cves": 0,
                "projects": defaultdict(int),
            }
        cwe_info_map[cwe_key]["cves"] += 1
        cwe_info_map[cwe_key]["projects"][proj] += 1

        # cwe/<id>.json row
        cwe_rows_map[cwe_key].append([
            adv_id,
            proj,
            pub,
            has_fix,
            has_fragments,
            has_fingerprint,
        ])

        # Function names and aliases for search.json
        fn_set = set()
        if frag_obj:
            for f in frag_obj["files"]:
                for fn in f["functions"]:
                    if fn["name"]:
                        fn_set.add(fn["name"])
        if fp_obj:
            for fn in fp_obj["functions"]:
                if fn["name"]:
                    fn_set.add(fn["name"])
        text_tokens = sorted(fn_set)
        aliases = sorted(entry.get("aliases") or [])
        if aliases:
            text_tokens.extend(aliases)
        fn_str = " ".join(text_tokens)

        search_rows.append([
            adv_id,
            proj,
            cwe_id,
            entry["subsystem"],
            fn_str,
        ])

        # cve/<project>/<CVE>.json
        cve_name = cluster_titles.get(cwe_id) if cwe_id else None
        repo_used = entry.get("repo") or REPO_MAP.get(proj)
        fixes = []
        for sha in entry["fix_shas"]:
            fixes.append({
                "sha": sha,
                "url": fix_url_for_commit(proj, sha, repo=repo_used),
            })

        cve_doc = {
            "aliases": sorted(entry.get("aliases") or []),
            "catalogs": sorted(entry["catalogs"]),
            "cwe": cwe_id,
            "cwe_name": cve_name,
            "cwe_source": entry["cwe_source"],
            "fingerprint": fp_obj,
            "fixes": fixes,
            "fragments": frag_obj,
            "group": cwe_grp,
            "id": adv_id,
            "patch_urls": sorted(entry["patch_urls"]),
            "project": proj,
            "published": pub,
            "related": related_map.get(key, []),
            "repo": repo_used,
            "subsystem": entry["subsystem"],
        }
        write_json(out_dir / "cve" / proj / f"{adv_id}.json", cve_doc)

    # Write cwe/<id>.json files
    # Rows sorted by published desc then id asc
    for cwe_key, rows in cwe_rows_map.items():
        sorted_rows = sorted(
            rows,
            key=lambda r: (0 if r[2] else 1, tuple(-ord(c) for c in (r[2] or "")), r[0]),
        )
        cwe_doc = {
            "group": cwe_info_map[cwe_key]["group"],
            "id": cwe_key,
            "name": cwe_info_map[cwe_key]["name"],
            "rows": sorted_rows,
        }
        write_json(out_dir / "cwe" / f"{cwe_key}.json", cwe_doc)

    # Write search.json
    search_rows.sort(key=lambda r: (r[1], r[0]))
    write_json(out_dir / "search.json", search_rows)

    # Write vectors.jsonl
    vectors_file = out_dir / "vectors.jsonl"
    with open(vectors_file, "w", encoding="utf-8") as vf:
        for key in sorted(merged_cves.keys(), key=lambda k: k[1]):
            adv_id = key[1]
            vec = vectors_map.get(key, {})
            line = json.dumps({"features": vec, "id": adv_id}, sort_keys=True, separators=(",", ":")) + "\n"
            vf.write(line)

    # Groups array for index.json
    groups_list = []
    for gname in GROUP_NAMES:
        # Collect cwes in this group
        cwes_in_group = [
            info for info in cwe_info_map.values()
            if info["group"] == gname
        ]
        cwes_in_group.sort(key=lambda c: c["id"])
        formatted_cwes = [
            {
                "cves": c["cves"],
                "id": c["id"],
                "name": c["name"],
                "projects": dict(sorted(c["projects"].items())),
            }
            for c in cwes_in_group
        ]
        groups_list.append({
            "cves": group_cve_counts.get(gname, 0),
            "cwes": formatted_cwes,
            "name": gname,
        })

    # Projects list for index.json
    projects_list = []
    for proj in sorted(project_stats.keys()):
        pdata = project_stats[proj]
        projects_list.append({
            "catalogs": pdata["catalogs"],
            "cves": pdata["cves"],
            "name": pdata["name"],
            "repo": pdata["repo"],
            "with_fingerprint": pdata["with_fingerprint"],
            "with_fix": pdata["with_fix"],
            "with_fragments": pdata["with_fragments"],
            "years": dict(sorted(pdata["years"].items())),
        })

    total_cves = len(merged_cves)
    total_with_fix = sum(1 for e in merged_cves.values() if len(e["fix_shas"]) > 0)
    total_with_frag = sum(1 for k in merged_cves.keys() if k in fragments_map)
    total_with_fp = sum(1 for k in merged_cves.keys() if k in fingerprints_map)

    index_doc = {
        "generated": get_generated_timestamp(repo_root),
        "groups": groups_list,
        "ksm_commit": get_git_commit(repo_root),
        "projects": projects_list,
        "schema": "ksm-site/1",
        "cwe_names_notice": cwe_names_notice,
        "totals": {
            "cves": total_cves,
            "projects": len(project_stats),
            "with_fingerprint": total_with_fp,
            "with_fix": total_with_fix,
            "with_fragments": total_with_frag,
        },
    }
    write_json(out_dir / "index.json", index_doc)

    # Bundle creation
    if not no_bundle:
        bundle_path = out_dir / "bundle.tar.gz"
        sha_path = out_dir / "bundle.sha256"

        files_to_pack: List[Tuple[str, Path]] = []

        # Add files in out_dir: index.json, search.json, vectors.jsonl, cwe/, cve/
        for p in out_dir.rglob("*"):
            if p.is_file() and p.name not in ("bundle.tar.gz", "bundle.sha256"):
                arcname = str(p.relative_to(out_dir))
                files_to_pack.append((arcname, p))

        # Add pattern_clusters.json if exists
        if pattern_clusters_file.is_file():
            files_to_pack.append(("pattern_clusters.json", pattern_clusters_file))

        # Add guardrails.json if exists
        guardrails_path = repo_root / "docs" / "skills" / "defensive-security-auditor" / "references" / "guardrails.json"
        if guardrails_path.is_file():
            files_to_pack.append(("guardrails.json", guardrails_path))

        # Add fingerprints corpus if exists
        if fingerprints_dir.is_dir():
            for fp in fingerprints_dir.rglob("*.json"):
                if fp.is_file():
                    arcname = "fingerprints/" + str(fp.relative_to(fingerprints_dir))
                    files_to_pack.append((arcname, fp))

        # Deduplicate files_to_pack by arcname
        unique_pack = {}
        for arcname, fp in files_to_pack:
            unique_pack[arcname] = fp

        sorted_pack = sorted(unique_pack.items(), key=lambda x: x[0])

        with open(bundle_path, "wb") as f_out:
            with gzip.GzipFile(filename="", mode="wb", fileobj=f_out, mtime=0.0) as gz_out:
                with tarfile.open(mode="w", fileobj=gz_out) as tar:
                    for arcname, filepath in sorted_pack:
                        info = tar.gettarinfo(str(filepath), arcname=arcname)
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = 0
                        info.mode = 0o644 if info.isreg() else 0o755
                        if info.isreg():
                            with open(filepath, "rb") as f_in:
                                tar.addfile(info, f_in)
                        else:
                            tar.addfile(info)

        bundle_bytes = bundle_path.read_bytes()
        digest = hashlib.sha256(bundle_bytes).hexdigest()
        sha_path.write_text(f"{digest}  bundle.tar.gz\n", encoding="utf-8")
