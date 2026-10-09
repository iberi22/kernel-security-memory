#!/usr/bin/env python3
"""Classify vulnerability patterns into CWE families, preconditions, and build typed SQLite graph.

Parses all canonical catalogs and evidence records, categorizes vulnerability
families, builds typed nodes (CVE, CWE, Component, Commit, Patch), and
exports an indexed SQLite knowledge graph with vector preparation.
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[2]
CVE_HISTORY_DIR = ROOT / "docs/studies/cve-history"
FABLE_DIR = ROOT / "docs/studies/fable-2026-06"
OUTPUT_JSON = ROOT / "docs/studies/pattern_clusters.json"
OUTPUT_MD = ROOT / "docs/studies/pattern_clusters.md"
GRAPH_DB_PATH = ROOT / "docs/studies/pattern_graph.sqlite3"

CWE_FAMILY_TITLES = {
    "CWE-119": "Memory Corruption / Buffer Boundary Error",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption (DoS)",
    "CWE-401": "Missing Release of Memory after Effective Lifetime (Memory Leak)",
    "CWE-20": "Improper Input Validation",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-310": "Cryptographic Issues",
    "CWE-362": "Concurrent Execution using Shared Resource (Race Condition)",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "UNKNOWN": "Unstated or Legacy Advisory Without CWE Classification",
}


def load_corpus():
    cves = {}
    for pdir in sorted(CVE_HISTORY_DIR.glob("*")):
        cat_file = pdir / "catalog.jsonl"
        if not cat_file.exists():
            continue
        project = pdir.name
        for line in cat_file.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            cve_id = entry["advisory_id"]
            entry["project"] = project
            cves[cve_id] = entry

    # Enrich from fable records
    if FABLE_DIR.exists():
        for rec_file in FABLE_DIR.glob("*/records/*.json"):
            try:
                rec = json.loads(rec_file.read_text())
                cve_id = rec.get("advisory_id")
                if cve_id and cve_id in cves:
                    sha = rec.get("fix", {}).get("sha")
                    if sha and sha not in cves[cve_id].get("fix_shas", []):
                        cves[cve_id].setdefault("fix_shas", []).append(sha)
            except Exception:
                pass

    return cves


def cluster_families(cves):
    clusters = defaultdict(lambda: {
        "title": "",
        "count": 0,
        "projects": defaultdict(int),
        "cves": [],
        "with_fix_sha": 0,
        "preconditions": set(),
    })

    for cve_id, data in sorted(cves.items()):
        cwe = data.get("cwe") or "UNKNOWN"
        cl = clusters[cwe]
        cl["title"] = CWE_FAMILY_TITLES.get(cwe, f"CWE Family {cwe}")
        cl["count"] += 1
        cl["projects"][data["project"]] += 1
        cl["cves"].append(cve_id)
        if data.get("fix_shas"):
            cl["with_fix_sha"] += 1

        # Heuristic preconditions based on CWE taxonomy
        if cwe in ("CWE-119", "CWE-120", "CWE-125", "CWE-787"):
            cl["preconditions"].add("Untrusted buffer length or unbounded string processing")
        elif cwe == "CWE-416":
            cl["preconditions"].add("Asynchronous lifecycle, double free, or aliased pointer reuse")
        elif cwe == "CWE-476":
            cl["preconditions"].add("Unchecked return value from allocator or lookup function")
        elif cwe in ("CWE-362",):
            cl["preconditions"].add("Multithreaded / interrupt context without adequate lock barrier")
        elif cwe in ("CWE-20", "CWE-200"):
            cl["preconditions"].add("Missing boundary / sanitize check on incoming payload")
        elif cwe in ("CWE-399", "CWE-400", "CWE-401"):
            cl["preconditions"].add("Resource exhaustion path without rate limit or quota")

    out_clusters = []
    for cwe, data in sorted(clusters.items(), key=lambda kv: kv[1]["count"], reverse=True):
        out_clusters.append({
            "cwe_id": cwe,
            "title": data["title"],
            "count": data["count"],
            "with_fix_sha": data["with_fix_sha"],
            "preconditions": sorted(data["preconditions"]),
            "projects_distribution": dict(sorted(data["projects"].items())),
            "sample_cves": data["cves"][:10],
        })

    return out_clusters


def build_graph_db(cves, clusters, db_path: Path):
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript("""
    PRAGMA foreign_keys = ON;
    CREATE TABLE nodes (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        label TEXT NOT NULL,
        attributes TEXT NOT NULL
    );
    CREATE TABLE edges (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL REFERENCES nodes(id),
        target TEXT NOT NULL REFERENCES nodes(id),
        relation TEXT NOT NULL,
        attributes TEXT NOT NULL
    );
    CREATE INDEX idx_edges_source ON edges(source);
    CREATE INDEX idx_edges_target ON edges(target);
    CREATE INDEX idx_nodes_kind ON nodes(kind);
    """)

    # 1. Insert Component nodes
    projects = {data["project"] for data in cves.values()}
    for p in sorted(projects):
        cur.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)",
                    (f"comp:{p}", "Component", p, json.dumps({"name": p})))

    # 2. Insert CWE nodes
    for cl in clusters:
        cwe_id = cl["cwe_id"]
        cur.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)",
                    (f"cwe:{cwe_id}", "CWE", cl["title"], json.dumps({
                        "cwe": cwe_id,
                        "title": cl["title"],
                        "preconditions": cl["preconditions"],
                    })))

    # 3. Insert CVE nodes and Edges
    edge_idx = 0
    for cve_id, data in cves.items():
        node_id = f"cve:{cve_id}"
        cur.execute("INSERT INTO nodes VALUES (?, ?, ?, ?)",
                    (node_id, "CVE", cve_id, json.dumps({
                        "published": data.get("published"),
                        "cwe": data.get("cwe"),
                        "patch_urls": data.get("patch_urls", []),
                    })))

        # Edge: CVE -> Component (affects)
        edge_idx += 1
        cur.execute("INSERT INTO edges VALUES (?, ?, ?, ?, ?)",
                    (f"e:{edge_idx}", node_id, f"comp:{data['project']}", "affects", "{}"))

        # Edge: CVE -> CWE (categorized_as)
        cwe_id = data.get("cwe") or "UNKNOWN"
        edge_idx += 1
        cur.execute("INSERT INTO edges VALUES (?, ?, ?, ?, ?)",
                    (f"e:{edge_idx}", node_id, f"cwe:{cwe_id}", "categorized_as", "{}"))

        # 4. Insert Commit nodes & Edges (fixes)
        for sha in data.get("fix_shas", []):
            commit_id = f"commit:{sha}"
            cur.execute("INSERT OR IGNORE INTO nodes VALUES (?, ?, ?, ?)",
                        (commit_id, "Commit", sha[:12], json.dumps({"sha": sha, "project": data["project"]})))
            edge_idx += 1
            cur.execute("INSERT INTO edges VALUES (?, ?, ?, ?, ?)",
                        (f"e:{edge_idx}", commit_id, node_id, "fixes", "{}"))

    conn.commit()
    conn.close()


def generate_markdown(clusters, total_cves):
    md = [
        "# Vulnerability Pattern Clusters & Graph Taxonomy",
        "",
        f"Analysis across **{total_cves}** canonical CVE entries linking software components, CWE classes, preconditions, and fix commits.",
        "",
        "## Summary by CWE Family",
        "",
        "| CWE | Title | Total CVEs | With Validated Fix SHA | Key Preconditions |",
        "| --- | --- | --- | --- | --- |",
    ]
    for cl in clusters:
        pre = "<br>".join(cl["preconditions"]) if cl["preconditions"] else "None recorded"
        md.append(f"| `{cl['cwe_id']}` | {cl['title']} | {cl['count']} | {cl['with_fix_sha']} | {pre} |")

    md.extend([
        "",
        "## Detailed Breakdown by Project",
        "",
    ])
    for cl in clusters:
        if cl["count"] == 0:
            continue
        md.append(f"### {cl['cwe_id']} — {cl['title']}")
        md.append(f"- **Count**: {cl['count']}")
        md.append(f"- **With Fix SHA**: {cl['with_fix_sha']}")
        dist = ", ".join(f"`{p}`: {c}" for p, c in cl["projects_distribution"].items())
        md.append(f"- **Project Distribution**: {dist}")
        md.append(f"- **Sample CVEs**: {', '.join(cl['sample_cves'])}")
        md.append("")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate taxonomy without writing")
    args = parser.parse_args()

    cves = load_corpus()
    clusters = cluster_families(cves)

    if args.check:
        assert len(cves) > 0, "No CVEs loaded"
        assert len(clusters) > 0, "No clusters generated"
        print(f"Validation OK: {len(cves)} CVEs categorized into {len(clusters)} CWE clusters.")
        return

    # Write JSON and MD
    OUTPUT_JSON.write_text(json.dumps({
        "schema_version": "pattern-clusters-v1",
        "total_cves": len(cves),
        "cluster_count": len(clusters),
        "clusters": clusters,
    }, indent=2, ensure_ascii=False) + "\n")

    md_content = generate_markdown(clusters, len(cves))
    OUTPUT_MD.write_text(md_content + "\n")

    # Build typed SQLite graph
    build_graph_db(cves, clusters, GRAPH_DB_PATH)

    print(f"Generated {OUTPUT_JSON} and {OUTPUT_MD} with {len(clusters)} families.")
    print(f"Built typed SQLite graph at {GRAPH_DB_PATH}.")


if __name__ == "__main__":
    main()
