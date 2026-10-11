#!/usr/bin/env python3
"""Evaluate the matcher on an old release of a project (deterministic, offline
apart from running code-graph on the given source tree).

Two measurements:
- same project: strong findings whose top match is a fix of this project
  published after the release date (the release really lacked that fix), as a
  share of all strong findings. Date is a proxy: a fix published later can
  touch code the release never had.
- other projects: the corpus without this project's fingerprints; every strong
  finding is then counted as a cross-project alarm per 1,000 scanned functions
  (true cross-project matches exist but are rare; this bounds the noise).
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ksm.match import STRONG_SCORE, load_corpus, match_documents  # noqa: E402
from ksm.sitedata import project_from_catalog  # noqa: E402

EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".py", ".go", ".java", ".ts", ".js"}
SKIP_DIRS = {".git", "test", "tests", "docs", "vendor", "node_modules", "target"}


def published_dates(catalog_dir):
    dates = {}
    for cat in sorted(Path(catalog_dir).glob("*/catalog.jsonl")):
        project = project_from_catalog(cat.parent.name)
        for line in cat.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("published"):
                dates[(project, row["advisory_id"])] = row["published"]
    return dates


def fingerprint_tree(source, code_graph):
    docs = []
    for root, dirs, files in os.walk(source):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            if Path(name).suffix.lower() not in EXTENSIONS:
                continue
            res = subprocess.run([code_graph, "fingerprint", str(Path(root) / name)],
                                 capture_output=True, text=True, check=False, timeout=300)
            if res.returncode == 0:
                doc = json.loads(res.stdout)
                if doc.get("schema") == "ksm-sfp/1":
                    docs.append(doc)
    return docs


def evaluate(docs, corpus, project, release_date, dates):
    functions = sum(len(d.get("functions", [])) for d in docs)
    own = [d for d in corpus if project_from_catalog(d.get("project", "")) == project]
    others = [d for d in corpus if project_from_catalog(d.get("project", "")) != project]

    same = [f for f in match_documents(docs, own) if f["score"] >= STRONG_SCORE]
    later = [f for f in same
             if dates.get((project, f["matches"][0]["advisory_id"]), "") > release_date]
    cross = [f for f in match_documents(docs, others) if f["score"] >= STRONG_SCORE]
    return {
        "project": project,
        "release_date": release_date,
        "functions_scanned": functions,
        "corpus_own_fixes": len(own),
        "corpus_other_fixes": len(others),
        "same_project_strong": len(same),
        "same_project_strong_fixed_after_release": len(later),
        "cross_project_strong": len(cross),
        "cross_project_strong_per_1000_functions": round(1000 * len(cross) / functions, 3) if functions else None,
        "cross_project_examples": [
            {"function": f["function"], "file": Path(f["file"]).name,
             "advisory_id": f["matches"][0]["advisory_id"], "project": f["matches"][0]["project"],
             "score": f["score"]}
            for f in cross[:10]],
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, help="source tree of the old release")
    p.add_argument("--project", required=True, help="project name as in the site data (curl, openssl, ...)")
    p.add_argument("--release-date", required=True, help="YYYY-MM-DD of the release")
    p.add_argument("--fingerprints", default=str(ROOT / "docs/studies/fingerprints"))
    p.add_argument("--catalog-dir", default=str(ROOT / "docs/studies/cve-history"))
    p.add_argument("--code-graph", default=os.environ.get("KSM_CODE_GRAPH", "code-graph"))
    args = p.parse_args(argv)
    docs = fingerprint_tree(args.source, args.code_graph)
    if not docs:
        print("no ksm-sfp/1 output; check --code-graph", file=sys.stderr)
        return 2
    result = evaluate(docs, load_corpus(args.fingerprints), args.project, args.release_date,
                      published_dates(args.catalog_dir))
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
