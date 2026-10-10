#!/usr/bin/env python3
"""Deterministic generator for the defensive-security-auditor guardrails reference.

Renders ``docs/skills/defensive-security-auditor/references/guardrails.md`` plus a
machine-readable twin (``guardrails.json``) from repository data only:

* rule ids, languages, patterns, severities and remediation text
  -> ``SECURITY_RULES`` in ``scripts/defensive_auditor.py``
* per-family advisory counts and ``with_fix_sha``
  -> ``docs/studies/pattern_clusters.json``
* advisory rows carrying a 40-hex fix SHA and the upstream repository URL
  -> ``docs/studies/cve-history/<project>/catalog.jsonl`` + ``index.json``
* verified fix commits (CVE id, project, commit URL)
  -> ``docs/memory/records/*.json``

A family is emitted only when it has BOTH at least one auditor rule AND at least one
40-hex fix commit reachable in this repository. Nothing is inferred, summarised or
invented: every number, pattern and citation printed below is read from those files.

Citation selection (deterministic, no sampling):

1. a candidate is ``(advisory id, project, 40-hex sha)`` linked to the family either by
   the row's own recorded ``cwe`` or by the advisory appearing in the family cluster's
   ``sample_cves`` list in ``pattern_clusters.json``;
2. one candidate per advisory id is kept, preferring a pack record over a catalog row,
   then the lowest-sorting SHA;
3. candidates are ordered by (source kind, advisory id) and the first three are emitted.

Output is byte-identical on rerun: no timestamps, no filesystem walk order, no locale
dependent sorting. ``--check`` re-renders in memory and fails on drift.

Stdlib only.
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from defensive_auditor import SECURITY_RULES  # noqa: E402

CLUSTERS_PATH = REPO_ROOT / "docs" / "studies" / "pattern_clusters.json"
CVE_HISTORY_DIR = REPO_ROOT / "docs" / "studies" / "cve-history"
RECORDS_DIR = REPO_ROOT / "docs" / "memory" / "records"
SKILL_REFERENCES_DIR = REPO_ROOT / "docs" / "skills" / "defensive-security-auditor" / "references"
MD_PATH = SKILL_REFERENCES_DIR / "guardrails.md"
JSON_PATH = SKILL_REFERENCES_DIR / "guardrails.json"

SCHEMA_VERSION = "defensive-guardrails-v1"
MAX_CITATIONS = 3
HEX40 = re.compile(r"^[0-9a-f]{40}$")

AUDIT_COMMAND = (
    "python3 scripts/defensive_auditor.py --target <changed paths> "
    "--clusters docs/studies/pattern_clusters.json "
    "--output docs/studies/audit-evidence.json --strict"
)
GATE_COMMAND = (
    "python3 scripts/quality_gate.py --target <changed paths> "
    "--evidence docs/studies/audit-evidence.json"
)


# --------------------------------------------------------------------------- data


def _repo_relative(path):
    """Repository-relative POSIX path, so output does not depend on where it runs."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_clusters():
    """Return {cwe_id: cluster dict} from pattern_clusters.json."""
    data = json.loads(CLUSTERS_PATH.read_text(encoding="utf-8"))
    clusters = data.get("clusters")
    if not isinstance(clusters, list):
        raise ValueError(f"{_repo_relative(CLUSTERS_PATH)}: 'clusters' must be a list")
    return {c["cwe_id"]: c for c in clusters if isinstance(c, dict) and "cwe_id" in c}


def load_catalog_repos():
    """Return {project: upstream repository URL} from each catalog index.json."""
    repos = {}
    for index_path in sorted(CVE_HISTORY_DIR.glob("*/index.json")):
        project = index_path.parent.name
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"Cannot read {_repo_relative(index_path)}: {exc}") from exc
        repo = index.get("repo")
        if isinstance(repo, str) and repo:
            repos[project] = repo.rstrip("/")
    return repos


def load_catalog_candidates():
    """Return {advisory_id: [candidate, ...]} from cve-history catalogs.

    Only rows whose ``fix_shas`` contains a 40-hex SHA contribute. The commit URL is
    derived from the repository URL recorded in the same catalog's ``index.json``.
    """
    repos = load_catalog_repos()
    candidates = {}
    for catalog_path in sorted(CVE_HISTORY_DIR.glob("*/catalog.jsonl")):
        project = catalog_path.parent.name
        source = _repo_relative(catalog_path)
        repo = repos.get(project)
        for line in catalog_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            advisory_id = row.get("advisory_id")
            if not advisory_id:
                continue
            for sha in row.get("fix_shas") or []:
                if not HEX40.match(str(sha)):
                    continue
                candidates.setdefault(advisory_id, []).append({
                    "advisory_id": advisory_id,
                    "project": project,
                    "fix_commit_sha": str(sha),
                    "fix_commit_url": f"{repo}/commit/{sha}" if repo else None,
                    "recorded_cwe": row.get("cwe"),
                    "source": source,
                    "source_kind": "catalog",
                })
    return candidates


def load_record_candidates():
    """Return {advisory_id: [candidate, ...]} from docs/memory/records/*.json."""
    candidates = {}
    for record_path in sorted(RECORDS_DIR.glob("*.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        advisory_id = recorded_cwe = sha = url = None
        for node in record.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            if node.get("type") == "advisory":
                advisory_id = node.get("label")
                recorded_cwe = (node.get("attributes") or {}).get("cwe")
            elif node.get("type") == "commit":
                attributes = node.get("attributes") or {}
                sha = attributes.get("sha")
                url = attributes.get("url")
        if not advisory_id or not sha or not HEX40.match(str(sha)):
            continue
        candidates.setdefault(advisory_id, []).append({
            "advisory_id": advisory_id,
            "project": record.get("project"),
            "fix_commit_sha": str(sha),
            "fix_commit_url": url if isinstance(url, str) and url else None,
            "recorded_cwe": recorded_cwe,
            "source": _repo_relative(record_path),
            "source_kind": "pack_record",
        })
    return candidates


# ----------------------------------------------------------------------- builder


def _rule_sort_key(rule):
    return (rule.get("cwe_id", ""), rule.get("id", ""))


def _cwe_sort_key(cwe_id):
    """Sort CWE ids numerically so sections are stable and readable."""
    match = re.match(r"CWE-(\d+)", cwe_id or "")
    return (0, int(match.group(1)), cwe_id) if match else (1, 0, cwe_id)


def _candidate_sort_key(candidate):
    # Pack records first (they carry the commit URL as recorded), then advisory id.
    return (0 if candidate["source_kind"] == "pack_record" else 1,
            candidate["advisory_id"], candidate["fix_commit_sha"])


def select_citations(cwe_id, cluster, catalog_candidates, record_candidates):
    """Return up to MAX_CITATIONS citations for one CWE family.

    A candidate qualifies when its row records this CWE, or when its advisory id is
    listed in this family's ``sample_cves`` in pattern_clusters.json.
    """
    sample_cves = set((cluster or {}).get("sample_cves") or [])
    by_advisory = {}
    for advisory_id in sorted(set(catalog_candidates) | set(record_candidates)):
        pool = list(record_candidates.get(advisory_id, [])) + list(catalog_candidates.get(advisory_id, []))
        for candidate in pool:
            if candidate["recorded_cwe"] != cwe_id and advisory_id not in sample_cves:
                continue
            linked_by = "recorded_cwe" if candidate["recorded_cwe"] == cwe_id else "cluster_sample_cves"
            entry = dict(candidate)
            entry["linked_by"] = linked_by
            previous = by_advisory.get(advisory_id)
            if previous is None or _candidate_sort_key(entry) < _candidate_sort_key(previous):
                by_advisory[advisory_id] = entry
    ordered = sorted(by_advisory.values(), key=_candidate_sort_key)
    return ordered[:MAX_CITATIONS]


def build_families():
    """Return (families, families_without_evidence) sorted deterministically."""
    clusters = load_clusters()
    catalog_candidates = load_catalog_candidates()
    record_candidates = load_record_candidates()

    rules_by_cwe = {}
    for rule in SECURITY_RULES:
        rules_by_cwe.setdefault(rule.get("cwe_id"), []).append(rule)

    families = []
    without_evidence = []
    for cwe_id in sorted(rules_by_cwe, key=_cwe_sort_key):
        rules = sorted(rules_by_cwe[cwe_id], key=lambda r: r.get("id", ""))
        cluster = clusters.get(cwe_id)
        citations = select_citations(cwe_id, cluster, catalog_candidates, record_candidates)
        entry = {
            "cwe_id": cwe_id,
            "cluster_title": (cluster or {}).get("title"),
            "cluster_count": (cluster or {}).get("count"),
            "cluster_with_fix_sha": (cluster or {}).get("with_fix_sha"),
            "cluster_sample_cves": sorted((cluster or {}).get("sample_cves") or []),
            "preconditions": list((cluster or {}).get("preconditions") or []),
            "rules": [{
                "rule_id": rule.get("id"),
                "title": rule.get("title"),
                "severity": rule.get("severity"),
                "language": rule.get("language"),
                "languages": list(rule.get("languages") or []),
                "pattern": rule.get("pattern"),
                "explanation": rule.get("explanation"),
                "lesson": rule.get("lesson"),
            } for rule in rules],
        }
        if citations:
            entry["citations"] = citations
            families.append(entry)
        else:
            entry["reason_no_evidence"] = (
                "no 40-hex fix commit for this CWE in docs/memory/records or "
                "docs/studies/cve-history"
            )
            without_evidence.append(entry)

    return families, without_evidence


def build_document():
    """Return (markdown_text, guardrails_dict)."""
    families, without_evidence = build_families()
    guardrails = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "scripts/build_guardrails.py",
        "sources": {
            "rules": "scripts/defensive_auditor.py:SECURITY_RULES",
            "clusters": _repo_relative(CLUSTERS_PATH),
            "catalogs": _repo_relative(CVE_HISTORY_DIR) + "/*/catalog.jsonl",
            "records": _repo_relative(RECORDS_DIR) + "/*.json",
        },
        "selection_rule": (
            "A family is emitted when it has at least one auditor rule and at least one "
            "40-hex fix commit in this repository, linked by the row's recorded cwe or by "
            "the advisory appearing in the family cluster's sample_cves. At most "
            f"{MAX_CITATIONS} citations per family: pack records before catalog rows, "
            "then advisory id, lowest-sorting SHA per advisory."
        ),
        "audit_command": AUDIT_COMMAND,
        "gate_command": GATE_COMMAND,
        "families": families,
        "families_without_evidence": without_evidence,
        "summary": {
            "families_covered": len(families),
            "citations_total": sum(len(f.get("citations", [])) for f in families),
            "rules_covered": sum(len(f["rules"]) for f in families),
            "rule_families_total": len(families) + len(without_evidence),
            "rule_families_without_evidence": len(without_evidence),
        },
    }
    return render_markdown(guardrails), guardrails


# ----------------------------------------------------------------------- renderer


def _md_escape(text):
    """Escape pipe characters so table cells cannot break out of the table."""
    return str(text).replace("|", "\\|")


def _cluster_line(family):
    cluster = family["cluster_title"]
    count = family["cluster_count"]
    with_fix = family["cluster_with_fix_sha"]
    if cluster is None:
        return (f"Cluster `{family['cwe_id']}`: **absent** from "
                "`docs/studies/pattern_clusters.json`.")
    return (f"Cluster `{family['cwe_id']}` \"{_md_escape(cluster)}\": **{count}** advisories, "
            f"**{with_fix}** with a fix SHA "
            "(`docs/studies/pattern_clusters.json`).")


def render_markdown(guardrails):
    """Render the reference document. Pure function of ``guardrails``."""
    summary = guardrails["summary"]
    lines = [
        "# Defensive Security Guardrails",
        "",
        "Generated by `scripts/build_guardrails.py`. Do not edit by hand: re-run "
        "`python3 scripts/build_guardrails.py` (or `python3 scripts/build_guardrails.py "
        "--check` in CI) after changing `SECURITY_RULES` in "
        "`scripts/defensive_auditor.py`, `docs/studies/pattern_clusters.json`, the "
        "`docs/studies/cve-history/*` catalogs or `docs/memory/records/*`. The "
        "machine-readable twin is `guardrails.json`.",
        "",
        "Every number, pattern and citation below is read from repository data:",
        "",
        "- rule ids, matched patterns, severities and remediation: `SECURITY_RULES` in "
        "`scripts/defensive_auditor.py`",
        "- family counts and `with_fix_sha`: `docs/studies/pattern_clusters.json`",
        "- advisory rows with a 40-hex fix SHA: `docs/studies/cve-history/*/catalog.jsonl` "
        "(commit URL derived from the `repo` recorded in the sibling `index.json`)",
        "- verified fix commits: `docs/memory/records/*.json`",
        "",
        "A family gets a section only when it has **both** an auditor rule **and** at "
        "least one 40-hex fix commit in this repository. "
        f"Covered: **{summary['families_covered']}** families, "
        f"**{summary['citations_total']}** citations, "
        f"**{summary['rules_covered']}** rules "
        f"(of {summary['rule_families_total']} rule families).",
        "",
        "## How to use a section",
        "",
        "Each guardrail names the auditor rule that fires, the check to run before a "
        "commit or PR, and the in-repo fix commits that justify the rule. Run:",
        "",
        "```bash",
        AUDIT_COMMAND,
        "```",
        "",
        "Exit code 0 means `PASS`/`WARN`; a finding whose `rule_id` matches a guardrail "
        "below blocks the commit until it is fixed. Then verify the cited evidence still "
        "matches the tree you are shipping:",
        "",
        "```bash",
        GATE_COMMAND,
        "```",
        "",
        "The gate exits non-zero with verdict `STALE` when the stored "
        "`evidence_chain_hash` no longer matches a fresh audit of the same target.",
        "",
    ]

    for family in guardrails["families"]:
        lines.append(f"## {family['cwe_id']} — {family['cluster_title'] or 'Unnamed cluster'}")
        lines.append("")
        lines.append(_cluster_line(family))
        if family["preconditions"]:
            lines.append("")
            lines.append("Preconditions recorded in the cluster: "
                         + "; ".join(_md_escape(p) for p in family["preconditions"]) + ".")
        lines.append("")
        for rule in family["rules"]:
            families = ", ".join(f"`{lang}`" for lang in (rule["languages"] or []))
            lines.append(f"### {rule['rule_id']} ({rule['severity']}, {rule['language']})")
            lines.append("")
            lines.append(f"- **Trigger** — language family {families} as classified by "
                         "`_detect_language()` in `scripts/defensive_auditor.py`. "
                         f"\"{_md_escape(rule['title'])}\": "
                         f"{_md_escape(rule['explanation'])}")
            lines.append("")
            lines.append("  ```python")
            lines.append(f"  {rule['pattern']}")
            lines.append("  ```")
            lines.append("")
            lines.append(f"- **Check** — run `{AUDIT_COMMAND}` and grep the evidence for "
                         f"`\"rule_id\": \"{rule['rule_id']}\"`. If the rule id is present, "
                         "the pre-commit contract is violated: fix before committing, then "
                         f"run `{GATE_COMMAND}` and require exit code 0.")
            lines.append("")
            lines.append(f"- **Required invariant** — {_md_escape(rule['lesson'])}")
            lines.append("")
        lines.append("#### Evidence")
        lines.append("")
        lines.append("| Advisory | Project | Fix commit | Linked by | Source |")
        lines.append("|---|---|---|---|---|")
        for citation in family["citations"]:
            sha = citation["fix_commit_sha"]
            url = citation["fix_commit_url"]
            commit_cell = f"[`{sha[:12]}`]({url})" if url else f"`{sha}`"
            lines.append(
                f"| {citation['advisory_id']} | {_md_escape(citation['project'])} | "
                f"{commit_cell} | {citation['linked_by']} | "
                f"`{citation['source']}` |"
            )
        lines.append("")

    lines.append("## Rule families without in-repo fix evidence")
    lines.append("")
    without_evidence = guardrails["families_without_evidence"]
    if not without_evidence:
        lines.append("None: every auditor rule family has at least one 40-hex fix commit.")
        lines.append("")
    else:
        lines.append("These families keep their `SECURITY_RULES` entries in "
                     "`scripts/defensive_auditor.py` and stay enforced, but this repository "
                     "holds no 40-hex fix commit linked to them, so no evidence section can "
                     "be generated without inventing data:")
        lines.append("")
        lines.append("| Rule family | Rules | Cluster count / with_fix_sha | Why no section |")
        lines.append("|---|---|---|---|---|")
        for family in without_evidence:
            count = family["cluster_count"]
            with_fix = family["cluster_with_fix_sha"]
            cluster_state = ("no cluster entry" if family["cluster_title"] is None
                             else f"{count} / {with_fix}")
            rule_ids = ", ".join(f"`{r['rule_id']}`" for r in family["rules"])
            lines.append(
                f"| {family['cwe_id']} | {rule_ids} | {cluster_state} | "
                f"{family['reason_no_evidence']} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


# -------------------------------------------------------------------------- checks


def iter_cited_shas(guardrails):
    """Yield (cwe_id, advisory_id, sha, source) for every emitted citation."""
    for family in guardrails["families"]:
        for citation in family.get("citations", []):
            yield (family["cwe_id"], citation["advisory_id"],
                   citation["fix_commit_sha"], citation["source"])


def verify_citations(guardrails):
    """Re-read the cited source files and confirm each SHA is really there.

    Returns a list of human-readable problems; empty means every cited fix commit is
    backed by a file in this repository.
    """
    cache = {}
    problems = []
    for cwe_id, advisory_id, sha, source in iter_cited_shas(guardrails):
        if source not in cache:
            path = REPO_ROOT / source
            cache[source] = path.read_text(encoding="utf-8") if path.is_file() else None
        content = cache[source]
        if content is None:
            problems.append(f"{cwe_id} {advisory_id}: source file missing: {source}")
            continue
        if sha not in content:
            problems.append(f"{cwe_id} {advisory_id}: sha {sha} not found in {source}")
    return problems


# ---------------------------------------------------------------------------- cli


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="Fail if the generated files differ from the ones on disk")
    parser.add_argument("--verify-citations", action="store_true",
                        help="Re-read every cited source file and confirm each fix SHA exists")
    parser.add_argument("--out-dir", type=Path, default=None,
                        help="Write/check guardrails.md and guardrails.json here instead of the skill references dir")
    args = parser.parse_args(argv)
    out_dir = args.out_dir.resolve() if args.out_dir else SKILL_REFERENCES_DIR
    md_path = out_dir / MD_PATH.name
    json_path = out_dir / JSON_PATH.name

    markdown, guardrails = build_document()

    # --check and --verify-citations are read-only: they never touch the output files.
    exit_code = 0

    if args.verify_citations:
        problems = verify_citations(guardrails)
        print(f"Citations verified: {guardrails['summary']['citations_total']} across "
              f"{guardrails['summary']['families_covered']} families, "
              f"{len(problems)} missing")
        for problem in problems:
            print(f"  MISSING {problem}", file=sys.stderr)
        if problems:
            exit_code = 1

    if args.check:
        expected = [(md_path, markdown),
                    (json_path, json.dumps(guardrails, indent=2, sort_keys=True,
                                           ensure_ascii=False) + "\n")]
        drifted = []
        for path, text in expected:
            if not path.is_file():
                drifted.append(f"{_repo_relative(path)}: missing")
            elif path.read_text(encoding="utf-8") != text:
                drifted.append(f"{_repo_relative(path)}: differs from generated output")
        for entry in drifted:
            print(f"DRIFT {entry}", file=sys.stderr)
        if drifted:
            print("guardrails are out of date; run: python3 scripts/build_guardrails.py",
                  file=sys.stderr)
            exit_code = 1
        else:
            print(f"guardrails up to date: {_repo_relative(md_path)}, "
                  f"{_repo_relative(json_path)}")

    if args.check or args.verify_citations:
        return exit_code

    out_dir.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown, encoding="utf-8", newline="\n")
    json_path.write_text(
        json.dumps(guardrails, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n")

    summary = guardrails["summary"]
    print(f"Wrote {_repo_relative(md_path)} and {_repo_relative(json_path)}")
    print(f"Families covered: {summary['families_covered']} "
          f"({', '.join(f['cwe_id'] for f in guardrails['families']) or 'none'})")
    print(f"Citations: {summary['citations_total']} "
          f"across {summary['rules_covered']} rules")
    print(f"Rule families without in-repo fix evidence: "
          f"{summary['rule_families_without_evidence']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
