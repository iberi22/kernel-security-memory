#!/usr/bin/env python3
"""Defensive Security Specialist Auditor for SWAL Agents.

Audits code files or patches against known vulnerability patterns,
mapping findings to KSM evidence packs and CWE pattern clusters.
Produces a verifiable, cryptographic evidence chain (tamper-evident hash)
for mandatory defensive security gates in agent workflows.

Stdlib only.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Known rule patterns for defensive security analysis
SECURITY_RULES = [
    {
        "id": "SEC-CWE-120-UNBOUNDED-COPY",
        "cwe_id": "CWE-120",
        "title": "Buffer Copy without Checking Size of Input",
        "severity": "HIGH",
        "pattern": r"\b(strcpy|strcat|gets|sprintf)\s*\(",
        "explanation": "Unbounded string function prone to classic stack/heap buffer overflow.",
        "lesson": "Replace with bounds-checked alternatives (strncpy, strlcpy, snprintf) and validate buffer bounds.",
    },
    {
        "id": "SEC-CWE-416-USE-AFTER-FREE",
        "cwe_id": "CWE-416",
        "title": "Use After Free / Lifetime Invariant Violation",
        "severity": "HIGH",
        "pattern": r"\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\);\s*[^;]*\b\1\b",
        "explanation": "Pointer accessed or dereferenced after free() without nullification.",
        "lesson": "Distinguish object lifetime from transaction visibility; set pointers to NULL immediately after free.",
    },
    {
        "id": "SEC-CWE-78-COMMAND-INJECTION",
        "cwe_id": "CWE-78",
        "title": "Improper Neutralization of Special Elements used in an OS Command",
        "severity": "CRITICAL",
        "pattern": r"(system\s*\([^\"'\)]*\%[sS]|popen\s*\([^\"'\)]*\%[sS]|subprocess\.call\s*\(.*shell\s*=\s*True)",
        "explanation": "Dynamic command construction vulnerable to command injection.",
        "lesson": "Use parameterized argument lists without shell interpretation.",
    },
    {
        "id": "SEC-CWE-190-INTEGER-OVERFLOW",
        "cwe_id": "CWE-190",
        "title": "Integer Overflow or Wraparound in Allocation",
        "severity": "MEDIUM",
        "pattern": r"\bmalloc\s*\(\s*([a-zA-Z0-9_]+)\s*\*\s*([a-zA-Z0-9_]+)\s*\)",
        "explanation": "Multiplication inside allocation argument without overflow check.",
        "lesson": "Use overflow-safe allocation helpers (e.g. calloc, check_mul_overflow).",
    },
    {
        "id": "SEC-CWE-476-NULL-DEREFERENCE",
        "cwe_id": "CWE-476",
        "title": "Unchecked Return Value / Potential NULL Pointer Dereference",
        "severity": "MEDIUM",
        "pattern": r"([a-zA-Z0-9_]+)\s*=\s*(malloc|kmalloc|kzalloc)\s*\([^;]+\);\s*(?!\s*if\s*\(\s*!\s*\1\b)\s*\1\s*->",
        "explanation": "Pointer dereferenced immediately after allocation without checking for NULL.",
        "lesson": "Always check allocation return values before dereferencing.",
    },
    {
        "id": "SEC-CWE-362-CONCURRENCY-RACE",
        "cwe_id": "CWE-362",
        "title": "Race Condition / Lock Inversion Risk",
        "severity": "MEDIUM",
        "pattern": r"(spin_unlock\s*\(&[a-zA-Z0-9_]+\);\s*spin_lock\s*\(&[a-zA-Z0-9_]+\);)",
        "explanation": "Rapid drop and re-acquire of lock creates a TOCTOU concurrency window.",
        "lesson": "Hold critical section invariant across compound state updates.",
    },
]


def load_pattern_clusters(clusters_path):
    """Load pattern clusters JSON if available."""
    if not clusters_path:
        return {}
    path = Path(clusters_path)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        clusters = data.get("clusters", [])
        return {c.get("cwe_id"): c for c in clusters if "cwe_id" in c}
    except Exception:
        return {}


def scan_content(content, filename="<buffer>", cluster_map=None):
    """Scan text content for defensive security violations."""
    findings = []
    lines = content.splitlines()

    for rule in SECURITY_RULES:
        regex = re.compile(rule["pattern"], re.MULTILINE)
        for match in regex.finditer(content):
            # Compute line number
            start_pos = match.start()
            line_no = content[:start_pos].count("\n") + 1
            line_text = lines[line_no - 1] if line_no <= len(lines) else ""

            cluster_info = (cluster_map or {}).get(rule["cwe_id"], {})
            matched_cve = cluster_info.get("sample_cves", [None])[0]

            findings.append({
                "rule_id": rule["id"],
                "cwe_id": rule["cwe_id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "file": str(filename),
                "line": line_no,
                "snippet": line_text.strip(),
                "explanation": rule["explanation"],
                "lesson": rule["lesson"],
                "cluster_reference": {
                    "cluster_cwe": rule["cwe_id"],
                    "cluster_title": cluster_info.get("title", "Standard Pattern"),
                    "representative_cve": matched_cve,
                },
            })

    return findings


def audit_path(target_path, cluster_map=None):
    """Audit a file or directory recursively."""
    path = Path(target_path)
    if not path.exists():
        raise FileNotFoundError(f"Target path not found: {target_path}")

    all_findings = []
    files_audited = []

    if path.is_file():
        files_to_scan = [path]
    else:
        # Scan code files
        valid_exts = {".c", ".h", ".cpp", ".cc", ".rs", ".py", ".sh", ".js", ".ts"}
        files_to_scan = [
            p for p in path.rglob("*")
            if p.is_file() and p.suffix in valid_exts and not any(part.startswith(".") for part in p.parts)
        ]

    for f in sorted(files_to_scan):
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            f_findings = scan_content(content, filename=str(f), cluster_map=cluster_map)
            all_findings.extend(f_findings)
            files_audited.append(str(f))
        except Exception as exc:
            pass

    return files_audited, all_findings


def build_evidence_chain(target, files_audited, findings, ksm_pack_ref="kernel-security-memory-bootstrap-v0"):
    """Construct a cryptographic evidence chain for the audit."""
    now_utc = datetime.now(timezone.utc).isoformat()
    
    # Severity assessment
    severities = {f["severity"] for f in findings}
    if "CRITICAL" in severities or "HIGH" in severities:
        verdict = "FAIL"
    elif "MEDIUM" in severities or "LOW" in severities:
        verdict = "WARN"
    else:
        verdict = "PASS"

    audit_payload = {
        "schema_version": "defensive-evidence-chain-v1",
        "target": str(target),
        "timestamp": now_utc,
        "files_audited_count": len(files_audited),
        "files_audited": files_audited,
        "findings_count": len(findings),
        "findings": findings,
        "verdict": verdict,
        "ksm_pack_reference": ksm_pack_ref,
    }

    # Deterministic canonical serialization for cryptographic hashing
    serialized = json.dumps(audit_payload, sort_keys=True, ensure_ascii=False)
    chain_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    return {
        "evidence_chain_hash": chain_hash,
        "audit": audit_payload,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True,
                        help="Path to file or directory to audit")
    parser.add_argument("--clusters", default="docs/studies/pattern_clusters.json",
                        help="Path to pattern_clusters.json")
    parser.add_argument("--output",
                        help="Optional path to write evidence chain JSON")
    parser.add_argument("--strict", action="store_true",
                        help="Exit code 1 on HIGH/CRITICAL findings")
    args = parser.parse_args(argv)

    cluster_map = load_pattern_clusters(args.clusters)
    files_audited, findings = audit_path(args.target, cluster_map=cluster_map)

    evidence = build_evidence_chain(args.target, files_audited, findings)
    
    out_json = json.dumps(evidence, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(out_json + "\n", encoding="utf-8")
        print(f"Evidence chain written to {args.output}")

    print(f"Audit Target: {args.target}")
    print(f"Files Audited: {len(files_audited)}")
    print(f"Findings: {len(findings)}")
    print(f"Verdict: {evidence['audit']['verdict']}")
    print(f"Evidence Chain Hash (SHA256): {evidence['evidence_chain_hash']}")

    if args.strict and evidence["audit"]["verdict"] == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()
