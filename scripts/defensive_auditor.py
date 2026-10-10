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
        "title": "Buffer Copy without Checking Size of Input (C/C++)",
        "severity": "HIGH",
        "language": "C",
        "languages": ["c", "cpp"],
        "pattern": r"\b(strcpy|strcat|gets|sprintf)\s*\(",
        "explanation": "Unbounded string function (strcpy, strcat, gets, sprintf) prone to classic stack/heap buffer overflow.",
        "lesson": "Replace with bounds-checked alternatives (strncpy, strlcat, fgets, snprintf) and validate buffer bounds.",
    },
    {
        "id": "SEC-CWE-416-USE-AFTER-FREE-C",
        "cwe_id": "CWE-416",
        "title": "Use After Free / Lifetime Invariant Violation (C/C++)",
        "severity": "HIGH",
        "language": "C",
        "languages": ["c", "cpp"],
        "pattern": r"\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\);\s*(?!\s*\1\s*=\s*(?:NULL|0|nullptr)\s*;)[^;]*\b\1\b",
        "explanation": "Pointer accessed or dereferenced after free() without nullification in C.",
        "lesson": "Distinguish object lifetime from transaction visibility; set pointers to NULL immediately after free.",
    },
    {
        "id": "SEC-CWE-416-USE-AFTER-FREE-RUST",
        "cwe_id": "CWE-416",
        "title": "Use After Free / Dereference After Drop or Deallocation (Rust)",
        "severity": "HIGH",
        "language": "Rust",
        "languages": ["rust"],
        "pattern": r"\b(?:libc::free|dealloc|drop)\s*\(\s*([a-zA-Z0-9_]+)[^)]*\);\s*(?!\s*\1\s*=\s*(?:ptr::null|std::ptr::null|null_mut)\s*;)[^;]*(?:\*+\s*\1|\b\1\s*\.)",
        "explanation": "Raw pointer or resource accessed after deallocation or drop in Rust.",
        "lesson": "Enforce Rust ownership invariants or invalidate raw pointers immediately upon manual deallocation.",
    },
    {
        "id": "SEC-CWE-78-COMMAND-INJECTION-C",
        "cwe_id": "CWE-78",
        "title": "OS Command Injection in C (system / popen / exec)",
        "severity": "CRITICAL",
        "language": "C",
        "languages": ["c", "cpp"],
        "pattern": r'\b(?:system|popen)\s*\(\s*(?!"[^\%"\'\n]*"\s*[,)])([a-zA-Z0-9_]+|"[^"]*\%[sS])|\bexec[l|v]p?e?\s*\([^;]*"/(?:bin/)?(?:sh|bash)"[^;]*\)',
        "explanation": "Dynamic command string passed to system(), popen(), or shell exec() in C without sanitization.",
        "lesson": "Use parameterized execv/execve with discrete arguments array instead of shell invocation.",
    },
    {
        "id": "SEC-CWE-78-COMMAND-INJECTION-PYTHON",
        "cwe_id": "CWE-78",
        "title": "OS Command Injection in Python (subprocess shell=True / os.system / exec)",
        "severity": "CRITICAL",
        "language": "Python",
        "languages": ["python"],
        "pattern": r"(?:subprocess\.(?:call|run|Popen|check_output)\s*\(.*shell\s*=\s*True|os\.(?:system|popen)\s*\([^)]+\)|(?<!\.)\bexec\s*\(\s*[a-zA-Z0-9_]+|\beval\s*\(\s*[a-zA-Z0-9_]+)",
        "explanation": "Executing commands via shell=True, os.system, os.popen, or dynamic exec() with unsanitized input.",
        "lesson": "Pass arguments as a sequence without shell=True; use ast.literal_eval instead of eval/exec.",
    },
    {
        "id": "SEC-CWE-78-COMMAND-INJECTION-SHELL",
        "cwe_id": "CWE-78",
        "title": "Command Injection / Unquoted Evaluation in Shell",
        "severity": "CRITICAL",
        "language": "Shell",
        "languages": ["shell"],
        "pattern": r'(?:eval\s+["\']?\$|\b(?:sh|bash)\s+-c\s+["\']?\$|\bexec\s+["\']?\$)',
        "explanation": "Unsanitized variables passed to eval, sh -c, or exec in shell script.",
        "lesson": "Avoid eval; use direct binary execution and strictly quote/validate all external parameters.",
    },
    {
        "id": "SEC-CWE-190-INTEGER-OVERFLOW-C",
        "cwe_id": "CWE-190",
        "title": "Integer Overflow or Wraparound in Allocation (C/C++)",
        "severity": "MEDIUM",
        "language": "C",
        "languages": ["c", "cpp"],
        "pattern": r"\b(?:malloc|kmalloc|kzalloc|vmalloc|xmalloc)\s*\(\s*([a-zA-Z0-9_]+)\s*(\*|\+)\s*([a-zA-Z0-9_]+)\s*(?:,[^)]+)?\)",
        "explanation": "Multiplication or addition inside allocation argument without bound or overflow check in C.",
        "lesson": "Use overflow-checked helpers (e.g. check_mul_overflow, calloc) or explicit bounds validation before allocation.",
    },
    {
        "id": "SEC-CWE-190-INTEGER-OVERFLOW-RUST",
        "cwe_id": "CWE-190",
        "title": "Integer Overflow in Allocation / Capacity (Rust)",
        "severity": "MEDIUM",
        "language": "Rust",
        "languages": ["rust"],
        "pattern": r"\b(?:Vec::with_capacity|alloc::alloc|Layout::array|Layout::from_size_align)\s*(?:<[^>]+>)?\s*\(\s*([a-zA-Z0-9_]+)\s*(\*|\+)\s*([a-zA-Z0-9_]+)",
        "explanation": "Unchecked arithmetic inside allocation size or capacity in Rust.",
        "lesson": "Use checked_mul() or checked_add() before computing collection capacity or layout size.",
    },
    {
        "id": "SEC-CWE-476-NULL-DEREFERENCE-C",
        "cwe_id": "CWE-476",
        "title": "Unchecked Return Value / NULL Pointer Dereference (C/C++)",
        "severity": "MEDIUM",
        "language": "C",
        "languages": ["c", "cpp"],
        "pattern": r"([a-zA-Z0-9_]+)\s*=\s*(?:malloc|kmalloc|kzalloc|fopen|strdup)\s*\([^;]+\);\s*(?!\s*if\s*\(\s*(?:!\s*\1|\1\s*==\s*NULL))\s*(?:\*\s*\1|\1\s*->)",
        "explanation": "Pointer dereferenced immediately after allocation without NULL check in C.",
        "lesson": "Always verify pointer return values against NULL before dereferencing.",
    },
    {
        "id": "SEC-CWE-476-NULL-DEREFERENCE-RUST",
        "cwe_id": "CWE-476",
        "title": "Unchecked Raw Pointer Dereference (Rust)",
        "severity": "MEDIUM",
        "language": "Rust",
        "languages": ["rust"],
        "pattern": r"(?:let\s+([a-zA-Z0-9_]+)\s*=\s*[^;]*as\s+\*(?:mut|const)\s+[a-zA-Z0-9_]+;(?![^;]*\1\.is_null\(\))[^;]*unsafe\s*\{\s*\*+\s*\1\b)",
        "explanation": "Raw pointer dereferenced in unsafe block without is_null() guard in Rust.",
        "lesson": "Validate raw pointers with .is_null() before dereferencing in unsafe blocks, or use NonNull.",
    },
    {
        "id": "SEC-CWE-362-CONCURRENCY-RACE-C",
        "cwe_id": "CWE-362",
        "title": "Race Condition / TOCTOU Window (C/C++)",
        "severity": "MEDIUM",
        "language": "C",
        "languages": ["c", "cpp"],
        "pattern": r"(?:(?:access|stat|lstat)\s*\(\s*([a-zA-Z0-9_\"'/]+)\s*,[^)]+\)(?:[^;]*;|[^\n]*)\s*[^;]*\b(?:fopen|open)\s*\(\s*\1\b|(?:spin_unlock|pthread_mutex_unlock|mutex_unlock)\s*\(&?([a-zA-Z0-9_]+)\);\s*(?:spin_lock|pthread_mutex_lock|mutex_lock)\s*\(&?\2\);)",
        "explanation": "TOCTOU check-then-open pattern or rapid unlock-relock window in C creates concurrency race window.",
        "lesson": "Use atomic open with O_CREAT|O_EXCL, or hold critical section invariants continuously.",
    },
    {
        "id": "SEC-CWE-362-CONCURRENCY-TOCTOU-PYTHON",
        "cwe_id": "CWE-362",
        "title": "Race Condition / TOCTOU File Access (Python)",
        "severity": "MEDIUM",
        "language": "Python",
        "languages": ["python"],
        "pattern": r"(?:if\s+os\.path\.exists\s*\(\s*([a-zA-Z0-9_]+)\s*\):[^:\n]*\n\s*(?:with\s+open|open)\s*\(\s*\1\b)",
        "explanation": "Checking os.path.exists() before open() introduces a TOCTOU race condition in Python.",
        "lesson": "Use atomic file operations (e.g. open with 'x' mode) or try/except FileExistsError/FileNotFoundError.",
    },
    {
        "id": "SEC-CWE-362-CONCURRENCY-TOCTOU-SHELL",
        "cwe_id": "CWE-362",
        "title": "Race Condition / TOCTOU File Operation (Shell)",
        "severity": "MEDIUM",
        "language": "Shell",
        "languages": ["shell"],
        "pattern": r'(?:if\s+\[\s*-[efrwxd]\s+["\']?\$[a-zA-Z0-9_]+["\']?\s*\];?\s*then[^;]+(?:\bcat\b|\bcp\b|\bmv\b|\brm\b|>)\s+[^;]*\$)',
        "explanation": "Testing file existence before operating on it in shell creates a TOCTOU race condition.",
        "lesson": "Use atomic file operations or mktemp; handle command error codes directly.",
    },
]


def _detect_language(filename):
    """Infer source language from filename extension."""
    if not filename or filename == "<buffer>":
        return None
    ext = Path(filename).suffix.lower()
    if ext in (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"):
        return "c"
    if ext in (".rs",):
        return "rust"
    if ext in (".py",):
        return "python"
    if ext in (".sh", ".bash"):
        return "shell"
    return None


def load_pattern_clusters(clusters_path):
    """Load pattern clusters JSON if available.

    Raises ValueError or FileNotFoundError on corrupt or unreadable files
    to prevent silent PASS verdicts when evidence assets are broken.
    """
    if not clusters_path:
        return {}
    path = Path(clusters_path)
    if not path.exists():
        raise FileNotFoundError(f"Pattern clusters file not found: {clusters_path}")
    if not path.is_file():
        raise ValueError(f"Pattern clusters path is not a file: {clusters_path}")
    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Corrupt pattern clusters JSON at {clusters_path}: {exc}") from exc
    except (PermissionError, OSError) as exc:
        raise PermissionError(f"Cannot read pattern clusters file {clusters_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Invalid pattern clusters JSON structure at {clusters_path}: root must be a dict")
    clusters = data.get("clusters", [])
    if not isinstance(clusters, list):
        raise ValueError(f"Invalid pattern clusters JSON structure at {clusters_path}: 'clusters' must be a list")
    return {c.get("cwe_id"): c for c in clusters if isinstance(c, dict) and "cwe_id" in c}


def scan_content(content, filename="<buffer>", cluster_map=None):
    """Scan text content for defensive security violations."""
    findings = []
    lines = content.splitlines()
    file_lang = _detect_language(filename)

    for rule in SECURITY_RULES:
        rule_langs = rule.get("languages", [])
        if file_lang and rule_langs and file_lang not in rule_langs:
            continue

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
    """Audit a file or directory recursively.

    If files are unreadable due to permission or I/O errors, explicit INCOMPLETE
    findings are generated to prevent a false-positive PASS verdict.
    """
    path = Path(target_path)
    if not path.exists():
        raise FileNotFoundError(f"Target path not found: {target_path}")

    all_findings = []
    files_audited = []

    if path.is_file():
        files_to_scan = [path]
    else:
        # Scan code files
        valid_exts = {".c", ".h", ".cpp", ".cc", ".rs", ".py", ".sh", ".bash", ".js", ".ts"}
        files_to_scan = [
            p for p in path.rglob("*")
            if p.is_file() and p.suffix.lower() in valid_exts and not any(part.startswith(".") for part in p.relative_to(path).parts)
        ]

    for f in sorted(files_to_scan):
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            f_findings = scan_content(content, filename=str(f), cluster_map=cluster_map)
            all_findings.extend(f_findings)
            files_audited.append(str(f))
        except (PermissionError, OSError) as exc:
            all_findings.append({
                "rule_id": "AUDIT-ERROR-UNREADABLE-FILE",
                "cwe_id": "CWE-732",
                "title": f"Unreadable File: {f.name}",
                "severity": "INCOMPLETE",
                "file": str(f),
                "line": 0,
                "snippet": f"{type(exc).__name__}: {exc}",
                "explanation": f"Audit cannot inspect file due to {type(exc).__name__}: {exc}",
                "lesson": "Ensure all codebase files in audit scope are readable and have proper permissions.",
                "cluster_reference": {
                    "cluster_cwe": "CWE-732",
                    "cluster_title": "Permission / I-O Read Failure",
                    "representative_cve": None,
                },
            })

    return files_audited, all_findings


def normalize_findings(findings):
    """Normalize and deterministically sort findings for hashing."""
    normalized = []
    for f in findings:
        cluster_ref = f.get("cluster_reference") or {}
        item = {
            "rule_id": str(f.get("rule_id", "")),
            "cwe_id": str(f.get("cwe_id", "")),
            "title": str(f.get("title", "")),
            "severity": str(f.get("severity", "")),
            "file": str(f.get("file", "")),
            "line": int(f.get("line", 0)),
            "snippet": str(f.get("snippet", "")).strip(),
            "explanation": str(f.get("explanation", "")),
            "lesson": str(f.get("lesson", "")),
            "cluster_reference": {
                "cluster_cwe": str(cluster_ref.get("cluster_cwe", "")),
                "cluster_title": str(cluster_ref.get("cluster_title", "")),
                "representative_cve": cluster_ref.get("representative_cve"),
            } if cluster_ref else {},
        }
        normalized.append(item)

    normalized.sort(key=lambda x: (x["file"], x["line"], x["rule_id"], x["cwe_id"]))
    return normalized


def compute_evidence_hash(target, files_audited, findings, verdict, ksm_pack_ref, rules_applied):
    """Compute deterministic cryptographic hash over audited content."""
    sorted_files = sorted(str(f) for f in files_audited)
    normalized = normalize_findings(findings)
    deterministic_payload = {
        "files_audited": sorted_files,
        "files_audited_count": len(sorted_files),
        "findings": normalized,
        "findings_count": len(normalized),
        "ksm_pack_reference": str(ksm_pack_ref),
        "rules_applied": sorted(str(r) for r in rules_applied),
        "target": str(target),
        "verdict": str(verdict),
    }
    serialized = json.dumps(deterministic_payload, sort_keys=True, ensure_ascii=False)
    chain_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return chain_hash, deterministic_payload


def build_evidence_chain(target, files_audited, findings, ksm_pack_ref="kernel-security-memory-bootstrap-v0", rules_applied=None, errors=None):
    """Construct a cryptographic evidence chain for the audit.

    The evidence_chain_hash is computed strictly from deterministic audit artifacts
    (target, files_audited, findings, verdict, ksm_pack_reference, rules_applied),
    excluding the volatile timestamp to ensure 100% reproducible hashes across runs.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    if rules_applied is None:
        rules_applied = [r["id"] for r in SECURITY_RULES]

    # Severity assessment
    severities = {f.get("severity") for f in findings}
    if errors or "INCOMPLETE" in severities or "ERROR" in severities:
        verdict = "INCOMPLETE"
    elif "CRITICAL" in severities or "HIGH" in severities:
        verdict = "FAIL"
    elif "MEDIUM" in severities or "LOW" in severities:
        verdict = "WARN"
    else:
        verdict = "PASS"

    sorted_files = sorted(str(f) for f in files_audited)
    normalized = normalize_findings(findings)

    chain_hash, deterministic_payload = compute_evidence_hash(
        target=target,
        files_audited=sorted_files,
        findings=normalized,
        verdict=verdict,
        ksm_pack_ref=ksm_pack_ref,
        rules_applied=rules_applied,
    )

    audit_payload = {
        "schema_version": "defensive-evidence-chain-v1",
        "target": str(target),
        "timestamp": now_utc,
        "files_audited_count": len(sorted_files),
        "files_audited": sorted_files,
        "findings_count": len(normalized),
        "findings": normalized,
        "verdict": verdict,
        "ksm_pack_reference": ksm_pack_ref,
        "rules_applied": sorted(str(r) for r in rules_applied),
        "deterministic_payload": deterministic_payload,
    }
    if errors:
        audit_payload["errors"] = errors

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
                        help="Exit code 1 on HIGH/CRITICAL findings or INCOMPLETE status")
    args = parser.parse_args(argv)

    try:
        cluster_map = load_pattern_clusters(args.clusters)
    except Exception as exc:
        print(f"Error loading pattern clusters: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        files_audited, findings = audit_path(args.target, cluster_map=cluster_map)
    except Exception as exc:
        print(f"Error during audit traversal: {exc}", file=sys.stderr)
        sys.exit(2)

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

    if args.strict and evidence["audit"]["verdict"] in ("FAIL", "INCOMPLETE"):
        sys.exit(1)


if __name__ == "__main__":
    main()
