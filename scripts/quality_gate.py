#!/usr/bin/env python3
"""Quality Gate for KSM and Xavier Publication.

Enforces strict verification of defensive security audit evidence chains
before granting authorization to publish memories or guardrails to Xavier
under the prefix ``ksm-guardrail/``.

Verification criteria:
1. Deterministic evidence chain hash integrity:
   Recomputed SHA-256 over deterministic payload must match the emitted hash.
2. Reproducibility:
   Multiple independent audit passes on the same target must produce identical hashes.
3. Non-incomplete and Clean Verdict:
   The audit verdict must be 'PASS'. Rejects 'FAIL', 'WARN' (in strict mode),
   and 'INCOMPLETE' (broken permissions, missing files, or corrupt clusters).

Stdlib only.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure scripts directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from defensive_auditor import (
    SECURITY_RULES,
    audit_path,
    build_evidence_chain,
    compute_evidence_hash,
    load_pattern_clusters,
)

DEFAULT_XAVIER_PREFIX = "ksm-guardrail/"


def verify_evidence_integrity(evidence_dict):
    """Verify cryptographic integrity of an evidence chain JSON structure.

    Returns:
        tuple[bool, str]: (is_valid, message)
    """
    if not isinstance(evidence_dict, dict):
        return False, "Evidence payload is not a dictionary"

    chain_hash = evidence_dict.get("evidence_chain_hash")
    audit = evidence_dict.get("audit")

    if not chain_hash or not isinstance(chain_hash, str) or len(chain_hash) != 64:
        return False, "Missing or invalid evidence_chain_hash format"
    if not audit or not isinstance(audit, dict):
        return False, "Missing or invalid audit object in evidence"

    target = audit.get("target")
    files_audited = audit.get("files_audited", [])
    findings = audit.get("findings", [])
    verdict = audit.get("verdict", "")
    ksm_pack_ref = audit.get("ksm_pack_reference", "kernel-security-memory-bootstrap-v0")
    rules_applied = audit.get("rules_applied", [r["id"] for r in SECURITY_RULES])

    expected_hash, _ = compute_evidence_hash(
        target=target,
        files_audited=files_audited,
        findings=findings,
        verdict=verdict,
        ksm_pack_ref=ksm_pack_ref,
        rules_applied=rules_applied,
    )

    if chain_hash != expected_hash:
        return False, f"Hash mismatch: reported {chain_hash} != expected {expected_hash}"

    return True, f"Evidence hash verified successfully: {chain_hash}"


def verify_reproducible_runs(target, runs=2, clusters_path=None):
    """Execute consecutive audit passes on target and check for hash identity.

    Returns:
        tuple[bool, list[str], dict]: (is_reproducible, list_of_hashes, last_evidence)
    """
    cluster_map = load_pattern_clusters(clusters_path)
    hashes = []
    last_evidence = None

    for _ in range(max(2, runs)):
        files, findings = audit_path(target, cluster_map=cluster_map)
        evidence = build_evidence_chain(target, files, findings)
        hashes.append(evidence["evidence_chain_hash"])
        last_evidence = evidence

    is_reproducible = len(set(hashes)) == 1
    return is_reproducible, hashes, last_evidence


def evaluate_quality_gate(
    target=None,
    evidence_data=None,
    clusters_path=None,
    reproducibility_runs=2,
    strict=True,
    xavier_prefix=DEFAULT_XAVIER_PREFIX,
):
    """Evaluate quality gate criteria for Xavier publication.

    Returns:
        dict: Structured quality gate decision and authorization receipt.
    """
    now_utc = datetime.now(timezone.utc).isoformat()

    # If existing evidence is provided, verify its integrity first
    if evidence_data:
        valid_hash, msg = verify_evidence_integrity(evidence_data)
        if not valid_hash:
            return {
                "status": "REJECTED",
                "authorized": False,
                "reason": f"Integrity failure on provided evidence: {msg}",
                "timestamp": now_utc,
            }
        audit = evidence_data.get("audit", {})
        target = target or audit.get("target")

    if not target:
        return {
            "status": "REJECTED",
            "authorized": False,
            "reason": "No target path specified for evaluation",
            "timestamp": now_utc,
        }

    # Verify reproducibility across consecutive runs
    try:
        is_reproducible, hashes, evidence = verify_reproducible_runs(
            target=target,
            runs=reproducibility_runs,
            clusters_path=clusters_path,
        )
    except Exception as exc:
        return {
            "status": "REJECTED",
            "authorized": False,
            "target": str(target),
            "reason": f"Audit execution failed: {type(exc).__name__}: {exc}",
            "timestamp": now_utc,
        }

    chain_hash = hashes[0]
    verdict = evidence["audit"]["verdict"]

    if not is_reproducible:
        return {
            "status": "REJECTED",
            "authorized": False,
            "target": str(target),
            "verdict": verdict,
            "evidence_chain_hash": chain_hash,
            "observed_hashes": hashes,
            "reason": "Evidence chain hash is not reproducible across consecutive runs",
            "timestamp": now_utc,
        }

    # Check verdict
    if verdict == "INCOMPLETE":
        return {
            "status": "REJECTED",
            "authorized": False,
            "target": str(target),
            "verdict": verdict,
            "evidence_chain_hash": chain_hash,
            "reason": "Audit verdict is INCOMPLETE (unreadable files or broken environment)",
            "timestamp": now_utc,
        }

    if verdict == "FAIL":
        return {
            "status": "REJECTED",
            "authorized": False,
            "target": str(target),
            "verdict": verdict,
            "evidence_chain_hash": chain_hash,
            "findings_count": len(evidence["audit"]["findings"]),
            "reason": "Audit verdict is FAIL (critical or high security findings detected)",
            "timestamp": now_utc,
        }

    if strict and verdict == "WARN":
        return {
            "status": "REJECTED",
            "authorized": False,
            "target": str(target),
            "verdict": verdict,
            "evidence_chain_hash": chain_hash,
            "findings_count": len(evidence["audit"]["findings"]),
            "reason": "Audit verdict is WARN and strict quality gating is enabled",
            "timestamp": now_utc,
        }

    # Check integrity of final evidence
    valid_hash, msg = verify_evidence_integrity(evidence)
    if not valid_hash:
        return {
            "status": "REJECTED",
            "authorized": False,
            "target": str(target),
            "verdict": verdict,
            "evidence_chain_hash": chain_hash,
            "reason": f"Evidence hash failed cryptographic integrity: {msg}",
            "timestamp": now_utc,
        }

    # All checks passed! Authorize publication to Xavier
    return {
        "status": "AUTHORIZED",
        "authorized": True,
        "target": str(target),
        "verdict": verdict,
        "evidence_chain_hash": chain_hash,
        "publication_prefix": str(xavier_prefix),
        "files_audited_count": evidence["audit"]["files_audited_count"],
        "findings_count": evidence["audit"]["findings_count"],
        "runs_verified": len(hashes),
        "authorized_at": now_utc,
        "evidence": evidence,
        "message": (
            f"Quality gate PASSED: hash verified, reproducible, and verdict '{verdict}'. "
            f"Authorized for Xavier publication at {xavier_prefix}"
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="Path to code file or directory to verify")
    parser.add_argument("--evidence", help="Path to existing evidence JSON file to verify")
    parser.add_argument("--clusters", default="docs/studies/pattern_clusters.json",
                        help="Path to pattern_clusters.json")
    parser.add_argument("--runs", type=int, default=2,
                        help="Number of verification runs for reproducibility check")
    parser.add_argument("--strict", action="store_true", default=True,
                        help="Enforce strict gate (reject WARN, FAIL, INCOMPLETE)")
    parser.add_argument("--prefix", default=DEFAULT_XAVIER_PREFIX,
                        help=f"Xavier publication path prefix (default: {DEFAULT_XAVIER_PREFIX})")
    parser.add_argument("--output", help="Optional path to write authorization report JSON")
    args = parser.parse_args(argv)

    if not args.target and not args.evidence:
        parser.error("Either --target or --evidence must be provided")

    evidence_data = None
    if args.evidence:
        try:
            content = Path(args.evidence).read_text(encoding="utf-8")
            evidence_data = json.loads(content)
        except Exception as exc:
            print(f"Error reading evidence file {args.evidence}: {exc}", file=sys.stderr)
            sys.exit(2)

    result = evaluate_quality_gate(
        target=args.target,
        evidence_data=evidence_data,
        clusters_path=args.clusters,
        reproducibility_runs=args.runs,
        strict=args.strict,
        xavier_prefix=args.prefix,
    )

    out_json = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(out_json + "\n", encoding="utf-8")
        print(f"Quality gate report written to {args.output}")

    print(f"Target: {result.get('target', '<unknown>')}")
    print(f"Quality Gate Status: {result.get('status')}")
    print(f"Verdict: {result.get('verdict', '<unknown>')}")
    print(f"Evidence Chain Hash: {result.get('evidence_chain_hash', '<none>')}")
    if result.get("authorized"):
        print(f"Publication Authorized: YES -> {result.get('publication_prefix')}")
        sys.exit(0)
    else:
        print(f"Publication Authorized: NO -> {result.get('reason')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
