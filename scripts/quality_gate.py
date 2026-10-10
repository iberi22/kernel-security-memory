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
3. Freshness (staleness):
   When an existing evidence file is supplied, its hash must still equal a fresh audit
   of the same target. Reporting the fresh hash instead would launder a citation that
   no longer describes the tree, so a mismatch is verdict STALE and is fatal.
4. Non-incomplete and Clean Verdict:
   The audit verdict must be 'PASS'. Rejects 'FAIL', 'WARN' (in strict mode),
   and 'INCOMPLETE' (broken permissions, missing files, or corrupt clusters).

Targets recorded in an evidence file are relative to the repository root, never to the
current working directory, so a gate invoked from any directory resolves the same tree.

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
DEFAULT_KSM_PACK_REF = "kernel-security-memory-bootstrap-v0"


def find_repo_root(start, target=None):
    """Return the nearest ancestor of ``start`` that contains ``.git``, else None.

    This is the anchor that makes evidence verification independent of the process
    working directory: an evidence file records a repository-relative target.

    When ``target`` is given, only ancestors that actually hold it qualify, so an
    unrelated ``.git`` above the tree cannot silently become the anchor.
    """
    current = Path(start).resolve()
    for candidate in [current, *current.parents]:
        if not (candidate / ".git").exists():
            continue
        if target is None or (candidate / target).exists():
            return candidate
    return None


def canonical_repo_path(path, repo_root):
    """Express ``path`` relative to ``repo_root`` when possible.

    ``audit_path`` records the paths it walked, so evidence generated with a relative
    target and evidence generated with an absolute target describe the same tree with
    different strings. Canonicalising both sides is what makes a stored/fresh hash
    comparison meaningful instead of an artefact of how the audit was invoked. With no
    ``repo_root`` the path is returned unchanged, which still compares like with like
    because both sides go through the same function.
    """
    raw = Path(path)
    if repo_root is None or not raw.is_absolute():
        return raw.as_posix()
    try:
        return raw.resolve().relative_to(Path(repo_root)).as_posix()
    except (ValueError, OSError):
        return raw.as_posix()


def evidence_repo_root(evidence_path, target, repo_root=None):
    """Anchor a stored evidence target, or None when there is nothing to anchor to.

    A relative target needs the anchor (it is meaningless without a repository root), an
    absolute target does not. ``--repo-root`` always wins.
    """
    if repo_root is not None:
        return Path(repo_root)
    if evidence_path is None:
        return None
    parent = Path(evidence_path).resolve().parent
    if target and not Path(target).is_absolute():
        return find_repo_root(parent, target)
    return find_repo_root(parent)


def _stored_audit_metadata(audit):
    """Read (ksm_pack_reference, rules_applied) from a stored audit block."""
    return (
        audit.get("ksm_pack_reference", DEFAULT_KSM_PACK_REF),
        audit.get("rules_applied", [r["id"] for r in SECURITY_RULES]),
    )


def canonical_stored_hash(audit, repo_root):
    """Recompute the evidence hash of a stored audit block with canonical paths."""
    ksm_pack_ref, rules_applied = _stored_audit_metadata(audit)
    files = [canonical_repo_path(f, repo_root) for f in audit.get("files_audited", [])]
    findings = [
        dict(finding, file=canonical_repo_path(finding.get("file"), repo_root))
        for finding in audit.get("findings", [])
    ]
    digests = {
        canonical_repo_path(p, repo_root): digest
        for p, digest in (audit.get("file_digests") or {}).items()
    }
    chain_hash, _ = compute_evidence_hash(
        target=canonical_repo_path(audit.get("target"), repo_root),
        files_audited=files,
        findings=findings,
        verdict=audit.get("verdict", ""),
        ksm_pack_ref=ksm_pack_ref,
        rules_applied=rules_applied,
        file_digests=digests,
    )
    return chain_hash


def audit_current_state(target_path, repo_root, clusters_path, ksm_pack_ref, rules_applied):
    """Audit the tree at ``target_path`` and hash it with repo-relative paths."""
    cluster_map = load_pattern_clusters(clusters_path)
    files, findings, digests = audit_path(target_path, cluster_map=cluster_map)
    canonical_findings = [
        dict(finding, file=canonical_repo_path(finding.get("file"), repo_root))
        for finding in findings
    ]
    canonical_digests = {
        canonical_repo_path(p, repo_root): digest for p, digest in digests.items()
    }
    return build_evidence_chain(
        target=canonical_repo_path(target_path, repo_root),
        files_audited=[canonical_repo_path(f, repo_root) for f in files],
        findings=canonical_findings,
        ksm_pack_ref=ksm_pack_ref,
        rules_applied=rules_applied,
        file_digests=canonical_digests,
    )



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
    file_digests = audit.get("file_digests")

    expected_hash, _ = compute_evidence_hash(
        target=target,
        files_audited=files_audited,
        findings=findings,
        verdict=verdict,
        ksm_pack_ref=ksm_pack_ref,
        rules_applied=rules_applied,
        file_digests=file_digests,
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
        files, findings, file_digests = audit_path(target, cluster_map=cluster_map)
        evidence = build_evidence_chain(target, files, findings, file_digests=file_digests)
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
    evidence_path=None,
    repo_root=None,
):
    """Evaluate quality gate criteria for Xavier publication.

    ``evidence_path`` (the file ``evidence_data`` was read from) anchors relative
    targets to the repository root instead of the current working directory.

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
        raw_target = target or audit.get("target")
        if repo_root is None:
            repo_root = evidence_repo_root(evidence_path, raw_target)
        if repo_root is None:
            return {
                "status": "REJECTED",
                "authorized": False,
                "reason": (
                    f"cannot resolve relative target {raw_target!r} without a repository "
                    "root: no ancestor of the evidence file holds both .git and that "
                    "target; pass --repo-root"
                ),
                "timestamp": now_utc,
            }
        repo_root = Path(repo_root)
        target = (Path(raw_target) if Path(raw_target).is_absolute()
                  else repo_root / raw_target)
        if clusters_path is None:
            clusters_path = str(repo_root / "docs" / "studies" / "pattern_clusters.json")
        elif not Path(clusters_path).is_absolute():
            clusters_path = str(repo_root / clusters_path)

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

    # Freshness: a stored hash that no longer describes this tree must not be
    # laundered by reporting the fresh hash instead.
    if evidence_data:
        stored_audit = evidence_data.get("audit", {})
        stored_hash = evidence_data.get("evidence_chain_hash")
        ksm_pack_ref, rules_applied = _stored_audit_metadata(stored_audit)
        try:
            fresh_evidence = audit_current_state(
                target_path=target,
                repo_root=repo_root,
                clusters_path=clusters_path,
                ksm_pack_ref=ksm_pack_ref,
                rules_applied=rules_applied,
            )
        except Exception as exc:
            return {
                "status": "REJECTED",
                "authorized": False,
                "target": str(target),
                "verdict": verdict,
                "reason": f"Staleness re-audit failed: {type(exc).__name__}: {exc}",
                "timestamp": now_utc,
            }
        expected_stored_hash = canonical_stored_hash(stored_audit, repo_root)
        fresh_hash = fresh_evidence["evidence_chain_hash"]
        if expected_stored_hash != fresh_hash:
            return {
                "status": "STALE",
                "authorized": False,
                "target": str(target),
                "verdict": fresh_evidence["audit"]["verdict"],
                "evidence_chain_hash": stored_hash,
                "stored_evidence_chain_hash": stored_hash,
                "fresh_evidence_chain_hash": fresh_hash,
                "files_audited_count": fresh_evidence["audit"]["files_audited_count"],
                "findings_count": fresh_evidence["audit"]["findings_count"],
                "reason": (
                    "Stored evidence is stale: its evidence_chain_hash no longer matches "
                    "a fresh audit of the same target. Re-run the auditor on this tree and "
                    "re-cite the new hash."
                ),
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
    # When evidence was supplied, report the cited hash: the freshness check above has
    # already proven it equals a fresh audit of this tree.
    cited_hash = (evidence_data.get("evidence_chain_hash", chain_hash)
                  if evidence_data else chain_hash)
    return {
        "status": "AUTHORIZED",
        "authorized": True,
        "target": str(target),
        "verdict": verdict,
        "evidence_chain_hash": cited_hash,
        "fresh_evidence_chain_hash": chain_hash,
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
    parser.add_argument("--clusters", default=None,
                        help="Path to pattern_clusters.json (default: "
                             "docs/studies/pattern_clusters.json, anchored at the "
                             "repository root of --evidence when one is found)")
    parser.add_argument("--runs", type=int, default=2,
                        help="Number of verification runs for reproducibility check")
    parser.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True,
                        help="Enforce strict gate (reject WARN, FAIL, INCOMPLETE)")
    parser.add_argument("--prefix", default=DEFAULT_XAVIER_PREFIX,
                        help=f"Xavier publication path prefix (default: {DEFAULT_XAVIER_PREFIX})")
    parser.add_argument("--output", help="Optional path to write authorization report JSON")
    parser.add_argument("--repo-root", help="Repository root used to resolve relative "
                        "targets recorded in --evidence (default: nearest ancestor of the "
                        "evidence file containing .git)")
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
        evidence_path=args.evidence,
        repo_root=args.repo_root,
    )

    out_json = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(out_json + "\n", encoding="utf-8")
        print(f"Quality gate report written to {args.output}")

    print(f"Target: {result.get('target', '<unknown>')}")
    print(f"Quality Gate Status: {result.get('status')}")
    print(f"Verdict: {result.get('verdict', '<unknown>')}")
    print(f"Evidence Chain Hash: {result.get('evidence_chain_hash', '<none>')}")
    if result.get("status") == "STALE":
        print(f"Stored Evidence Chain Hash: {result.get('stored_evidence_chain_hash')}")
        print(f"Fresh Audit Evidence Chain Hash: {result.get('fresh_evidence_chain_hash')}")
    if result.get("authorized"):
        print(f"Publication Authorized: YES -> {result.get('publication_prefix')}")
        sys.exit(0)
    else:
        print(f"Publication Authorized: NO -> {result.get('reason')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
