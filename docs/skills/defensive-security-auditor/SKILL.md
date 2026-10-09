---
name: defensive-security-auditor
description: Defensive Security Specialist Auditor for SWAL agents. Analyzes patches, PRs, and C/Rust/Python code against known CVE pattern clusters and KSM evidence packs. Emits a cryptographically verifiable evidence chain hash for strict quality gating.
version: 1.0.0
author: SWAL Kernel Security Memory Team
---

# Defensive Security Specialist Auditor

## Overview
The **Defensive Security Specialist Auditor** acts as an automated, non-repudiable security verification gate for all code written or modified by autonomous agents in SWAL.

It grounds vulnerability detection directly in empirical evidence from the **Kernel Security Memory (KSM)** corpus and Top-30 open-source catalog studies (`pattern_clusters.json`).

## Core Responsibilities
1. **Empirical Vulnerability Auditing**:
   - Evaluates code against historical vulnerability archetypes (Buffer Overflows, Use-After-Free, Command Injection, Integer Overflows, Concurrency Windows).
   - Maps detected patterns directly to CWE clusters and historical CVE precedents.

2. **Verifiable Evidence Chain**:
   - Every audit produces a deterministic `evidence_chain_hash` (SHA256).
   - Records the exact audited files, matched rules, CWE IDs, and remediation lessons.
   - Enforces a fail-closed policy (`FAIL` verdict on HIGH or CRITICAL issues).

3. **Causal Remediation Lessons**:
   - Provides concrete defensive invariants rather than abstract advice (e.g. lifetime pairing for garbage collection, safe bounded allocators).

## Usage & Execution

Run the auditor against any file, directory, or patch:

```bash
python3 scripts/defensive_auditor.py \
    --target <path/to/code> \
    --clusters docs/studies/pattern_clusters.json \
    --output docs/studies/audit-evidence.json \
    --strict
```

### Options
- `--target`: Target file or directory to scan.
- `--clusters`: Path to `pattern_clusters.json` (defaults to `docs/studies/pattern_clusters.json`).
- `--output`: Optional file to persist the structured JSON evidence chain.
- `--strict`: Fails with non-zero exit code if HIGH or CRITICAL severity findings are detected.

## Evidence Contract
The evidence JSON output schema:
```json
{
  "evidence_chain_hash": "<sha256>",
  "audit": {
    "schema_version": "defensive-evidence-chain-v1",
    "target": "<target-path>",
    "timestamp": "<iso8601-utc>",
    "files_audited_count": 12,
    "findings_count": 0,
    "findings": [],
    "verdict": "PASS",
    "ksm_pack_reference": "kernel-security-memory-bootstrap-v0"
  }
}
```
