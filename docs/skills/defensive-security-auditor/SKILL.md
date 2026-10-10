---
name: defensive-security-auditor
description: Defensive Security Specialist Auditor for SWAL agents (Jules, Hermes, Antigravity). Enforces pre-commit and pre-PR defensive contracts before writing sensitive C, Rust, Python, or shell code. Audits code against CVE pattern clusters, requires deterministic evidence chain hashes, and blocks vulnerable code with fail-closed gating.
version: 1.2.0
author: SWAL Kernel Security Memory Team
languages:
  - C
  - Rust
  - Python
  - shell
---

# Defensive Security Specialist Auditor

## Overview
The **Defensive Security Specialist Auditor** acts as an automated, non-repudiable security verification gate for all code written or modified by autonomous agents in SWAL (**Jules**, **Hermes**, **Antigravity**).

It grounds vulnerability detection directly in empirical evidence from the **Kernel Security Memory (KSM)** corpus and Top-30 open-source catalog studies (`pattern_clusters.json`).

---

## Explicit Language Triggers

Any autonomous agent (`Jules`, `Hermes`, `Antigravity`) modifying code in the following languages MUST activate this skill before writing or staging changes:

### 1. C (`.c`, `.h`)
- **Triggers**: Memory allocation/deallocation (`malloc`, `kmalloc`, `kzalloc`, `free`, `kfree`), string manipulation (`strcpy`, `strcat`, `sprintf`, `snprintf`), pointer arithmetic, array indexing, lock acquisition/release (`spin_lock`, `spin_unlock`, `mutex_lock`), parsing untrusted network/file formats.
- **Mandatory Defensive Rule**: Verify spatial bounds prior to copy, nullify pointers immediately after `free`, check allocation returns against `NULL`, enforce lock hierarchy without TOCTOU drop/re-acquire windows.

### 2. Rust (`.rs`)
- **Triggers**: Usage of `unsafe` blocks, raw pointer dereferences (`*const T`, `*mut T`), FFI declarations (`extern "C"`), `std::mem::transmute`, interior mutability (`UnsafeCell`, `RefCell`), manual memory layouts (`#[repr(C)]`), atomic operations and concurrency barriers.
- **Mandatory Defensive Rule**: Isolate `unsafe` behind sound, invariant-asserting abstractions; prevent aliasing violations; guarantee lifetime invariants match caller expectations.

### 3. Python (`.py`)
- **Triggers**: Process execution (`subprocess.call`, `subprocess.Popen`, `os.system`), dynamic evaluation (`eval`, `exec`), filesystem path joining from user inputs, regex compilation over untrusted inputs, serialization/deserialization (`pickle`, `yaml.load`).
- **Mandatory Defensive Rule**: Use parameterized argument lists (`shell=False`), validate inputs against strict allowlists, reject untrusted deserialization.

### 4. Shell (`.sh`, `.bash`, workflows)
- **Triggers**: Shell scripts, CI/CD execution steps (`.github/workflows/*.yml`), dynamic variable evaluation, unquoted parameter expansions (`$VAR`), pipes to `sh` or `bash`, temporary file creation in shared directories.
- **Mandatory Defensive Rule**: Quote all expansions (`"$VAR"`), enable `set -euo pipefail`, eliminate command-string injection vectors.

---

## Agent Pre-Commit & Pre-PR Contracts

All autonomous agents must abide by the following non-negotiable protocol:

### Pre-Commit Contract
1. **Pre-Flight Execution**: Prior to executing `git commit` or submitting patches, the agent MUST run the auditor against all staged or modified files.
2. **Fail-Closed Gate**: If the audit returns a verdict of `FAIL` (HIGH or CRITICAL findings) or `INCOMPLETE` (unreadable files or broken schemas), the agent **must not commit**. The agent is obligated to fix the violation locally before proceeding.
3. **Evidence Generation**: The audit MUST emit a structured evidence record with a deterministic `evidence_chain_hash`.

### Pre-PR Contract
1. **Evidence Citation**: Any Pull Request opened by Jules, Hermes, or Antigravity MUST include in its PR description:
   - The computed `evidence_chain_hash` (64-char lowercase SHA256).
   - The audited files count and verdict (`PASS`).
   - Statement that zero HIGH/CRITICAL patterns were introduced.
2. **Reproducibility Guarantee**: The `evidence_chain_hash` must be identical across sequential runs on the same tree state (timestamp-independent).

---

## Mandatory Checks to Invoke

Agents must invoke the following verification commands:

### Check 1: Mandatory Defensive Audit Scan
Run the specialist auditor in `--strict` mode over the changed files or directory:

```bash
python3 scripts/defensive_auditor.py \
    --target <path/to/target/or/file> \
    --clusters docs/studies/pattern_clusters.json \
    --output docs/studies/audit-evidence.json \
    --strict
```

- **Exit code 0**: Verdict is `PASS` or `WARN` (LOW/MEDIUM). Safe to proceed.
- **Exit code 1**: Verdict is `FAIL` (HIGH/CRITICAL) or `INCOMPLETE`. Commit/PR is BLOCKED.

### Check 2: Cryptographic Hash Reproducibility Verification
Verify that the generated evidence chain is deterministic, reproducible, **and** bound to
the audited tree state (each audited file's content digest is part of the hashed payload):

```bash
python3 -c "
from scripts.defensive_auditor import audit_path, build_evidence_chain

def run():
    files, findings, digests = audit_path('<path/to/target>')
    return build_evidence_chain('<path/to/target>', files, findings, file_digests=digests)

e1 = run()
e2 = run()
assert e1['evidence_chain_hash'] == e2['evidence_chain_hash'], 'Non-deterministic evidence chain hash!'
assert e1['audit']['file_digests'], 'Evidence chain must bind each audited file digest'
print('Evidence chain hash verified reproducible:', e1['evidence_chain_hash'])
"
```

Equivalently, use the quality gate helper, which audits the target once per run:

```bash
python3 -c "
from scripts.quality_gate import verify_reproducible_runs
ok, hashes, evidence = verify_reproducible_runs('<path/to/target>', runs=2)
assert ok, f'Hashes diverged: {hashes}'
print('Reproducible across runs:', hashes[0])
"
```

Because the payload carries per-file SHA-256 digests, re-auditing after a code change
must produce a **different** hash: a hash cited for older content no longer verifies.

### Check 2b: Gate an Existing Evidence File

Re-auditing an evidence file is not enough: the gate must also refuse the citation when
its stored `evidence_chain_hash` no longer matches the tree. Verdict `STALE` and a
non-zero exit code mean the evidence was produced on different content; re-run the
auditor and cite the new hash.

```bash
python3 scripts/quality_gate.py --target scripts --evidence docs/studies/audit_evidence_scripts.json
```

| Exit code | Status | Meaning |
|---|---|---|
| 0 | `AUTHORIZED` | Stored hash still equals a fresh audit of the same target, verdict `PASS` |
| 1 | `STALE` | Stored hash differs from a fresh audit: re-audit and re-cite |
| 1 | `REJECTED` | Verdict is `FAIL`/`WARN`/`INCOMPLETE`, hash diverged between runs, or integrity failed |
| 2 | — | The evidence or clusters file could not be read |

Targets recorded in the evidence file are resolved against the repository root of the
evidence file, not against the current working directory, so the same verdict is produced
from any directory. Pass `--repo-root` when that anchor is ambiguous.

### Check 3: Guardrails Reference (per-family evidence)

Load `references/guardrails.md` (machine-readable twin: `references/guardrails.json`)
when you are about to write code in one of the audited languages, or when you need the
evidence behind a rule before arguing about a finding. It is generated by
`scripts/build_guardrails.py` from repository data only, and it has one section per CWE
family that has **both** an auditor rule **and** at least one 40-hex fix commit in
`docs/memory/records` or `docs/studies/cve-history`. Each section gives the trigger
(language family plus the regex the rule matches), the check to run, and up to three
example citations (advisory id, project, fix commit URL).

```bash
python3 scripts/build_guardrails.py --check           # drift guard for CI
python3 scripts/build_guardrails.py --verify-citations
```

Read the section for the family you are touching before writing the fix. Each fix
commit URL is the commit the corpus records as the fix for that advisory: open the diff
and read it, and do not treat the link as proof that the change was complete. Families
in the closing table have rules but **no** in-repo fix commit, so treat their remediation
as unverified until a commit lands in the corpora above.

### Check 4: Language-Specific CWE Invariant Verification
The auditor validates code against canonical CWE vulnerability archetypes:

| CWE ID | Archetype | Target Languages | Invariant Required |
|---|---|---|---|
| **CWE-120** | Unbounded Buffer Copy | C | Bounded copy with explicit length check (`strncpy`, `snprintf`) |
| **CWE-416** | Use-After-Free | C, Rust (unsafe) | Immediate pointer nullification after free; strict lifetime invariants |
| **CWE-78** | OS Command Injection | C, Python, Shell | Parameterized argument lists; `shell=False`; strict quoting |
| **CWE-190** | Integer Overflow in Alloc | C, Rust | Overflow-checked arithmetic before allocation (`calloc`, `check_mul_overflow`) |
| **CWE-476** | NULL Pointer Dereference | C, Rust (unsafe) | Mandatory non-NULL check on allocation return prior to dereference |
| **CWE-362** | Concurrency TOCTOU Window | C, Python, Shell | Atomicity across check-and-act; no premature lock dropping |

Only these language families have rules: **C/C++** (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`,
`.hpp`), **Rust** (`.rs`), **Python** (`.py`), **shell** (`.sh`, `.bash`). Other extensions
are not traversed, so no rules are applied to them.

Rule IDs are language-suffixed; the full list is `SECURITY_RULES` in
`scripts/defensive_auditor.py`:

| CWE | Rule IDs |
|---|---|
| CWE-120 | `SEC-CWE-120-UNBOUNDED-COPY` |
| CWE-416 | `SEC-CWE-416-USE-AFTER-FREE-C`, `SEC-CWE-416-USE-AFTER-FREE-RUST` |
| CWE-78 | `SEC-CWE-78-COMMAND-INJECTION-C`, `SEC-CWE-78-COMMAND-INJECTION-PYTHON`, `SEC-CWE-78-COMMAND-INJECTION-SHELL` |
| CWE-190 | `SEC-CWE-190-INTEGER-OVERFLOW-C`, `SEC-CWE-190-INTEGER-OVERFLOW-RUST` |
| CWE-476 | `SEC-CWE-476-NULL-DEREFERENCE-C`, `SEC-CWE-476-NULL-DEREFERENCE-RUST` |
| CWE-362 | `SEC-CWE-362-CONCURRENCY-RACE-C`, `SEC-CWE-362-CONCURRENCY-TOCTOU-PYTHON`, `SEC-CWE-362-CONCURRENCY-TOCTOU-SHELL` |

---

## Evidence Chain Schema Contract

The evidence JSON emitted by the auditor conforms to `defensive-evidence-chain-v1`:

```json
{
  "evidence_chain_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "audit": {
    "schema_version": "defensive-evidence-chain-v1",
    "target": "scripts/studies",
    "timestamp": "2026-10-09T02:00:00Z",
    "files_audited_count": 14,
    "files_audited": [
      "scripts/studies/base_history_fetcher.py",
      "scripts/studies/build_catalog_manifest.py"
    ],
    "findings_count": 0,
    "findings": [],
    "verdict": "PASS",
    "ksm_pack_reference": "kernel-security-memory-bootstrap-v0",
    "rules_applied": [
      "SEC-CWE-120-UNBOUNDED-COPY",
      "SEC-CWE-190-INTEGER-OVERFLOW-C",
      "SEC-CWE-416-USE-AFTER-FREE-C",
      "SEC-CWE-476-NULL-DEREFERENCE-C",
      "SEC-CWE-78-COMMAND-INJECTION-PYTHON",
      "SEC-CWE-362-CONCURRENCY-TOCTOU-SHELL"
    ],
    "file_digests": {
      "scripts/studies/base_history_fetcher.py": "9f2c1d0a7b3e4f5a6b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c"
    },
    "deterministic_payload": { ... }
  }
}
```
