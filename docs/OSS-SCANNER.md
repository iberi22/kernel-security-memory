# OSS Scanner integration (MVP, KSM side)

KSM and Anthropic's [OSS Scanner](https://github.com/anthropics/oss-scanner)
complement each other:

- **KSM** is backward-looking: a memory of verified fixes (CVE history,
  pattern clusters, guardrail families with fix-commit citations). It says
  what already hurt projects like yours.
- **OSS Scanner** is forward-looking: model-driven scanning of enrolled
  repos. It says what might hurt you next.

KSM feeds the scanner a grounded threat model; scanner findings come back
as hypotheses, never as KSM facts.

## Generate a threat model

Write a small human CONTEXT.yaml (schema below — the parts KSM cannot know),
then run:

```bash
python3 scripts/oss_scanner/threat_model.py --repo PATH --name NAME \
  --context CONTEXT.yaml --out .oss-scanner/threat_model.md
# rerun check (output must match; the volatile KSM commit is ignored):
python3 scripts/oss_scanner/threat_model.py --repo PATH --name NAME \
  --context CONTEXT.yaml --out .oss-scanner/threat_model.md --check
```

CONTEXT.yaml schema:

```yaml
description: string            # required: what the project does
untrusted_inputs: [string]     # required: where untrusted input enters
trusted: [string]              # what is trusted / not attacker-controlled
components_most: [string]      # components that matter most
components_least: [string]     # components that matter least
exercise: [string]             # how to build / drive the project
leave_alone: [string]          # repo-relative paths excluded from the audit
severity_overrides: {CWE-ID: policy}  # human severity policy
```

The script adds deterministically: auditor hotspot files ranked by finding
count (rule IDs + CWE, no code excerpts; skips `target/`, `node_modules/`,
`vendor/`, `.git/`, `data/` and `leave_alone`), one KSM-evidence severity
line per guardrail family whose trigger languages occur in the repo (cluster
counts + 1–3 verified fix-commit URLs), and detected languages with file
counts. Output follows the scanner template headings plus a provenance
footer (KSM commit, `guardrails.json` sha256, auditor rule count).

## Enroll a project

```bash
python3 scripts/oss_scanner/enroll.py --name NAME \
  --repo-url https://... --contact somebody@example.org \
  --out DIR   # writes DIR/projects/<name>/project.yaml
```

Re-running enrollment for an existing name refuses to overwrite its
`project.yaml` (reporting settings such as `auto_ccs`/`pgp` are never
reset silently); pass `--force` to replace it explicitly.

The script validates twice and prints both results: KSM stdlib checks and
the real upstream `tools/validate.py` (`check_project`) from the pinned
read-only clone, given by `--oss-scanner-clone` or `$OSS_SCANNER_CLONE`; without it the
script refuses to report PASS. The contact email is always a parameter, never hardcoded.

## Data policy

- Threat models contain **no code excerpts**: file paths, finding counts,
  rule IDs, CWE IDs, line numbers only.
- Scanner findings are **model-generated hypotheses**. They enter KSM only
  as hypotheses (unverified), never as verified-fix memory. Promotion
  requires a confirmed fix commit, as with any other mining source.
- Never read secrets (`.env`, tokens, `data/*.db`) when drafting context;
  base it on README, docs, and source layout only.
