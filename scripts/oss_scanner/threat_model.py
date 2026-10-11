#!/usr/bin/env python3
"""Generate an OSS-Scanner threat_model.md from a human CONTEXT.yaml plus KSM evidence.

CONTEXT.yaml schema (all keys optional unless noted):
  description: string            free-text project description (required)
  untrusted_inputs: [string]     where untrusted input enters (required)
  trusted: [string]              what is trusted / out of scope for input
  components_most: [string]      components that matter most
  components_least: [string]     components that matter least / lower priority
  exercise: [string]             how to build / exercise the project
  leave_alone: [string]          repo-relative paths excluded from the audit
  severity_overrides: {str: str} human severity policy, e.g. {"CWE-78": "critical"}

KSM-added evidence (deterministic, no code excerpts):
  (a) defensive_auditor hotspots over the repo, minus exclusions
  (b) one KSM-evidence severity line per guardrail family whose trigger
      languages occur in the repo (cluster counts + verified fix citations)
  (c) detected languages with file counts

Output follows the oss-scanner template headings exactly, plus a provenance
footer. Byte-identical on rerun. Stdlib only (PyYAML used if importable).
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from defensive_auditor import SECURITY_RULES, scan_content  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARDRAILS_PATH = (
    REPO_ROOT / "docs" / "skills" / "defensive-security-auditor"
    / "references" / "guardrails.json"
)

EXCLUDED_DIRS = {"target", "node_modules", "vendor", ".git", "data"}

EXT_LANG = {
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c",
    ".rs": "rust", ".py": "python", ".sh": "shell", ".bash": "shell",
}
SCAN_EXTS = set(EXT_LANG)

CONTEXT_KEYS = {
    "description", "untrusted_inputs", "trusted", "components_most",
    "components_least", "exercise", "leave_alone", "severity_overrides",
}


def _parse_scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _parse_inline_list(text):
    """Parse a bracketed inline list ([a, b]) into strings."""
    inner = text.strip()[1:-1].strip()
    if not inner:
        return []
    return [_parse_scalar(item) for item in inner.split(",")]


def _mini_yaml(path):
    """Parse the restricted CONTEXT.yaml subset: top-level scalar keys,
    dash-list keys, and one inline {k: v} map (severity_overrides)."""
    data = {}
    current = None
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if raw[0] not in (" ", "\t") and ":" in raw:
            key, _, rest = raw.partition(":")
            key, rest = key.strip(), rest.strip()
            if key not in CONTEXT_KEYS:
                raise ValueError(f"unknown context key {key!r}")
            if rest.startswith("{"):
                inner = rest.strip()[1:-1].strip()
                mapping = {}
                if inner:
                    for pair in inner.split(","):
                        k, _, v = pair.partition(":")
                        mapping[_parse_scalar(k)] = _parse_scalar(v)
                data[key] = mapping
                current = None
            elif rest.startswith("[") and rest.endswith("]"):
                data[key] = _parse_inline_list(rest)
                current = None
            elif rest:
                data[key] = _parse_scalar(rest)
                current = None
            else:
                data[key] = []
                current = key
        elif raw.strip().startswith("- ") and isinstance(current, str):
            data[current].append(_parse_scalar(raw.strip()[2:]))
        else:
            raise ValueError(f"cannot parse line: {raw!r}")
    return data


def load_context(path):
    try:
        import yaml  # type: ignore
    except ImportError:
        data = _mini_yaml(path)
    else:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise ValueError("context file must be a mapping")
        for key in data:
            if key not in CONTEXT_KEYS:
                raise ValueError(f"unknown context key {key!r}")
    for key in ("description",):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ValueError(f"context key {key!r} must be a non-empty string")
    for key in ("untrusted_inputs", "trusted", "components_most",
                "components_least", "exercise", "leave_alone"):
        if key == "untrusted_inputs" and key not in data:
            continue  # required: rejected below, never silently defaulted
        data.setdefault(key, [])
        items = data[key]
        if not isinstance(items, list):
            raise ValueError(f"context key {key!r} must be a list of strings")
        normalized = []
        for item in items:
            # A dash item containing ": " parses as a one-pair mapping;
            # rejoin it so human prose with colons keeps working.
            if isinstance(item, dict) and len(item) == 1:
                ((k, v),) = item.items()
                item = f"{k}: {v}"
            if not isinstance(item, str):
                raise ValueError(
                    f"context key {key!r} must be a list of strings")
            normalized.append(item)
        data[key] = normalized
    data.setdefault("severity_overrides", {})
    if not isinstance(data["severity_overrides"], dict):
        raise ValueError("context key 'severity_overrides' must be a mapping")
    untrusted = data.get("untrusted_inputs")
    if (not isinstance(untrusted, list) or not untrusted
            or not all(isinstance(x, str) and x.strip() for x in untrusted)):
        raise ValueError(
            "context key 'untrusted_inputs' must be a non-empty list of strings")
    return data


def _excluded(rel_parts, leave_alone):
    if any(p in EXCLUDED_DIRS or p.startswith(".") for p in rel_parts[:-1]):
        return True
    rel = "/".join(rel_parts)
    for prefix in leave_alone:
        prefix = prefix.strip().strip("/")
        if prefix and (rel == prefix or rel.startswith(prefix + "/")):
            return True
    return False


def audit_repo(repo, leave_alone):
    """Walk repo, scan in-scope source files. Return (lang_counts, hotspots).

    hotspots: [(rel_path, count, [(rule_id, cwe, lines)])] ranked by
    count desc, path asc. No code excerpts leave this function."""
    repo = Path(repo)
    lang_counts = {}
    per_file = {}
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            rel_parts = path.relative_to(repo).parts
        except ValueError:
            continue
        if path.suffix.lower() not in SCAN_EXTS:
            continue
        if _excluded(rel_parts, leave_alone):
            continue
        rel = "/".join(rel_parts)
        lang_counts[EXT_LANG[path.suffix.lower()]] = \
            lang_counts.get(EXT_LANG[path.suffix.lower()], 0) + 1
        content = path.read_text(encoding="utf-8", errors="replace")
        for finding in scan_content(content, filename=rel):
            bucket = per_file.setdefault(rel, {})
            rule_bucket = bucket.setdefault(
                (finding["rule_id"], finding["cwe_id"]), [])
            rule_bucket.append(finding["line"])
    hotspots = [
        (rel, sum(len(v) for v in rules.values()),
         sorted((r, c, sorted(ls)) for (r, c), ls in rules.items()))
        for rel, rules in per_file.items()
    ]
    hotspots.sort(key=lambda h: (-h[1], h[0]))
    return lang_counts, hotspots


def load_guardrails():
    raw = GUARDRAILS_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw.decode("utf-8"))
    return data["families"], digest


def ksm_commit():
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return out.stdout.strip() if out.returncode == 0 else "unknown"


def bullets(items, empty="-"):
    if not items:
        return empty
    return "\n".join(f"- {x}" for x in items)


def render(name, ctx, lang_counts, hotspots, families, digest, commit):
    repo_langs = set(lang_counts)
    lines = ["<!-- Generated by KSM scripts/oss_scanner/threat_model.py;",
             "     human CONTEXT.yaml plus deterministic KSM evidence. -->",
             "# Threat model", "",
             "## What this project does and where untrusted input enters",
             f"- {name}: {ctx['description']}",
             "- Untrusted input enters via:"]
    lines += [f"  - {x}" for x in ctx["untrusted_inputs"]] or ["  - (not specified)"]
    if ctx["trusted"]:
        lines.append("- Trusted (not treated as untrusted input):")
        lines += [f"  - {x}" for x in ctx["trusted"]]
    lines += ["", "## Components that matter most / least",
              "- Components that matter most:"]
    lines += [f"  - {x}" for x in ctx["components_most"]] or ["  - (not specified)"]
    lines.append("- Components that matter least / lower priority:")
    lines += [f"  - {x}" for x in ctx["components_least"]] or ["  - (not specified)"]
    total = sum(count for _, count, _ in hotspots)
    lines.append(f"- Auditor hotspots (KSM evidence, {total} finding(s) "
                 f"in {len(hotspots)} file(s); no code excerpts):")
    if hotspots:
        for rel, count, rules in hotspots:
            detail = "; ".join(
                f"{r} ({c}) x{len(ls)} at line(s) {', '.join(map(str, ls))}"
                for r, c, ls in rules)
            lines.append(f"  - `{rel}` — {count} finding(s): {detail}")
    else:
        lines.append("  - No auditor findings in scope.")
    lines += ["", "## How to exercise it"]
    lines.append(bullets(ctx["exercise"], "- (not specified)"))
    lines += ["", "## How you rate severity"]
    for cwe in sorted(ctx["severity_overrides"]):
        lines.append(f"- {cwe}: {ctx['severity_overrides'][cwe]} (human policy)")
    lines.append("- KSM evidence (backward-looking verified-fix memory, not policy):")
    shown = 0
    for fam in sorted(families, key=lambda f: f["cwe_id"]):
        trigger = {lang for rule in fam["rules"] for lang in rule["languages"]}
        if not (trigger & repo_langs):
            continue
        shown += 1
        cites = fam.get("citations", [])[:3]
        cite_txt = ", ".join(
            f"{c.get('advisory_id', '?')} ({c['fix_commit_url']})" for c in cites)
        rules_txt = ", ".join(sorted(r["rule_id"] for r in fam["rules"]))
        lines.append(
            f"  - {fam['cwe_id']} ({fam.get('cluster_title', '')}): "
            f"{fam.get('cluster_count', '?')} clustered CVEs, "
            f"{fam.get('cluster_with_fix_sha', '?')} with verified fix commits"
            + (f", e.g. {cite_txt}" if cite_txt else "")
            + f"; auditor rules: {rules_txt}. "
            "Treat findings here as high-severity candidates; "
            "confirm exploitability before rating critical.")
    if not shown:
        lines.append("  - No guardrail family matches the detected languages.")
    if lang_counts:
        lang_txt = ", ".join(
            f"{lang} ({n} file(s))"
            for lang, n in sorted(lang_counts.items(), key=lambda kv: (-kv[1], kv[0])))
    else:
        lang_txt = "none"
    lines.append(f"- Languages detected: {lang_txt}.")
    lines += ["", "## Anything to leave alone"]
    lines.append(bullets(ctx["leave_alone"], "- Nothing listed."))
    lines += ["",
              "---",
              f"*Provenance: KSM commit {commit}; guardrails.json sha256:{digest} "
              f"({len(families)} families); defensive_auditor rules: "
              f"{len(SECURITY_RULES)}. Deterministic: reruns on the same tree "
              "and context produce byte-identical output. Contains no code excerpts.*",
              ""]
    return "\n".join(lines)


def _without_volatile_commit(text):
    """Blank the KSM commit in the provenance footer for drift comparison.

    Committing a generated model advances HEAD, so a byte comparison that
    includes the commit would fail on the next --check without any evidence
    change. All other content is still compared exactly.
    """
    return re.sub(r"KSM commit \S+;", "KSM commit <commit>;", text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--out", default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    try:
        ctx = load_context(args.context)
    except (OSError, ValueError) as exc:
        print(f"error: invalid context {args.context}: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - PyYAML parse errors
        print(f"error: cannot parse context {args.context}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if not Path(args.repo).is_dir():
        print(f"error: --repo {args.repo} is not a directory", file=sys.stderr)
        return 2
    lang_counts, hotspots = audit_repo(args.repo, ctx["leave_alone"])
    families, digest = load_guardrails()
    text = render(args.name, ctx, lang_counts, hotspots, families,
                  digest, ksm_commit())

    if args.check:
        if not args.out:
            print("--check requires --out", file=sys.stderr)
            return 2
        try:
            current = Path(args.out).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"--check: cannot read {args.out}: {exc}", file=sys.stderr)
            return 1
        if _without_volatile_commit(current) != _without_volatile_commit(text):
            print(f"--check: {args.out} differs from generated output",
                  file=sys.stderr)
            return 1
        print(f"--check: {args.out} matches generated output")
        return 0

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"threat model written to {args.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
