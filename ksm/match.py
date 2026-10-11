"""Structural matcher (ksm scan): compare target ksm-sfp/1 functions
against the ksm-fixfp/1 corpus. Deterministic, stdlib only."""
import json
import math
from pathlib import Path

MIN_BEFORE_DEFAULT = 0.55
MARGIN_DEFAULT = 0.05
LSH_BANDS_DEFAULT = 16
LSH_ROWS_DEFAULT = 4
LSH_JACCARD_MIN = 0.3
# Tiny functions (getters, wrappers) look alike structurally; they never
# produce a structural hit on their own.
MIN_NODES_DEFAULT = 40
# Missing-guard rules: the fix's new guard must sit at most this many lines
# before the protected call, and variables passed to at least HANDLE_CALLEES
# distinct callees are treated as context handles and never form a rule.
GUARD_WINDOW = 8
HANDLE_CALLEES = 3


def load_corpus(fingerprints_dir):
    """Load all ksm-fixfp/1 docs under a directory, sorted deterministically."""
    root = Path(fingerprints_dir)
    docs = []
    if not root.exists():
        return docs
    for fp in sorted(root.rglob("*.json")):
        if fp.name == "index.json":
            continue
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
        except Exception:
            continue
        if d.get("schema") != "ksm-fixfp/1":
            continue
        docs.append(d)
    docs.sort(key=lambda d: (str(d.get("project", "")), str(d.get("advisory_id", "")),
                             str(d.get("fix_sha", ""))))
    return docs


def cosine(a, b):
    a = a or {}
    b = b or {}
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    dot = sum(int(a.get(k, 0)) * int(b.get(k, 0)) for k in set(a) | set(b))
    na = math.sqrt(sum(int(v) * int(v) for v in a.values()))
    nb = math.sqrt(sum(int(v) * int(v) for v in b.values()))
    if na == 0 or nb == 0:
        return 1.0 if na == 0 and nb == 0 else 0.0
    return dot / (na * nb)


def est_jaccard(m1, m2):
    if not m1 or not m2 or len(m1) != len(m2) or not len(m1):
        return 0.0
    return sum(1 for x, y in zip(m1, m2) if x == y) / len(m1)


def shares_band(m1, m2, bands=16, rows=4):
    if not m1 or not m2 or len(m1) != bands * rows or len(m2) != bands * rows:
        return False
    for b in range(bands):
        seg1 = m1[b * rows:(b + 1) * rows]
        seg2 = m2[b * rows:(b + 1) * rows]
        if seg1 == seg2:
            return True
    return False


def is_candidate(t_fn, b_fn, lsh_bands=16, lsh_rows=4):
    """MinHash LSH pre-filter: needs a shared band and est Jaccard >= 0.3.

    Functions without usable minhash skip the filter (cosine decides).
    """
    tm, bm = (t_fn or {}).get("minhash"), (b_fn or {}).get("minhash")
    if not tm or not bm or len(tm) != lsh_bands * lsh_rows or len(bm) != lsh_bands * lsh_rows:
        return True
    if not shares_band(tm, bm, lsh_bands, lsh_rows):
        return False
    return est_jaccard(tm, bm) >= LSH_JACCARD_MIN


def _guard_near(guards, var, call_line, callee):
    """A precondition guard on `var` at most GUARD_WINDOW lines before the call.

    A guard that names the callee itself checks the call's result
    (`if (f(x) == NULL)`), not a precondition, and does not count.
    """
    return any(var in (g.get("vars", []) or []) and callee not in (g.get("vars", []) or [])
               and 0 < call_line - int(g.get("line", 0)) <= GUARD_WINDOW
               for g in guards or [])


def _guard_has_var(guards, var, before_line=None):
    for g in guards or []:
        if var in (g.get("vars", []) or []):
            if before_line is None or int(g.get("line", 0)) < before_line:
                return True
    return False


def guard_rules(before, after, delta):
    """Guarded call positions the fix introduced: {(callee, arg_index)}.

    A rule holds when, in the fixed version, a call's argument variable is
    checked by a guard the fix added (delta.added_guards) on an earlier line,
    and in the vulnerable version the same callee's argument at that position
    has no guard before the call. Derived from both versions, so the fixed
    function never violates its own rule and the vulnerable one always does.
    """
    if not before or not after:
        return set()
    added = {(g.get("kind", ""), tuple(g.get("vars", []) or []))
             for g in (delta or {}).get("added_guards", []) or []}
    if not added:
        return set()
    new_guards = [g for g in after.get("guards", []) or []
                  if (g.get("kind", ""), tuple(g.get("vars", []) or [])) in added]
    # Context handles (curl's `data`, a `ctx`) are passed to many callees and
    # appear in unrelated guards; they say nothing about this call.
    callees_by_var = {}
    for c in after.get("calls", []) or []:
        for v in c.get("args", []) or []:
            if v:
                callees_by_var.setdefault(v, set()).add(c.get("callee", ""))
    rules = set()
    for c in after.get("calls", []) or []:
        line = int(c.get("line", 0))
        for i, v in enumerate(c.get("args", []) or []):
            if (v and len(callees_by_var.get(v, ())) < HANDLE_CALLEES
                    and _guard_near(new_guards, v, line, c.get("callee", ""))):
                rules.add((c.get("callee", ""), i))
    out = set()
    for callee, i in rules:
        for bc in before.get("calls", []) or []:
            args = bc.get("args", []) or []
            if (bc.get("callee", "") == callee and i < len(args) and args[i]
                    and not _guard_has_var(before.get("guards", []), args[i],
                                           int(bc.get("line", 0)))):
                out.add((callee, i))
                break
    return out


def find_missing_guards(t_fn, rules):
    """Calls in T matching a rule whose argument variable has no earlier guard."""
    out = []
    seen = set()
    if not rules:
        return out
    for tc in (t_fn or {}).get("calls", []) or []:
        callee = tc.get("callee", "")
        args = tc.get("args", []) or []
        line = int(tc.get("line", 0))
        for c, i in sorted(rules):
            if c != callee or i >= len(args) or not args[i]:
                continue
            var = args[i]
            if _guard_has_var((t_fn or {}).get("guards", []), var, line + 1):
                continue
            key = (line, var, callee)
            if key not in seen:
                seen.add(key)
                out.append({"line": line, "variable": var, "callee": callee})
    out.sort(key=lambda e: (e["line"], e["variable"], e["callee"]))
    return out


def commit_url(project, repo, fix_sha):
    if project in ("linux", "linux-cna"):
        return f"https://git.kernel.org/linus/{fix_sha}"
    return f"https://github.com/{repo}/commit/{fix_sha}"


def _pair_score(s_b, s_a, n_missing):
    score = s_b - max(0.0, s_a - s_b) + 0.1 * n_missing
    return min(1.0, max(0.0, score))


def match_documents(target_docs, corpus, *, min_before=MIN_BEFORE_DEFAULT,
                    margin=MARGIN_DEFAULT, lsh_bands=LSH_BANDS_DEFAULT,
                    lsh_rows=LSH_ROWS_DEFAULT, min_nodes=MIN_NODES_DEFAULT):
    """Match target sfp docs against the corpus. Findings sorted by score desc."""
    pairs = []
    for doc in corpus:
        for f in doc.get("files", []) or []:
            for fn in f.get("functions", []) or []:
                before, after = fn.get("before"), fn.get("after")
                if before is None:
                    continue
                pairs.append((doc, f, fn, before, after))
    pairs.sort(key=lambda p: (str(p[0].get("project", "")), str(p[0].get("advisory_id", "")),
                              str(p[1].get("path", "")), str(p[2].get("name", ""))))

    # LSH index over the corpus "before" minhashes: a target function is only
    # compared with pairs sharing at least one band (pairs without a usable
    # minhash are always compared). Avoids target x corpus cosine products.
    width = lsh_bands * lsh_rows
    buckets = {}
    unindexed = []
    for i, (_, _, _, before, _) in enumerate(pairs):
        mh = before.get("minhash")
        if not mh or len(mh) != width:
            unindexed.append(i)
            continue
        for b in range(lsh_bands):
            buckets.setdefault((b, tuple(mh[b * lsh_rows:(b + 1) * lsh_rows])), []).append(i)

    rules = [guard_rules(p[3], p[4], p[2].get("delta", {})) for p in pairs]

    def candidates(tfn):
        mh = tfn.get("minhash")
        if not mh or len(mh) != width:
            return range(len(pairs))
        idx = set(unindexed)
        for b in range(lsh_bands):
            idx.update(buckets.get((b, tuple(mh[b * lsh_rows:(b + 1) * lsh_rows])), ()))
        return sorted(idx)

    findings = []
    for tdoc in target_docs or []:
        tfile = tdoc.get("file", "")
        for tfn in tdoc.get("functions", []) or []:
            tname = tfn.get("name", "")
            t_kg = tfn.get("kgrams", {}) or {}
            matches = []
            for i in candidates(tfn):
                doc, f, fn, before, after = pairs[i]
                if not is_candidate(tfn, before, lsh_bands, lsh_rows):
                    continue
                s_b = cosine(t_kg, before.get("kgrams", {}) or {})
                s_a = cosine(t_kg, (after or {}).get("kgrams", {}) or {}) if after else 0.0
                structural = (s_b >= min_before and s_b >= s_a + margin
                              and int(tfn.get("node_count", min_nodes)) >= min_nodes
                              and int(before.get("node_count", min_nodes)) >= min_nodes)
                missing = find_missing_guards(tfn, rules[i])
                if not structural and not missing:
                    continue
                score = _pair_score(s_b, s_a, len(missing))
                matches.append({
                    "advisory_id": doc.get("advisory_id", ""),
                    "project": doc.get("project", ""),
                    "path": f.get("path", ""),
                    "function": fn.get("name", ""),
                    "cwe": doc.get("cwe"),
                    "fix_sha": doc.get("fix_sha", ""),
                    "repo": doc.get("repo", ""),
                    "commit_url": commit_url(doc.get("project", ""), doc.get("repo", ""),
                                             doc.get("fix_sha", "")),
                    "s_before": round(s_b, 4),
                    "s_after": round(s_a, 4),
                    "missing_guards": missing,
                    "_score": score,
                })
            if not matches:
                continue
            matches.sort(key=lambda m: (-m["s_before"], str(m["advisory_id"])))
            score = round(min(1.0, max(m.pop("_score") for m in matches)), 4)
            lines = []
            seen_lines = set()
            reasons = []
            for m in matches:
                if m["s_before"] >= min_before and m["s_before"] >= m["s_after"] + margin:
                    reasons.append(
                        f"looks like {m['advisory_id']} vulnerable "
                        f"{tname} (s_before={m['s_before']:.2f} vs s_after={m['s_after']:.2f})")
                for g in m["missing_guards"]:
                    key = (g["line"], g["variable"], g["callee"])
                    if key not in seen_lines:
                        seen_lines.add(key)
                        lines.append({
                            "line": g["line"],
                            "reason": f"missing guard on `{g['variable']}` before `{g['callee']}`",
                            "variable": g["variable"],
                            "callee": g["callee"],
                        })
                    reasons.append(
                        f"fix added a check on `{g['variable']}` before `{g['callee']}`; "
                        f"this function calls `{g['callee']}` at line {g['line']} "
                        f"with no check on `{g['variable']}`")
            lines.sort(key=lambda e: (e["line"], str(e.get("variable", "")), str(e.get("callee", ""))))
            reasons = sorted(set(reasons))
            findings.append({
                "file": tfile,
                "function": tname,
                "start_line": int(tfn.get("start_line", 0)),
                "end_line": int(tfn.get("end_line", 0)),
                "score": round(score, 4),
                "lines": lines,
                "matches": matches,
                "reasons": reasons,
            })
    findings.sort(key=lambda f: (-f["score"], str(f["file"]), str(f["function"]),
                                 int(f["start_line"])))
    return findings


# Score at or above which a finding is reported as strong. Measured on curl
# 7.50.0 against 60 curl fix fingerprints: 11 of 12 findings >= 0.9 matched a
# fix released after that version; 5 of 14 below 0.7 did.
STRONG_SCORE = 0.9


def render_markdown(findings):
    if not findings:
        return "# KSM scan findings\n\nNo findings.\n"
    strong = sum(1 for f in findings if f["score"] >= STRONG_SCORE)
    parts = ["# KSM scan findings", "",
             f"{len(findings)} functions to review: {strong} strong (score >= {STRONG_SCORE}), "
             f"{len(findings) - strong} weak. Findings are hypotheses, not verdicts.", ""]
    for f in findings:
        label = "strong" if f["score"] >= STRONG_SCORE else "weak"
        parts.append(f"## `{f['file']}` — `{f['function']}` "
                     f"(lines {f['start_line']}–{f['end_line']}) — score {f['score']:.2f} ({label})")
        parts.append("")
        for r in f.get("reasons", []):
            parts.append(f"- {r}")
        if f.get("lines"):
            parts.append("")
            parts.append("Lines to review:")
            for ln in f["lines"]:
                parts.append(f"- line {ln['line']}: {ln['reason']}")
        if f.get("matches"):
            parts.append("")
            for m in f["matches"]:
                cwe = m.get("cwe") or "UNKNOWN"
                parts.append(f"- {m['advisory_id']} ({m['project']}, {cwe}) "
                             f"s_before={m['s_before']:.2f} s_after={m['s_after']:.2f} "
                             f"[fix]({m['commit_url']})")
        parts.append("")
    return "\n".join(parts).rstrip("\n") + "\n"


def self_test(corpus):
    """Corpus round-trip: after functions should not flag, before should hit.

    Returns {"after_flagged_rate", "before_recall", "pairs"} where rates are
    measured against the function's own advisory id.
    """
    items = []
    for doc in corpus:
        for f in doc.get("files", []) or []:
            for fn in f.get("functions", []) or []:
                if fn.get("before") is not None and fn.get("after") is not None:
                    items.append((doc, f, fn))
    pairs = len(items)
    if not pairs:
        return {"after_flagged_rate": 0.0, "before_recall": 0.0, "pairs": 0}
    flagged_after = 0
    found_before = 0
    for doc, f, fn in items:
        adv = doc.get("advisory_id", "")
        lang = f.get("language", "c")
        for side, key in (("before", "before"), ("after", "after")):
            fn_obj = fn.get(side)
            tdoc = {"schema": "ksm-sfp/1", "file": f"selftest/{adv}/{fn.get('name', 'fn')}.c",
                    "language": lang, "coverage": "OK", "functions": [dict(fn_obj)]}
            got = match_documents([tdoc], corpus)
            hit_own = any(m.get("advisory_id") == adv and m.get("path") == f.get("path")
                          and m.get("function") == fn.get("name")
                          for g in got for m in g.get("matches", []))
            if key == "before" and hit_own:
                found_before += 1
            if key == "after" and hit_own:
                flagged_after += 1
    return {"after_flagged_rate": round(flagged_after / pairs, 4),
            "before_recall": round(found_before / pairs, 4),
            "pairs": pairs}
