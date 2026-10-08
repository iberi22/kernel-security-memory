#!/usr/bin/env python3
"""Render a self-contained human-review HTML page for mined fix candidates.

Reads the seed evidence record plus a mined batch (see experiments/) and
writes docs/review.html with inline CSS/JS only (no CDN, no network).

Usage:
    python3 scripts/render_review.py [--seed PATH] [--batch PATH] [--output PATH]
"""
import argparse
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SEED = ROOT / "docs/memory/records/linux-CVE-2024-26581-mainline.json"
DEFAULT_BATCH = ROOT / "experiments/candidates-batch-001.json"
DEFAULT_OUTPUT = ROOT / "docs/review.html"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def short_sha(sha):
    return sha[:12] if isinstance(sha, str) and len(sha) >= 12 else str(sha)


def first_line(message):
    if not isinstance(message, str):
        return ""
    return message.split("\n", 1)[0].strip()


def render_row(commit):
    sha = str(commit.get("sha", ""))
    cve = commit.get("cve_id") or "UNBOUND"
    msg = first_line(commit.get("message", ""))
    files = commit.get("changed_files", []) or []
    signals = commit.get("candidate_signals", []) or []
    sole_parent = commit.get("sole_parent")
    source_url = commit.get("source_url", "")

    if signals:
        sig_items = "".join(
            "<li>{}: <code>{}</code> ({})</li>".format(
                html.escape(str(s.get("type", "?"))),
                html.escape(str(s.get("target", "?"))),
                html.escape(str(s.get("status", "?"))),
            )
            for s in signals
        )
        sig_html = "<ul>{}</ul>".format(sig_items)
    else:
        sig_html = "<span class=muted>none</span>"

    if files:
        file_items = "".join(
            "<li><code>{}</code></li>".format(html.escape(str(f))) for f in files[:20]
        )
        more = "" if len(files) <= 20 else "<li>... +{} more</li>".format(len(files) - 20)
        files_html = "<ul>{}{}</ul>".format(file_items, more)
    else:
        files_html = "<span class=muted>none listed</span>"

    parent_txt = "sole" if sole_parent is True else ("merge/missing" if sole_parent is False else "unknown")
    row_id = "cand-{}".format(html.escape(short_sha(sha) if sha else "unknown"))
    approve_id = "approve-{}".format(html.escape(sha))
    reject_id = "reject-{}".format(html.escape(sha))

    return (
        "<tr id=\"{row_id}\">"
        "<td>{cve}</td>"
        "<td><a href=\"{url}\"><code>{short}</code></a></td>"
        "<td>{msg}</td>"
        "<td>{files}</td>"
        "<td>{sigs}</td>"
        "<td>{parent}</td>"
        "<td>"
        "<label><input type=\"checkbox\" id=\"{aid}\" class=\"dec-approve\" data-sha=\"{sha}\"> approve</label><br>"
        "<label><input type=\"checkbox\" id=\"{rid}\" class=\"dec-reject\" data-sha=\"{sha}\"> reject</label>"
        "</td>"
        "</tr>"
    ).format(
        row_id=row_id,
        cve=html.escape(str(cve)),
        url=html.escape(str(source_url), quote=True),
        short=html.escape(short_sha(sha)),
        msg=html.escape(msg),
        files=files_html,
        sigs=sig_html,
        parent=html.escape(parent_txt),
        aid=approve_id,
        rid=reject_id,
        sha=html.escape(sha, quote=True),
    )


def build_html(seed, batch):
    seed_id = seed.get("id", "unknown-seed") if isinstance(seed, dict) else "unknown-seed"
    seed_title = seed.get("title", "") if isinstance(seed, dict) else ""
    seed_status = seed.get("status", "") if isinstance(seed, dict) else ""
    coverage = batch.get("coverage", "UNKNOWN") if isinstance(batch, dict) else "UNKNOWN"
    errors = batch.get("errors", []) if isinstance(batch, dict) else []
    commits = batch.get("commits", []) if isinstance(batch, dict) else []

    rows = "\n".join(render_row(c) for c in commits) if commits else (
        "<tr><td colspan=\"7\" class=\"muted\">No candidates in batch (offline or empty run).</td></tr>"
    )
    err_items = "".join("<li>{}</li>".format(html.escape(str(e))) for e in errors)
    err_html = "<ul>{}</ul>".format(err_items) if err_items else "<span class=muted>none</span>"

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Kernel Security Memory &mdash; candidate review</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2em auto;padding:0 1em;color:#111}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #999;padding:.4em .6em;vertical-align:top;text-align:left}}
th{{background:#eee}}
code{{font-size:.85em}}
.muted{{color:#666}}
#decisions{{width:100%;height:10em;font-family:monospace}}
button{{padding:.5em 1em;font-size:1em}}
</style>
</head>
<body>
<h1>Candidate fix review</h1>
<p>Seed record: <code>{seed_id}</code> &mdash; {seed_title} (status: {seed_status}).</p>
<p>Batch coverage: <strong id="batch-coverage">{coverage}</strong> &middot; candidates: <span id="cand-count">{n}</span></p>
<h2>Fetch/mining errors</h2>
{errs}
<table>
<thead><tr><th>CVE</th><th>Commit</th><th>Message</th><th>Files</th><th>Fixes signals</th><th>Parents</th><th>Decision</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<p><button id="export-btn" type="button">Export decisions to JSON</button></p>
<textarea id="decisions" readonly placeholder="Decisions JSON will appear here for copy-paste."></textarea>
<script>
(function(){{
function onlyOne(box){{
  var sha=box.getAttribute("data-sha");
  var cls=box.classList.contains("dec-approve")?"dec-reject":"dec-approve";
  var others=document.querySelectorAll("input."+cls+'[data-sha="'+sha+'"]');
  for(var i=0;i<others.length;i++){{others[i].checked=false;}}
}}
var boxes=document.querySelectorAll("input.dec-approve,input.dec-reject");
for(var i=0;i<boxes.length;i++){{boxes[i].addEventListener("change",function(){{onlyOne(this);}});}}
document.getElementById("export-btn").addEventListener("click",function(){{
  var out=[];
  var rows=document.querySelectorAll("tbody tr[id^='cand-']");
  for(var i=0;i<rows.length;i++){{
    var tds=rows[i].getElementsByTagName("td");
    var shaCell=rows[i].querySelector("input.dec-approve");
    var sha=shaCell?shaCell.getAttribute("data-sha"):"";
    var ap=rows[i].querySelector("input.dec-approve").checked;
    var rj=rows[i].querySelector("input.dec-reject").checked;
    out.push({{sha:sha,cve:tds[0].textContent,decision:ap?"approve":(rj?"reject":"pending")}});
  }}
  document.getElementById("decisions").value=JSON.stringify({{decisions:out}},null,2);
}});
}})();
</script>
</body>
</html>""".format(
        seed_id=html.escape(str(seed_id)),
        seed_title=html.escape(str(seed_title)),
        seed_status=html.escape(str(seed_status)),
        coverage=html.escape(str(coverage)),
        n=len(commits),
        errs=err_html,
        rows=rows,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", default=str(DEFAULT_SEED))
    parser.add_argument("--batch", default=str(DEFAULT_BATCH))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    seed = load_json(args.seed)
    batch = load_json(args.batch)
    page = build_html(seed, batch)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")
    print("Wrote {} ({} candidates)".format(out, len(batch.get("commits", []))))


if __name__ == "__main__":
    main()
