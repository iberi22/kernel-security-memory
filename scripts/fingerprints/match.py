#!/usr/bin/env python3
"""Match target ksm-sfp/1 documents against the ksm-fixfp/1 corpus."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ksm.match import load_corpus, match_documents, render_markdown, self_test


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Match sfp targets against fix fingerprints.")
    p.add_argument("--targets", nargs="+", default=[], help="ksm-sfp/1 JSON files")
    p.add_argument("--fingerprints", default="docs/studies/fingerprints")
    p.add_argument("--json", action="store_true", help="emit JSON findings")
    p.add_argument("--self-test", action="store_true", help="run corpus self-test")
    p.add_argument("--min-before", type=float, default=0.55)
    p.add_argument("--margin", type=float, default=0.05)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    corpus = load_corpus(args.fingerprints)
    if args.self_test:
        print(json.dumps(self_test(corpus), indent=1, sort_keys=True))
        return 0
    targets = []
    for fp in args.targets:
        targets.append(json.loads(Path(fp).read_text(encoding="utf-8")))
    findings = match_documents(targets, corpus, min_before=args.min_before,
                               margin=args.margin)
    if args.json:
        print(json.dumps(findings, indent=1, sort_keys=True))
    else:
        print(render_markdown(findings), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
