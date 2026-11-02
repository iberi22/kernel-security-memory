#!/usr/bin/env python3
"""Validate flat qrels review rows and report pre-adjudication agreement."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path


def cohens_kappa(left, right):
    """Unweighted nominal kappa; None for no pairs or constant agreement."""
    if len(left) != len(right):
        raise ValueError("reviewer label arrays must have equal length")
    n = len(left)
    if not n:
        return None
    a, b = Counter(left), Counter(right)
    expected_numerator = sum(a[label] * b[label] for label in a.keys() | b.keys())
    denominator = n * n - expected_numerator
    if not denominator:
        return None
    agreements = sum(x == y for x, y in zip(left, right))
    return (agreements * n - expected_numerator) / denominator


def check_review(data, reviewers=None):
    """Group rows by item id; never treat a missing review as a label."""
    errors, counts, groups = [], Counter(), defaultdict(dict)
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise ValueError("qrels must be an object with an items array")
    for index, item in enumerate(data["items"]):
        context = f"items[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{context}: must be an object")
            continue
        item_id = item.get("id")
        reviewer = item.get("reviewer")
        valid_id = isinstance(item_id, str) and bool(item_id.strip())
        valid_reviewer = isinstance(reviewer, str) and bool(reviewer.strip())
        if not valid_id:
            errors.append(f"{context}: missing or invalid id")
        else:
            groups[item_id]  # Retain items with no attributed reviews.
        if not valid_reviewer:
            errors.append(f"{context}: missing or invalid reviewer")
        else:
            counts[reviewer] += 1
        stamp = item.get("reviewed_at")
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timezone required")
        except (AttributeError, TypeError, ValueError):
            errors.append(f"{context}: reviewed_at must be an ISO-8601 timestamp with timezone")
        label = item.get("expect")
        if label not in ("FOUND", "ABSTAIN"):
            errors.append(f"{context}: expect must be FOUND or ABSTAIN")
        if valid_id and valid_reviewer:
            if reviewer in groups[item_id]:
                errors.append(f"{context}: duplicate review for {item_id} by {reviewer}")
            else:
                groups[item_id][reviewer] = label
    pair = list(reviewers) if reviewers is not None else sorted(counts) if len(counts) == 2 else []
    if pair and (len(pair) != 2 or pair[0] == pair[1]):
        raise ValueError("select two distinct reviewers")
    left, right = [], []
    if pair:
        for reviews in groups.values():
            if all(name in reviews and reviews[name] in ("FOUND", "ABSTAIN") for name in pair):
                left.append(reviews[pair[0]])
                right.append(reviews[pair[1]])
    kappa = cohens_kappa(left, right)
    return {
        "errors": errors,
        "reviewer_counts": dict(sorted(counts.items())),
        "item_count": len(groups),
        "single_reviewer_items": sorted(key for key, value in groups.items() if len(value) == 1),
        "unreviewed_items": sorted(key for key, value in groups.items() if not value),
        "reviewers": pair,
        "paired_items": len(left),
        "observed_agreement": sum(a == b for a, b in zip(left, right)) / len(left) if left else None,
        "kappa": kappa,
        "kappa_status": "AVAILABLE" if kappa is not None else (
            "UNDEFINED_CONSTANT_LABEL" if left else "UNAVAILABLE_NO_PAIRED_REVIEWS"
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qrels", type=Path)
    parser.add_argument("--reviewers", nargs=2, metavar=("REVIEWER_A", "REVIEWER_B"))
    args = parser.parse_args(argv)
    try:
        report = check_review(json.loads(args.qrels.read_text(encoding="utf-8")), args.reviewers)
    except (OSError, ValueError) as exc:
        print(json.dumps({"errors": [str(exc)]}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
