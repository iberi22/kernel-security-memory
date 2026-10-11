"""Feature extraction, TF-IDF and deterministic related CVE vectors."""

from collections import defaultdict
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ksm.cwe_groups import get_cwe_group, group_to_slug

FEATURE_WEIGHTS: Dict[str, float] = {
    "cwe": 3.0,
    "fam": 2.0,
    "proj": 1.0,
    "sub": 2.0,
    "path": 1.0,
    "fn": 3.0,
    "fixcall": 2.0,
    "kg": 1.0,
}

_COMMON_EXTENSIONS = {"c", "h", "cc", "cpp", "cxx", "py", "sh", "rs", "go", "java", "js", "ts"}


def extract_cve_features(
    cve_entry: Dict[str, Any],
    fragment: Optional[Dict[str, Any]] = None,
    fingerprint: Optional[Dict[str, Any]] = None,
) -> Set[str]:
    """Extract sparse features for a CVE per VULN-ATLAS.md Section 4."""
    features: Set[str] = set()

    # 1. CWE & 2. CWE Family
    cwe = cve_entry.get("cwe")
    if cwe and cwe != "UNKNOWN":
        features.add(f"cwe:{cwe}")
        group = get_cwe_group(cwe)
        if group != "Unknown":
            features.add(f"fam:{group_to_slug(group)}")

    # 3. Project
    project = cve_entry.get("project")
    if project:
        features.add(f"proj:{project.lower()}")

    # 4. Subsystem / top directory
    subsystem = cve_entry.get("subsystem")
    if subsystem:
        features.add(f"sub:{subsystem.lower()}")
    elif fragment:
        for f in fragment.get("files", []):
            path_str = f.get("path", "")
            if "/" in path_str:
                top_dir = path_str.split("/", 1)[0].lower()
                features.add(f"sub:{top_dir}")
                break

    # 5. File path tokens & 6. Function names (from fragments)
    if fragment:
        for f in fragment.get("files", []):
            path_str = f.get("path", "")
            for token in re.split(r"[/._-]+", path_str):
                token_lower = token.lower()
                if len(token_lower) >= 2 and token_lower not in _COMMON_EXTENSIONS:
                    features.add(f"path:{token_lower}")
            for fn in f.get("functions", []):
                fname = fn.get("name")
                if fname:
                    features.add(f"fn:{fname.lower()}")

    # 7. Callees added/removed & 8. Structural kgrams (from fingerprints)
    if fingerprint:
        functions = list(fingerprint.get("functions", []) or [])
        if not functions and "files" in fingerprint:
            for file_obj in fingerprint["files"]:
                functions.extend(file_obj.get("functions", []))

        for fn in functions:
            fname = fn.get("name")
            if fname:
                features.add(f"fn:{fname.lower()}")

            delta = fn.get("delta", fn)
            for call in delta.get("added_calls", []):
                features.add(f"fixcall:{call.lower()}")
            for call in delta.get("removed_calls", []):
                features.add(f"fixcall:{call.lower()}")

            added_kg = delta.get("added_kgrams", {})
            if isinstance(added_kg, dict):
                for kg in added_kg.keys():
                    features.add(f"kg:{kg.lower()}")
            elif isinstance(added_kg, list):
                for kg in added_kg:
                    features.add(f"kg:{kg.lower()}")

            removed_kg = delta.get("removed_kgrams", {})
            if isinstance(removed_kg, dict):
                for kg in removed_kg.keys():
                    features.add(f"kg:{kg.lower()}")
            elif isinstance(removed_kg, list):
                for kg in removed_kg:
                    features.add(f"kg:{kg.lower()}")

    return features


def compute_related_and_vectors(
    cve_dict: Dict[Tuple[str, str], Dict[str, Any]],
    fragments_map: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None,
    fingerprints_map: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None,
) -> Tuple[Dict[Tuple[str, str], List[Dict[str, Any]]], Dict[Tuple[str, str], Dict[str, float]]]:
    """Compute TF-IDF vectors and related CVE neighbours.

    Args:
        cve_dict: Map of (project, advisory_id) -> cve entry dict.
        fragments_map: Optional map of (project, advisory_id) -> fragment dict.
        fingerprints_map: Optional map of (project, advisory_id) -> fingerprint dict.

    Returns:
        related_map: Map of (project, advisory_id) -> list of top 10 neighbours.
        vectors_map: Map of (project, advisory_id) -> sparse feature vector dict.
    """
    if fragments_map is None:
        fragments_map = {}
    if fingerprints_map is None:
        fingerprints_map = {}

    N = len(cve_dict)
    if N == 0:
        return {}, {}

    # 1. Feature extraction & Document Frequency
    cve_features: Dict[Tuple[str, str], Set[str]] = {}
    df: Dict[str, int] = defaultdict(int)

    for key, entry in cve_dict.items():
        frag = fragments_map.get(key)
        fp = fingerprints_map.get(key)
        feats = extract_cve_features(entry, fragment=frag, fingerprint=fp)
        cve_features[key] = feats
        for f in feats:
            df[f] += 1

    # 2. Inverted index ignoring features with df > 5% of N (cutoff)
    cutoff = 0.05 * N if N >= 40 else float(N)
    inverted_index: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    idf: Dict[str, float] = {}

    for f, count in df.items():
        idf[f] = math.log(N / count)
        if count <= cutoff:
            inverted_index[f] = []

    # 3. TF-IDF vectors and L2 norms
    vectors: Dict[Tuple[str, str], Dict[str, float]] = {}
    norms: Dict[Tuple[str, str], float] = {}

    for key, feats in cve_features.items():
        vec: Dict[str, float] = {}
        norm_sq = 0.0
        for f in feats:
            prefix = f.split(":", 1)[0]
            base_w = FEATURE_WEIGHTS.get(prefix, 1.0)
            w = base_w * idf[f]
            if w > 0:
                vec[f] = round(w, 4)
                norm_sq += w * w
                if df[f] <= cutoff:
                    inverted_index[f].append(key)
        vectors[key] = vec
        norms[key] = math.sqrt(norm_sq)

    # 4. Neighbour calculation using inverted index candidates
    related: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for key, feats in cve_features.items():
        norm_a = norms[key]
        if norm_a == 0:
            related[key] = []
            continue

        vec_a = vectors[key]
        candidates: Set[Tuple[str, str]] = set()
        for f in feats:
            if df[f] <= cutoff:
                candidates.update(inverted_index[f])
        candidates.discard(key)

        scored: List[Tuple[float, Tuple[str, str]]] = []
        for other_key in candidates:
            norm_b = norms[other_key]
            if norm_b == 0:
                continue
            vec_b = vectors[other_key]
            # Dot product over all shared features between key and other_key
            shared_feats = set(vec_a.keys()) & set(vec_b.keys())
            dot = sum(vec_a[f] * vec_b[f] for f in shared_feats)
            if dot > 0:
                cos = dot / (norm_a * norm_b)
                score = round(cos, 4)
                scored.append((score, other_key))

        # Ties broken by id ascending (item[1][1] is advisory_id)
        scored.sort(key=lambda item: (-item[0], item[1][1]))
        top10 = scored[:10]

        top_neighbours: List[Dict[str, Any]] = []
        for score, other_key in top10:
            vec_b = vectors[other_key]
            shared_feats = set(vec_a.keys()) & set(vec_b.keys())
            # Top 3 shared feature names ranked by contribution to similarity, ties by name
            shared_ranked = sorted(
                shared_feats,
                key=lambda f: (-vec_a[f] * vec_b[f], f),
            )
            top_neighbours.append({
                "id": other_key[1],
                "project": other_key[0],
                "score": score,
                "shared": shared_ranked[:3],
            })

        related[key] = top_neighbours

    return related, vectors
