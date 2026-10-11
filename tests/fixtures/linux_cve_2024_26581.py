"""Fixture for linux-CVE-2024-26581 (netfilter interval GC fix)."""
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
BEFORE_C_PATH = FIXTURE_DIR / "linux_cve_2024_26581_before.c"
AFTER_C_PATH = FIXTURE_DIR / "linux_cve_2024_26581_after.c"

METADATA = {
    "repo": "torvalds/linux",
    "cve": "CVE-2024-26581",
    "symbol_name": "nft_rbtree_gc_elem",
    "language": "c",
    "file": "net/netfilter/nft_set_rbtree.c",
    "commit_before": "f82777e8ce6c039cdcacbcf1eb8619b99a20c06d",
    "commit_after": "60c0c230c6f046da536d3df8b39a20b9a9fd6af0",
    "blob_before": "5fd74f993988f0c8478cd7258355c4eea90cc2e4",
    "blob_after": "9944fe479e5361dc140f75be8b90bf3c5deb40f6",
    "ast_indexed": True,
}

BEFORE_C = BEFORE_C_PATH.read_text(encoding="utf-8")
AFTER_C = AFTER_C_PATH.read_text(encoding="utf-8")
