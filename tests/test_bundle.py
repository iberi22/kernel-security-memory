import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from export_bundle import export_bundle
from query_pack import query_database


class BundleTests(unittest.TestCase):
    def test_roundtrip_and_every_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pack"
            manifest = export_bundle(root, "a" * 40)
            self.assertEqual(manifest["coverage"], "SOURCE_LINKED_SEED_ONLY")
            self.assertEqual(manifest["indexes"]["vectors"], "NOT_BUILT")
            for file in manifest["files"]:
                body = (root / file["path"]).read_bytes()
                self.assertEqual(len(body), file["bytes"])
                self.assertEqual(hashlib.sha256(body).hexdigest(), file["sha256"])
            before = (root / "memory.sqlite3").read_bytes()
            self.assertTrue(query_database(root / "memory.sqlite3", "generation"))
            self.assertEqual((root / "memory.sqlite3").read_bytes(), before)
            self.assertEqual(json.loads((root / "distribution.json").read_text()), manifest)

    def test_refuses_existing_user_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "keep.txt"
            sentinel.write_text("user data")
            with self.assertRaises(ValueError):
                export_bundle(tmp, "a" * 40)
            self.assertEqual(sentinel.read_text(), "user data")

    def test_rejects_mutable_or_invalid_revision_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "absent"
            for revision in ("main", "a" * 7, "../danger"):
                with self.assertRaises(ValueError):
                    export_bundle(output, revision)
                self.assertFalse(output.exists())
