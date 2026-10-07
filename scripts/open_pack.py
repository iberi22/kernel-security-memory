#!/usr/bin/env python3
"""Hash verified portable memory reader."""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from build_pack import build_sql, validate
from query_pack import query_database

ROOT = Path(__file__).resolve().parents[1]

ALLOWED_HOSTS = {'raw.githubusercontent.com', 'iberi22.github.io'}
MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
TIMEOUT = 10


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirects not allowed", headers, fp)


def create_opener():
    opener = urllib.request.build_opener(NoRedirectHandler)
    return opener


def download_bounded(opener, url, expected_size=None, expected_sha256=None):
    try:
        with opener.open(url, timeout=TIMEOUT) as response:
            data = bytearray()
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_DOWNLOAD_SIZE:
                    raise ValueError(f"Download exceeded {MAX_DOWNLOAD_SIZE} bytes")
                if expected_size is not None and len(data) > expected_size:
                    raise ValueError(f"Download exceeded expected size {expected_size}")

            if expected_size is not None and len(data) != expected_size:
                raise ValueError(f"Size mismatch: expected {expected_size}, got {len(data)}")

            if expected_sha256 is not None:
                sha256 = hashlib.sha256(data).hexdigest()
                if sha256 != expected_sha256:
                    raise ValueError(f"Hash mismatch: expected {expected_sha256}, got {sha256}")

            return bytes(data)
    except urllib.error.URLError as e:
        raise ValueError(f"Network error fetching {url}: {e}")


def is_safe_path(base, path):
    try:
        base_path = Path(base).resolve()
        target_path = (Path(base) / path).resolve()
        return target_path.is_relative_to(base_path)
    except Exception:
        return False


def validate_manifest_path(path_str):
    if not path_str or ".." in path_str or path_str.startswith("/") or "\\" in path_str:
        raise ValueError(f"Invalid path in manifest: {path_str}")
    parsed = urllib.parse.urlparse(path_str)
    if parsed.query or parsed.fragment or parsed.scheme or parsed.netloc:
         raise ValueError(f"Invalid path in manifest (contains URI components): {path_str}")


class PackReader:
    def __init__(self, source: str, cache_dir: Path, manifest_sha256: Optional[str] = None):
        self.source = source
        self.cache_dir = Path(cache_dir).resolve()
        self.manifest_sha256 = manifest_sha256
        self.temp_dir = None
        self.db_path = None
        self.opener = create_opener()

    def __enter__(self):
        if not self.cache_dir.exists():
             self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.temp_dir = tempfile.mkdtemp(dir=self.cache_dir)
        try:
            self._mount()
        except Exception:
            self._cleanup()
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()

    def _cleanup(self):
        if self.temp_dir and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
        self.temp_dir = None
        self.db_path = None

    def _mount(self):
        is_url = self.source.startswith("https://")

        if is_url:
            if not self.manifest_sha256:
                raise ValueError("--manifest-sha256 is required for network sources")

            parsed_source = urllib.parse.urlparse(self.source)
            if parsed_source.netloc not in ALLOWED_HOSTS:
                raise ValueError(f"Host {parsed_source.netloc} not allowed")

            manifest_url = self.source
            if not manifest_url.endswith("/manifest.json"):
                manifest_url = manifest_url.rstrip("/") + "/manifest.json"

            manifest_bytes = download_bounded(self.opener, manifest_url, expected_sha256=self.manifest_sha256)
            manifest = json.loads(manifest_bytes.decode('utf-8'))
        else:
            manifest_path = Path(self.source) / "manifest.json"
            if not manifest_path.is_file():
                raise ValueError(f"Local manifest not found: {manifest_path}")
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes.decode('utf-8'))

            if self.manifest_sha256:
                sha256 = hashlib.sha256(manifest_bytes).hexdigest()
                if sha256 != self.manifest_sha256:
                     raise ValueError(f"Manifest hash mismatch: expected {self.manifest_sha256}, got {sha256}")

        if manifest.get('schema_version') != '0.1.0':
             raise ValueError("Unknown schema version in manifest")

        records = []
        for file_info in manifest.get('files', []):
            path_str = file_info.get('path')
            expected_sha256 = file_info.get('sha256')
            expected_size = file_info.get('bytes')

            validate_manifest_path(path_str)

            # Skip executing downloaded SQL. We only care about parsing JSON records.
            if path_str.endswith(".sql"):
                 continue

            if path_str.endswith(".json") and path_str.startswith("records/"):
                if is_url:
                    base_url = self.source.rsplit("/", 1)[0] if self.source.endswith("/manifest.json") else self.source.rstrip("/")
                    file_url = f"{base_url}/{urllib.parse.quote(path_str)}"
                    file_bytes = download_bounded(self.opener, file_url, expected_size=expected_size, expected_sha256=expected_sha256)
                else:
                    file_path = Path(self.source) / path_str
                    if not is_safe_path(self.source, file_path):
                        raise ValueError(f"Path traversal detected: {path_str}")
                    file_bytes = file_path.read_bytes()
                    if len(file_bytes) != expected_size:
                        raise ValueError(f"Size mismatch for {path_str}")
                    if hashlib.sha256(file_bytes).hexdigest() != expected_sha256:
                         raise ValueError(f"Hash mismatch for {path_str}")

                record = json.loads(file_bytes.decode('utf-8'))
                validate(record)
                records.append(record)

        if not records:
             raise ValueError("No valid records found in manifest")

        # Generate SQL locally via trusted build_sql
        sql_script = build_sql(records)

        # Build into separate temporary SQLite
        self.db_path = Path(self.temp_dir) / "pack.sqlite3"
        db = sqlite3.connect(str(self.db_path))
        try:
            db.executescript(sql_script)
            if db.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('Invalid SQL foreign keys in generated DB')
        finally:
            db.close()

    def query(self, query_str: str, limit: int = 5):
        if not self.db_path:
             raise RuntimeError("PackReader not mounted")
        return query_database(self.db_path, query_str, limit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='Local directory or HTTPS URL base to manifest')
    parser.add_argument('--cache', required=True, type=Path, help='Temp directory')
    parser.add_argument('--manifest-sha256', help='Explicit expected SHA256 for network use')
    parser.add_argument('--query', help='Optional query to run')
    parser.add_argument('--limit', type=int, default=5, help='Query limit')

    args = parser.parse_args()

    try:
        with PackReader(args.source, args.cache, args.manifest_sha256) as reader:
            if args.query:
                results = reader.query(args.query, args.limit)
                print(json.dumps({'results': results, 'status': 'EVIDENCE_FOUND' if results else 'ABSTAIN_NO_MATCH', 'detector': False}, indent=2))
            else:
                print("Pack successfully mounted and verified. No query provided.")
    except Exception as e:
        print(f"Error: {e}")
        import sys
        sys.exit(1)

if __name__ == '__main__':
    main()
