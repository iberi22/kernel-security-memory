#!/usr/bin/env python3
"""Publish a locally verified memory pack to Xavier over HTTP.

Reads a local pack directory (manifest.json + records/*.json), verifies
per-file sha256/size against the manifest and validates each record with
build_pack.validate (same rules as open_pack.PackReader), then POSTs each
record as one memory to a configurable Xavier HTTP endpoint.

Auth: ``XAVIER_URL`` (base URL) and ``XAVIER_TOKEN`` are read ONLY from the
environment at runtime. They are never committed, never written to files,
and never printed to stdout/stderr (errors are redacted).

Disconnect: re-run with ``--disconnect`` and the same ``--path-prefix``;
the script issues one DELETE per published path, then the procedure in
docs/XAVIER-BRIDGE.md applies. This bridge never mounts a foreign DB and
never restores SQL anywhere: only verified JSON records cross the boundary.

Stdlib only.
"""

import argparse
import hashlib
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_pack import validate
from open_pack import is_safe_path, validate_manifest_path

DEFAULT_ENDPOINT = "/v1/memories"
TIMEOUT = 15


def _redact(text):
    """Remove anything that could carry a secret from an error message."""
    text = str(text)
    for var in ("XAVIER_TOKEN",):
        secret = os.environ.get(var)
        if secret and secret in text:
            text = text.replace(secret, "<redacted>")
    return text


def _environ(name):
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"Error: {name} is not set in the environment")
    return value


def verify_pack(source, manifest_sha256=None):
    """Verify a local pack dir; return (manifest, records). Raises on failure."""
    source_dir = Path(source)
    manifest_path = source_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"Local manifest not found: {manifest_path}")
    manifest_bytes = manifest_path.read_bytes()
    if manifest_sha256:
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        if digest != manifest_sha256:
            raise ValueError("Manifest hash mismatch")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if manifest.get("schema_version") != "0.1.0":
        raise ValueError("Unknown schema version in manifest")
    records = []
    for file_info in manifest.get("files", []):
        path_str = file_info.get("path")
        validate_manifest_path(path_str)
        if not (path_str.endswith(".json") and path_str.startswith("records/")):
            continue
        file_path = source_dir / path_str
        # Validate the relative record path itself: file_path already
        # contains source_dir, so passing it would join the base twice.
        if not is_safe_path(str(source_dir), path_str):
            raise ValueError(f"Path traversal detected: {path_str}")
        resolved = (source_dir / path_str).resolve()
        if resolved != file_path.resolve() or \
                source_dir.resolve() not in resolved.parents:
            raise ValueError(f"Path traversal detected: {path_str}")
        data = file_path.read_bytes()
        if len(data) != file_info.get("bytes"):
            raise ValueError(f"Size mismatch for {path_str}")
        if hashlib.sha256(data).hexdigest() != file_info.get("sha256"):
            raise ValueError(f"Hash mismatch for {path_str}")
        record = json.loads(data.decode("utf-8"))
        validate(record)
        records.append(record)
    if not records:
        raise ValueError("No valid records found in manifest")
    return manifest, records


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code,
                                     "Redirects not allowed", headers, fp)


def _opener():
    return urllib.request.build_opener(_NoRedirect)


def _request(url, token, method="POST", body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
    )
    try:
        with _opener().open(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", "replace")[:500]
        except Exception:
            detail = ""
        raise RuntimeError(f"HTTP {exc.code} {method} {url} :: {detail}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error {method} {url} :: {exc.reason}")


def _url_allowed(base_url):
    """Bearer tokens travel only over TLS, or plain HTTP to loopback."""
    try:
        parts = urllib.parse.urlparse(base_url)
    except Exception:
        return False
    if parts.scheme == "https" and parts.hostname:
        return True
    if parts.scheme == "http" and parts.hostname in (
            "localhost", "127.0.0.1", "::1"):
        return True
    return False


def mem_path(prefix, record_id):
    return f"{prefix.rstrip('/')}/{record_id}"


def mem_body(prefix, record):
    return {
        "path": mem_path(prefix, record["id"]),
        "title": record["title"],
        "project": record["project"],
        "status": record["status"],
        "payload": record,
    }


def _load_inventory(path):
    if not path:
        return []
    try:
        items = json.loads(Path(path).read_bytes().decode("utf-8"))
    except FileNotFoundError:
        return []
    return [p for p in items if isinstance(p, str) and "/" in p]


def _save_inventory(path, paths):
    if not path:
        return
    Path(path).write_text(json.dumps(sorted(set(paths)), indent=2) + "\n")


def publish(records, base_url, token, endpoint=DEFAULT_ENDPOINT,
            prefix="ksm-pack", dry_run=False, disconnect=False,
            inventory=None):
    """Send one request per record. Returns a summary dict. No secrets in it."""
    url = base_url.rstrip("/") + endpoint
    action = "DELETE" if disconnect else "POST"
    if disconnect:
        paths = [mem_path(prefix, r["id"]) for r in records]
        for known in _load_inventory(inventory):
            if known not in paths:
                paths.append(known)
        plan = [(p, url + "/" + urllib.parse.quote(p, safe=""), None)
                for p in paths]
    else:
        plan = []
        for record in records:
            path = mem_path(prefix, record["id"])
            target = url + "/" + urllib.parse.quote(path, safe="")
            plan.append((path, target, mem_body(prefix, record)))
    if dry_run:
        for path, target, body in plan:
            nbytes = len(json.dumps(body).encode()) if body else 0
            print(f"DRY-RUN {action} {target} path={path} bytes={nbytes}")
        return {"action": action, "dry_run": True, "count": len(plan)}
    sent, failed = 0, []
    for path, target, body in plan:
        try:
            if disconnect:
                _request(target, token, method="DELETE")
            else:
                _request(target, token, method="POST", body=body)
            sent += 1
        except Exception as exc:  # noqa: BLE001 - report per-record, redacted
            failed.append({"path": path, "error": _redact(exc)})
    summary = {"action": action, "dry_run": False, "sent": sent,
               "failed": failed, "count": len(plan)}
    print(json.dumps(summary, indent=2))
    if failed:
        raise SystemExit(f"Error: {len(failed)}/{len(plan)} requests failed")
    if not disconnect:
        _save_inventory(inventory, [p for p, _, _ in plan])
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True,
                        help="Local verified pack directory (manifest.json + records/)")
    parser.add_argument("--path-prefix", default="ksm-pack",
                        help="Path prefix for published memories (also used to disconnect)")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                        help="API path appended to XAVIER_URL")
    parser.add_argument("--manifest-sha256",
                        help="Optional expected sha256 of manifest.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="Verify and show what would be sent; no network")
    parser.add_argument("--disconnect", action="store_true",
                        help="DELETE every path with the prefix instead of publishing")
    parser.add_argument("--inventory", default=None,
                        help="Optional JSON file recording published paths; "
                             "disconnect also deletes paths listed here")
    args = parser.parse_args(argv)

    if args.source.startswith(("http://", "https://")):
        raise SystemExit("Error: only local pack directories are accepted")

    manifest, records = verify_pack(args.source, args.manifest_sha256)
    print(f"Verified pack: {manifest.get('pack_id')} "
          f"({len(records)} records, manifest schema {manifest.get('schema_version')})")

    if args.dry_run:
        return publish(records, "<dry-run>", "<dry-run>",
                       args.endpoint, args.path_prefix, dry_run=True,
                       disconnect=args.disconnect, inventory=args.inventory)

    base_url = _environ("XAVIER_URL")
    token = _environ("XAVIER_TOKEN")
    if not _url_allowed(base_url):
        raise SystemExit("Error: XAVIER_URL must be https, or http loopback "
                         "(localhost/127.0.0.1/::1)")
    try:
        return publish(records, base_url, token, args.endpoint,
                       args.path_prefix, disconnect=args.disconnect,
                       inventory=args.inventory)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - never leak the token
        raise SystemExit(f"Error: {_redact(exc)}")


if __name__ == "__main__":
    main()
