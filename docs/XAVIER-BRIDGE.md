# Xavier bridge — connect / disconnect

Publish a locally verified memory pack to Xavier over HTTP. The bridge
copies **verified JSON records only**; it never mounts a foreign database,
never restores SQL anywhere, and never reads a live Xavier DB
(`apps/xavier/data` and `.env` files are out of bounds by rule).

## Connect (publish)

1. Build and check the pack first:
   `python3 scripts/build_pack.py --check`
2. Export the runtime credentials (never commit them):
   `export XAVIER_URL=https://<host>:8006` (https required; plain http
   is accepted only for loopback `localhost`/`127.0.0.1`/`::1`)
   `export XAVIER_TOKEN=<token>`
3. Preview without network:
   `python3 scripts/pack_to_xavier.py --source docs/memory --dry-run`
4. Publish (one POST per record under `--path-prefix`, default `ksm-pack`):
   `python3 scripts/pack_to_xavier.py --source docs/memory`
5. Optional: `--manifest-sha256 <hex>` pins the manifest;
   `--endpoint` overrides the default `/v1/memories` path.

Auth is `Authorization: Bearer <XAVIER_TOKEN>` from the environment only.
The token never appears in code, logs, or error messages (redacted).

## Disconnect (remove)

Re-run with the same prefix; one DELETE per published path, no SQL involved:

`python3 scripts/pack_to_xavier.py --source docs/memory --disconnect`

Disconnect deletes the current pack's paths **plus** every path recorded
in `--inventory <file>` (written on each successful publish), so memories
from earlier packs with retired IDs are also removed. Without an
inventory file, only the current pack's IDs are deleted.

Then verify server-side that no path under the prefix remains
(e.g. query by prefix; exact command depends on the Xavier version).
To rotate credentials afterwards, revoke `XAVIER_TOKEN` at the source.

## Limits

- Local pack directories only; remote URLs are rejected.
- Only `records/*.json` entries listed in `manifest.json` cross the
  boundary, after per-file sha256/size checks plus `build_pack.validate`.
  `.sql` exports are never executed or uploaded by this bridge.
- No mounting of another database, no SQL restore into production,
  no reads from live Xavier storage. HTTP API with a runtime env token
  is the only coupling.
- Fail-closed: missing env, hash mismatch, HTTP error, or tampered
  record aborts with a redacted message and a non-zero exit.
- Redirects are refused, not followed (a 3xx becomes an error).
- `--dry-run` honors `--disconnect` and previews DELETEs in that mode.

## Reversible native HTTP mount / unmount

`scripts/xavier_mount.py` imports into Xavier's memory HTTP API using a
pack-specific namespace `ksm-pack/<pack_id>/<manifest-sha256>`. Here mount
means an HTTP import; the adapter never attaches or opens a database file.
The complete pack is verified before any network request. Use the same
runtime `XAVIER_URL` and `XAVIER_TOKEN` environment variables as above.

```sh
python3 scripts/xavier_mount.py connect --source docs/memory \
  --revision <pinned-source-commit> --receipt /tmp/ksm-import.json --dry-run
python3 scripts/xavier_mount.py connect --source docs/memory \
  --revision <pinned-source-commit> --receipt /tmp/ksm-import.json
python3 scripts/xavier_mount.py status --receipt /tmp/ksm-import.json
python3 scripts/xavier_mount.py disconnect --receipt /tmp/ksm-import.json
```

Connect requires a new receipt filename and an explicit source revision
(`--revision`, or `revision` in the manifest); the caller supplies the
revision provenance. `--manifest-sha256` optionally pins the manifest.
Receipts store the pack ID, namespace, revision, manifest SHA-256, original
record IDs, exact memory paths and server memory IDs. Each POST also carries
import provenance in metadata. Existing target paths are rejected rather
than overwritten. A recovery receipt is saved atomically **before** the
first POST and updated after each response; keep it if an import fails.
A subsequent namespace listing verifies that every imported path exists.

Status lists server record IDs and paths under that exact namespace.
Disconnect resolves only receipt paths to their current server IDs, deletes
those IDs, then lists again and fails if any selected paths remain. Other
memories, including additional records in the same namespace, are preserved.
A repeated disconnect is safe. A receipt works after the original source
pack has gone away; without a receipt, `status` and `disconnect` accept
`--source docs/memory` and select only the current verified pack's records.
Keep receipts locally outside Git; they contain no runtime credentials.

All three commands accept `--dry-run`: they preview the action, namespace
and record selection without network requests, credentials or file writes.
Errors omit HTTP bodies and transport details and redact environment
credentials. HTTPS is required except on loopback; URL credentials, query
strings, fragments and redirects are refused.

The tested server contract is `GET /v1/memories?prefix=...&offset=...&limit=100`
returning `{"memories": [{"id": "...", "path": "..."}], "total": N}`,
`POST /v1/memories` returning an optional `id`, and
`DELETE /v1/memories/<percent-encoded-id>`. The client follows offset pages,
filters paths locally, and rejects malformed or unsupported listings. If
`total` is absent, a short page ends the listing. DELETE 404 is idempotent.
Validation uses an in-process stdlib mock server, including partial-import
recovery and deletion verification; compatibility with a deployed Xavier
version and live import deletion have **not** been validated.
