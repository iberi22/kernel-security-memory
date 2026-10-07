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
