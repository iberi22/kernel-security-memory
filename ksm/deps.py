"""ksm deps — known vulnerabilities in a project's dependencies via OSV.

Deterministic, no LLM: lockfile parsing (crates.io, npm, PyPI, Go), OSV
querybatch with disk caching, and one finding record per vulnerable locked
dependency. Advisory text is only ever printed, never written to disk.
"""

import hashlib
import json
import os
import re
import concurrent.futures
import http.client
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple, Optional, Sequence, Union

from ksm.data import resolve_data_dir

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_WEB_URL = "https://osv.dev/vulnerability/"
MAX_QUERIES_PER_REQUEST = 1000
CACHE_DIR_NAME = "osv-cache"

ECOSYSTEM_CRATES = "crates.io"
ECOSYSTEM_NPM = "npm"
ECOSYSTEM_PYPI = "PyPI"
ECOSYSTEM_GO = "Go"

LOCKFILE_BASENAMES = ("Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "go.sum")
REQUIREMENTS_PREFIX = "requirements"
REQUIREMENTS_SUFFIX = ".txt"

SKIP_DIRS = {".git", "node_modules", "target", "vendor", "dist", "build"}

SUPPORTED_LOCKFILES_HELP = (
    "Supported lockfiles: Cargo.lock (crates.io), package-lock.json (npm), "
    "pnpm-lock.yaml (npm, lockfileVersion 6.0/9.0), requirements*.txt (PyPI, "
    "exact name==version pins), go.sum (Go)."
)


class DepsError(Exception):
    """User-facing error: bad path, unreadable lockfile, OSV failure."""


class NoLockfileError(DepsError):
    """No supported lockfile found under PATH."""


class Dependency(NamedTuple):
    ecosystem: str
    package: str
    version: str


# ---------------------------------------------------------------------------
# Lockfile parsing
# ---------------------------------------------------------------------------


def _dedupe(deps: Iterable[Dependency]) -> list[Dependency]:
    seen = set()
    out = []
    for dep in deps:
        key = (dep.ecosystem, dep.package, dep.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(dep)
    return out


def _strip_toml_value(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        body = value[1:-1]
        return body.replace('\\"', '"').replace("\\\\", "\\")
    return value


def parse_cargo_lock(text: str) -> list[Dependency]:
    """Parse the [[package]] blocks of a Cargo.lock (v1-v4).

    Only registry dependencies count: entries with a path/git/wget source are
    skipped, as are [[patch.*]] blocks. v1 lockfiles carry no source field
    (implicit registry).
    """
    deps: list[Dependency] = []
    fields: Optional[dict] = None

    def flush() -> None:
        nonlocal fields
        if fields is None:
            return
        source = fields.get("source")
        if source is not None and not source.startswith("registry+"):
            fields = None
            return
        name = fields.get("name")
        version = fields.get("version")
        fields = None
        if name and version:
            deps.append(Dependency(ECOSYSTEM_CRATES, name, version))

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            flush()
            if line.startswith("[["):
                header = line[2:].split("]]", 1)[0].strip()
                if header == "package":
                    fields = {}
            continue
        if fields is not None and "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            if key in ("name", "version", "source"):
                fields[key] = _strip_toml_value(value.strip())
    flush()
    return _dedupe(deps)


def parse_package_lock(data: dict) -> list[Dependency]:
    """Parse package-lock.json: lockfileVersion 2/3 `packages` map, v1 `dependencies`."""
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            if not isinstance(info, dict):
                continue
            if not key:
                continue  # root package has key ""
            if info.get("link"):
                continue  # local link/symlink
            version = info.get("version")
            if not version:
                continue
            name = info.get("name")
            if not name:
                if "node_modules/" in key:
                    name = key.rsplit("node_modules/", 1)[1]
                else:
                    name = key
            if not name:
                continue
            deps.append(Dependency(ECOSYSTEM_NPM, str(name), str(version)))
        return _dedupe(deps)

    def walk(dependencies: dict) -> None:
        for name, info in sorted(dependencies.items()):
            if not isinstance(info, dict):
                continue
            nested = info.get("dependencies")
            if isinstance(nested, dict):
                walk(nested)
            version = info.get("version")
            if version:
                deps.append(Dependency(ECOSYSTEM_NPM, str(name), str(version)))

    walk(data.get("dependencies") or {})
    return _dedupe(deps)


def _split_pnpm_key(body: str) -> Optional[tuple]:
    """Split a pnpm package key into (name, version); None when not a key.

    Handles 'name@1.2.3', '@scope/name@1.2.3' and peer suffixes
    ('name@1.2.3(peer@x)').
    """
    key = body.split("(", 1)[0].strip()
    if not key:
        return None
    at = key.find("@", 1) if key.startswith("@") else key.find("@")
    if at <= 0:
        return None
    name, version = key[:at], key[at + 1:]
    if not name or not version:
        return None
    return name, version


def parse_pnpm_lock(text: str) -> list[Dependency]:
    """Parse the `packages:` section of a pnpm-lock.yaml (lockfileVersion 6.0/9.0).

    Line-based: v9 keys sit at indent 2, v6 keys at column 0; both are accepted
    until the next top-level section. `snapshots:` and `importers:` are ignored.
    """
    deps: list[Dependency] = []
    in_packages = False
    key_indent: Optional[int] = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if not stripped.endswith(":"):
            continue
        body = stripped[:-1].strip().strip("'\"")
        looks_like_key = _split_pnpm_key(body) is not None
        if indent == 0 and not in_packages:
            in_packages = body == "packages"
            key_indent = None
            continue
        if not in_packages:
            continue
        if key_indent is None:
            if not looks_like_key:
                in_packages = False
                continue
            key_indent = indent
        elif indent == key_indent:
            if not looks_like_key:
                in_packages = False
                key_indent = None
                continue
        elif indent > key_indent:
            continue  # child of a package entry (resolution, engines, ...)
        else:  # next top-level section
            in_packages = False
            key_indent = None
            if indent == 0 and looks_like_key:
                in_packages = True
                key_indent = 0
            continue
        split = _split_pnpm_key(body)
        if split:
            deps.append(Dependency(ECOSYSTEM_NPM, split[0], split[1]))
    return _dedupe(deps)


_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)\s*==\s*([0-9][A-Za-z0-9.!+*_]*)$"
)


def parse_requirements(text: str) -> list[Dependency]:
    """Parse a requirements*.txt, keeping only exact `name==version` pins."""
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue  # comments, options (-e, -r, --index-url), editable
        line = line.split(" #", 1)[0].strip()
        match = _REQ_LINE_RE.match(line)
        if not match:
            continue
        name = re.sub(r"\[.*\]", "", match.group(1))
        name = re.sub(r"[-_.]+", "-", name).lower()
        deps.append(Dependency(ECOSYSTEM_PYPI, name, match.group(2)))
    return _dedupe(deps)


_GO_SUM_RE = re.compile(r"^(\S+)\s+(\S+)\s+h1:")


def parse_go_sum(text: str) -> list[Dependency]:
    """Parse go.sum: module version lines, skipping /go.mod metadata and +incompatible."""
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _GO_SUM_RE.match(line)
        if not match:
            continue
        module, version = match.group(1), match.group(2)
        if version.endswith("/go.mod"):
            continue
        if version.endswith("+incompatible"):
            version = version[: -len("+incompatible")]
        deps.append(Dependency(ECOSYSTEM_GO, module, version))
    return _dedupe(deps)


def parse_lockfile(path: Path) -> list[Dependency]:
    """Dispatch to the parser for a discovered lockfile."""
    name = path.name
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise DepsError(f"could not read {path}: {exc}") from exc
    if name == "Cargo.lock":
        return parse_cargo_lock(text)
    if name == "package-lock.json":
        try:
            return parse_package_lock(json.loads(text))
        except ValueError as exc:
            raise DepsError(f"invalid JSON in {path}: {exc}") from exc
    if name == "pnpm-lock.yaml":
        return parse_pnpm_lock(text)
    if name == "go.sum":
        return parse_go_sum(text)
    if name.startswith(REQUIREMENTS_PREFIX) and name.endswith(REQUIREMENTS_SUFFIX):
        return parse_requirements(text)
    raise DepsError(f"unsupported lockfile: {path}")


def discover_lockfiles(root: Path) -> list[Path]:
    """Find supported lockfiles under root, skipping build/vendor directories."""
    if root.is_file():
        name = root.name
        if name in LOCKFILE_BASENAMES or (
            name.startswith(REQUIREMENTS_PREFIX) and name.endswith(REQUIREMENTS_SUFFIX)
        ):
            return [root]
        return []
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in LOCKFILE_BASENAMES or (
                name.startswith(REQUIREMENTS_PREFIX) and name.endswith(REQUIREMENTS_SUFFIX)
            ):
                found.append(Path(dirpath) / name)
    return sorted(found)


# ---------------------------------------------------------------------------
# OSV client (HTTP injectable for tests)
# ---------------------------------------------------------------------------


def _default_post_json(url: str, payload: dict, timeout: int = 60, retries: int = 4) -> dict:
    data = json.dumps(payload).encode("utf-8")
    for attempt in range(retries):
        try:
            request = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "ksm-cli"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            if attempt == retries - 1:
                raise
            time.sleep(1.0 * (attempt + 1))


def _default_get_json(url: str, timeout: int = 60, retries: int = 4) -> dict:
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "ksm-cli"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            if attempt == retries - 1:
                raise
            time.sleep(1.0 * (attempt + 1))


class OsvClient:
    """OSV API client with a disk cache and injectable HTTP functions.

    post_json/get_json take (url, payload) / (url) and return parsed JSON.
    Cache entries are keyed by sha256 of the request; --refresh bypasses reads.
    """

    def __init__(
        self,
        cache_dir: Optional[Union[str, Path]] = None,
        refresh: bool = False,
        post_json: Optional[Callable[[str, dict], dict]] = None,
        get_json: Optional[Callable[[str], dict]] = None,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.refresh = bool(refresh)
        self._post = post_json if post_json is not None else _default_post_json
        self._get = get_json if get_json is not None else _default_get_json
        self.cache_hits = 0
        self.cache_misses = 0

    def _cache_path(self, key: str) -> Optional[Path]:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _cache_get(self, key: str) -> Optional[dict]:
        path = self._cache_path(key)
        if path is None or self.refresh:
            return None
        try:
            if path.is_file():
                data = json.loads(path.read_text(encoding="utf-8"))
                self.cache_hits += 1
                return data
        except (OSError, ValueError):
            return None
        return None

    def _cache_put(self, key: str, data: dict) -> None:
        path = self._cache_path(key)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tid = threading.get_ident()
            tmp = path.with_name(f"{path.name}.{os.getpid()}.{tid}.tmp")
            tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass

    def post_json(self, url: str, payload: dict) -> dict:
        key = url + "\n" + json.dumps(payload, sort_keys=True)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        data = self._post(url, payload)
        self._cache_put(key, data)
        self.cache_misses += 1
        return data

    def get_json(self, url: str) -> dict:
        cached = self._cache_get(url)
        if cached is not None:
            return cached
        data = self._get(url)
        self._cache_put(url, data)
        self.cache_misses += 1
        return data

    def querybatch(self, queries: Sequence[dict]) -> list:
        """POST queries in batches of MAX_QUERIES_PER_REQUEST, following
        next_page_token per query. Returns one vuln-stub list per query."""
        all_results: list = []
        for start in range(0, len(queries), MAX_QUERIES_PER_REQUEST):
            chunk = queries[start : start + MAX_QUERIES_PER_REQUEST]
            all_results.extend(self._query_chunk(chunk))
        return all_results

    def _query_chunk(self, chunk: Sequence[dict]) -> list:
        per_query: list = [[] for _ in chunk]
        tokens: list = [None] * len(chunk)
        pending = list(range(len(chunk)))
        while pending:
            payload = []
            positions = []
            for idx in pending:
                query = dict(chunk[idx])
                if tokens[idx]:
                    query["page_token"] = tokens[idx]
                payload.append(query)
                positions.append(idx)
            response = self.post_json(OSV_BATCH_URL, {"queries": payload})
            results = response.get("results") or []
            next_pending = []
            for pos, idx in enumerate(positions):
                if pos >= len(results):
                    break
                result = results[pos] or {}
                per_query[idx].extend(result.get("vulns") or [])
                token = result.get("next_page_token")
                if token:
                    tokens[idx] = token
                    next_pending.append(idx)
            pending = next_pending
        return per_query

    def get_vuln_details(self, vuln_ids: Iterable[str]) -> dict:
        """Fetch GET /v1/vulns/<id> for each distinct id (cached)."""
        ids = sorted(set(vuln_ids))
        if not ids:
            return {}
        if len(ids) == 1:
            return {ids[0]: self.get_json(OSV_VULN_URL + ids[0])}
        details = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_id = {executor.submit(self.get_json, OSV_VULN_URL + vid): vid for vid in ids}
            for future in concurrent.futures.as_completed(future_to_id):
                vid = future_to_id[future]
                details[vid] = future.result()
        return details


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _version_key(version: str) -> tuple:
    """Best-effort comparable version key: numeric parts sort numerically."""
    key = []
    for part in re.split(r"[.\-+_]+", version.strip()):
        if not part:
            continue
        match = re.match(r"^(\d+)(.*)$", part)
        if match:
            key.append((1, int(match.group(1)), match.group(2)))
        else:
            key.append((0, 0, part))
    return tuple(key)


def _fixed_versions(detail: dict, ecosystem: str, package: str) -> list:
    """Fixed versions from the advisory's affected ranges for this package."""
    fixed = []
    for entry in detail.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package") or {}
        if pkg.get("name") != package:
            continue
        if pkg.get("ecosystem") not in (None, "", ecosystem):
            continue
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict):
                    version = event.get("fixed")
                    if version and version not in fixed:
                        fixed.append(version)
    return fixed


def _select_fixed(fixed_versions: Sequence[str], installed: str):
    """Smallest fixed version greater than installed when computable, else the sorted list."""
    if not fixed_versions:
        return []
    installed_key = _version_key(installed)
    greater = [v for v in fixed_versions if _version_key(v) > installed_key]
    if greater:
        return min(greater, key=_version_key)
    return sorted(fixed_versions, key=_version_key)


def _extract_severity(detail: dict) -> Optional[str]:
    for entry in detail.get("severity") or []:
        if isinstance(entry, dict) and entry.get("score"):
            return str(entry["score"])
    database_specific = detail.get("database_specific")
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        return str(database_specific["severity"])
    return None


def _build_finding(lockfile: Path, dep: Dependency, stub: dict, detail: dict) -> dict:
    advisory_id = detail.get("id") or stub.get("id") or "unknown"
    aliases = detail.get("aliases") or stub.get("aliases") or []
    summary = detail.get("summary") or stub.get("summary") or ""
    finding = {
        "lockfile": str(lockfile),
        "ecosystem": dep.ecosystem,
        "package": dep.package,
        "version": dep.version,
        "id": str(advisory_id),
        "aliases": sorted(str(a) for a in aliases),
        "summary": str(summary),
        "url": OSV_WEB_URL + str(advisory_id),
    }
    fixed = _fixed_versions(detail, dep.ecosystem, dep.package)
    selected = _select_fixed(fixed, dep.version)
    # fixed_version: the smallest fixed release above the installed one (None when
    # not computable); fixed_versions: every fixed release OSV lists.
    finding["fixed_version"] = selected if isinstance(selected, str) else None
    finding["fixed_versions"] = sorted(fixed, key=_version_key)
    severity = _extract_severity(detail)
    if severity:
        finding["severity"] = severity
    return finding


def _findings_for_queries(client: OsvClient, dep_records: Sequence[tuple]) -> list:
    """Query OSV once per distinct (ecosystem, package, version) and expand the
    results back to every lockfile that pins it."""
    order: list = []
    position_by_key: dict = {}
    for lockfile, dep in dep_records:
        key = (dep.ecosystem, dep.package, dep.version)
        pos = position_by_key.get(key)
        if pos is None:
            pos = len(order)
            position_by_key[key] = pos
            order.append((key, []))
        order[pos][1].append((lockfile, dep))

    queries = [
        {"package": {"name": key[1], "ecosystem": key[0]}, "version": key[2]}
        for key, _ in order
    ]
    per_query: list = []
    try:
        per_query = client.querybatch(queries)
        vuln_ids = sorted(
            {stub.get("id") for results in per_query for stub in results if stub.get("id")}
        )
        details = client.get_vuln_details(vuln_ids) if vuln_ids else {}
    except DepsError:
        raise
    except Exception as exc:
        raise DepsError(f"OSV request failed: {exc}") from exc

    findings = []
    for (key, pairs), results in zip(order, per_query):
        for stub in results or []:
            vid = stub.get("id")
            detail = details.get(vid) or {}
            for lockfile, dep in pairs:
                findings.append(_build_finding(lockfile, dep, stub, detail))
    return findings


# Preferred primary id when one vulnerability is published under several ids.
_ID_RANK = ("RUSTSEC-", "GHSA-", "PYSEC-", "GO-", "CVE-")


def _id_rank(advisory_id: str) -> tuple:
    for i, prefix in enumerate(_ID_RANK):
        if advisory_id.startswith(prefix):
            return (i, advisory_id)
    return (len(_ID_RANK), advisory_id)


def merge_aliases(findings: Sequence[dict]) -> list:
    """One finding per vulnerability: OSV often returns the same issue under
    several ids (RUSTSEC-... and GHSA-...) that alias each other."""
    groups: dict = {}
    for f in findings:
        key = (f["lockfile"], f["ecosystem"], f["package"], f["version"])
        ids = {f["id"], *f["aliases"]}
        bucket = groups.setdefault(key, [])
        merged = [g for g in bucket if g["_ids"] & ids]
        for g in merged:
            bucket.remove(g)
        members = [f] + [m for g in merged for m in g["_members"]]
        bucket.append({"_ids": ids.union(*(g["_ids"] for g in merged)), "_members": members})
    out = []
    for bucket in groups.values():
        for g in bucket:
            primary = min(g["_members"], key=lambda m: _id_rank(m["id"]))
            finding = dict(primary)
            finding["aliases"] = sorted(g["_ids"] - {primary["id"]})
            fixed = sorted({v for m in g["_members"] for v in m["fixed_versions"]}, key=_version_key)
            finding["fixed_versions"] = fixed
            selected = _select_fixed(fixed, primary["version"])
            finding["fixed_version"] = selected if isinstance(selected, str) else None
            if "severity" not in finding:
                sev = next((m["severity"] for m in g["_members"] if m.get("severity")), None)
                if sev:
                    finding["severity"] = sev
            out.append(finding)
    return out


def run_deps(
    path: Union[str, Path],
    data_dir: Optional[Union[str, Path]] = None,
    refresh: bool = False,
    client: Optional[OsvClient] = None,
) -> list:
    """Return the sorted finding list for every lockfile under path."""
    root = Path(path).expanduser()
    if not root.exists():
        raise DepsError(f"path does not exist: {root}")
    lockfiles = discover_lockfiles(root)
    if not lockfiles:
        raise NoLockfileError(
            f"no supported lockfile found under {root}. {SUPPORTED_LOCKFILES_HELP}"
        )
    if client is None:
        client = OsvClient(
            cache_dir=resolve_data_dir(data_dir) / CACHE_DIR_NAME, refresh=refresh
        )
    elif not hasattr(client, "querybatch"):
        client = OsvClient(
            cache_dir=getattr(client, "cache_dir", None),
            refresh=refresh,
            post_json=getattr(client, "post_json", None),
            get_json=getattr(client, "get_json", None),
        )
    dep_records = []
    for lockfile in lockfiles:
        try:
            deps = parse_lockfile(lockfile)
        except DepsError:
            raise
        except (OSError, ValueError) as exc:
            raise DepsError(f"could not parse {lockfile}: {exc}") from exc
        dep_records.extend((lockfile, dep) for dep in deps)
    findings = merge_aliases(_findings_for_queries(client, dep_records))
    findings.sort(key=lambda f: (f["lockfile"], f["package"].lower(), f["id"]))
    return findings


def format_human(findings: Sequence[dict]) -> str:
    """Group findings by lockfile, sorted by package then id, with a count line."""
    if not findings:
        return "No known vulnerabilities found in locked dependencies."
    by_lockfile: dict = {}
    for finding in findings:
        by_lockfile.setdefault(finding["lockfile"], []).append(finding)
    lines = []
    for lockfile in sorted(by_lockfile):
        lines.append(f"{lockfile}:")
        group = sorted(by_lockfile[lockfile], key=lambda f: (f["package"].lower(), f["id"]))
        for finding in group:
            lines.append(
                f"  {finding['ecosystem']} {finding['package']} "
                f"{finding['version']}: {finding['id']}"
            )
            if finding["aliases"]:
                lines.append(f"    aliases: {', '.join(finding['aliases'])}")
            if finding.get("severity"):
                lines.append(f"    severity: {finding['severity']}")
            if finding.get("fixed_version"):
                lines.append(f"    fixed in: {finding['fixed_version']}")
            elif finding["fixed_versions"]:
                lines.append(f"    fixed versions: {', '.join(finding['fixed_versions'])}")
            else:
                lines.append("    fixed in: no fixed release listed")
            lines.append(f"    {finding['url']}")
            summary = finding["summary"].strip()
            if summary:
                lines.append(f"    {summary}")
        lines.append("")
    lines.append(f"{len(findings)} finding(s) across {len(by_lockfile)} lockfile(s)")
    return "\n".join(lines)
