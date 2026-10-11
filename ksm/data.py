"""Data resolution, bundle download/extraction, and shard loading helpers for KSM."""

import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request

from ksm import net as _net
from pathlib import Path
from typing import Any, Optional, Union

DEFAULT_UPDATE_URL = "https://iberi22.github.io/kernel-security-memory/data/"


# Advisory ids are path components: CVE-..., OSV-..., letters, digits and dashes only.
CVE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z0-9-]+$")
CWE_ID_RE = re.compile(r"^(CWE-\d+|UNKNOWN)$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def _user_data_dir() -> Path:
    """Where `ksm update` installs the bundle: $XDG_DATA_HOME/ksm or ~/.local/share/ksm."""
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data and xdg_data.strip():
        return (Path(xdg_data).expanduser() / "ksm").resolve()
    return (Path.home() / ".local" / "share" / "ksm").resolve()


def resolve_data_dir(data_dir: Optional[Union[str, Path]] = None) -> Path:
    """Resolve the KSM data directory in precedence order:
    1. --data-dir
    2. $KSM_DATA
    3. the installed bundle ($XDG_DATA_HOME/ksm), when `ksm update` has run
    4. <repo checkout>/site/data, when built locally
    5. the bundle location (default for `ksm update`)
    `ksm update` writes to 1, 2 or 5, so reads after an update always see it.
    """
    if data_dir is not None and str(data_dir).strip():
        return Path(data_dir).expanduser().resolve()

    env_ksm_data = os.environ.get("KSM_DATA")
    if env_ksm_data and env_ksm_data.strip():
        return Path(env_ksm_data).expanduser().resolve()

    user_dir = _user_data_dir()
    if (user_dir / "index.json").is_file():
        return user_dir

    repo_site_data = Path(__file__).resolve().parent.parent / "site" / "data"
    if (repo_site_data / "index.json").is_file():
        return repo_site_data.resolve()

    return user_dir


def _is_safe_tar_member(member: tarfile.TarInfo) -> bool:
    """Check if a tar member is safe to extract."""
    name = member.name
    if name.startswith("/") or name.startswith(chr(92)):
        return False
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return False
    parts = Path(name).parts
    if ".." in parts:
        return False
    if member.issym() or member.islnk():
        return False
    return True


def update(
    url: str = DEFAULT_UPDATE_URL,
    dest: Optional[Union[str, Path]] = None,
) -> Path:
    """Download bundle.sha256 and bundle.tar.gz, verify sha256,
    extract safely, and atomically swap the directory into dest.
    """
    if dest is not None and str(dest).strip():
        dest_path = Path(dest).expanduser().resolve()
    else:
        env_ksm_data = os.environ.get("KSM_DATA")
        if env_ksm_data and env_ksm_data.strip():
            dest_path = Path(env_ksm_data).expanduser().resolve()
        else:
            dest_path = _user_data_dir()

    # Normalize base URL
    raw_url = str(url).strip()
    if not (raw_url.startswith("http://") or raw_url.startswith("https://") or raw_url.startswith("file://")):
        # Treat as local filesystem path
        raw_url = Path(raw_url).resolve().as_uri()

    if not raw_url.endswith("/"):
        raw_url += "/"

    sha_url = urllib.parse.urljoin(raw_url, "bundle.sha256")
    tar_url = urllib.parse.urljoin(raw_url, "bundle.tar.gz")

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Fetch expected sha256
    try:
        req_sha = urllib.request.Request(sha_url, headers={"User-Agent": "ksm-cli"})
        with _net.urlopen(req_sha, timeout=30) as resp:
            sha_content = resp.read().decode("utf-8").strip()
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch checksum from {sha_url}: {exc}") from exc

    if not sha_content:
        raise ValueError("Empty bundle.sha256 received")
    expected_sha = sha_content.split()[0].lower()

    # 2. Download bundle.tar.gz to a temporary file
    tmp_tar = tempfile.NamedTemporaryFile(
        dir=dest_path.parent,
        prefix="ksm-download-",
        suffix=".tar.gz",
        delete=False,
    )
    tmp_tar_path = Path(tmp_tar.name)
    hasher = hashlib.sha256()

    try:
        try:
            req_tar = urllib.request.Request(tar_url, headers={"User-Agent": "ksm-cli"})
            with _net.urlopen(req_tar, timeout=60) as resp:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    tmp_tar.write(chunk)
        finally:
            tmp_tar.close()

        actual_sha = hasher.hexdigest().lower()
        if actual_sha != expected_sha:
            raise ValueError(
                f"SHA256 checksum mismatch for bundle: expected {expected_sha}, got {actual_sha}"
            )

        # 3. Extract safely to stage directory
        stage_dir = Path(tempfile.mkdtemp(dir=dest_path.parent, prefix="ksm-stage-"))
        try:
            with tarfile.open(tmp_tar_path, "r:*") as tf:
                for member in tf.getmembers():
                    if not _is_safe_tar_member(member):
                        raise ValueError(f"Unsafe member in tar bundle rejected: {member.name}")

                extract_kwargs = {}
                if hasattr(tarfile, "data_filter"):
                    extract_kwargs["filter"] = "data"
                tf.extractall(path=stage_dir, **extract_kwargs)

            # Check if contents are nested under a single wrapper directory
            extracted_items = list(stage_dir.iterdir())
            if (
                len(extracted_items) == 1
                and extracted_items[0].is_dir()
                and not (stage_dir / "index.json").exists()
                and (extracted_items[0] / "index.json").exists()
            ):
                nested = extracted_items[0]
                for item in nested.iterdir():
                    shutil.move(str(item), str(stage_dir))
                nested.rmdir()

            # 4. Atomic directory swap
            if dest_path.exists():
                backup_parent = Path(tempfile.mkdtemp(dir=dest_path.parent, prefix="ksm-backup-"))
                old_dest = backup_parent / "old"
                os.rename(dest_path, old_dest)
                try:
                    os.rename(stage_dir, dest_path)
                    shutil.rmtree(backup_parent, ignore_errors=True)
                except Exception:
                    if not dest_path.exists() and old_dest.exists():
                        os.rename(old_dest, dest_path)
                    shutil.rmtree(backup_parent, ignore_errors=True)
                    raise
            else:
                os.rename(stage_dir, dest_path)

        finally:
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)

    finally:
        tmp_tar_path.unlink(missing_ok=True)

    return dest_path


def load_index(data_dir: Optional[Union[str, Path]] = None) -> dict[str, Any]:
    """Load index.json from the resolved data directory."""
    path = resolve_data_dir(data_dir) / "index.json"
    if not path.is_file():
        raise FileNotFoundError(f"KSM index.json not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_search(data_dir: Optional[Union[str, Path]] = None) -> list[list[Any]]:
    """Load search.json from the resolved data directory."""
    path = resolve_data_dir(data_dir) / "search.json"
    if not path.is_file():
        raise FileNotFoundError(f"KSM search.json not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_cwe(cwe_id: str, data_dir: Optional[Union[str, Path]] = None) -> dict[str, Any]:
    """Load cwe/<cwe_id>.json from the resolved data directory."""
    if not CWE_ID_RE.match(cwe_id.strip().upper()):
        raise FileNotFoundError(f"not a CWE id: {cwe_id!r}")
    data_path = resolve_data_dir(data_dir)
    target = data_path / "cwe" / f"{cwe_id.upper()}.json"
    if not target.is_file():
        target = data_path / "cwe" / f"{cwe_id}.json"
    if not target.is_file():
        raise FileNotFoundError(f"CWE data not found for {cwe_id} at {target}")
    return json.loads(target.read_text(encoding="utf-8"))


def load_cve(project: str, cve_id: str, data_dir: Optional[Union[str, Path]] = None) -> dict[str, Any]:
    """Load cve/<project>/<cve_id>.json from the resolved data directory."""
    if not CVE_ID_RE.match(cve_id.strip().upper()) or not PROJECT_RE.match(project):
        raise FileNotFoundError(f"not a CVE id / project name: {cve_id!r} {project!r}")
    data_path = resolve_data_dir(data_dir)
    target = data_path / "cve" / project / f"{cve_id.upper()}.json"
    if not target.is_file():
        target = data_path / "cve" / project / f"{cve_id}.json"
    if not target.is_file():
        raise FileNotFoundError(f"CVE data not found for {cve_id} ({project}) at {target}")
    return json.loads(target.read_text(encoding="utf-8"))


def find_cve_project(cve_id: str, data_dir: Optional[Union[str, Path]] = None) -> Optional[str]:
    """Find the owning project for a given CVE ID via search.json or directory scan."""
    cve_upper = cve_id.strip().upper()
    data_path = resolve_data_dir(data_dir)

    # 1. Try search.json first
    search_path = data_path / "search.json"
    if search_path.is_file():
        try:
            rows = json.loads(search_path.read_text(encoding="utf-8"))
            for row in rows:
                if row and len(row) >= 2 and str(row[0]).strip().upper() == cve_upper:
                    return str(row[1])
        except Exception:
            pass

    # 2. Fall back to scanning cve/ directory
    cve_dir = data_path / "cve"
    if cve_dir.is_dir():
        for proj_dir in cve_dir.iterdir():
            if proj_dir.is_dir():
                candidate = proj_dir / f"{cve_upper}.json"
                if candidate.is_file():
                    return proj_dir.name
                candidate_orig = proj_dir / f"{cve_id}.json"
                if candidate_orig.is_file():
                    return proj_dir.name

    return None


def get_pattern_clusters_path(data_dir: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """Find pattern_clusters.json path in data dir bundle or repo fallback."""
    base_data = resolve_data_dir(data_dir)
    candidates = [
        base_data / "pattern_clusters.json",
        base_data / "clusters.json",
        base_data / "docs" / "studies" / "pattern_clusters.json",
        Path(__file__).resolve().parent.parent / "docs" / "studies" / "pattern_clusters.json",
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    # Default to repo location even if not yet created
    return (Path(__file__).resolve().parent.parent / "docs" / "studies" / "pattern_clusters.json").resolve()


def get_fingerprints_dir(data_dir: Optional[Union[str, Path]] = None) -> Path:
    """Fingerprint corpus: the bundle's copy, else the repo checkout's."""
    bundled = resolve_data_dir(data_dir) / "fingerprints"
    if bundled.is_dir():
        return bundled
    repo = Path(__file__).resolve().parent.parent / "docs" / "studies" / "fingerprints"
    return repo if repo.is_dir() else bundled
