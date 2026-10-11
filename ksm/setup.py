"""`ksm setup` and `ksm doctor`: install and verify the code-graph scanner.

The scanner is an external binary (see ksm/scanner.py for the pinned
revision). `ksm setup` installs it without needing the Xavier repository:
a prebuilt Linux x86_64 tarball from the KSM releases page, or built from
source with cargo. `ksm doctor` reports data and scanner readiness without
touching the network.
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional, Union

from ksm.data import _user_data_dir, resolve_data_dir
from ksm.scanner import CODE_GRAPH_REV, XAVIER_REPO, resolve_code_graph_bin

TARBALL = "code-graph-x86_64-linux.tar.gz"

DownloadFn = Callable[[str, Path], Path]
ExtractFn = Callable[[Path, Path], Path]


def release_tag() -> str:
    """Release tag of the prebuilt binary: code-graph-<first 8 of the rev>."""
    return "code-graph-" + CODE_GRAPH_REV[:8]


def cargo_command() -> str:
    """The from-source install command (same form as in README)."""
    return (
        f"cargo install --locked --git {XAVIER_REPO} --rev {CODE_GRAPH_REV} code-graph"
    )


def supported_platform(system: Optional[str] = None, machine: Optional[str] = None) -> bool:
    """Only Linux x86_64 has a prebuilt binary."""
    if system is None:
        system = platform.system()
    if machine is None:
        machine = platform.machine()
    return system == "Linux" and machine == "x86_64"


def download_url(name: str) -> str:
    return (
        "https://github.com/iberi22/kernel-security-memory/releases/download/"
        f"{release_tag()}/{name}"
    )


def download_file(url: str, dest: Path, timeout: int = 300) -> Path:
    """Fetch url into dest (stdlib only, User-Agent like ksm.data.update)."""
    req = urllib.request.Request(url, headers={"User-Agent": "ksm-cli"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        dest.write_bytes(resp.read())
    return dest


def verify_file_sha256(path: Path, expected_sha: str) -> None:
    """Raise ValueError unless path's sha256 matches the expected hex digest."""
    actual = hashlib.sha256(path.read_bytes()).hexdigest().lower()
    if actual != expected_sha.strip().lower():
        raise ValueError(
            f"SHA256 checksum mismatch for {path.name}: expected {expected_sha.strip().lower()}, "
            f"got {actual}"
        )


def _is_safe_tar_member(member: tarfile.TarInfo) -> bool:
    """Check if a tar member is safe to extract (no paths, no links)."""
    name = member.name
    if name.startswith("/") or name.startswith("\\"):
        return False
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return False
    if ".." in Path(name).parts:
        return False
    if member.issym() or member.islnk():
        return False
    if "/" in name or "\\" in name:
        return False
    return True


def extract_code_graph_member(tarball: Path, install_dir: Path) -> Path:
    """Extract only the `code-graph` member of the tarball into install_dir.

    Refuses a missing member and any member with a path or a link. Returns the
    installed binary path (mode 755).
    """
    with tarfile.open(tarball, "r:*") as tf:
        members = tf.getmembers()
        for m in members:
            if not _is_safe_tar_member(m):
                raise ValueError(f"Unsafe member in tar rejected: {m.name}")
        member = None
        for candidate in members:
            if candidate.name == "code-graph":
                member = candidate
                break
        if member is None:
            raise ValueError(f"{tarball.name} has no 'code-graph' member")
        if not (member.isreg() or member.isfile()):
            raise ValueError(f"Tar member {member.name} is not a regular file")
        src = tf.extractfile(member)
        if src is None:
            raise ValueError(f"Cannot read tar member: {member.name}")
        payload = src.read()

    target = install_dir / "code-graph"
    install_dir.mkdir(parents=True, exist_ok=True)
    tmp_target = install_dir / ".code-graph.tmp"
    tmp_target.write_bytes(payload)
    os.chmod(tmp_target, 0o755)
    os.replace(tmp_target, target)
    return target


def _read_sha256_file(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError("Empty .sha256 file received")
    return text.split()[0].lower()


def install_prebuilt(
    data_dir: Path,
    download: DownloadFn = download_file,
    extract: ExtractFn = extract_code_graph_member,
) -> Path:
    """Download the prebuilt tarball, verify its sha256, install the binary."""
    with tempfile.TemporaryDirectory(prefix="ksm-setup-") as tmp:
        tmp_path = Path(tmp)
        tarball = tmp_path / TARBALL
        download(download_url(TARBALL), tarball)
        sha_file = tmp_path / (TARBALL + ".sha256")
        download(download_url(TARBALL + ".sha256"), sha_file)
        expected_sha = _read_sha256_file(sha_file)
        verify_file_sha256(tarball, expected_sha)
        return extract(tarball, data_dir / "bin")


def install_from_cargo(data_dir: Path) -> Path:
    """Build code-graph from the pinned Xavier revision with cargo."""
    cmd = [
        "cargo", "install", "--locked", "--git", XAVIER_REPO,
        "--rev", CODE_GRAPH_REV, "code-graph", "--root", str(data_dir),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip()
        raise RuntimeError(f"cargo install failed with exit code {res.returncode}: {detail}")
    return data_dir / "bin" / "code-graph"


def run_setup(
    from_cargo: bool = False,
    data_dir: Optional[Union[str, Path]] = None,
    download: Optional[DownloadFn] = None,
    extract: Optional[ExtractFn] = None,
) -> Path:
    """Install the code-graph scanner; returns the installed binary path."""
    target_dir = Path(data_dir).expanduser().resolve() if data_dir is not None else _user_data_dir()
    if download is None:
        download = download_file
    if extract is None:
        extract = extract_code_graph_member
    if from_cargo:
        return install_from_cargo(target_dir)
    return install_prebuilt(target_dir, download=download, extract=extract)


def count_fingerprints(data_dir: Path) -> int:
    """Number of fix-fingerprint JSON files under <data_dir>/fingerprints."""
    fp_dir = data_dir / "fingerprints"
    if fp_dir.is_dir():
        return sum(1 for p in fp_dir.rglob("*.json") if p.is_file())
    fallback = data_dir / "docs" / "studies" / "fingerprints"
    if fallback.is_dir():
        return sum(1 for p in fallback.rglob("*.json") if p.is_file())
    return 0


def check_scanner(bin_path: Optional[str]) -> dict:
    """Run the scanner on a tiny temp C file; check it prints ksm-sfp/1."""
    if not bin_path:
        return {"path": None, "ksm_sfp": False}
    with tempfile.TemporaryDirectory(prefix="ksm-doctor-") as tmp:
        tiny_c = Path(tmp) / "smoke.c"
        tiny_c.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        try:
            res = subprocess.run(
                [bin_path, "fingerprint", str(tiny_c)],
                capture_output=True, text=True, check=False, timeout=300,
            )
            doc = json.loads(res.stdout) if res.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            doc = None
    ok = isinstance(doc, dict) and doc.get("schema") == "ksm-sfp/1"
    return {"path": bin_path, "ksm_sfp": ok}


def doctor_status(data_dir: Optional[Union[str, Path]] = None) -> dict[str, Any]:
    """Network-free readiness status of the data dir and the scanner."""
    data_path = resolve_data_dir(data_dir)
    index_ok = (data_path / "index.json").is_file()
    scanner = check_scanner(resolve_code_graph_bin(data_path))
    ready = bool(index_ok and scanner["ksm_sfp"])
    return {
        "data_dir": str(data_path),
        "index_json": index_ok,
        "fingerprints": count_fingerprints(data_path),
        "scanner": scanner,
        "ready": ready,
    }


def render_doctor_text(status: dict[str, Any]) -> str:
    scanner = status["scanner"]
    index_str = "ok" if status["index_json"] else "missing (hint: run `ksm update`)"
    if not scanner["path"]:
        scanner_str = "not found (hint: run `ksm setup`)"
        check_str = "failed (hint: run `ksm setup`)"
    elif not scanner["ksm_sfp"]:
        scanner_str = scanner["path"]
        check_str = "failed (hint: run `ksm setup`)"
    else:
        scanner_str = scanner["path"]
        check_str = "ksm-sfp/1 ok"

    lines = [
        f"data dir:       {status['data_dir']}",
        f"index.json:     {index_str}",
        f"fingerprints:   {status['fingerprints']}",
        f"scanner:        {scanner_str}",
        f"scanner check:  {check_str}",
        f"ready:          {'yes' if status['ready'] else 'no'}",
    ]
    return "\n".join(lines)


def cmd_setup(args) -> int:
    """`ksm setup`: install the code-graph scanner binary."""
    from_cargo = getattr(args, "from_cargo", False)
    if not from_cargo and not supported_platform():
        sys.stderr.write(
            "Error: `ksm setup` prebuilt binary supports Linux x86_64 only "
            f"(this is {platform.system()} {platform.machine()}).\n"
            "Install code-graph from source instead:\n"
            f"{cargo_command()}\n"
        )
        return 2
    try:
        bin_path = run_setup(
            from_cargo=from_cargo,
            data_dir=getattr(args, "data_dir", None),
        )
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2
    print(bin_path)
    return 0


def cmd_doctor(args) -> int:
    """`ksm doctor`: print data/scanner readiness; exit 0 when ready."""
    status = doctor_status(getattr(args, "data_dir", None))
    if getattr(args, "json", False):
        print(json.dumps(status, indent=2))
    else:
        print(render_doctor_text(status))
    return 0 if status["ready"] else 1
