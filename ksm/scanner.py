"""code-graph scanner: pinned revision, install location, binary resolution."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Union

from ksm.data import _user_data_dir

# Xavier commit whose `code-graph fingerprint` produces ksm-sfp/1. Mirrors
# XAVIER_REV in .github/workflows/fingerprints.yml; a unit test fails if the
# two values ever differ.
CODE_GRAPH_REV = "229aa969aaac293ea9a4dee6f3999d19b178b4ce"

XAVIER_REPO = "https://github.com/iberi22/xavier"


def code_graph_bin_dir() -> Path:
    """Where `ksm setup` installs the scanner: <user data dir>/bin."""
    return _user_data_dir() / "bin"


def resolve_code_graph_bin(data_dir: Optional[Union[str, Path]] = None) -> Optional[str]:
    """Resolve the code-graph binary: $KSM_CODE_GRAPH, the `ksm setup` install,
    then `code-graph` on PATH."""
    env_bin = os.environ.get("KSM_CODE_GRAPH")
    if env_bin and env_bin.strip():
        return env_bin
    if data_dir is not None:
        custom_bin = Path(data_dir).expanduser().resolve() / "bin" / "code-graph"
        if custom_bin.is_file():
            return str(custom_bin)
    installed = code_graph_bin_dir() / "code-graph"
    if installed.is_file():
        return str(installed)
    return shutil.which("code-graph")


def verify_code_graph_bin(bin_path: str) -> bool:
    """True when the binary runs `fingerprint --help` successfully.

    An old code-graph without the `fingerprint` subcommand exits non-zero here;
    a wrong binary that exits 0 anyway is still caught by `ksm scan`'s
    ksm-sfp/1 output check.
    """
    try:
        res = subprocess.run(
            [bin_path, "fingerprint", "--help"],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0
