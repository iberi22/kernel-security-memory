"""Unit tests for `ksm setup`, `ksm doctor`, and code-graph scanner resolution."""

import argparse
import hashlib
import io
import json
import os
import platform
import stat
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ksm.cli import main
from ksm.scanner import (
    CODE_GRAPH_REV,
    XAVIER_REPO,
    code_graph_bin_dir,
    resolve_code_graph_bin,
    verify_code_graph_bin,
)
from ksm.setup import (
    TARBALL,
    cargo_command,
    check_scanner,
    cmd_doctor,
    cmd_setup,
    count_fingerprints,
    doctor_status,
    download_url,
    extract_code_graph_member,
    install_prebuilt,
    release_tag,
    render_doctor_text,
    run_setup,
    supported_platform,
    verify_file_sha256,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _make_tarball(target_path: Path, members: dict[str, bytes], member_types: dict[str, int] = None) -> Path:
    """Create a tarball with specified members for testing extraction safety."""
    if member_types is None:
        member_types = {}
    with tarfile.open(target_path, "w:gz") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = 0
            ti.mode = 0o755
            ti.type = member_types.get(name, tarfile.REGTYPE)
            if ti.type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                ti.linkname = "some/target"
            tf.addfile(ti, io.BytesIO(data))
    return target_path


class TestTagAndWorkflowConsistency(unittest.TestCase):
    """Test release tag computation and CODE_GRAPH_REV consistency with CI workflows."""

    def test_tag_computation(self):
        tag = release_tag()
        self.assertEqual(tag, f"code-graph-{CODE_GRAPH_REV[:8]}")
        self.assertTrue(tag.startswith("code-graph-"))
        self.assertEqual(len(tag), len("code-graph-") + 8)

        url = download_url(TARBALL)
        self.assertEqual(
            url,
            f"https://github.com/iberi22/kernel-security-memory/releases/download/{tag}/{TARBALL}",
        )

    def test_cargo_command(self):
        cmd = cargo_command()
        self.assertIn("cargo install --locked --git", cmd)
        self.assertIn(XAVIER_REPO, cmd)
        self.assertIn(CODE_GRAPH_REV, cmd)
        self.assertIn("code-graph", cmd)

    def test_code_graph_rev_matches_workflow(self):
        workflow_file = REPO_ROOT / ".github" / "workflows" / "fingerprints.yml"
        self.assertTrue(workflow_file.is_file(), f"Workflow not found at {workflow_file}")

        workflow_content = workflow_file.read_text(encoding="utf-8")
        xavier_rev = None
        for line in workflow_content.splitlines():
            line = line.strip()
            if line.startswith("XAVIER_REV:"):
                xavier_rev = line.split(":", 1)[1].strip()
                break

        self.assertIsNotNone(xavier_rev, "XAVIER_REV definition not found in fingerprints.yml")
        self.assertEqual(
            CODE_GRAPH_REV,
            xavier_rev,
            f"CODE_GRAPH_REV ({CODE_GRAPH_REV}) must match XAVIER_REV in fingerprints.yml ({xavier_rev})",
        )
        self.assertEqual(len(CODE_GRAPH_REV), 40, "CODE_GRAPH_REV must be a 40-character hex commit SHA")
        # Ensure it's valid hex
        int(CODE_GRAPH_REV, 16)


class TestSha256Verification(unittest.TestCase):
    """Test checksum verification and rejection on mismatch."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sha256_match_passes(self):
        file_path = self.tmp_dir / "sample.bin"
        data = b"hello binary content"
        file_path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        verify_file_sha256(file_path, digest)
        verify_file_sha256(file_path, digest.upper())

    def test_sha256_mismatch_refused(self):
        file_path = self.tmp_dir / "sample.bin"
        file_path.write_bytes(b"hello binary content")
        bad_digest = "0" * 64
        with self.assertRaises(ValueError) as ctx:
            verify_file_sha256(file_path, bad_digest)
        self.assertIn("mismatch", str(ctx.exception).lower())


class TestTarSafetyAndExtraction(unittest.TestCase):
    """Test safe extraction of code-graph member and refusal of unsafe members."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_safe_tar_member_extracted(self):
        tarball = self.tmp_dir / "good.tar.gz"
        payload = b"#!/bin/sh\necho ok\n"
        _make_tarball(tarball, {"code-graph": payload})

        install_dir = self.tmp_dir / "bin"
        installed = extract_code_graph_member(tarball, install_dir)
        self.assertEqual(installed, install_dir / "code-graph")
        self.assertTrue(installed.is_file())
        self.assertEqual(installed.read_bytes(), payload)
        self.assertTrue(os.access(installed, os.X_OK))
        self.assertEqual(installed.stat().st_mode & 0o755, 0o755)

    def test_missing_code_graph_member_refused(self):
        tarball = self.tmp_dir / "missing.tar.gz"
        _make_tarball(tarball, {"other-binary": b"some binary"})

        install_dir = self.tmp_dir / "bin"
        with self.assertRaises(ValueError) as ctx:
            extract_code_graph_member(tarball, install_dir)
        self.assertIn("has no 'code-graph' member", str(ctx.exception))

    def test_unsafe_tar_member_symlink_refused(self):
        tarball = self.tmp_dir / "symlink.tar.gz"
        _make_tarball(
            tarball,
            {"code-graph": b""},
            member_types={"code-graph": tarfile.SYMTYPE},
        )
        install_dir = self.tmp_dir / "bin"
        with self.assertRaises(ValueError) as ctx:
            extract_code_graph_member(tarball, install_dir)
        self.assertIn("unsafe", str(ctx.exception).lower())

    def test_unsafe_tar_member_hardlink_refused(self):
        tarball = self.tmp_dir / "hardlink.tar.gz"
        _make_tarball(
            tarball,
            {"code-graph": b""},
            member_types={"code-graph": tarfile.LNKTYPE},
        )
        install_dir = self.tmp_dir / "bin"
        with self.assertRaises(ValueError) as ctx:
            extract_code_graph_member(tarball, install_dir)
        self.assertIn("unsafe", str(ctx.exception).lower())

    def test_unsafe_tar_member_absolute_path_refused(self):
        tarball = self.tmp_dir / "abspath.tar.gz"
        _make_tarball(tarball, {"/etc/passwd": b"root:x", "code-graph": b"bin"})
        install_dir = self.tmp_dir / "bin"
        with self.assertRaises(ValueError) as ctx:
            extract_code_graph_member(tarball, install_dir)
        self.assertIn("unsafe", str(ctx.exception).lower())

    def test_unsafe_tar_member_parent_path_refused(self):
        tarball = self.tmp_dir / "parent.tar.gz"
        _make_tarball(tarball, {"../outside": b"evil", "code-graph": b"bin"})
        install_dir = self.tmp_dir / "bin"
        with self.assertRaises(ValueError) as ctx:
            extract_code_graph_member(tarball, install_dir)
        self.assertIn("unsafe", str(ctx.exception).lower())

    def test_unsafe_tar_member_nested_path_refused(self):
        tarball = self.tmp_dir / "nested.tar.gz"
        _make_tarball(tarball, {"bin/code-graph": b"bin"})
        install_dir = self.tmp_dir / "bin"
        with self.assertRaises(ValueError) as ctx:
            extract_code_graph_member(tarball, install_dir)
        self.assertIn("unsafe", str(ctx.exception).lower())


class TestInstallPathAndMode(unittest.TestCase):
    """Test prebuilt download, checksum check, install path and chmod 755."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_install_prebuilt_with_mocked_download(self):
        payload = b"ELF-binary-content-simulated"
        tarball_path = self.tmp_dir / "created.tar.gz"
        _make_tarball(tarball_path, {"code-graph": payload})
        tarball_bytes = tarball_path.read_bytes()
        sha_digest = hashlib.sha256(tarball_bytes).hexdigest()

        def fake_download(url: str, dest: Path) -> Path:
            if url.endswith(".sha256"):
                dest.write_text(f"{sha_digest}  {TARBALL}\n", encoding="utf-8")
            else:
                dest.write_bytes(tarball_bytes)
            return dest

        installed = install_prebuilt(self.tmp_dir, download=fake_download)
        expected_path = self.tmp_dir / "bin" / "code-graph"
        self.assertEqual(installed, expected_path)
        self.assertTrue(installed.is_file())
        self.assertEqual(installed.read_bytes(), payload)
        self.assertEqual(installed.stat().st_mode & 0o755, 0o755)

    def test_run_setup_delegates_to_install_prebuilt(self):
        payload = b"ELF-content"
        tarball_path = self.tmp_dir / "created.tar.gz"
        _make_tarball(tarball_path, {"code-graph": payload})
        tarball_bytes = tarball_path.read_bytes()
        sha_digest = hashlib.sha256(tarball_bytes).hexdigest()

        def fake_download(url: str, dest: Path) -> Path:
            if url.endswith(".sha256"):
                dest.write_text(f"{sha_digest}\n", encoding="utf-8")
            else:
                dest.write_bytes(tarball_bytes)
            return dest

        installed = run_setup(data_dir=self.tmp_dir, download=fake_download)
        self.assertEqual(installed, self.tmp_dir / "bin" / "code-graph")
        self.assertTrue(installed.is_file())
        self.assertEqual(installed.stat().st_mode & 0o755, 0o755)


class TestPlatformSupport(unittest.TestCase):
    """Test platform detection and non-Linux error message."""

    def test_supported_platform_matrix(self):
        self.assertTrue(supported_platform("Linux", "x86_64"))
        self.assertFalse(supported_platform("Linux", "aarch64"))
        self.assertFalse(supported_platform("Linux", "armv7l"))
        self.assertFalse(supported_platform("Darwin", "x86_64"))
        self.assertFalse(supported_platform("Darwin", "arm64"))
        self.assertFalse(supported_platform("Windows", "AMD64"))

    def test_non_linux_message_and_exit_code(self):
        args = argparse.Namespace(from_cargo=False, data_dir=None)
        with patch("ksm.setup.platform.system", return_value="Darwin"), \
             patch("ksm.setup.platform.machine", return_value="arm64"):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                code = cmd_setup(args)

            self.assertEqual(code, 2)
            msg = err_buf.getvalue()
            self.assertIn("Linux x86_64 only", msg)
            self.assertIn("Darwin arm64", msg)
            self.assertIn(cargo_command(), msg)

    def test_cli_setup_non_linux(self):
        with patch("ksm.setup.platform.system", return_value="Darwin"), \
             patch("ksm.setup.platform.machine", return_value="arm64"):
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                code = main(["setup"])
            self.assertEqual(code, 2)
            self.assertIn("Linux x86_64 only", err_buf.getvalue())
            self.assertIn(cargo_command(), err_buf.getvalue())


class TestDoctorReadiness(unittest.TestCase):
    """Test `ksm doctor` network-free status reporting."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_doctor_without_data_and_without_scanner(self):
        with patch.dict(os.environ, {"KSM_CODE_GRAPH": "", "PATH": ""}):
            status = doctor_status(self.tmp_dir)
            self.assertFalse(status["ready"])
            self.assertFalse(status["index_json"])
            self.assertEqual(status["fingerprints"], 0)
            self.assertFalse(status["scanner"]["ksm_sfp"])
            self.assertIsNone(status["scanner"]["path"])

            args = argparse.Namespace(data_dir=str(self.tmp_dir), json=False)
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                code = cmd_doctor(args)
            self.assertEqual(code, 1)
            text = out_buf.getvalue()
            self.assertIn("missing (hint: run `ksm update`)", text)
            self.assertIn("failed (hint: run `ksm setup`)", text)
            self.assertIn("ready:          no", text)

    def test_doctor_with_data_without_scanner(self):
        # Create index.json
        (self.tmp_dir / "index.json").write_text("{}", encoding="utf-8")
        with patch.dict(os.environ, {"KSM_CODE_GRAPH": "", "PATH": ""}):
            status = doctor_status(self.tmp_dir)
            self.assertFalse(status["ready"])
            self.assertTrue(status["index_json"])
            self.assertFalse(status["scanner"]["ksm_sfp"])

            args = argparse.Namespace(data_dir=str(self.tmp_dir), json=False)
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                code = cmd_doctor(args)
            self.assertEqual(code, 1)
            text = out_buf.getvalue()
            self.assertIn("index.json:     ok", text)
            self.assertIn("failed (hint: run `ksm setup`)", text)
            self.assertIn("ready:          no", text)

    def test_doctor_ready_with_data_and_fake_scanner(self):
        # Create index.json
        (self.tmp_dir / "index.json").write_text("{}", encoding="utf-8")

        # Create fake code-graph scanner binary
        fake_bin = self.tmp_dir / "code-graph"
        script = """#!/usr/bin/env python3
import json
import sys
if len(sys.argv) >= 3 and sys.argv[1] == "fingerprint":
    print(json.dumps({"schema": "ksm-sfp/1", "coverage": "OK"}))
"""
        fake_bin.write_text(script, encoding="utf-8")
        fake_bin.chmod(0o755)

        with patch.dict(os.environ, {"KSM_CODE_GRAPH": str(fake_bin)}):
            status = doctor_status(self.tmp_dir)
            self.assertTrue(status["ready"])
            self.assertTrue(status["index_json"])
            self.assertTrue(status["scanner"]["ksm_sfp"])
            self.assertEqual(status["scanner"]["path"], str(fake_bin))

            args = argparse.Namespace(data_dir=str(self.tmp_dir), json=False)
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                code = cmd_doctor(args)
            self.assertEqual(code, 0)
            text = out_buf.getvalue()
            self.assertIn("index.json:     ok", text)
            self.assertIn("scanner check:  ksm-sfp/1 ok", text)
            self.assertIn("ready:          yes", text)

    def test_doctor_json_mode(self):
        (self.tmp_dir / "index.json").write_text("{}", encoding="utf-8")
        args = argparse.Namespace(data_dir=str(self.tmp_dir), json=True)
        out_buf = io.StringIO()
        with redirect_stdout(out_buf):
            cmd_doctor(args)
        data = json.loads(out_buf.getvalue())
        self.assertIn("data_dir", data)
        self.assertIn("index_json", data)
        self.assertIn("fingerprints", data)
        self.assertIn("scanner", data)
        self.assertIn("ready", data)

    def test_count_fingerprints(self):
        fp_dir = self.tmp_dir / "fingerprints"
        fp_dir.mkdir()
        (fp_dir / "a.json").write_text("{}", encoding="utf-8")
        (fp_dir / "b.json").write_text("{}", encoding="utf-8")
        (fp_dir / "ignored.txt").write_text("{}", encoding="utf-8")
        self.assertEqual(count_fingerprints(self.tmp_dir), 2)


class TestCliIntegration(unittest.TestCase):
    """Test CLI subcommand dispatch for setup and doctor."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cli_doctor_subcommand(self):
        out_buf = io.StringIO()
        with redirect_stdout(out_buf):
            code = main(["doctor", "--data-dir", str(self.tmp_dir), "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out_buf.getvalue())
        self.assertFalse(data["ready"])

    def test_cli_setup_subcommand_success(self):
        payload = b"ELF-test"
        tarball_path = self.tmp_dir / "created.tar.gz"
        _make_tarball(tarball_path, {"code-graph": payload})
        tarball_bytes = tarball_path.read_bytes()
        sha_digest = hashlib.sha256(tarball_bytes).hexdigest()

        def fake_download(url: str, dest: Path) -> Path:
            if url.endswith(".sha256"):
                dest.write_text(f"{sha_digest}\n", encoding="utf-8")
            else:
                dest.write_bytes(tarball_bytes)
            return dest

        with patch("ksm.setup.download_file", side_effect=fake_download), \
             patch("ksm.setup.supported_platform", return_value=True):
            out_buf = io.StringIO()
            with redirect_stdout(out_buf):
                code = main(["setup", "--data-dir", str(self.tmp_dir)])
            self.assertEqual(code, 0)
            installed_path = Path(out_buf.getvalue().strip())
            self.assertEqual(installed_path, self.tmp_dir / "bin" / "code-graph")
            self.assertTrue(installed_path.is_file())


if __name__ == "__main__":
    unittest.main()
