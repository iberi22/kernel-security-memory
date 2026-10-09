#!/usr/bin/env python3
"""Tests for Defensive Security Specialist Auditor."""

import json
import tempfile
from pathlib import Path
from unittest import TestCase, main

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from defensive_auditor import (
    SECURITY_RULES,
    audit_path,
    build_evidence_chain,
    load_pattern_clusters,
    scan_content,
)


class TestDefensiveAuditor(TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_rules_structure(self):
        self.assertGreater(len(SECURITY_RULES), 0)
        for rule in SECURITY_RULES:
            self.assertIn("id", rule)
            self.assertIn("cwe_id", rule)
            self.assertIn("severity", rule)
            self.assertIn("pattern", rule)
            self.assertIn("lesson", rule)

    def test_detects_unbounded_copy(self):
        bad_code = """
        void process_input(char *src) {
            char buf[64];
            strcpy(buf, src);
        }
        """
        findings = scan_content(bad_code, "test.c")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["cwe_id"], "CWE-120")
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("strcpy", f["snippet"])

    def test_detects_command_injection(self):
        bad_code = """
        def run_cmd(user_arg):
            subprocess.call(f"ls {user_arg}", shell=True)
        """
        findings = scan_content(bad_code, "script.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")

    def test_clean_code_passes(self):
        clean_code = """
        void safe_copy(const char *src, size_t maxlen) {
            char buf[64];
            if (strlen(src) < sizeof(buf)) {
                strncpy(buf, src, sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = '\\0';
            }
        }
        """
        findings = scan_content(clean_code, "safe.c")
        self.assertEqual(len(findings), 0)

    def test_evidence_chain_and_hashing(self):
        files = ["safe1.c", "safe2.c"]
        evidence = build_evidence_chain("sample_project", files, [])
        self.assertEqual(evidence["audit"]["verdict"], "PASS")
        self.assertEqual(len(evidence["evidence_chain_hash"]), 64)
        
        # Verify hash integrity
        payload = evidence["audit"]
        serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        import hashlib
        expected_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self.assertEqual(evidence["evidence_chain_hash"], expected_hash)

    def test_audit_real_swal_files(self):
        # Audit kernel-security-memory scripts
        scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
        files_audited, findings = audit_path(str(scripts_dir))
        self.assertGreater(len(files_audited), 5)
        # Ensure scripts pass without CRITICAL command injection
        critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
        self.assertEqual(len(critical_findings), 0)


if __name__ == "__main__":
    main()
