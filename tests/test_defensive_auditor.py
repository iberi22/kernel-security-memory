#!/usr/bin/env python3
"""Tests for Defensive Security Specialist Auditor and Quality Gate."""

import json
import os
import re
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import TestCase, main

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from defensive_auditor import (
    SECURITY_RULES,
    audit_path,
    build_evidence_chain,
    compute_evidence_hash,
    load_pattern_clusters,
    normalize_findings,
    scan_content,
)
from quality_gate import (
    evaluate_quality_gate,
    verify_evidence_integrity,
    verify_reproducible_runs,
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
            self.assertIn("language", rule)
            self.assertIn("languages", rule)
            self.assertIsInstance(rule["languages"], list)

    # -------------------------------------------------------------------------
    # CWE-120: Buffer Copy without Checking Size (C/C++)
    # -------------------------------------------------------------------------
    def test_detects_unbounded_copy_strcpy(self):
        code = """
        void process_input(char *src) {
            char buf[64];
            strcpy(buf, src);
        }
        """
        findings = scan_content(code, "test.c")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["cwe_id"], "CWE-120")
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("strcpy", f["snippet"])

    def test_detects_unbounded_copy_strcat(self):
        code = """
        void append_data(char *src) {
            char buf[128] = "prefix_";
            strcat(buf, src);
        }
        """
        findings = scan_content(code, "test.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-120")
        self.assertIn("strcat", findings[0]["snippet"])

    def test_detects_unbounded_copy_gets(self):
        code = """
        void read_line(void) {
            char line[256];
            gets(line);
        }
        """
        findings = scan_content(code, "test.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-120")
        self.assertIn("gets", findings[0]["snippet"])

    def test_detects_unbounded_copy_sprintf(self):
        code = """
        void format_msg(const char *name) {
            char out[128];
            sprintf(out, "Hello %s", name);
        }
        """
        findings = scan_content(code, "test.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-120")
        self.assertIn("sprintf", findings[0]["snippet"])

    def test_clean_bounded_copy_passes(self):
        clean_code = """
        void safe_copy(const char *src, size_t maxlen) {
            char buf[64];
            if (strlen(src) < sizeof(buf)) {
                strncpy(buf, src, sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = '\\0';
            }
            snprintf(buf, sizeof(buf), "%s", src);
        }
        """
        findings = scan_content(clean_code, "safe.c")
        self.assertEqual(len(findings), 0)

    # -------------------------------------------------------------------------
    # CWE-416: Use-After-Free (C and Rust)
    # -------------------------------------------------------------------------
    def test_detects_use_after_free_c(self):
        code = """
        void teardown(struct session *s) {
            free(s);
            s->active = 0;
        }
        """
        findings = scan_content(code, "session.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-416")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_safe_free_with_nullification_c_passes(self):
        code = """
        void teardown(struct session *s) {
            free(s);
            s = NULL;
        }
        """
        findings = scan_content(code, "session.c")
        self.assertEqual(len(findings), 0)

    def test_detects_use_after_free_rust(self):
        code = """
        unsafe fn destroy_and_use(raw_ptr: *mut u32, layout: Layout) {
            dealloc(raw_ptr, layout);
            *raw_ptr = 42;
        }
        """
        findings = scan_content(code, "lib.rs")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-416")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_detects_drop_after_free_rust(self):
        code = """
        fn access_dropped(resource: Resource) {
            drop(resource);
            resource.process();
        }
        """
        findings = scan_content(code, "main.rs")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-416")

    # -------------------------------------------------------------------------
    # CWE-78: Command Injection (C, Python, and Shell)
    # -------------------------------------------------------------------------
    def test_detects_command_injection_c_system(self):
        code = """
        void run_user_cmd(char *user_input) {
            system(user_input);
        }
        """
        findings = scan_content(code, "exec.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_detects_command_injection_c_popen(self):
        code = """
        FILE *run_query(char *query) {
            return popen(query, "r");
        }
        """
        findings = scan_content(code, "query.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_detects_command_injection_c_execl_sh(self):
        code = """
        void spawn(char *cmd) {
            execl("/bin/sh", "sh", "-c", cmd, NULL);
        }
        """
        findings = scan_content(code, "spawn.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")

    def test_safe_system_constant_c_passes(self):
        code = """
        void init(void) {
            system("sync");
        }
        """
        findings = scan_content(code, "init.c")
        self.assertEqual(len(findings), 0)

    def test_detects_command_injection_python_subprocess(self):
        code = """
        def run_cmd(user_arg):
            subprocess.call(f"ls {user_arg}", shell=True)
        """
        findings = scan_content(code, "script.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")

    def test_detects_command_injection_python_os_system(self):
        code = """
        def execute(cmd):
            os.system(cmd)
        """
        findings = scan_content(code, "script.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")

    def test_detects_command_injection_python_exec(self):
        code = """
        def run_dyn(user_code):
            exec(user_code)
        """
        findings = scan_content(code, "script.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")

    def test_detects_command_injection_shell_eval(self):
        code = """
        #!/bin/bash
        USER_INPUT="$1"
        eval "$USER_INPUT"
        """
        findings = scan_content(code, "deploy.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_detects_command_injection_shell_sh_c(self):
        code = """
        #!/bin/sh
        sh -c "$DYNAMIC_CMD"
        """
        findings = scan_content(code, "runner.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")

    def test_detects_command_injection_shell_exec_var(self):
        code = """
        #!/bin/sh
        exec "$RUN_TARGET"
        """
        findings = scan_content(code, "entry.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-78")

    # -------------------------------------------------------------------------
    # CWE-190: Integer Overflow (C and Rust)
    # -------------------------------------------------------------------------
    def test_detects_integer_overflow_c_malloc(self):
        code = """
        int *alloc_table(size_t count, size_t size) {
            return (int *)malloc(count * size);
        }
        """
        findings = scan_content(code, "table.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-190")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_detects_integer_overflow_c_kmalloc(self):
        code = """
        void *alloc_net(int header_len, int body_len) {
            return kmalloc(header_len + body_len, GFP_KERNEL);
        }
        """
        findings = scan_content(code, "net.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-190")

    def test_detects_integer_overflow_rust_capacity(self):
        code = """
        fn allocate_buffer(count: usize, elem_size: usize) -> Vec<u8> {
            Vec::with_capacity(count * elem_size)
        }
        """
        findings = scan_content(code, "alloc.rs")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-190")

    # -------------------------------------------------------------------------
    # CWE-476: NULL Pointer Dereference (C and Rust)
    # -------------------------------------------------------------------------
    def test_detects_null_dereference_c(self):
        code = """
        void setup_node(void) {
            struct node *n = malloc(sizeof(struct node));
            n->val = 42;
        }
        """
        findings = scan_content(code, "node.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-476")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_safe_null_check_c_passes(self):
        code = """
        void setup_node(void) {
            struct node *n = malloc(sizeof(struct node));
            if (!n) return;
            n->val = 42;
        }
        """
        findings = scan_content(code, "node.c")
        self.assertEqual(len(findings), 0)

    def test_detects_null_dereference_rust(self):
        code = """
        fn direct_deref(addr: usize) -> u32 {
            let ptr = addr as *mut u32;
            unsafe { *ptr }
        }
        """
        findings = scan_content(code, "unsafe.rs")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-476")

    def test_safe_null_check_rust_passes(self):
        code = """
        fn safe_deref(addr: usize) -> u32 {
            let ptr = addr as *mut u32;
            if !ptr.is_null() {
                unsafe { *ptr }
            } else {
                0
            }
        }
        """
        findings = scan_content(code, "unsafe.rs")
        self.assertEqual(len(findings), 0)

    # -------------------------------------------------------------------------
    # CWE-362: Race Condition / Concurrency / TOCTOU (C, Python, Shell)
    # -------------------------------------------------------------------------
    def test_detects_toctou_c_access_open(self):
        code = """
        int open_user_file(const char *path) {
            if (access(path, R_OK) == 0) {
                return open(path, O_RDONLY);
            }
            return -1;
        }
        """
        findings = scan_content(code, "fs.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-362")

    def test_detects_spin_unlock_relock_c(self):
        code = """
        void update(void) {
            spin_unlock(&lock);
            spin_lock(&lock);
        }
        """
        findings = scan_content(code, "sync.c")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-362")

    def test_detects_toctou_python(self):
        code = """
        def read_file(filepath):
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    return f.read()
        """
        findings = scan_content(code, "io_helper.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-362")

    def test_detects_toctou_shell(self):
        code = """
        #!/bin/bash
        if [ -f "$TARGET_PATH" ]; then
            rm "$TARGET_PATH"
        fi
        """
        findings = scan_content(code, "cleanup.sh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe_id"], "CWE-362")

    # -------------------------------------------------------------------------
    # D1: Evidence Chain Hash Reproducibility and Determinism
    # -------------------------------------------------------------------------
    def test_evidence_chain_and_hashing(self):
        files = ["safe1.c", "safe2.c"]
        evidence = build_evidence_chain("sample_project", files, [])
        self.assertEqual(evidence["audit"]["verdict"], "PASS")
        self.assertEqual(len(evidence["evidence_chain_hash"]), 64)

        # Verify hash integrity against deterministic payload
        payload = evidence["audit"]["deterministic_payload"]
        serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        import hashlib
        expected_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self.assertEqual(evidence["evidence_chain_hash"], expected_hash)

    def test_evidence_chain_hash_identical_across_time(self):
        # Real files: the digests must be stable across runs and the payload must
        # carry them, so the hash is bound to the audited tree state.
        target = self.base_dir / "src"
        target.mkdir()
        (target / "a.c").write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        (target / "b.c").write_text("int sub(int a, int b) { return a - b; }\n", encoding="utf-8")

        import hashlib

        files, findings, digests = audit_path(str(target))
        self.assertEqual(len(digests), 2)
        for path, digest in digests.items():
            self.assertEqual(
                digest,
                hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                "file_digests must hold the raw-byte SHA-256 of every audited file",
            )

        ev1 = build_evidence_chain(str(target), files, findings, file_digests=digests)
        self.assertEqual(ev1["audit"]["file_digests"], dict(sorted(digests.items())))

        time.sleep(0.01)

        files2, findings2, digests2 = audit_path(str(target))
        ev2 = build_evidence_chain(str(target), files2, findings2, file_digests=digests2)
        hash2 = ev2["evidence_chain_hash"]

        self.assertEqual(hash2, ev1["evidence_chain_hash"], "evidence_chain_hash must be strictly identical across runs")
        # Notice that timestamps differ, but hashes remain strictly identical
        self.assertNotEqual(ev1["audit"]["timestamp"], ev2["audit"]["timestamp"])

    def test_evidence_hash_changes_when_audited_content_changes(self):
        # Two trees with identical paths and identical (empty) findings must not
        # collide: the hash has to identify the audited tree state.
        target = self.base_dir / "src"
        target.mkdir()
        (target / "a.c").write_text("int x = 1;\n", encoding="utf-8")

        files, findings, digests = audit_path(str(target))
        before = build_evidence_chain(str(target), files, findings, file_digests=digests)
        (target / "a.c").write_text("int x = 2;\n", encoding="utf-8")
        files2, findings2, digests2 = audit_path(str(target))
        after = build_evidence_chain(str(target), files2, findings2, file_digests=digests2)

        self.assertNotEqual(
            before["evidence_chain_hash"],
            after["evidence_chain_hash"],
            "a one-byte change in audited content must alter the evidence_chain_hash",
        )
        self.assertNotEqual(digests, digests2)
        self.assertEqual(before["audit"]["verdict"], after["audit"]["verdict"])
        self.assertEqual(before["audit"]["findings"], after["audit"]["findings"])

    def test_evidence_integrity_detects_post_audit_content_change(self):
        target = self.base_dir / "src"
        target.mkdir()
        (target / "a.c").write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        files, findings, digests = audit_path(str(target))
        evidence = build_evidence_chain(str(target), files, findings, file_digests=digests)

        valid, _ = verify_evidence_integrity(evidence)
        self.assertTrue(valid)

        # Re-audit after the code changed: the cited hash must not still validate.
        (target / "a.c").write_text("int add(int a, int b) { return a * b; }\n", encoding="utf-8")
        files2, findings2, digests2 = audit_path(str(target))
        stale = build_evidence_chain(str(target), files2, findings2, file_digests=digests2)
        stale["evidence_chain_hash"] = evidence["evidence_chain_hash"]
        valid, msg = verify_evidence_integrity(stale)
        self.assertFalse(valid, "evidence citing a hash from older content must be rejected")
        self.assertIn("Hash mismatch", msg)

    # -------------------------------------------------------------------------
    # D3: Incomplete Verdict on Unreadable Files and Corrupt Clusters
    # -------------------------------------------------------------------------
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root bypasses file permissions and can read mode-000 files")
    def test_unreadable_file_produces_incomplete_verdict(self):
        # Create unreadable file
        target_file = self.base_dir / "unreadable.c"
        target_file.write_text("int x = 1;\n", encoding="utf-8")
        target_file.chmod(0o000)

        try:
            files_audited, findings, _digests = audit_path(str(self.base_dir))
            evidence = build_evidence_chain(str(self.base_dir), files_audited, findings)

            self.assertEqual(
                evidence["audit"]["verdict"],
                "INCOMPLETE",
                "Unreadable files must produce INCOMPLETE verdict, never a silent PASS",
            )
            incomplete_findings = [f for f in findings if f.get("severity") == "INCOMPLETE"]
            self.assertGreaterEqual(len(incomplete_findings), 1)
        finally:
            target_file.chmod(0o644)

    def test_corrupt_clusters_json_raises_clear_error(self):
        bad_json_file = self.base_dir / "corrupt_clusters.json"
        bad_json_file.write_text("{ unclosed json: ...", encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            load_pattern_clusters(str(bad_json_file))
        self.assertIn("Corrupt pattern clusters JSON", str(ctx.exception))

    # -------------------------------------------------------------------------
    # E3: Quality Gate Verification for Xavier Publication
    # -------------------------------------------------------------------------
    def test_quality_gate_authorizes_clean_repo(self):
        # Create clean C file
        clean_file = self.base_dir / "clean.c"
        clean_file.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

        result = evaluate_quality_gate(target=str(self.base_dir), reproducibility_runs=2)
        self.assertTrue(result["authorized"])
        self.assertEqual(result["status"], "AUTHORIZED")
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["publication_prefix"], "ksm-guardrail/")
        self.assertEqual(len(result["evidence_chain_hash"]), 64)

    def test_quality_gate_rejects_vulnerable_target(self):
        vuln_file = self.base_dir / "vuln.py"
        vuln_file.write_text("import os; os.system(user_cmd)\n", encoding="utf-8")

        result = evaluate_quality_gate(target=str(self.base_dir), reproducibility_runs=2)
        self.assertFalse(result["authorized"])
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["verdict"], "FAIL")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root bypasses file permissions and can read mode-000 files")
    def test_quality_gate_rejects_incomplete_environment(self):
        broken_file = self.base_dir / "locked.py"
        broken_file.write_text("print('hello')\n", encoding="utf-8")
        broken_file.chmod(0o000)

        try:
            result = evaluate_quality_gate(target=str(self.base_dir), reproducibility_runs=2)
            self.assertFalse(result["authorized"])
            self.assertEqual(result["status"], "REJECTED")
            self.assertEqual(result["verdict"], "INCOMPLETE")
        finally:
            broken_file.chmod(0o644)

    def test_verify_evidence_integrity(self):
        files = ["file1.c"]
        evidence = build_evidence_chain("my_pkg", files, [])
        valid, msg = verify_evidence_integrity(evidence)
        self.assertTrue(valid)

        # Tamper with hash
        tampered = json.loads(json.dumps(evidence))
        tampered["evidence_chain_hash"] = "0" * 64
        valid, msg = verify_evidence_integrity(tampered)
        self.assertFalse(valid)
        self.assertIn("Hash mismatch", msg)

    # -------------------------------------------------------------------------
    # D4: Extension/Language Coherence Between Traversal and Rule Selection
    # -------------------------------------------------------------------------
    def test_javascript_and_typescript_are_not_given_c_rules(self):
        # .js/.ts have no language in _detect_language(); traversing them with the
        # C rules produced false HIGH findings that flipped the verdict to FAIL.
        target = self.base_dir / "web"
        target.mkdir()
        (target / "widget.js").write_text('const s = "a";\nfunction f(src) { strcpy(buf, src); free(p); }\n', encoding="utf-8")
        (target / "widget.ts").write_text('const s = "a";\nfunction f(src) { strcpy(buf, src); free(p); }\n', encoding="utf-8")
        files, findings, digests = audit_path(str(target))
        self.assertEqual(files, [], "extensions without a language mapping must not be audited")
        self.assertEqual(findings, [])
        self.assertEqual(digests, {})
        self.assertEqual(build_evidence_chain(str(target), files, findings)["audit"]["verdict"], "PASS")

    def test_same_c_pattern_in_a_c_file_still_fails(self):
        # Guard against the fix above simply disabling the C rules: the very same
        # pattern in a .c file must still produce a HIGH finding and a FAIL verdict.
        target = self.base_dir / "native"
        target.mkdir()
        (target / "widget.c").write_text('void f(char *src) { char buf[8]; strcpy(buf, src); free(p); }\n', encoding="utf-8")
        files, findings, digests = audit_path(str(target))
        self.assertEqual(len(files), 1)
        self.assertEqual(len(digests), 1)
        severities = {f["severity"] for f in findings}
        self.assertIn("HIGH", severities)
        self.assertEqual(build_evidence_chain(str(target), files, findings)["audit"]["verdict"], "FAIL")

    def test_cpp_extensions_detected_as_c_are_traversed(self):
        # .hpp/.cxx are mapped to "c" by _detect_language, so directory
        # traversal has to include them.
        target = self.base_dir / "native"
        target.mkdir()
        (target / "impl.cxx").write_text("int f(void) { return 0; }\n", encoding="utf-8")
        (target / "impl.hpp").write_text("int f(void);\n", encoding="utf-8")
        files, _findings, digests = audit_path(str(target))
        self.assertEqual(sorted(Path(p).name for p in files), ["impl.cxx", "impl.hpp"])
        self.assertEqual(len(digests), 2)

    # -------------------------------------------------------------------------
    # D5: Documented Skill Contract Matches the Auditor (code is source of truth)
    # -------------------------------------------------------------------------
    SKILL_DOC = Path(__file__).resolve().parents[1] / "docs" / "skills" / "defensive-security-auditor" / "SKILL.md"

    def _skill_doc_text(self):
        self.assertTrue(self.SKILL_DOC.exists(), f"skill doc missing: {self.SKILL_DOC}")
        return self.SKILL_DOC.read_text(encoding="utf-8")

    def test_documented_rule_ids_exist_in_auditor(self):
        text = self._skill_doc_text()
        real_ids = {r["id"] for r in SECURITY_RULES}
        documented = set(re.findall(r"`(SEC-[A-Z0-9-]+)`", text))

        self.assertTrue(documented, "skill doc must cite at least one rule id")
        unknown = documented - real_ids
        self.assertEqual(unknown, set(), f"skill doc cites rule IDs that do not exist: {sorted(unknown)}")

    def test_documented_cwe_languages_match_auditor(self):
        text = self._skill_doc_text()
        language_tokens = {"C": {"c", "cpp"}, "Rust": {"rust"}, "Python": {"python"}, "Shell": {"shell"}}

        rows = 0
        for line in text.splitlines():
            m = re.match(r"\|\s*\*\*CWE-(\d+)\*\*\s*\|[^|]*\|\s*([^|]+?)\s*\|", line)
            if not m:
                continue
            rows += 1
            cwe = f"CWE-{m.group(1)}"
            documented_langs = set()
            for token in re.findall(r"[A-Za-z]+", m.group(2)):
                if token in language_tokens:
                    documented_langs |= language_tokens[token]
            code_langs = {lang for r in SECURITY_RULES if r["cwe_id"] == cwe for lang in r["languages"]}
            self.assertEqual(
                documented_langs, code_langs,
                f"{cwe}: doc lists {sorted(documented_langs)} but auditor implements {sorted(code_langs)}",
            )
        self.assertGreaterEqual(rows, 6, "expected one CWE row per archetype in the skill doc")

    def test_documented_reproducibility_check_audits_per_run(self):
        # The old documented snippet hashed one (files, findings) pair twice, so the
        # assertion could never fail. Every build_evidence_chain call in the doc must
        # be fed by its own audit_path call.
        text = self._skill_doc_text()
        self.assertGreaterEqual(text.count("audit_path("), 1)
        self.assertEqual(
            text.count("build_evidence_chain("), text.count("audit_path("),
            "Check 2 must audit the target once per evidence chain, not reuse one scan",
        )
        self.assertIn("file_digests=digests", text, "Check 2 must bind the per-file digests")

    # -------------------------------------------------------------------------
    # Empirical Audit on scripts/
    # -------------------------------------------------------------------------
    def test_audit_real_swal_files(self):
        scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
        files_audited, findings, _digests = audit_path(str(scripts_dir))
        self.assertGreater(len(files_audited), 5)
        critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
        self.assertEqual(len(critical_findings), 0)


if __name__ == "__main__":
    main()
