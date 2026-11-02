---
name: qemu
description: Security lessons from qemu.
---

# Trigger
When modifying c code in qemu.

# Anti-patterns (Never do)
- Missing bounds checks on array/buffer access (CWE-125, CWE-787)
- Use-after-free / double-free (CWE-416, CWE-415)
- Integer overflow in size calculations (CWE-190)
- Command injection / path traversal (CWE-78, CWE-22)
- Missing authentication/authorization checks (CWE-862, CWE-863)

# Remediation (Fixes)
- Add bounds check before access
- Free-then-null (set pointer to NULL after free)
- Use size_t with overflow checks
- Parameterized queries / input validation at boundary
- Capability-based access control
