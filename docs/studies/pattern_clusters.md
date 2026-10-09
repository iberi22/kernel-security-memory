# Vulnerability Pattern Clusters & Graph Taxonomy

Analysis across **432** canonical CVE entries linking software components, CWE classes, preconditions, and fix commits.

## Summary by CWE Family

| CWE | Title | Total CVEs | With Validated Fix SHA | Key Preconditions |
| --- | --- | --- | --- | --- |
| `UNKNOWN` | Unstated or Legacy Advisory Without CWE Classification | 299 | 0 | None recorded |
| `CWE-399` | Resource Management Errors | 38 | 0 | Resource exhaustion path without rate limit or quota |
| `CWE-310` | Cryptographic Issues | 14 | 0 | None recorded |
| `CWE-20` | Improper Input Validation | 13 | 0 | Missing boundary / sanitize check on incoming payload |
| `CWE-264` | Permissions, Privileges, and Access Controls | 11 | 0 | None recorded |
| `CWE-119` | Memory Corruption / Buffer Boundary Error | 11 | 0 | Untrusted buffer length or unbounded string processing |
| `CWE-189` | CWE Family CWE-189 | 10 | 0 | None recorded |
| `CWE-476` | NULL Pointer Dereference | 6 | 0 | Unchecked return value from allocator or lookup function |
| `CWE-287` | Improper Authentication | 5 | 0 | None recorded |
| `CWE-667` | CWE Family CWE-667 | 4 | 0 | None recorded |
| `CWE-401` | Missing Release of Memory after Effective Lifetime (Memory Leak) | 3 | 0 | Resource exhaustion path without rate limit or quota |
| `CWE-295` | Improper Certificate Validation | 3 | 0 | None recorded |
| `CWE-362` | Concurrent Execution using Shared Resource (Race Condition) | 2 | 0 | Multithreaded / interrupt context without adequate lock barrier |
| `CWE-384` | CWE Family CWE-384 | 1 | 0 | None recorded |
| `CWE-193` | CWE Family CWE-193 | 1 | 0 | None recorded |
| `CWE-203` | CWE Family CWE-203 | 1 | 0 | None recorded |
| `CWE-415` | CWE Family CWE-415 | 1 | 0 | None recorded |
| `CWE-125` | Out-of-bounds Read | 1 | 0 | Untrusted buffer length or unbounded string processing |
| `CWE-190` | Integer Overflow or Wraparound | 1 | 0 | None recorded |
| `CWE-131` | CWE Family CWE-131 | 1 | 0 | None recorded |
| `CWE-697` | CWE Family CWE-697 | 1 | 0 | None recorded |
| `CWE-327` | CWE Family CWE-327 | 1 | 0 | None recorded |
| `CWE-862` | CWE Family CWE-862 | 1 | 0 | None recorded |
| `CWE-120` | Classic Buffer Overflow | 1 | 0 | Untrusted buffer length or unbounded string processing |
| `CWE-416` | Use After Free | 1 | 0 | Asynchronous lifecycle, double free, or aliased pointer reuse |
| `CWE-338` | CWE Family CWE-338 | 1 | 0 | None recorded |

## Detailed Breakdown by Project

### UNKNOWN — Unstated or Legacy Advisory Without CWE Classification
- **Count**: 299
- **With Fix SHA**: 0
- **Project Distribution**: `curl`: 2, `glibc`: 3, `linux`: 273, `openssh`: 2, `openssl`: 19
- **Sample CVEs**: CVE-1999-0804, CVE-1999-1018, CVE-1999-1166, CVE-1999-1341, CVE-2000-0227, CVE-2000-0274, CVE-2000-0335, CVE-2000-0344, CVE-2000-0506, CVE-2000-0525

### CWE-399 — Resource Management Errors
- **Count**: 38
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 24, `openssl`: 14
- **Sample CVEs**: CVE-2005-0210, CVE-2005-0756, CVE-2005-2099, CVE-2005-2548, CVE-2005-2708, CVE-2005-2709, CVE-2005-2800, CVE-2005-3784, CVE-2005-3806, CVE-2005-3857

### CWE-310 — Cryptographic Issues
- **Count**: 14
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1, `openssl`: 13
- **Sample CVEs**: CVE-2006-1056, CVE-2006-4339, CVE-2007-5502, CVE-2008-7270, CVE-2009-3765, CVE-2009-3766, CVE-2010-0742, CVE-2010-0928, CVE-2011-1945, CVE-2011-4108

### CWE-20 — Improper Input Validation
- **Count**: 13
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 9, `openssl`: 4
- **Sample CVEs**: CVE-2005-0209, CVE-2005-1761, CVE-2005-3055, CVE-2006-0744, CVE-2006-1522, CVE-2006-1528, CVE-2006-1858, CVE-2007-2172, CVE-2007-2764, CVE-2008-5077

### CWE-264 — Permissions, Privileges, and Access Controls
- **Count**: 11
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 8, `openssl`: 3
- **Sample CVEs**: CVE-2002-2254, CVE-2005-2492, CVE-2005-2555, CVE-2005-3179, CVE-2005-3257, CVE-2005-3273, CVE-2006-1524, CVE-2006-4572, CVE-2010-1633, CVE-2011-1473

### CWE-119 — Memory Corruption / Buffer Boundary Error
- **Count**: 11
- **With Fix SHA**: 0
- **Project Distribution**: `curl`: 1, `linux`: 6, `openssl`: 4
- **Sample CVEs**: CVE-2005-3185, CVE-2006-1368, CVE-2006-1857, CVE-2006-3738, CVE-2006-6106, CVE-2007-0005, CVE-2007-1217, CVE-2007-1592, CVE-2009-0590, CVE-2009-1377

### CWE-189 — CWE Family CWE-189
- **Count**: 10
- **With Fix SHA**: 0
- **Project Distribution**: `curl`: 1, `linux`: 3, `openssl`: 6
- **Sample CVEs**: CVE-2004-2731, CVE-2005-4077, CVE-2006-6058, CVE-2007-2875, CVE-2007-4995, CVE-2007-5135, CVE-2008-0891, CVE-2009-0789, CVE-2012-2131, CVE-2012-2333

### CWE-476 — NULL Pointer Dereference
- **Count**: 6
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1, `openssl`: 5
- **Sample CVEs**: CVE-2004-0079, CVE-2005-2459, CVE-2006-4343, CVE-2008-1672, CVE-2009-1386, CVE-2009-1387

### CWE-287 — Improper Authentication
- **Count**: 5
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 5
- **Sample CVEs**: CVE-2009-0129, CVE-2009-0591, CVE-2009-0653, CVE-2009-1390, CVE-2010-4252

### CWE-667 — CWE Family CWE-667
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 4
- **Sample CVEs**: CVE-2005-2456, CVE-2005-3847, CVE-2006-4342, CVE-2006-5158

### CWE-401 — Missing Release of Memory after Effective Lifetime (Memory Leak)
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 2, `openssl`: 1
- **Sample CVEs**: CVE-2005-3119, CVE-2005-3181, CVE-2009-1378

### CWE-295 — Improper Certificate Validation
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 3
- **Sample CVEs**: CVE-2009-2409, CVE-2009-3555, CVE-2009-3767

### CWE-362 — Concurrent Execution using Shared Resource (Race Condition)
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1, `openssl`: 1
- **Sample CVEs**: CVE-2006-0039, CVE-2010-3864

### CWE-384 — CWE Family CWE-384
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-1999-0428

### CWE-193 — CWE Family CWE-193
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1
- **Sample CVEs**: CVE-2001-1391

### CWE-203 — CWE Family CWE-203
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-2003-0078

### CWE-415 — CWE Family CWE-415
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-2003-0545

### CWE-125 — Out-of-bounds Read
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-2004-0112

### CWE-190 — Integer Overflow or Wraparound
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1
- **Sample CVEs**: CVE-2004-2013

### CWE-131 — CWE Family CWE-131
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `curl`: 1
- **Sample CVEs**: CVE-2005-0490

### CWE-697 — CWE Family CWE-697
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1
- **Sample CVEs**: CVE-2005-2801

### CWE-327 — CWE Family CWE-327
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-2005-2946

### CWE-862 — CWE Family CWE-862
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1
- **Sample CVEs**: CVE-2005-3623

### CWE-120 — Classic Buffer Overflow
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1
- **Sample CVEs**: CVE-2006-2935

### CWE-416 — Use After Free
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1
- **Sample CVEs**: CVE-2006-4997

### CWE-338 — CWE Family CWE-338
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-2008-0166

