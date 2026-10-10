# Vulnerability Pattern Clusters & Graph Taxonomy

Analysis across **18275** canonical CVE entries linking software components, CWE classes, preconditions, and fix commits.

65 advisory ids appear in more than one catalog (an NVD keyword catalog and an upstream snapshot); each is counted once, with fix SHAs unioned and any stated CWE kept.

## Summary by CWE Family

| CWE | Title | Total CVEs | With Validated Fix SHA | Key Preconditions |
| --- | --- | --- | --- | --- |
| `UNKNOWN` | Unstated or Legacy Advisory Without CWE Classification | 17834 | 17425 | None recorded |
| `CWE-399` | Resource Management Errors | 39 | 2 | Resource exhaustion path without rate limit or quota |
| `CWE-295` | Improper Certificate Validation | 20 | 17 | None recorded |
| `CWE-476` | NULL Pointer Dereference | 19 | 14 | Unchecked return value from allocator or lookup function |
| `CWE-305` | CWE Family CWE-305 | 19 | 12 | None recorded |
| `CWE-264` | Permissions, Privileges, and Access Controls | 18 | 0 | None recorded |
| `CWE-125` | Out-of-bounds Read | 16 | 15 | Untrusted buffer length or unbounded string processing |
| `CWE-416` | Use After Free | 16 | 14 | Asynchronous lifecycle, double free, or aliased pointer reuse |
| `CWE-119` | Memory Corruption / Buffer Boundary Error | 15 | 2 | Untrusted buffer length or unbounded string processing |
| `CWE-126` | CWE Family CWE-126 | 15 | 14 | None recorded |
| `CWE-20` | Improper Input Validation | 14 | 3 | Missing boundary / sanitize check on incoming payload |
| `CWE-310` | Cryptographic Issues | 14 | 0 | None recorded |
| `CWE-189` | CWE Family CWE-189 | 12 | 0 | None recorded |
| `CWE-770` | Allocation of Resources Without Limits or Throttling | 12 | 12 | None recorded |
| `CWE-297` | CWE Family CWE-297 | 11 | 7 | None recorded |
| `CWE-415` | CWE Family CWE-415 | 10 | 9 | None recorded |
| `CWE-201` | CWE Family CWE-201 | 10 | 10 | None recorded |
| `CWE-122` | CWE Family CWE-122 | 10 | 8 | None recorded |
| `CWE-787` | Out-of-bounds Write | 10 | 8 | Untrusted buffer length or unbounded string processing |
| `CWE-200` | Exposure of Sensitive Information | 9 | 8 | Missing boundary / sanitize check on incoming payload |
| `CWE-522` | CWE Family CWE-522 | 9 | 9 | None recorded |
| `CWE-131` | CWE Family CWE-131 | 7 | 5 | None recorded |
| `CWE-287` | Improper Authentication | 7 | 1 | None recorded |
| `CWE-319` | CWE Family CWE-319 | 6 | 6 | None recorded |
| `CWE-121` | CWE Family CWE-121 | 5 | 5 | None recorded |
| `CWE-667` | CWE Family CWE-667 | 5 | 1 | None recorded |
| `CWE-488` | CWE Family CWE-488 | 5 | 5 | None recorded |
| `CWE-325` | CWE Family CWE-325 | 5 | 5 | None recorded |
| `CWE-94` | CWE Family CWE-94 | 4 | 0 | None recorded |
| `CWE-401` | Missing Release of Memory after Effective Lifetime (Memory Leak) | 4 | 2 | Resource exhaustion path without rate limit or quota |
| `CWE-754` | CWE Family CWE-754 | 4 | 4 | None recorded |
| `CWE-835` | CWE Family CWE-835 | 3 | 3 | None recorded |
| `CWE-440` | CWE Family CWE-440 | 3 | 3 | None recorded |
| `CWE-294` | CWE Family CWE-294 | 3 | 3 | None recorded |
| `CWE-354` | CWE Family CWE-354 | 3 | 3 | None recorded |
| `CWE-208` | CWE Family CWE-208 | 3 | 3 | None recorded |
| `CWE-362` | Concurrent Execution using Shared Resource (Race Condition) | 2 | 0 | Multithreaded / interrupt context without adequate lock barrier |
| `CWE-170` | CWE Family CWE-170 | 2 | 1 | None recorded |
| `CWE-281` | CWE Family CWE-281 | 2 | 1 | None recorded |
| `CWE-924` | CWE Family CWE-924 | 2 | 1 | None recorded |
| `CWE-124` | CWE Family CWE-124 | 2 | 2 | None recorded |
| `CWE-22` | CWE Family CWE-22 | 2 | 1 | None recorded |
| `CWE-299` | CWE Family CWE-299 | 2 | 2 | None recorded |
| `CWE-457` | CWE Family CWE-457 | 2 | 2 | None recorded |
| `CWE-385` | CWE Family CWE-385 | 2 | 2 | None recorded |
| `CWE-384` | CWE Family CWE-384 | 1 | 0 | None recorded |
| `CWE-193` | CWE Family CWE-193 | 1 | 0 | None recorded |
| `CWE-916` | CWE Family CWE-916 | 1 | 0 | None recorded |
| `CWE-203` | CWE Family CWE-203 | 1 | 0 | None recorded |
| `CWE-190` | Integer Overflow or Wraparound | 1 | 0 | None recorded |
| `CWE-697` | CWE Family CWE-697 | 1 | 0 | None recorded |
| `CWE-327` | CWE Family CWE-327 | 1 | 0 | None recorded |
| `CWE-862` | CWE Family CWE-862 | 1 | 0 | None recorded |
| `CWE-120` | Classic Buffer Overflow | 1 | 0 | Untrusted buffer length or unbounded string processing |
| `CWE-79` | CWE Family CWE-79 | 1 | 0 | None recorded |
| `CWE-298` | CWE Family CWE-298 | 1 | 0 | None recorded |
| `CWE-338` | CWE Family CWE-338 | 1 | 0 | None recorded |
| `CWE-142` | CWE Family CWE-142 | 1 | 1 | None recorded |
| `CWE-628` | CWE Family CWE-628 | 1 | 1 | None recorded |
| `CWE-30` | CWE Family CWE-30 | 1 | 1 | None recorded |
| `CWE-93` | CWE Family CWE-93 | 1 | 1 | None recorded |
| `CWE-444` | CWE Family CWE-444 | 1 | 1 | None recorded |
| `CWE-187` | CWE Family CWE-187 | 1 | 1 | None recorded |
| `CWE-178` | CWE Family CWE-178 | 1 | 0 | None recorded |
| `CWE-172` | CWE Family CWE-172 | 1 | 1 | None recorded |
| `CWE-838` | CWE Family CWE-838 | 1 | 1 | None recorded |
| `CWE-330` | CWE Family CWE-330 | 1 | 1 | None recorded |
| `CWE-304` | CWE Family CWE-304 | 1 | 1 | None recorded |
| `CWE-641` | CWE Family CWE-641 | 1 | 1 | None recorded |
| `CWE-825` | CWE Family CWE-825 | 1 | 1 | None recorded |
| `CWE-674` | CWE Family CWE-674 | 1 | 1 | None recorded |
| `CWE-359` | CWE Family CWE-359 | 1 | 1 | None recorded |
| `CWE-290` | CWE Family CWE-290 | 1 | 1 | None recorded |
| `CWE-349` | CWE Family CWE-349 | 1 | 1 | None recorded |
| `CWE-706` | CWE Family CWE-706 | 1 | 1 | None recorded |
| `CWE-177` | CWE Family CWE-177 | 1 | 1 | None recorded |
| `CWE-1286` | CWE Family CWE-1286 | 1 | 1 | None recorded |
| `CWE-75` | CWE Family CWE-75 | 1 | 1 | None recorded |
| `CWE-662` | CWE Family CWE-662 | 1 | 1 | None recorded |
| `CWE-73` | CWE Family CWE-73 | 1 | 1 | None recorded |
| `CWE-311` | CWE Family CWE-311 | 1 | 1 | None recorded |
| `CWE-392` | CWE Family CWE-392 | 1 | 1 | None recorded |
| `CWE-115` | CWE Family CWE-115 | 1 | 1 | None recorded |
| `CWE-772` | CWE Family CWE-772 | 1 | 1 | None recorded |
| `CWE-843` | CWE Family CWE-843 | 1 | 1 | None recorded |
| `CWE-590` | CWE Family CWE-590 | 1 | 1 | None recorded |
| `CWE-1025` | CWE Family CWE-1025 | 1 | 1 | None recorded |
| `CWE-1341` | CWE Family CWE-1341 | 1 | 1 | None recorded |
| `CWE-680` | CWE Family CWE-680 | 1 | 1 | None recorded |
| `CWE-340` | CWE Family CWE-340 | 1 | 1 | None recorded |
| `CWE-322` | CWE Family CWE-322 | 1 | 1 | None recorded |
| `CWE-567` | CWE Family CWE-567 | 1 | 1 | None recorded |
| `CWE-347` | CWE Family CWE-347 | 1 | 1 | None recorded |
| `CWE-789` | CWE Family CWE-789 | 1 | 1 | None recorded |
| `CWE-923` | CWE Family CWE-923 | 1 | 1 | None recorded |
| `CWE-757` | CWE Family CWE-757 | 1 | 1 | None recorded |
| `CWE-1325` | CWE Family CWE-1325 | 1 | 1 | None recorded |
| `CWE-514` | CWE Family CWE-514 | 1 | 1 | None recorded |
| `CWE-407` | CWE Family CWE-407 | 1 | 1 | None recorded |
| `CWE-405` | CWE Family CWE-405 | 1 | 1 | None recorded |
| `CWE-346` | CWE Family CWE-346 | 1 | 1 | None recorded |
| `CWE-134` | CWE Family CWE-134 | 1 | 1 | None recorded |
| `CWE-1284` | CWE Family CWE-1284 | 1 | 1 | None recorded |

## Detailed Breakdown by Project

### UNKNOWN — Unstated or Legacy Advisory Without CWE Classification
- **Count**: 17834
- **With Fix SHA**: 17425
- **Project Distribution**: `git`: 1, `glibc`: 3, `linux`: 273, `linux-cna`: 17337, `openssh`: 2, `openssl`: 19, `openssl-upstream`: 163, `postgresql`: 30, `qemu`: 3, `sqlite`: 3
- **Sample CVEs**: CVE-1999-0804, CVE-1999-0862, CVE-1999-1018, CVE-1999-1166, CVE-1999-1341, CVE-2000-0227, CVE-2000-0274, CVE-2000-0335, CVE-2000-0344, CVE-2000-0506

### CWE-399 — Resource Management Errors
- **Count**: 39
- **With Fix SHA**: 2
- **Project Distribution**: `linux`: 24, `openssl`: 14, `postgresql`: 1
- **Sample CVEs**: CVE-2005-0210, CVE-2005-0756, CVE-2005-2099, CVE-2005-2548, CVE-2005-2708, CVE-2005-2709, CVE-2005-2800, CVE-2005-3784, CVE-2005-3806, CVE-2005-3857

### CWE-295 — Improper Certificate Validation
- **Count**: 20
- **With Fix SHA**: 17
- **Project Distribution**: `curl-upstream`: 15, `openssl`: 3, `openssl-upstream`: 2
- **Sample CVEs**: CVE-2009-2409, CVE-2009-3555, CVE-2009-3767, CVE-2016-9952, CVE-2021-22924, CVE-2021-22926, CVE-2023-28321, CVE-2024-2379, CVE-2024-8096, CVE-2025-13034

### CWE-476 — NULL Pointer Dereference
- **Count**: 19
- **With Fix SHA**: 14
- **Project Distribution**: `curl-upstream`: 1, `linux`: 1, `openssl`: 5, `openssl-upstream`: 12
- **Sample CVEs**: CVE-2004-0079, CVE-2005-2459, CVE-2006-4343, CVE-2008-1672, CVE-2009-1386, CVE-2009-1387, CVE-2018-1000121, CVE-2025-15468, CVE-2025-69421, CVE-2026-14457

### CWE-305 — CWE Family CWE-305
- **Count**: 19
- **With Fix SHA**: 12
- **Project Distribution**: `curl-upstream`: 19
- **Sample CVEs**: CVE-2014-0015, CVE-2014-0138, CVE-2015-3143, CVE-2015-3148, CVE-2015-3236, CVE-2016-0755, CVE-2016-5419, CVE-2016-5420, CVE-2016-7141, CVE-2017-7468

### CWE-264 — Permissions, Privileges, and Access Controls
- **Count**: 18
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 8, `openssl`: 3, `postgresql`: 5, `qemu`: 2
- **Sample CVEs**: CVE-2002-2254, CVE-2005-0244, CVE-2005-2492, CVE-2005-2555, CVE-2005-3179, CVE-2005-3257, CVE-2005-3273, CVE-2006-0553, CVE-2006-1524, CVE-2006-4572

### CWE-125 — Out-of-bounds Read
- **Count**: 16
- **With Fix SHA**: 15
- **Project Distribution**: `curl-upstream`: 6, `openssl`: 1, `openssl-upstream`: 9
- **Sample CVEs**: CVE-2004-0112, CVE-2017-8818, CVE-2018-16842, CVE-2018-16890, CVE-2019-3823, CVE-2024-5535, CVE-2024-7264, CVE-2024-9143, CVE-2025-9086, CVE-2025-9230

### CWE-416 — Use After Free
- **Count**: 16
- **With Fix SHA**: 14
- **Project Distribution**: `curl-upstream`: 11, `linux`: 1, `openssl-upstream`: 4
- **Sample CVEs**: CVE-2006-4997, CVE-2016-5421, CVE-2016-8623, CVE-2018-16840, CVE-2021-22901, CVE-2022-43552, CVE-2023-28319, CVE-2024-4741, CVE-2026-10536, CVE-2026-18924

### CWE-119 — Memory Corruption / Buffer Boundary Error
- **Count**: 15
- **With Fix SHA**: 2
- **Project Distribution**: `curl`: 1, `linux`: 6, `openssl`: 4, `postgresql`: 2, `qemu`: 2
- **Sample CVEs**: CVE-2002-1401, CVE-2005-0247, CVE-2005-3185, CVE-2006-1368, CVE-2006-1857, CVE-2006-3738, CVE-2006-6106, CVE-2007-0005, CVE-2007-1217, CVE-2007-1592

### CWE-126 — CWE Family CWE-126
- **Count**: 15
- **With Fix SHA**: 14
- **Project Distribution**: `curl-upstream`: 15
- **Sample CVEs**: CVE-2013-2174, CVE-2014-3707, CVE-2015-3237, CVE-2016-8621, CVE-2016-9953, CVE-2017-1000100, CVE-2017-1000101, CVE-2017-1000254, CVE-2017-1000257, CVE-2017-7407

### CWE-20 — Improper Input Validation
- **Count**: 14
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 1, `linux`: 9, `openssl`: 4
- **Sample CVEs**: CVE-2005-0209, CVE-2005-1761, CVE-2005-3055, CVE-2006-0744, CVE-2006-1522, CVE-2006-1528, CVE-2006-1858, CVE-2007-2172, CVE-2007-2764, CVE-2008-5077

### CWE-310 — Cryptographic Issues
- **Count**: 14
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1, `openssl`: 13
- **Sample CVEs**: CVE-2006-1056, CVE-2006-4339, CVE-2007-5502, CVE-2008-7270, CVE-2009-3765, CVE-2009-3766, CVE-2010-0742, CVE-2010-0928, CVE-2011-1945, CVE-2011-4108

### CWE-189 — CWE Family CWE-189
- **Count**: 12
- **With Fix SHA**: 0
- **Project Distribution**: `curl`: 1, `linux`: 3, `openssl`: 6, `postgresql`: 2
- **Sample CVEs**: CVE-2004-2731, CVE-2005-4077, CVE-2006-6058, CVE-2007-2875, CVE-2007-4769, CVE-2007-4995, CVE-2007-5135, CVE-2007-6067, CVE-2008-0891, CVE-2009-0789

### CWE-770 — Allocation of Resources Without Limits or Throttling
- **Count**: 12
- **With Fix SHA**: 12
- **Project Distribution**: `curl-upstream`: 5, `openssl-upstream`: 7
- **Sample CVEs**: CVE-2022-32205, CVE-2022-32206, CVE-2023-23916, CVE-2023-38039, CVE-2026-11586, CVE-2026-14456, CVE-2026-35189, CVE-2026-54873, CVE-2026-63074, CVE-2026-63075

### CWE-297 — CWE Family CWE-297
- **Count**: 11
- **With Fix SHA**: 7
- **Project Distribution**: `curl-upstream`: 11
- **Sample CVEs**: CVE-2013-4545, CVE-2013-6422, CVE-2014-0139, CVE-2014-1263, CVE-2014-2522, CVE-2014-8151, CVE-2016-3739, CVE-2024-2466, CVE-2025-15079, CVE-2026-12064

### CWE-415 — CWE Family CWE-415
- **Count**: 10
- **With Fix SHA**: 9
- **Project Distribution**: `curl-upstream`: 7, `openssl`: 1, `openssl-upstream`: 2
- **Sample CVEs**: CVE-2003-0545, CVE-2016-8618, CVE-2016-8619, CVE-2019-5481, CVE-2021-22945, CVE-2022-42915, CVE-2023-27537, CVE-2026-18798, CVE-2026-35188, CVE-2026-8925

### CWE-201 — CWE Family CWE-201
- **Count**: 10
- **With Fix SHA**: 10
- **Project Distribution**: `curl-upstream`: 10
- **Sample CVEs**: CVE-2003-1605, CVE-2013-1944, CVE-2014-3613, CVE-2014-3620, CVE-2015-3153, CVE-2022-27779, CVE-2023-46218, CVE-2026-80255, CVE-2026-82209, CVE-2026-8924

### CWE-122 — CWE Family CWE-122
- **Count**: 10
- **With Fix SHA**: 8
- **Project Distribution**: `curl`: 1, `curl-upstream`: 9
- **Sample CVEs**: CVE-2006-1061, CVE-2016-8620, CVE-2016-8622, CVE-2017-9502, CVE-2018-0500, CVE-2018-1000120, CVE-2018-1000300, CVE-2019-5436, CVE-2019-5482, CVE-2023-38545

### CWE-787 — Out-of-bounds Write
- **Count**: 10
- **With Fix SHA**: 8
- **Project Distribution**: `openssl-upstream`: 8, `qemu`: 2
- **Sample CVEs**: CVE-2007-1320, CVE-2007-5730, CVE-2025-11187, CVE-2025-15467, CVE-2025-68160, CVE-2025-69419, CVE-2026-31789, CVE-2026-63072, CVE-2026-72897, CVE-2026-7383

### CWE-200 — Exposure of Sensitive Information
- **Count**: 9
- **With Fix SHA**: 8
- **Project Distribution**: `curl-upstream`: 8, `qemu`: 1
- **Sample CVEs**: CVE-2008-2004, CVE-2020-8169, CVE-2020-8284, CVE-2022-27775, CVE-2024-11053, CVE-2025-0167, CVE-2026-6429, CVE-2026-9545, CVE-2026-9546

### CWE-522 — CWE Family CWE-522
- **Count**: 9
- **With Fix SHA**: 9
- **Project Distribution**: `curl-upstream`: 9
- **Sample CVEs**: CVE-2018-1000007, CVE-2021-22923, CVE-2022-27774, CVE-2022-27776, CVE-2025-14524, CVE-2026-3783, CVE-2026-6253, CVE-2026-8926, CVE-2026-9079

### CWE-131 — CWE Family CWE-131
- **Count**: 7
- **With Fix SHA**: 5
- **Project Distribution**: `curl`: 1, `curl-upstream`: 6
- **Sample CVEs**: CVE-2005-0490, CVE-2016-7167, CVE-2016-8617, CVE-2017-8816, CVE-2018-14618, CVE-2018-16839, CVE-2019-5435

### CWE-287 — Improper Authentication
- **Count**: 7
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `openssl`: 5, `postgresql`: 1
- **Sample CVEs**: CVE-2007-6601, CVE-2009-0129, CVE-2009-0591, CVE-2009-0653, CVE-2009-1390, CVE-2010-4252, CVE-2025-15224

### CWE-319 — CWE Family CWE-319
- **Count**: 6
- **With Fix SHA**: 6
- **Project Distribution**: `curl-upstream`: 6
- **Sample CVEs**: CVE-2022-30115, CVE-2022-42916, CVE-2022-43551, CVE-2023-23914, CVE-2023-23915, CVE-2026-4873

### CWE-121 — CWE Family CWE-121
- **Count**: 5
- **With Fix SHA**: 5
- **Project Distribution**: `curl`: 1, `curl-upstream`: 4
- **Sample CVEs**: CVE-2000-0973, CVE-2013-0249, CVE-2016-9586, CVE-2019-3822, CVE-2022-35260

### CWE-667 — CWE Family CWE-667
- **Count**: 5
- **With Fix SHA**: 1
- **Project Distribution**: `linux`: 4, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2005-2456, CVE-2005-3847, CVE-2006-4342, CVE-2006-5158, CVE-2022-3996

### CWE-488 — CWE Family CWE-488
- **Count**: 5
- **With Fix SHA**: 5
- **Project Distribution**: `curl-upstream`: 5
- **Sample CVEs**: CVE-2021-22897, CVE-2026-19931, CVE-2026-5773, CVE-2026-80231, CVE-2026-8458

### CWE-325 — CWE Family CWE-325
- **Count**: 5
- **With Fix SHA**: 5
- **Project Distribution**: `curl-upstream`: 1, `openssl-upstream`: 4
- **Sample CVEs**: CVE-2021-22946, CVE-2025-69418, CVE-2026-42770, CVE-2026-45445, CVE-2026-45446

### CWE-94 — CWE Family CWE-94
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `curl-upstream`: 2, `postgresql`: 1, `sqlite`: 1
- **Sample CVEs**: CVE-2005-0227, CVE-2008-0516, CVE-2016-4802, CVE-2019-5443

### CWE-401 — Missing Release of Memory after Effective Lifetime (Memory Leak)
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `linux`: 2, `openssl`: 1, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2005-3119, CVE-2005-3181, CVE-2009-1378, CVE-2026-54876

### CWE-754 — CWE Family CWE-754
- **Count**: 4
- **With Fix SHA**: 4
- **Project Distribution**: `openssl-upstream`: 4
- **Sample CVEs**: CVE-2025-69420, CVE-2026-22795, CVE-2026-22796, CVE-2026-31790

### CWE-835 — CWE Family CWE-835
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 3
- **Sample CVEs**: CVE-2022-27781, CVE-2025-5399, CVE-2026-11352

### CWE-440 — CWE Family CWE-440
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 2, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2022-32221, CVE-2023-28322, CVE-2026-35191

### CWE-294 — CWE Family CWE-294
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 3
- **Sample CVEs**: CVE-2026-11856, CVE-2026-7168, CVE-2026-8927

### CWE-354 — CWE Family CWE-354
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `openssl-upstream`: 3
- **Sample CVEs**: CVE-2026-34181, CVE-2026-34182, CVE-2026-75803

### CWE-208 — CWE Family CWE-208
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `openssl-upstream`: 3
- **Sample CVEs**: CVE-2026-54872, CVE-2026-54875, CVE-2026-77696

### CWE-362 — Concurrent Execution using Shared Resource (Race Condition)
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1, `openssl`: 1
- **Sample CVEs**: CVE-2006-0039, CVE-2010-3864

### CWE-170 — CWE Family CWE-170
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2009-2417, CVE-2017-1000099

### CWE-281 — CWE Family CWE-281
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2011-2192, CVE-2022-32207

### CWE-924 — CWE Family CWE-924
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2011-3389, CVE-2022-32208

### CWE-124 — CWE Family CWE-124
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2015-3144, CVE-2015-3145

### CWE-22 — CWE Family CWE-22
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2016-0754, CVE-2023-27534

### CWE-299 — CWE Family CWE-299
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2020-8286, CVE-2024-0853

### CWE-457 — CWE Family CWE-457
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2021-22898, CVE-2021-22925

### CWE-385 — CWE Family CWE-385
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `openssl-upstream`: 2
- **Sample CVEs**: CVE-2024-13176, CVE-2025-9231

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

### CWE-916 — CWE Family CWE-916
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `postgresql`: 1
- **Sample CVEs**: CVE-2002-1657

### CWE-203 — CWE Family CWE-203
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-2003-0078

### CWE-190 — Integer Overflow or Wraparound
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `linux`: 1
- **Sample CVEs**: CVE-2004-2013

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

### CWE-79 — CWE Family CWE-79
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `sqlite`: 1
- **Sample CVEs**: CVE-2007-1231

### CWE-298 — CWE Family CWE-298
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2007-3564

### CWE-338 — CWE Family CWE-338
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-2008-0166

### CWE-142 — CWE Family CWE-142
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2009-0037

### CWE-628 — CWE Family CWE-628
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2010-0734

### CWE-30 — CWE Family CWE-30
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2010-3842

### CWE-93 — CWE Family CWE-93
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2012-0036

### CWE-444 — CWE Family CWE-444
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2014-8150

### CWE-187 — CWE Family CWE-187
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2016-8615

### CWE-178 — CWE Family CWE-178
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2016-8616

### CWE-172 — CWE Family CWE-172
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2016-8624

### CWE-838 — CWE Family CWE-838
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2016-8625

### CWE-330 — CWE Family CWE-330
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2016-9594

### CWE-304 — CWE Family CWE-304
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2017-2629

### CWE-641 — CWE Family CWE-641
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2020-8177

### CWE-825 — CWE Family CWE-825
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2020-8231

### CWE-674 — CWE Family CWE-674
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2020-8285

### CWE-359 — CWE Family CWE-359
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2021-22876

### CWE-290 — CWE Family CWE-290
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2021-22890

### CWE-349 — CWE Family CWE-349
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2021-22947

### CWE-706 — CWE Family CWE-706
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2022-27778

### CWE-177 — CWE Family CWE-177
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2022-27780

### CWE-1286 — CWE Family CWE-1286
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2022-35252

### CWE-75 — CWE Family CWE-75
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2023-27533

### CWE-662 — CWE Family CWE-662
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2023-28320

### CWE-73 — CWE Family CWE-73
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2023-38546

### CWE-311 — CWE Family CWE-311
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2023-46219

### CWE-392 — CWE Family CWE-392
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2024-12797

### CWE-115 — CWE Family CWE-115
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2024-2004

### CWE-772 — CWE Family CWE-772
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2024-2398

### CWE-843 — CWE Family CWE-843
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2024-6119

### CWE-590 — CWE Family CWE-590
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2024-6197

### CWE-1025 — CWE Family CWE-1025
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2024-9681

### CWE-1341 — CWE Family CWE-1341
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2025-0665

### CWE-680 — CWE Family CWE-680
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2025-0725

### CWE-340 — CWE Family CWE-340
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2025-10148

### CWE-322 — CWE Family CWE-322
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2025-10966

### CWE-567 — CWE Family CWE-567
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2025-14017

### CWE-347 — CWE Family CWE-347
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2025-15469

### CWE-789 — CWE Family CWE-789
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2025-66199

### CWE-923 — CWE Family CWE-923
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2026-13608

### CWE-757 — CWE Family CWE-757
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-2673

### CWE-1325 — CWE Family CWE-1325
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-34183

### CWE-514 — CWE Family CWE-514
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-42768

### CWE-407 — CWE Family CWE-407
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-42772

### CWE-405 — CWE Family CWE-405
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-54874

### CWE-346 — CWE Family CWE-346
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2026-6276

### CWE-134 — CWE Family CWE-134
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-63073

### CWE-1284 — CWE Family CWE-1284
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-75806

