# Vulnerability Pattern Clusters & Graph Taxonomy

Analysis across **18424** canonical CVE entries linking software components, CWE classes, preconditions, and fix commits.

65 advisory ids appear in more than one catalog (an NVD keyword catalog and an upstream snapshot); each is counted once, with fix SHAs unioned and any stated CWE kept.

## CWE Provenance

The deterministic overlay (docs/studies/cwe-overlay.jsonl) supplies a CWE only where the merged catalog row has none. Precedence: CNA-stated in catalog > NVD Primary > CISA ADP > NVD Secondary.

- From catalog (stated by CNA/upstream): 468
- From overlay nvd-primary: 7920
- From overlay cisa-adp: 376
- From overlay nvd-secondary: 43
- Still UNKNOWN: 9617

## Summary by CWE Family

| CWE | Title | Total CVEs | With Validated Fix SHA | Key Preconditions |
| --- | --- | --- | --- | --- |
| `UNKNOWN` | Unstated or Legacy Advisory Without CWE Classification | 9617 | 9244 | None recorded |
| `CWE-476` | NULL Pointer Dereference | 2078 | 2063 | Unchecked return value from allocator or lookup function |
| `CWE-416` | Use After Free | 1380 | 1372 | Asynchronous lifecycle, double free, or aliased pointer reuse |
| `CWE-401` | Missing Release of Memory after Effective Lifetime (Memory Leak) | 1114 | 1111 | Resource exhaustion path without rate limit or quota |
| `CWE-125` | Out-of-bounds Read | 609 | 600 | Untrusted buffer length or unbounded string processing |
| `CWE-667` | CWE Family CWE-667 | 529 | 525 | None recorded |
| `CWE-787` | Out-of-bounds Write | 485 | 479 | Untrusted buffer length or unbounded string processing |
| `CWE-362` | Concurrent Execution using Shared Resource (Race Condition) | 405 | 397 | Multithreaded / interrupt context without adequate lock barrier |
| `CWE-908` | CWE Family CWE-908 | 278 | 278 | None recorded |
| `CWE-415` | CWE Family CWE-415 | 217 | 216 | None recorded |
| `CWE-129` | CWE Family CWE-129 | 152 | 151 | None recorded |
| `CWE-190` | Integer Overflow or Wraparound | 135 | 127 | None recorded |
| `CWE-617` | CWE Family CWE-617 | 101 | 101 | None recorded |
| `CWE-369` | CWE Family CWE-369 | 94 | 93 | None recorded |
| `CWE-835` | CWE Family CWE-835 | 91 | 90 | None recorded |
| `CWE-770` | Allocation of Resources Without Limits or Throttling | 68 | 66 | None recorded |
| `CWE-120` | Classic Buffer Overflow | 59 | 55 | Untrusted buffer length or unbounded string processing |
| `CWE-191` | CWE Family CWE-191 | 53 | 53 | None recorded |
| `CWE-399` | Resource Management Errors | 47 | 4 | Resource exhaustion path without rate limit or quota |
| `CWE-119` | Memory Corruption / Buffer Boundary Error | 46 | 24 | Untrusted buffer length or unbounded string processing |
| `CWE-193` | CWE Family CWE-193 | 42 | 41 | None recorded |
| `CWE-754` | CWE Family CWE-754 | 39 | 39 | None recorded |
| `CWE-674` | CWE Family CWE-674 | 38 | 38 | None recorded |
| `CWE-367` | CWE Family CWE-367 | 34 | 34 | None recorded |
| `CWE-459` | CWE Family CWE-459 | 32 | 32 | None recorded |
| `CWE-200` | Exposure of Sensitive Information | 28 | 17 | Missing boundary / sanitize check on incoming payload |
| `CWE-20` | Improper Input Validation | 27 | 7 | Missing boundary / sanitize check on incoming payload |
| `CWE-310` | Cryptographic Issues | 27 | 1 | None recorded |
| `CWE-295` | Improper Certificate Validation | 27 | 23 | None recorded |
| `CWE-400` | Uncontrolled Resource Consumption (DoS) | 27 | 26 | Resource exhaustion path without rate limit or quota |
| `CWE-772` | CWE Family CWE-772 | 20 | 20 | None recorded |
| `CWE-264` | Permissions, Privileges, and Access Controls | 19 | 1 | None recorded |
| `CWE-305` | CWE Family CWE-305 | 19 | 12 | None recorded |
| `CWE-668` | CWE Family CWE-668 | 19 | 18 | None recorded |
| `CWE-131` | CWE Family CWE-131 | 18 | 16 | None recorded |
| `CWE-126` | CWE Family CWE-126 | 16 | 15 | None recorded |
| `CWE-189` | CWE Family CWE-189 | 15 | 1 | None recorded |
| `CWE-122` | CWE Family CWE-122 | 15 | 9 | None recorded |
| `CWE-763` | CWE Family CWE-763 | 14 | 14 | None recorded |
| `CWE-252` | CWE Family CWE-252 | 13 | 13 | None recorded |
| `CWE-203` | CWE Family CWE-203 | 12 | 10 | None recorded |
| `CWE-522` | CWE Family CWE-522 | 12 | 12 | None recorded |
| `CWE-665` | CWE Family CWE-665 | 12 | 11 | None recorded |
| `CWE-824` | CWE Family CWE-824 | 12 | 12 | None recorded |
| `CWE-297` | CWE Family CWE-297 | 11 | 7 | None recorded |
| `CWE-755` | CWE Family CWE-755 | 11 | 11 | None recorded |
| `CWE-201` | CWE Family CWE-201 | 10 | 10 | None recorded |
| `CWE-1284` | CWE Family CWE-1284 | 10 | 10 | None recorded |
| `CWE-909` | CWE Family CWE-909 | 10 | 10 | None recorded |
| `CWE-327` | CWE Family CWE-327 | 8 | 7 | None recorded |
| `CWE-287` | Improper Authentication | 8 | 2 | None recorded |
| `CWE-670` | CWE Family CWE-670 | 8 | 8 | None recorded |
| `CWE-269` | CWE Family CWE-269 | 7 | 2 | None recorded |
| `CWE-672` | CWE Family CWE-672 | 7 | 7 | None recorded |
| `CWE-404` | CWE Family CWE-404 | 7 | 7 | None recorded |
| `CWE-354` | CWE Family CWE-354 | 7 | 4 | None recorded |
| `CWE-22` | CWE Family CWE-22 | 6 | 4 | None recorded |
| `CWE-319` | CWE Family CWE-319 | 6 | 6 | None recorded |
| `CWE-121` | CWE Family CWE-121 | 5 | 5 | None recorded |
| `CWE-488` | CWE Family CWE-488 | 5 | 5 | None recorded |
| `CWE-325` | CWE Family CWE-325 | 5 | 5 | None recorded |
| `CWE-834` | CWE Family CWE-834 | 5 | 5 | None recorded |
| `CWE-704` | CWE Family CWE-704 | 5 | 5 | None recorded |
| `CWE-843` | CWE Family CWE-843 | 5 | 5 | None recorded |
| `CWE-94` | CWE Family CWE-94 | 4 | 0 | None recorded |
| `CWE-862` | CWE Family CWE-862 | 4 | 3 | None recorded |
| `CWE-78` | CWE Family CWE-78 | 4 | 2 | None recorded |
| `CWE-59` | CWE Family CWE-59 | 4 | 2 | None recorded |
| `CWE-440` | CWE Family CWE-440 | 4 | 4 | None recorded |
| `CWE-1341` | CWE Family CWE-1341 | 4 | 4 | None recorded |
| `CWE-17` | CWE Family CWE-17 | 3 | 0 | None recorded |
| `CWE-681` | CWE Family CWE-681 | 3 | 3 | None recorded |
| `CWE-863` | CWE Family CWE-863 | 3 | 1 | None recorded |
| `CWE-825` | CWE Family CWE-825 | 3 | 3 | None recorded |
| `CWE-457` | CWE Family CWE-457 | 3 | 3 | None recorded |
| `CWE-662` | CWE Family CWE-662 | 3 | 3 | None recorded |
| `CWE-209` | CWE Family CWE-209 | 3 | 3 | None recorded |
| `CWE-706` | CWE Family CWE-706 | 3 | 3 | None recorded |
| `CWE-911` | CWE Family CWE-911 | 3 | 3 | None recorded |
| `CWE-1188` | CWE Family CWE-1188 | 3 | 3 | None recorded |
| `CWE-669` | CWE Family CWE-669 | 3 | 1 | None recorded |
| `CWE-116` | CWE Family CWE-116 | 3 | 2 | None recorded |
| `CWE-294` | CWE Family CWE-294 | 3 | 3 | None recorded |
| `CWE-208` | CWE Family CWE-208 | 3 | 3 | None recorded |
| `CWE-697` | CWE Family CWE-697 | 2 | 1 | None recorded |
| `CWE-170` | CWE Family CWE-170 | 2 | 1 | None recorded |
| `CWE-628` | CWE Family CWE-628 | 2 | 2 | None recorded |
| `CWE-281` | CWE Family CWE-281 | 2 | 1 | None recorded |
| `CWE-924` | CWE Family CWE-924 | 2 | 1 | None recorded |
| `CWE-326` | CWE Family CWE-326 | 2 | 1 | None recorded |
| `CWE-124` | CWE Family CWE-124 | 2 | 2 | None recorded |
| `CWE-284` | CWE Family CWE-284 | 2 | 2 | None recorded |
| `CWE-330` | CWE Family CWE-330 | 2 | 2 | None recorded |
| `CWE-89` | CWE Family CWE-89 | 2 | 1 | None recorded |
| `CWE-290` | CWE Family CWE-290 | 2 | 1 | None recorded |
| `CWE-299` | CWE Family CWE-299 | 2 | 2 | None recorded |
| `CWE-273` | CWE Family CWE-273 | 2 | 2 | None recorded |
| `CWE-73` | CWE Family CWE-73 | 2 | 1 | None recorded |
| `CWE-385` | CWE Family CWE-385 | 2 | 2 | None recorded |
| `CWE-1325` | CWE Family CWE-1325 | 2 | 2 | None recorded |
| `CWE-134` | CWE Family CWE-134 | 2 | 2 | None recorded |
| `CWE-1258` | CWE Family CWE-1258 | 2 | 2 | None recorded |
| `CWE-682` | CWE Family CWE-682 | 2 | 2 | None recorded |
| `CWE-1025` | CWE Family CWE-1025 | 2 | 1 | None recorded |
| `CWE-1288` | CWE Family CWE-1288 | 2 | 2 | None recorded |
| `CWE-384` | CWE Family CWE-384 | 1 | 0 | None recorded |
| `CWE-916` | CWE Family CWE-916 | 1 | 0 | None recorded |
| `CWE-79` | CWE Family CWE-79 | 1 | 0 | None recorded |
| `CWE-298` | CWE Family CWE-298 | 1 | 0 | None recorded |
| `CWE-338` | CWE Family CWE-338 | 1 | 0 | None recorded |
| `CWE-142` | CWE Family CWE-142 | 1 | 1 | None recorded |
| `CWE-30` | CWE Family CWE-30 | 1 | 1 | None recorded |
| `CWE-93` | CWE Family CWE-93 | 1 | 1 | None recorded |
| `CWE-444` | CWE Family CWE-444 | 1 | 1 | None recorded |
| `CWE-254` | CWE Family CWE-254 | 1 | 0 | None recorded |
| `CWE-187` | CWE Family CWE-187 | 1 | 1 | None recorded |
| `CWE-178` | CWE Family CWE-178 | 1 | 0 | None recorded |
| `CWE-172` | CWE Family CWE-172 | 1 | 1 | None recorded |
| `CWE-838` | CWE Family CWE-838 | 1 | 1 | None recorded |
| `CWE-601` | CWE Family CWE-601 | 1 | 0 | None recorded |
| `CWE-304` | CWE Family CWE-304 | 1 | 1 | None recorded |
| `CWE-320` | CWE Family CWE-320 | 1 | 1 | None recorded |
| `CWE-502` | CWE Family CWE-502 | 1 | 0 | None recorded |
| `CWE-88` | CWE Family CWE-88 | 1 | 1 | None recorded |
| `CWE-426` | CWE Family CWE-426 | 1 | 0 | None recorded |
| `CWE-434` | CWE Family CWE-434 | 1 | 1 | None recorded |
| `CWE-268` | CWE Family CWE-268 | 1 | 0 | None recorded |
| `CWE-641` | CWE Family CWE-641 | 1 | 1 | None recorded |
| `CWE-359` | CWE Family CWE-359 | 1 | 1 | None recorded |
| `CWE-349` | CWE Family CWE-349 | 1 | 1 | None recorded |
| `CWE-266` | CWE Family CWE-266 | 1 | 1 | None recorded |
| `CWE-544` | CWE Family CWE-544 | 1 | 1 | None recorded |
| `CWE-177` | CWE Family CWE-177 | 1 | 1 | None recorded |
| `CWE-1286` | CWE Family CWE-1286 | 1 | 1 | None recorded |
| `CWE-75` | CWE Family CWE-75 | 1 | 1 | None recorded |
| `CWE-1333` | CWE Family CWE-1333 | 1 | 1 | None recorded |
| `CWE-311` | CWE Family CWE-311 | 1 | 1 | None recorded |
| `CWE-77` | CWE Family CWE-77 | 1 | 1 | None recorded |
| `CWE-1335` | CWE Family CWE-1335 | 1 | 1 | None recorded |
| `CWE-920` | CWE Family CWE-920 | 1 | 1 | None recorded |
| `CWE-684` | CWE Family CWE-684 | 1 | 1 | None recorded |
| `CWE-606` | CWE Family CWE-606 | 1 | 1 | None recorded |
| `CWE-300` | CWE Family CWE-300 | 1 | 0 | None recorded |
| `CWE-392` | CWE Family CWE-392 | 1 | 1 | None recorded |
| `CWE-115` | CWE Family CWE-115 | 1 | 1 | None recorded |
| `CWE-324` | CWE Family CWE-324 | 1 | 1 | None recorded |
| `CWE-312` | CWE Family CWE-312 | 1 | 1 | None recorded |
| `CWE-276` | CWE Family CWE-276 | 1 | 1 | None recorded |
| `CWE-212` | CWE Family CWE-212 | 1 | 1 | None recorded |
| `CWE-590` | CWE Family CWE-590 | 1 | 1 | None recorded |
| `CWE-680` | CWE Family CWE-680 | 1 | 1 | None recorded |
| `CWE-340` | CWE Family CWE-340 | 1 | 1 | None recorded |
| `CWE-322` | CWE Family CWE-322 | 1 | 1 | None recorded |
| `CWE-567` | CWE Family CWE-567 | 1 | 1 | None recorded |
| `CWE-347` | CWE Family CWE-347 | 1 | 1 | None recorded |
| `CWE-364` | CWE Family CWE-364 | 1 | 0 | None recorded |
| `CWE-789` | CWE Family CWE-789 | 1 | 1 | None recorded |
| `CWE-197` | CWE Family CWE-197 | 1 | 0 | None recorded |
| `CWE-244` | CWE Family CWE-244 | 1 | 0 | None recorded |
| `CWE-923` | CWE Family CWE-923 | 1 | 1 | None recorded |
| `CWE-757` | CWE Family CWE-757 | 1 | 1 | None recorded |
| `CWE-130` | CWE Family CWE-130 | 1 | 1 | None recorded |
| `CWE-826` | CWE Family CWE-826 | 1 | 1 | None recorded |
| `CWE-696` | CWE Family CWE-696 | 1 | 0 | None recorded |
| `CWE-348` | CWE Family CWE-348 | 1 | 0 | None recorded |
| `CWE-514` | CWE Family CWE-514 | 1 | 1 | None recorded |
| `CWE-407` | CWE Family CWE-407 | 1 | 1 | None recorded |
| `CWE-480` | CWE Family CWE-480 | 1 | 1 | None recorded |
| `CWE-123` | CWE Family CWE-123 | 1 | 1 | None recorded |
| `CWE-664` | CWE Family CWE-664 | 1 | 1 | None recorded |
| `CWE-280` | CWE Family CWE-280 | 1 | 1 | None recorded |
| `CWE-1058` | CWE Family CWE-1058 | 1 | 1 | None recorded |
| `CWE-366` | CWE Family CWE-366 | 1 | 1 | None recorded |
| `CWE-823` | CWE Family CWE-823 | 1 | 1 | None recorded |
| `CWE-386` | CWE Family CWE-386 | 1 | 1 | None recorded |
| `CWE-253` | CWE Family CWE-253 | 1 | 1 | None recorded |
| `CWE-393` | CWE Family CWE-393 | 1 | 1 | None recorded |
| `CWE-820` | CWE Family CWE-820 | 1 | 1 | None recorded |
| `CWE-405` | CWE Family CWE-405 | 1 | 1 | None recorded |
| `CWE-346` | CWE Family CWE-346 | 1 | 1 | None recorded |

## Detailed Breakdown by Project

### UNKNOWN — Unstated or Legacy Advisory Without CWE Classification
- **Count**: 9617
- **With Fix SHA**: 9244
- **Project Distribution**: `git`: 1, `git-upstream`: 4, `glibc`: 3, `linux`: 273, `linux-cna`: 9233, `openssh`: 2, `openssl`: 19, `openssl-upstream`: 20, `postgresql`: 30, `qemu`: 3, `sqlite`: 3, `sqlite-upstream`: 11, `systemd-upstream`: 15
- **Sample CVEs**: CVE-1999-0804, CVE-1999-0862, CVE-1999-1018, CVE-1999-1166, CVE-1999-1341, CVE-2000-0227, CVE-2000-0274, CVE-2000-0335, CVE-2000-0344, CVE-2000-0506

### CWE-476 — NULL Pointer Dereference
- **Count**: 2078
- **With Fix SHA**: 2063
- **Project Distribution**: `curl-upstream`: 1, `linux`: 1, `linux-cna`: 2031, `openssl`: 5, `openssl-upstream`: 27, `sqlite-upstream`: 12, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2004-0079, CVE-2005-2459, CVE-2006-4343, CVE-2008-1672, CVE-2009-1386, CVE-2009-1387, CVE-2014-0198, CVE-2014-3470, CVE-2015-3194, CVE-2016-7052

### CWE-416 — Use After Free
- **Count**: 1380
- **With Fix SHA**: 1372
- **Project Distribution**: `curl-upstream`: 11, `linux`: 1, `linux-cna`: 1354, `openssl-upstream`: 6, `sqlite-upstream`: 6, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2006-4997, CVE-2016-5421, CVE-2016-6309, CVE-2016-8623, CVE-2018-16840, CVE-2019-25162, CVE-2019-5018, CVE-2020-11656, CVE-2020-13630, CVE-2020-13871

### CWE-401 — Missing Release of Memory after Effective Lifetime (Memory Leak)
- **Count**: 1114
- **With Fix SHA**: 1111
- **Project Distribution**: `linux`: 2, `linux-cna`: 1107, `openssl`: 1, `openssl-upstream`: 2, `sqlite-upstream`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2005-3119, CVE-2005-3181, CVE-2009-1378, CVE-2016-6304, CVE-2019-20386, CVE-2020-36777, CVE-2020-36786, CVE-2020-36790, CVE-2021-4453, CVE-2021-45346

### CWE-125 — Out-of-bounds Read
- **Count**: 609
- **With Fix SHA**: 600
- **Project Distribution**: `curl-upstream`: 6, `git-upstream`: 1, `linux-cna`: 579, `openssl`: 1, `openssl-upstream`: 17, `sqlite-upstream`: 4, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2004-0112, CVE-2014-0160, CVE-2016-2180, CVE-2016-6306, CVE-2017-10989, CVE-2017-3731, CVE-2017-3737, CVE-2017-8818, CVE-2018-11233, CVE-2018-16842

### CWE-667 — CWE Family CWE-667
- **Count**: 529
- **With Fix SHA**: 525
- **Project Distribution**: `linux`: 4, `linux-cna`: 524, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2005-2456, CVE-2005-3847, CVE-2006-4342, CVE-2006-5158, CVE-2020-36775, CVE-2021-46927, CVE-2021-46987, CVE-2021-47038, CVE-2021-47041, CVE-2021-47055

### CWE-787 — Out-of-bounds Write
- **Count**: 485
- **With Fix SHA**: 479
- **Project Distribution**: `linux-cna`: 467, `openssl-upstream`: 13, `qemu`: 2, `sqlite-upstream`: 1, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2007-1320, CVE-2007-5730, CVE-2016-2182, CVE-2016-6303, CVE-2017-9445, CVE-2019-6454, CVE-2020-15358, CVE-2021-46931, CVE-2021-47132, CVE-2021-47138

### CWE-362 — Concurrent Execution using Shared Resource (Race Condition)
- **Count**: 405
- **With Fix SHA**: 397
- **Project Distribution**: `linux`: 1, `linux-cna`: 397, `openssl`: 1, `openssl-upstream`: 4, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2006-0039, CVE-2010-3864, CVE-2010-5298, CVE-2014-3509, CVE-2015-1791, CVE-2015-3196, CVE-2018-1049, CVE-2018-15687, CVE-2021-46925, CVE-2021-46982

### CWE-908 — CWE Family CWE-908
- **Count**: 278
- **With Fix SHA**: 278
- **Project Distribution**: `linux-cna`: 278
- **Sample CVEs**: CVE-2021-47056, CVE-2021-47096, CVE-2021-47101, CVE-2021-47136, CVE-2021-47139, CVE-2021-47297, CVE-2021-47339, CVE-2021-47424, CVE-2021-47446, CVE-2021-47451

### CWE-415 — CWE Family CWE-415
- **Count**: 217
- **With Fix SHA**: 216
- **Project Distribution**: `curl-upstream`: 7, `linux-cna`: 206, `openssl`: 1, `openssl-upstream`: 3
- **Sample CVEs**: CVE-2003-0545, CVE-2016-8618, CVE-2016-8619, CVE-2019-5481, CVE-2020-36785, CVE-2021-22945, CVE-2021-46938, CVE-2021-46979, CVE-2021-47082, CVE-2021-47123

### CWE-129 — CWE Family CWE-129
- **Count**: 152
- **With Fix SHA**: 151
- **Project Distribution**: `linux-cna`: 151, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2020-36776, CVE-2021-4439, CVE-2021-46984, CVE-2021-47065, CVE-2021-47135, CVE-2021-47449, CVE-2021-47547, CVE-2021-47548, CVE-2022-35737, CVE-2022-48702

### CWE-190 — Integer Overflow or Wraparound
- **Count**: 135
- **With Fix SHA**: 127
- **Project Distribution**: `linux`: 1, `linux-cna`: 124, `openssl-upstream`: 4, `sqlite-upstream`: 6
- **Sample CVEs**: CVE-2004-2013, CVE-2016-2105, CVE-2016-2177, CVE-2018-20346, CVE-2018-20506, CVE-2019-1551, CVE-2020-13434, CVE-2021-23840, CVE-2021-46940, CVE-2021-47098

### CWE-617 — CWE Family CWE-617
- **Count**: 101
- **With Fix SHA**: 101
- **Project Distribution**: `linux-cna`: 101
- **Sample CVEs**: CVE-2021-47305, CVE-2021-47315, CVE-2021-47351, CVE-2022-48633, CVE-2022-49154, CVE-2022-49158, CVE-2022-49171, CVE-2022-49325, CVE-2022-49347, CVE-2022-49409

### CWE-369 — CWE Family CWE-369
- **Count**: 94
- **With Fix SHA**: 93
- **Project Distribution**: `linux-cna`: 93, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2019-16168, CVE-2021-46915, CVE-2021-47080, CVE-2021-47363, CVE-2021-47495, CVE-2021-47584, CVE-2021-47606, CVE-2021-47641, CVE-2022-49294, CVE-2022-49330

### CWE-835 — CWE Family CWE-835
- **Count**: 91
- **With Fix SHA**: 90
- **Project Distribution**: `curl-upstream`: 3, `linux-cna`: 85, `openssl-upstream`: 2, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2017-15908, CVE-2021-4044, CVE-2021-47159, CVE-2021-47406, CVE-2021-47448, CVE-2021-47617, CVE-2022-0778, CVE-2022-27781, CVE-2022-48630, CVE-2022-48635

### CWE-770 — Allocation of Resources Without Limits or Throttling
- **Count**: 68
- **With Fix SHA**: 66
- **Project Distribution**: `curl-upstream`: 5, `linux-cna`: 52, `openssl-upstream`: 8, `systemd-upstream`: 3
- **Sample CVEs**: CVE-2018-16864, CVE-2018-16865, CVE-2021-33910, CVE-2021-47057, CVE-2021-47130, CVE-2021-47137, CVE-2021-47170, CVE-2021-47182, CVE-2021-47374, CVE-2021-47551

### CWE-120 — Classic Buffer Overflow
- **Count**: 59
- **With Fix SHA**: 55
- **Project Distribution**: `git-upstream`: 1, `linux`: 1, `linux-cna`: 53, `openssl-upstream`: 3, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2006-2935, CVE-2014-0195, CVE-2018-15688, CVE-2021-3711, CVE-2021-47040, CVE-2021-47107, CVE-2021-47172, CVE-2021-47347, CVE-2021-47485, CVE-2021-47609

### CWE-191 — CWE Family CWE-191
- **Count**: 53
- **With Fix SHA**: 53
- **Project Distribution**: `linux-cna`: 53
- **Sample CVEs**: CVE-2021-46951, CVE-2021-47555, CVE-2022-48643, CVE-2022-48665, CVE-2022-48804, CVE-2022-48828, CVE-2022-49199, CVE-2022-49208, CVE-2022-49278, CVE-2022-49280

### CWE-399 — Resource Management Errors
- **Count**: 47
- **With Fix SHA**: 4
- **Project Distribution**: `linux`: 24, `openssl`: 14, `openssl-upstream`: 8, `postgresql`: 1
- **Sample CVEs**: CVE-2005-0210, CVE-2005-0756, CVE-2005-2099, CVE-2005-2548, CVE-2005-2708, CVE-2005-2709, CVE-2005-2800, CVE-2005-3784, CVE-2005-3806, CVE-2005-3857

### CWE-119 — Memory Corruption / Buffer Boundary Error
- **Count**: 46
- **With Fix SHA**: 24
- **Project Distribution**: `curl`: 1, `git-upstream`: 2, `linux`: 6, `linux-cna`: 19, `openssl`: 4, `openssl-upstream`: 9, `postgresql`: 2, `qemu`: 2, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2002-1401, CVE-2005-0247, CVE-2005-3185, CVE-2006-1368, CVE-2006-1857, CVE-2006-3738, CVE-2006-6106, CVE-2007-0005, CVE-2007-1217, CVE-2007-1592

### CWE-193 — CWE Family CWE-193
- **Count**: 42
- **With Fix SHA**: 41
- **Project Distribution**: `linux`: 1, `linux-cna`: 40, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2001-1391, CVE-2021-47046, CVE-2021-47373, CVE-2022-3821, CVE-2022-48672, CVE-2022-48732, CVE-2022-49077, CVE-2022-49365, CVE-2022-50428, CVE-2023-53143

### CWE-754 — CWE Family CWE-754
- **Count**: 39
- **With Fix SHA**: 39
- **Project Distribution**: `linux-cna`: 33, `openssl-upstream`: 5, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2019-19646, CVE-2021-46909, CVE-2021-46934, CVE-2021-47007, CVE-2021-47014, CVE-2021-47227, CVE-2023-52678, CVE-2023-5678, CVE-2024-35785, CVE-2024-36481

### CWE-674 — CWE Family CWE-674
- **Count**: 38
- **With Fix SHA**: 38
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 34, `openssl-upstream`: 1, `sqlite-upstream`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2018-0739, CVE-2019-19645, CVE-2020-8285, CVE-2021-3997, CVE-2021-47465, CVE-2022-49782, CVE-2022-50118, CVE-2022-50407, CVE-2023-52761, CVE-2023-52986

### CWE-367 — CWE Family CWE-367
- **Count**: 34
- **With Fix SHA**: 34
- **Project Distribution**: `linux-cna`: 34
- **Sample CVEs**: CVE-2021-47280, CVE-2023-52478, CVE-2024-26974, CVE-2024-42107, CVE-2024-43882, CVE-2024-49998, CVE-2024-50220, CVE-2024-50234, CVE-2025-21746, CVE-2025-21958

### CWE-459 — CWE Family CWE-459
- **Count**: 32
- **With Fix SHA**: 32
- **Project Distribution**: `linux-cna`: 31, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2021-47110, CVE-2021-47143, CVE-2021-47178, CVE-2021-47365, CVE-2022-1473, CVE-2022-48893, CVE-2022-49012, CVE-2022-49028, CVE-2023-52617, CVE-2023-52929

### CWE-200 — Exposure of Sensitive Information
- **Count**: 28
- **With Fix SHA**: 17
- **Project Distribution**: `curl-upstream`: 8, `linux-cna`: 4, `openssl-upstream`: 14, `qemu`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2008-2004, CVE-2014-3508, CVE-2015-3193, CVE-2015-3195, CVE-2015-3197, CVE-2016-0701, CVE-2016-0702, CVE-2016-0703, CVE-2016-0704, CVE-2016-0800

### CWE-20 — Improper Input Validation
- **Count**: 27
- **With Fix SHA**: 7
- **Project Distribution**: `curl-upstream`: 1, `git-upstream`: 1, `linux`: 9, `openssl`: 4, `openssl-upstream`: 8, `sqlite-upstream`: 2, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2005-0209, CVE-2005-1761, CVE-2005-3055, CVE-2006-0744, CVE-2006-1522, CVE-2006-1528, CVE-2006-1858, CVE-2007-2172, CVE-2007-2764, CVE-2008-5077

### CWE-310 — Cryptographic Issues
- **Count**: 27
- **With Fix SHA**: 1
- **Project Distribution**: `linux`: 1, `openssl`: 13, `openssl-upstream`: 13
- **Sample CVEs**: CVE-2006-1056, CVE-2006-4339, CVE-2007-5502, CVE-2008-7270, CVE-2009-3765, CVE-2009-3766, CVE-2010-0742, CVE-2010-0928, CVE-2011-1945, CVE-2011-4108

### CWE-295 — Improper Certificate Validation
- **Count**: 27
- **With Fix SHA**: 23
- **Project Distribution**: `curl-upstream`: 15, `openssl`: 3, `openssl-upstream`: 8, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2009-2409, CVE-2009-3555, CVE-2009-3767, CVE-2016-9952, CVE-2018-21029, CVE-2019-1552, CVE-2021-22924, CVE-2021-22926, CVE-2021-3450, CVE-2022-1343

### CWE-400 — Uncontrolled Resource Consumption (DoS)
- **Count**: 27
- **With Fix SHA**: 26
- **Project Distribution**: `git-upstream`: 1, `linux-cna`: 24, `openssl-upstream`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2016-6307, CVE-2017-15298, CVE-2021-4440, CVE-2021-47010, CVE-2021-47023, CVE-2021-47238, CVE-2021-47284, CVE-2021-47295, CVE-2021-47313, CVE-2021-47329

### CWE-772 — CWE Family CWE-772
- **Count**: 20
- **With Fix SHA**: 20
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 19
- **Sample CVEs**: CVE-2021-47283, CVE-2021-47389, CVE-2022-50189, CVE-2023-53152, CVE-2023-53199, CVE-2024-2398, CVE-2024-35821, CVE-2024-47733, CVE-2024-53074, CVE-2025-71232

### CWE-264 — Permissions, Privileges, and Access Controls
- **Count**: 19
- **With Fix SHA**: 1
- **Project Distribution**: `linux`: 8, `openssl`: 3, `postgresql`: 5, `qemu`: 2, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2002-2254, CVE-2005-0244, CVE-2005-2492, CVE-2005-2555, CVE-2005-3179, CVE-2005-3257, CVE-2005-3273, CVE-2006-0553, CVE-2006-1524, CVE-2006-4572

### CWE-305 — CWE Family CWE-305
- **Count**: 19
- **With Fix SHA**: 12
- **Project Distribution**: `curl-upstream`: 19
- **Sample CVEs**: CVE-2014-0015, CVE-2014-0138, CVE-2015-3143, CVE-2015-3148, CVE-2015-3236, CVE-2016-0755, CVE-2016-5419, CVE-2016-5420, CVE-2016-7141, CVE-2017-7468

### CWE-668 — CWE Family CWE-668
- **Count**: 19
- **With Fix SHA**: 18
- **Project Distribution**: `git-upstream`: 1, `linux-cna`: 18
- **Sample CVEs**: CVE-2021-46906, CVE-2021-46917, CVE-2021-46921, CVE-2021-46923, CVE-2021-46935, CVE-2021-46937, CVE-2021-47401, CVE-2022-24975, CVE-2022-48757, CVE-2022-49509

### CWE-131 — CWE Family CWE-131
- **Count**: 18
- **With Fix SHA**: 16
- **Project Distribution**: `curl`: 1, `curl-upstream`: 6, `linux-cna`: 11
- **Sample CVEs**: CVE-2005-0490, CVE-2016-7167, CVE-2016-8617, CVE-2017-8816, CVE-2018-14618, CVE-2018-16839, CVE-2019-5435, CVE-2021-46943, CVE-2022-48889, CVE-2024-26721

### CWE-126 — CWE Family CWE-126
- **Count**: 16
- **With Fix SHA**: 15
- **Project Distribution**: `curl-upstream`: 15, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2013-2174, CVE-2014-3707, CVE-2015-3237, CVE-2016-8621, CVE-2016-9953, CVE-2017-1000100, CVE-2017-1000101, CVE-2017-1000254, CVE-2017-1000257, CVE-2017-7407

### CWE-189 — CWE Family CWE-189
- **Count**: 15
- **With Fix SHA**: 1
- **Project Distribution**: `curl`: 1, `linux`: 3, `openssl`: 6, `openssl-upstream`: 3, `postgresql`: 2
- **Sample CVEs**: CVE-2004-2731, CVE-2005-4077, CVE-2006-6058, CVE-2007-2875, CVE-2007-4769, CVE-2007-4995, CVE-2007-5135, CVE-2007-6067, CVE-2008-0891, CVE-2009-0789

### CWE-122 — CWE Family CWE-122
- **Count**: 15
- **With Fix SHA**: 9
- **Project Distribution**: `curl`: 1, `curl-upstream`: 9, `sqlite-upstream`: 5
- **Sample CVEs**: CVE-2006-1061, CVE-2016-8620, CVE-2016-8622, CVE-2017-9502, CVE-2018-0500, CVE-2018-1000120, CVE-2018-1000300, CVE-2019-5436, CVE-2019-5482, CVE-2023-38545

### CWE-763 — CWE Family CWE-763
- **Count**: 14
- **With Fix SHA**: 14
- **Project Distribution**: `linux-cna`: 14
- **Sample CVEs**: CVE-2021-47087, CVE-2021-47221, CVE-2021-47387, CVE-2022-48835, CVE-2022-49160, CVE-2024-35832, CVE-2024-36890, CVE-2024-38617, CVE-2024-42132, CVE-2024-50057

### CWE-252 — CWE Family CWE-252
- **Count**: 13
- **With Fix SHA**: 13
- **Project Distribution**: `linux-cna`: 13
- **Sample CVEs**: CVE-2021-47360, CVE-2023-52680, CVE-2023-52687, CVE-2023-52692, CVE-2023-52797, CVE-2023-53070, CVE-2024-39492, CVE-2024-42067, CVE-2024-42068, CVE-2025-22026

### CWE-203 — CWE Family CWE-203
- **Count**: 12
- **With Fix SHA**: 10
- **Project Distribution**: `linux-cna`: 5, `openssl`: 1, `openssl-upstream`: 6
- **Sample CVEs**: CVE-2003-0078, CVE-2016-2178, CVE-2018-5407, CVE-2019-1559, CVE-2019-1563, CVE-2020-1968, CVE-2021-47226, CVE-2022-4304, CVE-2022-48730, CVE-2024-47678

### CWE-522 — CWE Family CWE-522
- **Count**: 12
- **With Fix SHA**: 12
- **Project Distribution**: `curl-upstream`: 9, `git-upstream`: 2, `postgres-upstream`: 1
- **Sample CVEs**: CVE-2018-1000007, CVE-2020-11008, CVE-2020-5260, CVE-2021-22923, CVE-2021-23222, CVE-2022-27774, CVE-2022-27776, CVE-2025-14524, CVE-2026-3783, CVE-2026-6253

### CWE-665 — CWE Family CWE-665
- **Count**: 12
- **With Fix SHA**: 11
- **Project Distribution**: `linux-cna`: 11, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2020-11655, CVE-2021-46932, CVE-2021-47194, CVE-2023-52452, CVE-2024-38558, CVE-2024-39301, CVE-2024-39485, CVE-2024-42078, CVE-2024-44947, CVE-2024-45018

### CWE-824 — CWE Family CWE-824
- **Count**: 12
- **With Fix SHA**: 12
- **Project Distribution**: `linux-cna`: 12
- **Sample CVEs**: CVE-2021-47602, CVE-2024-26799, CVE-2024-36966, CVE-2024-42275, CVE-2024-46844, CVE-2024-49938, CVE-2024-50087, CVE-2024-50088, CVE-2024-57943, CVE-2025-37995

### CWE-297 — CWE Family CWE-297
- **Count**: 11
- **With Fix SHA**: 7
- **Project Distribution**: `curl-upstream`: 11
- **Sample CVEs**: CVE-2013-4545, CVE-2013-6422, CVE-2014-0139, CVE-2014-1263, CVE-2014-2522, CVE-2014-8151, CVE-2016-3739, CVE-2024-2466, CVE-2025-15079, CVE-2026-12064

### CWE-755 — CWE Family CWE-755
- **Count**: 11
- **With Fix SHA**: 11
- **Project Distribution**: `linux-cna`: 9, `sqlite-upstream`: 2
- **Sample CVEs**: CVE-2019-19924, CVE-2019-20218, CVE-2021-46928, CVE-2022-48673, CVE-2024-26584, CVE-2024-26911, CVE-2024-50001, CVE-2024-50002, CVE-2024-50176, CVE-2024-50202

### CWE-201 — CWE Family CWE-201
- **Count**: 10
- **With Fix SHA**: 10
- **Project Distribution**: `curl-upstream`: 10
- **Sample CVEs**: CVE-2003-1605, CVE-2013-1944, CVE-2014-3613, CVE-2014-3620, CVE-2015-3153, CVE-2022-27779, CVE-2023-46218, CVE-2026-80255, CVE-2026-82209, CVE-2026-8924

### CWE-1284 — CWE Family CWE-1284
- **Count**: 10
- **With Fix SHA**: 10
- **Project Distribution**: `linux-cna`: 9, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2021-47251, CVE-2022-50020, CVE-2024-35963, CVE-2024-35964, CVE-2024-35965, CVE-2024-38659, CVE-2024-56716, CVE-2025-39700, CVE-2026-52905, CVE-2026-75806

### CWE-909 — CWE Family CWE-909
- **Count**: 10
- **With Fix SHA**: 10
- **Project Distribution**: `linux-cna`: 10
- **Sample CVEs**: CVE-2022-49217, CVE-2022-49865, CVE-2022-50169, CVE-2024-26635, CVE-2024-43873, CVE-2024-50076, CVE-2024-56676, CVE-2025-38532, CVE-2025-38601, CVE-2026-43040

### CWE-327 — CWE Family CWE-327
- **Count**: 8
- **With Fix SHA**: 7
- **Project Distribution**: `openssl`: 1, `openssl-upstream`: 7
- **Sample CVEs**: CVE-2005-2946, CVE-2018-0734, CVE-2018-0735, CVE-2018-0737, CVE-2019-1543, CVE-2021-23839, CVE-2022-1434, CVE-2022-2097

### CWE-287 — Improper Authentication
- **Count**: 8
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 1, `openssl`: 5, `openssl-upstream`: 1, `postgresql`: 1
- **Sample CVEs**: CVE-2007-6601, CVE-2009-0129, CVE-2009-0591, CVE-2009-0653, CVE-2009-1390, CVE-2010-4252, CVE-2023-2975, CVE-2025-15224

### CWE-670 — CWE Family CWE-670
- **Count**: 8
- **With Fix SHA**: 8
- **Project Distribution**: `linux-cna`: 8
- **Sample CVEs**: CVE-2022-49393, CVE-2023-52742, CVE-2023-52781, CVE-2024-47745, CVE-2024-53134, CVE-2025-38291, CVE-2026-98051, CVE-2026-98164

### CWE-269 — CWE Family CWE-269
- **Count**: 7
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 1, `systemd-upstream`: 6
- **Sample CVEs**: CVE-2017-1000082, CVE-2018-16888, CVE-2019-3843, CVE-2020-13776, CVE-2023-26604, CVE-2026-29111, CVE-2026-46333

### CWE-672 — CWE Family CWE-672
- **Count**: 7
- **With Fix SHA**: 7
- **Project Distribution**: `linux-cna`: 7
- **Sample CVEs**: CVE-2021-47069, CVE-2021-47294, CVE-2024-49953, CVE-2024-49955, CVE-2024-56674, CVE-2024-57929, CVE-2026-98080

### CWE-404 — CWE Family CWE-404
- **Count**: 7
- **With Fix SHA**: 7
- **Project Distribution**: `linux-cna`: 7
- **Sample CVEs**: CVE-2022-48661, CVE-2022-49745, CVE-2024-26757, CVE-2024-46752, CVE-2024-56757, CVE-2024-57879, CVE-2025-38385

### CWE-354 — CWE Family CWE-354
- **Count**: 7
- **With Fix SHA**: 4
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 3, `systemd-upstream`: 3
- **Sample CVEs**: CVE-2023-31437, CVE-2023-31438, CVE-2023-31439, CVE-2024-49875, CVE-2026-34181, CVE-2026-34182, CVE-2026-75803

### CWE-22 — CWE Family CWE-22
- **Count**: 6
- **With Fix SHA**: 4
- **Project Distribution**: `curl-upstream`: 2, `git-upstream`: 2, `linux-cna`: 2
- **Sample CVEs**: CVE-2016-0754, CVE-2018-11235, CVE-2023-27534, CVE-2023-52623, CVE-2024-32002, CVE-2024-47742

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

### CWE-834 — CWE Family CWE-834
- **Count**: 5
- **With Fix SHA**: 5
- **Project Distribution**: `linux-cna`: 3, `openssl-upstream`: 2
- **Sample CVEs**: CVE-2022-48939, CVE-2023-3817, CVE-2024-42071, CVE-2024-42237, CVE-2024-4603

### CWE-704 — CWE Family CWE-704
- **Count**: 5
- **With Fix SHA**: 5
- **Project Distribution**: `linux-cna`: 5
- **Sample CVEs**: CVE-2022-49873, CVE-2024-57839, CVE-2025-22044, CVE-2025-37746, CVE-2025-39880

### CWE-843 — CWE Family CWE-843
- **Count**: 5
- **With Fix SHA**: 5
- **Project Distribution**: `linux-cna`: 3, `openssl-upstream`: 2
- **Sample CVEs**: CVE-2023-0286, CVE-2024-49860, CVE-2024-6119, CVE-2026-31502, CVE-2026-43038

### CWE-94 — CWE Family CWE-94
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `curl-upstream`: 2, `postgresql`: 1, `sqlite`: 1
- **Sample CVEs**: CVE-2005-0227, CVE-2008-0516, CVE-2016-4802, CVE-2019-5443

### CWE-862 — CWE Family CWE-862
- **Count**: 4
- **With Fix SHA**: 3
- **Project Distribution**: `linux`: 1, `linux-cna`: 3
- **Sample CVEs**: CVE-2005-3623, CVE-2023-52642, CVE-2024-26705, CVE-2026-64042

### CWE-78 — CWE Family CWE-78
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `git-upstream`: 2, `openssl-upstream`: 2
- **Sample CVEs**: CVE-2017-14867, CVE-2019-19604, CVE-2022-1292, CVE-2022-2068

### CWE-59 — CWE Family CWE-59
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `git-upstream`: 1, `linux-cna`: 1, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2017-18078, CVE-2018-6954, CVE-2021-21300, CVE-2024-46744

### CWE-440 — CWE Family CWE-440
- **Count**: 4
- **With Fix SHA**: 4
- **Project Distribution**: `curl-upstream`: 2, `openssl-upstream`: 2
- **Sample CVEs**: CVE-2022-32221, CVE-2023-28322, CVE-2023-4807, CVE-2026-35191

### CWE-1341 — CWE Family CWE-1341
- **Count**: 4
- **With Fix SHA**: 4
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 3
- **Sample CVEs**: CVE-2025-0665, CVE-2026-43494, CVE-2026-45898, CVE-2026-52987

### CWE-17 — CWE Family CWE-17
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `openssl-upstream`: 3
- **Sample CVEs**: CVE-2015-0286, CVE-2015-0287, CVE-2015-0290

### CWE-681 — CWE Family CWE-681
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 2, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2019-19317, CVE-2026-53133, CVE-2026-98049

### CWE-863 — CWE Family CWE-863
- **Count**: 3
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2019-3842, CVE-2024-36963, CVE-2026-40224

### CWE-825 — CWE Family CWE-825
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 2
- **Sample CVEs**: CVE-2020-8231, CVE-2026-46176, CVE-2026-46243

### CWE-457 — CWE Family CWE-457
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 2, `linux-cna`: 1
- **Sample CVEs**: CVE-2021-22898, CVE-2021-22925, CVE-2024-26882

### CWE-662 — CWE Family CWE-662
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 2
- **Sample CVEs**: CVE-2021-46939, CVE-2023-28320, CVE-2026-53277

### CWE-209 — CWE Family CWE-209
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 3
- **Sample CVEs**: CVE-2021-47161, CVE-2021-47381, CVE-2024-35935

### CWE-706 — CWE Family CWE-706
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 2
- **Sample CVEs**: CVE-2021-47261, CVE-2021-47276, CVE-2022-27778

### CWE-911 — CWE Family CWE-911
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 3
- **Sample CVEs**: CVE-2021-47327, CVE-2026-46099, CVE-2026-46316

### CWE-1188 — CWE Family CWE-1188
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 3
- **Sample CVEs**: CVE-2021-47343, CVE-2022-49099, CVE-2025-38523

### CWE-669 — CWE Family CWE-669
- **Count**: 3
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2024-42158, CVE-2026-40225, CVE-2026-40228

### CWE-116 — CWE Family CWE-116
- **Count**: 3
- **With Fix SHA**: 2
- **Project Distribution**: `git-upstream`: 3
- **Sample CVEs**: CVE-2024-50349, CVE-2024-52005, CVE-2024-52006

### CWE-294 — CWE Family CWE-294
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 3
- **Sample CVEs**: CVE-2026-11856, CVE-2026-7168, CVE-2026-8927

### CWE-208 — CWE Family CWE-208
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `openssl-upstream`: 3
- **Sample CVEs**: CVE-2026-54872, CVE-2026-54875, CVE-2026-77696

### CWE-697 — CWE Family CWE-697
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `linux`: 1, `linux-cna`: 1
- **Sample CVEs**: CVE-2005-2801, CVE-2021-47370

### CWE-170 — CWE Family CWE-170
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2009-2417, CVE-2017-1000099

### CWE-628 — CWE Family CWE-628
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 1
- **Sample CVEs**: CVE-2010-0734, CVE-2026-43133

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

### CWE-326 — CWE Family CWE-326
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2014-0224, CVE-2025-39889

### CWE-124 — CWE Family CWE-124
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2015-3144, CVE-2015-3145

### CWE-284 — CWE Family CWE-284
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2016-7054, CVE-2023-52801

### CWE-330 — CWE Family CWE-330
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 1, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2016-9594, CVE-2019-1549

### CWE-89 — CWE Family CWE-89
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `postgres-upstream`: 1, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2018-20505, CVE-2021-23214

### CWE-290 — CWE Family CWE-290
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2020-13529, CVE-2021-22890

### CWE-299 — CWE Family CWE-299
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2020-8286, CVE-2024-0853

### CWE-273 — CWE Family CWE-273
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2
- **Sample CVEs**: CVE-2021-47129, CVE-2023-52433

### CWE-73 — CWE Family CWE-73
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `git-upstream`: 1
- **Sample CVEs**: CVE-2023-38546, CVE-2025-48385

### CWE-385 — CWE Family CWE-385
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `openssl-upstream`: 2
- **Sample CVEs**: CVE-2024-13176, CVE-2025-9231

### CWE-1325 — CWE Family CWE-1325
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `openssl-upstream`: 2
- **Sample CVEs**: CVE-2024-2511, CVE-2026-34183

### CWE-134 — CWE Family CWE-134
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 1
- **Sample CVEs**: CVE-2024-35845, CVE-2026-63073

### CWE-1258 — CWE Family CWE-1258
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2
- **Sample CVEs**: CVE-2024-36912, CVE-2024-36913

### CWE-682 — CWE Family CWE-682
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2
- **Sample CVEs**: CVE-2024-41011, CVE-2024-42231

### CWE-1025 — CWE Family CWE-1025
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2024-9681, CVE-2026-40227

### CWE-1288 — CWE Family CWE-1288
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2
- **Sample CVEs**: CVE-2026-31431, CVE-2026-31709

### CWE-384 — CWE Family CWE-384
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1
- **Sample CVEs**: CVE-1999-0428

### CWE-916 — CWE Family CWE-916
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `postgresql`: 1
- **Sample CVEs**: CVE-2002-1657

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

### CWE-254 — CWE Family CWE-254
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2015-1793

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

### CWE-601 — CWE Family CWE-601
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `git-upstream`: 1
- **Sample CVEs**: CVE-2017-1000117

### CWE-304 — CWE Family CWE-304
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2017-2629

### CWE-320 — CWE Family CWE-320
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2018-0732

### CWE-502 — CWE Family CWE-502
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `systemd-upstream`: 1
- **Sample CVEs**: CVE-2018-15686

### CWE-88 — CWE Family CWE-88
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `git-upstream`: 1
- **Sample CVEs**: CVE-2018-17456

### CWE-426 — CWE Family CWE-426
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `git-upstream`: 1
- **Sample CVEs**: CVE-2018-19486

### CWE-434 — CWE Family CWE-434
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2019-19925

### CWE-268 — CWE Family CWE-268
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `systemd-upstream`: 1
- **Sample CVEs**: CVE-2019-3844

### CWE-641 — CWE Family CWE-641
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2020-8177

### CWE-359 — CWE Family CWE-359
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2021-22876

### CWE-349 — CWE Family CWE-349
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2021-22947

### CWE-266 — CWE Family CWE-266
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2021-47241

### CWE-544 — CWE Family CWE-544
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2021-47482

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

### CWE-1333 — CWE Family CWE-1333
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2023-3446

### CWE-311 — CWE Family CWE-311
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2023-46219

### CWE-77 — CWE Family CWE-77
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2023-52624

### CWE-1335 — CWE Family CWE-1335
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2023-52810

### CWE-920 — CWE Family CWE-920
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2023-52832

### CWE-684 — CWE Family CWE-684
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2023-5363

### CWE-606 — CWE Family CWE-606
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2023-6237

### CWE-300 — CWE Family CWE-300
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `systemd-upstream`: 1
- **Sample CVEs**: CVE-2023-7008

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

### CWE-324 — CWE Family CWE-324
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2024-36031

### CWE-312 — CWE Family CWE-312
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2024-45004

### CWE-276 — CWE Family CWE-276
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2024-46695

### CWE-212 — CWE Family CWE-212
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2024-49997

### CWE-590 — CWE Family CWE-590
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2024-6197

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

### CWE-364 — CWE Family CWE-364
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `systemd-upstream`: 1
- **Sample CVEs**: CVE-2025-4598

### CWE-789 — CWE Family CWE-789
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2025-66199

### CWE-197 — CWE Family CWE-197
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2025-6965

### CWE-244 — CWE Family CWE-244
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2025-70873

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

### CWE-130 — CWE Family CWE-130
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-31635

### CWE-826 — CWE Family CWE-826
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-31663

### CWE-696 — CWE Family CWE-696
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `systemd-upstream`: 1
- **Sample CVEs**: CVE-2026-40223

### CWE-348 — CWE Family CWE-348
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `systemd-upstream`: 1
- **Sample CVEs**: CVE-2026-40226

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

### CWE-480 — CWE Family CWE-480
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-43114

### CWE-123 — CWE Family CWE-123
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-43284

### CWE-664 — CWE Family CWE-664
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-43503

### CWE-280 — CWE Family CWE-280
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-46054

### CWE-1058 — CWE Family CWE-1058
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-46152

### CWE-366 — CWE Family CWE-366
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-46181

### CWE-823 — CWE Family CWE-823
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-46244

### CWE-386 — CWE Family CWE-386
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-53081

### CWE-253 — CWE Family CWE-253
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-53090

### CWE-393 — CWE Family CWE-393
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-53092

### CWE-820 — CWE Family CWE-820
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-53153

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

