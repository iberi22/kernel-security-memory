# Vulnerability Pattern Clusters & Graph Taxonomy

Analysis across **20448** canonical CVE entries linking software components, CWE classes, preconditions, and fix commits.

65 advisory ids appear in more than one catalog (an NVD keyword catalog and an upstream snapshot); each is counted once, with fix SHAs unioned and any stated CWE kept.

## CWE Provenance

The deterministic overlay (docs/studies/cwe-overlay.jsonl) supplies a CWE only where the merged catalog row has none. Precedence: CNA-stated in catalog > NVD Primary > CISA ADP > NVD Secondary.

- From catalog (stated by CNA/upstream): 1782
- From overlay nvd-primary: 7920
- From overlay cisa-adp: 376
- From overlay nvd-secondary: 43
- Still UNKNOWN: 10327

## Summary by CWE Family

| CWE | Title | Total CVEs | With Validated Fix SHA | Key Preconditions |
| --- | --- | --- | --- | --- |
| `UNKNOWN` | Unstated or Legacy Advisory Without CWE Classification | 10327 | 9243 | None recorded |
| `CWE-476` | NULL Pointer Dereference | 2097 | 2063 | Unchecked return value from allocator or lookup function |
| `CWE-416` | Use After Free | 1430 | 1372 | Asynchronous lifecycle, double free, or aliased pointer reuse |
| `CWE-401` | Missing Release of Memory after Effective Lifetime (Memory Leak) | 1117 | 1111 | Resource exhaustion path without rate limit or quota |
| `CWE-125` | Out-of-bounds Read | 658 | 600 | Untrusted buffer length or unbounded string processing |
| `CWE-667` | CWE Family CWE-667 | 530 | 525 | None recorded |
| `CWE-787` | Out-of-bounds Write | 514 | 479 | Untrusted buffer length or unbounded string processing |
| `CWE-362` | Concurrent Execution using Shared Resource (Race Condition) | 459 | 397 | Multithreaded / interrupt context without adequate lock barrier |
| `CWE-908` | CWE Family CWE-908 | 311 | 278 | None recorded |
| `CWE-415` | CWE Family CWE-415 | 248 | 216 | None recorded |
| `CWE-190` | Integer Overflow or Wraparound | 164 | 127 | None recorded |
| `CWE-129` | CWE Family CWE-129 | 156 | 151 | None recorded |
| `CWE-770` | Allocation of Resources Without Limits or Throttling | 117 | 66 | None recorded |
| `CWE-617` | CWE Family CWE-617 | 111 | 101 | None recorded |
| `CWE-835` | CWE Family CWE-835 | 100 | 90 | None recorded |
| `CWE-369` | CWE Family CWE-369 | 98 | 93 | None recorded |
| `CWE-119` | Memory Corruption / Buffer Boundary Error | 90 | 24 | Untrusted buffer length or unbounded string processing |
| `CWE-20` | Improper Input Validation | 78 | 7 | Missing boundary / sanitize check on incoming payload |
| `CWE-400` | Uncontrolled Resource Consumption (DoS) | 74 | 26 | Resource exhaustion path without rate limit or quota |
| `CWE-120` | Classic Buffer Overflow | 72 | 55 | Untrusted buffer length or unbounded string processing |
| `CWE-191` | CWE Family CWE-191 | 58 | 53 | None recorded |
| `CWE-200` | Exposure of Sensitive Information | 55 | 17 | Missing boundary / sanitize check on incoming payload |
| `CWE-674` | CWE Family CWE-674 | 55 | 38 | None recorded |
| `CWE-367` | CWE Family CWE-367 | 53 | 34 | None recorded |
| `CWE-22` | CWE Family CWE-22 | 51 | 4 | None recorded |
| `CWE-399` | Resource Management Errors | 47 | 4 | Resource exhaustion path without rate limit or quota |
| `CWE-754` | CWE Family CWE-754 | 47 | 39 | None recorded |
| `CWE-193` | CWE Family CWE-193 | 46 | 41 | None recorded |
| `CWE-295` | Improper Certificate Validation | 38 | 23 | None recorded |
| `CWE-459` | CWE Family CWE-459 | 35 | 32 | None recorded |
| `CWE-248` | CWE Family CWE-248 | 32 | 0 | None recorded |
| `CWE-863` | CWE Family CWE-863 | 30 | 1 | None recorded |
| `CWE-310` | Cryptographic Issues | 27 | 1 | None recorded |
| `CWE-131` | CWE Family CWE-131 | 26 | 16 | None recorded |
| `CWE-122` | CWE Family CWE-122 | 25 | 9 | None recorded |
| `CWE-668` | CWE Family CWE-668 | 23 | 18 | None recorded |
| `CWE-772` | CWE Family CWE-772 | 22 | 20 | None recorded |
| `CWE-347` | CWE Family CWE-347 | 22 | 1 | None recorded |
| `CWE-327` | CWE Family CWE-327 | 21 | 7 | None recorded |
| `CWE-126` | CWE Family CWE-126 | 21 | 15 | None recorded |
| `CWE-264` | Permissions, Privileges, and Access Controls | 19 | 1 | None recorded |
| `CWE-79` | CWE Family CWE-79 | 19 | 0 | None recorded |
| `CWE-305` | CWE Family CWE-305 | 19 | 12 | None recorded |
| `CWE-269` | CWE Family CWE-269 | 19 | 2 | None recorded |
| `CWE-203` | CWE Family CWE-203 | 18 | 10 | None recorded |
| `CWE-755` | CWE Family CWE-755 | 18 | 11 | None recorded |
| `CWE-662` | CWE Family CWE-662 | 18 | 3 | None recorded |
| `CWE-1284` | CWE Family CWE-1284 | 18 | 10 | None recorded |
| `CWE-345` | CWE Family CWE-345 | 18 | 0 | None recorded |
| `CWE-252` | CWE Family CWE-252 | 17 | 13 | None recorded |
| `CWE-843` | CWE Family CWE-843 | 17 | 5 | None recorded |
| `CWE-287` | Improper Authentication | 16 | 2 | None recorded |
| `CWE-665` | CWE Family CWE-665 | 16 | 11 | None recorded |
| `CWE-670` | CWE Family CWE-670 | 16 | 8 | None recorded |
| `CWE-918` | CWE Family CWE-918 | 16 | 0 | None recorded |
| `CWE-189` | CWE Family CWE-189 | 15 | 1 | None recorded |
| `CWE-824` | CWE Family CWE-824 | 15 | 12 | None recorded |
| `CWE-77` | CWE Family CWE-77 | 15 | 1 | None recorded |
| `CWE-444` | CWE Family CWE-444 | 14 | 1 | None recorded |
| `CWE-59` | CWE Family CWE-59 | 14 | 2 | None recorded |
| `CWE-763` | CWE Family CWE-763 | 14 | 14 | None recorded |
| `CWE-201` | CWE Family CWE-201 | 13 | 10 | None recorded |
| `CWE-78` | CWE Family CWE-78 | 13 | 2 | None recorded |
| `CWE-522` | CWE Family CWE-522 | 13 | 12 | None recorded |
| `CWE-682` | CWE Family CWE-682 | 13 | 2 | None recorded |
| `CWE-862` | CWE Family CWE-862 | 12 | 3 | None recorded |
| `CWE-297` | CWE Family CWE-297 | 11 | 7 | None recorded |
| `CWE-284` | CWE Family CWE-284 | 11 | 2 | None recorded |
| `CWE-909` | CWE Family CWE-909 | 11 | 10 | None recorded |
| `CWE-704` | CWE Family CWE-704 | 11 | 5 | None recorded |
| `CWE-354` | CWE Family CWE-354 | 11 | 4 | None recorded |
| `CWE-672` | CWE Family CWE-672 | 10 | 7 | None recorded |
| `CWE-121` | CWE Family CWE-121 | 9 | 5 | None recorded |
| `CWE-94` | CWE Family CWE-94 | 9 | 0 | None recorded |
| `CWE-404` | CWE Family CWE-404 | 9 | 7 | None recorded |
| `CWE-281` | CWE Family CWE-281 | 8 | 1 | None recorded |
| `CWE-319` | CWE Family CWE-319 | 8 | 6 | None recorded |
| `CWE-116` | CWE Family CWE-116 | 8 | 2 | None recorded |
| `CWE-208` | CWE Family CWE-208 | 8 | 3 | None recorded |
| `CWE-325` | CWE Family CWE-325 | 7 | 5 | None recorded |
| `CWE-440` | CWE Family CWE-440 | 7 | 4 | None recorded |
| `CWE-276` | CWE Family CWE-276 | 7 | 1 | None recorded |
| `CWE-285` | CWE Family CWE-285 | 7 | 0 | None recorded |
| `CWE-506` | CWE Family CWE-506 | 7 | 0 | None recorded |
| `CWE-488` | CWE Family CWE-488 | 6 | 5 | None recorded |
| `CWE-209` | CWE Family CWE-209 | 6 | 3 | None recorded |
| `CWE-706` | CWE Family CWE-706 | 6 | 3 | None recorded |
| `CWE-1333` | CWE Family CWE-1333 | 6 | 1 | None recorded |
| `CWE-130` | CWE Family CWE-130 | 6 | 1 | None recorded |
| `CWE-532` | CWE Family CWE-532 | 6 | 0 | None recorded |
| `CWE-758` | CWE Family CWE-758 | 6 | 0 | None recorded |
| `CWE-61` | CWE Family CWE-61 | 6 | 0 | None recorded |
| `CWE-1240` | CWE Family CWE-1240 | 6 | 0 | None recorded |
| `CWE-681` | CWE Family CWE-681 | 5 | 3 | None recorded |
| `CWE-290` | CWE Family CWE-290 | 5 | 1 | None recorded |
| `CWE-266` | CWE Family CWE-266 | 5 | 1 | None recorded |
| `CWE-834` | CWE Family CWE-834 | 5 | 5 | None recorded |
| `CWE-73` | CWE Family CWE-73 | 5 | 1 | None recorded |
| `CWE-684` | CWE Family CWE-684 | 5 | 1 | None recorded |
| `CWE-1025` | CWE Family CWE-1025 | 5 | 1 | None recorded |
| `CWE-789` | CWE Family CWE-789 | 5 | 1 | None recorded |
| `CWE-732` | CWE Family CWE-732 | 5 | 0 | None recorded |
| `CWE-639` | CWE Family CWE-639 | 5 | 0 | None recorded |
| `CWE-150` | CWE Family CWE-150 | 5 | 0 | None recorded |
| `CWE-176` | CWE Family CWE-176 | 5 | 0 | None recorded |
| `CWE-697` | CWE Family CWE-697 | 4 | 1 | None recorded |
| `CWE-330` | CWE Family CWE-330 | 4 | 2 | None recorded |
| `CWE-601` | CWE Family CWE-601 | 4 | 0 | None recorded |
| `CWE-502` | CWE Family CWE-502 | 4 | 0 | None recorded |
| `CWE-89` | CWE Family CWE-89 | 4 | 1 | None recorded |
| `CWE-299` | CWE Family CWE-299 | 4 | 2 | None recorded |
| `CWE-1188` | CWE Family CWE-1188 | 4 | 3 | None recorded |
| `CWE-134` | CWE Family CWE-134 | 4 | 2 | None recorded |
| `CWE-1258` | CWE Family CWE-1258 | 4 | 2 | None recorded |
| `CWE-1341` | CWE Family CWE-1341 | 4 | 4 | None recorded |
| `CWE-1288` | CWE Family CWE-1288 | 4 | 2 | None recorded |
| `CWE-253` | CWE Family CWE-253 | 4 | 1 | None recorded |
| `CWE-703` | CWE Family CWE-703 | 4 | 0 | None recorded |
| `CWE-328` | CWE Family CWE-328 | 4 | 0 | None recorded |
| `CWE-497` | CWE Family CWE-497 | 4 | 0 | None recorded |
| `CWE-188` | CWE Family CWE-188 | 4 | 0 | None recorded |
| `CWE-326` | CWE Family CWE-326 | 3 | 1 | None recorded |
| `CWE-17` | CWE Family CWE-17 | 3 | 0 | None recorded |
| `CWE-426` | CWE Family CWE-426 | 3 | 0 | None recorded |
| `CWE-825` | CWE Family CWE-825 | 3 | 3 | None recorded |
| `CWE-457` | CWE Family CWE-457 | 3 | 3 | None recorded |
| `CWE-273` | CWE Family CWE-273 | 3 | 2 | None recorded |
| `CWE-911` | CWE Family CWE-911 | 3 | 3 | None recorded |
| `CWE-75` | CWE Family CWE-75 | 3 | 1 | None recorded |
| `CWE-311` | CWE Family CWE-311 | 3 | 1 | None recorded |
| `CWE-385` | CWE Family CWE-385 | 3 | 2 | None recorded |
| `CWE-669` | CWE Family CWE-669 | 3 | 1 | None recorded |
| `CWE-294` | CWE Family CWE-294 | 3 | 3 | None recorded |
| `CWE-377` | CWE Family CWE-377 | 3 | 0 | None recorded |
| `CWE-228` | CWE Family CWE-228 | 3 | 0 | None recorded |
| `CWE-331` | CWE Family CWE-331 | 3 | 0 | None recorded |
| `CWE-693` | CWE Family CWE-693 | 3 | 0 | None recorded |
| `CWE-288` | CWE Family CWE-288 | 3 | 0 | None recorded |
| `CWE-384` | CWE Family CWE-384 | 2 | 0 | None recorded |
| `CWE-338` | CWE Family CWE-338 | 2 | 0 | None recorded |
| `CWE-170` | CWE Family CWE-170 | 2 | 1 | None recorded |
| `CWE-628` | CWE Family CWE-628 | 2 | 2 | None recorded |
| `CWE-924` | CWE Family CWE-924 | 2 | 1 | None recorded |
| `CWE-93` | CWE Family CWE-93 | 2 | 1 | None recorded |
| `CWE-124` | CWE Family CWE-124 | 2 | 2 | None recorded |
| `CWE-172` | CWE Family CWE-172 | 2 | 1 | None recorded |
| `CWE-88` | CWE Family CWE-88 | 2 | 1 | None recorded |
| `CWE-1286` | CWE Family CWE-1286 | 2 | 1 | None recorded |
| `CWE-920` | CWE Family CWE-920 | 2 | 1 | None recorded |
| `CWE-1325` | CWE Family CWE-1325 | 2 | 2 | None recorded |
| `CWE-212` | CWE Family CWE-212 | 2 | 1 | None recorded |
| `CWE-680` | CWE Family CWE-680 | 2 | 1 | None recorded |
| `CWE-340` | CWE Family CWE-340 | 2 | 1 | None recorded |
| `CWE-923` | CWE Family CWE-923 | 2 | 1 | None recorded |
| `CWE-407` | CWE Family CWE-407 | 2 | 1 | None recorded |
| `CWE-664` | CWE Family CWE-664 | 2 | 1 | None recorded |
| `CWE-366` | CWE Family CWE-366 | 2 | 1 | None recorded |
| `CWE-820` | CWE Family CWE-820 | 2 | 1 | None recorded |
| `CWE-346` | CWE Family CWE-346 | 2 | 1 | None recorded |
| `CWE-1289` | CWE Family CWE-1289 | 2 | 0 | None recorded |
| `CWE-1285` | CWE Family CWE-1285 | 2 | 0 | None recorded |
| `CWE-1395` | CWE Family CWE-1395 | 2 | 0 | None recorded |
| `CWE-306` | CWE Family CWE-306 | 2 | 0 | None recorded |
| `CWE-460` | CWE Family CWE-460 | 2 | 0 | None recorded |
| `CWE-363` | CWE Family CWE-363 | 2 | 0 | None recorded |
| `CWE-451` | CWE Family CWE-451 | 2 | 0 | None recorded |
| `CWE-223` | CWE Family CWE-223 | 2 | 0 | None recorded |
| `CWE-409` | CWE Family CWE-409 | 2 | 0 | None recorded |
| `CWE-307` | CWE Family CWE-307 | 2 | 0 | None recorded |
| `CWE-666` | CWE Family CWE-666 | 2 | 0 | None recorded |
| `CWE-204` | CWE Family CWE-204 | 2 | 0 | None recorded |
| `CWE-15` | CWE Family CWE-15 | 2 | 0 | None recorded |
| `CWE-1104` | CWE Family CWE-1104 | 2 | 0 | None recorded |
| `CWE-657` | CWE Family CWE-657 | 2 | 0 | None recorded |
| `CWE-427` | CWE Family CWE-427 | 2 | 0 | None recorded |
| `CWE-916` | CWE Family CWE-916 | 1 | 0 | None recorded |
| `CWE-298` | CWE Family CWE-298 | 1 | 0 | None recorded |
| `CWE-142` | CWE Family CWE-142 | 1 | 1 | None recorded |
| `CWE-30` | CWE Family CWE-30 | 1 | 1 | None recorded |
| `CWE-254` | CWE Family CWE-254 | 1 | 0 | None recorded |
| `CWE-187` | CWE Family CWE-187 | 1 | 1 | None recorded |
| `CWE-178` | CWE Family CWE-178 | 1 | 0 | None recorded |
| `CWE-838` | CWE Family CWE-838 | 1 | 1 | None recorded |
| `CWE-304` | CWE Family CWE-304 | 1 | 1 | None recorded |
| `CWE-320` | CWE Family CWE-320 | 1 | 1 | None recorded |
| `CWE-434` | CWE Family CWE-434 | 1 | 1 | None recorded |
| `CWE-268` | CWE Family CWE-268 | 1 | 0 | None recorded |
| `CWE-641` | CWE Family CWE-641 | 1 | 1 | None recorded |
| `CWE-359` | CWE Family CWE-359 | 1 | 1 | None recorded |
| `CWE-349` | CWE Family CWE-349 | 1 | 1 | None recorded |
| `CWE-544` | CWE Family CWE-544 | 1 | 1 | None recorded |
| `CWE-177` | CWE Family CWE-177 | 1 | 1 | None recorded |
| `CWE-1335` | CWE Family CWE-1335 | 1 | 1 | None recorded |
| `CWE-606` | CWE Family CWE-606 | 1 | 1 | None recorded |
| `CWE-300` | CWE Family CWE-300 | 1 | 0 | None recorded |
| `CWE-392` | CWE Family CWE-392 | 1 | 1 | None recorded |
| `CWE-115` | CWE Family CWE-115 | 1 | 1 | None recorded |
| `CWE-324` | CWE Family CWE-324 | 1 | 1 | None recorded |
| `CWE-312` | CWE Family CWE-312 | 1 | 1 | None recorded |
| `CWE-590` | CWE Family CWE-590 | 1 | 1 | None recorded |
| `CWE-322` | CWE Family CWE-322 | 1 | 1 | None recorded |
| `CWE-567` | CWE Family CWE-567 | 1 | 1 | None recorded |
| `CWE-364` | CWE Family CWE-364 | 1 | 0 | None recorded |
| `CWE-197` | CWE Family CWE-197 | 1 | 0 | None recorded |
| `CWE-244` | CWE Family CWE-244 | 1 | 0 | None recorded |
| `CWE-757` | CWE Family CWE-757 | 1 | 1 | None recorded |
| `CWE-826` | CWE Family CWE-826 | 1 | 1 | None recorded |
| `CWE-696` | CWE Family CWE-696 | 1 | 0 | None recorded |
| `CWE-348` | CWE Family CWE-348 | 1 | 0 | None recorded |
| `CWE-514` | CWE Family CWE-514 | 1 | 1 | None recorded |
| `CWE-480` | CWE Family CWE-480 | 1 | 1 | None recorded |
| `CWE-123` | CWE Family CWE-123 | 1 | 1 | None recorded |
| `CWE-280` | CWE Family CWE-280 | 1 | 1 | None recorded |
| `CWE-1058` | CWE Family CWE-1058 | 1 | 1 | None recorded |
| `CWE-823` | CWE Family CWE-823 | 1 | 1 | None recorded |
| `CWE-386` | CWE Family CWE-386 | 1 | 1 | None recorded |
| `CWE-393` | CWE Family CWE-393 | 1 | 1 | None recorded |
| `CWE-405` | CWE Family CWE-405 | 1 | 1 | None recorded |
| `CWE-250` | CWE Family CWE-250 | 1 | 0 | None recorded |
| `CWE-829` | CWE Family CWE-829 | 1 | 0 | None recorded |
| `CWE-441` | CWE Family CWE-441 | 1 | 0 | None recorded |
| `CWE-406` | CWE Family CWE-406 | 1 | 0 | None recorded |
| `CWE-733` | CWE Family CWE-733 | 1 | 0 | None recorded |
| `CWE-613` | CWE Family CWE-613 | 1 | 0 | None recorded |
| `CWE-768` | CWE Family CWE-768 | 1 | 0 | None recorded |
| `CWE-611` | CWE Family CWE-611 | 1 | 0 | None recorded |
| `CWE-283` | CWE Family CWE-283 | 1 | 0 | None recorded |
| `CWE-573` | CWE Family CWE-573 | 1 | 0 | None recorded |
| `CWE-642` | CWE Family CWE-642 | 1 | 0 | None recorded |
| `CWE-494` | CWE Family CWE-494 | 1 | 0 | None recorded |
| `CWE-549` | CWE Family CWE-549 | 1 | 0 | None recorded |
| `CWE-183` | CWE Family CWE-183 | 1 | 0 | None recorded |
| `CWE-610` | CWE Family CWE-610 | 1 | 0 | None recorded |
| `CWE-673` | CWE Family CWE-673 | 1 | 0 | None recorded |
| `CWE-489` | CWE Family CWE-489 | 1 | 0 | None recorded |
| `CWE-159` | CWE Family CWE-159 | 1 | 0 | None recorded |
| `CWE-636` | CWE Family CWE-636 | 1 | 0 | None recorded |
| `CWE-278` | CWE Family CWE-278 | 1 | 0 | None recorded |
| `CWE-214` | CWE Family CWE-214 | 1 | 0 | None recorded |
| `CWE-647` | CWE Family CWE-647 | 1 | 0 | None recorded |
| `CWE-1336` | CWE Family CWE-1336 | 1 | 0 | None recorded |
| `CWE-226` | CWE Family CWE-226 | 1 | 0 | None recorded |
| `CWE-783` | CWE Family CWE-783 | 1 | 0 | None recorded |
| `CWE-708` | CWE Family CWE-708 | 1 | 0 | None recorded |
| `CWE-198` | CWE Family CWE-198 | 1 | 0 | None recorded |
| `CWE-147` | CWE Family CWE-147 | 1 | 0 | None recorded |
| `CWE-23` | CWE Family CWE-23 | 1 | 0 | None recorded |
| `CWE-323` | CWE Family CWE-323 | 1 | 0 | None recorded |
| `CWE-113` | CWE Family CWE-113 | 1 | 0 | None recorded |
| `CWE-67` | CWE Family CWE-67 | 1 | 0 | None recorded |
| `CWE-41` | CWE Family CWE-41 | 1 | 0 | None recorded |
| `CWE-334` | CWE Family CWE-334 | 1 | 0 | None recorded |
| `CWE-25` | CWE Family CWE-25 | 1 | 0 | None recorded |
| `CWE-184` | CWE Family CWE-184 | 1 | 0 | None recorded |
| `CWE-475` | CWE Family CWE-475 | 1 | 0 | None recorded |
| `CWE-915` | CWE Family CWE-915 | 1 | 0 | None recorded |
| `CWE-195` | CWE Family CWE-195 | 1 | 0 | None recorded |
| `CWE-762` | CWE Family CWE-762 | 1 | 0 | None recorded |
| `CWE-180` | CWE Family CWE-180 | 1 | 0 | None recorded |
| `CWE-155` | CWE Family CWE-155 | 1 | 0 | None recorded |
| `CWE-436` | CWE Family CWE-436 | 1 | 0 | None recorded |

## Detailed Breakdown by Project

### UNKNOWN — Unstated or Legacy Advisory Without CWE Classification
- **Count**: 10327
- **With Fix SHA**: 9243
- **Project Distribution**: `git`: 1, `git-upstream`: 4, `glibc`: 3, `linux`: 273, `linux-cna`: 9233, `openssh`: 2, `openssl`: 19, `openssl-upstream`: 20, `postgresql`: 30, `qemu`: 3, `rustsec`: 710, `sqlite`: 3, `sqlite-upstream`: 11, `systemd-upstream`: 15
- **Sample CVEs**: CVE-1999-0804, CVE-1999-0862, CVE-1999-1018, CVE-1999-1166, CVE-1999-1341, CVE-2000-0227, CVE-2000-0274, CVE-2000-0335, CVE-2000-0344, CVE-2000-0506

### CWE-476 — NULL Pointer Dereference
- **Count**: 2097
- **With Fix SHA**: 2063
- **Project Distribution**: `curl-upstream`: 1, `linux`: 1, `linux-cna`: 2031, `openssl`: 5, `openssl-upstream`: 27, `rustsec`: 19, `sqlite-upstream`: 12, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2004-0079, CVE-2005-2459, CVE-2006-4343, CVE-2008-1672, CVE-2009-1386, CVE-2009-1387, CVE-2014-0198, CVE-2014-3470, CVE-2015-3194, CVE-2016-7052

### CWE-416 — Use After Free
- **Count**: 1430
- **With Fix SHA**: 1372
- **Project Distribution**: `curl-upstream`: 11, `linux`: 1, `linux-cna`: 1354, `openssl-upstream`: 6, `rustsec`: 50, `sqlite-upstream`: 6, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2006-4997, CVE-2016-5421, CVE-2016-6309, CVE-2016-8623, CVE-2018-16840, CVE-2019-25162, CVE-2019-5018, CVE-2020-11656, CVE-2020-13630, CVE-2020-13871

### CWE-401 — Missing Release of Memory after Effective Lifetime (Memory Leak)
- **Count**: 1117
- **With Fix SHA**: 1111
- **Project Distribution**: `linux`: 2, `linux-cna`: 1107, `openssl`: 1, `openssl-upstream`: 2, `rustsec`: 3, `sqlite-upstream`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2005-3119, CVE-2005-3181, CVE-2009-1378, CVE-2016-6304, CVE-2019-20386, CVE-2020-36777, CVE-2020-36786, CVE-2020-36790, CVE-2021-4453, CVE-2021-45346

### CWE-125 — Out-of-bounds Read
- **Count**: 658
- **With Fix SHA**: 600
- **Project Distribution**: `curl-upstream`: 6, `git-upstream`: 1, `linux-cna`: 579, `openssl`: 1, `openssl-upstream`: 17, `rustsec`: 49, `sqlite-upstream`: 4, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2004-0112, CVE-2014-0160, CVE-2016-2180, CVE-2016-6306, CVE-2017-10989, CVE-2017-3731, CVE-2017-3737, CVE-2017-8818, CVE-2018-11233, CVE-2018-16842

### CWE-667 — CWE Family CWE-667
- **Count**: 530
- **With Fix SHA**: 525
- **Project Distribution**: `linux`: 4, `linux-cna`: 524, `openssl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2005-2456, CVE-2005-3847, CVE-2006-4342, CVE-2006-5158, CVE-2020-36775, CVE-2021-46927, CVE-2021-46987, CVE-2021-47038, CVE-2021-47041, CVE-2021-47055

### CWE-787 — Out-of-bounds Write
- **Count**: 514
- **With Fix SHA**: 479
- **Project Distribution**: `linux-cna`: 467, `openssl-upstream`: 13, `qemu`: 2, `rustsec`: 29, `sqlite-upstream`: 1, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2007-1320, CVE-2007-5730, CVE-2016-2182, CVE-2016-6303, CVE-2017-9445, CVE-2019-6454, CVE-2020-15358, CVE-2021-46931, CVE-2021-47132, CVE-2021-47138

### CWE-362 — Concurrent Execution using Shared Resource (Race Condition)
- **Count**: 459
- **With Fix SHA**: 397
- **Project Distribution**: `linux`: 1, `linux-cna`: 397, `openssl`: 1, `openssl-upstream`: 4, `rustsec`: 54, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2006-0039, CVE-2010-3864, CVE-2010-5298, CVE-2014-3509, CVE-2015-1791, CVE-2015-3196, CVE-2018-1049, CVE-2018-15687, CVE-2021-46925, CVE-2021-46982

### CWE-908 — CWE Family CWE-908
- **Count**: 311
- **With Fix SHA**: 278
- **Project Distribution**: `linux-cna`: 278, `rustsec`: 33
- **Sample CVEs**: CVE-2021-47056, CVE-2021-47096, CVE-2021-47101, CVE-2021-47136, CVE-2021-47139, CVE-2021-47297, CVE-2021-47339, CVE-2021-47424, CVE-2021-47446, CVE-2021-47451

### CWE-415 — CWE Family CWE-415
- **Count**: 248
- **With Fix SHA**: 216
- **Project Distribution**: `curl-upstream`: 7, `linux-cna`: 206, `openssl`: 1, `openssl-upstream`: 3, `rustsec`: 31
- **Sample CVEs**: CVE-2003-0545, CVE-2016-8618, CVE-2016-8619, CVE-2019-5481, CVE-2020-36785, CVE-2021-22945, CVE-2021-46938, CVE-2021-46979, CVE-2021-47082, CVE-2021-47123

### CWE-190 — Integer Overflow or Wraparound
- **Count**: 164
- **With Fix SHA**: 127
- **Project Distribution**: `linux`: 1, `linux-cna`: 124, `openssl-upstream`: 4, `rustsec`: 29, `sqlite-upstream`: 6
- **Sample CVEs**: CVE-2004-2013, CVE-2016-2105, CVE-2016-2177, CVE-2018-20346, CVE-2018-20506, CVE-2019-1551, CVE-2020-13434, CVE-2021-23840, CVE-2021-46940, CVE-2021-47098

### CWE-129 — CWE Family CWE-129
- **Count**: 156
- **With Fix SHA**: 151
- **Project Distribution**: `linux-cna`: 151, `rustsec`: 4, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2020-36776, CVE-2021-4439, CVE-2021-46984, CVE-2021-47065, CVE-2021-47135, CVE-2021-47449, CVE-2021-47547, CVE-2021-47548, CVE-2022-35737, CVE-2022-48702

### CWE-770 — Allocation of Resources Without Limits or Throttling
- **Count**: 117
- **With Fix SHA**: 66
- **Project Distribution**: `curl-upstream`: 5, `linux-cna`: 52, `openssl-upstream`: 8, `rustsec`: 49, `systemd-upstream`: 3
- **Sample CVEs**: CVE-2018-16864, CVE-2018-16865, CVE-2021-33910, CVE-2021-47057, CVE-2021-47130, CVE-2021-47137, CVE-2021-47170, CVE-2021-47182, CVE-2021-47374, CVE-2021-47551

### CWE-617 — CWE Family CWE-617
- **Count**: 111
- **With Fix SHA**: 101
- **Project Distribution**: `linux-cna`: 101, `rustsec`: 10
- **Sample CVEs**: CVE-2021-47305, CVE-2021-47315, CVE-2021-47351, CVE-2022-48633, CVE-2022-49154, CVE-2022-49158, CVE-2022-49171, CVE-2022-49325, CVE-2022-49347, CVE-2022-49409

### CWE-835 — CWE Family CWE-835
- **Count**: 100
- **With Fix SHA**: 90
- **Project Distribution**: `curl-upstream`: 3, `linux-cna`: 85, `openssl-upstream`: 2, `rustsec`: 9, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2017-15908, CVE-2021-4044, CVE-2021-47159, CVE-2021-47406, CVE-2021-47448, CVE-2021-47617, CVE-2022-0778, CVE-2022-27781, CVE-2022-48630, CVE-2022-48635

### CWE-369 — CWE Family CWE-369
- **Count**: 98
- **With Fix SHA**: 93
- **Project Distribution**: `linux-cna`: 93, `rustsec`: 4, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2019-16168, CVE-2021-46915, CVE-2021-47080, CVE-2021-47363, CVE-2021-47495, CVE-2021-47584, CVE-2021-47606, CVE-2021-47641, CVE-2022-49294, CVE-2022-49330

### CWE-119 — Memory Corruption / Buffer Boundary Error
- **Count**: 90
- **With Fix SHA**: 24
- **Project Distribution**: `curl`: 1, `git-upstream`: 2, `linux`: 6, `linux-cna`: 19, `openssl`: 4, `openssl-upstream`: 9, `postgresql`: 2, `qemu`: 2, `rustsec`: 44, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2002-1401, CVE-2005-0247, CVE-2005-3185, CVE-2006-1368, CVE-2006-1857, CVE-2006-3738, CVE-2006-6106, CVE-2007-0005, CVE-2007-1217, CVE-2007-1592

### CWE-20 — Improper Input Validation
- **Count**: 78
- **With Fix SHA**: 7
- **Project Distribution**: `curl-upstream`: 1, `git-upstream`: 1, `linux`: 9, `openssl`: 4, `openssl-upstream`: 8, `rustsec`: 51, `sqlite-upstream`: 2, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2005-0209, CVE-2005-1761, CVE-2005-3055, CVE-2006-0744, CVE-2006-1522, CVE-2006-1528, CVE-2006-1858, CVE-2007-2172, CVE-2007-2764, CVE-2008-5077

### CWE-400 — Uncontrolled Resource Consumption (DoS)
- **Count**: 74
- **With Fix SHA**: 26
- **Project Distribution**: `git-upstream`: 1, `linux-cna`: 24, `openssl-upstream`: 1, `rustsec`: 47, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2016-6307, CVE-2017-15298, CVE-2021-4440, CVE-2021-47010, CVE-2021-47023, CVE-2021-47238, CVE-2021-47284, CVE-2021-47295, CVE-2021-47313, CVE-2021-47329

### CWE-120 — Classic Buffer Overflow
- **Count**: 72
- **With Fix SHA**: 55
- **Project Distribution**: `git-upstream`: 1, `linux`: 1, `linux-cna`: 53, `openssl-upstream`: 3, `rustsec`: 13, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2006-2935, CVE-2014-0195, CVE-2018-15688, CVE-2021-3711, CVE-2021-47040, CVE-2021-47107, CVE-2021-47172, CVE-2021-47347, CVE-2021-47485, CVE-2021-47609

### CWE-191 — CWE Family CWE-191
- **Count**: 58
- **With Fix SHA**: 53
- **Project Distribution**: `linux-cna`: 53, `rustsec`: 5
- **Sample CVEs**: CVE-2021-46951, CVE-2021-47555, CVE-2022-48643, CVE-2022-48665, CVE-2022-48804, CVE-2022-48828, CVE-2022-49199, CVE-2022-49208, CVE-2022-49278, CVE-2022-49280

### CWE-200 — Exposure of Sensitive Information
- **Count**: 55
- **With Fix SHA**: 17
- **Project Distribution**: `curl-upstream`: 8, `linux-cna`: 4, `openssl-upstream`: 14, `qemu`: 1, `rustsec`: 27, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2008-2004, CVE-2014-3508, CVE-2015-3193, CVE-2015-3195, CVE-2015-3197, CVE-2016-0701, CVE-2016-0702, CVE-2016-0703, CVE-2016-0704, CVE-2016-0800

### CWE-674 — CWE Family CWE-674
- **Count**: 55
- **With Fix SHA**: 38
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 34, `openssl-upstream`: 1, `rustsec`: 17, `sqlite-upstream`: 1, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2018-0739, CVE-2019-19645, CVE-2020-8285, CVE-2021-3997, CVE-2021-47465, CVE-2022-49782, CVE-2022-50118, CVE-2022-50407, CVE-2023-52761, CVE-2023-52986

### CWE-367 — CWE Family CWE-367
- **Count**: 53
- **With Fix SHA**: 34
- **Project Distribution**: `linux-cna`: 34, `rustsec`: 19
- **Sample CVEs**: CVE-2021-47280, CVE-2023-52478, CVE-2024-26974, CVE-2024-42107, CVE-2024-43882, CVE-2024-49998, CVE-2024-50220, CVE-2024-50234, CVE-2025-21746, CVE-2025-21958

### CWE-22 — CWE Family CWE-22
- **Count**: 51
- **With Fix SHA**: 4
- **Project Distribution**: `curl-upstream`: 2, `git-upstream`: 2, `linux-cna`: 2, `rustsec`: 45
- **Sample CVEs**: CVE-2016-0754, CVE-2018-11235, CVE-2023-27534, CVE-2023-52623, CVE-2024-32002, CVE-2024-47742, GHSA-2cv4-cqwr-gwf7, GHSA-2cvj-g5r5-jrrg, GHSA-2m67-cxxq-c3h8, GHSA-3227-r97m-8j95

### CWE-399 — Resource Management Errors
- **Count**: 47
- **With Fix SHA**: 4
- **Project Distribution**: `linux`: 24, `openssl`: 14, `openssl-upstream`: 8, `postgresql`: 1
- **Sample CVEs**: CVE-2005-0210, CVE-2005-0756, CVE-2005-2099, CVE-2005-2548, CVE-2005-2708, CVE-2005-2709, CVE-2005-2800, CVE-2005-3784, CVE-2005-3806, CVE-2005-3857

### CWE-754 — CWE Family CWE-754
- **Count**: 47
- **With Fix SHA**: 39
- **Project Distribution**: `linux-cna`: 33, `openssl-upstream`: 5, `rustsec`: 8, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2019-19646, CVE-2021-46909, CVE-2021-46934, CVE-2021-47007, CVE-2021-47014, CVE-2021-47227, CVE-2023-52678, CVE-2023-5678, CVE-2024-35785, CVE-2024-36481

### CWE-193 — CWE Family CWE-193
- **Count**: 46
- **With Fix SHA**: 41
- **Project Distribution**: `linux`: 1, `linux-cna`: 40, `rustsec`: 4, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2001-1391, CVE-2021-47046, CVE-2021-47373, CVE-2022-3821, CVE-2022-48672, CVE-2022-48732, CVE-2022-49077, CVE-2022-49365, CVE-2022-50428, CVE-2023-53143

### CWE-295 — Improper Certificate Validation
- **Count**: 38
- **With Fix SHA**: 23
- **Project Distribution**: `curl-upstream`: 15, `openssl`: 3, `openssl-upstream`: 8, `rustsec`: 11, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2009-2409, CVE-2009-3555, CVE-2009-3767, CVE-2016-9952, CVE-2018-21029, CVE-2019-1552, CVE-2021-22924, CVE-2021-22926, CVE-2021-3450, CVE-2022-1343

### CWE-459 — CWE Family CWE-459
- **Count**: 35
- **With Fix SHA**: 32
- **Project Distribution**: `linux-cna`: 31, `openssl-upstream`: 1, `rustsec`: 3
- **Sample CVEs**: CVE-2021-47110, CVE-2021-47143, CVE-2021-47178, CVE-2021-47365, CVE-2022-1473, CVE-2022-48893, CVE-2022-49012, CVE-2022-49028, CVE-2023-52617, CVE-2023-52929

### CWE-248 — CWE Family CWE-248
- **Count**: 32
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 32
- **Sample CVEs**: GHSA-29x4-r6jv-ff4w, GHSA-2gw2-qgjg-xh6p, GHSA-46wq-28cx-mhw4, GHSA-5873-6fwq-463f, GHSA-5v93-9mqw-p9mh, GHSA-6wr5-jmpr-mjcx, GHSA-8xff-473h-f863, GHSA-9qjc-q7hw-vw5r, GHSA-9qrf-6whp-92w3, GHSA-f2jv-wjjc-2c94

### CWE-863 — CWE Family CWE-863
- **Count**: 30
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 27, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2019-3842, CVE-2024-36963, CVE-2026-40224, GHSA-23rx-c3g5-hv9w, GHSA-27vp-2mmc-vmh3, GHSA-2f98-6626-h2p2, GHSA-2ppx-66jv-wpw5, GHSA-4c8g-jvcx-v4hv, GHSA-4f9v-jpx9-mjvw, GHSA-66r2-5gwj-gxm2

### CWE-310 — Cryptographic Issues
- **Count**: 27
- **With Fix SHA**: 1
- **Project Distribution**: `linux`: 1, `openssl`: 13, `openssl-upstream`: 13
- **Sample CVEs**: CVE-2006-1056, CVE-2006-4339, CVE-2007-5502, CVE-2008-7270, CVE-2009-3765, CVE-2009-3766, CVE-2010-0742, CVE-2010-0928, CVE-2011-1945, CVE-2011-4108

### CWE-131 — CWE Family CWE-131
- **Count**: 26
- **With Fix SHA**: 16
- **Project Distribution**: `curl`: 1, `curl-upstream`: 6, `linux-cna`: 11, `rustsec`: 8
- **Sample CVEs**: CVE-2005-0490, CVE-2016-7167, CVE-2016-8617, CVE-2017-8816, CVE-2018-14618, CVE-2018-16839, CVE-2019-5435, CVE-2021-46943, CVE-2022-48889, CVE-2024-26721

### CWE-122 — CWE Family CWE-122
- **Count**: 25
- **With Fix SHA**: 9
- **Project Distribution**: `curl`: 1, `curl-upstream`: 9, `rustsec`: 10, `sqlite-upstream`: 5
- **Sample CVEs**: CVE-2006-1061, CVE-2016-8620, CVE-2016-8622, CVE-2017-9502, CVE-2018-0500, CVE-2018-1000120, CVE-2018-1000300, CVE-2019-5436, CVE-2019-5482, CVE-2023-38545

### CWE-668 — CWE Family CWE-668
- **Count**: 23
- **With Fix SHA**: 18
- **Project Distribution**: `git-upstream`: 1, `linux-cna`: 18, `rustsec`: 4
- **Sample CVEs**: CVE-2021-46906, CVE-2021-46917, CVE-2021-46921, CVE-2021-46923, CVE-2021-46935, CVE-2021-46937, CVE-2021-47401, CVE-2022-24975, CVE-2022-48757, CVE-2022-49509

### CWE-772 — CWE Family CWE-772
- **Count**: 22
- **With Fix SHA**: 20
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 19, `rustsec`: 2
- **Sample CVEs**: CVE-2021-47283, CVE-2021-47389, CVE-2022-50189, CVE-2023-53152, CVE-2023-53199, CVE-2024-2398, CVE-2024-35821, CVE-2024-47733, CVE-2024-53074, CVE-2025-71232

### CWE-347 — CWE Family CWE-347
- **Count**: 22
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1, `rustsec`: 21
- **Sample CVEs**: CVE-2025-15469, GHSA-2x3r-hwv5-p32x, GHSA-3vmh-33xr-9cqh, GHSA-5j98-2g5x-46v6, GHSA-5x2r-hc65-25f9, GHSA-75rw-34q6-72cr, GHSA-8m7c-8m39-rv4x, GHSA-gq4h-3grw-2rhv, GHSA-pf4j-pf3w-95f9, GHSA-r38m-44fw-h886

### CWE-327 — CWE Family CWE-327
- **Count**: 21
- **With Fix SHA**: 7
- **Project Distribution**: `openssl`: 1, `openssl-upstream`: 7, `rustsec`: 13
- **Sample CVEs**: CVE-2005-2946, CVE-2018-0734, CVE-2018-0735, CVE-2018-0737, CVE-2019-1543, CVE-2021-23839, CVE-2022-1434, CVE-2022-2097, GHSA-253q-9q78-63x4, GHSA-6698-mhxx-r84g

### CWE-126 — CWE Family CWE-126
- **Count**: 21
- **With Fix SHA**: 15
- **Project Distribution**: `curl-upstream`: 15, `rustsec`: 5, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2013-2174, CVE-2014-3707, CVE-2015-3237, CVE-2016-8621, CVE-2016-9953, CVE-2017-1000100, CVE-2017-1000101, CVE-2017-1000254, CVE-2017-1000257, CVE-2017-7407

### CWE-264 — Permissions, Privileges, and Access Controls
- **Count**: 19
- **With Fix SHA**: 1
- **Project Distribution**: `linux`: 8, `openssl`: 3, `postgresql`: 5, `qemu`: 2, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2002-2254, CVE-2005-0244, CVE-2005-2492, CVE-2005-2555, CVE-2005-3179, CVE-2005-3257, CVE-2005-3273, CVE-2006-0553, CVE-2006-1524, CVE-2006-4572

### CWE-79 — CWE Family CWE-79
- **Count**: 19
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 18, `sqlite`: 1
- **Sample CVEs**: CVE-2007-1231, GHSA-54m3-5fxr-2f3j, GHSA-g5x8-v2ch-gj2g, GHSA-gprj-6m2f-j9hx, GHSA-gpxg-fx2g-qxj2, GHSA-mphm-gqh9-q59x, GHSA-qqwr-j9mm-fhw6, GHSA-rjf8-2wcw-f6mp, GHSA-rwfq-v4hq-h7fg, GHSA-v9fg-3cr2-277j

### CWE-305 — CWE Family CWE-305
- **Count**: 19
- **With Fix SHA**: 12
- **Project Distribution**: `curl-upstream`: 19
- **Sample CVEs**: CVE-2014-0015, CVE-2014-0138, CVE-2015-3143, CVE-2015-3148, CVE-2015-3236, CVE-2016-0755, CVE-2016-5419, CVE-2016-5420, CVE-2016-7141, CVE-2017-7468

### CWE-269 — CWE Family CWE-269
- **Count**: 19
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 12, `systemd-upstream`: 6
- **Sample CVEs**: CVE-2017-1000082, CVE-2018-16888, CVE-2019-3843, CVE-2020-13776, CVE-2023-26604, CVE-2026-29111, CVE-2026-46333, GHSA-838h-jqp6-cf2f, GHSA-g29h-pfmp-qp9r, GHSA-h4hq-rgvh-wh27

### CWE-203 — CWE Family CWE-203
- **Count**: 18
- **With Fix SHA**: 10
- **Project Distribution**: `linux-cna`: 5, `openssl`: 1, `openssl-upstream`: 6, `rustsec`: 6
- **Sample CVEs**: CVE-2003-0078, CVE-2016-2178, CVE-2018-5407, CVE-2019-1559, CVE-2019-1563, CVE-2020-1968, CVE-2021-47226, CVE-2022-4304, CVE-2022-48730, CVE-2024-47678

### CWE-755 — CWE Family CWE-755
- **Count**: 18
- **With Fix SHA**: 11
- **Project Distribution**: `linux-cna`: 9, `rustsec`: 7, `sqlite-upstream`: 2
- **Sample CVEs**: CVE-2019-19924, CVE-2019-20218, CVE-2021-46928, CVE-2022-48673, CVE-2024-26584, CVE-2024-26911, CVE-2024-50001, CVE-2024-50002, CVE-2024-50176, CVE-2024-50202

### CWE-662 — CWE Family CWE-662
- **Count**: 18
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 2, `rustsec`: 15
- **Sample CVEs**: CVE-2021-46939, CVE-2023-28320, CVE-2026-53277, RUSTSEC-2019-0013, RUSTSEC-2020-0090, RUSTSEC-2020-0096, RUSTSEC-2020-0098, RUSTSEC-2020-0099, RUSTSEC-2020-0101, RUSTSEC-2020-0102

### CWE-1284 — CWE Family CWE-1284
- **Count**: 18
- **With Fix SHA**: 10
- **Project Distribution**: `linux-cna`: 9, `openssl-upstream`: 1, `rustsec`: 8
- **Sample CVEs**: CVE-2021-47251, CVE-2022-50020, CVE-2024-35963, CVE-2024-35964, CVE-2024-35965, CVE-2024-38659, CVE-2024-56716, CVE-2025-39700, CVE-2026-52905, CVE-2026-75806

### CWE-345 — CWE Family CWE-345
- **Count**: 18
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 18
- **Sample CVEs**: GHSA-33f5-2c5q-wgwj, GHSA-37wc-h8xc-5hc4, GHSA-45x7-px36-x8w8, GHSA-4v58-8p28-2rq3, GHSA-63x8-x938-vx33, GHSA-799f-29jm-gr6c, GHSA-83hf-93m4-rgwq, GHSA-fvvm-949w-qj4w, GHSA-g3qg-6746-3mg9, GHSA-gvjc-3w7c-92jx

### CWE-252 — CWE Family CWE-252
- **Count**: 17
- **With Fix SHA**: 13
- **Project Distribution**: `linux-cna`: 13, `rustsec`: 4
- **Sample CVEs**: CVE-2021-47360, CVE-2023-52680, CVE-2023-52687, CVE-2023-52692, CVE-2023-52797, CVE-2023-53070, CVE-2024-39492, CVE-2024-42067, CVE-2024-42068, CVE-2025-22026

### CWE-843 — CWE Family CWE-843
- **Count**: 17
- **With Fix SHA**: 5
- **Project Distribution**: `linux-cna`: 3, `openssl-upstream`: 2, `rustsec`: 12
- **Sample CVEs**: CVE-2023-0286, CVE-2024-49860, CVE-2024-6119, CVE-2026-31502, CVE-2026-43038, GHSA-cm3g-qm4h-xm6m, GHSA-h395-gr6q-cpjc, GHSA-v2p5-q653-9j99, RUSTSEC-2019-0036, RUSTSEC-2023-0006

### CWE-287 — Improper Authentication
- **Count**: 16
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 1, `openssl`: 5, `openssl-upstream`: 1, `postgresql`: 1, `rustsec`: 8
- **Sample CVEs**: CVE-2007-6601, CVE-2009-0129, CVE-2009-0591, CVE-2009-0653, CVE-2009-1390, CVE-2010-4252, CVE-2023-2975, CVE-2025-15224, GHSA-857q-xmph-p2v5, GHSA-gh9f-6xm2-c4j2

### CWE-665 — CWE Family CWE-665
- **Count**: 16
- **With Fix SHA**: 11
- **Project Distribution**: `linux-cna`: 11, `rustsec`: 4, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2020-11655, CVE-2021-46932, CVE-2021-47194, CVE-2023-52452, CVE-2024-38558, CVE-2024-39301, CVE-2024-39485, CVE-2024-42078, CVE-2024-44947, CVE-2024-45018

### CWE-670 — CWE Family CWE-670
- **Count**: 16
- **With Fix SHA**: 8
- **Project Distribution**: `linux-cna`: 8, `rustsec`: 8
- **Sample CVEs**: CVE-2022-49393, CVE-2023-52742, CVE-2023-52781, CVE-2024-47745, CVE-2024-53134, CVE-2025-38291, CVE-2026-98051, CVE-2026-98164, GHSA-4chv-4c6w-w254, GHSA-hj9r-8pfm-rmjj

### CWE-918 — CWE Family CWE-918
- **Count**: 16
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 16
- **Sample CVEs**: GHSA-3jvj-v6w2-h948, GHSA-5q9x-554g-9jgg, GHSA-6v2g-fpxh-pmmh, GHSA-7723-35v7-qcxw, GHSA-7gmj-67g7-phm9, GHSA-83pc-3rw9-qpwj, GHSA-88gh-2526-gfrr, GHSA-96ff-gc8g-wpvg, GHSA-97vg-427p-8hx5, GHSA-c9xm-49cp-xcr9

### CWE-189 — CWE Family CWE-189
- **Count**: 15
- **With Fix SHA**: 1
- **Project Distribution**: `curl`: 1, `linux`: 3, `openssl`: 6, `openssl-upstream`: 3, `postgresql`: 2
- **Sample CVEs**: CVE-2004-2731, CVE-2005-4077, CVE-2006-6058, CVE-2007-2875, CVE-2007-4769, CVE-2007-4995, CVE-2007-5135, CVE-2007-6067, CVE-2008-0891, CVE-2009-0789

### CWE-824 — CWE Family CWE-824
- **Count**: 15
- **With Fix SHA**: 12
- **Project Distribution**: `linux-cna`: 12, `rustsec`: 3
- **Sample CVEs**: CVE-2021-47602, CVE-2024-26799, CVE-2024-36966, CVE-2024-42275, CVE-2024-46844, CVE-2024-49938, CVE-2024-50087, CVE-2024-50088, CVE-2024-57943, CVE-2025-37995

### CWE-77 — CWE Family CWE-77
- **Count**: 15
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 14
- **Sample CVEs**: CVE-2023-52624, GHSA-5wp8-q9mx-8jx8, GHSA-6fgx-x7m2-74qm, GHSA-73v2-rxqp-7q4f, GHSA-ccj3-5p93-8p42, GHSA-h5q3-3v5q-v5j8, GHSA-m2gf-x3f6-8hq3, GHSA-m3c4-prhw-mrx6, GHSA-m4f9-c775-wg56, GHSA-xrv8-2pf5-f3q7

### CWE-444 — CWE Family CWE-444
- **Count**: 14
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 13
- **Sample CVEs**: CVE-2014-8150, GHSA-262p-vjx5-45xh, GHSA-3qmp-g57h-rxf2, GHSA-f9v3-j2m7-4hpg, GHSA-xhj4-vrgc-hr34, RUSTSEC-2020-0008, RUSTSEC-2020-0031, RUSTSEC-2020-0093, RUSTSEC-2021-0020, RUSTSEC-2021-0078

### CWE-59 — CWE Family CWE-59
- **Count**: 14
- **With Fix SHA**: 2
- **Project Distribution**: `git-upstream`: 1, `linux-cna`: 1, `rustsec`: 10, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2017-18078, CVE-2018-6954, CVE-2021-21300, CVE-2024-46744, GHSA-66fx-fqv6-5wwx, GHSA-67hm-27mx-9cg7, GHSA-6xx4-9wp6-65p7, GHSA-7cr3-h577-g38j, GHSA-8m49-2xj8-67v9, GHSA-f89h-2fjh-2r9q

### CWE-763 — CWE Family CWE-763
- **Count**: 14
- **With Fix SHA**: 14
- **Project Distribution**: `linux-cna`: 14
- **Sample CVEs**: CVE-2021-47087, CVE-2021-47221, CVE-2021-47387, CVE-2022-48835, CVE-2022-49160, CVE-2024-35832, CVE-2024-36890, CVE-2024-38617, CVE-2024-42132, CVE-2024-50057

### CWE-201 — CWE Family CWE-201
- **Count**: 13
- **With Fix SHA**: 10
- **Project Distribution**: `curl-upstream`: 10, `rustsec`: 3
- **Sample CVEs**: CVE-2003-1605, CVE-2013-1944, CVE-2014-3613, CVE-2014-3620, CVE-2015-3153, CVE-2022-27779, CVE-2023-46218, CVE-2026-80255, CVE-2026-82209, CVE-2026-8924

### CWE-78 — CWE Family CWE-78
- **Count**: 13
- **With Fix SHA**: 2
- **Project Distribution**: `git-upstream`: 2, `openssl-upstream`: 2, `rustsec`: 9
- **Sample CVEs**: CVE-2017-14867, CVE-2019-19604, CVE-2022-1292, CVE-2022-2068, GHSA-29hf-rm4x-xxph, GHSA-4c96-w8v2-p28j, GHSA-5c5j-jmhx-q2gr, GHSA-7xh3-mhg9-jcw8, GHSA-hhjv-jq77-cmvx, GHSA-hmh4-3xvx-q5hr

### CWE-522 — CWE Family CWE-522
- **Count**: 13
- **With Fix SHA**: 12
- **Project Distribution**: `curl-upstream`: 9, `git-upstream`: 2, `postgres-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2018-1000007, CVE-2020-11008, CVE-2020-5260, CVE-2021-22923, CVE-2021-23222, CVE-2022-27774, CVE-2022-27776, CVE-2025-14524, CVE-2026-3783, CVE-2026-6253

### CWE-682 — CWE Family CWE-682
- **Count**: 13
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2, `rustsec`: 11
- **Sample CVEs**: CVE-2024-41011, CVE-2024-42231, GHSA-9qmm-4mfr-r3wj, GHSA-fcmm-54jp-7vf6, GHSA-jv4h-j224-23cc, GHSA-v57h-6hmh-g2p4, GHSA-x5m4-43jf-hh65, RUSTSEC-2018-0012, RUSTSEC-2021-0075, RUSTSEC-2022-0095

### CWE-862 — CWE Family CWE-862
- **Count**: 12
- **With Fix SHA**: 3
- **Project Distribution**: `linux`: 1, `linux-cna`: 3, `rustsec`: 8
- **Sample CVEs**: CVE-2005-3623, CVE-2023-52642, CVE-2024-26705, CVE-2026-64042, GHSA-95q8-x6r6-672m, GHSA-gcwr-5mrf-fvch, GHSA-jmxc-hhwx-gvv3, GHSA-mf42-3c8q-x7x8, GHSA-mx42-j6wv-px98, GHSA-pfcq-4gjr-6gjm

### CWE-297 — CWE Family CWE-297
- **Count**: 11
- **With Fix SHA**: 7
- **Project Distribution**: `curl-upstream`: 11
- **Sample CVEs**: CVE-2013-4545, CVE-2013-6422, CVE-2014-0139, CVE-2014-1263, CVE-2014-2522, CVE-2014-8151, CVE-2016-3739, CVE-2024-2466, CVE-2025-15079, CVE-2026-12064

### CWE-284 — CWE Family CWE-284
- **Count**: 11
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 1, `rustsec`: 9
- **Sample CVEs**: CVE-2016-7054, CVE-2023-52801, GHSA-436v-8fw5-4mj8, GHSA-4mq4-7rw3-vm5j, GHSA-57fm-592m-34r7, GHSA-cg8r-jwg7-r2x4, GHSA-g8jh-vg5j-4h3f, GHSA-v8fw-85r8-5m23, RUSTSEC-2022-0091, RUSTSEC-2026-0147

### CWE-909 — CWE Family CWE-909
- **Count**: 11
- **With Fix SHA**: 10
- **Project Distribution**: `linux-cna`: 10, `rustsec`: 1
- **Sample CVEs**: CVE-2022-49217, CVE-2022-49865, CVE-2022-50169, CVE-2024-26635, CVE-2024-43873, CVE-2024-50076, CVE-2024-56676, CVE-2025-38532, CVE-2025-38601, CVE-2026-43040

### CWE-704 — CWE Family CWE-704
- **Count**: 11
- **With Fix SHA**: 5
- **Project Distribution**: `linux-cna`: 5, `rustsec`: 6
- **Sample CVEs**: CVE-2022-49873, CVE-2024-57839, CVE-2025-22044, CVE-2025-37746, CVE-2025-39880, GHSA-g9hv-x236-4qp3, RUSTSEC-2019-0028, RUSTSEC-2019-0035, RUSTSEC-2020-0009, RUSTSEC-2020-0012

### CWE-354 — CWE Family CWE-354
- **Count**: 11
- **With Fix SHA**: 4
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 3, `rustsec`: 4, `systemd-upstream`: 3
- **Sample CVEs**: CVE-2023-31437, CVE-2023-31438, CVE-2023-31439, CVE-2024-49875, CVE-2026-34181, CVE-2026-34182, CVE-2026-75803, GHSA-7v42-g35v-xrch, GHSA-c7ph-f7jm-xv4w, GHSA-cwfq-rfcr-8hmp

### CWE-672 — CWE Family CWE-672
- **Count**: 10
- **With Fix SHA**: 7
- **Project Distribution**: `linux-cna`: 7, `rustsec`: 3
- **Sample CVEs**: CVE-2021-47069, CVE-2021-47294, CVE-2024-49953, CVE-2024-49955, CVE-2024-56674, CVE-2024-57929, CVE-2026-98080, RUSTSEC-2020-0105, RUSTSEC-2025-0019, RUSTSEC-2025-0046

### CWE-121 — CWE Family CWE-121
- **Count**: 9
- **With Fix SHA**: 5
- **Project Distribution**: `curl`: 1, `curl-upstream`: 4, `rustsec`: 4
- **Sample CVEs**: CVE-2000-0973, CVE-2013-0249, CVE-2016-9586, CVE-2019-3822, CVE-2022-35260, GHSA-8h58-w33p-wq3g, GHSA-ghm9-cr32-g9qj, RUSTSEC-2024-0020, RUSTSEC-2026-0009

### CWE-94 — CWE Family CWE-94
- **Count**: 9
- **With Fix SHA**: 0
- **Project Distribution**: `curl-upstream`: 2, `postgresql`: 1, `rustsec`: 5, `sqlite`: 1
- **Sample CVEs**: CVE-2005-0227, CVE-2008-0516, CVE-2016-4802, CVE-2019-5443, GHSA-72w5-pf8h-xfp4, GHSA-fjj5-v948-whjj, GHSA-gx45-xrj5-g6c4, GHSA-jqq4-c7wq-36h7, GHSA-wx44-2q6h-j6p8

### CWE-404 — CWE Family CWE-404
- **Count**: 9
- **With Fix SHA**: 7
- **Project Distribution**: `linux-cna`: 7, `rustsec`: 2
- **Sample CVEs**: CVE-2022-48661, CVE-2022-49745, CVE-2024-26757, CVE-2024-46752, CVE-2024-56757, CVE-2024-57879, CVE-2025-38385, GHSA-mjjp-xjfg-97wg, RUSTSEC-2022-0025

### CWE-281 — CWE Family CWE-281
- **Count**: 8
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 2, `rustsec`: 6
- **Sample CVEs**: CVE-2011-2192, CVE-2022-32207, GHSA-79rc-qpw3-jv92, GHSA-957r-r8gc-vv3h, GHSA-pmf6-rcx4-v53v, GHSA-r9hw-mj3w-phcq, GHSA-x2wv-9p67-mh9w, RUSTSEC-2025-0001

### CWE-319 — CWE Family CWE-319
- **Count**: 8
- **With Fix SHA**: 6
- **Project Distribution**: `curl-upstream`: 6, `rustsec`: 2
- **Sample CVEs**: CVE-2022-30115, CVE-2022-42916, CVE-2022-43551, CVE-2023-23914, CVE-2023-23915, CVE-2026-4873, GHSA-chqv-56wv-7564, RUSTSEC-2016-0003

### CWE-116 — CWE Family CWE-116
- **Count**: 8
- **With Fix SHA**: 2
- **Project Distribution**: `git-upstream`: 3, `rustsec`: 5
- **Sample CVEs**: CVE-2024-50349, CVE-2024-52005, CVE-2024-52006, GHSA-286m-6pg9-v42v, GHSA-5qr2-v392-m9g8, GHSA-6gcw-w7cp-94g9, GHSA-cwv4-h3j5-w3cf, GHSA-p7h3-7q52-72w8

### CWE-208 — CWE Family CWE-208
- **Count**: 8
- **With Fix SHA**: 3
- **Project Distribution**: `openssl-upstream`: 3, `rustsec`: 5
- **Sample CVEs**: CVE-2026-54872, CVE-2026-54875, CVE-2026-77696, GHSA-53hj-r94p-8c8f, GHSA-q7pg-9pr4-mrp2, RUSTSEC-2019-0027, RUSTSEC-2024-0354, RUSTSEC-2026-0043

### CWE-325 — CWE Family CWE-325
- **Count**: 7
- **With Fix SHA**: 5
- **Project Distribution**: `curl-upstream`: 1, `openssl-upstream`: 4, `rustsec`: 2
- **Sample CVEs**: CVE-2021-22946, CVE-2025-69418, CVE-2026-42770, CVE-2026-45445, CVE-2026-45446, GHSA-5379-f5hf-w38v, GHSA-9xg4-qhm4-g43w

### CWE-440 — CWE Family CWE-440
- **Count**: 7
- **With Fix SHA**: 4
- **Project Distribution**: `curl-upstream`: 2, `openssl-upstream`: 2, `rustsec`: 3
- **Sample CVEs**: CVE-2022-32221, CVE-2023-28322, CVE-2023-4807, CVE-2026-35191, GHSA-fqf6-gxhh-2xhw, GHSA-q9p4-hw9m-fj2v, RUSTSEC-2024-0011

### CWE-276 — CWE Family CWE-276
- **Count**: 7
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 6
- **Sample CVEs**: CVE-2024-46695, GHSA-5w4j-f78p-4wh9, GHSA-862g-9h5m-m3qv, GHSA-m8pp-qc66-6pgp, GHSA-vmg6-53r4-jhpw, GHSA-x5fr-7hhj-34j3, GHSA-x7m9-mv49-fv73

### CWE-285 — CWE Family CWE-285
- **Count**: 7
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 7
- **Sample CVEs**: GHSA-9722-9j67-vjcr, GHSA-f82j-v89j-mf86, GHSA-j9rh-f527-3x87, GHSA-vcwh-pff9-64cc, GHSA-whwg-vh4f-pmmf, GHSA-wmff-grcw-jcfm, GHSA-xpwj-7v8q-mcgj

### CWE-506 — CWE Family CWE-506
- **Count**: 7
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 7
- **Sample CVEs**: RUSTSEC-2025-0150, RUSTSEC-2025-0151, RUSTSEC-2025-0152, RUSTSEC-2026-0011, RUSTSEC-2026-0107, RUSTSEC-2026-0108, RUSTSEC-2026-0155

### CWE-488 — CWE Family CWE-488
- **Count**: 6
- **With Fix SHA**: 5
- **Project Distribution**: `curl-upstream`: 5, `rustsec`: 1
- **Sample CVEs**: CVE-2021-22897, CVE-2026-19931, CVE-2026-5773, CVE-2026-80231, CVE-2026-8458, GHSA-wrqv-pf6j-mqjp

### CWE-209 — CWE Family CWE-209
- **Count**: 6
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 3, `rustsec`: 3
- **Sample CVEs**: CVE-2021-47161, CVE-2021-47381, CVE-2024-35935, GHSA-6g9v-7gq3-p2c6, GHSA-cc8f-fcx3-gpjr, GHSA-p7hp-79jj-q923

### CWE-706 — CWE Family CWE-706
- **Count**: 6
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 2, `rustsec`: 3
- **Sample CVEs**: CVE-2021-47261, CVE-2021-47276, CVE-2022-27778, GHSA-67hp-f6hq-2h6g, RUSTSEC-2020-0040, RUSTSEC-2024-0367

### CWE-1333 — CWE Family CWE-1333
- **Count**: 6
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1, `rustsec`: 5
- **Sample CVEs**: CVE-2023-3446, GHSA-fqhp-rhm6-8rrj, GHSA-jc97-h3h9-7xh6, GHSA-qfh9-8p57-mjjj, GHSA-xr9w-x6gw-c9mj, RUSTSEC-2022-0013

### CWE-130 — CWE Family CWE-130
- **Count**: 6
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 5
- **Sample CVEs**: CVE-2026-31635, GHSA-624c-2h52-gf7f, GHSA-qwhm-h7v3-mrjx, RUSTSEC-2023-0077, RUSTSEC-2024-0447, RUSTSEC-2025-0015

### CWE-532 — CWE Family CWE-532
- **Count**: 6
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 6
- **Sample CVEs**: GHSA-2625-rw7m-5q5x, GHSA-333v-68xh-8mmq, GHSA-9ggc-845v-gcgv, GHSA-r54g-49rx-98cr, RUSTSEC-2023-0125, RUSTSEC-2024-0358

### CWE-758 — CWE Family CWE-758
- **Count**: 6
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 6
- **Sample CVEs**: GHSA-3rjw-m598-pq24, RUSTSEC-2020-0035, RUSTSEC-2023-0092, RUSTSEC-2025-0067, RUSTSEC-2025-0143, RUSTSEC-2026-0012

### CWE-61 — CWE Family CWE-61
- **Count**: 6
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 6
- **Sample CVEs**: GHSA-459f-x8vq-xjjm, GHSA-j26p-6wx7-f3pw, GHSA-jq42-7mfv-hm57, GHSA-wq63-vh5h-pr5p, RUSTSEC-2026-0067, RUSTSEC-2026-0113

### CWE-1240 — CWE Family CWE-1240
- **Count**: 6
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 6
- **Sample CVEs**: GHSA-753p-wrj5-g8fj, GHSA-hj49-h7fq-px5h, GHSA-vj64-rjf3-w3v7, RUSTSEC-2017-0001, RUSTSEC-2025-0144, RUSTSEC-2026-0075

### CWE-681 — CWE Family CWE-681
- **Count**: 5
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 2, `rustsec`: 2, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2019-19317, CVE-2026-53133, CVE-2026-98049, GHSA-pm4j-7r4q-ccg8, RUSTSEC-2021-0065

### CWE-290 — CWE Family CWE-290
- **Count**: 5
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 3, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2020-13529, CVE-2021-22890, GHSA-fc6g-2gcp-2qrq, RUSTSEC-2025-0041, RUSTSEC-2026-0159

### CWE-266 — CWE Family CWE-266
- **Count**: 5
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 4
- **Sample CVEs**: CVE-2021-47241, GHSA-jq8x-v7jw-v675, GHSA-qwcc-2r77-5w2f, GHSA-vg2r-rmgp-cgqj, RUSTSEC-2025-0040

### CWE-834 — CWE Family CWE-834
- **Count**: 5
- **With Fix SHA**: 5
- **Project Distribution**: `linux-cna`: 3, `openssl-upstream`: 2
- **Sample CVEs**: CVE-2022-48939, CVE-2023-3817, CVE-2024-42071, CVE-2024-42237, CVE-2024-4603

### CWE-73 — CWE Family CWE-73
- **Count**: 5
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `git-upstream`: 1, `rustsec`: 3
- **Sample CVEs**: CVE-2023-38546, CVE-2025-48385, GHSA-7j5w-7r7x-9v27, GHSA-f632-vm87-2m2f, GHSA-wfgq-w7cq-qj7j

### CWE-684 — CWE Family CWE-684
- **Count**: 5
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1, `rustsec`: 4
- **Sample CVEs**: CVE-2023-5363, GHSA-532v-xp3f-837c, GHSA-fhr3-xh3q-69w6, GHSA-gf9r-m956-97qx, GHSA-pmfc-4wjj-gmhx

### CWE-1025 — CWE Family CWE-1025
- **Count**: 5
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 3, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2024-9681, CVE-2026-40227, GHSA-76g3-38jv-wxh4, GHSA-q6r9-r9pw-4cf7, GHSA-xvj8-ph7x-65gf

### CWE-789 — CWE Family CWE-789
- **Count**: 5
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1, `rustsec`: 4
- **Sample CVEs**: CVE-2025-66199, GHSA-3633-g6mg-p6qq, GHSA-fpf5-4jw8-67x8, RUSTSEC-2021-0066, RUSTSEC-2026-0094

### CWE-732 — CWE Family CWE-732
- **Count**: 5
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 5
- **Sample CVEs**: GHSA-27vq-hv74-7cqp, GHSA-5hgf-628x-mcqf, GHSA-77g9-363w-rccq, GHSA-w8m4-4v35-v6x3, RUSTSEC-2025-0149

### CWE-639 — CWE Family CWE-639
- **Count**: 5
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 5
- **Sample CVEs**: GHSA-3f6w-45q9-v69m, GHSA-6vg3-hgrw-p5gf, GHSA-848m-r628-vrxw, GHSA-w9f8-m526-h7fh, RUSTSEC-2026-0035

### CWE-150 — CWE Family CWE-150
- **Count**: 5
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 5
- **Sample CVEs**: GHSA-89xp-c3mq-qj84, GHSA-m4pq-fv2w-6hrw, GHSA-vq67-rp93-65qf, RUSTSEC-2024-0364, RUSTSEC-2025-0055

### CWE-176 — CWE Family CWE-176
- **Count**: 5
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 5
- **Sample CVEs**: GHSA-8xpq-cjcf-3wh9, GHSA-hwhf-8p2f-45wr, GHSA-jcjr-rh8q-7xqf, GHSA-vx9m-xjwf-8cqm, GHSA-xh5h-p8c5-4w4x

### CWE-697 — CWE Family CWE-697
- **Count**: 4
- **With Fix SHA**: 1
- **Project Distribution**: `linux`: 1, `linux-cna`: 1, `rustsec`: 2
- **Sample CVEs**: CVE-2005-2801, CVE-2021-47370, GHSA-x2hw-px52-wp4m, RUSTSEC-2019-0026

### CWE-330 — CWE Family CWE-330
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 1, `openssl-upstream`: 1, `rustsec`: 2
- **Sample CVEs**: CVE-2016-9594, CVE-2019-1549, RUSTSEC-2021-0023, RUSTSEC-2026-0004

### CWE-601 — CWE Family CWE-601
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `git-upstream`: 1, `rustsec`: 3
- **Sample CVEs**: CVE-2017-1000117, GHSA-4wm2-cwcf-wwvp, GHSA-vhj5-x93p-67jw, RUSTSEC-2022-0072

### CWE-502 — CWE Family CWE-502
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 3, `systemd-upstream`: 1
- **Sample CVEs**: CVE-2018-15686, GHSA-2jx3-ff3v-j7jj, RUSTSEC-2021-0089, RUSTSEC-2024-0402

### CWE-89 — CWE Family CWE-89
- **Count**: 4
- **With Fix SHA**: 1
- **Project Distribution**: `postgres-upstream`: 1, `rustsec`: 2, `sqlite-upstream`: 1
- **Sample CVEs**: CVE-2018-20505, CVE-2021-23214, RUSTSEC-2024-0365, RUSTSEC-2025-0043

### CWE-299 — CWE Family CWE-299
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 2, `rustsec`: 2
- **Sample CVEs**: CVE-2020-8286, CVE-2024-0853, RUSTSEC-2026-0049, RUSTSEC-2026-0109

### CWE-1188 — CWE Family CWE-1188
- **Count**: 4
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 3, `rustsec`: 1
- **Sample CVEs**: CVE-2021-47343, CVE-2022-49099, CVE-2025-38523, RUSTSEC-2024-0342

### CWE-134 — CWE Family CWE-134
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 1, `rustsec`: 2
- **Sample CVEs**: CVE-2024-35845, CVE-2026-63073, RUSTSEC-2019-0005, RUSTSEC-2019-0006

### CWE-1258 — CWE Family CWE-1258
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2, `rustsec`: 2
- **Sample CVEs**: CVE-2024-36912, CVE-2024-36913, RUSTSEC-2022-0086, RUSTSEC-2022-0087

### CWE-1341 — CWE Family CWE-1341
- **Count**: 4
- **With Fix SHA**: 4
- **Project Distribution**: `curl-upstream`: 1, `linux-cna`: 3
- **Sample CVEs**: CVE-2025-0665, CVE-2026-43494, CVE-2026-45898, CVE-2026-52987

### CWE-1288 — CWE Family CWE-1288
- **Count**: 4
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2, `rustsec`: 2
- **Sample CVEs**: CVE-2026-31431, CVE-2026-31709, GHSA-5vmp-m5v2-hx47, RUSTSEC-2023-0073

### CWE-253 — CWE Family CWE-253
- **Count**: 4
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 3
- **Sample CVEs**: CVE-2026-53090, GHSA-853p-5678-hv8f, GHSA-88ch-q68x-36v7, GHSA-vp6q-mv9j-j428

### CWE-703 — CWE Family CWE-703
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 4
- **Sample CVEs**: GHSA-27wg-99g8-2v4v, GHSA-7587-4wv6-m68m, GHSA-9c48-w39g-hm26, GHSA-r344-xw3p-2frj

### CWE-328 — CWE Family CWE-328
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 4
- **Sample CVEs**: GHSA-3g92-f9ch-qjcm, GHSA-794x-2rpg-rfgr, GHSA-g2p6-hh5v-7hfm, RUSTSEC-2025-0021

### CWE-497 — CWE Family CWE-497
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 4
- **Sample CVEs**: GHSA-98cv-wqjx-wx8f, GHSA-g693-v3jr-8hcr, GHSA-w9q3-g4p5-5q2r, RUSTSEC-2022-0093

### CWE-188 — CWE Family CWE-188
- **Count**: 4
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 4
- **Sample CVEs**: RUSTSEC-2020-0078, RUSTSEC-2020-0080, RUSTSEC-2020-0081, RUSTSEC-2026-0137

### CWE-326 — CWE Family CWE-326
- **Count**: 3
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `openssl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2014-0224, CVE-2025-39889, RUSTSEC-2024-0430

### CWE-17 — CWE Family CWE-17
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `openssl-upstream`: 3
- **Sample CVEs**: CVE-2015-0286, CVE-2015-0287, CVE-2015-0290

### CWE-426 — CWE Family CWE-426
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `git-upstream`: 1, `rustsec`: 2
- **Sample CVEs**: CVE-2018-19486, GHSA-mh5c-xrmh-m794, GHSA-x7fr-pg8f-93f5

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

### CWE-273 — CWE Family CWE-273
- **Count**: 3
- **With Fix SHA**: 2
- **Project Distribution**: `linux-cna`: 2, `rustsec`: 1
- **Sample CVEs**: CVE-2021-47129, CVE-2023-52433, GHSA-47c7-qrm7-mqw7

### CWE-911 — CWE Family CWE-911
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `linux-cna`: 3
- **Sample CVEs**: CVE-2021-47327, CVE-2026-46099, CVE-2026-46316

### CWE-75 — CWE Family CWE-75
- **Count**: 3
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 2
- **Sample CVEs**: CVE-2023-27533, GHSA-64f8-pjgr-9wmr, GHSA-xw2c-hrr9-4xwr

### CWE-311 — CWE Family CWE-311
- **Count**: 3
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 2
- **Sample CVEs**: CVE-2023-46219, GHSA-779w-xvpm-78jx, RUSTSEC-2022-0032

### CWE-385 — CWE Family CWE-385
- **Count**: 3
- **With Fix SHA**: 2
- **Project Distribution**: `openssl-upstream`: 2, `rustsec`: 1
- **Sample CVEs**: CVE-2024-13176, CVE-2025-9231, RUSTSEC-2023-0071

### CWE-669 — CWE Family CWE-669
- **Count**: 3
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `systemd-upstream`: 2
- **Sample CVEs**: CVE-2024-42158, CVE-2026-40225, CVE-2026-40228

### CWE-294 — CWE Family CWE-294
- **Count**: 3
- **With Fix SHA**: 3
- **Project Distribution**: `curl-upstream`: 3
- **Sample CVEs**: CVE-2026-11856, CVE-2026-7168, CVE-2026-8927

### CWE-377 — CWE Family CWE-377
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 3
- **Sample CVEs**: GHSA-2cxp-xq3c-mjxx, GHSA-2w8r-9xj7-69j5, GHSA-p4jg-pccf-h82c

### CWE-228 — CWE Family CWE-228
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 3
- **Sample CVEs**: GHSA-32jf-h775-g29h, GHSA-8m95-fffc-h4c5, RUSTSEC-2023-0062

### CWE-331 — CWE Family CWE-331
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 3
- **Sample CVEs**: GHSA-5844-q3fc-56rh, GHSA-w3g8-fp6j-wvqw, RUSTSEC-2024-0343

### CWE-693 — CWE Family CWE-693
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 3
- **Sample CVEs**: GHSA-cpgj-f7g3-2pp2, GHSA-qqc3-94qv-7fw3, GHSA-x442-m7cc-hr92

### CWE-288 — CWE Family CWE-288
- **Count**: 3
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 3
- **Sample CVEs**: GHSA-fxc9-7j2w-vx54, GHSA-x33c-7c2v-mrj9, RUSTSEC-2024-0010

### CWE-384 — CWE Family CWE-384
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-1999-0428, GHSA-5qfp-32cf-69jh

### CWE-338 — CWE Family CWE-338
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `openssl`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2008-0166, RUSTSEC-2020-0089

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

### CWE-924 — CWE Family CWE-924
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2011-3389, CVE-2022-32208

### CWE-93 — CWE Family CWE-93
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2012-0036, RUSTSEC-2017-0002

### CWE-124 — CWE Family CWE-124
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `curl-upstream`: 2
- **Sample CVEs**: CVE-2015-3144, CVE-2015-3145

### CWE-172 — CWE Family CWE-172
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2016-8624, RUSTSEC-2024-0359

### CWE-88 — CWE Family CWE-88
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `git-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2018-17456, RUSTSEC-2026-0136

### CWE-1286 — CWE Family CWE-1286
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2022-35252, GHSA-v653-r55g-hcmg

### CWE-920 — CWE Family CWE-920
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2023-52832, RUSTSEC-2024-0361

### CWE-1325 — CWE Family CWE-1325
- **Count**: 2
- **With Fix SHA**: 2
- **Project Distribution**: `openssl-upstream`: 2
- **Sample CVEs**: CVE-2024-2511, CVE-2026-34183

### CWE-212 — CWE Family CWE-212
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2024-49997, RUSTSEC-2022-0075

### CWE-680 — CWE Family CWE-680
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2025-0725, RUSTSEC-2026-0007

### CWE-340 — CWE Family CWE-340
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2025-10148, RUSTSEC-2021-0102

### CWE-923 — CWE Family CWE-923
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2026-13608, GHSA-m3c3-78fh-w3w7

### CWE-407 — CWE Family CWE-407
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2026-42772, RUSTSEC-2026-0119

### CWE-664 — CWE Family CWE-664
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2026-43503, RUSTSEC-2025-0023

### CWE-366 — CWE Family CWE-366
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2026-46181, RUSTSEC-2023-0018

### CWE-820 — CWE Family CWE-820
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2026-53153, RUSTSEC-2022-0008

### CWE-346 — CWE Family CWE-346
- **Count**: 2
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1, `rustsec`: 1
- **Sample CVEs**: CVE-2026-6276, RUSTSEC-2026-0140

### CWE-1289 — CWE Family CWE-1289
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-22w3-693w-x895, RUSTSEC-2024-0421

### CWE-1285 — CWE Family CWE-1285
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-2f9f-gq7v-9h6m, GHSA-4hgp-59h5-gvrj

### CWE-1395 — CWE Family CWE-1395
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-37xq-q42p-rv3p, RUSTSEC-2024-0368

### CWE-306 — CWE Family CWE-306
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-46q5-g3j9-wx5c, GHSA-4cm8-xpfv-jv6f

### CWE-460 — CWE Family CWE-460
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-472w-7w45-g3w5, RUSTSEC-2020-0082

### CWE-363 — CWE Family CWE-363
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-4g74-7cff-xcv8, GHSA-vf95-55w6-qmrf

### CWE-451 — CWE Family CWE-451
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-53gr-wmf4-8hh3, GHSA-xv5w-cw7x-72gj

### CWE-223 — CWE Family CWE-223
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-5p2p-6g2c-hf7m, RUSTSEC-2024-0434

### CWE-409 — CWE Family CWE-409
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-cgqf-3cq5-wvcj, GHSA-cjcg-cxmh-9wcr

### CWE-307 — CWE Family CWE-307
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-g6xm-f9xp-qq35, GHSA-v6pg-v89r-w8wr

### CWE-666 — CWE Family CWE-666
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-m65r-rprj-r5rg, RUSTSEC-2025-0051

### CWE-204 — CWE Family CWE-204
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-qhp6-635j-x7r2, GHSA-qxrw-f6fh-34r7

### CWE-15 — CWE Family CWE-15
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: GHSA-rpcf-rmh6-42xr, RUSTSEC-2026-0038

### CWE-1104 — CWE Family CWE-1104
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: RUSTSEC-2019-0039, RUSTSEC-2021-0144

### CWE-657 — CWE Family CWE-657
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: RUSTSEC-2020-0013, RUSTSEC-2020-0148

### CWE-427 — CWE Family CWE-427
- **Count**: 2
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 2
- **Sample CVEs**: RUSTSEC-2021-0106, RUSTSEC-2024-0355

### CWE-916 — CWE Family CWE-916
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `postgresql`: 1
- **Sample CVEs**: CVE-2002-1657

### CWE-298 — CWE Family CWE-298
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2007-3564

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

### CWE-838 — CWE Family CWE-838
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2016-8625

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

### CWE-1335 — CWE Family CWE-1335
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2023-52810

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

### CWE-590 — CWE Family CWE-590
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `curl-upstream`: 1
- **Sample CVEs**: CVE-2024-6197

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

### CWE-364 — CWE Family CWE-364
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `systemd-upstream`: 1
- **Sample CVEs**: CVE-2025-4598

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

### CWE-757 — CWE Family CWE-757
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-2673

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

### CWE-393 — CWE Family CWE-393
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `linux-cna`: 1
- **Sample CVEs**: CVE-2026-53092

### CWE-405 — CWE Family CWE-405
- **Count**: 1
- **With Fix SHA**: 1
- **Project Distribution**: `openssl-upstream`: 1
- **Sample CVEs**: CVE-2026-54874

### CWE-250 — CWE Family CWE-250
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-2j3p-gqw5-g59j

### CWE-829 — CWE Family CWE-829
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-2q6j-gqc4-4gw3

### CWE-441 — CWE Family CWE-441
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-3v2x-9xcv-2v2v

### CWE-406 — CWE Family CWE-406
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-4855-q42w-5vr4

### CWE-733 — CWE Family CWE-733
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-4hff-hh47-7788

### CWE-613 — CWE Family CWE-613
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-4m82-p8cx-f94j

### CWE-768 — CWE Family CWE-768
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-5pv5-xh52-hvrp

### CWE-611 — CWE Family CWE-611
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-7gf7-jv65-wjmh

### CWE-283 — CWE Family CWE-283
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-7rhf-42qf-vrvc

### CWE-573 — CWE Family CWE-573
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-8m29-fpq5-89jj

### CWE-642 — CWE Family CWE-642
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-97f8-h76h-f297

### CWE-494 — CWE Family CWE-494
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-9f3p-wvj7-q82x

### CWE-549 — CWE Family CWE-549
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-c978-wq47-pvvw

### CWE-183 — CWE Family CWE-183
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-f26g-jm89-4g65

### CWE-610 — CWE Family CWE-610
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-f3h7-gpjj-wcvh

### CWE-673 — CWE Family CWE-673
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-fmj9-77q8-g6c4

### CWE-489 — CWE Family CWE-489
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-fq3w-p4fg-mw73

### CWE-159 — CWE Family CWE-159
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-gjv3-89hh-9xq2

### CWE-636 — CWE Family CWE-636
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-hc4m-q9jh-xw4j

### CWE-278 — CWE Family CWE-278
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-j3xp-wfr4-hx87

### CWE-214 — CWE Family CWE-214
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-m8f5-rh7h-vgg3

### CWE-647 — CWE Family CWE-647
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-p688-r7jv-fm6f

### CWE-1336 — CWE Family CWE-1336
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-qp6f-w4r3-h8wg

### CWE-226 — CWE Family CWE-226
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-r45x-ghr2-qjxc

### CWE-783 — CWE Family CWE-783
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-w6fv-6gcc-x825

### CWE-708 — CWE Family CWE-708
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: GHSA-wr2m-38xh-rpc9

### CWE-198 — CWE Family CWE-198
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2021-0013

### CWE-147 — CWE Family CWE-147
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2021-0069

### CWE-23 — CWE Family CWE-23
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2021-0105

### CWE-323 — CWE Family CWE-323
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2023-0068

### CWE-113 — CWE Family CWE-113
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2024-0008

### CWE-67 — CWE Family CWE-67
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2024-0351

### CWE-41 — CWE Family CWE-41
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2024-0371

### CWE-334 — CWE Family CWE-334
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2024-0398

### CWE-25 — CWE Family CWE-25
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2024-0432

### CWE-184 — CWE Family CWE-184
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2024-0438

### CWE-475 — CWE Family CWE-475
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2025-0131

### CWE-915 — CWE Family CWE-915
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2025-0132

### CWE-195 — CWE Family CWE-195
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2025-0136

### CWE-762 — CWE Family CWE-762
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2025-0163

### CWE-180 — CWE Family CWE-180
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2025-0168

### CWE-155 — CWE Family CWE-155
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2026-0044

### CWE-436 — CWE Family CWE-436
- **Count**: 1
- **With Fix SHA**: 0
- **Project Distribution**: `rustsec`: 1
- **Sample CVEs**: RUSTSEC-2026-0066

