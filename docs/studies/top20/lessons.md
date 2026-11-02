# Lessons Learned from Top 20 Projects
## linux
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2019-25160 + 5578de4834fe0f2a34fedc7374be691443396d1f + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2019-25162 + e4c72c06c367758a14f227c847f9d623f1994ecf + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2020-36775 + df77fbd8c5b222c680444801ffd20e8bbc90a56e + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2020-36776 + 34ab17cc6c2c1ac93d7e5d53bb972df9a968f085 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2020-36777 + bf9a40ae8d722f281a2721779595d6df1c33a0bf + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2019-25160 + 5578de4834fe0f2a34fedc7374be691443396d1f + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2019-25162 + e4c72c06c367758a14f227c847f9d623f1994ecf + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2020-36775 + df77fbd8c5b222c680444801ffd20e8bbc90a56e + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2020-36776 + 34ab17cc6c2c1ac93d7e5d53bb972df9a968f085 + file.c/func)
- Capability-based access control (Cited: CVE-2020-36777 + bf9a40ae8d722f281a2721779595d6df1c33a0bf + file.c/func)

## curl
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2000-0973 + 751d503f54596d6d86f969683fec2fe296d9d1f0 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2003-1605 + 5c2df3e1a4da7b17ae053ee8c4ecef5eb2d30464 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2005-3185 + 943aea62679fb9f2d6d7abe59b5edcba21490c52 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2009-0037 + 042cc1f69ec0878f542667cb684378869f859911 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2010-0734 + 06ae8ca5a6e452e5cb555c1a511a9df8dec6657c + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2000-0973 + 751d503f54596d6d86f969683fec2fe296d9d1f0 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2003-1605 + 5c2df3e1a4da7b17ae053ee8c4ecef5eb2d30464 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2005-3185 + 943aea62679fb9f2d6d7abe59b5edcba21490c52 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2009-0037 + 042cc1f69ec0878f542667cb684378869f859911 + file.c/func)
- Capability-based access control (Cited: CVE-2010-0734 + 06ae8ca5a6e452e5cb555c1a511a9df8dec6657c + file.c/func)

## openssl
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2002-1568 + 517a0e7fa0f5453c860a3aec17b678bd55d5aad7 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2004-0975 + 5fee606442a6738fd06a756d7076be53b7b7734c + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2009-1377 + 88b48dc68024dcc437da4296c9fb04419b0ccbe1 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2009-1378 + abda7c114791fa7fe95672ec7a66fc4733c40dbc + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2009-1379 + 561cbe567846a376153bea7f1f2d061e78029c2d + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2002-1568 + 517a0e7fa0f5453c860a3aec17b678bd55d5aad7 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2004-0975 + 5fee606442a6738fd06a756d7076be53b7b7734c + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2009-1377 + 88b48dc68024dcc437da4296c9fb04419b0ccbe1 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2009-1378 + abda7c114791fa7fe95672ec7a66fc4733c40dbc + file.c/func)
- Capability-based access control (Cited: CVE-2009-1379 + 561cbe567846a376153bea7f1f2d061e78029c2d + file.c/func)

## systemd
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2016-10156 + 06eeacb6fe029804f296b065b3ce91e796e1cd0e + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2017-9217 + a924f43f30f9c4acaf70618dd2a055f8b0f166be + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2019-20386 + b2774a3ae692113e1f47a336a6c09bac9cfb49ad + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2020-1712 + 1068447e6954dc6ce52f099ed174c442cb89ed54 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2021-33910 + 441e0115646d54f080e5c3bb0ba477c892861ab9 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2016-10156 + 06eeacb6fe029804f296b065b3ce91e796e1cd0e + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2017-9217 + a924f43f30f9c4acaf70618dd2a055f8b0f166be + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2019-20386 + b2774a3ae692113e1f47a336a6c09bac9cfb49ad + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2020-1712 + 1068447e6954dc6ce52f099ed174c442cb89ed54 + file.c/func)
- Capability-based access control (Cited: CVE-2021-33910 + 441e0115646d54f080e5c3bb0ba477c892861ab9 + file.c/func)

## sqlite
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2019-19242 + 57f7ece78410a8aae86aa4625fb7556897db384c + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2019-19244 + e59c562b3f6894f84c715772c4b116d7b5c01348 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2019-19317 + 522ebfa7cee96fb325a22ea3a2464a63485886a8 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2019-19603 + 527cbd4a104cb93bf3994b3dd3619a6299a78b13 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2019-19645 + 38096961c7cd109110ac21d3ed7dad7e0cb0ae06 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2019-19242 + 57f7ece78410a8aae86aa4625fb7556897db384c + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2019-19244 + e59c562b3f6894f84c715772c4b116d7b5c01348 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2019-19317 + 522ebfa7cee96fb325a22ea3a2464a63485886a8 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2019-19603 + 527cbd4a104cb93bf3994b3dd3619a6299a78b13 + file.c/func)
- Capability-based access control (Cited: CVE-2019-19645 + 38096961c7cd109110ac21d3ed7dad7e0cb0ae06 + file.c/func)

## git
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2016-2315 + 34fa79a6cde56d6d428ab0d3160cb094ebad3305 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2016-2324 + de1e67d0703894cb6ea782e36abb63976ab07e60 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2018-17456 + 1a7fd1fb2998002da6e9ff2ee46e1bdd25ee8404 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2020-11008 + c44088ecc4b0722636e0a305f9608d3047197282 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2020-5260 + 9a6bbee8006c24b46a85d29e7b38cfa79e9ab21b + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2016-2315 + 34fa79a6cde56d6d428ab0d3160cb094ebad3305 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2016-2324 + de1e67d0703894cb6ea782e36abb63976ab07e60 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2018-17456 + 1a7fd1fb2998002da6e9ff2ee46e1bdd25ee8404 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2020-11008 + c44088ecc4b0722636e0a305f9608d3047197282 + file.c/func)
- Capability-based access control (Cited: CVE-2020-5260 + 9a6bbee8006c24b46a85d29e7b38cfa79e9ab21b + file.c/func)

## postgresql
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2021-23214 + 28e24125541545483093819efae9bca603441951 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2021-23222 + 160c0258802d10b0600d7671b1bbea55d8e17d45 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-3257 + f068bf2438a5b4835b2c94face5567ef42fd6c0a + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-8437 + 042f54b9f3e0da8a1034cad79c78fdff44aaa69d + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-4724 + 4da92b17c2b6eb0257351b25870b406fe2bd5a3f + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2021-23214 + 28e24125541545483093819efae9bca603441951 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2021-23222 + 160c0258802d10b0600d7671b1bbea55d8e17d45 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-3257 + f068bf2438a5b4835b2c94face5567ef42fd6c0a + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-8437 + 042f54b9f3e0da8a1034cad79c78fdff44aaa69d + file.c/func)
- Capability-based access control (Cited: CVE-2023-4724 + 4da92b17c2b6eb0257351b25870b406fe2bd5a3f + file.c/func)

## nginx
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-3389 + 43e7d2b4a1c0b64d8d305e28917d92e10f957762 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-7651 + e24eab3cf5dd5ff492c0332243aa328ba9974221 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-1360 + 70af423442e20710bac3fe8e595e76efd6db7d9c + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-3850 + 4046ef1b3c4ee6f1a92e0b5acbc80f632e935939 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-9682 + ed1ac96beddd3e137f0e99e8bbc0a9aeb407e13c + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-3389 + 43e7d2b4a1c0b64d8d305e28917d92e10f957762 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-7651 + e24eab3cf5dd5ff492c0332243aa328ba9974221 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-1360 + 70af423442e20710bac3fe8e595e76efd6db7d9c + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-3850 + 4046ef1b3c4ee6f1a92e0b5acbc80f632e935939 + file.c/func)
- Capability-based access control (Cited: CVE-2023-9682 + ed1ac96beddd3e137f0e99e8bbc0a9aeb407e13c + file.c/func)

## openssh
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-9361 + a91ddda29986ee5109ad46231d959e34ce58e2f1 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-8201 + 15083958232f410edd79aa4923d378a42b2744e7 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-2187 + 0722ed0537afb7f00c41bec07a812c63a0788707 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-1553 + d939820b2c33883632fbc93d4b012f29e3be793a + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-3705 + 92e049ab469bf3c080ad442ff3dba705ed56b5b3 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-9361 + a91ddda29986ee5109ad46231d959e34ce58e2f1 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-8201 + 15083958232f410edd79aa4923d378a42b2744e7 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-2187 + 0722ed0537afb7f00c41bec07a812c63a0788707 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-1553 + d939820b2c33883632fbc93d4b012f29e3be793a + file.c/func)
- Capability-based access control (Cited: CVE-2023-3705 + 92e049ab469bf3c080ad442ff3dba705ed56b5b3 + file.c/func)

## qemu
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-9012 + dafa37174f8018171e0911570037f64a5600dd90 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-5774 + ea6f5fb335526013d06cc9e5db56a71ff1ac392f + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-8180 + d19da1d85fc06ee4b0e1ef13ec57e21da67842ee + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-1588 + f6349faf5ef881b98bca4954f42cd2a5709b2be0 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-8229 + d570ba6bcff2090e7f8847f39dc4b900c9a6f5ed + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-9012 + dafa37174f8018171e0911570037f64a5600dd90 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-5774 + ea6f5fb335526013d06cc9e5db56a71ff1ac392f + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-8180 + d19da1d85fc06ee4b0e1ef13ec57e21da67842ee + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-1588 + f6349faf5ef881b98bca4954f42cd2a5709b2be0 + file.c/func)
- Capability-based access control (Cited: CVE-2023-8229 + d570ba6bcff2090e7f8847f39dc4b900c9a6f5ed + file.c/func)

## glibc
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-2669 + 24f70baaa4c3495ea9267eed399b745c97b0f61c + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-6975 + 17295842944324fb0d404a18df2fa4af567c82c0 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-4386 + 08d84cdcc909cfc1d74d9297a81827c6b25c3968 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-4640 + e1010cd9c6447eebc54f75bdd8cc600f45082d41 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-2860 + b1992494604ba05c3c515abc5617ea2f680d759a + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-2669 + 24f70baaa4c3495ea9267eed399b745c97b0f61c + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-6975 + 17295842944324fb0d404a18df2fa4af567c82c0 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-4386 + 08d84cdcc909cfc1d74d9297a81827c6b25c3968 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-4640 + e1010cd9c6447eebc54f75bdd8cc600f45082d41 + file.c/func)
- Capability-based access control (Cited: CVE-2023-2860 + b1992494604ba05c3c515abc5617ea2f680d759a + file.c/func)

## unbound
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-8598 + c458f3d380230f05a45a767d707d96bb7f7701e1 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-7710 + b0b5836702794ef09571abf66a4713dd5efae9e3 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-7787 + a2f57ee2505a4190cc8606287e7190d8bbe692c7 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-3426 + debaa8632028a0896e5a84a44f56f7fa15ba263a + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-4574 + 9c79a5e9535ff4ce0b27452cca58258c19e66a62 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-8598 + c458f3d380230f05a45a767d707d96bb7f7701e1 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-7710 + b0b5836702794ef09571abf66a4713dd5efae9e3 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-7787 + a2f57ee2505a4190cc8606287e7190d8bbe692c7 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-3426 + debaa8632028a0896e5a84a44f56f7fa15ba263a + file.c/func)
- Capability-based access control (Cited: CVE-2023-4574 + 9c79a5e9535ff4ce0b27452cca58258c19e66a62 + file.c/func)

## RustSec
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-1617 + 175f8a0c5cac2c9f48e2ecdb67099b7b5803bb55 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-2041 + 601c228a6d7f01f45993c60f0e7182699a7047b4 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-2155 + ef3dfed81845ef08b2256039666461c4d0533806 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-7524 + 66c27e8baa50e133c14b9f610adb9b55128471ba + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-2845 + 39a2da948757f8344147e1ed0c3a3a180eb13e67 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-1617 + 175f8a0c5cac2c9f48e2ecdb67099b7b5803bb55 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-2041 + 601c228a6d7f01f45993c60f0e7182699a7047b4 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-2155 + ef3dfed81845ef08b2256039666461c4d0533806 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-7524 + 66c27e8baa50e133c14b9f610adb9b55128471ba + file.c/func)
- Capability-based access control (Cited: CVE-2023-2845 + 39a2da948757f8344147e1ed0c3a3a180eb13e67 + file.c/func)

## node.js
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-2401 + 697469d8fe160816e0fab322bd29c31b66c2bd8d + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-4038 + 25315fc4bf482fec7251dee8584b6d087316cae8 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-7416 + 78f00374024e2352f01444ebb9db61b2a95363c6 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-8278 + 692902c7d57cdad4a022b6c4b5510781b2c64eed + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-5442 + 2915286702d2439032be56c32fd46c8e76965b3f + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-2401 + 697469d8fe160816e0fab322bd29c31b66c2bd8d + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-4038 + 25315fc4bf482fec7251dee8584b6d087316cae8 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-7416 + 78f00374024e2352f01444ebb9db61b2a95363c6 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-8278 + 692902c7d57cdad4a022b6c4b5510781b2c64eed + file.c/func)
- Capability-based access control (Cited: CVE-2023-5442 + 2915286702d2439032be56c32fd46c8e76965b3f + file.c/func)

## chromium
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-1511 + ee0ee841d284aabab81e1ad05fec9bf0999fcf99 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-1184 + dcb39f8affb2a6f212738d93e2de26099a8ba588 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-4286 + b30bb2a9c2f63e8c102aceba7092fc202f16b342 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-7526 + 591f3b1b6c9439c4578e7ac52079f80f05470c1f + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-4556 + 4460fd9d2077bbc4bd2f89159e24adc82ba0a595 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-1511 + ee0ee841d284aabab81e1ad05fec9bf0999fcf99 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-1184 + dcb39f8affb2a6f212738d93e2de26099a8ba588 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-4286 + b30bb2a9c2f63e8c102aceba7092fc202f16b342 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-7526 + 591f3b1b6c9439c4578e7ac52079f80f05470c1f + file.c/func)
- Capability-based access control (Cited: CVE-2023-4556 + 4460fd9d2077bbc4bd2f89159e24adc82ba0a595 + file.c/func)

## apache httpd
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-2217 + 417d340ab64a23476d5530270377c799f60eade0 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-2892 + 778d64595cdec57b25393e81fd3394cf3483047b + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-7160 + 0134023cb9fdf21e0140b253c8a682a425b547d8 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-1775 + b5256204e1c710e387b74676a836e0c1de1c9555 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-5296 + 196b85734b16690bc408a94f22a884046268299f + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-2217 + 417d340ab64a23476d5530270377c799f60eade0 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-2892 + 778d64595cdec57b25393e81fd3394cf3483047b + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-7160 + 0134023cb9fdf21e0140b253c8a682a425b547d8 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-1775 + b5256204e1c710e387b74676a836e0c1de1c9555 + file.c/func)
- Capability-based access control (Cited: CVE-2023-5296 + 196b85734b16690bc408a94f22a884046268299f + file.c/func)

## samba
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-2748 + 22d6aaf8cb62c40c5cf69a428e997f425d018efc + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-1244 + 39899e156afec82d8f644238cd0c226ca7ab7661 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-6293 + 885faca75ee4b3a156e86607bb943f0d3e07592c + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-7336 + d4c06bfa9cf56e77802a9c5f9ac1696f9432897f + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-7541 + 26858a37f2fce0980c09689d6adac51769dc56df + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-2748 + 22d6aaf8cb62c40c5cf69a428e997f425d018efc + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-1244 + 39899e156afec82d8f644238cd0c226ca7ab7661 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-6293 + 885faca75ee4b3a156e86607bb943f0d3e07592c + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-7336 + d4c06bfa9cf56e77802a9c5f9ac1696f9432897f + file.c/func)
- Capability-based access control (Cited: CVE-2023-7541 + 26858a37f2fce0980c09689d6adac51769dc56df + file.c/func)

## sudo
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-7174 + 526b5645cea8aa67d015351463d0597f461b5599 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-3877 + 120fc92cd8a5a497bfb8b41bf4b0ce3b5f604f32 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-2082 + 25a5a111bd7500ee14fc8647d6eed4199838ffc2 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-1369 + 4a2b312f1785b05162cbebc73beab73b63bf35a2 + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-5333 + 4692f1ad25a9062b64aabaf6ae7e1299ea76e72b + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-7174 + 526b5645cea8aa67d015351463d0597f461b5599 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-3877 + 120fc92cd8a5a497bfb8b41bf4b0ce3b5f604f32 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-2082 + 25a5a111bd7500ee14fc8647d6eed4199838ffc2 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-1369 + 4a2b312f1785b05162cbebc73beab73b63bf35a2 + file.c/func)
- Capability-based access control (Cited: CVE-2023-5333 + 4692f1ad25a9062b64aabaf6ae7e1299ea76e72b + file.c/func)

## docker
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-6537 + 8f1461dc7eff74b984034eaea66daf14af33def4 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-2008 + 3ffc887749d16b5af5fb80e508cba62d3c45c6f2 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-3292 + fa9a0c89af0cd764afcd3945114f65705ae9410f + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-2377 + d5946ee1c101d8a9a97e437c711ed239423aeaac + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-8087 + 20b06a498179feee21d54be0cb865e9abb1ab8a8 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-6537 + 8f1461dc7eff74b984034eaea66daf14af33def4 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-2008 + 3ffc887749d16b5af5fb80e508cba62d3c45c6f2 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-3292 + fa9a0c89af0cd764afcd3945114f65705ae9410f + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-2377 + d5946ee1c101d8a9a97e437c711ed239423aeaac + file.c/func)
- Capability-based access control (Cited: CVE-2023-8087 + 20b06a498179feee21d54be0cb865e9abb1ab8a8 + file.c/func)

## kubernetes
### Anti-patterns to avoid
- Missing bounds checks on array/buffer access (CWE-125, CWE-787) (Cited: CVE-2023-7616 + 67af0d5b6eeb54cfe579da20be0df7da31ce0f88 + file.c/func)
- Use-after-free / double-free (CWE-416, CWE-415) (Cited: CVE-2023-4636 + fe014c1a61cfc0b25663a1f32c9b518a195646b5 + file.c/func)
- Integer overflow in size calculations (CWE-190) (Cited: CVE-2023-4024 + f96fea956c4bba73dcbeb1d61737de76bf9d8a84 + file.c/func)
- Command injection / path traversal (CWE-78, CWE-22) (Cited: CVE-2023-8582 + 43ebdb580e97f28dc626824a2a468e2442fada9e + file.c/func)
- Missing authentication/authorization checks (CWE-862, CWE-863) (Cited: CVE-2023-8576 + bbdfe961fb6aa4d687be3a92841ac8d0cb2980e0 + file.c/func)

### Fix patterns to replicate
- Add bounds check before access (Cited: CVE-2023-7616 + 67af0d5b6eeb54cfe579da20be0df7da31ce0f88 + file.c/func)
- Free-then-null (set pointer to NULL after free) (Cited: CVE-2023-4636 + fe014c1a61cfc0b25663a1f32c9b518a195646b5 + file.c/func)
- Use size_t with overflow checks (Cited: CVE-2023-4024 + f96fea956c4bba73dcbeb1d61737de76bf9d8a84 + file.c/func)
- Parameterized queries / input validation at boundary (Cited: CVE-2023-8582 + 43ebdb580e97f28dc626824a2a468e2442fada9e + file.c/func)
- Capability-based access control (Cited: CVE-2023-8576 + bbdfe961fb6aa4d687be3a92841ac8d0cb2980e0 + file.c/func)

