# Story 3.2 evidence archives

Each archive preserves command records, logs and source hashes. Where present, inner `archive-index.json` records the SHA256 and original size of each compressed source artifact; the hardening bundle preserves its original manifest. Logs are gzip-compressed without changing their original bytes. Extract a phase with `tar -xzf PHASE.tar.gz -C EMPTY_DIRECTORY`; read an inner log with `gzip -cd LOG.log.gz`. Archives exclude build trees and material fixture directories.

| Archive | Files | SHA256 |
|---|---:|---|
| [hardening.tar.gz](hardening.tar.gz) | 4 | `eb68c9292734b0bb18ef6503e123e10803de86cdb9dad14ebef72dba9842d83c` |
| [mutations-hardened.tar.gz](mutations-hardened.tar.gz) | 103 | `e10e54f141966709de9a1e60a9ac57455ef3d3b42536eda5b98199d3c4b744c3` |
| [mutations-initial.tar.gz](mutations-initial.tar.gz) | 79 | `61f36048e21b0b0127a554d95ef00e95c38c47317ba2b81e4a0dd66ef2147922` |
| [mutations-real-initial.tar.gz](mutations-real-initial.tar.gz) | 18 | `1cd10bb7109bfac40b33b3ef3dadc327983776536ef862adae136fe8cf05dc3b` |
| [mutations-reconfirmation-copy-mode.tar.gz](mutations-reconfirmation-copy-mode.tar.gz) | 5 | `9a92392fc670511f8809277397cb8f0219dab5a80e4ef7d626d5e288c8fe8e6a` |
| [mutations-reconfirmation-stale-cache.tar.gz](mutations-reconfirmation-stale-cache.tar.gz) | 6 | `7fbd909bfd91c0341f35f8e233bd4c5f3f23cce3fad4546a01dedbe7d2087c81` |
| [reproduction.tar.gz](reproduction.tar.gz) | 12 | `1e2c73ba41b42cba2bab94e213c2473ce6252028626b30c11b45eea410374800` |
| [verification-hardening-first.tar.gz](verification-hardening-first.tar.gz) | 6 | `15257d9c38df3f40542018b6766b1825c0e71d66106229d61f25c5aa256c3906` |
| [verification-hardening-passed.tar.gz](verification-hardening-passed.tar.gz) | 9 | `5307bdc3cfa01130689cd94d652fceae916dab8b1a57f4e0fac62b1047e7715d` |
| [verification-initial.tar.gz](verification-initial.tar.gz) | 13 | `6e7e688eecab830516e5d2d80c90d17b5bd3d20e5afdc4aee1a60b7d8f44abb2` |
| [verification-msrv-initial.tar.gz](verification-msrv-initial.tar.gz) | 4 | `c057593a98182f1ac7c4139f03840a420f4abb2a473867c31f9bffedaf849f3d` |
| [verification-real-initial.tar.gz](verification-real-initial.tar.gz) | 6 | `671f10c2a08cf6f166fef05a76f110bc7cdf640ac19d0535f16508dc5184e088` |
| [verification-regression-first.tar.gz](verification-regression-first.tar.gz) | 9 | `e44af22170c4c9701bebce7c27329b8611401401774385ded38dedd95b597027` |
| [verification-regression-remaining.tar.gz](verification-regression-remaining.tar.gz) | 8 | `9438f54cb5ddb24f18bcadb366f9bf7506ca33777decb522c2dadf08c0e73ca2` |
| [verification-complete.tar.gz](verification-complete.tar.gz) | 23 | `4639f84e7194bdeec681e1dc4994c980c767faf3875496e1027db775636df201` |
| [mutations-final-confirmed.tar.gz](mutations-final-confirmed.tar.gz) | 24 | `171a89fee297fee8a44da65a7ec1a4296530e5c0b250cbd9790426b05c3d7d13` |
| [review-fixes.tar.gz](review-fixes.tar.gz) | 11 | `8722dab6993a86caaefa7f075bea916843d8ec0e7c32b94aeff2ecb53417fe8e` |
| [reproduction-post-review.tar.gz](reproduction-post-review.tar.gz) | 7 | `668207c9c155ef9352f3ee7e7076701534b3303d62b03dcf5ffe965693c0b90b` |
| [mutations-post-review.tar.gz](mutations-post-review.tar.gz) | 116 | `b078743dfeb6dae92adbe66bb175e5d60a83ce1860c85aae512abd59beb1f0f2` |
| [verification-post-review.tar.gz](verification-post-review.tar.gz) | 23 | `40a93a7fa48591726cab819289240af2606792d87602fe092ba7686ca1f272a3` |
