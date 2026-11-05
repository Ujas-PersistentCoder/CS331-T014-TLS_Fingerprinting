# Reduced ECH checkpoint 3 results

Complete experiment: **True**.

Corpus attempts 60, confirmed accepted and joined 60, excluded 0.

| Features | Groups | Shared groups | Observations in shared groups | A distinct / modal share | B distinct / modal share |
|---|---:|---:|---:|---|---|
| ja3 | 60 | 0 | 0.0 | 30 / 0.03333333333333333 | 30 / 0.03333333333333333 |
| ja3_augmented | 60 | 0 | 0.0 | 30 / 0.03333333333333333 | 30 / 0.03333333333333333 |
| ja4 | 1 | 1 | 1.0 | 1 / 1.0 | 1 / 1.0 |
| ja4_augmented | 1 | 1 | 1.0 | 1 / 1.0 | 1 / 1.0 |

The feature groups and per-session variation are recorded in the accompanying JSON files.

These are two configurations of the same pinned BoringSSL implementation. Supported TLS groups differ, while ALPN, ECH configuration, cipher and signature settings match. Ordinary GREASE and extension permutation remain enabled. JA3 variation is an observed behavior.

Endpoint observations establish ECH labels. The passive engine continues to emit unknown offer type and unverified TLS 1.3 ECH acceptance. An ECH envelope alone cannot reliably separate GREASE from a real offer. Rejected real offers can resemble GREASE, including decryption failure at a server.

The comparisons describe grouping and repeatability on this corpus. They establish neither recognition accuracy nor identification of browsers, devices or arbitrary applications. No ECH-off comparison or latency benchmark was performed.
