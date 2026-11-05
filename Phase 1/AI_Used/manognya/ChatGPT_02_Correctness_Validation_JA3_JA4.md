# Session 2 — Correctness Validation: JA3 / JA3S / JA4 / JA4S

## Environment

- macOS, Apple Silicon
- Python 3.13 project environment
- C++ Release build with CMake
- Wireshark / TShark 4.6.8
- TShark path:
  `/Applications/Wireshark.app/Contents/MacOS/tshark`

## Why correctness came first

Before timing the engines, both implementations were checked against known captures and TShark.

### Early findings

- JA3/JA3S generally matched.
- A C++ JA4 extension-count mismatch was found.
- C++ initially missed later ClientHellos in `cloudflare_run1.pcap`.
- Python/TShark showed more ClientHellos than the earlier C++ build.

### Response

Benchmarking should wait until the engines agree on the logical output. A faster implementation that detects fewer handshakes would not be a fair performance win.

---

## JA4 extension-count bug

### Reconstructed user question

Why are SNI and ALPN excluded from one JA4 component but still counted in the extension count?

### Explanation

JA4 uses different rules for the count and the extension hash:

- GREASE is excluded from the count.
- SNI and ALPN still count toward the total extension count.
- SNI and ALPN are excluded from the extension list used for the JA4_c hash.

This explained the C++ mismatch.

### Final result

After the fix, C++ JA4 matched the reference behavior on the verification captures.

---

## Missed ClientHello issue

`cloudflare_run1.pcap` exposed a difference:

- Python/TShark found 11 ClientHellos.
- The earlier C++ build found fewer.

The issue was tied to handling later ClientHellos / reassembly behavior in flows such as TLS 1.3 HelloRetryRequest cases.

### Verification after fix

The corrected C++ engine reached the intended 11/11 ClientHello/ServerHello behavior on the test capture.

## Principle retained

> Correctness is a gate for benchmarking.
