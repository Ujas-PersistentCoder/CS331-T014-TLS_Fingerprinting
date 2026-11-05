> Historical project notes: commands, paths and test counts describe the recorded revision. For the current repository layout and runnable commands, use the [phase README](../../README.md).

# Phase 2 Unified Charter: End Goal, Architecture, and Branch Review Rubric
**Project:** CS331 Advanced TLS Fingerprinting Engine (`tlsfp_phase2`)  
**Team:** T014  
**Date:** November 2026  
**Status:** Approved Architectural Charter & Review Standard

---

## 1. Executive Summary & The End Goal

### What We Are Building
We are evolving `tlsfp_phase2` from a standard passive TLS fingerprinter (JA3 / JA4) into an **enterprise-grade, spoof-resistant, next-generation TLS inspection and telemetry engine**. 

Modern encrypted traffic is facing two seismic transitions:
1. **Metadata Privacy via ECH (RFC 9849):** The SNI and sensitive handshake extensions are encrypted inside `ClientHelloInner`, leaving middleboxes with only the outer envelope.
2. **Post-Quantum Cryptography via Hybrid KEMs (RFC 10024 / RFC 9954):** Lattice-based key shares (ML-KEM) dramatically inflate the handshake payload, causing multi-segment fragmentation at standard MTUs.
3. **Fingerprint Evasion & Spoofing:** Attackers trivially forge user-space TLS client signatures (e.g. using `curl-impersonate` or custom TLS stacks) while running on a completely different OS kernel.

### The Unified System Vision
When processing packets at wire speed (from live interfaces or large PCAP captures), the engine produces a **unified four-layer forensic fingerprint** for every TLS flow:

```
+-----------------------------------------------------------------------------------------+
|                                UNIFIED FORENSIC RECORD                                  |
+-----------------------------------------------------------------------------------------+
|  [Layer 1: TLS Fingerprint]    JA3: 771,4865-4866-4867...,0-23-65281-10-11...,29-23...   |
|                                JA4: t13d1516h2_8daaf6152771_0271bf386a56                |
+-----------------------------------------------------------------------------------------+
|  [Layer 2: Transport Ground]   JA4T: 65535_mss1460,wscale7,sackOK,ts_128_df (Win11/x64)|
|                                Cross-Layer Integrity: MATCH (or SPOOF_DETECTED)         |
+-----------------------------------------------------------------------------------------+
|  [Layer 3: ECH Posture]        ECH: PRESENT (Outer SNI: cloudflare.com, ConfigID: 0x42) |
|                                Compliance: RFC 9849 (Payload: 144B, %32==16, Outer OK)  |
|                                Server Disposition: ACCEPTED_CONFIRMED (via Keylog/HRR)  |
+-----------------------------------------------------------------------------------------+
|  [Layer 4: Quantum Posture]    KEM Group: 0x11ec (X25519MLKEM768, RFC 10024)           |
|                                Client Share: 1216B | Server Share: 1120B (Directional)  |
|                                Quantum Readiness: POST_QUANTUM_HYBRID (Level 3/FIPS 203)|
+-----------------------------------------------------------------------------------------+
```

---

## 2. The Three Parallel Tracks: Scopes, Requirements & Boundaries

```
                             [ Raw Packet Stream ]
                                       |
                +----------------------+----------------------+
                |                                             |
         [ TCP SYN / ACK ]                             [ TCP Data Segments ]
                |                                             |
        +---------------+                             +---------------+
        |  TRACK A:     |                             | Two-Tier      |
        |  JA4T / L4    |                             | Accumulator   |
        |  Transport    |                             +-------+-------+
        +-------+-------+                                     |
                |                                    [ Assembled ClientHello ]
                |                                             |
                |                             +---------------+---------------+
                |                             |                               |
                |                      +---------------+               +---------------+
                |                      |  TRACK B:     |               |  TRACK C:     |
                |                      |  ECH Outer    |               |  PQ-TLS       |
                |                      |  Telemetry    |               |  Inspection   |
                +----------------------+-------+-------+---------------+-------+-------+
                                               |
                                     [ Unified JSON Output ]
```

---

### Track A: JA4T & Transport-Layer Grounding (The Anti-Spoofing Anchor)

#### 1. Core Purpose
- TLS fingerprints (JA3/JA4) execute entirely in user space. Any tool (`curl-impersonate`, Python `tls-client`, Go `utls`) can mimic a browser's exact cipher suite, extension order, and ALPN.
- **The Ground Truth:** The TCP/IP handshake is constructed by the operating system kernel. An attacker running `curl-impersonate` on an Ubuntu server pretending to be Windows 11 Chrome exhibits a fatal discrepancy: the TCP SYN options match Linux (TCP window size, MSS, option order `MSS,SACK,TS,NOP,WScale`), but the TLS fingerprint claims Windows.
- JA4T inspects the SYN packet to fingerprint the transport stack, bridging the OS-layer and application-layer identity.

#### 2. Key Deliverables
- **TCP SYN Option Extractor:** Zero-copy parsing of TCP header options (`MSS`, `Window Scale`, `SACK Permitted`, `Timestamps`, `NOP`).
- **JA4T Formatter:** Standard JA4T string generation (`WindowSize_Options_TTL_Flags`).
- **OS Discrepancy Matrix:** Fast lookup verifying if the declared JA3/JA4 client profile matches the observed TCP SYN signature.
- **Performance Toggle (`-T` / `--ja4t`):**
  - Must have zero performance impact when disabled.
  - When enabled, only inspects SYN/SYN-ACK packets without adding overhead to data paths.

#### 3. What to Accept as a Bonus
- TCP window size scaling analysis, TTL hop-distance estimation (estimating initial TTL: 64, 128, or 255), active TCP RST / window-probing detection.

#### 4. What Must Be Flagged / Rejected
- **Do NOT** parse TCP options on non-SYN packets (wastes CPU cycles; options are negotiated only on SYN).
- **Do NOT** allocate heap memory per TCP packet.
- **Do NOT** block the TLS pipeline if SYN is missed (asymmetric routing or mid-flow capture must degrade gracefully).

---

### Track B: ECH — Encrypted Client Hello (RFC 9849 Compliance & Telemetry)

#### 1. Core Purpose
- Ensure 100% compliance with RFC 9849, RFC 9848, RFC 9850, and RFC 8879.
- Extract transparent outer envelope metadata from extension `0xfe0d` without attempting impossible in-flight decryption.
- Quantify network-wide ECH adoption and distinguish real ECH deployments from GREASE probes.

#### 2. Key Deliverables & The Strict Evidence Contract
The reviewer must enforce the **3-Tier Evidence Contract**:
- **Tier 1 (Observed Facts):**
  - ECH Outer Extension `0xfe0d` extracted without truncating.
  - `config_id`, `cipher_suite` (KDF / AEAD), `enc` length, and `payload` length.
  - Outer SNI vs absence of SNI.
  - Padding adherence: Evaluate $L_{\text{payload}} \pmod{32} \equiv 16$.
  - Duplicate Extension Guard: Enforce RFC 8446 §4.2 (`EchParse::DUPLICATE` if `0xfe0d` appears $>1$ time).
- **Tier 2 (Inferred Hypotheses - Wire Only):**
  - Server Hello rejection: Extension `0xfe0d` sent in ServerHello contains `retry_configs` (server rejected ECH).
  - HRR status: RFC 9849 §7.1 permits a rejecting server to send `0xfe0d` in HRR. **Presence does NOT confirm acceptance.** Only absence confirms non-acceptance.
- **Tier 3 (Ground Truth Verification - SSLKEYLOGFILE):**
  - Under RFC 9850 §2.3, if ECH was accepted, the TLS 1.3 traffic secrets in `SSLKEYLOGFILE` are indexed by `ClientHelloInner.random`, which differs from `ClientHelloOuter.random`.

#### 3. What to Accept as a Bonus
- Support for Compressed Certificates (RFC 8879: Brotli, Zstandard) telemetry.
- Config ID stability tracking across connections to detect DNS cache TTL expirations.

#### 4. What Must Be Flagged / Rejected
- **Factual Error:** Claiming that the presence of `0xfe0d` in HRR proves ECH acceptance.
- **Malformed Spec Citations:** Referring to draft numbers when RFC 9849 is published.
- **Buffer Truncation:** Clamping the outer payload to 64 or 128 bytes (it must parse full variable-length HPKE enc shares).
- **Silent Failure on Malformed Extensions:** Engine must report parsing error codes (`EchParse::MALFORMED_LENGTH`, `DUPLICATE`).

---

### Track C: PQ-TLS — Post-Quantum TLS (RFC 10024 & RFC 9954 Telemetry)

#### 1. Core Purpose
- Full compliance with RFC 10024 (Hybrid Key Exchange: X25519MLKEM768) and RFC 9954 (P-256 / P-384 ML-KEM hybrids).
- Measure organizational and Internet-scale quantum readiness.
- Bridge the JA4 blind spot: because JA4 deliberately omits `supported_groups`, our engine outputs the PQ classification alongside JA4.

#### 2. Key Deliverables & Wire Precision
- **Codepoint Recognition:**
  - `0x11ec`: `X25519MLKEM768` (ML-KEM-768 + X25519)
  - `0x11eb`: `SecP256r1MLKEM768` (ML-KEM-768 + P-256)
  - `0x11ed`: `SecP384r1MLKEM1024` (ML-KEM-1024 + P-384)
  - `0x639a`: Historical draft Kyber hybrid (Chrome 124–130)
- **Exact Key Share Sizing (Direction-Specific):**
  - For `0x11ec`: Client key share is **1216 bytes** (ML-KEM-768 1184B + X25519 32B). Server key share is **1120 bytes** (ML-KEM-768 ciphertext 1088B + X25519 32B).
- **Multi-Segment Accumulation Verification:**
  - A hybrid PQ ClientHello with ECH exceeds standard MSS (~1448B), producing 2 to 3 TCP segments (2.0–2.8 KB total). The Two-Tier Accumulator must assemble these without dropping or corrupting the handshake.

#### 3. What to Accept as a Bonus
- Tracking server acceptance of PQ key shares (confirming whether the server selected `0x11ec` or downgraded to classical `0x001d` X25519).
- Latency / round-trip impact metrics comparing PQ handshakes vs classical handshakes.

#### 4. What Must Be Flagged / Rejected
- **Factual Error:** Claiming FIPS 203 defines TLS wire format (FIPS 203 defines the mathematical KEM algorithm; RFC 10024 defines the TLS wire integration).
- **Order Error:** Assuming X25519 comes first on the wire (ML-KEM comes first, X25519 second).
- **Overselling JA4 Blind Spot:** Claiming JA4 is completely broken. (The accurate statement is: *JA4 does not encode key exchange groups; our engine extracts and reports group metadata alongside JA4*).

---

## 3. Engineering & Performance Guardrails (Non-Negotiable)

Every PR and code contribution across all three branches must satisfy the following system constraints:

1. **Zero-Copy & Memory Bounds:**
   - No dynamic allocations (`malloc`, `new`, `std::string` copies) in the packet processing hot path.
   - Accumulator per-flow buffer capped at **8 KB** to prevent TCP state-exhaustion DoS.
2. **Deterministic CLI Performance:**
   - Running with default settings must sustain $>100\text{k pps}$ on standard PCAPs.
   - Optional features (e.g. JA4T) must be gateable via CLI flags (`-T`, `--ja4t`).
3. **Structured JSON Output:**
   - Output records must conform to the unified 4-layer JSON schema for downstream consumption.
4. **POSIX C++17 Standard:**
   - Must build cleanly with `-Wall -Wextra -Werror` on standard Linux/WSL with GCC 11+ or Clang 13+.
   - No external runtime dependencies beyond `libpcap` and `OpenSSL` (libcrypto). Unit tests use fetched GoogleTest.

---

## 4. Code Review Rubric & Acceptance Checklist

When a teammate submits code for Track A, B, or C, evaluate against this checklist:

| Check Category | Criteria | Pass / Flag |
| :--- | :--- | :--- |
| **Correctness** | Adheres strictly to RFCs (RFC 8446, RFC 9849, RFC 10024). No draft confusion. | MUST PASS |
| **Evidence Contract** | Distinguishes observed wire facts from ground truth. No false ECH acceptance claims. | MUST PASS |
| **Wire Robustness** | Handles fragmented packets, zero-length fields, out-of-order segments, GRO/LRO frames. | MUST PASS |
| **Memory Safety** | Bounds checks on all byte reads (`ByteReader`). No buffer overflows or leaks. | MUST PASS |
| **Performance** | O(1) or tight bounded lookups; no unbounded allocations in packet callbacks. | MUST PASS |
| **Test Coverage** | Accompanied by unit tests and validated against realistic PCAPs (e.g., `pq_ech_chrome.pcap`). | MUST PASS |

---
*Document approved for Phase 2 implementation. All branches must align with these specifications.*

