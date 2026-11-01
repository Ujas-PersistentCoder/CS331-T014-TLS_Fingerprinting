# Phase 2 Implementation Plan: Architecture, Verticals & Team Breakdown

**CS 331 Computer Networks — Project 11 (Team T014)**  
**Objective:** Pivot from a basic hash generator into an end-to-end network security and transport analysis engine.

---

## 1. What We Learned from Midterm Feedback

1. **Drop the Python vs. C++ Language Race:** We are no longer comparing speeds. **C++ is our Core Network Monitor** (zero-copy wire sniffing, POSIX headers); **Python is our Testbed** (traffic generation, attack orchestration, automated testing).
2. **Fix the Hook Point:** We are removing the fragile 500-line user-space TCP reassembler. Standard TLS handshakes fit inside a single 1500-byte MTU frame. Rebuilding RFC 793 in user space was architecturally misplaced.
3. **Focus on Real Defensive Value:** TLS fingerprints (JA3/JA4) run in user space and are easily spoofed by tools like `curl-impersonate`. To provide real security value, we will cross-reference Layer 7 TLS handshakes with Layer 4 OS kernel TCP signatures (JA4T).

---

## 2. Phase 2 Workflow & Timeline


```

+-------------------------------------------------------------------------+
| Milestone 1: Core Engine Revamp (Baseline Foundation)                  |
| Deliverable: Clean AF_PACKET hook, zero-copy buffer, no reassembler    |
+-------------------------------------------------------------------------+
│
▼
┌────────────────────────────┼────────────────────────────┐
│                            │                            │ 
▼                            ▼                            ▼
(Feature Branch 1)          (Feature Branch 2)        (Feature Branch 3)
[ Track A: JA4T & Evasion ]   [ Track B: UDP & QUIC ]    [ Track C: Offloads, PQ & ECH ]

* TCP SYN options parser      - UDP port 443 sniffer     - ethtool GRO on/off matrix
* Flow tracker (4-tuple)      - Initial header decode    - ML-KEM-768 multi-packet MTU
* curl-impersonate detection  - CRYPTO frame decrypt     - Encrypted Client Hello
* OS discrepancy alert        - q13... JA4-QUIC hash     - Privacy vs. visibility report
│                            │                            │
└────────────────────────────┼────────────────────────────┘
│
▼
+-------------------------------------------------------------------------+
| Milestone 3: Integration, Benchmarking & Final Submission               |
| Deliverable: Merged C++ engine, automated Python testbed, final report |
+-------------------------------------------------------------------------+

```

---

## 3. Detailed Work Breakdown

### Milestone 1: Core Engine Revamp (Prerequisite Foundation)
*Must be merged into `main` before feature branches begin coding in C++.*
* Strip out old sequence tracking, retransmission handling, and out-of-order buffers.

> **Confusion regarding the need for TCP Reassembly**. Here is the supporting theory:
> - An application using a TCP socket receives an ordered byte stream. It does not ordinarily need to reassemble TCP segments, remove retransmissions, or reorder out-of-order data itself.
> - A passive packet analyzer reading captured packets sees individual packets. If it wants to reconstruct the same byte stream, it may need to account for TCP segmentation, retransmissions, ordering, and missing data—or use a library that does so.  
>
> Our TLS fingerprinting project sits at the intersection of these two perspectives. Whether reassembly is needed depends on *where* the tool obtains its input.
> - TCP stream reassembly is needed if our packet parser must reconstruct a stream from individual segments and the relevant bytes do not arrive together.
> - Similarly, need for custom dedup logic also depends. The TCP stack removes duplicate data for a socket consumer; but a packet observer may see retransmissions.
> - TLS record framing and TLS handshake parsing are still required as it's L7 (application layer) level.

* Implement a **Two-Tier Stream Handler**:
  * **Fast Path (Single Packet):** If TLS Handshake Length $\le$ TCP Payload, parse directly from zero-copy `libpcap` buffer. (Applies to >95% of classic handshakes).
  * **Slow Path (Segment Accumulator):** If Handshake Length $>$ TCP Payload, append contiguous segments into a bounded **8192-byte (8 KB)** scratchpad, parse, and reset. *(Rationale: Modern Post-Quantum ClientHellos with ML-KEM-768/Kyber keys, certificate compression, and hybrid extension suites reach 2.5 KB – 3.5 KB. Bumping the scratchpad from 4 KB to 8 KB provides safe headroom with negligible memory overhead, ensuring large PQ-TLS handshakes are never truncated).*
* Validate 100% parity across our existing 7 PCAP baselines.

---

### Track A: JA4T & Cross-Layer Impersonation Detection
*Focus: Catching tools that spoof browser TLS handshakes.*

* **The Problem:** `curl-impersonate` on Linux sends Chrome's exact TLS extension order. In general, **L7 (TLS/Application layer) can be easily modified/spoofed**. JA3/JA4 alone cannot detect this spoof.
* **The Solution:** The user controls the TLS handshake (L7), but the OS kernel controls TCP options (L4).  
> **Why L4 Identifies the OS**: The kernel dictates default values for the Initial Window Size, TTL (Time to Live), Window Scaling, and the specific order of TCP Options (like SACK or Timestamps).  
* **Tasks:**
  1. Parse the TCP SYN packet in C++: extract TCP Initial Window, Window Scale, and ordered TCP options (`mss-ws-sack-ts`) to compute the **JA4T** fingerprint.
  2. Extract and normalize IP TTL (Linux defaults to 64; Windows defaults to 128).
  3. Correlate SYN data with the subsequent ClientHello on the same 4-tuple.
  4. Build an alert: If L7 claims Windows Chrome, but L4 TCP options and TTL indicate a Linux kernel, flag `IMPERSONATION_MISMATCH`.
  5. Build a Python/Docker test harness running `curl-impersonate` to trigger and prove this detection live.

---

### Track B: Transport Layer Evolution — UDP & QUIC Support
*Focus: Extending coverage to modern HTTP/3 traffic.*

* **The Problem:** Over 30% of modern web traffic (Google, Cloudflare, Meta) runs HTTP/3 over UDP port 443. Classic TCP sniffers miss this completely.
* **Tasks:**
  1. Extend `libpcap` filter to capture UDP port 443 traffic.
  2. Parse the QUIC Long Header and detect `Initial` packets.
  3. Extract the Destination Connection ID (DCID).
  4. Derive initial decryption secrets using RFC 9001 HKDF-Expand-Label with fixed QUIC v1 salt (`0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`).
  5. Remove header protection (AES-ECB mask on packet number) and decrypt the `CRYPTO` frame payload using OpenSSL AES-128-GCM to access the plaintext TLS 1.3 ClientHello.
  6. Output JA4 fingerprints with the formal `q13...` transport prefix.
* **Pro-Tips for Track B Pair:**
  * *Verify against Wireshark first:* Capture a QUIC trace, decrypt it in Wireshark, and extract the DCID and decrypted keys as ground-truth unit tests.
  * *Prototype in Python first:* Test HKDF derivation and AES-GCM decryption in a 15-line Python script using `cryptography` before writing C++ OpenSSL EVP calls.
  * *Target QUIC v1 only:* Hardcode support strictly for QUIC version 1 (`0x00000001`), ignoring obsolete drafts and v2.

---

### Track C: Systems Depth — Kernel Offloads, PQ-TLS & ECH
*Focus: Investigating hardware offloading, real MTU fragmentation, and encryption limits.*

* **1. Offload Testing (GRO / TSO):**
  * Write a Python automation script using `ethtool` to test two network states:
    * **State 1 (Production):** `gro on`, `tso on` (Kernel coalesces packets into super-buffers).
    * **State 2 (Raw Wire):** `gro off`, `tso off` (Packets arrive strictly bounded by 1500B MTU).
  * Record packet counts, processing times, and buffer behavior across both states.
* **2. Post-Quantum TLS (PQ-TLS):**
  * Modern ML-KEM-768 (Kyber) key shares add ~1184+ bytes, pushing the ClientHello to 2.5 KB – 3.5 KB.
  * Capture live handshakes against Cloudflare PQ endpoints (`pq.cloudflareresearch.com`).
  * Demonstrate that with `gro off`, PQ-TLS physically fragments across 2 to 3 TCP packets, verifying the need for the Segment Accumulator.
* **3. Encrypted Client Hello (ECH) — Blindness & Unmasking Investigation:**
  * **The Cryptographic Reality:** ECH splits the handshake into a plaintext dummy `ClientHelloOuter` (decoy SNI like `cloudflare.com`) and an encrypted `ClientHelloInner` (real SNI and ciphers) via HPKE (RFC 9180). Eavesdroppers without keys cannot decrypt this payload.
  * **Our Dual-Perspective Demonstration:**
    1. *Authorized Decryption (Enterprise Gateway / Forensic Model):* Feed the parser the ECH private key or client-side `SSLKEYLOGFILE` HPKE secrets $\rightarrow$ decrypt `ClientHelloInner` $\rightarrow$ reveal true SNI and true JA4 fingerprint (`Outer: t13d030200_...` vs. `Inner: t13d1516h2_...`).
    2. *Unauthorized Side-Channel Unmasking (Wire Sniffer Model):* Unmask destinations without keys using multi-protocol correlation:
       * **DNS Dependency Attack:** Correlate preceding cleartext `HTTPS` Resource Record (Type 65) DNS queries (`ech=...`) to subsequent ECH flows with 100% accuracy.
       * **Ciphertext Length Side-Channel:** Coarse padding variations leaking domain length.
       * **Active Enterprise Downgrade:** Middlebox DNS stripping of `ech=` to force plaintext SNI fallback.

---

## 4. Work Ownership & Pairings

| Track | Primary Focus | Key Deliverable |
| :--- | :--- | :--- |
| **Foundation** | Core Engine Revamp | Clean two-tier stream handler on `main` |
| **Track A** | JA4T & Impersonation | `curl-impersonate` detection via TCP options |
| **Track B** | UDP & QUIC Support | QUIC Initial packet decryption (`q13...`) |
| **Track C** | Offloads, PQ & ECH | `ethtool` matrix, PQ-TLS MTU trace & ECH report |

---

## 5. Development Rules to Avoid Roadblocks

1. **Branching Strategy:** Work strictly in feature branches (`feature/ja4t`, `feature/quic`, `feature/offloads-pq`). Do not touch `main` until the baseline engine revamp is merged.
2. **Fixed Structs First:** The Systems Leads must define and agree upon the shared data structures in C++ header files before writing internal logic, allowing Automation Leads to write test scripts against expected outputs in parallel.
3. **The 2-Hour Rule:** If anyone is stuck on an environment bug, dependency issue, or syntax error for more than 2 hours, flag it in the group chat immediately to get paired help.

---

## 6. What We Are Deliberately NOT Doing (And Why)

* **No JA4H (HTTP Fingerprinting):** In an encrypted HTTPS network, HTTP request headers are inside the encrypted TLS record. Inspecting HTTP headers without an active MITM certificate proxy violates the core requirement of **passive, non-intrusive traffic analysis**.
* **No JA4SSH:** Excluded to maintain undivided focus on TLS and transport-layer evolution.
* **No Superficial GUI Additions:** Flashy UI buttons do not earn marks in a Computer Networks evaluation. Deep packet dissection, architectural understanding, and empirical data do.

---

## 7. Summary Comparison: Phase 1 vs. Phase 2

| Dimension | Phase 1 (Midterm) | Phase 2 (Final Plan) |
| :--- | :--- | :--- |
| **Primary Focus** | Parsing byte offsets and computing MD5/SHA256 hashes. | Cross-layer network telemetry, evasion detection, and transport evolution. |
| **Transport Scope** | TCP only (`t13...`). | **Dual-Transport:** TCP (`t13...`) + **QUIC / UDP (`q13...`)**. |
| **TCP Handling** | 500-line user-space TCP reassembler trying to do full RFC 793. | Architecturally sound Fast Path + Bounded 8 KB Accumulator. |
| **Network Offloads** | Ignored (treated socket data as wire data). | Evaluated empirically using an `ethtool` GRO/TSO matrix. |
| **Attacker Model** | None (assumed benign traffic). | Adversarial (detecting spoofed TLS stacks using `curl-impersonate` via JA4T TCP/IP stack signatures). |
| **Protocol Scope** | Classic TLS 1.2 / 1.3 (single-packet assumption). | Next-generation TLS: Post-Quantum TLS (multi-packet fragmentation) + ECH (privacy vs. visibility). |
| **Language Dualism** | "C++ is faster than Python" microbenchmark. | C++ as wire-speed monitor; Python as adversarial experimentation harness. |
