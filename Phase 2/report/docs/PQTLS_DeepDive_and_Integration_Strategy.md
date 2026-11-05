> Historical project notes: commands, paths and test counts describe the recorded revision. For the current repository layout and runnable commands, use the [phase README](../../README.md).

# Post-Quantum TLS (PQ-TLS): Conceptual Blueprint, Protocol Mechanics & Engine Extension Strategy
**CS331: Computer Networks — Network Security & TLS Fingerprinting (Phase 2 Revamp)**  
**Team T014** · **Target Binary:** `tlsfp_phase2` · **Part 2 Final Deliverable**  
**Governing Specifications:**  
- **RFC 10024:** Hybrid Key Exchange in TLS 1.3 (August 2026)  
- **RFC 9954:** Combiner Function for Hybrid Key Exchange in TLS 1.3  
- **NIST FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM, August 2024)  
- **RFC 8446:** The Transport Layer Security (TLS) Protocol Version 1.3  
- **RFC 8701:** Generating Extensible Extensions and Ciphers (GREASE)  
- **RFC 9293:** Transmission Control Protocol (TCP)  
- **RFC 9849:** TLS Encrypted Client Hello (ECH)  

---

## 1. Executive Summary: The Post-Quantum Paradigm Shift

Classical asymmetric cryptography (RSA, Diffie-Hellman, ECDHE) relies on mathematical problems—specifically integer factorization and the discrete logarithm problem over finite fields and elliptic curves—that are vulnerable to quantum computing.

When a Cryptanalytically Relevant Quantum Computer (CRQC) becomes viable, **Shor's Algorithm** will solve these problems in polynomial time ($\mathcal{O}((\log N)^3)$). While symmetric cryptography (AES-256, SHA-256) remains quantum-resistant under Grover's Algorithm (which merely halves the effective bit-security), **all classical key exchange mechanisms (X25519, P-256, RSA) will be completely compromised**.

### 1.1 The Immediate Operational Threat: "Harvest Now, Decrypt Later" (HNDL)
Adversaries and nation-states do not need to possess a quantum computer today to compromise encrypted communications. Under HNDL attacks, adversaries passively capture and archive encrypted TLS sessions crossing public network infrastructure today, waiting for quantum computers to decrypt the pre-master secrets retroactively.

### 1.2 The Standardized Defense: Hybrid Key Exchange (RFC 10024 & RFC 9954)
NIST FIPS 203 standardizes ML-KEM itself as a mathematical Key-Encapsulation Mechanism. The integration of ML-KEM into TLS 1.3 is standardized by the IETF in **RFC 10024** (Hybrid Key Exchange in TLS 1.3) using the dual-PRF combiner construction from **RFC 9954**:
- Rather than immediately abandoning vetted elliptic curves, modern TLS clients and servers negotiate a **Hybrid Key Exchange** combining a post-quantum KEM (ML-KEM) with a classical ECDHE curve (X25519 or P-256).
- **Secret Combination:** Both parties compute:
  $$\text{Shared Secret } Z = Z_{\text{MLKEM}} \parallel Z_{\text{ECDHE}}$$
  This concatenated value $Z$ is fed directly into the standard TLS 1.3 key schedule (RFC 8446 §7.1) as the input keying material for `HKDF-Extract(0, Z)`.
- **Dual Security Guarantee:** Even if an unforeseen algebraic breakthrough weakens ML-KEM, classical ECDHE guarantees security against classical eavesdroppers; if quantum computers emerge, ML-KEM protects the session against retroactive decryption.
- **Authentication Scope Caveat:** Hybrid key exchange provides post-quantum *confidentiality* against passive recording. It does **not** provide post-quantum *authentication*: the server's certificate and signature algorithms (`signature_algorithms`, `0x000d`) remain classical RSA or ECDSA (RFC 10024 §1).

---

## 2. Protocol Facts: Wire Mechanics, Codepoints & Chronology

### 2.1 Standardized Codepoints & Chronological Deployment
Post-quantum TLS adoption has progressed across distinct chronological phases:

| Group Codepoint | Standard Name | Cryptographic Composition | Wire Order | Deployment Chronology |
| :--- | :--- | :--- | :--- | :--- |
| **`0x6399`** | `X25519Kyber768Draft00` | X25519 + Kyber-768 Draft | Kyber \|\| X25519 | **Precursor:** Chrome 124–130 (early Cloudflare/Google trials) |
| **`0x639a`** | `SecP256r1Kyber768Draft00` | NIST P-256 + Kyber-768 Draft | Kyber \|\| P-256 | **Precursor:** Early enterprise/NIST testbeds |
| **`0x11ec`** | `X25519MLKEM768` | X25519 + NIST FIPS 203 ML-KEM-768 | **ML-KEM-768 \|\| X25519** | **IETF Standard:** Chrome 131+, Go 1.24+, OpenSSL 3.5+ (RFC 10024) |
| **`0x11eb`** | `SecP256r1MLKEM768` | NIST P-256 + ML-KEM-768 | **ML-KEM-768 \|\| P-256** | **IETF Standard:** FIPS/government hybrid profile (RFC 10024) |
| **`0x11ed`** | `SecP384r1MLKEM1024` | NIST P-384 + ML-KEM-1024 | **ML-KEM-1024 \|\| P-384** | **IETF Standard:** High-security profile (RFC 10024) |

*Important Wire Clarification:* RFC 10024 §3 explicitly mandates the wire order: the **ML-KEM component comes FIRST**, and the **ECDHE component comes SECOND**.

### 2.2 Direction-Specific Key Share Dimensions (RFC 10024 §3)
The wire size of post-quantum key exchange payloads diverges substantially between the client offer and the server response:

```
                          RFC 10024 KEY SHARE FIELD SIZES
┌─────────────────────┬───────────┬──────────────────────────┬──────────────────────────┐
│ Hybrid Group Name   │ Codepoint │ Client Share (key_share) │ Server Share (key_share) │
├─────────────────────┼───────────┼──────────────────────────┼──────────────────────────┤
│ X25519MLKEM768      │  0x11ec   │ 1216 Bytes               │ 1120 Bytes               │
│                     │           │ (1184B KEM PK + 32B EC)  │ (1088B CT + 32B EC)      │
├─────────────────────┼───────────┼──────────────────────────┼──────────────────────────┤
│ SecP256r1MLKEM768   │  0x11eb   │ 1249 Bytes               │ 1153 Bytes               │
│                     │           │ (1184B KEM PK + 65B EC)  │ (1088B CT + 65B EC)      │
├─────────────────────┼───────────┼──────────────────────────┼──────────────────────────┤
│ SecP384r1MLKEM1024  │  0x11ed   │ 1665 Bytes               │ 1665 Bytes               │
│                     │           │ (1568B KEM PK + 97B EC)  │ (1568B CT + 97B EC)      │
└─────────────────────┴───────────┴──────────────────────────┴──────────────────────────┘
```
- **P-256 Encoding:** P-256 points in TLS 1.3 are encoded uncompressed (1 byte format `0x04` $+$ 32 bytes X $+$ 32 bytes Y = **65 bytes**). Thus, `SecP256r1MLKEM768` client share = $1184 + 65 = \mathbf{1249\text{ bytes}}$.
- **P-384 Encoding:** Uncompressed P-384 point = $1 + 48 + 48 = \mathbf{97\text{ bytes}}$. Client share = $1568 + 97 = \mathbf{1665\text{ bytes}}$.
- **Server Asymmetry:** In ML-KEM-768, the client transmits an encapsulation public key (1,184 bytes), while the server responds with a ciphertext encapsulation (1,088 bytes) plus its 32-byte X25519 public key, totaling **1,120 bytes**.
- These dimensions describe strictly the `key_exchange` field inside extension `0x0033`, not the complete packet length.

---

## 3. The Fingerprinting Frontier: The JA4 Relationship

### 3.1 How JA4 Evaluates ClientHellos
FoxIO's JA4 algorithm hashes three distinct components:
- **`ja4_a`:** Protocol transport, TLS version, SNI indicator (`d` or `i`), cipher count, extension count, ALPN.
- **`ja4_b`:** SHA-256 (truncated to 12 hex characters) of numerically sorted cipher suite IDs.
- **`ja4_c`:** SHA-256 (truncated to 12 hex characters) of numerically sorted extension IDs (excluding SNI `0x0000` and ALPN `0x0010`) $+$ wire-ordered signature algorithm IDs.

### 3.2 The Grounded Evaluation of JA4 & PQC
1. **Payload Agnosticism:** JA4 hashes extension IDs, **not** extension payloads. Both classical Chrome and Post-Quantum Chrome transmit extension `0x0033` (`key_share`) and extension `0x000a` (`supported_groups`).
2. **Supported Groups Omission:** FoxIO deliberately omitted `supported_groups` (`0x000a`) from `ja4_c` to reduce hash churn caused by varying elliptic curve offerings across client environments.
3. **The Concrete Finding:**  
   If all other client offerings (cipher suites, extensions, signature algorithms) remain unchanged, a client offering classical X25519 and a client offering X25519MLKEM768 will produce the **exact same JA4 hash**.
4. **The Project's Role:**  
   JA4 alone does not identify the key-exchange group. Our engine reports group offerings and key-share metadata alongside JA4, evaluating its complementary security inventory value.

### 3.3 JA3 vs. JA4 Under PQC
- **JA3:** Field 4 of JA3 hashes the exact decimal values of `supported_groups`. When a client adds `0x11ec` (`4588`) or `0x6399` (`25497`), the JA3 hash changes completely, causing database cache misses.
- **Connection Security vs. Client Identity:** A ClientHello fingerprint cannot determine a future server choice. A client offering `0x11ec` can result in a hybrid session with a modern server, or a classical fallback with an older server. Client identification and connection security posture are separate tasks.

---

## 4. Transport Layer Reality: Stream Accumulation for PQ-TLS

### 4.1 TCP Segmentation vs. IP Fragmentation
A common network engineering inaccuracy is conflating TCP segmentation with IP fragmentation:
- **TCP Segmentation (RFC 9293):** Operating at Layer 4, the operating system splits the application-layer TLS stream across multiple TCP segments bounded by the Maximum Segment Size (MSS). No IP-layer fragmentation occurs.
- **MSS Reality:** On standard Ethernet networks (MTU 1500 bytes), IPv4 TCP MSS is typically **1448 to 1460 bytes** (accounting for IP and TCP options like timestamps).

### 4.2 Handshake Size Dimensions & Real-World Framing
- A classical ClientHello fits comfortably in a single packet (roughly 500–800 bytes).
- A modern hybrid ClientHello offering `X25519MLKEM768` carries a **1,216-byte key share**. Combined with standard extensions, session ID, ciphers, and GREASE padding, the handshake reaches approximately **1.8 KB to 2.4 KB**.
- When combined with Encrypted Client Hello (ECH, ~350–450 bytes), the total ClientHello spans **2.2 KB to 2.8 KB**.
- **Transport Consequence:** Modern post-quantum browser handshakes **routinely span 2 TCP segments** on standard MTU networks.

### 4.3 The Role of the 8 KB Accumulator
- **Implementation Tradeoff:** An 8192-byte (8 KB) scratchpad is an engine implementation limit, not a protocol guarantee. (RFC 8446 allows TLS plaintext records up to 16 KB, and handshakes can span multiple records).
- **Engine Function:** Our **Two-Tier Accumulator** buffers multi-segment handshakes up to 8 KB without heap allocations in steady state. If segments exceed 8 KB or arrive out-of-order beyond tracking windows, the engine safely flags `ACCUMULATOR_OVERFLOW` or `GAP_DETECTED` rather than corrupting memory.

---

## 5. How PQ-TLS Extends & Upgrades Our Engine

Integrating Post-Quantum TLS telemetrics transforms our engine from a simple passive hash calculator into a **comprehensive cryptographic intelligence and connection security inventory platform**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        HOW PQ-TLS ENHANCES THE ENGINE                                  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. Bridges the JA4 Blind Spot    │ Reports key exchange group & share dimension        │
│                                  │ alongside JA4 without breaking hash stability.      │
├──────────────────────────────────┼─────────────────────────────────────────────────────┤
│ 2. Connection Security Inventory │ Distinguishes negotiated hybrid sessions from       │
│                                  │ classical fallbacks (HYBRID vs. CLASSICAL).         │
├──────────────────────────────────┼─────────────────────────────────────────────────────┤
│ 3. Proactive vs. Reactive Audit  │ Detects whether client supplied a 1.2 KB share      │
│                                  │ upfront or deferred share transmission to an HRR.   │
├──────────────────────────────────┼─────────────────────────────────────────────────────┤
│ 4. Validates Stream Accumulation │ Exercises bounded accumulator slow-path against     │
│                                  │ real-world multi-segment 2 KB+ TCP streams.         │
├──────────────────────────────────┼─────────────────────────────────────────────────────┤
│ 5. Empirical Profile Consistency │ Correlates L4 TCP parameters (JA4T) with modern     │
│                                  │ crypto library capabilities (Go 1.24+, Chrome 131+).│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Bridging the "JA4 Blind Spot"
While JA4 provides an exceptionally stable fingerprint across browser updates by omitting elliptic curves, this exact design decision renders it insensitive to post-quantum adoption:
- A connection secured with classical X25519 (vulnerable to future quantum decryption) and a connection secured with hybrid X25519MLKEM768 produce identical JA4 hashes.
- **Engine Upgrade:** Our engine extracts and reports the advertised groups, top preference, and key share dimensions as an orthogonal metadata layer. Operators obtain both the stable client identity (via JA4) and the cryptographic security posture (via PQ telemetry) in a single unified output.

### 5.2 Cryptographic Downgrade & Stripping Detection
Passive fingerprinting engines traditionally inspect only the ClientHello. PQ-TLS integration extends our engine across both directions of the handshake, introducing bidirectional **Handshake Symmetry Analysis**:
- **Client Preference vs. Server Selection:** The engine inspects whether the client designated a hybrid group (`0x11ec` / `0x11eb`) as its primary preference (first entry in `supported_groups`) and proactively supplied its 1.2 KB share.
- **Negotiation Telemetry:**
  - `HYBRID_SELECTED_OBSERVED`: Server selected `0x11ec` from the proactive share in 1 RTT (quantum-safe forward secrecy achieved).
  - `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER`: Client explicitly offered hybrid PQC, but the server negotiated a classical curve (e.g., `0x001d` X25519 or `0x0017` secp256r1) or downgraded to TLS 1.2.
  - `HRR_REQUESTED_RETRY`: Server requested a hybrid key share via `HelloRetryRequest` because the client supported `0x11ec` but did not provide a proactive share.
- **Downgrade vs. Benign Fallback:** A classical selection is mathematically distinct from an active attack—most legacy servers simply do not yet support RFC 10024. However, by maintaining an optional endpoint cache, the engine can flag **anomalous cryptographic regression**: when a domain known to negotiate hybrid PQC suddenly negotiates classical X25519 or TLS 1.2, alerting security operators to potential active Man-in-the-Middle (MitM) key stripping.

### 5.3 Proactive vs. Reactive Negotiation Analysis
Clients navigate a bandwidth-versus-latency tradeoff when offering post-quantum keys:
- **Proactive KEM Negotiation:** Desktop clients on unmetered connections proactively include the 1,216-byte key share in their initial ClientHello to establish the session in 1 RTT.
- **Reactive KEM Negotiation:** Constrained mobile clients or battery-sensitive endpoints may advertise `0x11ec` in `supported_groups` but supply only a 32-byte classical key share initially to avoid transmitting 1.2 KB over cellular links unless the server explicitly demands it.
- **Engine Upgrade:** By verifying the presence and physical dimension of the offered share vector ($\ge 1200\text{ bytes}$), our engine categorizes client behavior into `PROACTIVE_SHARE_VALID` vs. `SUPPORTED_ONLY`.

### 5.4 Empirical Validation of the Stream Accumulation Pipeline
In classical TLS 1.3, the vast majority of ClientHellos fit inside a single 1500-byte Ethernet frame, rarely exercising multi-segment assembly paths.
- The inclusion of hybrid key shares (1,216 bytes) and ECH payloads (~400 bytes) pushes modern handshakes to 2.0 KB – 2.8 KB, forcing TCP segmentation across 2 packets.
- **Engine Upgrade:** PQ-TLS serves as the living empirical testbed for our **Two-Tier Accumulator**, demonstrating that our bounded 8 KB scratchpad reassembles fragmented handshakes with zero steady-state heap allocations.

### 5.5 Multi-Layer Profile Consistency
Rather than claiming to be an infallible "bot detector" (since Go 1.24+ and modern automated toolchains natively support `0x11ec`), our engine uses PQ telemetry as part of an objective **Profile Consistency Framework**:
- Cross-references Layer 4 transport metrics (JA4T: TCP window size, MSS, scale factor) with Layer 6 TLS capabilities (PQC group preferences, extension order).
- Correlates client-advertised capabilities with typical operating system network stacks to flag implementation discrepancies.

### 5.6 Strict RFC Wire Validation & Malformed Share Anomaly Telemetry
A critical vulnerability in passive network monitors is crashing or buffer-overflowing when encountering fuzzed, corrupted, or malicious handshake packets. The engine upgrades wire parsing into an active **protocol validation and intrusion detection layer**:
- **Direction-Specific Length Invariants (RFC 10024 §3):**
  - For client shares: `0x11ec` MUST be exactly 1,216 bytes; `0x11eb` MUST be exactly 1,249 bytes; `0x11ed` MUST be exactly 1,665 bytes.
  - For server shares: `0x11ec` MUST be exactly 1,120 bytes; `0x11eb` MUST be exactly 1,153 bytes.
  - If a packet advertises group `0x11ec` but `key_exchange_len != 1216`, the engine immediately flags `PQC_MALFORMED_SHARE_LENGTH` and safely terminates parsing without attempting out-of-bounds reads.
- **Duplicate Extension Guards (RFC 8446 §4.2):** RFC 8446 forbids multiple occurrences of any extension type. If an attacker injects multiple `0x0033` (key_share) or `0x000a` (supported_groups) extensions to cause parser desynchronization, the engine halts further extension processing and records `PQC_DUPLICATE_EXTENSION_ANOMALY`.
- **Zero-Allocation Safety:** Parsing runs through strict, bounds-checked span readers (`ByteReader`). Vector lengths and remaining buffer bytes are verified before every single byte read.

### 5.7 Transport-Layer Profiling: TCP Segmentation & Flight Correlation
Post-quantum handshakes span Layer 4 (Transport) and Layer 7 (Application) in ways classical TLS never did. The engine leverages this physical reality to create a new dimension of **Transport Flight Telemetry**:
- **Flight Segment Accounting:** The Two-Tier Accumulator instruments and logs the exact physical packet flight required to assemble the ClientHello:
  - `tcp_segment_count`: Number of TCP segments assembled (typically 1 for classical, 2 for hybrid PQC under standard MTU).
  - `tcp_payload_bytes`: Total wire bytes accumulated across segments before record completion.
  - `tcp_mss_clamped`: Whether segments were sliced cleanly at the standard 1,448-byte TCP MSS boundary.
- **GRO / LRO Kernel Offload Telemetry:** Distinguishes between handshakes assembled across distinct physical Ethernet frames versus "jumbo" frames reassembled in kernel-space via Large Receive Offload (LRO) or Generic Receive Offload (GRO).
- **Out-of-Order & Loss Metrics:** Tracks whether the initial 5-byte TLS record header arrived in segment 1 or was delayed/reordered, providing empirical network health indicators directly alongside TLS fingerprints.

---

## 6. Epistemological Framework: The Evidence Contract

Every output field displayed by the engine maps strictly to an authoritative wire source, an allowed claim, and an explicit unknown state:

| Field / Property | Wire Source | What It Proves (Observed) | What It Infers | When It Must Remain Unknown (Abstain) |
| :--- | :--- | :--- | :--- | :--- |
| **`supported_groups` contains `0x11ec`** | Ext `0x000a` body | Client advertises support for `X25519MLKEM768`. | Client crypto library supports RFC 10024 hybrid exchange. | Truncated extension. |
| **`key_share` contains `0x11ec`** | Ext `0x0033` client share | Client supplied an initial hybrid key share. | Client proactively offers hybrid key exchange. | Initial share omitted (e.g. reactive client). |
| **`key_share_len == 1216`** | Ext `0x0033` vector | Length matches RFC 10024 client share size. | Validly framed hybrid share vector. | Length mismatch $\rightarrow$ flag `MALFORMED_SHARE`. |
| **`server_selected_group`** | ServerHello ext `0x0033` | Server selected a specific group for this session. | Cryptographic key exchange group negotiated. | Server omitted `key_share` or sent HRR. |
| **`connection_posture`** | Handshake correlation | `HYBRID_SELECTED_OBSERVED` vs. `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER`. | Whether the server agreed to hybrid key exchange. | Session incomplete, truncated, or unobserved server flight. |
| **`malformed_share_anomaly`** | Vector length check | `key_exchange_len` does not match RFC 10024 invariant (e.g. $\neq 1216$ for `0x11ec`). | Packet corruption, fuzzer probe, or non-compliant client implementation. | Valid vector dimensions. |
| **`duplicate_ext_anomaly`** | Extension parser pass | Same extension ID seen $> 1$ time in one hello. | Direct RFC 8446 §4.2 protocol violation / injection anomaly. | All extension IDs unique. |
| **`tcp_flight_segments`** | Accumulator telemetry | Physical TCP segment count and accumulated payload bytes for ClientHello. | Layer 4 transport segmentation behavior across standard MTU/MSS boundaries. | Incomplete TCP stream or unreassembled fragments. |

---

## 7. Refined Presentation Strategy & Academic Viva Defense

### 7.1 Slide Deck Structure
- **Slide 1: The Threat & The Standard:** Shor's algorithm threatens classical forward secrecy ("Harvest Now, Decrypt Later"). The IETF standardized hybrid key exchange in RFC 10024 / RFC 9954 (August 2026), combining ML-KEM-768 with classical ECDHE.
- **Slide 2: The JA4 Relationship:** JA4 hashes extension IDs, not payloads, and omits supported groups to stabilize hashes. Consequently, JA4 alone does not identify the key exchange group. Our engine reports group and share metadata alongside JA4 to provide connection security posture.
- **Slide 3: Transport & Segmentation Reality:** A hybrid key share expands by 38× (1216B vs 32B), pushing ClientHellos to ~2.0 KB. On standard Ethernet networks, handshakes span 2 TCP segments. This provides concrete empirical justification for our bounded Two-Tier Accumulator.
- **Slide 4: Wire Dissection & Directional Asymmetry:** Client shares carry an encapsulation public key (1216B for X25519MLKEM768), while server shares carry an encapsulation ciphertext (1120B). Strict vector bounds validation guarantees memory safety.
- **Slide 5: Live Empirical Demo:** Comparing classical curl vs. modern Chrome visiting Cloudflare/Google post-quantum endpoints.

### 7.2 Defending Tough Viva Questions

- **Q: "Why didn't browsers just switch entirely to ML-KEM-768 instead of a hybrid?"**  
  *A: "Lattice-based cryptography is relatively new compared to 30 years of elliptic curve vetting. RFC 10024 mandates hybrid key exchange as a fail-safe: if an unexpected vulnerability breaks ML-KEM, classical X25519 guarantees security; if a quantum computer arrives, ML-KEM guarantees forward secrecy."*

- **Q: "Does JA4 distinguish between Post-Quantum and Classical connections?"**  
  *A: "JA4 hashes extension IDs, not payloads, and intentionally omits supported groups. Therefore, if other extensions and ciphers remain unchanged, classical and post-quantum connections produce identical JA4 hashes. Our engine does not claim to 'fix' JA4; instead, it reports group and key-share metadata alongside JA4 to provide security posture visibility."*

- **Q: "Does a client offering X25519MLKEM768 prove it is genuine Google Chrome?"**  
  *A: "No. Standard non-browser environments like Go 1.24+ enable X25519MLKEM768 by default. Furthermore, automated tools can drive real Chrome binaries. Observing group 0x11ec indicates client library capability, not software identity or human presence."*

- **Q: "Why is the server key share smaller than the client key share?"**  
  *A: "In RFC 10024 §3, the client share carries the ML-KEM-768 public key (1,184 bytes) plus the 32-byte X25519 public key (1,216 bytes). The server share carries the ML-KEM-768 ciphertext (1,088 bytes) plus its 32-byte X25519 public key, totaling 1,120 bytes."*

- **Q: "How does the engine distinguish a normal classical server from a post-quantum downgrade attack?"**  
  *A: "Passive inspection cannot cryptographically prove attack intent because an uncompromised server that lacks RFC 10024 support behaves identically to a server subjected to an active stripping proxy. Our engine adheres to the Evidence Contract: it objectively reports CLASSICAL_SELECTED_AFTER_HYBRID_OFFER. When historical endpoint telemetry is enabled, persistent regression on known-PQC endpoints is elevated to an anomaly alert for SOC operators."*

- **Q: "Why does the engine measure TCP segments when fingerprinting happens at the TLS layer?"**  
  *A: "Post-quantum keys physically change the transport characteristics of TLS. Because hybrid shares push ClientHellos beyond the standard 1,448-byte MSS, transport segmentation is no longer an anomaly—it is standard behavior. Instrumenting segment counts and reassembly buffer usage directly connects Layer 4 network reality with Layer 7 cryptographic security."*

- **Q: "What if a client lists 0x11ec in supported_groups but sends no initial key share?"**  
  *A: "TLS 1.3 allows clients to advertise group support without supplying a proactive key share. This is common in bandwidth-constrained clients. If the server selects that group, it issues a HelloRetryRequest (HRR) requesting the share. Our engine tracks this cleanly as SUPPORTED_ONLY."*

---

## 8. Explicit Non-Claims: What the Engine Does NOT Claim

| Non-Claim | Technical Justification |
| :--- | :--- |
| **"NIST FIPS 203 standardizes TLS hybrid exchange"** | FIPS 203 standardizes ML-KEM itself. TLS hybrid key exchange is standardized by IETF in RFC 10024 / RFC 9954. |
| **"JA4 is completely blind to all aspects of TLS"** | JA4 hashes extension IDs and ciphers. It omits supported groups and payloads by design. Other extensions may still differ. |
| **"PQC detection deterministically exposes bots"** | Go 1.24+ and modern libraries support ML-KEM; automation tools run real browsers. Crypto capabilities do not prove human presence. |
| **"Classical selection proves an adversarial downgrade"** | A server selecting X25519 may simply lack post-quantum support. |
| **"Hybrid key exchange provides post-quantum authentication"** | RFC 10024 hybrid exchange protects confidentiality; digital certificates and signatures remain classical RSA/ECDSA. |
| **"8 KB accumulator is a TLS protocol guarantee"** | RFC 8446 allows TLS records up to 16 KB. 8 KB is an engine implementation limit. |
