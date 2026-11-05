# High-Speed TLS Fingerprinting Engine (Phase 2)
**CS 331: Computer Networks | Spring 2026**  
**Team T014 — Project 11: Modernized Wire Inspection & Protocol Defense**

---

## 📖 1. Introduction

Passive TLS fingerprinting extracts immutable configuration parameters from unencrypted handshake metadata (cipher suites, extensions, elliptic curves, signature algorithms, and ALPN) to identify client applications without decrypting network payload. 

While Phase 1 established foundational implementations of **JA3/JA3S** and **JA4/JA4S**, real-world enterprise and carrier networks introduce major operational challenges:
1. **Extreme Throughput Requirements**: High-density uplinks process tens of thousands of concurrent handshakes per second, requiring sub-microsecond parsing latency and zero-copy packet ingestion.
2. **Network-Layer Fragmentation & Hardware Offloading**: Real-world ClientHellos exceed standard Ethernet MTU sizes (1500 bytes) due to extensive modern extension lists and quantum-safe key shares. Network interface cards (NICs) employ **Generic Receive Offload (GRO)** and **Large Receive Offload (LRO)** to coalesce packets into jumbo buffers (up to 7KB+) with synthetic TCP sequence offsets, breaking naive per-packet parsers.
3. **Transport-Level Impersonation & Evasion**: Advanced malware and tools like `curl-impersonate` spoof application-level TLS handshakes (e.g., mimicking Chrome on Windows), while running on Linux C2 nodes or automated bots.
4. **Encrypted Client Hello (ECH / RFC 8744)**: TLS 1.3 extensions that encrypt the inner handshake, masking true Server Name Indication (SNI) and extensions behind outer decoy framing.
5. **Post-Quantum Cryptography (PQ-TLS / RFC 10024)**: Hybrid key exchange mechanisms (e.g., X25519Kyber768Draft00, X25519MLKEM768) deploy large cryptographic keys (>1KB), introducing new negotiation states, HelloRetryRequest (HRR) loops, and wire fragmentation.

**Phase 2 delivers `tlsfp_phase2`**, a high-performance, multi-threaded C++17 wire-inspection engine designed to solve these modern transport challenges at line rate.

---

## 🔬 2. Theoretical Foundations & Architecture

```
                   ┌──────────────────────────────────────────────┐
                   │               NIC / PCAP Ingest              │
                   └──────────────────────┬───────────────────────┘
                                          │ Raw Packets
                                          ▼
                   ┌──────────────────────────────────────────────┐
                   │           Two-Tier TCP Accumulator           │
                   │  - Tier 1: Zero-copy Fast-Path (Single Pkt)  │
                   │  - Tier 2: Flow-pinned Reassembly (GRO/LRO)  │
                   │  - Out-of-Order / Retransmission / Rollover  │
                   └──────────────────────┬───────────────────────┘
                                          │ Complete TLS Records
                                          ▼
                   ┌──────────────────────────────────────────────┐
                   │    Symmetric Flow Dispatcher (SPSC Queues)   │
                   │    Hash: (src_ip ^ dst_ip) ^ (src_p ^ dst_p) │
                   └──────────────┬────────────────┬──────────────┘
                                  │                │
                    Worker 0 Queue│    ...         │Worker N Queue
                                  ▼                ▼
                     ┌──────────────────┐    ┌──────────────────┐
                     │  Worker Thread 0 │    │  Worker Thread N │
                     │ ──────────────── │    │ ──────────────── │
                     │ • JA3/JA3S (MD5) │    │ • JA3/JA3S (MD5) │
                     │ • JA4/JA4S (SHA) │    │ • JA4/JA4S (SHA) │
                     │ • JA4T / Cross-OS│    │ • JA4T / Cross-OS│
                     │ • ECH Dissection │    │ • ECH Dissection │
                     │ • PQ-TLS Offers  │    │ • PQ-TLS Offers  │
                     └──────────────────┘    └──────────────────┘
```

### 2.1 Two-Tier TCP Stream Accumulator
Naive TLS sniffers process packets in isolation, failing whenever a `ClientHello` spans multiple TCP segments. The Phase 2 engine implements a stateful **Two-Tier Accumulator**:
* **Tier 1 (Fast-Path)**: Zero-copy in-place parsing when a packet contains a complete TLS record header and payload within a single segment. Operates at near memory-bandwidth speeds.
* **Tier 2 (Slow-Path Reassembly)**: If a TLS record header indicates `length > segment_bytes`, or segments arrive out of sequence, the flow is promoted to Tier 2 reassembly:
  * Buffers contiguous bytes up to 16KB per flow.
  * Correctly handles **TCP sequence number rollovers** ($2^{32}-1 \to 0$).
  * Detects duplicate retransmissions and drops overlapping redundant prefixes.
  * Enforces stale-flow eviction timeouts to prevent memory exhaustion under asymmetric traffic.
* **GRO/LRO Invariance**: NICs often merge multiple TCP segments into 3KB–7KB jumbo frames. Our accumulator guarantees that packet streams parsed under **GRO ON** and **GRO OFF** yield byte-for-byte identical JA3, JA4, and ECH fingerprints (proven in `tests/test_fingerprints.cpp:GROInvarianceTest`).

---

### 2.2 JA4T / JA4TS: TCP Stack Fingerprinting & Cross-Layer Defense
While the TLS ClientHello is written by user-space applications (and can be spoofed by tools like `curl-impersonate`), the TCP `SYN` packet is crafted directly by the **operating system kernel**.

JA4T (FoxIO standard) inspects the TCP initial SYN to generate a deterministic fingerprint:
$$\text{JA4T} = \langle\text{WindowSize}\rangle\_\langle\text{TCP Options Wire Order}\rangle\_\langle\text{MSS}\rangle\_\langle\text{WindowScale}\rangle$$

* **Option Kinds**: `1` (NOP), `2` (MSS), `3` (Window Scale), `4` (SACK Permitted), `8` (Timestamps).
* **Stack Signatures**:
  * **Windows 10/11**: `64240_2-1-3-1-1-4_1460_8` (Default TTL: 128)
  * **Linux (Ubuntu/Debian)**: `64240_2-4-8-1-3_1460_7` (Default TTL: 64)
  * **Apple (macOS / iOS)**: `65535_2-1-3-1-1-8-4-0-0_1460_6` (Default TTL: 64)

#### Cross-Layer Impersonation Alerting
The engine inspects L3 (IP initial TTL and hop distance), L4 (TCP JA4T options layout), and L7 (TLS JA3/JA4 claimed browser/OS):
* If a packet advertises a **Windows Chrome TLS signature** (`JA4: t13d...` mapped to Windows), but arrives with a **Linux TCP stack layout** (`2-4-8-1-3`) and **TTL 64**, the engine triggers an immediate cross-layer alert:
  ```text
  [ALERT] Cross-Layer Impersonation Detected!
     Claimed Application OS: Windows
     Actual TCP Stack OS:    Linux (Corroborated by layout and TTL 64)
  ```

---

### 2.3 Encrypted Client Hello (ECH / RFC 8744)
ECH replaces the legacy cleartext Server Name Indication (SNI) by wrapping the client's handshake inside an outer dummy handshake:
* **Outer ClientHello**: Carries an unencrypted, public-facing cover name (e.g., `cloudflare.com`).
* **Encrypted Inner ClientHello**: Carries the real destination SNI and sensitive extensions, encrypted via **HPKE (Hybrid Public Key Encryption)** using AES-128-GCM or ChaCha20-Poly1305.

#### Engine Capabilities:
1. **Wire-Level Dissection**: Extracts extension `0xfe0d`, decoding the HPKE cipher suite, KDF ID, AEAD ID, Config ID, public encapsulated key, and ciphertext payload.
2. **GREASE vs. Real ECH Discrimination**: Differentiates browser GREASE probes from authentic ECH offers based on payload heuristics and outer extensions.
3. **Connection Lifecycle State Tracking**: Follows bidirectional flows from TCP SYN, through potential `HelloRetryRequest` (HRR) renegotiations, to final server cipher acceptance.
4. **Structured Telemetry**: Emits standard newline-delimited JSON (`--json <file>`) tracking full connection framing, negotiation parameters, and anomalies.

---

### 2.4 Post-Quantum TLS (PQ-TLS / RFC 10024)
To counter future "Harvest Now, Decrypt Later" quantum attacks, TLS 1.3 clients propose hybrid key exchange combining classical elliptic curves (X25519/SecP256r1) with post-quantum Key Encapsulation Mechanisms (**ML-KEM / Kyber-768**).

#### Engine Capabilities:
1. **Supported Groups Decoding**:
   * Draft: `0x6399` (`X25519Kyber768Draft00`)
   * NIST Standard: `0x11ec` (`SecP256r1MLKEM768`), `0x11ed` (`X25519MLKEM768`)
2. **Wire-Level Key Size Validation (RFC 10024)**:
   * `X25519Kyber768Draft00`: Exact expected key size 1184 bytes (Client) / 1088 bytes (Server).
   * `X25519MLKEM768`: Exact expected key size 1216 bytes (Client) / 1120 bytes (Server).
   * Detects truncated, oversized, or malformed key shares.
3. **Offer-to-Selection Posture Analysis**:
   * Evaluates client proactive shares: `PROACTIVE_SHARE_VALID`, `NO_PQ_OFFERED`, `UNKNOWN_SHARE`.
   * Correlates client offers against server choices:
     * `HYBRID_SELECTED_OBSERVED`: Server chose quantum-resistant hybrid exchange.
     * `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER`: Server downgraded to classical ECDH despite PQ offer.
     * `CLASSICAL_NO_PQ_OFFERED`: Classical handshake without PQ proposals.
     * `HRR_REQUESTED_RETRY`: Server requested key exchange renegotiation.

---

### 2.5 Multi-Threaded Engine with Symmetric Flow Pinning
To scale past **50,000–60,000+ packets/sec**, the engine adopts a lock-free parallel architecture:
1. **Symmetric Flow Pinning**:
   $$\text{worker\_idx} = [(\text{src\_ip} \oplus \text{dst\_ip}) \oplus (\text{src\_port} \oplus \text{dst\_port})] \pmod N$$
   Because bitwise XOR is commutative, packets in both flow directions ($A \to B$ and $B \to A$) map to the **exact same worker queue**.
2. **Lock-Free SPSC Queues**:
   Handshake jobs pass from the capture thread to worker threads via Single-Producer Single-Consumer lock-free ring buffers (`SPSCQueue<HandshakeJob, 2048>`), eliminating mutex lock contention during packet ingestion.
3. **Thread-Local State**:
   Each worker thread maintains its own isolated `PqtlsOfferTable` and scratchpads. Client offers and Server choices correlate within the same thread with **zero mutex locks and zero atomic contention**.

---

## 💻 3. Command-Line Reference

```text
Usage: tlsfp_phase2 [OPTIONS]

Options:
  -r <file>        Read and analyze offline PCAP/PCAPNG file
  -i <interface>   Capture live packets from network interface (requires root)
  -f <filter>      BPF packet filter string (default: "tcp")
  -t               Enable JA4T/JA4TS TCP fingerprinting and cross-layer alerts
  -v               Enable verbose dissection of TLS handshake fields
  -q               Quiet / benchmark mode (suppress output, measure pps)
  -j <threads>     Number of worker threads (default: auto-detect CPU cores)
  -u               Interactively prompt to label unknown fingerprints
  --json <file>    Create a new JSON Lines file of connection summaries
  -e, --ech        Enable stateful ECH analysis and connection tracking
  --no-ech         Disable ECH analysis (high-throughput line-rate mode, default)
  -p, --pq         Enable Post-Quantum TLS (PQ-TLS) posture analysis and wire checks
  --no-pq          Disable Post-Quantum TLS analysis (default)
  -c <catalog>     Load an extra catalog JSON (seed schema, e.g. ja4t / expected_os lab records)
  -h               Show this help message and exit
```

---

## 🚀 4. How to Clone, Build, and Run

### 4.1 System Prerequisites
Ensure standard C++17 build tools, CMake, libpcap, and OpenSSL development headers are installed:

#### Ubuntu 22.04 / 24.04 / WSL:
```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libssl-dev redis-server
```

#### macOS (Homebrew):
```bash
brew install cmake libpcap openssl redis
```

---

### 4.2 Build Instructions

Clone the repository and compile the Phase 2 engine:

```bash
git clone https://github.com/Ujas-PersistentCoder/CS331-T014-TLS_Fingerprinting.git
cd CS331-T014-TLS_Fingerprinting

# Configure and compile using CMake
cmake -S "Phase 2/code/engine" -B "Phase 2/code/engine/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "Phase 2/code/engine/build" --parallel
```

The resulting binary will be located at:
```text
Phase 2/code/engine/build/tlsfp_phase2
```

---

### 4.3 Running the Test Suite

Execute the GoogleTest regression suite containing **188 automated tests** covering flow tracking, accumulator reassembly, GRO/LRO invariance, JA4T options extraction, ECH parsing, and PQ-TLS posture validation:

```bash
ctest --test-dir "Phase 2/code/engine/build" --output-on-failure
```

Expected output:
```text
100% tests passed, 0 tests failed out of 188
Total Test time (real) = ~12.50 sec
```

---

### 4.4 Running on Bundled PCAPs

The repository includes curated packet captures under `Phase 2/code/pcaps/` illustrating each protocol capability:

#### 1. Baseline Fingerprinting (JA3 + JA4):
```bash
"./Phase 2/code/engine/build/tlsfp_phase2" -r "Phase 2/code/pcaps/tls-sni.pcapng" -v
```

#### 2. High-Throughput Line-Rate Benchmark (500k Packets):
```bash
"./Phase 2/code/engine/build/tlsfp_phase2" -r "Phase 2/code/pcaps/benchmark_500k.pcap" -q -j 4
```
*Measures raw throughput across worker threads without terminal I/O latency.*

#### 3. Full Modern Stack: ECH + Post-Quantum TLS + TCP Stack Inspection:
```bash
"./Phase 2/code/engine/build/tlsfp_phase2" -r "Phase 2/code/pcaps/pq_ech_chrome.pcap" -v -p -t -e
```

Sample output:
```text
 CLIENT  10.7.37.16:49678 ──▶ 192.178.177.95:443
   │  JA3:  ae4cd3a6bcef16e54026d4615523f62d  [<unknown>]
   │  JA4:  t13d1517h2_8daaf6152771_cb7bf5808d99  [Chromium (browser)]
   │  JA4T: 65535_2-1-3-1-1-4_1460_8  [inferred: Windows]  TTL 128, 0 hops
   │  [V-ClientHello] status=complete (complete ClientHello framing)
   │  [V-Outer SNI]   safebrowsing.googleapis.com
   │  [V-ECH #1] status=complete (decoded) variant=0 kdf_id=1 aead_id=1 config_id=31 enc_length=32 ciphertext_length=176
   │  [V-PQTLS-Offer] offered 0x11ec (X25519MLKEM768), first choice
   │  [V-PQTLS-Keys]  0x11ec (X25519MLKEM768) 1216B, 0x001d (x25519) 32B
   │  [V-PQTLS-Share] PROACTIVE_SHARE_VALID
   │  [V-PQTLS-Check] ok

 SERVER  192.178.177.95:443 ──▶ 10.7.37.16:49678
   │  JA3S: 907bf3ecef1c987c889946b737b43de8  [<unknown>]
   │  JA4S: t130200_1302_234ea6891581  [<unknown>]
   │  [V-PQTLS-Group]  0x11ec (X25519MLKEM768), post-quantum hybrid, key 1120B
   │  [V-PQTLS-Result] HYBRID_SELECTED_OBSERVED
   │  [V-PQTLS-Check]  ok
```

#### 4. GRO/LRO Invariance Check:
Verify that hardware offloaded jumbo frames and fragmented segments yield identical fingerprints:
```bash
"./Phase 2/code/engine/build/tlsfp_phase2" -r "Phase 2/code/pcaps/gro_on.pcap" -v
"./Phase 2/code/engine/build/tlsfp_phase2" -r "Phase 2/code/pcaps/gro_off.pcap" -v
```

#### 5. Cross-Layer Spoofing Detection:
```bash
"./Phase 2/code/engine/build/tlsfp_phase2" -r "Phase 2/code/testbed/generated/ja4t_only_spoof.pcap" -t -v \
  -c "Phase 2/code/testbed/generated/ja4t_lab_catalog.json"
```

#### 6. Live Interface Capture:
Capture live TLS traffic on network interface `eth0` with BPF filtering (requires root):
```bash
sudo "./Phase 2/code/engine/build/tlsfp_phase2" -i eth0 -f "tcp port 443" -v -p -t
```

---

## 🧪 5. Experimental Testbeds & Artifacts

The `Phase 2` directory includes experimental laboratories and empirical test suites:

* **ECH Laboratory (`Phase 2/code/experiments/ech/`)**:
  * An automated testbed integrating a pinned BoringSSL build and custom client/server binaries (`ech_lab`).
  * Generates real encrypted traffic sessions, pilot validations, and automated cross-checks against Wireshark/tshark.
* **JA4T Cross-Layer Spoofing Testbed (`Phase 2/code/testbed/ja4t_lab.py`)**:
  * Scapy-based framework injecting crafted TCP SYN packets with mismatched OS option layouts to validate cross-layer alerting.
* **Research Documentation & Presentations**:
  * Full technical report: `Phase 2/report/report.md` (and `report.docx`).
  * Deep-dive documentation: `Phase 2/report/docs/` covering GRO/LRO findings, kernel hookpoints, ECH integration, and PQ-TLS analysis.
  * Final presentation slides: `Phase 2/ppt/CN presentation.pptx`.

---

## 📁 6. Source File Structure

```text
Phase 2/code/engine/
├── CMakeLists.txt                # Unified build configuration and test harnesses
├── include/tlsfp/
│   ├── accumulator.hpp           # Two-Tier TCP stream reassembly buffer
│   ├── capture.hpp               # Ingestion engine and worker thread context
│   ├── db.hpp                    # In-memory and Redis catalog interface
│   ├── ech_analysis.hpp          # ECH state machine & interpretation
│   ├── ech_parser.hpp            # Wire dissection of extension 0xfe0d
│   ├── ja3.hpp                   # Salesforce JA3/JA3S fingerprint generation
│   ├── ja4.hpp                   # FoxIO JA4/JA4S fingerprint generation
│   ├── ja4t.hpp                  # TCP SYN option parsing and OS inference
│   ├── parser.hpp                # Zero-copy TLS ClientHello/ServerHello framing
│   ├── pqtls_analysis.hpp        # PQ-TLS posture state & offer tables
│   └── pqtls_parser.hpp          # Post-Quantum key share length validation
├── src/
│   ├── accumulator.cpp           # Fast-path / slow-path TCP reassembly logic
│   ├── capture.cpp               # Symmetric flow dispatching & worker loop
│   ├── db.cpp                    # JSON catalog loader and Redis client
│   ├── ech_analysis.cpp          # Connection summary lifecycle and JSON export
│   ├── ech_parser.cpp            # ECH framing & GREASE detection
│   ├── ja3.cpp                   # OpenSSL MD5 hashing and GREASE suppression
│   ├── ja4.cpp                   # OpenSSL SHA-256 hashing & extension sorting
│   ├── ja4t.cpp                  # Kernel stack signatures & cross-layer checks
│   ├── main.cpp                  # Command-line parsing and signal handlers
│   ├── parser.cpp                # TLS record boundary & extension slicing
│   ├── pqtls_analysis.cpp        # Offer-to-selection matching & posture logic
│   └── pqtls_parser.cpp          # RFC 10024 wire checks for ML-KEM/Kyber
└── tests/                        # 188 unit & integration tests (GoogleTest)
```
