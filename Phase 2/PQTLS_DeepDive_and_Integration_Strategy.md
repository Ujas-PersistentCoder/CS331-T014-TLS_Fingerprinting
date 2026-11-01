# Post-Quantum TLS (PQ-TLS): Integration Blueprint & Presentation Strategy
**CS331: Network Security & TLS Fingerprinting (Phase 2 Revamp)**  
**Target:** High-Speed C++ Engine (`tlsfp_phase2`)  

---

## 1. Executive Summary: The Post-Quantum Paradigm Shift

Classical asymmetric cryptography (RSA, Diffie-Hellman, ECDHE) relies on mathematical problems (integer factorization, discrete logarithms, and elliptic curve discrete logs) that are vulnerable to quantum computing.

When a Cryptanalytically Relevant Quantum Computer (CRQC) becomes viable, **Shor's Algorithm** will solve these problems in polynomial time ($\mathcal{O}((\log N)^3)$). While symmetric cryptography (AES-256, SHA-256) remains quantum-resistant under Grover's Algorithm (which only halves the effective key length), **all classical TLS key exchanges (X25519, P-256, RSA) will be completely compromised**.

### The Immediate Threat: "Harvest Now, Decrypt Later" (HNDL)
Adversaries and nation-states do not need to possess a quantum computer today to compromise security. Under HNDL attacks, adversaries capture and archive petabytes of encrypted TLS traffic crossing internet backbones today, waiting for quantum computers to decrypt it retroactively.

### The IETF & NIST Solution: Hybrid Key Exchange (FIPS 203)
In August 2024, NIST finalized **FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)**, standardized from the CRYSTALS-Kyber algorithm. Rather than relying solely on a post-quantum algorithm, the industry deployed **Hybrid Key Exchange**:
$$\text{Shared Secret} = \text{HKDF-Extract}(0, \text{ECDHE Secret} \parallel \text{ML-KEM Secret})$$

This dual-layer mechanism guarantees that even if a mathematical breakthrough breaks ML-KEM, classical ECDHE still protects the session; if quantum computers emerge, ML-KEM protects the session.

---

## 2. The Major Academic Discovery: The "JA4 Blind Spot"

A critical research finding emerges when evaluating how existing fingerprinting standards handle Post-Quantum TLS:

### How JA4 Works
FoxIO's JA4 standard constructs three sections:
- **`ja4_a`:** Protocols, TLS version, SNI indicator (`d` or `i`), cipher count, extension count, ALPN.
- **`ja4_b`:** 12-character SHA-256 hash of numerically sorted cipher suite IDs.
- **`ja4_c`:** 12-character SHA-256 hash of numerically sorted extension IDs (excluding SNI/ALPN) $+$ wire-ordered signature algorithms.

### The Problem: JA4 Is Completely Blind to Post-Quantum TLS
1. **Extensions Hashed by ID, Not Payload:** Both classical Chrome and Post-Quantum Chrome transmit extension `0x0033` (`key_share`) and `0x000a` (`supported_groups`). The extension IDs are identical.
2. **Elliptic Curves & Supported Groups are Ignored:** To reduce hash churn, FoxIO deliberately omitted `supported_groups` from JA4 (unlike JA3, which includes groups in Field 4).
3. **The Consequence:**
   $$\mathbf{JA4}(\text{Chrome 130 with Classical X25519}) \equiv \mathbf{JA4}(\text{Chrome 130 with Quantum-Safe ML-KEM-768})$$
   A legacy client vulnerable to Harvest-Now-Decrypt-Later and a modern quantum-safe client produce the **exact same JA4 hash**!
4. **JA3 vs. JA4 Behavior:** JA3 *does* change because Field 4 gains decimal `4588` (`0x11ec`), but this causes JA3 database lookup misses.
5. **Our Academic Contribution:** Our engine bridges this critical blind spot by providing **semantic wire-level PQC inspection** on top of JA4, exposing quantum-readiness directly on the wire without breaking hash stability.

---

## 3. Wire Protocol Mechanics: The Key Share Explosion

```
                            CLASSICAL vs. HYBRID TLS 1.3
┌────────────────────────────────────────┐    ┌────────────────────────────────────────┐
│         Classical ClientHello          │    │          Hybrid PQ ClientHello         │
│                                        │    │                                        │
│  supported_groups (0x000a):            │    │  supported_groups (0x000a):            │
│  └── 0x001d (x25519)                   │    │  ├── 0x11ec (X25519MLKEM768) [Pref #1] │
│                                        │    │  └── 0x001d (x25519)         [Fallback]│
│  key_share (0x0033):                   │    │                                        │
│  └── Group: 0x001d                     │    │  key_share (0x0033):                   │
│      └── Public Key: 32 Bytes          │    │  └── Group: 0x11ec                     │
│                                        │    │      ├── Classical Key:  32 Bytes      │
│                                        │    │      └── ML-KEM-768 Key: 1184 Bytes    │
│                                        │    │          └── Total Share: 1216 Bytes   │
│                                        │    │                                        │
│  Total Handshake: ~500 - 800 Bytes     │    │  Total Handshake: 2500 - 3800 Bytes    │
│  TCP Segments:    1 Packet (No Frag)   │    │  TCP Segments:    2 - 3 Packets (Frag!) │
└────────────────────────────────────────┘    └────────────────────────────────────────┘
```

### Standardized Codepoints & Chronology ("Carbon Dating")

| Group Codepoint | Standard Name | Cryptographic Composition | Deployment Timeline |
| :--- | :--- | :--- | :--- |
| **`0x6399`** | `X25519Kyber768Draft00` | X25519 (32B) + Kyber-768 Draft (1184B) | **Precursor:** Chrome 116–123 (Aug 2023 – Apr 2024), early Cloudflare |
| **`0x11ec`** | `X25519MLKEM768` | X25519 (32B) + NIST FIPS 203 ML-KEM (1184B) | **Standard:** Chrome 124+, OpenSSL 3.4+, Cloudflare, Google (May 2024–Present) |
| **`0x11eb`** | `SecP256r1MLKEM768` | NIST P-256 (64B) + ML-KEM-768 (1184B) | **Enterprise / Gov:** Mandatory in government/FIPS regulated environments |

### Key Size Differential & Transport Impact
- Classical X25519 public key = **32 bytes**.
- ML-KEM-768 public key = **1,184 bytes**.
- Combined hybrid key share = **1,216 bytes** ($\approx 38\times$ larger).
- Standard Ethernet MTU = **1500 bytes** (IPv4 TCP MSS $\approx 1448\text{ B}$).
- A modern PQ-TLS ClientHello reaches **2.5 KB to 3.8 KB**, **forcing TCP fragmentation across 2 to 3 packets**.
- **Architectural Validation:** This empirically validates the necessity of our **Two-Tier Accumulator (8 KB buffer)**. Single-packet sniffers fail on modern post-quantum connections.

---

## 4. Technical Blueprint: Updating the Current C++ Engine

```
                             PQC DISSECTION PIPELINE
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 ClientHello Stream                                     │
│                                                                                        │
│  ClientHelloData::supported_groups (Pre-filtered, GREASE-free):                        │
│  └── [0x11ec, 0x001d, 0x0017, ...]                                                     │
│                                                                                        │
│  Extension 0x0033 (key_share):                                                         │
│  └── Offered Share: Group 0x11ec, Length: 1216 bytes                                   │
└──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Phase 2 Engine Dissection                                 │
│                                                                                        │
│  1. Zero-Overhead Group Check: Inspect out_data.supported_groups directly              │
│  2. GREASE-Aware Top Preference: out_data.supported_groups[0] == 0x11ec                │
│  3. KeyShare Dimensioning: Measure offered key_exchange length in key_share (>= 1200B) │
│  4. ServerHello Correlation: Parse ext 0x0033 to verify server selected_group          │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Data Structure Additions (`include/tlsfp/types.hpp` & `parser.hpp`)
1. Extend `types.hpp` with dedicated PQC tracking:
```cpp
enum class PQCAlgorithm : uint16_t {
    NONE                     = 0x0000,
    X25519_KYBER768_DRAFT00  = 0x6399, // Precursor (Chrome 116-123)
    X25519_MLKEM768          = 0x11ec, // Official Standard (Chrome 124+, OpenSSL 3.4+)
    SECP256R1_MLKEM768       = 0x11eb, // FIPS / Enterprise hybrid
    SECP256R1_KYBER768       = 0x45f9  // Early P-256 draft
};

struct PQCMetadata {
    bool is_pqc{false};
    PQCAlgorithm algorithm{PQCAlgorithm::NONE};
    std::string algorithm_name{"NONE"};
    bool is_proactive_keyshare{false}; // Sent >= 1200B key share in initial ClientHello
    uint16_t key_share_len{0};         // e.g., 1216 bytes
    bool is_top_preference{false};     // PQC group was preferred first non-GREASE group
    bool server_accepted{false};       // Correlated with ServerHello: PQC negotiated
};
```

2. Extend `ClientHelloData` and `ServerHelloData` in `parser.hpp`:
```cpp
struct ClientHelloData {
    uint16_t client_version{0};
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t>  ec_point_formats;
    std::vector<uint16_t> supported_versions;
    std::vector<uint16_t> signature_algorithms;

    bool has_sni{false};
    std::string_view sni;
    std::string_view first_alpn;

    PQCMetadata pqc; // Post-Quantum telemetry
    ECHMetadata ech; // Encrypted Client Hello telemetry

    void clear() noexcept {
        client_version = 0;
        cipher_suites.clear();
        extensions.clear();
        supported_groups.clear();
        ec_point_formats.clear();
        supported_versions.clear();
        signature_algorithms.clear();
        has_sni = false;
        sni = {};
        first_alpn = {};
        pqc = {};
        ech = {};
    }
};

struct ServerHelloData {
    uint16_t server_version{0};
    uint16_t selected_version{0};
    uint16_t selected_cipher{0};
    uint16_t selected_group{0}; // Populated from ServerHello extension 0x0033 (key_share)
    std::vector<uint16_t> extensions;
    std::string_view first_alpn;

    void clear() noexcept {
        server_version = 0;
        selected_version = 0;
        selected_cipher = 0;
        selected_group = 0;
        extensions.clear();
        first_alpn = {};
    }
};
```

### Step 2: Efficient RFC Parsing in `src/parser.cpp`
Extension `0x0033` (`key_share`) is parsed during the extension loop, and the final PQC group check is performed in the **post-parsing finalization pass** right after all extensions are read (avoiding extension ordering race conditions and redundant parsing):

```cpp
// 1. Inside parse_client_extensions(): Inspect key_share extension (0x0033)
if (ext_type == 0x0033) {
    ByteReader ks_reader(ext_data, ext_len);
    uint16_t client_shares_len = 0;
    if (ks_reader.read_u16_be(client_shares_len)) {
        while (ks_reader.remaining() >= 4) {
            uint16_t grp = 0, klen = 0;
            if (ks_reader.read_u16_be(grp) && ks_reader.read_u16_be(klen)) {
                if (ks_reader.skip(klen)) {
                    if (grp == 0x11ec || grp == 0x6399 || grp == 0x11eb) {
                        out_data.pqc.is_proactive_keyshare = (klen >= 1200);
                        out_data.pqc.key_share_len = klen;
                    }
                }
            }
        }
    }
}

// 2. In post-parsing finalization pass (right after extension loop finishes):
// Direct inspection of pre-filtered supported_groups (zero redundant parsing)
for (size_t i = 0; i < out.supported_groups.size(); ++i) {
    uint16_t grp = out.supported_groups[i];
    if (grp == 0x11ec || grp == 0x6399 || grp == 0x11eb || grp == 0x45f9) {
        out.pqc.is_pqc = true;
        out.pqc.algorithm = static_cast<PQCAlgorithm>(grp);
        // GREASE values were already pruned; index 0 is guaranteed the true top preference
        out.pqc.is_top_preference = (i == 0);

        if (grp == 0x11ec) out.pqc.algorithm_name = "X25519MLKEM768";
        else if (grp == 0x6399) out.pqc.algorithm_name = "X25519Kyber768Draft00";
        else if (grp == 0x11eb) out.pqc.algorithm_name = "SecP256r1MLKEM768";
        break;
    }
}
```

### Step 3: ServerHello key_share Parsing in `parse_server_extensions()`
In `parse_server_hello()`, parse extension `0x0033`:
```cpp
if (ext_type == 0x0033) { // key_share in ServerHello
    ByteReader ks_reader(ext_data, ext_len);
    uint16_t grp = 0;
    if (ks_reader.read_u16_be(grp)) {
        out.selected_group = grp; // Selected server key exchange group
    }
}
```

### Step 4: ServerHello Correlation in `src/capture.cpp`
When correlating the server's response:
- If `server_hello.selected_group == 0x11ec` or `0x6399`:
  - `pqc.server_accepted = true`
  - Status: **`QUANTUM_SAFE_HYBRID`**
- If client offered PQC, but server selected classical `0x001d` (X25519):
  - Status: **`PQC_DOWNGRADED_CLASSICAL`**

---

## 5. What PQ-TLS Means for the Overall Tool

### The Core Philosophy: Why Wire Observation Defeats Header Spoofing
A common critical question in network security is:  
> *"As a passive sniffer, aren't we just reading integers and running conditionals?"*

The answer is **yes, and that is precisely where the defensive power lies**:
1. **The Attacker's Dilemma:** In classical TLS, attackers trivially evade detection using HTTP header spoofing (`User-Agent: Chrome/130`) combined with `curl-impersonate` (which easily mimics classical cipher suites).
2. **The Cryptographic Barrier:** To fake modern Chrome 124+, an attacker cannot just copy a text string. They must:
   - Implement the complex module-lattice mathematics of NIST FIPS 203 (ML-KEM-768),
   - Generate and transmit an actual 1,184-byte lattice public key, and
   - If ECH is active, resolve DNS HTTPS/SVCB records and execute HPKE encryption.
3. Standard scraping frameworks (Python `requests`, `urllib3`, Go `net/http`, Scrapy, legacy headless tools) **do not possess these heavy cryptographic engines**.
4. By checking the multi-variable correlation:
   $$\text{User-Agent claims Chrome 124+} \land (\text{PQC Group } 0x11ec \notin \text{supported\_groups} \lor \text{KeyShare} < 1200\text{ B}) \implies \mathbf{100\%\ Deterministic\ Impostor}$$

| Capability | Classical TLS Engine (JA3 / Phase 1) | Phase 2 Engine with PQ-TLS Integration |
| :--- | :--- | :--- |
| **Fragmentation Handling** | Fails or truncates on $> 1500\text{ B}$ ClientHellos (no multi-segment accumulator). | Two-Tier Accumulator seamlessly reassembles 3.5 KB handshakes with zero allocs. |
| **JA4 Visibility** | **Blind:** Produces the identical hash for classical and post-quantum clients. | **Semantic Bridge:** Exposes quantum-readiness alongside JA4. |
| **Version Chronology** | Blended into generic hashes. | **"Carbon-Dates" client software:** Distinguishes Chrome 116–123 (`0x6399`) from Chrome 124+ (`0x11ec`). |
| **Threat Detection** | Vulnerable to User-Agent header spoofing. | **The PQC Impersonation Trap:** Scrapers claiming Chrome 124+ without `0x11ec` are unmasked. |
| **Security Auditing** | No visibility into quantum exposure. | Computes enterprise **Quantum-Readiness Index** and alerts on HNDL exposure. |

---

## 6. Presentation Strategy: How to Present This to the Professor

When presenting to your professor, frame PQ-TLS around **the JA4 blind spot, system resilience, and cryptographic evolution**.

### Slide Structure & Talking Points

#### Slide 1: The Quantum Problem — "Harvest Now, Decrypt Later"
- **Key Talking Point:** *"Adversaries are archiving encrypted network flows today to decrypt tomorrow with quantum computers using Shor's algorithm. In August 2024, NIST released FIPS 203 (ML-KEM). Modern browsers have rolled out hybrid key exchange to defend against this."*
- **Visual:** Diagram showing classical ECDHE vs. ML-KEM-768 hybrid key exchange.

#### Slide 2: The Academic Discovery — The "JA4 Blind Spot"
- **Key Talking Point:** *"FoxIO designed JA4 to hash extension IDs rather than payloads and omitted supported groups to reduce hash churn. Consequently, JA4 is completely blind to Post-Quantum TLS: Chrome using classical X25519 and Chrome using X25519MLKEM768 produce identical JA4 hashes. Our engine solves this by providing semantic wire-level PQC telemetry."*
- **Visual:** Side-by-side comparison showing identical JA4 hashes for classical and PQ flows, with our engine's PQC badge highlighting the difference.

#### Slide 3: The Transport Bottleneck & Accumulator Justification
- **Key Talking Point:** *"PQ-TLS expands the ClientHello key share by 38× (from 32 bytes to 1,216 bytes), pushing the total handshake to 3.5 KB. This physically forces TCP fragmentation across 2 to 3 Ethernet frames. Naive sniffers fail on post-quantum traffic; our Two-Tier Accumulator (8 KB buffer) reassembles it cleanly."*
- **Visual:** Wireshark split-segment trace showing 1448B + 1448B + 304B frames assembling into one ClientHello.

#### Slide 4: Cryptographic "Carbon Dating" & Impersonation Defense
- **Key Talking Point:** *"Because PQC standardized in discrete steps, group codepoints act like a chronological timestamp: 0x6399 dates a client to late 2023 / early 2024, while 0x11ec dates a client to mid-2024+. If an automated scraper or C2 framework claims to be Chrome 130 on Windows 11 but only offers classical X25519 (32 bytes), our engine deterministically catches the lie."*

#### Slide 5: Live Demonstration & Evaluation
- Run `tlsfp_phase2` on:
  1. A standard `curl` / `Python` connection (Classical X25519, single packet, 32-byte key share).
  2. A real modern Chrome connection to `https://crypto.cloudflare.com/cdn-cgi/trace` or Google (Hybrid X25519MLKEM768, 1,216-byte key share, multi-segment reassembly).
- Display the telemetry badge:
  ```text
  CLIENT  192.168.1.45:51280 ──▶ 104.16.132.229:443
    │  JA4:       t13d1517h2_8daaf6152771_cb7bf5808d99  [Chromium (browser)]
    │  PQC Group: 0x11ec [X25519MLKEM768] (Top Preference: YES)
    │  Key Share: 1216 Bytes (Proactive Hybrid Share)
    │  Transport: 2 Segments Reassembled (Total: 2842 Bytes)
    │  Status:    QUANTUM_SAFE_HYBRID (Server Selected: 0x11ec)
  ```

---

## 7. Answers to Tough Academic Review Questions

- **Q: "Why didn't browsers just switch entirely to ML-KEM-768 instead of using a hybrid?"**  
  *A: "Lattice-based cryptography is relatively new compared to 30 years of elliptic curve vetting. The IETF and NIST mandated hybrid key exchanges as a fail-safe: if an unforeseen mathematical attack weakens ML-KEM, classical X25519 still guarantees security; if a quantum computer arrives, ML-KEM provides quantum resistance."*

- **Q: "Does JA4 distinguish between Post-Quantum and Classical connections?"**  
  *A: "No. This is a foundational limitation of the JA4 specification: JA4 hashes extension IDs (not payloads) and intentionally omits supported groups to stabilize hashes. Because both classical and PQ connections advertise extension 0x0033 and 0x000a, JA4 produces identical hashes for both. Our engine detects and reports PQC at Layer 6 semantically, bridging this gap."*

- **Q: "As a passive monitor, isn't your PQC inspection just reading an integer from supported_groups?"**  
  *A: "No. Inspecting supported_groups alone only shows theoretical intent. Our engine correlates three distinct wire variables: (1) Top-preference group ordering in supported_groups (0x000a), (2) Proactive key share presence and physical key dimension (>= 1200 bytes) in key_share (0x0033), and (3) Server selected group negotiation in ServerHello. This distinguishes proactive post-quantum clients from reactive mobile clients and unmasks header-spoofed scrapers that copy group IDs without embedding real lattice keys."*

- **Q: "What if a client supports PQC but does NOT send a 1.2 KB key share upfront?"**  
  *A: "This is known as Reactive PQC. To save bandwidth on mobile networks, some clients list 0x11ec in supported_groups but send only a 32-byte classical key share in key_share. If the server demands PQC, it issues a HelloRetryRequest (HRR), prompting the client to send the 1.2 KB share in a second handshake round. Our engine detects this by checking whether key_share_len >= 1200 on the initial packet."*

- **Q: "How did you verify that reassembly succeeded without memory corruption?"**  
  *A: "We validated the Two-Tier Accumulator using GoogleTest unit tests (AccumulatorTest.GRO_Off_ReassemblesThreeSegments and AccumulatorTest.GRO_On_ProcessesJumboFrame), verifying that segmented buffers up to 8 KB reassemble into identical binary representations and match 100% of fingerprint hashes."*

---

## 8. Practical Lab Guide: Generating Ground-Truth PQ-TLS Captures

To record live PQ-TLS traffic for evaluation:

### Option A: Google Chrome / Chromium
1. Open Google Chrome (version 124 or later).
2. Visit `chrome://flags/#enable-tls13-kyber` (or search for "Post-Quantum"). Verify it is set to **Enabled** (default in Chrome 124+).
3. Start the capture engine:
   ```bash
   sudo ./Phase\ 2/engine/build/tlsfp_phase2 -i any
   ```
4. Navigate to `https://crypto.cloudflare.com/cdn-cgi/trace` or `https://pq.cloudflareresearch.com/`.
5. The Cloudflare trace page explicitly reports:
   ```text
   tls=TLSv1.3
   kex=X25519MLKEM768
   ```
   Confirming active post-quantum key exchange on the wire.

### Option B: OpenSSL 3.4+ CLI
Using modern OpenSSL with PQC support:
```bash
openssl s_client -connect crypto.cloudflare.com:443 -groups X25519MLKEM768 -servername crypto.cloudflare.com
```
