# Encrypted Client Hello (ECH): Technical Blueprint, Observability Analysis & Empirical Research Plan
**CS331: Computer Networks — Network Security & TLS Fingerprinting (Phase 2 Revamp)**  
**Team T014** · **Target Binary:** `tlsfp_phase2` · **Part 2 Final Deliverable**  
**Governing Specifications:**  
- **RFC 9849:** TLS Encrypted Client Hello (March 2026)  
- **RFC 9848:** Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings  
- **RFC 9850:** The SSLKEYLOGFILE Format for TLS (§2.3 ECH Labels)  
- **RFC 9460:** Service Binding and Parameter Specification via the DNS (Base SVCB/HTTPS)  
- **RFC 9180:** Hybrid Public Key Encryption (HPKE)  
- **RFC 8879:** TLS Certificate Compression  
- **RFC 8701:** Generating Extensible Extensions and Ciphers (GREASE)  
- **RFC 8744:** Issues and Requirements for SNI Encryption in TLS  
- **RFC 8446:** The Transport Layer Security (TLS) Protocol Version 1.3  

---

## 1. Executive Summary & Project Research Framing

For over two decades, passive network monitoring tools (firewalls, Intrusion Detection Systems, DLP sensors, academic taps, and classic fingerprinting engines like JA3) operated on a universal wire assumption: **the Server Name Indication (SNI) extension was transmitted in cleartext**. Anyone on the wire could inspect the client handshake and determine the intended destination domain.

**Encrypted Client Hello (RFC 9849)** fundamentally redesigns the TLS 1.3 handshake:
- The client encapsulates privacy-sensitive handshake fields (the true SNI, ALPN protocol list, and sensitive extensions) inside an **inner ClientHello (`ClientHelloInner`)**.
- The `ClientHelloInner` is encrypted using Hybrid Public Key Encryption (HPKE, RFC 9180) in Base mode using a public key published out-of-band by the destination server via DNS HTTPS/SVCB records (RFC 9460, RFC 9848).
- The client transmits an unencrypted **outer ClientHello (`ClientHelloOuter`)** on the wire. This outer envelope contains a public cover domain in its cleartext SNI (`public_name`), an `encrypted_client_hello` extension (`0xfe0d`), and the opaque ciphertext payload.

### 1.1 The Project Research Question
> *"When the true destination hostname is cryptographically concealed on the wire, what client-identifying and structural information survives in observable TCP/TLS handshakes, how does our C++ engine reliably dissect it, and how much does it add beyond classical outer-handshake fingerprints (JA3/JA4)?"*

### 1.2 The Three Non-Negotiable Engineering Rules
1. **Parsing is Deterministic and Strict:** Direct wire facts (extension presence, raw lengths, KDF/AEAD IDs, byte digests) are parsed with strict bounds checking.
2. **Interpretation is Separate and Evidentiary:** Any deduction (whether an offer is likely genuine or GREASE, or whether non-acceptance was observed) carries explicit supporting evidence and may abstain (`UNKNOWN`).
3. **Ground Truth is Strictly Sourced:** Ground truth (true inner SNI, client software version, whether the server accepted ECH) is established *only* through endpoint instrumentation (browser automation, RFC 9850 keylogs, server logs), **never** inferred circular-fashion from the passive parser.

We make no claims of "100% deterministic bot detection," "sniffers being rendered obsolete," or "passively decrypting inner payloads without keys."

---

## 2. Protocol Facts: Wire Mechanics & Cryptographic Boundaries

### 2.1 Extension Codepoints & Structural Framing
- **`0xfe0d` (`65037`):** The exclusive IANA-registered codepoint for `encrypted_client_hello` (RFC 9849 §5, §11.1). The `ECHConfig.version` field itself is `0xfe0d`. There is no separate "draft vs. RFC" codepoint story for modern ECH (early pre-ECH experiments in 2018 used draft ESNI `0xffce`, which is obsolete).
- **`0xfd00` (`64768`):** Reserved for `ech_outer_extensions` (RFC 9849 §5.1). This extension appears **only** in `EncodedClientHelloInner` to compress shared extensions. It **MUST NOT** appear in `ClientHelloOuter` or in the reconstructed `ClientHelloInner`. Its appearance in cleartext is an RFC violation and is flagged as an anomaly.
- **`0x001b` (`27`):** Allocated strictly for **Certificate Compression (`compress_certificate`, RFC 8879 §3)**. Mainstream browsers (Chrome, Firefox) send `0x001b` on almost every connection. It must **never** be parsed as ECH.

### 2.2 Envelope Layout of `ClientHelloOuter` (RFC 9849 §4–§5)
```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 ClientHelloOuter                                       │
│                                                                                        │
│  Cleartext SNI (0x0000): "public-front.example.com" (Configurable public_name)         │
│                                                                                        │
│  Extension 0xfe0d (EncryptedClientHello):                                              │
│  ├── type: Outer (0x00) [1 byte]                                                       │
│  ├── kdf_id:  0x0001 (HKDF-SHA256) [2 bytes]                                           │
│  ├── aead_id: 0x0001 (AES-128-GCM) / 0x0003 (ChaCha20-Poly1305) [2 bytes]              │
│  ├── config_id: Key identifier from DNS ECHConfig [1 byte]                             │
│  ├── enc: Ephemeral public key [2-byte length prefix + raw bytes]                      │
│  └── payload: Ciphertext [2-byte length prefix (>= 1) + raw ciphertext bytes]          │
│          └── [EncodedClientHelloInner (includes padding) + 16-byte AEAD Tag]           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
- **The Inner Variant:** An ECH extension with `type = 1` (`inner`) has an empty body. It exists solely in `EncodedClientHelloInner` (and on internal links in split-mode deployments between a Client-Facing Server and Backend Server). A server receiving `type = 1` directly from the network must abort with an `illegal_parameter` alert (RFC 9849 §7). On a passive client-side tap, any value other than `0` is an anomaly.
- **The KEM is NOT on the Wire:** The outer extension carries only `kdf_id`, `aead_id`, `config_id`, `enc`, and `payload`. The `kem_id` lives strictly in the out-of-band `ECHConfig` (RFC 9848 / RFC 9460). While an ephemeral key length of $|enc| = 32\text{ bytes}$ is consistent with DHKEM(X25519), that is an **inferred property**, not an explicit wire field. Other KEM lengths include 65 bytes (P-256), 97 bytes (P-384), 133 bytes (P-521), and 56 bytes (X448). Future Post-Quantum HPKE KEMs will introduce much larger key lengths.
- **Cipher Suite Selection Constraints:** In genuine ECH, the client *must* select its KDF/AEAD pair from the list advertised in the server's `ECHConfig` (RFC 9849 §6.1). For instance, Cloudflare's published ECH configuration advertised a single suite. Thus, for genuine ECH, the chosen suite reflects the server's configuration plus client support, not a unique client fingerprint. Only in GREASE ECH (where the client generates dummy values) does the client choose its suite freely (§6.2.1).
- **Invalid Values:** An `aead_id` of `0xFFFF` indicates an export-only HPKE AEAD (RFC 9180 §7.3), which cannot be used for ECH sealing and is flagged as malformed. An `enc_len == 0` on an initial ClientHello is invalid (§5); empty `enc` is legal only in a second ClientHello following an HRR.

### 2.3 Ciphertext Length Arithmetic & Padding
A passive observer sees only `ciphertext_length`, **not** raw padding length:
$$\text{ciphertext\_length} = \text{len}(\text{EncodedClientHelloInner}) + \text{AEAD\_Tag\_Overhead} \, (16\text{ bytes})$$
Note that `EncodedClientHelloInner` already includes the zero-padding bytes. RFC 9849 §6.1.3 recommends (`SHOULD`) rounding `EncodedClientHelloInner` up to a multiple of 32 bytes ($L_{\text{padded}} \pmod{32} \equiv 0$). When sealed with standard 16-byte AEAD tags (AES-128-GCM or ChaCha20-Poly1305), the resulting wire ciphertext satisfies:
$$\mathbf{ciphertext\_length \pmod{32} \equiv 16}$$
- Examples: 336B, 368B, 400B satisfy this condition. A length of 352B ($352 \pmod{32} = 0$) deviates from this recommendation. Failing this check is a deviation from a `SHOULD`, not an invalid packet.
- **GREASE Invariance:** Because GREASE payloads are also sized in accordance with §6.1.3 (§6.2.1), this padding invariant **does not** separate real ECH from GREASE.
- **SNI Length Tracking:** When a server config sets `maximum_name_length = 0` (as Cloudflare deployed), only 32-byte bucket rounding applies. Consequently, variations in `ciphertext_length` can track variations in inner SNI length across hosts.

### 2.4 Cryptographic Visibility: Passive Boundaries of Acceptance
A passive observer faces strict mathematical limits regarding whether an ECH offer was accepted:

1. **Acceptance Confirmation Is Cryptographically Opaque:**  
   In RFC 9849 §7.2, an accepting server replaces the last 8 bytes of `ServerHello.random` with:
   $$\text{accept\_confirmation} = \text{HKDF-Expand-Label}(\text{HKDF-Extract}(0, \text{ClientHelloInner.random}), \text{"ech accept confirmation"}, \text{transcript\_ech\_conf}, 8)$$
   - `HKDF-Extract` salt: `Hash.length` zero bytes.
   - `transcript_ech_conf`: Hash of `ClientHelloInner` through `ServerHello` (with its last 8 random bytes zeroed).
   - Because `ClientHelloInner.random` is locked inside the HPKE ciphertext, **a passive observer cannot compute this confirmation value**. To a sniffer without the server's private key, the last 8 bytes of `ServerHello.random` are computationally indistinguishable from uniform pseudorandom noise. (§6.1.4 specifies the client's internal verification).
2. **Rejection & Fallback Are Encrypted:**  
   When a server rejects ECH (e.g., due to stale DNS keys):
   - The server completes the handshake using `ClientHelloOuter`.
   - Its response (`EncryptedExtensions` carrying `retry_configs`, and the server `Certificate`) is encrypted under the Handshake Traffic Keys. A passive observer without endpoint secrets cannot read `retry_configs` or the true certificate subject.
   - The client terminates the connection with `ech_required` and reconnects on a fresh TCP connection using the provided `retry_configs` (RFC 9849 §6.1.6).
3. **Scoped Negative Inferences (When Non-Acceptance CAN Be Observed):**
   - **Negotiation Below TLS 1.3:** RFC 9849 mandates TLS 1.3 for ECH. If the server negotiates TLS 1.2 or earlier (checked via `ServerHello.server_version` or `supported_versions`), ECH was rejected or ignored (§6.1.4).
   - **HelloRetryRequest (HRR) Without ECH:** If the server issues an HRR (identified by the special random value `CF 21 AD 74 15 99 46 37 AF 13 56 66 76 96 B7 F6 86 42 C9 5C E1 D3 6B C1 EE 79 0C 6F 27 78 46 07`, RFC 8446 §4.1.3) that **omits** extension `0xfe0d`, ECH non-acceptance is confirmed (§6.1.4).
   - **HRR ECH Presence Proves Nothing:** RFC 9849 §7.1 explicitly states that a rejecting server MAY include an `encrypted_client_hello` extension with 8 random bytes in its HRR. Therefore, the *presence* of `0xfe0d` in an HRR is **not** evidence of acceptance. Only its *absence* proves rejection.
4. **Passive Heuristics for Suspected Rejection:**  
   While not mathematical proof, observable behavioral signals of rejection include: an immediate connection termination followed by a fast reconnect to the same IP with a different `config_id` (the `retry_configs` reconnect pattern, §6.1.6), lack of encrypted application data after the handshake, or size disparities in the server flight.

### 2.5 Real ECH vs. GREASE ECH Mechanics
Clients without a usable `ECHConfig` **SHOULD** send a GREASE ECH extension (RFC 9849 §6.2.1).
- **Indistinguishability by Design:** RFC 9849 §10.10.4 explicitly notes that Real ECH and GREASE are designed to be indistinguishable to a per-connection passive observer who does not possess the `ECHConfigList`. Extension IDs, ordering, and lengths are designed not to vary.
- **The Stateful Discriminators Conceded by the RFC:**
  1. **The HRR Identical-Copy Test (§6.2.1 vs. §7.1.1):** When an HRR is issued, a GREASE client copies its entire ECH extension **verbatim** into the second ClientHello (§6.2.1). A genuine ECH client sends an **empty `enc` field (`enc_len == 0`)**, the same `config_id` and suite, and a newly derived ciphertext payload (§5, §7.1.1).
  2. **Stateful `config_id` Stability:** Genuine ECH reuses the `config_id` from the cached DNS `ECHConfig` across consecutive sessions to the same endpoint. GREASE selects a random byte for `config_id` (§6.2.1), causing `config_id` churn across connections. (Note: under §10.4, clients could theoretically randomize `config_id`, but the default is MUST NOT).
  3. **Outer SNI Context (§6.1):** Genuine ECH sets outer SNI to the server's `public_name` (e.g., `cloudflare-ech.com`). GREASE sets outer SNI to the target host (or omits it for IP-literals).

### 2.6 Out-of-Band Delivery, DNS & Browser Realities
- **DNS Records (RFC 9460 / RFC 9848):** ECH configurations ride inside DNS `HTTPS` (Type 65) and `SVCB` (Type 64) resource records under the `ech` parameter.
- **Plaintext DNS & IP Leakage:** ECH conceals the SNI on the wire, but **plaintext DNS queries and destination IP routing remain disclosure channels** (RFC 9849 §1, §10). A network monitor observing standard UDP/53 DNS sees the requested domain regardless of ECH.
- **DNSSEC vs. Confidentiality:** DNSSEC provides *origin authentication and integrity*, but **not confidentiality** (§10.2). An eavesdropper can inspect unencrypted DNS. Meaningful SNI concealment requires pairing ECH with encrypted DNS (DoH, RFC 8484; DoT, RFC 7858; or DoQ, RFC 9250).
- **Enterprise & Middlebox Behavior:** RFC 9849 §8.1.2 and §8.2 discuss network proxies and disabling ECH by policy. Network administrators can disable ECH by blocking or filtering DNS SVCB/HTTPS queries, causing browsers to fall back to unencrypted SNI if configured in opportunistic mode.
- **Browser Rollout:** Chrome enabled ECH by default in v117 (September 2023); Firefox enabled it by default in v119 (October 2023). Chrome fetches HTTPS records via DoH and via its built-in resolver (Secure DNS is not universally mandatory).
- **Keylogging (RFC 9850):** The SSLKEYLOGFILE format defines:
  - `ECH_SECRET <client_random> <secret>` (HPKE KEM shared secret)
  - `ECH_CONFIG <client_random> <config>` (Serialized ECHConfig)
  - **Ground-Truth Acceptance Oracle:** When ECH is accepted, standard TLS 1.3 secrets (`CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`) are keyed by **`ClientHelloInner.random`**, not the outer random. If logged TLS secrets do not match the outer random seen on the wire, ECH was accepted.

### 2.7 What ECH Does NOT Change
- **Layer 4 TCP Profile:** ECH does not alter TCP SYN window size, MSS, scale factor, or option ordering. Layer 4 cross-correlation (JA4T) is an independent transport capability, not an ECH feature.
- **HTTP User-Agent:** HTTP headers are transmitted inside encrypted TLS application data (RFC 8446). A passive handshake parser cannot inspect the `User-Agent`.
- **Bot vs. Human Detection:** A browser-family TLS fingerprint identifies the underlying cryptographic library (e.g., BoringSSL), not human intent. Automated tools (Puppeteer, Playwright, undetected-chromedriver) drive genuine Chrome binaries and emit genuine browser handshakes.
- **Post-Quantum Status:** Cloudflare’s published ECH HPKE KEM was classical X25519. Observing `kex=X25519MLKEM768` on a diagnostic trace page reflects the **TLS 1.3 handshake key exchange**, not the ECH HPKE wrapper.

### 2.8 Cryptographic Downgrade & ECH Stripping Detection
In adversarial or enterprise environments, active network intermediaries (e.g., inspection firewalls, MITM proxies) may attempt to bypass privacy protections by stripping or suppressing ECH:
- **Active ECH Stripping:** A middlebox removes the `0xfe0d` extension in transit. If the client runs in *opportunistic mode*, it may complete the handshake using the unencrypted `ClientHelloOuter`, inadvertently disclosing the SNI. If the client runs in *strict ECH mode*, the server aborts the handshake with `ech_required`.
- **Observable Downgrade Indicators:**
  - `REJECTED_OR_IGNORED_TLS12_NEGOTIATED`: Client offered `0xfe0d`, but the server negotiated TLS 1.2 or earlier, dropping ECH entirely.
  - `REJECTED_HRR_WITHOUT_ECH`: Server issued a `HelloRetryRequest` omitting extension `0xfe0d`, proving non-acceptance (RFC 9849 §6.1.4).
  - `ECH_STRIPPED_SUSPECTED`: A client session initiates with an outer SNI known to mandate ECH (or previously observed using ECH), but omits extension `0xfe0d` entirely.
- **Evidence Contract Boundary:** Passive observers cannot verify why ECH failed (e.g., whether caused by an active MITM proxy, a stale DNS RR, or intentional enterprise policy). The engine objectively records the wire outcome (`NON_ACCEPTANCE_TLS12` or `NON_ACCEPTANCE_HRR_NO_ECH`) without attributing definitive adversary intent unless corroborated by external policy telemetry.

---

## 3. Engine Architecture & Integration in `Phase 2/engine`

### 3.1 The Three-Layer Engine Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              THREE-LAYER ENGINE DESIGN                                 │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Layer 1: OBSERVATION   │ Direct wire parsing: presence, lengths, digests, outer SNI.   │
│                        │ Strict bounds-checked reader; no guesswork.                   │
├────────────────────────┼───────────────────────────────────────────────────────────────┤
│ Layer 2: INTERPRETATION│ Stateful analysis rules: HRR copy test, config_id stability,  │
│                        │ non-acceptance detection. May abstain (UNKNOWN).              │
├────────────────────────┼───────────────────────────────────────────────────────────────┤
│ Layer 3: GROUND TRUTH  │ Endpoint instrumentation ONLY: RFC 9850 logs, trace responses, │
│                        │ server logs. Never derived circular-fashion from the parser.  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Models (`include/tlsfp/types.hpp`)
The interpretation state is cleanly separated into two independent axes: (a) Offer Type, and (b) Observed Acceptance State.

```cpp
#ifndef TLSFP_TYPES_ECH_HPP
#define TLSFP_TYPES_ECH_HPP

#include <cstdint>
#include <string>

namespace tlsfp {

enum class EchParse : uint8_t {
    ABSENT = 0,
    OUTER_OK,
    INNER_ON_WIRE,        // type == 1 observed in cleartext on network tap (RFC 9849 §7 anomaly)
    MALFORMED,            // Trailing bytes, invalid vector lengths, aead_id == 0xFFFF, or type > 1
    INCOMPLETE_CAPTURE,   // Segment boundary truncated mid-extension
    DUPLICATE,            // Multiple ECH extensions in a single ClientHello (RFC 8446 §4.2 violation)
    ANOMALY_FD00_IN_OUTER // Extension 0xfd00 observed in cleartext (RFC 9849 §5.1 violation)
};

enum class EchOfferType : uint8_t {
    UNKNOWN = 0,          // Default; evidence is insufficient to classify
    OFFERED_LIKELY_REAL,  // Corroborated by HRR empty-enc, known public_name, or stable config_id
    OFFERED_LIKELY_GREASE // Corroborated by HRR verbatim copy or random config_id churn
};

enum class EchAcceptanceObserved : uint8_t {
    UNVERIFIED = 0,            // Standard passive state; acceptance cannot be verified passively
    NON_ACCEPTANCE_BELOW_TLS13,// Server negotiated <= TLS 1.2
    NON_ACCEPTANCE_HRR_NO_ECH  // Server sent HRR without ECH extension
};

struct EchObservation {
    bool extension_present{false};
    EchParse parse_status{EchParse::ABSENT};
    
    uint8_t type{0xFF};             // 0x00 = Outer (only valid wire format)
    uint16_t kdf_id{0};
    uint16_t aead_id{0};
    uint8_t config_id{0};
    uint16_t enc_len{0};
    uint16_t ciphertext_len{0};
    uint64_t extension_hash{0};     // 64-bit digest for stateful HRR duplicate comparison
    uint8_t handshake_index{0};     // 0 = ClientHello #1, 1 = ClientHello #2 (post-HRR)
    bool satisfies_32byte_padding{false}; // ciphertext_len % 32 == 16
    std::string inferred_kem{"Unknown"};  // Provenance: Inferred from enc_len (e.g. 32B -> X25519)
    std::string outer_sni;
};

struct EchInterpretation {
    EchOfferType offer_type{EchOfferType::UNKNOWN};
    EchAcceptanceObserved acceptance{EchAcceptanceObserved::UNVERIFIED};
    std::string evidence;
    uint16_t rule_version{1};
};

} // namespace tlsfp

#endif
```

### 3.3 Strict, Validated Parser Implementation (`src/parser.cpp`)
The parser verifies vector lengths, validates non-zero ciphertext, checks for export-only AEAD, ensures complete buffer consumption, and registers presence immediately:

```cpp
namespace tlsfp {

void parse_ech_extension(ByteReader &reader, EchObservation &out, uint8_t hs_index) {
    out.extension_present = true; // Mark present immediately upon encountering 0xfe0d
    out.handshake_index = hs_index;

    const uint8_t *raw_start = reader.current_ptr();
    size_t raw_len = reader.remaining();

    uint8_t type = 0xFF;
    if (!reader.read_u8(type)) {
        out.parse_status = EchParse::INCOMPLETE_CAPTURE;
        return;
    }

    out.type = type;

    // RFC 9849 §7: type inner (1) in cleartext is illegal; type > 1 is unknown/malformed
    if (type == 0x01) {
        out.parse_status = (reader.remaining() == 0) ? EchParse::INNER_ON_WIRE : EchParse::MALFORMED;
        return;
    }
    if (type != 0x00) {
        out.parse_status = EchParse::MALFORMED;
        return;
    }

    uint16_t kdf = 0, aead = 0;
    uint8_t cfg_id = 0;
    uint16_t enc_l = 0;

    if (!reader.read_u16_be(kdf) || !reader.read_u16_be(aead) ||
        !reader.read_u8(cfg_id) || !reader.read_u16_be(enc_l)) {
        out.parse_status = EchParse::INCOMPLETE_CAPTURE;
        return;
    }

    // Export-only AEAD (0xFFFF) is illegal for ECH sealing (RFC 9180 §7.3)
    if (aead == 0xFFFF) {
        out.parse_status = EchParse::MALFORMED;
        return;
    }

    // enc_len == 0 is valid ONLY in a second ClientHello post-HRR (RFC 9849 §5)
    if (enc_l == 0 && hs_index == 0) {
        out.parse_status = EchParse::MALFORMED;
        return;
    }

    // Ephemeral key vector
    if (enc_l > 0) {
        if (!reader.has_bytes(enc_l) || !reader.skip(enc_l)) {
            out.parse_status = EchParse::INCOMPLETE_CAPTURE;
            return;
        }
    }

    uint16_t cipher_l = 0;
    if (!reader.read_u16_be(cipher_l)) {
        out.parse_status = EchParse::INCOMPLETE_CAPTURE;
        return;
    }

    // RFC 9849 §5: Payload length must be at least 1 byte
    if (cipher_l == 0) {
        out.parse_status = EchParse::MALFORMED;
        return;
    }

    // Check payload bytes exist in the packet buffer
    if (!reader.has_bytes(cipher_l) || !reader.skip(cipher_l)) {
        out.parse_status = EchParse::INCOMPLETE_CAPTURE;
        return;
    }

    // RFC 9849 §5: Entire extension structure must be consumed completely
    if (reader.remaining() != 0) {
        out.parse_status = EchParse::MALFORMED;
        return;
    }

    // All boundary validations succeeded; commit observation
    out.parse_status = EchParse::OUTER_OK;
    out.kdf_id = kdf;
    out.aead_id = aead;
    out.config_id = cfg_id;
    out.enc_len = enc_l;
    out.ciphertext_len = cipher_l;
    out.satisfies_32byte_padding = (cipher_l % 32 == 16);

    // 64-bit FNV-1a hash of raw extension envelope for stateful HRR identity comparison
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < raw_len; ++i) {
        h = (h ^ raw_start[i]) * 1099511628211ull;
    }
    out.extension_hash = h;

    // Attach inferred KEM provenance
    if (enc_l == 32) {
        out.inferred_kem = "DHKEM(X25519) [Inferred: enc_len=32]";
    } else if (enc_l == 65) {
        out.inferred_kem = "DHKEM(P-256) [Inferred: enc_len=65]";
    } else if (enc_l == 97) {
        out.inferred_kem = "DHKEM(P-384) [Inferred: enc_len=97]";
    } else if (enc_l == 133) {
        out.inferred_kem = "DHKEM(P-521) [Inferred: enc_len=133]";
    } else if (enc_l == 56) {
        out.inferred_kem = "DHKEM(X448) [Inferred: enc_len=56]";
    } else if (enc_l == 0) {
        out.inferred_kem = "None (HRR Outer Hello)";
    } else {
        out.inferred_kem = "Unknown";
    }
}

} // namespace tlsfp
```

### 3.4 Client Extension Loop & Duplicate Extension Guard (`src/parser.cpp`)
In `parse_client_extensions()`, enforce RFC 8446 §4.2 (duplicate extension guard), route `0xfe0d`, and flag cleartext `0xfd00`:

```cpp
case 0xfe0d: { // EncryptedClientHello (RFC 9849)
    if (out.ech.extension_present) {
        out.ech.parse_status = EchParse::DUPLICATE; // RFC 8446 §4.2 mandate
        break;
    }
    parse_ech_extension(reader, out.ech, hs_index);
    break;
}
case 0xfd00: { // ech_outer_extensions MUST NOT appear in outer hello (RFC 9849 §5.1)
    if (out.ech.parse_status != EchParse::OUTER_OK) {
        out.ech.parse_status = EchParse::ANOMALY_FD00_IN_OUTER;
    }
    break;
}
case 0x001b: { // Certificate Compression (RFC 8879) - NOT ECH
    break;
}
```

### 3.5 Two-Pass Finalization Architecture
The engine preserves our core architectural rule: **Defer multi-extension classification until all extensions are parsed**.
- In Chrome, extension ordering is randomized; extension `0xfe0d` can appear before or after `0x0000` (SNI).
- **Pass 1 (Streaming Parser):** As extensions arrive, extension-local properties (`kdf_id`, `aead_id`, `ciphertext_len`, `outer_sni`) are recorded strictly from wire bytes.
- **Pass 2 (Finalization):** Once the extension vector is fully consumed, the engine evaluates cross-extension rules and executes stateful comparisons.

### 3.6 Stateful Interpretation Rules (All Optional, All May Abstain)

| Rule | Condition Observed | Inferred Conclusion | Basis and Limits |
| :--- | :--- | :--- | :--- |
| **I1** | Second ClientHello after an HRR; `extension_hash` is byte-identical to the first. | `offer_type = OFFERED_LIKELY_GREASE` | RFC 9849 §6.2.1. Requires an HRR, which is rare with modern key shares. |
| **I2** | Second ClientHello after an HRR; ECH present; `enc_len == 0`; same `config_id` and suite; fresh payload. | `offer_type = OFFERED_LIKELY_REAL` | RFC 9849 §5, §7.1.1. Verifiable only when an HRR occurs. |
| **I3** | First server message negotiates $\le \text{TLS 1.2}$, or HRR omits ECH extension, after ECH was offered. | `acceptance = NON_ACCEPTANCE_OBSERVED` | RFC 9849 §6.1.4. Inactive ECH confirmed; does not separate GREASE from rejected real ECH. |
| **I4** | `config_id` remains constant across $\ge N$ consecutive connections to a destination vs. randomized on every connection. | Weak `OFFERED_LIKELY_REAL` vs. `GREASE` | RFC 9849 §4.1, §6.2.1, §10.4. Requires stateful multi-connection flow cache. |
| **I5** | Outer SNI exactly equals or ends with a known `public_name` (e.g., `.cloudflare-ech.com`). | `offer_type = OFFERED_LIKELY_REAL` | RFC 9849 §6.1. Hostname pattern heuristic; never absolute ground truth. |

Any flow not matching these narrow, grounded conditions produces **`EchOfferType::UNKNOWN`** and **`EchAcceptanceObserved::UNVERIFIED`**.

---

## 4. The Evidence Contract: Mapping Wire Fields to Claims

Every output field displayed by the engine maps strictly to an authoritative wire source, an allowed claim, and an explicit unknown state:

| Field Name | Wire Source | Permitted Claim | Unknown / Abstention State |
| :--- | :--- | :--- | :--- |
| **`extension_present`** | ClientHello extension header | An `encrypted_client_hello` (`0xfe0d`) appears in this hello. | `false` (Absent) |
| **`parse_status`** | Parser validation logic | Well-formed (`OUTER_OK`), malformed, truncated, duplicate, or protocol anomaly. | `INCOMPLETE_CAPTURE` |
| **`outer_sni`** | Extension `0x0000` | The hostname transmitted in the cleartext `server_name`. | `<none>` (No SNI present) |
| **`kdf_id`, `aead_id`, `config_id`** | Ext `0xfe0d` body | Exact cryptographic identifiers sent on the wire. | Invalid unless `parse_status == OUTER_OK`. |
| **`ciphertext_len`** | Ext `0xfe0d` payload length | Byte length of the encrypted inner hello $+$ padding $+$ AEAD tag. | Never described as raw padding length. |
| **`inferred_kem`** | Ext `enc_len` | KEM algorithm consistent with the observed ephemeral key length. | `Unknown`; explicitly labeled as inferred. |
| **`acceptance`** | ServerHello / HRR / Keys | Non-acceptance observed (I3) or verified via lab keylog oracle. | `UNVERIFIED` to passive tap for standard TLS 1.3 completions. |
| **`offer_type`** | Rules I1, I2, I4, I5 | Inferred hypothesis with named supporting evidence rule. | `UNKNOWN` (rules fired: none) |
| **`downgrade_detected`** | Handshake correlation | `REJECTED_OR_IGNORED_TLS12` or `REJECTED_HRR_WITHOUT_ECH` after ECH offer. | `NONE` (normal TLS 1.3 completion or unobserved server flight). |
| **`padding_anomaly`** | Ciphertext arithmetic check | $\text{ciphertext\_len} \pmod{32} \not\equiv 16$ indicating non-standard inner padding. | Valid RFC 9849 §6.1.3 padding invariant. |
| **`tcp_flight_metrics`** | Accumulator telemetry | Segment count, payload bytes, and MSS boundary splits for the ClientHello. | Incomplete TCP stream or unreassembled fragments. |

---

## 5. Transport Layer Reality: Stream Accumulation for ECH

### 5.1 Real-World Handshake Size Explosion
A vital finding from real-world network captures is that **ECH ClientHellos frequently exceed single-packet Ethernet MTUs**:
- In Chrome 124–130, `X25519Kyber768Draft00` (1216B key share) was enabled; starting in Chrome 131, `X25519MLKEM768` (1216B key share) is standard.
- The hybrid post-quantum key share alone takes ~1.2 KB. The ECH extension adds an additional **350–450 bytes** of ephemeral public keys and ciphertext.
- Total handshake length reaches **roughly 2.0 KB to 2.8 KB**, causing ECH-bearing handshakes to span **2 TCP packets** under standard MTU (1500 bytes, MSS ~1448 bytes).
- **The Engine's Two-Tier Accumulator:** This transport reality validates our Milestone 1 **Two-Tier Accumulator (8 KB bounded buffer)**. Naive single-packet sniffers fail or truncate on modern ECH handshakes; our engine reassembles them cleanly with zero steady-state heap allocations.

### 5.2 Transport Flight Accounting & Segmentation Profiling
By tracking the physical delivery of ECH-bearing ClientHellos at Layer 4, the engine correlates transport mechanics with TLS security:
- **Segment Flight Count:** Records the physical number of TCP packets required to deliver the outer handshake (typically 2 segments under standard 1,500-byte MTU, or 1 jumbo segment under Linux GRO/LRO).
- **MSS Boundary Slicing:** Verifies whether segments are partitioned cleanly at the standard 1,448-byte TCP MSS boundary. Unusual fragment offsets or micro-segments highlight proxy buffering or traffic shaping.
- **Header Buffering Diagnostics:** Validates whether the 5-byte TLS record header arrived split across segment boundaries, testing the engine's partial header buffer.

### 5.3 Strict Wire Validation & Malformed Anomaly Telemetry
The engine upgrades ECH parsing into a hardened, fuzzer-resistant protocol validation layer:
- **Padding Invariant Verification (RFC 9849 §6.1.3):** Because AEAD ciphers in ECH (AES-128-GCM, ChaCha20-Poly1305) produce a 16-byte authentication tag and the inner hello is padded to a multiple of 32 bytes, the outer ciphertext length must strictly satisfy:
  $$\text{ciphertext\_len} \pmod{32} \equiv 16$$
  Any deviation is flagged as an `ECH_PADDING_ANOMALY`, detecting non-standard padding implementations or packet tampering.
- **Duplicate Extension Guard (RFC 8446 §4.2):** Multiple occurrences of `0xfe0d` are flagged as `EchParse::DUPLICATE`, preventing extension collision attacks.
- **Cleartext Outer Anomaly (RFC 9849 §5.1):** Cleartext presence of `0xfd00` (`ech_outer_extensions`) in the outer ClientHello is flagged as `EchParse::ANOMALY_FD00_IN_OUTER`.
- **Zero-Allocation Safety:** Strict bounds checking via `ByteReader` guarantees that truncated or corrupted payloads cannot cause out-of-bounds memory accesses.

---

## 6. Empirical Research Hypotheses & Validation Matrix

| Research Hypothesis | Decisive Evidence Required | Main Confound / Risk |
| :--- | :--- | :--- |
| **H1: Ciphertext length distinguishes browser families.** | Repeat captures across identical destinations and configs; measure Chrome vs. Firefox vs. curl-impersonate. | Inner hello contents, extensions, compression, and padding vary together. |
| **H2: Ciphertext length tracks inner SNI length when $M=0$.** | Map inner SNI lengths against `ciphertext_len` across Cloudflare-hosted domains using a scripted client. | Provider `ECHConfig` changes or internal extension variations. |
| **H3: HPKE suite fields add identification entropy.** | Compare outer JA3/JA4 alone against outer JA3/JA4 $+$ `{kdf_id, aead_id}`. | Server `ECHConfig` advertises only a single suite, eliminating client choice (§6.1). |
| **H4: Real and GREASE offers can be separated in narrow subsets.** | Evaluate HRR verbatim copy (I1), empty enc (I2), and stateful `config_id` stability (I4) against labeled captures. | Requires HRR or stateful multi-connection history; fails on single isolated flows. |

---

## 7. Concrete Lab Recipe: Recording Ground-Truth Captures

To ensure 100% reproducibility for project evaluation:

1. **Force TCP Transport:** Disable QUIC in Google Chrome via `--disable-quic` to ensure all handshakes run over TCP and are captured by the engine. (QUIC/HTTP/3 encapsulation inside CRYPTO frames is documented as a scope boundary).
2. **Fresh User Profile:** Always pass a dedicated `--user-data-dir=/tmp/ech_test` so Chrome does not connect to an existing running instance (which silently ignores `SSLKEYLOGFILE`).
3. **Configuration A (DoH Enabled — Real ECH Active):**
   - Configure Chrome with Cloudflare DoH (`https://1.1.1.1/dns-query`).
   - Run:
     ```bash
     SSLKEYLOGFILE=./ech_keys.log google-chrome --disable-quic --user-data-dir=/tmp/ech_chrome https://crypto.cloudflare.com/cdn-cgi/trace
     ```
   - Verify endpoint ground-truth: Page outputs `sni=encrypted` and `tls=TLSv1.3`.
   - Inspect keylog: Check for RFC 9850 labels (`ECH_SECRET`, `ECH_CONFIG`) and verify that standard TLS traffic secrets are keyed by `ClientHelloInner.random`.
4. **Configuration B (Plaintext DNS — SVCB Out-of-Band Delivery):**
   - Configure standard system DNS via port 53.
   - Run `dig HTTPS crypto.cloudflare.com` and record the raw `ECHConfigList`.
   - Inspect DNS Type 65 (`HTTPS`) in Wireshark to demonstrate out-of-band delivery (RFC 9848).
5. **GREASE ECH Capture:**
   - Connect Chrome to a verified non-ECH website (verify with `dig HTTPS <target>` that no `ech` parameter is present):
     ```bash
     google-chrome --disable-quic --user-data-dir=/tmp/ech_grease https://example.com
     ```
   - Verify that extension `0xfe0d` is sent alongside the real cleartext SNI `example.com`.
6. **HRR Verification (H4 Recipe):**
   - Because Chrome offers both hybrid and X25519 key shares by default, HRR is rare.
   - To trigger an HRR in the lab, configure a local OpenSSL 3.0+ test server restricted to group `secp384r1` or `P-256` only (groups that Chrome does not proactively send a key share for), prompting the server to issue an HRR.

---

## 8. Presentation Strategy & Academic Viva Defense

### 8.1 Slide Deck Structure
- **Slide 1: The Observability Challenge:** RFC 9849 encrypts the inner ClientHello. Plaintext SNI is replaced by an outer public cover domain.
- **Slide 2: The Evidence Contract:** Passive sniffers cannot compute `accept_confirmation` (derived from `ClientHelloInner.random`). Telemetry separates Observed facts, Inferred hypotheses, and Endpoint Ground Truth.
- **Slide 3: Wire Dissection & Compliance:** Parsing `0xfe0d` envelopes, evaluating the 32-byte padding invariant ($\text{ciphertext\_len} \pmod{32} \equiv 16$), and detecting anomalies like cleartext `0xfd00` and `aead_id == 0xFFFF`.
- **Slide 4: Stateful GREASE Disambiguation & Accumulator Proof:** Demonstrating HRR verbatim-copy tests (I1) vs. empty-enc (I2), and showing how our 8 KB accumulator reassembles fragmented post-quantum ECH handshakes.

### 8.2 Defending Tough Viva Questions

- **Q: "Can your passive sniffer determine whether the server accepted ECH?"**  
  *A: "In standard successful handshakes, no—and claiming to do so passively is mathematically false. In RFC 9849 §7.2, accept_confirmation in ServerHello.random is derived from ClientHelloInner.random, which is inside the ciphertext. To a passive observer, the last 8 bytes of ServerHello.random appear uniformly random. We can passively infer non-acceptance only under narrow conditions: if the server negotiates below TLS 1.3 or issues an HRR omitting the ECH extension."*

- **Q: "Does the presence of extension 0xfe0d in an HRR prove acceptance?"**  
  *A: "No. RFC 9849 §7.1 explicitly states that a rejecting server MAY send an ECH extension containing 8 random bytes in its HRR. Therefore, presence proves nothing. Only the complete absence of extension 0xfe0d in an HRR definitively proves non-acceptance (§6.1.4)."*

- **Q: "Why does your engine match only 0xfe0d and ignore 0x001b?"**  
  *A: "0x001b is allocated by IANA for Certificate Compression (RFC 8879 §3), sent by modern browsers on almost every connection. ECH is registered exclusively as 0xfe0d (RFC 9849 §11.1). Treating 0x001b as ECH is a known analytical error that corrupts fingerprint metadata."*

- **Q: "Can you distinguish Real ECH from GREASE ECH with 100% certainty on a single connection?"**  
  *A: "No. RFC 9849 §10.10.4 explicitly notes that Real ECH and GREASE are designed to be indistinguishable to a per-connection passive observer without the ECHConfigList. Our engine uses a 3-state output (OFFERED_LIKELY_REAL, OFFERED_LIKELY_GREASE, UNKNOWN) supported by stateful evidence: config_id stability over time, known public_name patterns, and HRR extension-copy behavior."*

- **Q: "How does the outer extension identify the KEM algorithm?"**  
  *A: "It does not identify it directly. The outer extension carries only kdf_id, aead_id, config_id, enc, and payload. The kem_id lives in the ECHConfig distributed via DNS (RFC 9848). Identifying DHKEM-X25519 from enc_len = 32 is an inference based on current deployment profiles, and our engine explicitly labels it as inferred."*

- **Q: "How can the engine detect ECH downgrade or stripping attempts?"**  
  *A: "When an active MITM proxy strips extension 0xfe0d, or when a server drops ECH, the engine tracks handshake symmetry: if a client offers 0xfe0d and the server negotiates TLS 1.2 or issues an HRR omitting 0xfe0d, non-acceptance is proven. When historical telemetry is available, observing a known-ECH domain suddenly running unencrypted SNI flags an anomalous downgrade."*

- **Q: "Why does the engine validate the ciphertext padding invariant?"**  
  *A: "RFC 9849 §6.1.3 mandates that inner ClientHellos be padded to a multiple of 32 bytes. Combined with the 16-byte AEAD authentication tag, valid ECH ciphertexts must strictly satisfy ciphertext_len mod 32 == 16. Checking this invariant allows our engine to detect malformed packets, corrupted captures, or non-compliant client stacks."*

---

## 9. Explicit Non-Claims: What the Engine Does NOT Claim

| Non-Claim | Technical Justification |
| :--- | :--- |
| **"ECH completely eliminates the plaintext domain"** | Plaintext DNS lookups and destination IP addresses remain visible disclosure channels (RFC 9849 §1, §10). |
| **"ECH uses extension codepoint 0x001b"** | `0x001b` is Certificate Compression (RFC 8879). ECH is exclusively `0xfe0d`. |
| **"Real ECH is proven by outer SNI or missing SNI"** | `public_name` is configured per provider; GREASE to IP literals has no SNI. Outer SNI is an out-of-scope differentiator (§10.10.4). |
| **"Passive detection of ECH acceptance"** | Computing `accept_confirmation` requires `ClientHelloInner.random`, which is sealed in ciphertext (§7.2). |
| **"Presence of 0xfe0d in an HRR proves acceptance"** | A rejecting server MAY send an ECH extension with 8 random bytes in an HRR (§7.1). |
| **"KEM algorithm is directly identified from the ClientHello"** | `kem_id` lives strictly in the out-of-band `ECHConfig` (§4). |
| **"Payload length equals padding length"** | Ciphertext includes the inner ClientHello, zero-padding, and the 16-byte AEAD tag (§6.1.1). |
| **"Deterministic bot or impersonation detection"** | `User-Agent` is encrypted application data in TLS 1.3 (RFC 8446). Browser fingerprinting identifies the crypto stack, not human presence. |
| **"Sniffers are obsolete / Shadow IT bypass"** | Exaggerated claims unsupported by measurement; policy evaluation must be grounded in explicit enterprise rules. |
| **"L4/TCP correlation is an ECH result"** | ECH does not touch TCP options; cross-layer correlation belongs to the JA4T track. |
