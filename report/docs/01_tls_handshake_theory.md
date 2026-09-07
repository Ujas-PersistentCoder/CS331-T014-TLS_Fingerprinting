# TLS Handshake Theory — Conceptual Foundation

**Document Scope:** Computer networks theory underlying the TLS handshake, mapped to the specific byte offsets and parsing logic used in our implementation.

---

## 1. Why the Handshake Is Visible

TLS encrypts application-layer data, but the initial cryptographic negotiation — the **handshake** — must be transmitted in plaintext. Both parties need to agree on a cipher suite, exchange key material, and authenticate before any encryption can begin. This creates a window where a passive observer on the wire can extract the following metadata without possessing any keys:

- Which TLS versions the client supports
- Which cipher suites the client offers (and which one the server selects)
- Which extensions the client advertises (and which the server echoes)
- Which elliptic curves the client supports
- Which ALPN protocols the client requests

This metadata is sufficient to construct a **behavioral fingerprint** that uniquely identifies the TLS library, application, or operating system generating the traffic.

---

## 2. TLS Record Protocol

Every TLS message — handshake, alert, change-cipher-spec, or application data — is wrapped in a **Record** layer. This is the outermost framing structure visible on the wire.

### Wire Format (5 bytes)

```
Byte Offset   Field               Size     Description
──────────────────────────────────────────────────────────
0             Content Type        1 byte   20=CCS, 21=Alert, 22=Handshake, 23=AppData
1–2           Legacy Version      2 bytes  e.g., 0x0301 (TLS 1.0), 0x0303 (TLS 1.2)
3–4           Fragment Length      2 bytes  Length of the payload fragment
──────────────────────────────────────────────────────────
5..           Fragment             variable The actual message payload
```

### Implementation Mapping

| Field | Python (`parser.py`) | C++ (`parser.cpp`) |
|-------|---------------------|-------------------|
| Content Type | `data[offset]` (line 42) | `reader.read_u8()` — compared against `0x16` (line 200) |
| Legacy Version | `struct.unpack('!H', data[offset+1:offset+3])` (line 43) | `reader.skip(2)` — explicitly ignored per JA3 spec (line 202) |
| Fragment Length | `struct.unpack('!H', data[offset+3:offset+5])` (line 44) | `reader.read_u16()` (line 203) |

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Parse the TLS Record header to extract the handshake payload |
| **Design Choice** | Skip the Record-layer version field; use only the Handshake-layer version for fingerprinting |
| **Reason** | The JA3 specification explicitly states that the Record-layer version should be ignored. In TLS 1.3, the Record-layer version is frozen at 0x0303 for middlebox compatibility (RFC 8446 §4.2.1). The *true* negotiated version is inside the `supported_versions` extension |
| **Alternative Considered** | Use the Record-layer version as a fingerprinting input |
| **Trade-off** | Ignoring the Record-layer version means we are compliant with the JA3 specification and correctly handle TLS 1.3, at the cost of losing one potential discriminator |

### Key Implementation Detail — Content Type Filtering

Our capture modules only process records with Content Type `22` (Handshake). Non-handshake records (ChangeCipherSpec=20, Alert=21, Application Data=23) are **skipped** in the stream, not dropped — any subsequent handshake data in the same TCP stream is still processed.

```
Python (capture.py, line 332):    if content_type != 22: del flow.stream[:total_record_size]; continue
C++    (capture.cpp, line 338):   (record_type == 0x16) check — non-0x16 flows are never tracked
```

---

## 3. TLS Handshake Protocol

Within a Record of Content Type 22, one or more **Handshake** messages are carried. Each Handshake message has its own 4-byte header.

### Wire Format (4 bytes)

```
Byte Offset   Field               Size     Description
──────────────────────────────────────────────────────────
0             Message Type        1 byte   1=ClientHello, 2=ServerHello, 11=Certificate, ...
1–3           Length              3 bytes  Length of the handshake body (big-endian, 24-bit)
──────────────────────────────────────────────────────────
4..           Handshake Body      variable
```

### Implementation Mapping

| Field | Python (`parser.py`) | C++ (`parser.cpp`) |
|-------|---------------------|-------------------|
| Message Type | `data[offset]` (line 66) | `reader.read_u8()` — compared against `0x01` or `0x02` (lines 208, 271) |
| Length | 3-byte unpack: `b'\x00' + data[offset+1:offset+4]` → `struct.unpack('!I', ...)` (lines 68–69) | `reader.read_u24()` (lines 210, 273) |

### Why 3-byte Length?

The Handshake length field is 24 bits, allowing messages up to 16 MB. This accommodates large certificate chains that can exceed the 16 KB maximum TLS record fragment. When a handshake message exceeds one record, it is split across multiple records — our reassembly logic handles this via the `pending_handshake` buffer (Python) or the `StreamBuffer` (C++).

---

## 4. ClientHello Message Structure

The ClientHello is the first message sent by the client. It contains all the fields that constitute a JA3 fingerprint.

### Wire Format

```
Byte Offset   Field                    Size        Description
───────────────────────────────────────────────────────────────────────
0–1           Client Version           2 bytes     e.g., 0x0303 = TLS 1.2
                                                   ★ JA3 Field 1
2–33          Random                   32 bytes    Client nonce (skipped)
34            Session ID Length (N)     1 byte      Length of Session ID
35..(35+N-1)  Session ID               N bytes     (skipped)
(35+N)        Cipher Suites Length (M)  2 bytes     Total byte length of cipher list
(37+N)..      Cipher Suites            M bytes     Array of 2-byte cipher IDs
                                                   ★ JA3 Field 2
...           Comp. Methods Length (C)  1 byte
...           Compression Methods      C bytes     (skipped — always null in TLS 1.3)
...           Extensions Length         2 bytes     Total byte length of all extensions
...           Extension 1              variable    ★ Extension types → JA3 Field 3
...           Extension 2              variable    
...           ...                                  
```

### Extensions Relevant to Fingerprinting

| Extension Type | Code | JA3 Field | JA4 Usage | Parsing Logic |
|----------------|------|-----------|-----------|---------------|
| **Server Name Indication (SNI)** | 0x0000 | Field 3 (type code only) | JA4_a: 'd' (domain) vs 'i' (IP). Excluded from JA4_c hash | Parse hostname for display |
| **Supported Groups** | 0x000a | Field 4 (curve IDs) | Not used in JA4 | Parse 2-byte group IDs |
| **EC Point Formats** | 0x000b | Field 5 (format IDs) | Not used in JA4 | Parse 1-byte format IDs |
| **Signature Algorithms** | 0x000d | Not used in JA3 | JA4_c: appended in wire order after `_` separator | Parse 2-byte algorithm IDs |
| **ALPN** | 0x0010 | Not used in JA3 | JA4_a: first+last character. Excluded from JA4_c hash | Parse length-prefixed protocol strings |
| **Supported Versions** | 0x002b | Not used in JA3 | JA4_a: true version resolution (prefers 0x0304 = TLS 1.3) | Parse 2-byte version IDs |

### Implementation Mapping (ClientHello Parser)

```
Python (parser.py, parse_client_hello):
  Line 97:  tls_version = struct.unpack('!H', data[0:2])[0]
  Line 99:  offset = 34  # Skip version(2) + random(32)
  Line 100: session_id_len = data[offset]
  Line 106: cipher_suites_len = struct.unpack('!H', data[offset:offset+2])[0]
  Line 116: cipher_suite = struct.unpack('!H', data[offset+i:offset+i+2])[0]   # loop M/2 times
  Line 141: ext_total_len = struct.unpack('!H', data[offset:offset+2])[0]
  Line 149: ext_type = struct.unpack('!H', data[offset:offset+2])[0]          # extension type
  Line 150: ext_len = struct.unpack('!H', data[offset+2:offset+4])[0]         # extension length

C++ (parser.cpp, parse_client_hello):
  Line 218: out.client_version = reader.read_u16();
  Line 221: reader.skip(32);                    // Random
  Line 225: session_id_len = reader.read_u8();
  Line 230: cipher_suites_len = reader.read_u16();
  Line 235: cs = reader.read_u16();             // each cipher suite
  Line 248: extensions_len = reader.read_u16();
  Line 56:  ext_type = reader.read_u16();       // in parse_extensions()
  Line 57:  ext_len = reader.read_u16();
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Parse variable-length TLS structures to extract fingerprint fields |
| **Design Choice** | Manual byte-by-byte TLV parsing using `struct.unpack` (Python) and a custom `ByteReader` (C++) |
| **Reason** | TLS is a chain of Type-Length-Value structures. Each field's offset depends on the variable lengths of all preceding fields. Manual parsing gives complete control over every byte offset and makes each step explainable at the protocol level |
| **Alternative Considered** | Using a TLS parsing library (e.g., `scapy.layers.tls`, `dpkt.ssl`), or ASN.1 decoders |
| **Trade-off** | Manual parsing requires more code and more bounds checking, but it eliminates external dependencies and ensures every student can trace the exact byte that produces each fingerprint component |

---

## 5. ServerHello Message Structure

The ServerHello is the server's response. It contains fewer fields because the server **selects** one cipher suite (not a list) and echoes only the extensions it supports.

### Wire Format

```
Byte Offset   Field                    Size        Description
───────────────────────────────────────────────────────────────────────
0–1           Server Version           2 bytes     e.g., 0x0303
                                                   ★ JA3S Field 1
2–33          Random                   32 bytes    Server nonce (skipped)
34            Session ID Length (N)     1 byte
35..(35+N-1)  Session ID               N bytes     (skipped)
(35+N)        Selected Cipher Suite    2 bytes     Single cipher
                                                   ★ JA3S Field 2
(37+N)        Compression Method       1 byte      (skipped — 0x00 in TLS 1.3)
(38+N)        Extensions Length         2 bytes
(40+N)..      Extensions               variable    ★ JA3S Field 3
```

### Key Difference: Supported Versions in ServerHello

In TLS 1.3, the ServerHello's `supported_versions` extension (0x002b) contains exactly **2 bytes** — the single negotiated version — unlike the ClientHello which contains a list. Our parser handles this asymmetry:

```
Python (parser.py, line 273–275):
  if ext_type == 0x002b:  # ServerHello supported_versions is just 2 bytes
      if len(ext_data) >= 2:
          supported_version = struct.unpack('!H', ext_data[0:2])[0]

C++ (parser.cpp, line 321):
  if (ext_type == 0x002b && ext_len == 2 && reader.has_bytes(2))
```

---

## 6. The TLV Parsing Chain — Conceptual Overview

TLS parsing is fundamentally a chain of **Type-Length-Value** (TLV) structures nested inside each other:

```
TLS Record (TLV₁)
  └─ Content Type (T₁), Fragment Length (L₁), Fragment (V₁)
       └─ Handshake Message (TLV₂)
            └─ Message Type (T₂), Length (L₂), Body (V₂)
                 └─ ClientHello Body
                      ├─ Version (fixed 2 bytes)
                      ├─ Random (fixed 32 bytes)
                      ├─ Session ID (LV)
                      ├─ Cipher Suites (LV — length-prefixed array of 2-byte values)
                      ├─ Compression Methods (LV)
                      └─ Extensions Block (LV)
                           └─ Extension₁ (TLV₃)
                                └─ Type (T₃), Length (L₃), Data (V₃)
                                     └─ May contain further nested LV structures
                                        (e.g., Supported Groups has its own length prefix)
```

Each "L" (length) field determines how far to advance the cursor before reading the next structure. A single off-by-one error cascades through the entire parse. This is why both implementations include extensive bounds checking.

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Safely navigate deeply nested TLV structures without crashes or buffer overflows |
| **Design Choice** | Check remaining buffer length before every read; break on truncation rather than raising exceptions in the inner loop |
| **Reason** | Network data is inherently untrusted. Malformed packets, truncated captures, and deliberate fuzzing can produce any byte sequence. The parser must be robust to all inputs |
| **Alternative Considered** | Trust the length fields and rely on exception handlers for out-of-bounds access |
| **Trade-off** | Defensive parsing adds conditional branches to every read, but prevents crashes and produces clean error messages (or silent skip) for malformed data |

---

## 7. Data Structures — Parsed Output

### Python: Frozen Dataclasses

```python
@dataclass(frozen=True)
class ClientHelloFields:
    tls_version: int              # Handshake body version (e.g., 0x0303 = 771)
    cipher_suites: tuple[int, ...]
    extensions: tuple[int, ...]
    elliptic_curves: tuple[int, ...]
    ec_point_formats: tuple[int, ...]
    server_name: str | None
    alpn: tuple[str, ...] | None
    signature_algorithms: tuple[int, ...] | None
    supported_versions: tuple[int, ...] | None
```

### C++: Mutable Scratchpad Structs

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
    std::string_view sni;       // Zero-copy reference into packet buffer
    std::string_view first_alpn;
    void clear() noexcept;      // Reset for reuse
};
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Store parsed handshake fields for downstream fingerprint computation |
| **Design Choice** | Python uses frozen (immutable) dataclasses with tuples; C++ uses mutable structs with a `clear()` method |
| **Reason** | Python's frozen dataclasses enforce immutability, preventing accidental mutation after parsing. C++ scratchpad structs with `clear()` allow reuse across packets without heap allocation per packet — critical for high-throughput capture |
| **Alternative Considered** | C++ could use `std::optional` or return new structs per packet; Python could use mutable dicts |
| **Trade-off** | Python allocates a new object per handshake (clean, but more GC pressure). C++ reuses one object (faster, but requires disciplined `clear()` before each parse) |

---

## 8. Version Negotiation — TLS 1.2 vs TLS 1.3

TLS 1.3 (RFC 8446) introduced a significant change to version negotiation that directly impacts fingerprinting:

### Pre-TLS 1.3 (Versions ≤ 1.2)
- The `client_version` field in the ClientHello body directly indicates the highest version the client supports
- The `server_version` field in the ServerHello body directly indicates the negotiated version

### TLS 1.3
- The `client_version` / `server_version` fields are **frozen at 0x0303** (TLS 1.2) for middlebox compatibility
- The **true** version capability is communicated via the `supported_versions` extension (0x002b)
- ClientHello: extension contains a **list** of supported versions
- ServerHello: extension contains a **single** selected version

### Impact on Fingerprinting

| Specification | Version Source |
|--------------|---------------|
| JA3 / JA3S | Uses `client_version` / `server_version` from the handshake body (the legacy field). Does **not** consult `supported_versions` |
| JA4 / JA4S | Prefers `supported_versions` extension. Falls back to the handshake body version only if the extension is absent |

This means JA3 will report version `771` (0x0303 = TLS 1.2) for a TLS 1.3 connection, while JA4 will correctly resolve to version `"13"`.
