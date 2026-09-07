# JA3 and JA3S Fingerprint Specification

**Document Scope:** Complete documentation of the Salesforce JA3/JA3S fingerprint algorithm as implemented in both Python and C++ tracks.

---

## 1. Specification Origin

JA3 was created by John Althouse, Jeff Atkinson, and Josh Atkins at Salesforce in 2017. It generates a deterministic hash from five fields of the TLS ClientHello message. JA3S is the server-side counterpart, using three fields from the ServerHello.

**Reference:** [github.com/salesforce/ja3](https://github.com/salesforce/ja3)

---

## 2. JA3 (Client Fingerprint)

### 2.1 Field Composition

The JA3 raw string is a comma-separated concatenation of five fields, each internally separated by hyphens:

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
```

| Field # | Name | Source | Format |
|---------|------|--------|--------|
| 1 | TLS Version | `ClientHello.client_version` (handshake body, NOT record layer) | Decimal integer (e.g., `771` for 0x0303) |
| 2 | Cipher Suites | `ClientHello.cipher_suites` (GREASE-filtered) | Hyphen-separated decimal (e.g., `4865-4866-4867`) |
| 3 | Extensions | Extension type codes (GREASE-filtered, wire order) | Hyphen-separated decimal |
| 4 | Elliptic Curves | From `supported_groups` extension (0x000a), GREASE-filtered | Hyphen-separated decimal |
| 5 | EC Point Formats | From `ec_point_formats` extension (0x000b) | Hyphen-separated decimal |

### 2.2 GREASE Filtering

**RFC 8701** defines 16 "Generate Random Extensions And Sustain Extensibility" values that clients insert to test middlebox tolerance. These MUST be removed before fingerprinting because they are intentionally random.

GREASE values follow the pattern `0x?a?a` where `?` is any hex nibble and both bytes are identical:

```
0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
```

#### Implementation: Python (`ja3.py`)

```python
GREASE_VALUES = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
})

def is_grease(value: int) -> bool:
    return value in GREASE_VALUES

def filter_grease(values: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(v for v in values if not is_grease(v))
```

#### Implementation: C++ (`parser.hpp`)

```cpp
inline bool is_grease(uint16_t val) noexcept {
    return ((val & 0x0f0f) == 0x0a0a) && ((val >> 8) == (val & 0x00ff));
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Detect and remove GREASE values from fingerprint inputs |
| **Design Choice** | Python uses a frozenset lookup (O(1) average); C++ uses a bitwise formula (O(1) worst-case, no memory) |
| **Reason** | Python's frozenset is idiomatic and readable. C++ bitwise check is branchless and avoids any heap allocation — important at packet-processing speed |
| **Alternative Considered** | Both could use a sorted array with binary search, or a precomputed bitmask |
| **Trade-off** | The frozenset uses ~512 bytes of memory; the bitwise formula uses zero. Both are effectively instant for 16 values |

### 2.3 Serialization

Each field is serialized as hyphen-separated decimal integers. Empty fields produce an empty string between the commas.

```python
def serialize_field(values: tuple[int, ...]) -> str:
    return "-".join(str(v) for v in values)
```

```cpp
template <typename T>
static inline void append_joined(std::string &out, const std::vector<T> &vec, char delimiter = '-') {
    char num_buf[16];
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) out += delimiter;
        auto [ptr, ec] = std::to_chars(num_buf, num_buf + sizeof(num_buf), static_cast<uint32_t>(vec[i]));
        out.append(num_buf, static_cast<size_t>(ptr - num_buf));
    }
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Convert integer arrays to the JA3 string format |
| **Design Choice** | Python uses `str.join()` with generator expressions; C++ uses `std::to_chars` with a stack buffer |
| **Reason** | Python's approach is idiomatic and concise. C++ uses `std::to_chars` (C++17) to avoid `std::stringstream` overhead — zero heap allocation per number conversion |
| **Alternative Considered** | `snprintf` (C), `std::ostringstream` (C++), `f-string` formatting (Python) |
| **Trade-off** | `std::to_chars` is less readable than `snprintf` but avoids locale dependency and is guaranteed not to allocate |

### 2.4 MD5 Hashing

The final JA3 hash is the MD5 hexadecimal digest (32 lowercase hex characters) of the raw string.

```python
def compute_ja3_hash(fields: ClientHelloFields) -> str:
    ja3_str = compute_ja3_string(fields)
    return hashlib.md5(ja3_str.encode('utf-8')).hexdigest()
```

```cpp
std::string md5_hex(const std::string &input) {
    static thread_local ThreadLocalEvpContext tls_ctx;  // Reusable context
    // ... EVP_DigestInit_ex / EVP_DigestUpdate / EVP_DigestFinal_ex ...
    // Convert 16-byte digest to 32-char hex via nibble LUT
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Produce a deterministic, fixed-length identifier from the variable-length JA3 string |
| **Design Choice** | MD5 hash (as specified by the JA3 standard) |
| **Reason** | The JA3 specification mandates MD5. MD5 produces a compact 32-character hex string suitable for database keys and log correlation. Collision resistance is not critical here — JA3 is a classification heuristic, not a cryptographic identifier |
| **Alternative Considered** | SHA-256 (used by JA4), or using the raw string directly |
| **Trade-off** | MD5 is cryptographically broken for collision resistance, but this is irrelevant for fingerprinting. Using the raw string would be more precise but unwieldy for database keys |

### 2.5 C++ Performance Optimization: Thread-Local EVP Context

```cpp
struct ThreadLocalEvpContext {
    EVP_MD_CTX *ctx{nullptr};
    ThreadLocalEvpContext() : ctx(EVP_MD_CTX_new()) {}
    ~ThreadLocalEvpContext() { if (ctx) EVP_MD_CTX_free(ctx); }
};

std::string md5_hex(const std::string &input) {
    static thread_local ThreadLocalEvpContext tls_ctx;
    // Reuses ctx across calls — no heap allocation per packet
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Compute MD5 hashes at line rate without per-packet heap allocation |
| **Design Choice** | `thread_local` OpenSSL EVP context, allocated once per thread, reused for every hash |
| **Reason** | `EVP_MD_CTX_new()` performs a heap allocation. At high packet rates (>100k pps), per-packet allocation becomes a bottleneck |
| **Alternative Considered** | Per-call `EVP_MD_CTX_new()`/`EVP_MD_CTX_free()`, or the deprecated `MD5()` one-shot function |
| **Trade-off** | Thread-local storage adds complexity and makes the context lifetime implicit, but eliminates allocation overhead in the hot path |

---

## 3. JA3S (Server Fingerprint)

### 3.1 Field Composition

```
TLSVersion,SelectedCipher,Extensions
```

| Field # | Name | Source | Format |
|---------|------|--------|--------|
| 1 | TLS Version | `ServerHello.server_version` | Decimal integer |
| 2 | Selected Cipher | `ServerHello.cipher_suite` (single value, NOT a list) | Decimal integer |
| 3 | Extensions | Extension type codes (GREASE-filtered, wire order) | Hyphen-separated decimal |

Note: JA3S has no Elliptic Curves or EC Point Formats fields because the server does not advertise these in the ServerHello.

### 3.2 Implementation

```python
def compute_ja3s_string(fields: ServerHelloFields) -> str:
    version_str = str(fields.tls_version)
    cipher_str = str(fields.cipher_suite)
    extensions_str = serialize_field(filter_grease(fields.extensions))
    return f"{version_str},{cipher_str},{extensions_str}"
```

```cpp
JA3Fingerprint compute_ja3s(const ServerHelloData &server) {
    // 1. Version
    fp.raw_string.append(to_chars(server.server_version));
    fp.raw_string += ',';
    // 2. Selected Cipher (single value, not joined)
    fp.raw_string.append(to_chars(server.selected_cipher));
    fp.raw_string += ',';
    // 3. Extensions
    append_joined(fp.raw_string, server.extensions);
    fp.md5_hash = md5_hex(fp.raw_string);
}
```

---

## 4. Complete Example: JA3 Computation

### Input: Salesforce Official Test Vector 1

```
ClientHello:
  client_version: 769 (0x0301 = TLS 1.0)
  cipher_suites: [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]
  extensions: [0, 10, 11]
  supported_groups: [23, 24, 25]
  ec_point_formats: [0]
```

### Step-by-Step

1. **GREASE filter:** No GREASE values present → all values pass through
2. **Serialize each field:**
   - Version: `"769"`
   - Ciphers: `"47-53-5-10-49161-49162-49171-49172-50-56-19-4"`
   - Extensions: `"0-10-11"`
   - Curves: `"23-24-25"`
   - Formats: `"0"`
3. **Concatenate:** `"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"`
4. **MD5:** `ada70206e40642a3e4461f35503241d5`

### Validation

This matches the official Salesforce test vector. Both our Python and C++ test suites verify this:

```python
# Python: test_fingerprints.py
assert compute_ja3_hash(fields) == "ada70206e40642a3e4461f35503241d5"
```

```cpp
// C++: test_fingerprints.cpp, SalesforceOfficialVector1
EXPECT_EQ(fp.md5_hash, "ada70206e40642a3e4461f35503241d5");
```

---

## 5. Important JA3 Behaviors

### 5.1 Empty Fields

When a field has no values (e.g., no extensions), it serializes to an empty string. The commas are always present:

```
"771,4865-4866-4867,,,"   ← Three trailing commas for empty Extensions, Curves, Formats
```

This is verified by the `EmptyFieldsArePreserved` test in the C++ suite.

### 5.2 Wire Order Preservation

JA3 preserves the **original wire order** of cipher suites and extensions. This is critical: different TLS libraries present the same set of ciphers in different orders, and this ordering is part of the fingerprint.

### 5.3 Extension Types vs Extension Data

JA3 uses only the extension **type codes** (2-byte identifiers like 0x0000 for SNI, 0x000a for Supported Groups). The extension **data** is used to extract Supported Groups and EC Point Formats, but those values go into separate JA3 fields.

### 5.4 Version Field Semantics

JA3 uses the version from the **handshake body** (`ClientHello.client_version`), not the TLS Record layer version. For TLS 1.3 connections, this means JA3 reports `771` (0x0303 = TLS 1.2) because TLS 1.3 freezes this field for middlebox compatibility. This is documented as a known limitation of JA3 addressed by the JA4 specification.
