# JA4 and JA4S Fingerprint Specification

**Document Scope:** Complete documentation of the FoxIO JA4/JA4S fingerprint algorithm, its differences from JA3, and the implementation in both Python and C++.

---

## 1. Specification Origin

JA4 was created by John Althouse at FoxIO as a successor to JA3. It addresses several JA3 limitations:

- **Version resolution:** JA4 correctly identifies TLS 1.3 via the `supported_versions` extension
- **Sorting:** JA4 sorts cipher suites and extensions, making the fingerprint invariant to the wire order permutations that modern browsers introduce
- **Richer metadata:** JA4 incorporates SNI presence, ALPN protocol, and signature algorithms
- **Truncated SHA-256:** Uses first 12 hex characters of SHA-256 instead of full MD5

---

## 2. JA4 Structure: Three-Part Fingerprint

A JA4 fingerprint consists of three sections separated by underscores:

```
JA4_a _ JA4_b _ JA4_c
```

Example: `t13d1516h2_8daaf6152771_e56270d44002`

---

## 3. JA4_a — Prefix (10 Characters)

The prefix encodes high-level metadata about the handshake in a fixed 10-character string:

```
Position   Field            Values              Example
─────────────────────────────────────────────────────────
1          Protocol         t=TCP, q=QUIC       t
2-3        TLS Version      13, 12, 11, 10,     13
                            s3, s2, d1-d3, 00
4          SNI Indicator    d=SNI ext present,   d
                            i=absent
5-6        Cipher Count     00–99 (non-GREASE)   15
7-8        Extension Count  00–99 (non-GREASE)   16
9-10       ALPN Chars       First+Last char       h2
```

### 3.1 Version Resolution

JA4 prefers the `supported_versions` extension (0x002b) over the handshake body version. This correctly identifies TLS 1.3 connections where the body version is frozen at 0x0303. Per the spec, the version is the **highest** non-GREASE value in the extension, mapped through the spec's table (`0x0002` = `s2`, `0x0300` = `s3`, `0xfeff`/`0xfefd`/`0xfefc` = `d1`/`d2`/`d3`); an unrecognised highest value gives `00`, as in FoxIO's reference.

```python
# ja4.py — resolve_ja4_version
def resolve_ja4_version(fields: ClientHelloFields) -> str:
    versions = filter_grease(fields.supported_versions or ())
    if versions:
        return ja4_version_code(max(versions))
    # Fallback to handshake body version
    return ja4_version_code(fields.tls_version)
```

```cpp
// ja4.cpp — resolve_ja4_version
static inline const char* resolve_ja4_version(const ClientHelloData &client) noexcept {
    if (!client.supported_versions.empty()) {
        bool has_13 = false, has_12 = false, has_11 = false, has_10 = false;
        for (uint16_t v : client.supported_versions) {
            if (v == 0x0304) has_13 = true;
            // ...
        }
        if (has_13) return "13";
        // ...
    }
    switch (client.client_version) { /* fallback */ }
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Correctly determine the highest TLS version the client supports |
| **Design Choice** | Priority scan through `supported_versions` extension, falling back to handshake body version |
| **Reason** | TLS 1.3 clients set `client_version` to 0x0303 for middlebox compatibility (RFC 8446 §4.2.1). The true version is in the `supported_versions` extension. Using only the body version would misidentify all TLS 1.3 clients as TLS 1.2 |
| **Alternative Considered** | Always use the body version (JA3 approach), or only use `supported_versions` |
| **Trade-off** | The fallback logic adds code paths but ensures backward compatibility with pre-TLS 1.3 clients that don't include the `supported_versions` extension |

### 3.2 SNI Indicator

```python
# Spec: "If the SNI extension (0x0000) exists, then the destination of the connection is a domain"
sni = 'd' if 0x0000 in fields.extensions else 'i'
```

The flag records whether the SNI extension is present, not what it contains. Clients omit SNI when connecting to an IP address (RFC 6066 forbids IP literals in SNI), which is why its absence indicates an IP destination.

### 3.3 ALPN Characters

The first and last characters of the **first** ALPN value as sent (GREASE values included), used unchanged. If the first or last byte is not ASCII alphanumeric, the first and last characters of the value's hex encoding are used instead. No ALPN, or an empty first value, produces `"00"`.

```python
def resolve_alpn_chars(alpn: tuple[str, ...] | None) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first_alpn = alpn[0]                 # latin-1 decoded: one character per wire byte
    f, l = first_alpn[0], first_alpn[-1]
    if f in ASCII_ALNUM and l in ASCII_ALNUM:
        return f + l
    hex_value = first_alpn.encode("latin-1").hex()
    return hex_value[0] + hex_value[-1]
```

Examples: `"h2"` → `"h2"`, `"http/1.1"` → `"h1"`, `None` → `"00"`, bytes `0xBA 0xAD` → hex `baad` → `"bd"`, `0x30 0xAB` → `"3b"`. FoxIO's reference tool still prints `"99"` for non-ASCII bytes; this implementation follows the written specification (`technical_details/JA4.md`).

---

## 4. JA4_b — Sorted Cipher Hash (12 Hex Characters)

### Computation

1. Filter GREASE values from cipher suites
2. **Sort** cipher suites numerically (ascending)
3. Format each cipher as 4-character lowercase hex, comma-separated
4. Compute SHA-256 of the resulting string
5. Take the first 12 hex characters (6 bytes)

```python
def compute_ja4_b_raw(fields: ClientHelloFields) -> str:
    ciphers = filter_grease(fields.cipher_suites)
    return ",".join(f"{c:04x}" for c in sorted(ciphers))

def compute_ja4_b(fields: ClientHelloFields) -> str:
    raw = compute_ja4_b_raw(fields)
    return _sha256_hex12(raw) if raw else "000000000000"
```

```cpp
std::vector<uint16_t> sorted_ciphers = client.cipher_suites;
std::sort(sorted_ciphers.begin(), sorted_ciphers.end());
append_hex4_joined(fp.raw_ja4_b, sorted_ciphers, ',');
fp.ja4_b = sha256_hex_12(fp.raw_ja4_b);
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Create a cipher-based fingerprint component that is invariant to ordering |
| **Design Choice** | Sort ciphers numerically, format as hex, hash with truncated SHA-256 |
| **Reason** | Modern browsers (Chrome 107+) randomize the order of cipher suites. Sorting neutralizes this permutation, making the fingerprint stable across sessions of the same browser |
| **Alternative Considered** | Using wire order (JA3 approach), or hashing the sorted integer values directly |
| **Trade-off** | Sorting loses the ordering information that JA3 uses for fingerprinting. This is intentional — JA4 trades granularity for stability in the presence of randomization |

---

## 5. JA4_c — Sorted Extension + Signature Algorithm Hash (12 Hex Characters)

### Computation

1. Filter GREASE values from extensions
2. **Exclude** SNI (0x0000) and ALPN (0x0010) from the hash input (they're already represented in JA4_a)
3. **Sort** remaining extensions numerically (ascending)
4. Format as 4-character lowercase hex, comma-separated
5. If signature algorithms are present, append `_` followed by signature algorithms in **wire order** (NOT sorted), formatted as 4-character hex, comma-separated
6. Compute SHA-256 and take first 12 hex characters

```python
def compute_ja4_c_raw(fields: ClientHelloFields) -> str:
    exts = filter_grease(fields.extensions)
    filtered = [e for e in exts if e not in (0x0000, 0x0010)]  # Exclude SNI, ALPN
    exts_str = ",".join(f"{e:04x}" for e in sorted(filtered))
    
    if fields.signature_algorithms:
        sigalgs = filter_grease(fields.signature_algorithms)
        if sigalgs:
            sigalgs_str = ",".join(f"{s:04x}" for s in sigalgs)  # Wire order!
            if exts_str:
                return exts_str + "_" + sigalgs_str
            return "_" + sigalgs_str
    return exts_str
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Encode extension and signature algorithm information into a single hash component |
| **Design Choice** | Sort extensions (for stability) but preserve signature algorithm wire order (for uniqueness) |
| **Reason** | Extensions are permuted by some browsers (like cipher suites), so sorting stabilizes the fingerprint. Signature algorithms are NOT permuted by current implementations and their order is semantically meaningful (preference order), so wire order is preserved for maximum discriminating power |
| **Alternative Considered** | Sort both, or preserve wire order for both |
| **Trade-off** | Mixed sorting strategy is more complex but captures the best of both approaches: stability where randomization occurs, and precision where it doesn't |

### Why Exclude SNI and ALPN?

SNI and ALPN values are already encoded in JA4_a (SNI as `d`/`i`, ALPN as character pair). Including their type codes in JA4_c would be redundant and would not add discriminating power.

---

## 6. SHA-256 Truncation

Both Python and C++ compute a full SHA-256 digest and truncate to the first 12 hex characters (6 bytes = 48 bits).

```python
def _sha256_hex12(data: str) -> str:
    if not data:
        return "000000000000"
    return hashlib.sha256(data.encode('utf-8')).hexdigest()[:12]
```

```cpp
std::string sha256_hex_12(std::string_view input) {
    static thread_local ThreadLocalSha256Context tls_ctx;
    // ... EVP_DigestInit_ex / EVP_DigestUpdate / EVP_DigestFinal_ex ...
    std::string hex_str;
    hex_str.resize(12);
    for (size_t i = 0; i < 6; ++i) {
        hex_str[i * 2]     = HEX_LUT[(digest[i] >> 4) & 0x0F];
        hex_str[i * 2 + 1] = HEX_LUT[digest[i] & 0x0F];
    }
    return hex_str;
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Produce compact hashes for each JA4 component |
| **Design Choice** | Truncated SHA-256 to 12 hex characters (48 bits) per the JA4 specification |
| **Reason** | 48 bits provides ~2⁴⁸ possible values (>281 trillion), which is more than sufficient to avoid collisions within the practical fingerprint space. The full JA4 string (10 + 12 + 12 = 36 characters) is compact enough for logging while being more collision-resistant than JA3's 32-character MD5 |
| **Alternative Considered** | Full SHA-256 (64 characters per component), or MD5 (JA3 approach) |
| **Trade-off** | Truncation introduces theoretical collision possibility, but the probability is negligible in practice |

---

## 7. JA4S (Server Fingerprint)

JA4S follows the same three-part structure adapted for the ServerHello:

### 7.1 JA4S_a (7 Characters)

```
Position   Field            Values
──────────────────────────────────────
1          Protocol         t=TCP, q=QUIC
2-3        TLS Version      13, 12, 11, 10, s3, s2, 00
4-5        Extension Count  00–99 (all extensions, as sent)
6-7        ALPN Chars       First+Last char
```

Note: JA4S_a has **7 characters** (no SNI indicator or cipher count), compared to JA4_a's 10.

### 7.2 JA4S_b (4 Hex Characters)

The server's selected cipher suite as a 4-character hex string:

```python
def compute_ja4s_b(fields: ServerHelloFields) -> str:
    return f"{fields.cipher_suite:04x}"
```

Note: JA4S_b is **not hashed** — it's the raw cipher value. This is because the server selects exactly one cipher, so there's nothing to sort or compress.

### 7.3 JA4S_c (12 Hex Characters)

Unlike JA4_c, the server's extensions are hashed **in wire order**, with nothing sorted or removed (ALPN and GREASE stay in), and there is no signature algorithms section. FoxIO's reference implementation says so explicitly ("preserving the original order of server's TLS extensions"). The server does not randomise its extension order, so the order identifies its TLS stack: OpenSSL sends `002b,0033` while BoringSSL-based servers (Google, Cloudflare) send `0033,002b`.

```python
def compute_ja4s_c_raw(fields: ServerHelloFields) -> str:
    # Wire order, nothing sorted or removed: the server's extension order is its fingerprint
    return ",".join(f"{e:04x}" for e in fields.extensions)
```

An earlier version sorted the extensions and dropped ALPN, as JA4_c does. That made the two stacks above indistinguishable and disagreed with FoxIO's published values on 31 of FoxIO's own test handshakes.

### 7.4 JA4S Version Resolution

JA4S uses `selected_version` from the `supported_versions` extension if available, otherwise falls back to `server_version`:

```python
ver = fields.supported_version if fields.supported_version and not is_grease(fields.supported_version) else fields.tls_version
```

---

## 8. Key Differences: JA3 vs JA4

| Aspect | JA3 | JA4 |
|--------|-----|-----|
| Hash algorithm | MD5 (32 hex chars) | Truncated SHA-256 (12 hex chars per section) |
| Cipher order | Wire order (preserved) | Sorted numerically |
| Extension order | Wire order (preserved) | Sorted numerically |
| Version source | Handshake body only | `supported_versions` extension preferred |
| ALPN | Not used | First+last character in prefix |
| SNI | Not used (except for display) | `d`/`i` indicator in prefix |
| Signature algorithms | Not used | Wire-order in JA4_c after `_` separator |
| Browser stability | Unstable (extension permutation, GREASE) | Stable (sorting neutralizes permutation) |
| Output format | 32-char hex (single hash) | 36-char structured string (prefix + 2 hashes) |
| Readability | Opaque hash | Prefix is human-readable (protocol, version, counts) |

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Implement both JA3 and JA4 to demonstrate the evolution of fingerprinting techniques |
| **Design Choice** | Implement both specifications independently, computing both for every handshake |
| **Reason** | JA3 has a larger community database (ja3er.com). JA4 is more stable against modern browsers. Using both maximizes identification coverage |
| **Alternative Considered** | Implement only JA4 (newer, better) or only JA3 (larger database) |
| **Trade-off** | Computing both adds CPU overhead per handshake, but since handshakes are infrequent relative to data packets, this overhead is negligible |

---

## 9. Complete Example: JA4 for curl

Given a curl ClientHello captured via the controlled local test:

```
Captured Fields:
  supported_versions: [0x0304, 0x0303]  → resolves to "13"
  server_name: "example.com"             → 'd' (domain)
  cipher_suites (after GREASE): 31 suites
  extensions (after GREASE): 12 extensions (SNI and ALPN included)
  first ALPN: "h2"                       → "h2"
  signature_algorithms: [0x0403, 0x0503, ...]
```

### Step-by-step:

1. **JA4_a:** `t13d3112h2`
   - `t` = TCP, `13` = TLS 1.3, `d` = SNI present, `31` = cipher count, `12` = ext count, `h2` = ALPN
2. **JA4_b:** Sort ciphers → hex → SHA-256[:12] → `e8f1e7e78f70`
3. **JA4_c:** Sort extensions (minus SNI, ALPN) → hex → append `_` + wire-order sigalgs → SHA-256[:12] → `b26ce05bbdd6`
4. **Final:** `t13d3112h2_e8f1e7e78f70_b26ce05bbdd6`

This matches the seed database entry for curl in `code/db/seed_fingerprints.json`.
