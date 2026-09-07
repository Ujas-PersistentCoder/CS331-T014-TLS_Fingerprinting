# Testing and Validation

**Document Scope:** Complete inventory and analysis of the test suites for both Python and C++ engines, validation methodology, and known-answer verification.

---

## 1. Test Suite Overview

| Engine | Framework | Test File(s) | Test Count |
|--------|-----------|-------------|------------|
| Python | pytest | `tests/test_parser.py` (9 tests) | 9 |
| Python | pytest | `tests/test_fingerprints.py` (6 tests) | 6 |
| Python | pytest | `tests/test_ja4.py` (11 tests) | 11 |
| Python | pytest | `tests/test_capture.py` (16 tests across 8 classes) | 16 |
| Python | pytest | `tests/test_integration.py` (2 tests) | 2 |
| C++ | GoogleTest 1.12.1 | `tests/test_fingerprints.cpp` (~55 tests) | ~55 |
| **Total** | | | **~99** |

---

## 2. Python Test Suite

### 2.1 Parser Tests — `test_parser.py`

Tests the byte-level TLS record and handshake parsing logic.

| Test | What It Verifies |
|------|-----------------|
| `test_parse_tls_record` | Correct extraction of content type, version, length from a 5-byte TLS record header |
| `test_parse_tls_record_truncated` | Returns `None` for truncated input (< 5 bytes) |
| `test_parse_handshake_header` | Correct extraction of message type and 3-byte length from a handshake header |
| `test_parse_minimal_client_hello` | Parses a minimal ClientHello (version, session ID, ciphers, compression) without extensions |
| `test_parse_client_hello_with_extensions` | Parses a ClientHello with SNI, Supported Groups, and EC Point Formats extensions |
| `test_parse_client_hello_with_grease` | Verifies that GREASE values (0x0A0A) in cipher suites are preserved in the parsed output (filtering happens later, at fingerprint computation time) |
| `test_parse_server_hello` | Parses a minimal ServerHello with version, selected cipher, and extensions |
| `test_parse_server_hello_with_alpn` | Parses a ServerHello containing an ALPN extension |
| `test_client_hello_alpn_grease_latin1_roundtrip` | Verifies that binary GREASE ALPN values survive Latin-1 decoding without corruption |

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Verify that the parser correctly extracts every field from raw byte sequences |
| **Design Choice** | Hand-crafted binary payloads with known field values |
| **Reason** | Using synthetic byte arrays (not real PCAPs) isolates the parser from the capture pipeline. Each test controls exactly which bytes are present, making failure diagnosis unambiguous |
| **Alternative Considered** | Parsing real PCAP files and comparing results to a reference implementation (e.g., Wireshark) |
| **Trade-off** | Synthetic payloads don't cover every real-world edge case, but they enable precise regression testing of specific byte-offset logic |

### 2.2 JA3/JA3S Fingerprint Tests — `test_fingerprints.py`

| Test | What It Verifies |
|------|-----------------|
| `test_filter_grease` | GREASE values are correctly removed from a mixed tuple |
| `test_ja3_known_fingerprint_1` | Salesforce official test vector 1: raw string and MD5 hash match specification |
| `test_ja3_known_fingerprint_empty_sections` | Empty extensions/curves/formats produce the correct comma-separated format with trailing commas |
| `test_ja3_with_grease_values` | GREASE cipher suites and extensions are excluded from the JA3 string |
| `test_ja3s_known_fingerprint` | JA3S computation for a known ServerHello |
| `test_ja3s_with_grease` | GREASE extensions are excluded from JA3S |

### 2.3 JA4/JA4S Tests — `test_ja4.py`

| Test | What It Verifies |
|------|-----------------|
| `test_is_literal_ip` | IPv4 and IPv6 address detection for SNI indicator |
| `test_resolve_ja4_version` | Version resolution from `supported_versions` extension (prefers 0x0304) |
| `test_resolve_alpn_chars` | ALPN first+last character extraction, including edge cases |
| `test_ja4_known_vector_controlled_curl` | Full JA4 computation against the controlled curl capture test vector |
| `test_ja4_cipher_grease_filter` | GREASE cipher suites excluded from JA4_b |
| `test_ja4_extension_grease_filter` | GREASE extensions excluded from JA4_c |
| `test_ja4_empty_extensions` | Correct output when no extensions are present |
| `test_ja4_ip_literal_sni` | SNI indicator is `'i'` for IP address literals |
| `test_ja4s_known_vector_controlled_curl` | Full JA4S computation against controlled curl ServerHello |
| `test_ja4s_alpn_in_output` | ALPN characters appear correctly in JA4S prefix |
| `test_ja4s_version_fallback` | Fallback to handshake body version when `supported_versions` is absent |

### 2.4 TCP Reassembly Tests — `test_capture.py`

Organized into 8 test classes covering the full `TCPReassembler` functionality.

#### `TestBasicParsing` (3 tests)

| Test | What It Verifies |
|------|-----------------|
| `test_single_packet_client_hello` | A complete ClientHello in a single TCP segment is correctly parsed |
| `test_single_packet_server_hello` | A complete ServerHello in a single segment is correctly parsed |
| `test_multiple_handshakes_in_one_record` | Multiple handshake messages in a single TLS record are all extracted |

#### `TestStreamBuffering` (1 test)

| Test | What It Verifies |
|------|-----------------|
| `test_tls_record_split_across_two_segments` | A TLS record split across two TCP segments is correctly reassembled and parsed |

#### `TestNonHandshakeSkip` (1 test)

| Test | What It Verifies |
|------|-----------------|
| `test_change_cipher_spec_before_handshake` | A ChangeCipherSpec (type 20) record is skipped, and the subsequent Handshake record is still parsed |

#### `TestOutOfOrder` (2 tests)

| Test | What It Verifies |
|------|-----------------|
| `test_two_segments_out_of_order` | Two TCP segments arriving in reverse order are correctly buffered and reassembled |
| `test_three_segments_reversed` | Three TCP segments arriving in fully reversed order are correctly reassembled |

#### `TestRetransmissionAndOverlap` (2 tests)

| Test | What It Verifies |
|------|-----------------|
| `test_pure_retransmission` | A fully retransmitted segment (same seq, same data) is silently dropped |
| `test_partial_overlap_trim` | A partially overlapping segment has its redundant leading bytes trimmed |

#### `TestFlowLifecycle` (3 tests)

| Test | What It Verifies |
|------|-----------------|
| `test_fin_cleans_up_flow` | A TCP FIN flag causes the flow to be cleaned up after processing |
| `test_rst_cleans_up_flow` | A TCP RST flag causes immediate flow cleanup |
| `test_syn_initializes_expected_seq` | A SYN flag correctly initializes the expected sequence number to `seq + 1` |

#### `TestTimeoutEviction` (1 test)

| Test | What It Verifies |
|------|-----------------|
| `test_stale_flow_evicted` | A flow inactive for > 30 seconds is evicted during the cleanup sweep |

#### `TestOOOCap` (1 test)

| Test | What It Verifies |
|------|-----------------|
| `test_ooo_segment_cap` | Exceeding `MAX_OOO_SEGMENTS` (10) causes the oldest buffered segment to be evicted |

#### `TestCrossRecordHandshake` (1 test)

| Test | What It Verifies |
|------|-----------------|
| `test_handshake_spanning_two_tls_records` | A handshake message split across two TLS records (using `pending_handshake`) is correctly reassembled |

#### `TestStatsSummary` (2 tests)

| Test | What It Verifies |
|------|-----------------|
| `test_stats_after_mixed_scenario` | Correct statistics counting after a mix of normal, retransmitted, and OOO segments |
| `test_summary_string` | The `CaptureStats.summary()` method produces a correctly formatted string |

### 2.5 Integration Tests — `test_integration.py`

| Test | What It Verifies |
|------|-----------------|
| `test_integration_sigalg_grease` | End-to-end: construct bytes with GREASE in signature algorithms → parse → JA4 → verify GREASE is excluded from the JA4_c hash |
| `test_integration_tls_non_ascii_alpn` | End-to-end: binary (non-ASCII) ALPN protocol → parse → JA4 → verify ALPN characters default to `'0'` |

---

## 3. C++ Test Suite — `test_fingerprints.cpp`

### 3.1 Test Fixtures

| Fixture | Purpose |
|---------|---------|
| `FlowTrackingTest` | Tests `FlowKey` equality, hash consistency, and flow cleanup |
| `LinkLayerDemuxTest` | Tests `packet_callback` with synthetic packets for each DLT type |

### 3.2 Flow Tracking Tests (8 tests)

| Test | What It Verifies |
|------|-----------------|
| `IPv4Equality` | Same IPv4 5-tuple → equal, different port → not equal, different IP → not equal |
| `IPv4DifferentDestinationPort` | Different destination ports produce different keys |
| `IPv6Equality` | Same IPv6 5-tuple → equal, different IP → not equal |
| `VersionMismatchRejection` | IPv4 key ≠ IPv6 key even with same raw bytes |
| `HashDeterminism` | Identical keys always produce identical hashes |
| `EqualKeysHaveEqualHashes` | Verifies the hash function contract: equal keys → equal hashes |
| `HashDistinguishesReverseFlows` | Forward flow `A→B` hashes differently from reverse flow `B→A` |
| `StaleFlowCleanupStrictBoundaries` | Flows at exactly 30s survive; flows at 31s are evicted |

### 3.3 Link-Layer Demux Tests (18 tests)

| Test | What It Verifies |
|------|-----------------|
| `HandlesDltRaw` | DLT_RAW: packet starts directly with IP header |
| `HandlesDltNullLoopback` | DLT_NULL: 4-byte family header + IP |
| `HandlesLinuxSLL` | DLT_LINUX_SLL: 16-byte SLL header |
| `HandlesLinuxSLL2` | DLT_LINUX_SLL2: 20-byte SLL2 header |
| `HandlesEthernet` | DLT_EN10MB: 14-byte Ethernet header |
| `RejectsUnknownDlt` | Unknown DLT type → packet silently dropped |
| `RejectsTruncatedRawPacket` | 1-byte packet → rejected |
| `RejectsNonIPv4Version` | IP version 6 in IPv4 position → rejected |
| `RejectsUDP` | Protocol 17 (UDP) → rejected |
| `RejectsTruncatedTCPHeader` | Packet truncated before TCP header end → rejected |
| `RejectsInvalidTCPDataOffset` | TCP data offset < 5 words → rejected |
| `IgnoresEmptyTCPPayload` | Zero-length TCP payload → no flow created |
| `RejectsNonTLSPayload` | HTTP GET request → rejected |
| `RejectsInvalidTLSRecordType` | Alert (0x15) → rejected |
| `RejectsInvalidTLSMajorVersion` | TLS major version 0x02 → rejected |
| `RejectsTLSVersionAbove0304` | TLS version 0x0305 → rejected |
| `RejectsOversizedTLSRecord` | Record length > 16K → rejected |
| `TLSRecordCanBeSplitAcrossTCPPackets` | Two-segment TLS record reassembly |

### 3.4 Stream Reassembly Tests (2 tests)

| Test | What It Verifies |
|------|-----------------|
| `OutOfOrderPacketDropsFlow` | Gap in sequence numbers → flow dropped |
| `EntireRetransmissionIsIgnored` | Same seq + same data → buffer length unchanged |

### 3.5 VLAN Tests (2 tests)

| Test | What It Verifies |
|------|-----------------|
| `HandlesSingleVLAN` | Single 802.1Q VLAN tag (0x8100) is correctly peeled |
| `HandlesDoubleVLAN` | QinQ double VLAN (0x88A8 + 0x8100) is correctly peeled |

### 3.6 MD5 Tests (5 tests)

| Test | What It Verifies | Reference |
|------|-----------------|-----------|
| `EmptyString` | MD5("") = `d41d8cd98f00b204e9800998ecf8427e` | RFC 1321 |
| `ABC` | MD5("abc") = `900150983cd24fb0d6963f7d28e17f72` | RFC 1321 |
| `Deterministic` | Same input → same hash (multiple calls) | — |
| `DifferentInputsProduceDifferentHashes` | MD5("abc") ≠ MD5("abd") | — |
| `Produces32LowercaseHexCharacters` | Output is exactly 32 chars, all lowercase hex | — |

### 3.7 JA3 Tests (16 tests)

| Test | What It Verifies |
|------|-----------------|
| `SalesforceOfficialVector1` | Official Salesforce test vector: raw string + MD5 hash |
| `SalesforceOfficialVector2` | Second official vector: empty extensions |
| `EmptyFieldsArePreserved` | Trailing commas for empty extension/curve/format fields |
| `ExtensionOnly` | Only extensions present → correct comma positions |
| `SupportedGroupsOnly` | Only curves present → correct comma positions |
| `PointFormatsOnly` | Only EC point formats present → correct comma positions |
| `CipherOrderIsPreserved` | Wire order of cipher suites is maintained |
| `ExtensionOrderIsPreserved` | Wire order of extensions is maintained |
| `ChangingOrderChangesFingerprint` | Different ordering → different JA3 hash |
| `GreaseCipherIsIgnored` | GREASE values in ciphers are filtered out |
| `GreaseExtensionIsIgnored` | GREASE values in extensions are filtered out |
| `GreaseSupportedGroupIsIgnored` | GREASE values in supported groups are filtered out |
| `GreasePointFormatIsIgnored` | GREASE values in EC point formats are filtered out |

### 3.8 JA3S Tests (3 tests)

| Test | What It Verifies |
|------|-----------------|
| `BasicServerHello` | Correct JA3S string and hash for a basic ServerHello |
| `EmptyExtensions` | Trailing comma for empty extensions field |
| `ExtensionOrderingPreserved` | Server extension order is maintained |

---

## 4. Validation Methodology

### 4.1 Known-Answer Testing (KAT)

Both implementations validate against known-good test vectors from:

| Source | Type | Used In |
|--------|------|---------|
| Salesforce official specification | JA3 raw string + MD5 hash | C++ `SalesforceOfficialVector1`, `SalesforceOfficialVector2`; Python `test_ja3_known_fingerprint_1`, `test_ja3_known_fingerprint_empty_sections` |
| RFC 1321 | MD5 digest values | C++ `MD5Test` suite |
| Self-captured PCAPs | JA3/JA3S/JA4/JA4S hashes from controlled captures | Python `test_ja4_known_vector_controlled_curl`, `test_ja4s_known_vector_controlled_curl` |

### 4.2 Cross-Implementation Validation

The same controlled PCAP files (`code/pcaps/controlled_curl.pcap`) are processed by both engines, and the output fingerprints are compared. The seed database (`seed_fingerprints.json`) records both Python and C++ computed JA4 hashes where they differ (see the `controlled_curl.pcap` note: "C++ representation is `t13d3110h2_...`; Python representation is `t13d3112h2_...`").

### 4.3 Community Validation

JA3 hashes are cross-referenced against the `ja3er.com` community database, which contains millions of JA3 fingerprints submitted by the community. The `expected_hashes.csv` file records specific hashes validated against this database:

```csv
Hash,Client
7a73fb0bdeaa2a79fadf356c34e7577e,curl (Modern)
ecdf4f49dd59effc439639da29186671,VS Code Update Client
9d5822a704bea7a186e3849e40441698,Brave Browser
```

### 4.4 PCAP Test Collection

The `code/pcaps/` directory contains PCAPs captured from controlled sources:

| PCAP | Client | Purpose |
|------|--------|---------|
| `controlled_curl.pcap` | curl → OpenSSL s_server (loopback) | Primary validation: known client + known server |
| `curl_test2_*.pcap` | curl (legacy) | Backward compatibility |
| `curl_tls13_only_*.pcap` | curl `--tlsv1.3` | TLS 1.3-only mode |
| `chrome_headless_*.pcap` | Chrome (headless) | Browser fingerprint |
| `firefox_headless_*.pcap` | Firefox (headless) | Browser fingerprint |
| `python_requests_*.pcap` | Python requests/urllib3 | Library fingerprint |
| `python_raw_ssl_*.pcap` | Python ssl module | Library fingerprint |

---

## 5. Running the Tests

### Python

```bash
cd code/python
.venv/bin/python -m pytest tests/ -v
```

### C++

```bash
cd code/cpp
cmake -B build -DBUILD_TESTING=ON
cmake --build build
cd build && ctest --output-on-failure
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Comprehensive test coverage across both implementations |
| **Design Choice** | pytest for Python (function-based), GoogleTest for C++ (class-based fixtures) |
| **Reason** | pytest is the de facto Python testing standard with minimal boilerplate. GoogleTest integrates with CMake via `FetchContent` and provides structured test fixtures for shared setup (e.g., `LinkLayerDemuxTest` builds synthetic packets) |
| **Alternative Considered** | Catch2 (C++), unittest (Python), or property-based testing (Hypothesis) |
| **Trade-off** | GoogleTest requires a network fetch at build time (mitigated by CMake cache). pytest requires a virtual environment but is zero-configuration |
