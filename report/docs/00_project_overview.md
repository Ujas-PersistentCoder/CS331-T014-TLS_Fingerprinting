# Project 11: TLS Fingerprinting — Project Overview

**Course:** CS 331 Computer Networks  
**Team:** T014 (6 members)  
**Document Scope:** System-level architecture, objectives, and repository structure

---

## 1. Project Objective

Build a passive network telemetry tool that captures TLS `ClientHello` and `ServerHello` handshake messages from live network interfaces or offline PCAP files, extracts protocol metadata from the plaintext handshake, and computes deterministic behavioral fingerprints using the **JA3/JA3S** (Salesforce) and **JA4/JA4S** (FoxIO) specifications. Fingerprints are matched against a curated reference database to identify client applications (e.g., Chrome, Firefox, curl, Python `requests`) purely from their on-the-wire cryptographic negotiation parameters.

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Identify TLS client applications without decrypting traffic |
| **Design Choice** | Passive fingerprinting via ClientHello/ServerHello metadata extraction |
| **Reason** | The TLS handshake is transmitted in plaintext before encryption is established. Different TLS libraries advertise different combinations of cipher suites, extensions, elliptic curves, and point formats — forming a unique behavioral signature per implementation |
| **Alternative Considered** | Active probing (sending crafted handshakes to servers), deep packet inspection with decryption keys |
| **Trade-off** | Passive fingerprinting cannot see post-handshake data and is vulnerable to evasion via randomization (GREASE, extension permutation). However, it requires no cooperation from endpoints and imposes zero additional network load |

---

## 2. System Architecture

The system is implemented as a dual-track project: a **Python engine** for rapid prototyping, validation, and GUI, and a **C++ engine** for high-performance production analysis.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        PACKET SOURCE                                 │
│        ┌──────────────┐              ┌──────────────────┐            │
│        │ Live NIC      │              │ PCAP/PCAPNG File │            │
│        │ (en0, eth0)   │              │ (offline)        │            │
│        └──────┬────────┘              └────────┬─────────┘            │
│               │  BPF filter: "tcp"             │                     │
│               └──────────┬─────────────────────┘                     │
│                          ▼                                           │
│            ┌──────────────────────────┐                              │
│            │   LINK-LAYER DEMUX       │                              │
│            │  Ethernet / SLL / NULL   │                              │
│            │  / Raw / VLAN peeling    │                              │
│            └────────────┬─────────────┘                              │
│                         ▼                                            │
│            ┌──────────────────────────┐                              │
│            │  IP DEMUX (v4 / v6)      │                              │
│            │  Protocol = TCP (6)      │                              │
│            └────────────┬─────────────┘                              │
│                         ▼                                            │
│            ┌──────────────────────────┐                              │
│            │  TCP REASSEMBLY          │                              │
│            │  Sequence tracking,      │                              │
│            │  OOO buffering,          │                              │
│            │  Overlap trimming,       │                              │
│            │  Flow lifecycle          │                              │
│            └────────────┬─────────────┘                              │
│                         ▼                                            │
│            ┌──────────────────────────┐                              │
│            │  TLS RECORD PARSE        │                              │
│            │  Content Type (0x16 =    │                              │
│            │  Handshake), Version,    │                              │
│            │  Fragment Length          │                              │
│            └────────────┬─────────────┘                              │
│                         ▼                                            │
│            ┌──────────────────────────┐                              │
│            │  HANDSHAKE PARSE         │                              │
│            │  ClientHello (0x01)      │                              │
│            │  ServerHello (0x02)      │                              │
│            │  → Extract all TLV       │                              │
│            │    fields into structs   │                              │
│            └────────────┬─────────────┘                              │
│                         ▼                                            │
│       ┌─────────────────┴─────────────────┐                         │
│       ▼                                   ▼                         │
│  ┌──────────────┐                 ┌───────────────┐                 │
│  │ JA3 / JA3S   │                 │ JA4 / JA4S    │                 │
│  │ Engine       │                 │ Engine         │                 │
│  │ (MD5 hash)   │                 │ (SHA-256 hash) │                 │
│  └──────┬───────┘                 └───────┬───────┘                 │
│         └──────────────┬──────────────────┘                         │
│                        ▼                                            │
│           ┌──────────────────────────┐                              │
│           │  FINGERPRINT DATABASE    │                              │
│           │  Redis (primary) +       │                              │
│           │  JSON (fallback)         │                              │
│           │  → Lookup / Enroll       │                              │
│           └────────────┬─────────────┘                              │
│                        ▼                                            │
│           ┌──────────────────────────┐                              │
│           │  OUTPUT                  │                              │
│           │  CLI / GUI / Benchmark   │                              │
│           └──────────────────────────┘                              │
└──────────────────────────────────────────────────────────────────────┘
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Modular, layered processing pipeline from raw packets to fingerprint output |
| **Design Choice** | Strict layer separation: capture → parse → fingerprint → database → output |
| **Reason** | Each layer maps directly to an OSI/TCP-IP layer or a TLS protocol layer. This makes the system explainable at the packet-field level, which is the primary grading criterion for CS 331 |
| **Alternative Considered** | Monolithic processing (parse everything in one function), or using an existing library like `tshark`/`pyshark` |
| **Trade-off** | More code to maintain, but each module can be tested independently. Students can trace every byte from the wire through to the final hash |

---

## 3. Technology Stack

### 3.1 Python Track

| Component | Technology | File(s) |
|-----------|-----------|---------|
| Packet capture (offline) | `dpkt` | `code/python/src/capture.py` |
| Packet capture (live) | `scapy` | `code/python/src/capture.py` |
| TLS parsing | `struct.unpack` (stdlib) | `code/python/src/parser.py` |
| JA3/JA3S hashing | `hashlib.md5` (stdlib) | `code/python/src/ja3.py` |
| JA4/JA4S hashing | `hashlib.sha256` (stdlib) | `code/python/src/ja4.py` |
| Database (primary) | `redis-py` | `code/python/src/db.py` |
| Database (fallback) | JSON file | `code/python/src/db.py` |
| GUI | PyQt6 | `code/gui/` |
| Testing | pytest | `code/python/tests/` |

### 3.2 C++ Track

| Component | Technology | File(s) |
|-----------|-----------|---------|
| Packet capture | libpcap (`pcap_loop`) | `code/cpp/src/capture.cpp` |
| TLS parsing | Custom `ByteReader` | `code/cpp/src/parser.cpp` |
| JA3/JA3S hashing | OpenSSL EVP (MD5) | `code/cpp/src/ja3.cpp` |
| JA4/JA4S hashing | OpenSSL EVP (SHA-256) | `code/cpp/src/ja4.cpp` |
| Database | Raw RESP protocol over TCP socket | `code/cpp/src/db.cpp` |
| JSON parsing | Custom `JsonReader` | `code/cpp/src/db.cpp` |
| Build system | CMake 3.14+ / C++17 | `code/cpp/CMakeLists.txt` |
| Testing | GoogleTest 1.12.1 | `code/cpp/tests/test_fingerprints.cpp` |

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Implement in both Python and C++ |
| **Design Choice** | Python for prototyping, validation, and GUI; C++ for performance and systems-level demonstration |
| **Reason** | Python's `struct.unpack` allows rapid iteration on TLS parsing logic. C++ with libpcap and zero-copy parsing demonstrates systems programming competence and provides a benchmark baseline |
| **Alternative Considered** | Single-language implementation (Python only, or Go, or Rust) |
| **Trade-off** | Two codebases must be kept in sync. The C++ engine has no GUI but supports a dedicated quiet benchmark mode (`-q`) not available in Python |

---

## 4. Repository Layout

```
TLS-Fingerprinting/
├── README.md                          # Project overview and quick-start
├── report/                            # ← This documentation suite
├── code/
│   ├── python/                        # Python engine
│   │   ├── main.py                    # CLI entrypoint (pcap / live subcommands)
│   │   ├── conftest.py                # Pytest configuration
│   │   ├── requirements.txt           # Python dependencies
│   │   ├── fingerprints.json          # Legacy flat hash→name map (~160 entries)
│   │   ├── src/
│   │   │   ├── parser.py              # TLS record + handshake parser
│   │   │   ├── ja3.py                 # JA3/JA3S computation
│   │   │   ├── ja4.py                 # JA4/JA4S computation
│   │   │   ├── capture.py             # TCPReassembler + pcap reader + live capture
│   │   │   └── db.py                  # FingerprintDB (Redis + JSON)
│   │   └── tests/
│   │       ├── test_parser.py         # Byte-level parser tests
│   │       ├── test_fingerprints.py   # JA3/JA3S known-answer tests
│   │       ├── test_ja4.py            # JA4/JA4S tests
│   │       ├── test_capture.py        # TCP reassembly tests
│   │       └── test_integration.py    # End-to-end integration tests
│   ├── cpp/                           # C++ engine
│   │   ├── CMakeLists.txt             # Build configuration
│   │   ├── include/tlsfp/             # Public headers
│   │   │   ├── parser.hpp             # Data structures + parse declarations
│   │   │   ├── ja3.hpp                # JA3 fingerprint API
│   │   │   ├── ja4.hpp                # JA4 fingerprint API
│   │   │   ├── capture.hpp            # Capture context, FlowKey, StreamBuffer
│   │   │   └── db.hpp                 # FingerprintDatabase class
│   │   ├── src/                       # Implementation files
│   │   │   ├── parser.cpp             # TLS parser (ByteReader-based)
│   │   │   ├── ja3.cpp                # JA3/JA3S (OpenSSL EVP MD5)
│   │   │   ├── ja4.cpp                # JA4/JA4S (OpenSSL EVP SHA-256)
│   │   │   ├── capture.cpp            # libpcap callback + stream reassembly
│   │   │   ├── db.cpp                 # Redis RESP client + JSON reader
│   │   │   └── main.cpp               # CLI entrypoint (getopt)
│   │   └── tests/
│   │       └── test_fingerprints.cpp   # GoogleTest suite
│   ├── gui/                           # PyQt6 GUI application
│   │   ├── main.py                    # GUI entrypoint
│   │   ├── window.py                  # Main window (TlsMonitorGui)
│   │   └── workers.py                 # QThread workers for PCAP + live capture
│   ├── db/                            # Shared fingerprint database files
│   │   ├── seed_fingerprints.json     # Curated JA3/JA3S/JA4/JA4S catalog
│   │   ├── capture_manifest.json      # Metadata for captured client profiles
│   │   ├── seed_reference_db.py       # Legacy CSV-to-JSON seed script
│   │   └── import_fingerprints.py     # External catalog importer
│   ├── pcaps/                         # Test PCAP collection
│   └── reference/                     # Validation data
│       ├── expected_hashes.csv        # Known-good hash→client mappings
│       └── validation_notes.md        # Validation methodology notes
└── ppt/                               # Presentation materials
```

---

## 5. Fingerprint Specifications Implemented

| Specification | Author | Hash Algorithm | Client Fields | Server Fields | Status |
|---------------|--------|---------------|---------------|---------------|--------|
| JA3 | Salesforce | MD5 (32 hex chars) | Version, Ciphers, Extensions, Curves, Point Formats | — | ✅ Validated |
| JA3S | Salesforce | MD5 (32 hex chars) | — | Version, Selected Cipher, Extensions | ✅ Validated |
| JA4 | FoxIO | Truncated SHA-256 (12 hex chars per section) | Protocol, Version, SNI, Cipher count, Ext count, ALPN, Sorted ciphers, Sorted exts + SigAlgs | — | ✅ Implemented |
| JA4S | FoxIO | Truncated SHA-256 (12 hex chars per section) | — | Protocol, Version, Ext count, ALPN, Selected cipher, Sorted exts | ✅ Implemented |

---

## 6. Client Profiles in Reference Database

The seed fingerprint database (`code/db/seed_fingerprints.json`) contains entries for the following client categories:

| Category | Clients |
|----------|---------|
| **CLI tools** | curl (multiple versions/configs), OpenSSL s_client |
| **Browsers** | Chrome (headless), Firefox (headless), Brave |
| **Language libraries** | Python `requests`/`urllib3`, Python `ssl` module |
| **Servers** | OpenSSL s_server |
| **Evasion** | curl-impersonate (planned in manifest) |
| **Public catalog** | ~160 entries from Salesforce CSV via `fingerprints.json` |

The `capture_manifest.json` defines 20+ client/server profiles for systematic capture and cataloging.
