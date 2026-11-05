CS 331 Computer Networks
# Team T014 - Project 11: TLS Fingerprinting
# Team Members:
* Ujas Devang Shah 24110376
* Satyakam Mishra 24110318
* Pranjal Goyal 24110274
* Harshal Kundanlal Rana 24110131
* Divyansh Sharma 24110113
* D A S K R Manognya 24110097

## About the project
This project implements passive TLS fingerprinting using the JA3/JA3S (Salesforce) 
and JA4/JA4S (FoxIO) specifications. It captures TLS ClientHello and ServerHello 
handshake messages — either offline from PCAP files or live from a network 
interface — and computes deterministic fingerprints from handshake metadata 
(cipher suites, extensions, elliptic curves, ALPN, etc.) without needing to 
decrypt any traffic.

The system ships two independent, parallel implementations:

- **Python engine** (primary submission) — built with `dpkt` for offline pcap 
  parsing and `scapy` for live capture, with manual `struct.unpack`-based TLS 
  field extraction. Includes a PyQt6 GUI for interactive analysis and labeling.
- **C++ engine** (stretch/performance track) — built with `libpcap` and 
  zero-copy parsing via OpenSSL EVP hashing, achieving significantly higher 
  throughput on large captures. POSIX-only due to `libpcap`.

Both engines validate against the same curated reference database 
(`Phase 1/code/db/`), backed by Redis with a JSON fallback, and are cross-checked
against official JA3 test vectors and each other's output on shared PCAPs.

The tool demonstrates distinguishing real-world TLS clients — curl, browsers 
(Chrome, Firefox), Python `requests`, OpenSSL `s_client`, and custom TLS 
clients — purely from their on-the-wire handshake fingerprint, and documents 
the security applications (e.g. C2 detection) and known limitations (GREASE, 
browser extension randomization, spoofability) of this technique.

## Build and run from the repository root

Set `PYTHON` to an existing virtual environment as described in the [root README](../README.md). All paths below are relative to the Git repository root, including when reading this Phase 1 README.

C++ needs a C++17 compiler, CMake, libpcap and OpenSSL development files. GoogleTest is fetched for tests. The Phase 1 C++ catalog requires a local Redis service; Phase 2 separately supports in-memory catalog lookup.

```sh
cmake -S 'Phase 1/code/cpp' -B build/phase1 -DCMAKE_BUILD_TYPE=Release
cmake --build build/phase1 -j 4
ctest --test-dir build/phase1 --output-on-failure
build/phase1/tlsfp_engine -r 'Phase 1/code/pcaps/test_ja3.pcap'
build/phase1/tlsfp_engine -r 'Phase 1/code/pcaps/test_ja3.pcap' -u
```

`-u` enables interactive labeling. Live capture uses `-i INTERFACE` and requires capture permission. Shared catalogs are in `Phase 1/code/db/` and `Phase 1/code/python/fingerprints.json`. CMake records their source location so a build can load them independently of its working directory. Rebuild after moving the source checkout.

## Python CLI, GUI and tests

```sh
"$PYTHON" 'Phase 1/code/python/main.py' pcap 'Phase 1/code/pcaps/test_ja3.pcap'
"$PYTHON" 'Phase 1/code/gui/main.py'
"$PYTHON" -m pytest 'Phase 1/code/python/tests' -q
```

The GUI needs PyQt6; Scapy and dpkt handle packet inputs. See `Phase 1/code/python/requirements.txt` for dependencies. The CLI's default JSON catalog is anchored beside its source, and GUI paths are also file-relative. Select a capture from `Phase 1/code/pcaps/`. Confirm a client independently before labeling an unknown fingerprint.

## Catalog utilities

Redis is on `127.0.0.1:6379` by default. The C++ loader seeds the tracked catalog when Redis is available. Import only approved external datasets with known provenance:

```sh
"$PYTHON" 'Phase 1/code/db/import_fingerprints.py' path/to/approved_catalog.csv
"$PYTHON" 'Phase 1/code/db/seed_reference_db.py'
```

The legacy seed utility reads tracked local reference hashes. An optional external Salesforce-format CSV can be supplied explicitly with `--ja3-csv /absolute/path/to/file.csv`; no sibling `ja3` checkout is assumed. Do not overwrite an existing catalog with unverified labels.

## Legacy benchmarks

Build `build/phase1/tlsfp_engine` first, then run:

```sh
"$PYTHON" 'Phase 1/code/benchmarks/benchmark_cpp.py'
"$PYTHON" 'Phase 1/code/benchmarks/benchmark_python.py'
"$PYTHON" 'Phase 1/code/benchmarks/benchmark_compare.py'
```

New CSVs and plots go to ignored `build/benchmarks/phase1/`. The original files under `Phase 1/code/benchmarks/results/` remain historical evidence. Check packet and hello counts before treating a comparison as equal work; differing counts invalidate broad speedup claims.

## AI Usage Disclosure

Portions of this project (code scaffolding, debugging assistance, documentation 
drafting, and test case generation) were developed with the assistance of AI 
tools (Claude, Gemini, Copilot). All AI-assisted code was reviewed, tested, and validated against 
known-answer test vectors (Salesforce JA3 reference values, FoxIO JA4 test 
vectors) by the team before inclusion. The core protocol understanding, 
architectural decisions, and validation methodology are the team's own work.
