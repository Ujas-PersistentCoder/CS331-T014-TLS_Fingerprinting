# High-Speed TLS Fingerprinting Engine
**CS 331: Computer Networks | Spring 2026**  
**Team T014 — Project 11: TLS Fingerprinting**

---

## 👥 Team Members

| Name | Roll Number |
| :--- | :---: |
| **Ujas Devang Shah** | 24110376 |
| **Satyakam Mishra** | 24110318 |
| **Pranjal Goyal** | 24110274 |
| **Harshal Kundanlal Rana** | 24110131 |
| **Divyansh Sharma** | 24110113 |
| **D A S K R Manognya** | 24110097 |

---

## 📌 Executive Summary

Modern encrypted traffic analysis requires observing client identities, configurations, and anomalies **without decrypting user payload data**. This project implements a comprehensive, passive TLS fingerprinting suite capable of line-rate wire inspection on live interfaces and offline packet captures.

The repository spans two evolutionary milestones:
1. **Phase 1 (Foundational Fingerprinting)**: Dual Python and C++ implementations of Salesforce **JA3/JA3S** and FoxIO **JA4/JA4S**, an interactive PyQt6 graphical user interface, and an analysts' catalog backed by Redis with zero-config JSON fallback.
2. **Phase 2 (Modernized High-Speed Engine & Protocol Defense)**: A high-throughput, multi-threaded C++17 engine (**`tlsfp_phase2`**) scaling past 50,000–60,000 packets/second. It extends classical TLS inspection into evasive transport challenges:
   * **Two-Tier TCP Stream Reassembly**: Transparent handling of out-of-order packets, sequence rollover, and hardware offloads (Generic Receive Offload / Large Receive Offload up to 7KB jumbo frames).
   * **JA4T / JA4TS TCP Stack Fingerprinting**: Passive TCP SYN/SYN-ACK options profiling and network distance estimation.
   * **Cross-Layer OS Impersonation Detection**: Corroborating TCP stack signatures against claimed TLS application environments (e.g., catching malicious bots masquerading as Windows browsers from Linux network stacks).
   * **Encrypted Client Hello (ECH / RFC 8744)**: Outer ClientHello parsing, HPKE cryptographic parameter extraction, GREASE vs. real ECH discrimination, and stateful connection lifecycle tracking.
   * **Post-Quantum TLS (PQ-TLS)**: Wire-level inspection of quantum-safe key shares (Kyber-768 / ML-KEM-768 per RFC 10024), duplicate extension/key share validation, and offer-to-selection posture correlation.

---

## 📁 Repository Structure

The repository is cleanly partitioned into Phase 1 and Phase 2 modules, each containing dedicated source code, test suites, experimental testbeds, presentation decks, technical reports, and AI disclosures:

```text
CS331-T014-TLS_Fingerprinting/
├── Phase 1/
│   ├── AI_Used/                 # Transparent prompt transcripts and AI usage logs for Phase 1
│   ├── code/
│   │   ├── benchmarks/          # Benchmarking scripts comparing Python and C++ throughput
│   │   ├── cpp/                 # Phase 1 standalone C++ engine (libpcap + OpenSSL)
│   │   ├── db/                  # Curated catalog (seed_fingerprints.json) & import scripts
│   │   ├── gui/                 # Interactive PyQt6 graphical user interface
│   │   ├── pcaps/               # Bundled test captures for JA3/JA4 verification
│   │   └── python/              # Primary Phase 1 Python engine (dpkt / scapy)
│   ├── ppt/                     # Phase 1 presentation deck
│   ├── report/                  # Phase 1 technical submission report
│   └── README.md                # Phase 1 documentation & reproduction guide
│
├── Phase 2/
│   ├── AI_Used/                 # Phase 2 AI chat logs, prompt records, and transcripts
│   ├── code/
│   │   ├── engine/              # High-speed C++ engine source, CMake, and 188 unit tests
│   │   ├── experiments/         # BoringSSL ECH lab testbed, pilot runs, and verification
│   │   ├── pcaps/               # Real-world benchmark, GRO/LRO, ECH, and PQ-TLS PCAPs
│   │   └── testbed/             # Synthetic JA4T TCP cross-layer spoofing testbed
│   ├── ppt/                     # Final presentation slides (CN presentation.pptx)
│   ├── report/                  # Phase 2 technical report (.md and .docx) & research docs
│   └── README.md                # Phase 2 detailed architecture & reproduction guide
│
├── .gitignore                   # Workspace gitignore rules
├── .gitattributes               # Git attributes and LFS rules
└── README.md                    # Root overview and repository index (this file)
```

---

## ⚡ Quick Navigation & Reproduction Guides

To build, test, and run either phase of the project, follow their respective dedicated guides:

* 👉 **[Phase 2 Detailed Guide (High-Speed Engine, ECH, PQ-TLS, JA4T)](file:///Phase%202/README.md)**  
  *How to build `tlsfp_phase2`, run all 188 unit tests, evaluate bundled 500k-packet benchmarks, and inspect real-world Encrypted Client Hello and Post-Quantum TLS traffic.*

* 👉 **[Phase 1 Detailed Guide (Python Engine, PyQt6 GUI, Classical C++ Engine)](file:///Phase%201/README.md)**  
  *How to launch the PyQt6 analyst GUI, connect to Redis, and cross-benchmark Python vs. C++ throughput.*

---

## 🛠️ System Prerequisites

The project is natively developed and evaluated on **Ubuntu 24.04 LTS** (including **WSL 2**) and is compatible with modern POSIX systems (Linux / macOS).

### Install Core Packages (Ubuntu / Debian / WSL):
```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libssl-dev redis-server python3-venv python3-pip
sudo systemctl enable --now redis-server
```

### Install Core Packages (macOS):
```bash
brew update
brew install cmake libpcap openssl redis python
brew services start redis
```

---

## 🧪 Quick Test: Running the Phase 2 Engine

Build the Phase 2 engine directly from the repository root:

```bash
# 1. Configure and compile
cmake -S "Phase 2/code/engine" -B "Phase 2/code/engine/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "Phase 2/code/engine/build" --parallel

# 2. Run the 188-test regression suite
ctest --test-dir "Phase 2/code/engine/build" --output-on-failure

# 3. Analyze bundled Post-Quantum & ECH Chrome capture with full dissection:
"./Phase 2/code/engine/build/tlsfp_phase2" -r "Phase 2/code/pcaps/pq_ech_chrome.pcap" -v -p -t -e
```

---

## 📑 AI Usage Disclosure

In compliance with course policies, artificial intelligence assistants (Claude, Gemini, ChatGPT) were utilized for code scaffolding, documentation drafting, test case ideation, and debugging support. All generated code and design formulations were thoroughly reviewed, manually verified, and grounded against RFC specifications and authoritative test vectors (Salesforce JA3 reference captures, FoxIO JA4 specifications, and RFC 10024 Post-Quantum key exchange definitions). Detailed interaction logs and transcripts are preserved inside `Phase 1/AI_Used/` and `Phase 2/AI_Used/`.
