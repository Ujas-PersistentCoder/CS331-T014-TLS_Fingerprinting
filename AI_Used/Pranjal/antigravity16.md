Have we done any socket programming in this projecT?

Searched for "socket"

Yes, we have indeed done socket programming in this project, primarily for communicating with the database and handling network tasks. 

Here are the main areas where socket programming has been utilized:

### 1. Custom Redis Client (C++ Engine)
The most significant use of socket programming is in the C++ engine (`TLS-Fingerprinting/code/cpp/src/db.cpp`). Rather than using a heavy third-party library like `hiredis`, a **custom, minimal RESP (REdis Serialization Protocol) client** was implemented directly over POSIX TCP sockets. 

Key details of this implementation include:
- **POSIX Sockets:** Includes `<sys/socket.h>` and uses standard socket functions like `socket()`, `connect()`, `send()`, and `recv()`.
- **Functions:** Custom implementations such as `write_all` to send commands over the socket, and `read_byte` / `read_redis_value` to parse RESP responses.
- **Why:** This design choice was made to keep the C++ engine minimal, fast, and dependency-free while maximizing raw compute and protocol processing speeds.

*(You can see this documented in [`05_fingerprint_database.md`](file:///Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/report/docs/05_fingerprint_database.md) and implemented in [`db.cpp`](file:///Users/pranjal/Projects/CS 331 CN 2026/TLS-Fingerprinting/code/cpp/src/db.cpp)).*

### 2. Live Packet Capture Interface (Python Engine)
The project documentation notes that while `dpkt` is used for fast parsing of bulk `.pcap` files, the Python engine leverages `scapy`'s `L2socket` interface for native live packet capture on the network interface.

### 3. IP Formatting (Python Engine)
The standard Python `socket` module is imported across various JA3/JA3S script implementations (e.g., [`ja3.py`](file:///Users/pranjal/Projects/CS 331 CN 2026/ja3/python/ja3.py) and [`ja3s.py`](file:///Users/pranjal/Projects/CS 331 CN 2026/ja3/python/ja3s.py)). It is mainly used as a utility to parse and convert raw binary IP addresses into human-readable strings using `socket.inet_ntop(socket.AF_INET, value)` (and `AF_INET6` for IPv6).

If there's a specific aspect of the socket implementation you'd like to dive into or modify, let me know!

Viewed README.md:1-62

---

[README.md](file;file:///Users/pranjal/Projects/CS%20331%20CN%202026/TLS-Fingerprinting/README.md) the about section should have a overall summary of the project, not just about the C++ engine. Suggest an improved about section

Edited README.md

I've updated the "About the project" section in [`README.md`](file:///Users/pranjal/Projects/CS%20331%20CN%202026/TLS-Fingerprinting/README.md) to provide a comprehensive summary of the entire project suite.

The new section now covers:
- **Core Concept**: The general purpose of TLS fingerprinting, extracting plaintext ClientHello and ServerHello information to deterministically identify connecting applications without decrypting payloads.
- **Specifications Supported**: The implementation of JA3/JA3S and JA4/JA4S, including modern TLS behaviors like GREASE normalization.
- **Dual Architecture**: A clear distinction between the High-Performance C++ Engine (optimized for bulk parsing and benchmarking using `libpcap`) and the Python Engine/GUI (geared towards live capture and interactive visual analysis).
- **Shared Infrastructure**: The use of an in-memory Redis database linking both engines to a shared fingerprint catalog for identifying applications ranging from basic web browsers to specific scripts and malware.

Take a look and let me know if you need any further refinements!

Viewed README.md:1-55
Viewed README.md:7-60

---

"telemetry" we don't have much of telemetry

"Project Description:  Build a tool that passively captures TLS ClientHello and ServerHello messages and computes JA3/JA3S fingerprints (with JA4/JA4S as a stretch goal) to identify the client or server application/library generating the traffic. Curate a small reference database and demonstrate distinguishing real clients (browsers, curl, custom scripts) purely from their handshake fingerprint.  
Tools/Technologies: : libpcap/Scapy (or raw sockets) for capture; fingerprint computation implemented per the JA3/JA4 specifications, eBPF/XDP, Packet/Flow Generators like TRex, KV-stores (Redis, Valkey).
Expected Outcome: Demonstrate the working JA3/JA3S fingerprint extractor, validated against published reference JA3 hashes for known clients; A curated database correctly identifying at least 5 distinct clients/tools by fingerprint alone. Demonstrate distinguishing, e.g., curl vs. a browser vs. a custom TLS client on the wire.
Understanding on the fingerprinting's role in security monitoring (malware C2 detection, client identification) and its limitations, including fingerprint randomization in modern browsers as an evasion technique."

This is the actual project spec that was handed to us in the beginning. See what you can use from here

Edited README.md

I have updated the "About the project" section in [`README.md`](file:///Users/pranjal/Projects/CS%20331%20CN%202026/TLS-Fingerprinting/README.md) to closely mirror the original project specification and its educational goals.

The word "telemetry" has been removed, and the section now specifically mentions:
- The core objective: passively capturing ClientHello and ServerHello messages to compute JA3/JA3S and JA4/JA4S fingerprints.
- Use cases and security monitoring context (e.g., distinguishing real clients like browsers, curl, and custom scripts, or detecting malware C2).
- The inclusion of a reference database using a Redis Key-Value store.
- Acknowledgement of fingerprinting limitations and evasion techniques, such as randomization and GREASE.
- The use of `libpcap` and `scapy` across the C++ and Python engines. 

Let me know if there's anything else you'd like to adjust in the README!