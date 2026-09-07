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
TLSFP Engine is a high-performance passive network telemetry tool written in C++17 designed to inspect, reassemble, and fingerprint encrypted traffic without payload decryption. While modern traffic is encrypted under TLS 1.2 and TLS 1.3, the initial cryptographic negotiation in ClientHello and ServerHello packets remains observable in plaintext on the wire. By extracting cipher suites, extensions, elliptic curves, and ALPN parameters, the engine constructs deterministic behavioral signatures for connecting applications. It implements both Salesforce JA3/JA3S and next-generation FoxIO JA4/JA4S specifications, incorporating RFC 8701 GREASE normalization and lexical parameter sorting. The pipeline uses libpcap for zero-copy frame peeling alongside RFC 1982-compliant TCP stream reassembly to handle packet fragmentation and TLS 1.3 middlebox records seamlessly. Extracted hashes are matched against an in-memory Redis database to distinguish tools like cURL, Python requests, Google Chrome, and Mozilla Firefox purely from their handshake. The engine operates across both live interfaces and offline PCAPs, featuring dedicated quiet benchmark (-q) and verbose dissection (-v) modes for performance profiling and deep protocol analysis.

## Quick start

The project is developed and tested on Ubuntu 24.04 and Ubuntu under WSL. Redis runs locally on `127.0.0.1:6379`; the repository JSON files seed the Redis database when either implementation starts.

### Install system dependencies

```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libssl-dev redis-server python3-venv
sudo systemctl enable --now redis-server
```

### Redis database setup

Redis runs locally at `127.0.0.1:6379` using database `0`. The Redis data itself is runtime state and is not stored in GitHub. The fingerprint catalog is committed to the repository in these files:

- `code/db/seed_fingerprints.json`: curated JA3, JA3S, JA4, and JA4S records
- `code/python/fingerprints.json`: public and legacy JA3 records

No manual database import is required. When the C++ engine or Python application starts, it connects to Redis and automatically seeds the committed records. A fresh clone therefore gets the same catalog after Redis is installed and running.

Verify that Redis is available with:

```bash
redis-cli ping
```

Expected output:

```text
PONG
```

If Redis is not running, start it with:

```bash
sudo systemctl start redis-server
```

The application can use its JSON fallback when Redis is unavailable, but Redis is required for the shared JA3/JA3S/JA4/JA4S catalog, persistent analyst enrollments, and consistent behavior between the C++ engine and Python GUI.

### Build the C++ engine

Run these commands from the repository root:

```bash
cmake -S code/cpp -B build
cmake --build build --parallel
```

Analyze a bundled PCAP without root privileges:

```bash
./build/tlsfp_engine -r code/pcaps/test_ja3.pcap
```

Use `-a` to interactively label an unknown fingerprint after verifying its source:

```bash
./build/tlsfp_engine -r code/pcaps/test_ja3.pcap -a
```

Live capture requires root or suitable packet-capture capabilities:

```bash
sudo ./build/tlsfp_engine -i lo -f "tcp port 443"
```

### Run the Python GUI

Create the Python environment and install the dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r code/python/requirements.txt
python code/gui/main.py
```

Click **Load PCAP File** and select a file under `code/pcaps`. Select an unknown row and use **Label Selected Fingerprint** only after confirming the client that generated the traffic.

### Run Python tests

```bash
source .venv/bin/activate
python -m pytest code/python/tests -q
```

### Import an approved external catalog

External datasets must be reviewed for licensing and provenance before import. Use a CSV with `kind,hash,name,role,version,os,category,source,notes` columns, or grouped JSON using the same `ja3`, `ja3s`, `ja4`, and `ja4s` sections as `code/db/seed_fingerprints.json`.

```bash
source .venv/bin/activate
python code/db/import_fingerprints.py path/to/approved_catalog.csv
```

Existing curated records are preserved. Use `--overwrite` only when the external record has been verified to be more authoritative.
