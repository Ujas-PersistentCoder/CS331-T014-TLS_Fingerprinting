# Fingerprint Database Architecture

**Document Scope:** Storage, retrieval, seeding, and enrollment of fingerprint records across both the Redis-backed primary store and the JSON fallback.

---

## 1. Overview

The fingerprint database maps hash strings to human-readable client/server identifiers. It supports four fingerprint kinds: `ja3`, `ja3s`, `ja4`, `ja4s`. The system uses a two-tier architecture:

1. **Primary:** Redis (in-memory key-value store) for fast lookup and shared state between C++ and Python engines
2. **Fallback:** JSON file (`fingerprints.json`) for offline usage when Redis is unavailable

Both implementations (Python `FingerprintDB`, C++ `FingerprintDatabase`) share the same Redis key schema, enabling cross-engine interoperability.

---

## 2. Data Model: `FingerprintRecord`

### Python (`db.py`)

```python
@dataclass(frozen=True)
class FingerprintRecord:
    kind: str          # "ja3", "ja3s", "ja4", "ja4s"
    hash: str          # The fingerprint hash value
    role: str = ""     # "client" or "server"
    name: str = ""     # Human-readable identifier (e.g., "Chrome", "curl")
    version: str = ""  # Version string (e.g., "8.9.1")
    os: str = ""       # Operating system (e.g., "linux")
    category: str = "" # Classification (e.g., "browser", "cli", "library")
    source: str = ""   # Provenance (e.g., "self-captured: chrome_headless.pcap")
    notes: str = ""    # Free-form annotation
```

### C++ (`db.hpp`)

```cpp
struct FingerprintRecord {
    FingerprintKind kind{FingerprintKind::JA3};
    std::string hash;
    std::string role;
    std::string name;
    std::string version;
    std::string os;
    std::string category;
    std::string source;
    std::string notes;
};
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Store rich metadata about each fingerprint beyond just a hash→name mapping |
| **Design Choice** | A flat record with 9 fields covering identity, provenance, and classification |
| **Reason** | Rich metadata enables graduated confidence in matches ("self-captured" vs "public-catalog"), supports the capture manifest enrichment pipeline, and provides context for analyst enrollment decisions |
| **Alternative Considered** | Simple hash→name map (legacy `fingerprints.json` approach), or a relational schema with normalized tables |
| **Trade-off** | A flat record duplicates some metadata across entries but avoids join complexity. Redis hash maps (HSET/HGETALL) map naturally to flat key-value records |

---

## 3. Redis Key Schema

Both implementations use the same key naming convention:

```
tlsfp:{kind}:{hash}
```

Examples:
```
tlsfp:ja3:ada70206e40642a3e4461f35503241d5
tlsfp:ja3s:15af977ce25de452b96affa2addb1036
tlsfp:ja4:t13d3110h2_e8f1e7e78f70_b26ce05bbdd6
tlsfp:ja4s:t130200_1302_a56c5b993250
```

Each key stores a Redis **hash** (HSET) with all `FingerprintRecord` fields.

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | A key schema that prevents collisions between different fingerprint kinds |
| **Design Choice** | Namespace-prefixed keys: `tlsfp:{kind}:{hash}` |
| **Reason** | Different fingerprint kinds (JA3 vs JA4) can have different hash formats (32-char hex vs structured string). Prefixing with kind ensures uniqueness and enables kind-specific queries |
| **Alternative Considered** | Single namespace with compound keys, or separate Redis databases per kind |
| **Trade-off** | Key prefix adds 8–10 bytes per key but enables all fingerprints to coexist in a single Redis database |

---

## 4. Lookup Flow

### Python: `FingerprintDB.lookup_record()` (`db.py` lines 114–140)

```
1. Check in-memory cache (dict[tuple[str, str], FingerprintRecord | None])
   └─ Hit → return cached record (or None for negative cache)

2. Query Redis: HGETALL tlsfp:{kind}:{hash}
   └─ Hit → construct FingerprintRecord, cache it, return
   └─ Miss → cache as None (negative cache), return None

3. Redis unavailable → set self._redis = None, fall through
```

### C++: `FingerprintDatabase::lookup()` (`db.cpp` lines 436–478)

```
1. Check in-memory cache (unordered_map<string, FingerprintRecord>)
   └─ Hit → return cached record

2. Check negative cache (unordered_set<string>)
   └─ Hit → return false (known miss)

3. Send Redis command: HGETALL tlsfp:{kind}:{hash}
   └─ Hit → parse fields, cache record, return true
   └─ Miss → add to negative cache, return false
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Fast fingerprint lookup at packet-processing speed |
| **Design Choice** | Three-tier lookup: in-memory cache → Redis → return miss |
| **Reason** | Redis network round-trip (~100μs on localhost) is acceptable for individual lookups but adds up at high packet rates. The in-memory cache eliminates repeat lookups for the same hash within a capture session |
| **Alternative Considered** | Preload the entire database into memory at startup, or use Redis pipelining for batch lookups |
| **Trade-off** | Caching introduces stale-data risk if the database is modified externally during a capture, but this is acceptable for a passive monitoring tool |

### Negative Caching (C++ Only)

The C++ implementation maintains a separate `missing_cache_` set for hashes that were queried in Redis and returned empty. This prevents repeated Redis queries for unknown fingerprints.

---

## 5. Database Seeding Pipeline

At startup, both implementations load fingerprint records from committed JSON files into Redis.

### Seed Files

| File | Contents | Format |
|------|----------|--------|
| `code/db/seed_fingerprints.json` | Curated JA3/JA3S/JA4/JA4S records from self-captured traffic | Grouped JSON: `{"ja3": [...], "ja3s": [...], "ja4": [...], "ja4s": [...]}` |
| `code/db/capture_manifest.json` | Metadata for captured client profiles (version, OS, category) | `{"label": {"role": "...", "name": "...", ...}}` |
| `code/python/fingerprints.json` | Legacy flat JA3 hash→name map (~160 entries from Salesforce CSV) | `{"hash": "name", ...}` |

### Loading Order

```
1. Load seed_fingerprints.json
   └─ For each record, enrich with capture_manifest.json metadata
   └─ Write to Redis via HSET (Python: pipeline batch, C++: individual commands)

2. Load fingerprints.json (legacy)
   └─ Only import records that DON'T already exist in Redis
   └─ Prevents legacy labels from overwriting curated records
```

### Manifest Enrichment

The `capture_manifest.json` file provides metadata that may be missing from the seed records. The enrichment logic matches records to manifest entries by their `source` field:

```python
# db.py — _enrich_from_manifest
source_name = record.source.removeprefix("self-captured: ")
# Match against manifest keys (e.g., "curl_test2" matches "curl_test2_20260831_053405.pcap")
metadata = next(
    (fields for label, fields in manifest.items()
     if source_name == label or source_name.startswith(f"{label}_")),
    {},
)
# Fill in missing fields (version, os, category, notes)
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Populate the database with known fingerprints on fresh deployments |
| **Design Choice** | JSON seed files committed to the repository, auto-loaded into Redis at startup |
| **Reason** | JSON files are version-controlled and portable. Auto-loading ensures a fresh `git clone` + Redis start produces a working database without manual import steps |
| **Alternative Considered** | Redis RDB/AOF snapshots committed to the repo, or SQL dump files |
| **Trade-off** | JSON parsing at startup adds ~100ms, but this is a one-time cost. The JSON format is human-readable and easily auditable |

### Python: Pipeline Batching

The Python implementation uses Redis pipelines for efficient bulk loading:

```python
pipeline = self._redis.pipeline(transaction=False)
for entry in entries:
    pipeline.hset(key, mapping=asdict(record))
pipeline.execute()   # Single network round-trip for all commands
```

---

## 6. Analyst Enrollment

Both implementations support interactive fingerprint labeling — an analyst verifies the source of an unknown fingerprint and assigns a name.

### Python: `FingerprintDB.enroll()` (`db.py` lines 160–177)

```python
def enroll(self, hash_str: str, kind: str, name: str, role: str | None = None) -> None:
    record = FingerprintRecord(
        kind=kind,
        hash=clean_hash,
        role=role or ("server" if kind.endswith("s") else "client"),
        name=clean_name,
    )
    self._data[clean_hash] = clean_name   # Update legacy JSON
    self.store_record(record)              # Write to Redis
    self.save()                            # Persist JSON to disk
```

### C++: Interactive Prompt (`capture.cpp` lines 38–47)

```cpp
std::cout << "[?] Unknown " << kind_name << " fingerprint " << hash
          << ". Enter verified client/server name (empty to skip): " << std::flush;
std::string name;
if (!std::getline(std::cin, name) || name.empty()) return "<unknown>";
ctx.database->enroll(kind, hash, name);
```

The C++ interactive enrollment is activated via the `-u` flag (`--prompt-unknown` equivalent).

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Allow analysts to label unknown fingerprints during or after analysis |
| **Design Choice** | `enroll()` persists to both Redis (for shared state) and JSON (for portability) |
| **Reason** | Redis provides immediate availability to both engines. JSON provides a portable fallback and version-controllable artifact |
| **Alternative Considered** | Redis-only storage, or a separate enrollment database |
| **Trade-off** | Dual-write adds complexity but ensures data survives Redis restarts (JSON) and is immediately available (Redis) |

---

## 7. External Catalog Import

`code/db/import_fingerprints.py` provides a CLI tool for importing external fingerprint catalogs from CSV or JSON files.

### Supported Formats

**CSV:**
```
kind,hash,name,role,version,os,category,source,notes
ja3,abc123...,curl,client,8.9.1,linux,cli,,
```

**JSON (grouped):**
```json
{"ja3": [{"hash": "abc123...", "client": "curl"}], "ja4": [...]}
```

### Key Behaviors

- **Deduplication:** Tracks `(kind, hash)` pairs to skip duplicates within the import file
- **Preservation:** Existing Redis records are preserved unless `--overwrite` is specified
- **Validation:** JA3/JA3S hashes must match the 32-char hex pattern; JA4/JA4S must match alphanumeric+underscore

---

## 8. C++ Raw RESP Protocol Client

The C++ engine implements the Redis RESP (REdis Serialization Protocol) directly over a TCP socket, avoiding any Redis client library dependency.

### Connection

```cpp
bool FingerprintDatabase::connect() {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    // ... getaddrinfo → socket → connect with timeout → select_database ...
}
```

### RESP Command Encoding

```cpp
bool FingerprintDatabase::send_command(const std::vector<std::string> &arguments, RedisValue &reply) {
    // RESP array format: *{count}\r\n${len}\r\n{arg}\r\n...
    std::string request = "*" + std::to_string(arguments.size()) + "\r\n";
    for (const std::string &argument : arguments) {
        request += "$" + std::to_string(argument.size()) + "\r\n" + argument + "\r\n";
    }
    write_all(socket_, request.data(), request.size());
    read_redis_value(socket_, reply);
}
```

### RESP Response Parsing

The `read_redis_value` function (lines 312–346) handles all RESP types:
- `+` Simple string
- `-` Error
- `:` Integer
- `$` Bulk string (with length prefix)
- `*` Array (recursive)

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Communicate with Redis from C++ without adding a library dependency |
| **Design Choice** | Implement a minimal RESP protocol client using POSIX sockets |
| **Reason** | The C++ engine only needs HSET, HGETALL, EXISTS, PING, and SELECT. A full Redis client library (hiredis, cpp_redis) would be a disproportionate dependency for 5 commands. The RESP protocol is simple enough (text-based with length prefixes) to implement directly |
| **Alternative Considered** | Using `hiredis` (C library), `cpp_redis` (C++ library), or `redis-plus-plus` |
| **Trade-off** | The custom client lacks features like connection pooling, reconnection logic, and TLS transport. For a local development tool, these are unnecessary |

---

## 9. JSON Fallback (Python)

When Redis is unavailable, the Python engine falls back to the legacy `fingerprints.json` file — a flat `{hash: name}` dictionary.

```python
def lookup(self, hash_str: str, kind: str | None = None) -> str | None:
    record = self.lookup_record(hash_str, kind)
    if record is not None:
        return record.name or None
    return self._data.get(hash_str)   # Fallback to flat JSON map
```

The JSON file is loaded at construction and written back on `save()`:

```python
def save(self) -> None:
    with self._path.open("w", encoding="utf-8") as database_file:
        json.dump(self._data, database_file, indent=4)
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Support fingerprint lookup when Redis is not installed or not running |
| **Design Choice** | Transparent fallback to a JSON file with the same lookup interface |
| **Reason** | Not all deployment environments have Redis. The JSON fallback ensures the tool is functional (with reduced features) out of the box |
| **Alternative Considered** | Require Redis as a hard dependency, or use SQLite as the fallback |
| **Trade-off** | The JSON fallback only stores `{hash: name}` pairs (no rich metadata), so matches from the fallback have less context. This is acceptable for basic identification |
