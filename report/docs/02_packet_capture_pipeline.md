# Packet Capture and TCP Reassembly Pipeline

**Document Scope:** Layer 2–4 processing from raw frames to reassembled TCP byte streams, covering both Python and C++ implementations.

---

## 1. Packet Capture Sources

Both implementations support two input modes: **offline** (PCAP/PCAPNG file) and **live** (network interface sniffing).

### 1.1 Offline Capture

| Aspect | Python | C++ |
|--------|--------|-----|
| **Library** | `dpkt` (`dpkt.pcap.Reader` / `dpkt.pcapng.Reader`) | `libpcap` (`pcap_open_offline`) |
| **Format Detection** | Reads 4-byte magic number: `0x0a0d0d0a` → pcapng, else pcap (`capture.py` lines 429–432) | Handled internally by libpcap |
| **Entry Point** | `read_pcap(filepath, stats)` → yields `TLSHandshakeResult` | `start_capture(opts)` → calls `pcap_loop` |
| **Pattern** | Python generator (lazy iteration via `yield`) | C callback function (`packet_callback`) |

### 1.2 Live Capture

| Aspect | Python | C++ |
|--------|--------|-----|
| **Library** | `scapy` (`conf.L2socket` for CLI, `AsyncSniffer` for GUI) | `libpcap` (`pcap_open_live`) |
| **BPF Filter** | `"tcp"` (hardcoded in CLI), configurable in GUI | Configurable via `-f` flag, default `"tcp"` |
| **Privileges** | Requires root (`sudo`) | Requires root or `CAP_NET_RAW` |
| **Termination** | `KeyboardInterrupt` / `EOFError` | POSIX `sigaction` for SIGINT/SIGTERM → `pcap_breakloop` |

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Read packets from both files and live interfaces |
| **Design Choice** | Python uses `dpkt` for offline (lightweight, pure-Python pcap parsing) and `scapy` for live (rich packet dissection); C++ uses `libpcap` for both |
| **Reason** | `dpkt` is faster than `scapy` for bulk file parsing because it avoids scapy's per-packet object construction overhead. For live capture, `scapy`'s `L2socket` provides a convenient Python-native interface. `libpcap` is the de facto standard C library for packet capture |
| **Alternative Considered** | Using `scapy` for everything (Python), using `PF_RING` or `AF_PACKET` directly (C++) |
| **Trade-off** | Two different libraries in Python increases dependency surface but optimizes each use case. C++'s single `libpcap` dependency is simpler but relies on the OS-provided pcap version |

---

## 2. Link-Layer Demultiplexing

The first byte of a captured frame depends on the **data link type** of the capture source. The system must strip the link-layer header to find the IP header.

### Supported Link Types

| DLT Constant | Header Size | EtherType Location | Used When |
|--------------|-------------|---------------------|-----------|
| `DLT_EN10MB` (Ethernet) | 14 bytes | Bytes 12–13 | Standard wired/wireless captures |
| `DLT_LINUX_SLL` | 16 bytes | Bytes 14–15 | Linux `any` interface |
| `DLT_LINUX_SLL2` | 20 bytes | Bytes 0–1 | Newer Linux cooked capture format |
| `DLT_NULL` (Loopback) | 4 bytes | 4-byte family code (2=IPv4) | macOS loopback, BSD |
| `DLT_RAW` | 0 bytes | IP version from byte 0 bits 4–7 | Raw IP captures |

### VLAN Peeling (C++ Only)

The C++ implementation handles 802.1Q VLAN tags by iterating through stacked VLAN headers:

```cpp
// capture.cpp lines 158–163
while ((ethertype == 0x8100 || ethertype == 0x88A8) && 
       pkthdr->caplen >= link_header_len + 4) {
    ethertype = (packet[link_header_len + 2] << 8) | packet[link_header_len + 3];
    link_header_len += 4;  // Each VLAN tag is 4 bytes
}
```

This peels both single-tagged (0x8100) and QinQ double-tagged (0x88A8 outer + 0x8100 inner) frames.

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Support diverse capture environments (Ethernet, loopback, containerized Linux, raw) |
| **Design Choice** | Explicit switch/case on data link type with hardcoded header offsets |
| **Reason** | Each link type has a fixed, well-defined header structure. A lookup table or switch is simpler and more performant than dynamic discovery |
| **Alternative Considered** | Using libpcap's `pcap_datalink_val_to_name()` with offset tables, or letting dpkt/scapy handle demux automatically |
| **Trade-off** | Manual demux code must be updated if new link types are needed, but it avoids relying on library internals and ensures every header byte is explicitly accounted for |

---

## 3. IP Demultiplexing

After stripping the link-layer header, the system identifies the IP version and extracts the transport layer.

### IPv4

```
EtherType 0x0800:
  Byte 0:     Version (4 bits) + IHL (4 bits)
  Byte 9:     Protocol (must be 6 = TCP)
  Bytes 12–15: Source IP
  Bytes 16–19: Destination IP
```

### IPv6

```
EtherType 0x86DD:
  Byte 0:     Version (4 bits, must be 6)
  Byte 6:     Next Header (must reach 6 = TCP, may need extension header peeling)
  Bytes 8–23:  Source IP (16 bytes)
  Bytes 24–39: Destination IP (16 bytes)
```

### IPv6 Extension Header Peeling (C++ Only)

The C++ implementation handles Hop-by-Hop (0) and Routing (43) extension headers:

```cpp
// capture.cpp lines 228–232
while ((next_proto == 0 || next_proto == 43) && pkthdr->caplen >= ext_offset + 8) {
    next_proto = packet[ext_offset];
    ext_offset += (packet[ext_offset + 1] + 1) * 8;
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Support both IPv4 and IPv6 traffic |
| **Design Choice** | Check EtherType for 0x0800 (IPv4) or 0x86DD (IPv6), then parse headers accordingly |
| **Reason** | Both IP versions are common in modern networks. IPv6 is particularly important for captures from dual-stack hosts |
| **Alternative Considered** | IPv4 only (simpler), or using `dpkt`/scapy's built-in IP layer detection |
| **Trade-off** | Supporting both versions adds code paths but ensures the tool works on modern networks |

---

## 4. TCP Reassembly

TLS handshake messages can span multiple TCP segments. The system must reassemble the byte stream in sequence order before parsing TLS records.

### 4.1 Python Implementation: `TCPReassembler`

**File:** `code/python/src/capture.py`, class `TCPReassembler` (lines 130–406)

This is a full-featured, sequence-aware TCP stream reassembler.

#### Data Structures

```python
@dataclass
class FlowState:
    expected_seq: int | None = None        # Next expected sequence number
    stream: bytearray = field(...)         # Reassembled in-order bytes
    ooo_segments: dict[int, bytes] = ...   # Out-of-order buffer: seq → payload
    lifecycle: str = "NEW"                 # NEW | SYN_SEEN | ESTABLISHED | CLOSED
    last_seen_ts: float = 0.0             # For timeout eviction
    pending_handshake: bytes = b''        # Partial handshake spanning TLS records
```

#### Flow Identification

Flows are keyed by the 4-tuple `(src_ip, src_port, dst_ip, dst_port)`:

```python
key = (src_ip, src_port, dst_ip, dst_port)   # capture.py line 158
```

#### Segment Insertion Logic

The `_insert_segment` method (lines 219–248) handles three cases:

| Condition | Action | Statistic |
|-----------|--------|-----------|
| `seq == expected_seq` | Append directly to stream, advance `expected_seq` | — |
| `seq < expected_seq` and `end <= expected_seq` | Pure retransmission — drop entirely | `retransmissions_dropped += 1` |
| `seq < expected_seq` and `end > expected_seq` | Partial overlap — trim leading bytes, append new tail | `overlaps_trimmed += 1` |
| `seq > expected_seq` | Out-of-order — buffer in `ooo_segments` | — |

#### Out-of-Order Buffering

```python
MAX_OOO_SEGMENTS = 10       # Max buffered segments per flow
MAX_OOO_BYTES    = 65536    # Max total OOO buffer size (64 KB)
```

When caps are exceeded, the oldest (lowest-sequence) buffered segment is evicted. After each in-order append, `_flush_ooo()` checks if any buffered segments are now contiguous and merges them.

#### Flow Lifecycle

```
SYN → SYN_SEEN → SYN-ACK → ESTABLISHED → FIN/RST → CLOSED → flow removed
         │                      │
         └── data arrives ──────┘   (missed SYN? Initialize on first data)
```

#### Cross-Record Handshake Reassembly

A TLS Handshake message can span multiple TLS Records. The `pending_handshake` buffer stores partial handshake bytes:

```python
# capture.py lines 352–354
if frag_offset + 4 > len(fragment):
    flow.pending_handshake = fragment[frag_offset:]
    break
```

On the next Handshake record, the pending bytes are prepended to the new fragment:

```python
# capture.py lines 344–346
if flow.pending_handshake:
    fragment = flow.pending_handshake + fragment
    flow.pending_handshake = b''
```

### 4.2 C++ Implementation: Inline `StreamBuffer`

**File:** `code/cpp/src/capture.cpp`, function `packet_callback` (lines 136–434)

The C++ approach is simpler: a fixed-size contiguous buffer per flow, with no explicit out-of-order buffering.

#### Data Structure

```cpp
struct StreamBuffer {
    static constexpr size_t MAX_BUF_SIZE = 4096;  // Fits post-quantum handshakes
    uint8_t bytes[MAX_BUF_SIZE];
    uint16_t len{0};
    uint32_t next_seq{0};
    bool seq_initialized{false};
    time_t last_seen{0};
};
```

#### Sequence Arithmetic

The C++ implementation uses **RFC 1982 modular sequence arithmetic** for safe unsigned distance calculation:

```cpp
// capture.cpp lines 304–317
uint32_t diff = seq - buf.next_seq;

if (diff > 0x80000000U) {
    // Modular negative: retransmission or overlap
    uint32_t overlap = buf.next_seq - seq;
    if (overlap >= payload_len) return;  // Full retransmission
    payload += overlap;
    payload_len -= overlap;
} else if (diff > 0) {
    // Modular positive: gap (out-of-order) → drop the flow
    ctx->active_flows.erase(key);
    return;
}
```

#### Key Difference: Gap Handling

| Scenario | Python | C++ |
|----------|--------|-----|
| Out-of-order segment | Buffer it, flush later | **Drop the entire flow** |
| Buffer overflow | Evict oldest buffered segment | **Drop the entire flow** |

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Reassemble TCP byte streams to parse TLS records that span multiple segments |
| **Design Choice** | Python: full OOO-capable reassembler. C++: inline contiguous-only reassembler that drops flows on gaps |
| **Reason** | Python's reassembler was designed for correctness and pedagogical completeness — it demonstrates every TCP reassembly concept. C++ was designed for speed; TLS handshakes rarely require OOO buffering because they occur at connection start when congestion is minimal |
| **Alternative Considered** | Using `libnids` or `libndpi` for TCP reassembly (C++), or `scapy.sessions.TCPSession` (Python) |
| **Trade-off** | Python handles edge cases (OOO, overlap, cross-record) that C++ drops. C++ is faster because it avoids heap allocation for buffered segments and processes each packet in a single callback invocation |

---

## 5. TLS Record Extraction from the Reassembled Stream

Once the TCP stream is reassembled, TLS records are extracted in a loop.

### Python: `_extract_tls` (capture.py lines 292–392)

```python
while len(flow.stream) >= 5:
    content_type = flow.stream[0]
    
    # Validate content type (20, 21, 22, 23)
    if content_type not in (20, 21, 22, 23):
        flow.stream.clear()  # Non-TLS data → clear to avoid infinite loop
        break
    
    record_len = struct.unpack('!H', flow.stream[3:5])[0]
    
    # Sanity check: TLS records can't exceed ~18 KB
    if record_len > MAX_TLS_RECORD_LEN:
        flow.stream.clear()
        break
    
    total_record_size = 5 + record_len
    if len(flow.stream) < total_record_size:
        break  # Incomplete record, wait for more data
    
    if content_type != 22:
        del flow.stream[:total_record_size]  # Skip non-handshake records
        continue
    
    # Extract handshake fragment and parse messages
    fragment = bytes(flow.stream[5:total_record_size])
    del flow.stream[:total_record_size]
```

### C++: Inline in `packet_callback` (capture.cpp lines 330–356)

The C++ code performs the same validation inline, with an additional check for TLS 1.3 middlebox compatibility ChangeCipherSpec records:

```cpp
// capture.cpp lines 273–284 — Strip TLS 1.3 middlebox CCS
if (payload_len >= 6 && 
    payload[0] == 0x14 && payload[1] == 0x03 && payload[2] == 0x03 &&
    payload[3] == 0x00 && payload[4] == 0x01) {
    payload += 6;
    payload_len -= 6;
    seq += 6;  // Advance sequence anchor
}
```

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Handle non-handshake TLS records in the stream without losing subsequent handshake data |
| **Design Choice** | Skip non-handshake records by consuming their bytes from the stream, then continue parsing |
| **Reason** | A TCP stream may contain ChangeCipherSpec (type 20) or Alert (type 21) records interspersed with or preceding Handshake records. Simply dropping the flow on a non-handshake record would miss valid handshakes |
| **Alternative Considered** | Only track flows where the first byte is 0x16 (Handshake) |
| **Trade-off** | The C++ implementation does use the first-byte filter for new flows (`if (payload[0] != 0x16) return`), which is simpler but may miss handshakes that are preceded by other record types on the same TCP connection |

---

## 6. Flow Eviction and Timeout

Both implementations evict inactive flows to prevent memory growth.

| Aspect | Python | C++ |
|--------|--------|-----|
| **Timeout** | `FLOW_TIMEOUT = 30.0` seconds | `TIMEOUT_SECONDS = 30` seconds |
| **Trigger** | Called at the start of every `process_packet()` invocation | Called every 2048 packets (`packet_counter & 0x7FF == 0`) |
| **Cleanup** | Iterate all flows, remove stale ones, count unresolved OOO segments | Iterate all flows, erase stale entries |
| **Statistics** | `flows_timed_out += 1`, `gaps_unresolved += len(ooo_segments)` | No explicit statistics |

### Requirement → Design Choice → Reason → Alternative → Trade-off

| Aspect | Detail |
|--------|--------|
| **Requirement** | Prevent unbounded memory growth from abandoned flows |
| **Design Choice** | 30-second inactivity timeout with periodic cleanup sweeps |
| **Reason** | TLS handshakes complete within milliseconds. A flow inactive for 30 seconds has either completed its handshake (which was already processed) or has been abandoned. 30 seconds is generous enough to handle slow networks |
| **Alternative Considered** | FIN/RST-only cleanup (no timeout), or LRU eviction |
| **Trade-off** | Timeout-based eviction may prematurely evict flows on extremely slow links, but it guarantees bounded memory usage |

---

## 7. Capture Statistics

The Python implementation tracks comprehensive statistics via the `CaptureStats` dataclass:

```python
@dataclass
class CaptureStats:
    packets_processed: int = 0
    tls_handshakes_found: int = 0
    flows_tracked: int = 0
    flows_completed: int = 0       # FIN or RST seen
    flows_timed_out: int = 0
    segments_reordered: int = 0
    retransmissions_dropped: int = 0
    overlaps_trimmed: int = 0
    gaps_unresolved: int = 0
    packets_skipped: int = 0       # Malformed packets
```

The C++ implementation tracks simpler metrics in the `CaptureContext`:

```cpp
size_t total_packets{0};
size_t client_hellos{0};
size_t server_hellos{0};
// Plus timing for benchmark mode
```

### Documented Limitations

Both implementations document their limitations explicitly in code comments:

- No TCP window scaling or congestion control
- No sequence number wraparound handling (2³² wrap) — Python only
- Reorder window is capped; persistent gaps beyond the cap are lost — Python only
- TCP Fast Open (SYN with payload) may lose the first data byte — Python only
- Out-of-order segments drop the flow entirely — C++ only
