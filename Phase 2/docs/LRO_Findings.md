# Engineering Verification: Resilience Against Hardware LRO and Kernel GRO Network Offloads

## Executive Summary
This document records the architectural verification of the Phase 2 TLS Fingerprinting Engine (`tlsfp`) against Large Receive Offload (LRO) and Generic Receive Offload (GRO). 

Testing and architectural analysis confirm that the engine is **offload-invariant**: JA3 and JA4 fingerprints remain 100% deterministic regardless of whether incoming TCP streams arrive un-offloaded (standard 1514 B MTU segments), kernel-coalesced (GRO), or hardware-coalesced on the Network Interface Card (LRO).

---

## Technical Analysis: GRO vs. LRO at the User-Space Boundary

Both GRO (software offload in Linux NAPI) and LRO (hardware offload on physical NIC ASICs/drivers) merge multiple wire-level TCP segments into jumbo frames before passing them up the network stack.

| Metric / Mechanism | Un-offloaded Traffic | GRO (Generic Receive Offload) | LRO (Large Receive Offload) |
| :--- | :--- | :--- | :--- |
| **Execution Layer** | Wire / Driver | Linux Kernel NAPI (Software) | Physical NIC ASIC / Driver (Hardware) |
| **Max Frame Delivery** | 1,514 Bytes (Standard MTU) | Up to 65,535 Bytes (64 KB) | Up to 65,535 Bytes (64 KB) |
| **libpcap Abstraction** | Multiple `pcap` callbacks | Single `pcap` callback | Single `pcap` callback |
| **Header Presentation** | Individual IP/TCP headers | Reconstructed IP/TCP header | Reconstructed IP/TCP header |
| **`tlsfp` Engine Path** | **Tier 2 (Slow Path)** | **Tier 1 (Fast Path)** | **Tier 1 (Fast Path)** |

---

## Architectural Guarantees for LRO Compliance

### 1. Zero-Copy Tier 1 Ingestion
In `TwoTierAccumulator::process_segment()`, incoming TCP payloads are evaluated against the record length embedded in the TLS Record Header (`0x16`):

$$\text{payload\_len} \ge 5 + \text{record\_len}$$

When LRO merges TCP segments on the NIC, the entire ClientHello payload ($2\text{ KB} - 64\text{ KB}$) is delivered in a single `pcap` callback. The engine evaluates the Tier 1 fast-path condition as `true`, immediately processing the handshake zero-copy without allocating entries in the Tier 2 reassembly table.

### 2. Snaplen Buffer Boundary Verification
To prevent frame truncation when capturing under LRO/GRO offload states, `pcap_open_live()` and `pcap_open_offline()` are configured with a capture snapshot length of $65,535\text{ bytes}$:

```cpp
pcap_handle = pcap_open_live(interface.c_str(), 65535, 1, 1000, errbuf);