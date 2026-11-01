# Findings Report: GRO Offload Impact on `tlsfp` Engine

## 1. Executive Summary
This report analyzes the behavior of the `tlsfp` engine when handling Generic Receive Offload (GRO) coalesced traffic versus un-offloaded (fragmented) TCP streams. 

Using Linux network namespaces (`server_ns`) and virtual Ethernet pairs (`veth`), two distinct packet captures (`gro_on.pcap` and `gro_off.pcap`) were evaluated in Wireshark and processed through `tlsfp_phase2`. The results confirm that `tlsfp` achieves **100% fingerprint determinism (JA3/JA4)** across both capture modes.

---

## 2. Wireshark Deep-Dive Observations

Wireshark analysis highlights the exact structural differences between software-aggregated (GRO ON) and wire-fragmented (GRO OFF) TLS `ClientHello` messages:

| Wireshark Metric / Field | `gro_on.pcap` (GRO Active) | `gro_off.pcap` (GRO Disabled) | Technical Explanation |
| :--- | :--- | :--- | :--- |
| **Top List `Info` Column** | Single `Client Hello` entry | Packet #4: `[TCP segment of a reassembled PDU]`<br>Packet #6: `Client Hello` | In `gro_off`, Wireshark must perform TCP PDU reassembly in user-space. In `gro_on`, the kernel hands Wireshark an already-reassembled packet. |
| **Frame Wire Length (`frame.len`)** | **1701 Bytes** ($>1514\text{ B}$ MTU) | **Packet #4:** 1514 Bytes<br>**Packet #6:** 253 Bytes | `gro_on` exceeds Ethernet MTU due to NAPI kernel polling aggregation. `gro_off` strictly bounds packets to MTU ($\le 1514\text{ B}$). |
| **TCP Payload Length (`tcp.len`)** | 1635 Bytes | **Packet #4:** 1448 Bytes (MSS)<br>**Packet #6:** 187 Bytes | The 1635-byte payload is delivered intact in `gro_on`, but split across MSS boundaries in `gro_off`. |
| **Sequence Number Delta ($\Delta\text{Seq}$)** | $\Delta\text{Seq} = 1635$ | **Packet #4:** $\Delta\text{Seq} = 1448$<br>**Packet #6:** $\Delta\text{Seq} = 187$ | Next expected sequence number (`tcp.nxtseq`) advances incrementally in `gro_off` versus a single large leap in `gro_on`. |
| **Packet Details Tree** | Standard TCP / TLS tree | Displays `[2 Reassembled TCP Segments (1635 bytes): #4(1448), #6(187)]` | Confirms manual frame-stitching by Wireshark's TCP dissector for `gro_off.pcap`. |

---

## 3. Engine Validation Results

| Test Parameter | `gro_on.pcap` | `gro_off.pcap` | Match Status |
| :--- | :--- | :--- | :--- |
| **JA3 Hash** | `284deaeae14ea5ddc96c5d7e59855422` | `284deaeae14ea5ddc96c5d7e59855422` | **100% Identical** |
| **JA4 Hash** | `t13d301200_1d37bd780c83_ecd0401ec68b` | `t13d301200_1d37bd780c83_ecd0401ec68b` | **100% Identical** |
| **Extracted Ciphers** | 30 | 30 | **100% Identical** |
| **Extracted Extensions** | 12 | 12 | **100% Identical** |

---

## 4. Architectural Verification

1. **`capture.cpp` (Jumbo Frame Ingestion):**
   * Successfully processes single incoming frames up to $1701\text{ bytes}$ without truncation or ring buffer overflow when GRO is enabled.
2. **`accumulator.cpp` (Stream Reassembly):**
   * Correctly holds partial TCP payloads (Segment 1: $1448\text{ B}$ payload) in flow tracking state until Segment 2 ($187\text{ B}$ payload) completes the TLS Record header length.
3. **`parser.cpp` & Hash Engines (`ja3.cpp`/`ja4.cpp`):**
   * Output deterministic fingerprint hashes regardless of whether the payload arrived in single or multi-segment form.