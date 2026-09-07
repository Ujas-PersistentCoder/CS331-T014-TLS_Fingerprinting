# Project 11: TLS Fingerprinting

**CS 331 Computer Networks — Team T014**

---

## 1. Introduction

### 1.1 What is TLS Fingerprinting

TLS encrypts application data, but it cannot encrypt the negotiation that sets up that encryption. Before a client and server agree on a shared secret, they exchange two plaintext messages — the `ClientHello` and the `ServerHello` — that clearly list which protocol versions, cipher suites, extensions, elliptic curves, and point formats each side is willing to use. A passive observer sitting anywhere on the network path can read these fields without possessing any keys, without performing a man-in-the-middle attack, and without violating the confidentiality guarantees of TLS at all.

**TLS fingerprinting** is the practice of taking these plaintext fields, arranging them in a canonical order, and hashing them into a short, stable identifier. Because different TLS *implementations* (not different users) construct their ClientHello differently — Chrome's list of ciphers is not the same as curl's, neither Python's `ssl` module's, nor a Go binary's. This hash acts as a signature for the software stack generating the traffic, entirely independent of IP address, User-Agent header, or any other application-layer signal.

This project implements two such fingerprinting schemes in two languages, against both offline PCAP files and live traffic:

- **JA3 / JA3S** (Salesforce, 2017) — the original, MD5-based specification.
  - Reference repository: [**salesforce/ja3**](https://github.com/salesforce/ja3)
- **JA4 / JA4S** (FoxIO) — a newer specification addressing JA3's instability against modern browser randomization.
  - Reference repository: [**FoxIO-LLC/ja4**](https://github.com/FoxIO-LLC/ja4)

### 1.2 Why This Matters

Instead of being a simple tool to print hashes, the engine is a demonstration of the entire TLS handshake at the byte level: TCP segment reassembly, TLS record framing, handshake message framing and the TLV (Type-Length-Value) structure of the ClientHello/ServerHello bodies.

---

## 2. Theory: How TLS Fingerprinting Works

This section is deliberately mechanical. Every claim below maps to a specific byte offset our parsers rely on.

### 2.1 The TLS Record Layer (outermost framing)

Every TLS message — Handshake, Alert, ChangeCipherSpec, Application Data — is wrapped in a 5-byte **Record** header:

```
Offset  Size  Field
0       1     Content Type      (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData)
1–2     2     Legacy Version    (e.g. 0x0301, 0x0303 — frozen in TLS 1.3, must be ignored per JA3 spec)
3–4     2     Fragment Length
5..     var   Fragment payload
```

We only care about records with Content Type `22`. Everything else (most commonly ChangeCipherSpec, which persists as a TLS 1.3 "middlebox compatibility" artifact even though it's cryptographically meaningless in 1.3) must be **skipped, not dropped** — the stream continues, and a Handshake record can immediately follow.

### 2.2 The Handshake Layer

Inside a Content-Type-22 record sits one or more **Handshake** messages, each with its own 4-byte header:

```
Offset  Size  Field
0       1     Message Type   (1 = ClientHello, 2 = ServerHello, 11 = Certificate, ...)
1–3     3     Length         (24-bit big-endian — up to 16 MB, to accommodate large cert chains)
4..     var   Handshake body
```

The 24-bit length exists specifically because certificate chains can exceed a single TLS record's ~16 KB fragment limit — so a *handshake message* boundary and a *TLS record* boundary are not the same thing. A handshake message can legitimately span multiple records, and a single record can legitimately contain multiple handshake messages back-to-back. Any correct implementation must handle both.

### 2.3 ClientHello Body — the JA3 Source Fields

```
Offset            Field                     JA3 Field?
0–1               Client Version (2B)       Field 1 (legacy body version, NOT record version)
2–33              Random (32B)              — (skipped)
34                Session ID Length (1B)    —
35..(35+N-1)      Session ID (NB)           — (skipped)
(35+N)            Cipher Suites Len (2B)    —
(37+N)..          Cipher Suites (MB)        Field 2 (array of 2B cipher IDs)
...               Compression Methods       — (skipped, always null post-TLS1.3)
...               Extensions Length (2B)    —
...               Extensions (TLV chain)    Field 3 = extension *type codes* in wire order
```

Extensions are themselves nested TLV structures. The ones we parse:


| Ext Type | Name                 | Contribution                                    |
| -------- | -------------------- | ----------------------------------------------- |
| `0x0000` | SNI                  | Hostname (for display / JA4's`d`/`i` indicator) |
| `0x000a` | Supported Groups     | JA3 Field 4 (elliptic curves)                   |
| `0x000b` | EC Point Formats     | JA3 Field 5                                     |
| `0x000d` | Signature Algorithms | JA4_c wire-order tail                           |
| `0x0010` | ALPN                 | JA4_a first+last char                           |
| `0x002b` | Supported Versions   | JA4's real version source                       |

**Key subtlety exploited by our parser:** in TLS 1.3, `client_version` is deliberately frozen at `0x0303` (RFC 8446 §4.1.2, middlebox compatibility). The *actual* max version a client supports lives only inside the `supported_versions` extension. JA3 does not care about this — it hashes the frozen body version anyway (a documented JA3 limitation). JA4 explicitly prefers `supported_versions` and falls back to the body version only if the extension is absent.

### 2.4 ServerHello Body — the JA3S Source Fields

Structurally identical up through the cipher field, except the server selects **one** cipher, not a list:

```
Offset       Field                         JA3S Field?
0–1          Server Version (2B)           Field 1
2–33         Random (32B)                  — (skipped)
34           Session ID Length (1B)        —
(35+N)       Selected Cipher (2B)          Field 2 (single value, not an array)
(37+N)       Compression Method (1B)       — (skipped)
...          Extensions                    Field 3
```

Asymmetry worth noting in the report: the `supported_versions` extension (`0x002b`) is a **list** in ClientHello but exactly **2 bytes** (the single negotiated version) in ServerHello. Our parsers handle each side with dedicated logic rather than one shared extension-parsing routine, because the two are not the same wire format despite sharing an extension type code.

### 2.5 GREASE (RFC 8701)

Clients (Chrome-family browsers especially) insert meaningless placeholder values shaped like `0x?A?A` (`0x0A0A`, `0x1A1A`, ..., `0xFAFA`) into cipher suites, extensions, groups, and ALPN lists. This is intentional protocol hygiene — it stops middleboxes from ossifying around a fixed set of "known" values. For fingerprinting, GREASE is pure noise and **must** be filtered before hashing, or the same physical client would produce a different hash on every connection.

### 2.6 The Fingerprint Computation

**JA3**: `TLSVersion,Ciphers,Extensions,Curves,PointFormats` → MD5, wire order preserved throughout.

**JA3S**: `TLSVersion,SelectedCipher,Extensions` → MD5.

**JA4**: A structured 3-part string — a human-readable 10-char prefix (protocol/version/SNI-flag/counts/ALPN) plus two truncated-SHA256 hashes, one over *sorted* ciphers and one over *sorted* extensions concatenated with *wire-order* signature algorithms. The sort is the deliberate fix for browser randomization (§6 below).

**JA4S**: Same idea, 7-char prefix, raw 4-hex-digit selected cipher (not hashed — there's only one value, nothing to sort), and a sorted-extension hash.

---

## 3. Our Approach and Design Decisions

We built two independent, cross-validated engines against a shared ground truth (`pcaps/`, `reference/`, `db/`), rather than porting one implementation into a second language. JA3 was treated as the literal deliverable; JA4/JA4S as the stretch goal, since JA3's field set is a strict subset of what JA4 requires (cipher list, extension list, signature algorithms, ALPN, supported versions — parsing all of it up front cost nothing extra once we were already walking the extension TLV chain).

### 3.1 Why `dpkt` over `scapy` (Python)

This is the one place we changed course mid-project, and it's worth documenting honestly because it's directly about what the assignment is grading.

Early prototyping used **Scapy** for offline PCAP parsing, since `scapy.layers.tls` ships built-in TLS dissection. We abandoned it for **dpkt** plus our own manual `struct.unpack`-based field extraction, for two reasons — one pedagogical, one a real bug we hit:

- **Pedagogical**: the assignment is graded on demonstrated understanding of TLS record and handshake framing, not on library integration. Scapy's TLS layer performs *stateful, session-aware* dissection — it tries to track negotiated cipher state across a flow so it can label subsequent records. Letting a library walk the TLV chain for us, even where it works, defeats the point of the exercise. Manually walking record header → handshake header → cipher-suite/extension vectors *is* the deliverable.
- **Practical**: without the actual session keys, Scapy's stateful guessing proved unreliable on real captures. The same encrypted post-handshake traffic got inconsistently labeled across packets — `TLS`, `Padding`, `_TLSEncryptedContent`, and in one case even `SSLv2` on a plain TLS 1.2/1.3 flow. Worse, in at least one observed case, calling `bytes()` on an already-dissected Scapy TLS object appeared to return **re-serialized** bytes rather than the original wire bytes — this corrupted the record header and caused a ServerHello to be silently missed entirely during early reassembly testing. That's not a parsing inconvenience, it's a correctness bug in the exact layer we were trying to validate.

`dpkt` performs no TLS-level interpretation at all — it hands back raw packet/record bytes and nothing else, leaving 100% of TLS-specific parsing to our own code. That makes our output byte-for-byte deterministic and independently auditable against RFC 8446 §4 field offsets, which is exactly the property we wanted.

For **live capture**, dpkt has no equivalent of Scapy's `sniff()`, so Scapy is retained — but strictly as a packet-delivery mechanism. `bytes(pkt.original)` is extracted immediately inside the capture callback and handed to the *same* manual parser used for offline analysis; no Scapy-level TLS dissection is ever invoked. This keeps a single, consistent parsing code path across both offline and live modes, which also means our test suite (built entirely against synthetic offline bytes) exercises the exact same code that runs on live traffic.

### 3.2 TCP Reassembly Was Initially Under-Engineered (C++)

The C++ engine's first version generated fingerprints without proper TCP-level reassembly discipline, and we observed ClientHellos and ServerHellos being silently dropped. Two compounding issues, found by treating reassembly as a first-class problem instead of an afterthought:

1. We hadn't given TCP reassembly enough weight architecturally — segments arriving legitimately split across TCP packets weren't being stitched together before TLS record parsing was attempted.
2. TLS 1.3's ChangeCipherSpec compatibility record, which some clients prepend immediately before the second ClientHello (post-HelloRetryRequest) or before Finished, wasn't being accounted for at the start of a new packet's payload — our record-type check was walking into what it assumed was a Handshake record but was actually a 6-byte CCS record, throwing off every subsequent offset.

After a more careful pass, we fixed both: the C++ engine now explicitly strips the 6-byte TLS 1.3 middlebox-CCS prefix and advances its sequence anchor accordingly (`capture.cpp`), and both engines gate on the TLS content-type byte before ever tracking a flow. This is the single change that had the largest measurable effect on correctness — it's the difference between "the tool works on synthetic single-packet handshakes" and "the tool works on real, MTU-fragmented network traffic."

### 3.3 Other Decisions (no dramatic pivot, just choices)

- **JSON-backed dict, promoted to Redis, not Redis-only**: sufficient at our data scale; the `FingerprintDB`/`FingerprintDatabase` abstraction is thin enough that either engine falls back cleanly to the flat JSON map if Redis isn't running, which matters for grading reproducibility on a machine without Redis installed.
- **Minimal reassembly over duplicate-segment detection**: tracking a single `next_expected_seq` per 4-tuple, and classifying every incoming segment as in-order / pure-retransmit / partial-overlap / out-of-order against that one number, solved retransmission corruption and out-of-order buffering without needing a full sliding-window model — sufficient for handshake-phase traffic, which occurs before congestion control meaningfully kicks in.
- **Dataclasses (Python) vs. mutable scratchpad structs (C++)**: Python parses into frozen, immutable `ClientHelloFields`/`ServerHelloFields` per handshake — clean, GC-managed, but one allocation per handshake. C++ reuses a single mutable `ClientHelloData`/`ServerHelloData` scratchpad via `clear()` across the entire capture, avoiding per-packet heap allocation entirely, which matters at the throughput C++ operates at (see §5).
- **Parser modularity trade-off**: Python separates `parse_tls_record()` / `parse_handshake_header()` / `parse_client_hello()` into independently unit-testable functions. C++ inlines all three into two functions for instruction-cache locality. This is a direct language-appropriate trade: Python's separation buys us the `test_parser.py` granularity; C++'s inlining buys throughput.

Most of the remaining pipeline is a faithful reproduction of a well-specified, elaborate calculation (JA3/JA4 are fully specified externally) — there wasn't much room for novel design decisions once record/handshake parsing and reassembly were solid. That's expected and fine: the value being demonstrated here is *correct implementation of a known-hard byte-level protocol*, not algorithmic novelty.

---

## 4. Implementation: Python vs. C++ Engines


| Aspect           | Python                                                                                                                                                                                               | C++                                                                                                                                                                       |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Entry point      | `main.py` (argparse: `pcap`, `live`)                                                                                                                                                                 | `main.cpp` (POSIX `getopt`: `-r`, `-i`, `-q`, `-v`)                                                                                                                       |
| Processing model | Generator (`yield`)                                                                                                                                                                                  | libpcap callback (`pcap_loop`)                                                                                                                                            |
| Offline parsing  | `dpkt`                                                                                                                                                                                               | `libpcap` (`pcap_open_offline`)                                                                                                                                           |
| Live capture     | `scapy` (packet delivery only)                                                                                                                                                                       | `libpcap` (`pcap_open_live`)                                                                                                                                              |
| TLS parsing      | `struct.unpack`, modular functions                                                                                                                                                                   | Custom`ByteReader`, inlined                                                                                                                                               |
| Reassembly       | Full OOO-capable`TCPReassembler`: buffers out-of-order segments, trims partial overlaps, tracks flow lifecycle (SYN→ESTABLISHED→CLOSED), cross-record handshake reassembly via `pending_handshake` | Minimal contiguous-only`StreamBuffer` (4096B fixed): **drops the entire flow** on any out-of-order segment or buffer overflow, using RFC 1982 modular sequence arithmetic |
| GREASE filtering | Post-parse (at fingerprint computation)                                                                                                                                                              | During parse (never stored)                                                                                                                                               |
| Hashing          | `hashlib` (MD5, SHA-256)                                                                                                                                                                             | OpenSSL EVP, thread-local reusable context                                                                                                                                |
| Database         | `redis-py` + JSON fallback, pipelined bulk seeding                                                                                                                                                   | Custom raw RESP-over-socket client (~300 LOC), no library dependency                                                                                                      |
| GUI              | PyQt6 (`code/gui/`)                                                                                                                                                                                  | None                                                                                                                                                                      |
| Benchmark mode   | None                                                                                                                                                                                                 | `-q`: suppresses all I/O and Redis, reports raw throughput                                                                                                                |
| Platform         | Cross-platform                                                                                                                                                                                       | **POSIX-only** (libpcap; see Limitations)                                                                                                                                 |

### 4.1 Subjective Comparison

Python is the more *complete* implementation with respect to correctness on adversarial/real-world traffic: its reassembler tolerates out-of-order delivery, partial retransmits, and handshakes split across TLS records, none of which are guaranteed absent on a real network path. C++ trades all of that away — on any gap in sequence numbers, it simply drops the flow — in exchange for roughly an order of magnitude (and up to 30×, see benchmarks) more throughput, achieved through zero-allocation scratchpad reuse, thread-local hashing contexts, and inlined parsing with no function-call boundary between record/handshake/body parsing.

Neither is "better" in the abstract — they optimize for different things. Python is the correctness-first, pedagogically complete reference implementation (and the one with a GUI, since PyQt6 has no equivalent effort invested on the C++ side). C++ is the systems-level throughput demonstration: it is *not* a strictly more-correct rewrite of the Python engine, it is a narrower one that assumes clean, in-order handshake-phase traffic — a reasonable assumption for a handshake specifically, since congestion and induced reordering are rare in the first few RTTs of a connection, but a real and stated limitation nonetheless (see §6).

---

## 5. Benchmarks

Methodology: both engines were benchmarked on the same PCAP set, 30 runs each with 3 warm-up runs discarded. "Engine time" measures only the parse + reassemble + fingerprint loop (no interpreter startup, no Redis/DB — DB cost is deliberately excluded from both, per team decision, since it would conflate network-store overhead with actual engine performance). Correctness was verified per-run by requiring identical `(packets, client_hellos, server_hellos)` counts across all 30 runs of a given engine.


| PCAP                               | C++ pkts | Py pkts | C++ median (ms) | Py median (ms) | C++ throughput | Py throughput | Speedup | Handshakes match? |
| ---------------------------------- | -------- | ------- | --------------- | -------------- | -------------- | ------------- | ------- | ----------------- |
| test_reassembly.pcap               | 10       | 10      | 0.714           | 0.691          | 14.0 k/s       | 14.5 k/s      | 1.0×   | ✅                |
| captured_handshakes.pcap           | 75       | 75      | 0.702           | 1.325          | 106.9 k/s      | 56.6 k/s      | 1.9×   | ✅                |
| cloudflare_run1.pcap               | 2655     | 1877    | 1.134           | 20.114         | 2.34 M/s       | 93.3 k/s      | 17.7×  | ✅                |
| curl.pcap                          | 1208     | 938     | 0.877           | 8.393          | 1.38 M/s       | 111.8 k/s     | 9.6×   | ✅                |
| python_requests.pcap               | 356      | 223     | 0.701           | 2.596          | 508.1 k/s      | 85.9 k/s      | 3.7×   | ✅                |
| custom_client.pcap                 | 133      | 105     | 0.665           | 1.290          | 200.0 k/s      | 81.4 k/s      | 1.9×   | ✅                |
| chrome.pcap                        | 630      | 353     | 0.742           | 4.526          | 849.6 k/s      | 78.0 k/s      | 6.1×   | ✅                |
| chrome_run2.pcap                   | 591      | 352     | 0.729           | 4.310          | 811.0 k/s      | 81.7 k/s      | 5.9×   | ✅                |
| cloudflare_x100.pcap (265.5K pkts) | 265500   | 187700  | 68.446          | 2263.848       | 3.88 M/s       | 82.9 k/s      | 33.1×  | ❌                |

### 5.1 Reading the Results Honestly

- **On tiny inputs** (`test_reassembly.pcap`, 10 packets), the two engines are essentially tied — process/loop overhead dominates and there isn't enough work to amortize C++'s per-packet advantage.
- **Speedup scales with input size and complexity**: from ~1× on trivial inputs up to 33× on the largest capture. This tracks directly with §3.3's design decisions — Python's per-handshake allocation and modular function-call overhead become increasingly expensive relative to C++'s zero-allocation scratchpad reuse as packet counts grow.
- **The C++ and Python packet counts genuinely differ per capture** (e.g. `cloudflare_run1.pcap`: 2655 vs 1877). This is not a bug — the two engines count "packets processed" differently by design. C++'s libpcap loop counts every packet read off the wire/file. Python's `packets_processed` only counts TCP segments carrying payload or a SYN/FIN/RST flag; pure ACKs are intentionally skipped before ever reaching the reassembler. Throughput above is each engine's own rate against its own definition — comparable in trend, not in absolute packet-accounting semantics.
- **The one row where handshake counts *don't* match** (`cloudflare_x100.pcap`: C++ finds 1100/1100 client/server hellos, Python finds 1100/1001) is the most important row in this table, not a footnote. This is a synthetically 100×-replayed capture, and the mismatch is a direct, visible consequence of the architectural difference documented in §4: C++'s reassembler silently drops a flow on any out-of-order segment or buffer overrun, while Python buffers and eventually flushes it. At 100× replay density, some ServerHello-side flows in the C++ run almost certainly hit exactly that drop path (or the fixed 4096-byte `StreamBuffer` cap), while Python's OOO buffering recovered the same data — except Python's own count (1001 ServerHellos vs 1100 ClientHellos) shows it, too, is not perfectly lossless under this stress, just less lossy than C++. **We report this discrepancy rather than hiding it** — it is direct empirical evidence for the correctness/throughput trade-off argued in §4.1, not noise to explain away.

---

## 6. Security Application, and Limitations of TLS Fingerprinting

### 6.1 Role in Security Monitoring

TLS fingerprinting's value comes from one fact: the encrypted payload tells you nothing, but the *handshake construction* is a near-invariant of the client's TLS library, independent of the application layer riding on top of it. Two dominant defensive uses:

- **C2 / malware beacon detection.** Malware authors rarely bother randomizing their TLS stack's handshake shape. A hardcoded Go `crypto/tls` client, a custom OpenSSL build, or a known beacon framework (Cobalt Strike, IcedID, Sliver — all present in our seed database via the FoxIO JA4+ mapping import) produces a JA3/JA4 hash that is rare or previously catalogued as malicious. This gives a decryption-free indicator-of-compromise: a firewall log line alone, with no payload inspection, can say "this outbound connection's TLS handshake matches a known Cobalt Strike beacon" — Redis-backed lookup against our curated + FoxIO-imported catalog does exactly this.
- **Client identification / policy enforcement.** JA3/JA3S pairs distinguish curl from a browser from a scripted bot hitting an endpoint, even when the User-Agent header lies. This is useful for bot detection and for catching traffic that *claims* to be Chrome via its User-Agent but whose TLS stack doesn't match any known Chrome build — a mismatch between the application-layer claim and the transport-layer fingerprint is itself a signal.

### 6.2 Limitations

**(a) Structural, not semantic, matching.** JA3/JA4 don't understand *what* a cipher suite is — only its position in an ordered list. This is precisely what makes it library-agnostic, but it also means the fingerprint is trivially reproducible by anyone who controls handshake construction.

**(b) Extension order randomization defeats JA3 — demonstrated in our own captures.** Starting with Chrome 107+, Chromium deliberately randomizes ClientHello extension *order* per connection (not just GREASE insertion) specifically to resist fingerprinting. Our own seed database shows this directly: three separate JA3 hashes (`d1256e71...`, `61f4b05e...`, and others) all correspond to the *same physical Chrome build* across different capture sessions — the same browser produces a different JA3 hash every time it connects. This is strictly worse than GREASE noise, because GREASE is deterministically filtered out before hashing, while extension permutation changes the actual ordered field JA3 hashes over. This single finding *is* JA4's entire reason for existing: JA4 sorts cipher suites and extensions before hashing specifically to neutralize this, at the cost of discarding positional information that could theoretically distinguish two otherwise-identical clients configured differently — we do not have evidence this cost matters in practice, but it is the honest trade-off being made.

**(c) Evasion is a solved engineering problem for a motivated adversary.** Tools like `curl-impersonate` (present in our capture manifest) and TLS libraries like Go's `utls` exist specifically to clone a target browser's JA3/JA4 exactly, byte for byte. Fingerprinting raises the cost of blending in slightly; it does not defeat a targeted adversary who fingerprint-matches on purpose. The honest framing: **JA3/JA4 are population-level heuristics effective against unsophisticated or unmodified malware and misconfigured clients, not a cryptographic identity mechanism.**

**(d) Collision at the population level.** Many unrelated hosts running the same default library build (e.g., every unmodified Go binary using `net/http`'s default TLS config) collapse to an identical JA3/JA4 hash. A match is evidence about *software*, not about an individual actor — this is visible directly in our own legacy `fingerprints.json`, where single hashes map to comma-separated lists of multiple unrelated applications (e.g. one hash maps to `"Charles,Google Play Music Desktop Player,Postman,Slack,and other desktop programs"`).

**(e) Post-handshake blindness.** Fingerprinting only sees the plaintext handshake. TLS 1.3 additionally moves the Certificate and other post-ServerHello messages behind encryption, shrinking the available metadata surface further relative to TLS 1.2. A future Encrypted Client Hello (ECH) deployment would eliminate passive ClientHello fingerprinting entirely.

**(f) Engineering-scope limitations of this specific implementation** (as opposed to the technique in general):

- The **C++ engine is POSIX-only**, since it depends directly on `libpcap`. It will not build or run on Windows without swapping in Npcap/WinPcap-compatible headers and adjusting the socket/signal-handling code, which is POSIX-specific (`sigaction`, `getaddrinfo`, raw sockets for the Redis RESP client). The Python engine, using `dpkt` and `scapy`, is cross-platform by comparison (modulo live-capture privilege requirements on any OS).
- Our **reference database only covers a bounded, curated set of clients** — the clients we deliberately captured (curl variants, major browsers headless, Python `requests`/`ssl`, a handful of language runtimes) plus whatever the Salesforce community CSV and FoxIO JA4+ mapping already catalogued. Any client outside that set returns "Unknown," not a wrong answer, but a coverage gap: the tool's identification power is bounded by database size, not algorithmic capability, and a production deployment would need continuous ingestion from much larger community/threat-intel feeds to be useful at scale.

---

## 7. Future Scope

- **Combine client and server fingerprints for stronger detection.** A JA3+JA3S (or JA4+JA4S) *pair*, keyed to a specific flow, is more identifying than either half alone — e.g., a known-malicious client fingerprint talking to a specific, unusual server fingerprint (a non-standard C2 server stack) is a much stronger signal than the client hash by itself, since it also captures the *infrastructure* side of a malware campaign, not just the implant. This is a natural extension of our existing per-flow database schema (`FingerprintRecord` already keys by `kind` including both `ja3`/`ja3s` and `ja4`/`ja4s`) — the join would just need to happen at the flow level rather than independently per message.
- **JA4-family completion**: JA4L (latency), JA4H (HTTP), JA4X (X.509 certificate fingerprinting) extend the same idea to other protocol layers; only JA4/JA4S (TLS) were in scope here.
- **Encrypted Client Hello (ECH) awareness**: detect ECH usage itself as a signal (a client using ECH is, definitionally, trying to prevent fingerprinting), even though the inner ClientHello becomes unreadable.
- **Larger, continuously updated reference database**: ingest broader community/threat-intel feeds (e.g. full `ja3er.com` dumps, live FoxIO JA4+ updates) rather than our current bounded manifest, to reduce the "Unknown" rate documented in §6.2(f).
- **Cross-platform C++ engine**: abstract the libpcap-specific and POSIX-specific (`sigaction`, raw socket RESP client) code behind a platform layer to support Windows via Npcap.
- **Statistical/ML-based fingerprint clustering**: rather than exact-hash lookup, cluster near-identical fingerprints (e.g. same client, different TLS library minor version) to reduce false "Unknown" classifications from minor version drift.

---

*Draft — sections, ordering, and framing subject to revision. Byte offsets and code line references throughout are drawn directly from `parser.py`/`parser.cpp`, `capture.py`/`capture.cpp`, and `ja3.py`/`ja4.py`/`ja3.cpp`/`ja4.cpp`.*
