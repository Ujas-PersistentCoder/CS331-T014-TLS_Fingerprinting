<!--
AUTHOR REVIEW — not part of the final Word report
Status: initial working draft; content has NOT been approved.
Current implementation: post-restructure working tree based on main 2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1,
including the locally verified layout fixes. Source and binary digests are recorded below.
The original 1254a3f measurements are preserved as historical records, not pooled with current trials.
Fresh verification date: 6 November 2026, Asia/Kolkata.
Only this Markdown file is being authored. Do not generate or modify report.docx.
The template's skipped IV and duplicated IX have been corrected without dropping sections.
Target: about five body pages; below eight where practical; maximum ten. References and
appendices are excluded by the template. Actual pagination awaits separately authorized Word work.

OPEN ITEMS
1. Author will manually fill the six contribution rows and six distinct, team-agreed ratings.
2. Author will manually fill the AI tool/purpose table and significant prompt/chat-log links.
3. Is there an original JA3/JA3S ja3er.com validation record with inputs, outputs and provenance?
   code/reference/expected_hashes.csv has three client mappings; validation_notes.md is empty.
   This draft does not claim that the community-validation gate was demonstrated.
4. Review the reported PQ-capture mode difference and hardware-LRO evidence boundary.
   Source fixes or additional live experiments require a separate task; none were made here.
5. Confirm the provisional title, technical content and final page budget before approving content.

EVIDENCE NOTES
- Charter/roadmap intentions do not establish implemented features. In particular, there is no
  unified JSON record containing JA4T and PQ posture in this revision; QUIC remains unsupported.
- Historical test counts (76/123/139 for ECH stages; 63/83/96 for PQ stages) refer to earlier
  trees and are not results for the evaluated baseline. Its CTest has 187 GoogleTest cases plus one
  standalone JA4T entry, all passing in both configurations. The current suite adds one catalog-path regression (189 entries).
- The older Python/C++ comparison has unequal packet counts, and stress_test.pcap has unequal
  hello counts. Neither supplies a fair current-engine speedup claim.
- LRO_Findings.md makes broader claims than the available hardware evidence supports. Current
  LRO boundary checks are synthetic; no fresh hardware LRO or live capture was performed.
- The original ECH collection used engine dd3860a00c7c9096ba18d1612017ca748e29c6ff.
  Original JSON is preserved. Current replay reproduces joins/grouping; do not claim full JSON
  equality to that older engine, since server JA4S wire-order handling changed at integration.
- Benchmarking used the unmodified CLI. Verbose/JA4T checks used the same Release static
  CaptureEngine library through a temporary driver, with Redis port 0 to avoid catalog writes.
  JA4T checks called the tracked testbed's verify() on the tracked PCAP/catalog, without generation.
  Fresh Scapy PCAP generation attempted neighbor resolution and failed on unavailable BPF access;
  this does not invalidate replay of the tracked synthetic fixture. No live scenario was generated.
- The complete fresh evidence and temporary runners are in
  /private/tmp/cs331-final-report-1254a3f/; durable benchmark values are retained below.
  An earlier Section VII.C used a separate refreshed 1/2/4-worker batch under
  /private/tmp/cs331-final-report-workers124/, using the identical verified baseline binary.
- The author confirms that the original ECH collection used the same MacBook Air.
-->

# Passive TLS Fingerprinting with Transport ECH and Post Quantum Metadata

**CS 331 Computer Networks — Team T014 — Phase 2**

Ujas Devang Shah (24110376); Satyakam Mishra (24110318); Pranjal Goyal (24110274); Harshal Kundanlal Rana (24110131); Divyansh Sharma (24110113); D A S K R Manognya (24110097).

## I. Introduction

TLS encrypts application data, but its initial handshake exposes some protocol choices. A passive observer can extract these choices from ClientHello and ServerHello messages [[6]](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1), [[7]](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.1) and summarize them as fingerprints. A fingerprint describes visible behavior shared by a TLS stack or configuration; it does not prove the identity of an application or device.

Phase 1 provided Python and C++ fingerprinting implementations and a reference catalog. Phase 2 develops the C++ engine into a modular TCP/TLS monitor with worker threads, bounded record accumulation, transport fingerprints, Encrypted ClientHello (ECH) observations, and post-quantum (PQ) key-share inspection [1]. Our evaluation combines known-answer tests, saved traffic, synthetic controls, and endpoint-labeled ECH experiments. It also exposes limits: ECH fields add no profile discrimination in the supplied controlled corpus, and stateful tracking can miss a later hello after a sequence gap.

## II. Problem Statement

Given packets from a live interface or a PCAP/PCAPNG file, extract supported visible TLS hellos, compute JA3/JA3S and JA4/JA4S, and report transport fingerprints (JA4T/JA4TS) and optional key-exchange observations. Inputs may contain TLS records split across TCP segments, retransmissions, coalesced records, missing packets, or incomplete connections. Outputs include terminal fingerprints, catalog labels, optional JA4T/JA4TS cross-layer alerts, verbose inspection, and optional TLS/ECH JSON Lines summaries.

The engineering problem is to connect packet-level explanations with bounded processing and honest uncertainty. The project extends its earlier fingerprint-only pipeline; it does not establish a general weakness in existing monitoring products. Capture requires access to the relevant traffic. Both directions improve correlation, while missing SYNs or hellos reduce the available evidence. The engine supports TCP rather than QUIC/UDP, does not decrypt ECH or application traffic, and does not guarantee application recognition, successful TLS completion, or attack detection.


## III. Project Objectives

1.Compute the four TLS fingerprints and check representative known-answer vectors.
2.Handle complete TLS records and supported TCP segmentation with explicit size and state limits.
3.Compute JA4T/JA4TS fingerprints, correlate SYN/SYN-ACK metadata with TLS hellos, and exercise honest, inconsistent, and fully spoofed synthetic controls.
4.Extract ECH envelope fields while separating presence, parse status, findings, and acceptance evidence.
5.Optionally inspect advertised PQ groups and key-share sizes without claiming cryptographic verification.
6.Evaluate current engine modes on identical captures with recorded settings and reproducible counts.

## IV. Architecture and Design

```mermaid
flowchart TD
    A["libpcap file or interface"] --> B["Link, IP and TCP parsing"]
    B --> C["Bounded TLS record accumulator"]
    B --> D["Optional SYN and TTL observations"]
    C --> E["Bounded record jobs"]
    D --> E
    E --> F["Workers: hello parsing, JA3/JA4, PQ inspection"]
    F --> G["Catalog labels and terminal output"]
    D --> G
    C --> H["Optional ordered TLS/ECH connection analysis"]
    H --> I["TLS/ECH JSON Lines summaries"]
```

*Figure 1. Capture-thread state is separate from worker reporting. The JSON branch does not include the terminal JA4T/PQ findings.*

The capture thread parses link, IP and TCP headers and owns record accumulation. With ECH tracking enabled, it also owns bidirectional connection generations, lifecycle state, and JSON output. Each complete record sent to a worker is copied into a bounded job, including any captured SYN and TTL context. A symmetric flow hash sends both directions to the same worker. Workers have separate parser scratchpads and PQ offer tables, and terminal output is synchronized [2].

The accumulator can borrow bytes for a complete record and allocate storage for an unfinished one. This reduces copying at record delivery, but worker jobs still copy records: the whole pipeline is not zero-copy. In stateful tracking, sequence watermarks suppress delivered retransmissions; partial overlaps retain only the new suffix. A gap after framing starts stops that direction. There is no general out-of-order queue. Split record headers and multiple records in one segment are supported; a hello spanning multiple TLS records is not. The central stateful rule is:

```text
discard already-delivered prefix bytes; keep any new suffix
if a gap breaks established framing: stop this direction
read or complete the five-byte TLS record header
if total record size exceeds 8192: report unsupported input
retain partial bytes until complete; then deliver the record
repeat for any remaining records in the segment
```

An assembled record is limited to 8,192 bytes including its five-byte header. Incomplete-record timeout is three seconds; default ECH connection timeout is 30 seconds, with at most 65,536 retained connections. These are implementation limits, not TLS protocol guarantees. Bounded worker queues make offline capture wait when full; live dispatch may drop jobs. Ordered producer state simplifies ownership at the cost of serial work and some repeated parsing. Consumer threads drain before capture returns.

## V. Implementation

The engine uses C++17, libpcap for capture, OpenSSL EVP for hashing, and standard threads. GoogleTest supplies most tests; JA4T also has a standalone test runner. Redis is optional: the engine can load the tracked JSON catalog into memory. Catalog matches are labels associated with observed fingerprints, not independently verified identities. The repository is [TLS-Fingerprinting](https://github.com/Ujas-PersistentCoder/TLS-Fingerprinting), and this report describes the post-restructure tree based on `2f4a78b`, including the verified layout fixes [1].

### A. TLS fingerprints

JA3 serializes five ClientHello fields:

```text
legacy_version,cipher_suites,extension_types,supported_groups,ec_point_formats
```

Numeric values are written in decimal; list values are separated by hyphens, empty fields are retained, and MD5 produces the final hash. Reserved GREASE values are filtered from the applicable 16-bit fields. GREASE deliberately exercises protocol extensibility [[8]](https://www.rfc-editor.org/rfc/rfc8701.html#section-1). The remaining list order is preserved, so browser extension permutation can change JA3. JA3S uses the server's legacy version, selected cipher, and ordered non-GREASE extensions. MD5 is required for compatibility here; it supplies no identity or security proof.

JA4 combines a readable prefix with two 12-hex-digit SHA-256 prefixes. The prefix encodes TCP, the highest non-GREASE offered version, server name indication (SNI) extension presence, cipher and extension counts, and two characters derived from the first application-layer protocol negotiation (ALPN) value. Cipher IDs and selected extension IDs are sorted for hashing; SNI and ALPN are excluded from the extension hash, while signature algorithms retain wire order. JA4S uses the selected cipher and hashes server extensions in wire order, including GREASE. HelloRetryRequest (HRR) is recognized separately and excluded from ordinary server fingerprints. With ECH, the client fingerprints describe the visible outer hello [2].

### B. Transport and modern TLS observations

| Capability | Implemented behavior | Evidence limit |
|---|---|---|
| JA4T / JA4TS | SYN / SYN-ACK window, option order, MSS and window scale | Requires a captured, correlated SYN |
| Transport alerts | Compare expected OS, inferred stack and packet TTL | Heuristics; matching metadata can be spoofed |
| ECH | Decode variant, KDF/AEAD IDs, config ID and lengths | Does not recover the inner hello or prove acceptance |
| PQ inspection | Read group IDs, share lengths and server selection | Does not validate key contents or completed key exchange |
| JSON Lines | Version 1 TLS/ECH connection summaries and transport issues | No unified JA4T/PQ posture record |

TCP header fields, options and connection setup are specified in RFC 9293 [[10]](https://www.rfc-editor.org/rfc/rfc9293.html#section-3). JA4T has the form `window_option-kinds_MSS_window-scale`; TTL is used alongside it. The engine can report `IMPERSONATION_MISMATCH`, `TTL_MISMATCH`, and `STACK_ANOMALY`. An impersonation mismatch requires an OS-specific `expected_os` catalog entry. A generic Chrome fingerprint does not establish Windows identity. The TTL check tolerates a one-hop difference. Proxies and crafted TCP/IP headers further limit interpretation [3].

ECH encrypts a private inner ClientHello, including the intended server name, while leaving an outer hello visible [[9]](https://www.rfc-editor.org/rfc/rfc9849.html#section-3.2). Extension `0xfe0d` is decoded with nested length checks. Findings include duplicates, an external inner marker, forbidden outer-extension references, and inappropriate empty encapsulation. Missing information remains unknown. TLS 1.3 alone does not establish acceptance; a completely observed older negotiation can establish non-acceptance. Positive ECH acceptance in our experiment comes from separate endpoint logs. A complete hello pair is only a parsing/correlation result [4].

PQ inspection distinguishes advertised capabilities in `supported_groups` from the bytes actually offered in `key_share` [[6]](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8). It recognizes hybrid groups `0x11ec`, `0x11eb`, `0x11ed` and historical draft IDs `0x6399`/`0x639a`. For example, the engine checks X25519MLKEM768 shares against 1,216 client bytes and 1,120 server bytes. Malformed framing, wrong recognized lengths, and duplicate relevant extensions are flagged. Worker-local offer tables correlate client offers with server choices; their size is bounded, but they have no time or FIN/RST expiry. Reported hybrid selection is a wire observation, not proof of quantum security [5].

### C. Controls and output

`-r` selects a saved capture; `-i` selects live capture; `-f` changes the default `tcp` BPF filter. `-j` sets workers, otherwise the engine uses reported hardware concurrency. `-t` enables JA4T/JA4TS and transport checks; `-v` adds dissection; `-q` suppresses presentation while retaining fingerprint computation. `-c` adds a catalog, and `-u` allows interactive labeling. Stateful ECH analysis is off by default and enabled by `-e`/`--ech`. `--json file` creates a new JSON Lines file and forces ECH tracking on, even with `--no-ech`. Existing output files are refused. PQ posture correlation and verbose checks are enabled with `-p`/`--pq` and disabled by default; `--no-pq` disables them explicitly. PQ extension field parsing remains part of shared hello parsing.

## VI. Testbed Setup

Fresh builds, replays and timing trials were performed on 6 November 2026. They used a MacBook Air (Mac16,12), Apple M4 with ten cores (four performance and six efficiency), 16 GB RAM, ARM64, and macOS 27.0.1 build 26A434. The tools were AppleClang 21.0.0, CMake 4.4.5, OpenSSL 4.1.0, Apple libpcap 1.10.1, GoogleTest 1.14.0, Python 3.13.6 in the existing parent `.venv`, and TShark 4.6.8. Release used CMake's Release settings plus the engine's `-O3`; Debug instrumented the engine and GoogleTest with AddressSanitizer and UndefinedBehaviorSanitizer. No GPU was used.

| Workload or testbed | Configuration and role |
|---|---|
| Distinct-flow stress capture | 20,000 TCP packets; 10,000 ClientHellos and 10,000 ServerHellos; synthetic throughput workload |
| Saved PQ/ECH Chrome capture | 5,580 frames; default TCP filter delivers 4,259 packets; segmented, hybrid and HRR examples |
| JA4T fixture | 19 synthetic scenarios plus an explicit lab catalog; offline verdict checks |
| Original ECH experiment | IPv4 loopback; two profiles of pinned BoringSSL; endpoint logs and saved PCAPs; current work replays these artifacts |

The ECH dependency revision is `df870ed7fa51110edb872beb3357a44d20e1ce56`. Profile A offers TLS X25519 and B offers P-256; both use ALPN `h2`, common cipher/signature settings, GREASE and extension permutation. They share one ECH configuration using X25519 HPKE, KDF 1, AEAD 1 and config ID 42. Each session contains ten connections per profile, with fresh clients and no resumption. Endpoint records are joined to passive records using session, oriented tuple, and outer random. The original capture used engine `dd3860a` on the same MacBook Air described above. Its recorded compiler, CMake and TShark versions are retained in the build manifest [4].

## VII. Evaluation

### A. Tests and replay

| Current verification after layout fixes | Result | Interpretation |
|---|---|---|
| Release CTest | 189/189 pass | Includes a catalog lookup regression across four working directories |
| ASan/UBSan Debug CTest | 189/189 pass | No sanitizer findings reported in this run |
| ECH lab checks | 17/17 pass | Join rules, evidence boundaries and runner behavior |
| Freshly generated JA4T scenarios | 19/19 expected verdicts | Includes honest controls, missing SYNs and fully copied headers |
| Twelve selected captures | Ordered JSON matches across Release 1/2/4 workers and Debug 4 workers | Capture ID and relocated source path normalized before comparison |

The tests include Salesforce JA3 known-answer vectors, FoxIO JA4/JA4S vectors, malformed inputs, segmented/coalesced records, lifecycle handling and synthetic large-record boundaries [2]. Passing them does not establish complete protocol compliance or recognition accuracy. The available community hash mappings do not provide a reproducible audit trail for full JA3/JA3S community-dataset validation.

Replaying the GRO-on and GRO-off captures yields the same unique client JA3 (`284deaeae14ea5ddc96c5d7e59855422`) and JA4 (`t13d301200_1d37bd780c83_ecd0401ec68b`). Their packet and connection counts differ, so this is a feature comparison, not whole-capture equality. Synthetic LRO-sized record tests pass; actual hardware-LRO invariance has not been demonstrated by this rerun.

In default ECH-off mode, the PQ capture produces 22 ClientHellos, 19 ordinary ServerHellos and three HRRs. Thirteen client hellos contain 1,216-byte `0x11ec` shares; eight server hellos select 1,120-byte hybrid shares. All 44 inspected hellos, including HRRs, report PQ wire checks as `ok`. With ECH tracking enabled, only 18 ordinary ServerHellos are counted. On the affected connection, frame 26 arrives ahead of missing sequence bytes after HRR; tracking reports a gap and does not process the later ServerHello at frame 29. TShark's out-of-order reassembly exposes that hello. This illustrates the engine's reordering limit and prevents an equal-work speed comparison between these modes on this capture.

### B. Controlled ECH result

The original corpus contains 60 endpoint-confirmed accepted connections across three sessions, with zero exclusions. A separate three-attempt pilot contains accepted A, accepted B, and an explicit GREASE control. Recomputing the original analysis and replaying all four PCAPs through the evaluated engine reproduce the joins and grouping results. Original evidence files were preserved [4].

| Feature set on the 60 accepted connections | Distinct groups | Groups shared by A and B |
|---|---:|---:|
| Outer JA3 | 60 | 0 |
| JA3 plus selected ECH fields | 60 | 0 |
| Outer JA4 | 1 | 1 |
| JA4 plus selected ECH fields | 1 | 1 |

The added fields are KDF ID, AEAD ID, encapsulation length and ciphertext length. Every accepted offer has values `(1, 1, 32, 176)`, so they add no discrimination here. All JA3 values differ with permutation enabled; this is variation without repeatable profile identification. Both profiles share JA4 `t13d0308h2_55b375c5d22e_0365bc7f0f41`. TShark pilot checks agree after removing GREASE signature IDs from its raw JA4 input, a documented tool discrepancy. These are two configurations of one library, not independent browser families. We did not compare matched connections with real ECH enabled and disabled, or evaluate TLS handshake latency. The throughput measurements in Section VII.C concern offline packet analysis.

### C. Offline replay throughput

Workers 1, 2 and 4 were measured together on the repaired post-restructure Release build, with `--pq` explicitly enabled in every configuration. Each workload has six configurations: three worker counts with ECH tracking off or on. Worker counts exclude the capture thread. Each configuration received one warm-up followed by seven measured runs, with order rotated between rounds. The table reports median and minimum–maximum throughput in thousands of packets per second (kpps), using the engine's internal capture/processing interval through worker draining. No builds or other verification ran during timing.

| Capture | Workers | ECH tracking | Median kpps | Range kpps |
|---|---:|---|---:|---:|
| Distinct-flow stress | 1 | Off | 254.6 | 209.4–298.1 |
| Distinct-flow stress | 1 | On | 229.6 | 204.9–302.7 |
| Distinct-flow stress | 2 | Off | 488.2 | 379.9–533.1 |
| Distinct-flow stress | 2 | On | 220.9 | 185.9–288.0 |
| Distinct-flow stress | 4 | Off | 609.5 | 318.6–826.9 |
| Distinct-flow stress | 4 | On | 160.8 | 46.4–208.4 |
| PQ/ECH Chrome | 1 | Off | 1,807.7 | 1,469.1–1,846.9 |
| PQ/ECH Chrome | 1 | On | 1,600.5 | 1,490.2–1,670.2 |
| PQ/ECH Chrome | 2 | Off | 1,801.6 | 1,399.6–1,870.4 |
| PQ/ECH Chrome | 2 | On | 1,572.7 | 1,394.6–1,633.1 |
| PQ/ECH Chrome | 4 | Off | 1,771.6 | 541.8–1,903.0 |
| PQ/ECH Chrome | 4 | On | 1,353.8 | 1,274.8–1,551.5 |

All stress runs process the same 20,000 packets and 10,000 hellos per direction. ECH-off median throughput increases with worker count in this batch; ECH-on medians do not show that gain. Ranges are wide, so these short trials do not isolate a bottleneck or establish a statistically significant scaling result. The PQ capture has unequal server work across tracking modes and very short median intervals; its rows are descriptive timings, not evidence of a feature-overhead ratio. Quiet mode retains TLS hashing and the explicitly enabled PQ posture work, but excludes catalog presentation, verbose transport alerts and JSON output. The ECH toggle changes analyzer tracking, not the recorded connections. These warm-cache, offline trials do not establish live line-rate performance or long-run capacity. Earlier benchmark batches remain historical records and were not pooled with these trials.

## VIII. Summary

Phase 2 connects passive TLS fingerprints with bounded TCP record handling, worker reporting, transport consistency checks, ECH observations and PQ share inspection. Tests and selected replay checks pass after the layout fixes. The controlled ECH corpus demonstrates fingerprint computation on confirmed accepted ECH, while showing no added profile discrimination from the selected envelope fields. The refreshed one-, two- and four-worker benchmark demonstrates workload-dependent throughput: additional workers improve the stress workload with ECH tracking off, but do not provide an observed gain with tracking on.

The tool remains a limited passive observer. It cannot reliably classify real versus GREASE ECH from the envelope, prove application identity, validate PQ cryptography, or recover arbitrary missing/reordered bytes. Future work includes explicit cross-record and reordering support, unified JA4T/PQ JSON telemetry, better lifecycle handling for PQ offers, longer controlled benchmarks, and independently labeled client families. QUIC and hardware-LRO validation remain separate work. These directions are not reported as implemented results.

## IX. Reproducibility

Use the current repository layout and the path fixes described here [1]. The verified tree is based on `2f4a78b`; source and binary digests accompany the measurements. Run all commands from the repository root. Use a C++17 compiler, CMake, libpcap and OpenSSL; CMake obtains GoogleTest 1.14.0 for Phase 2. TShark is required for the ECH evidence checks. Set `PYTHON` to an existing virtual environment; in this workspace it is the parent `.venv`:

```sh
export PYTHON="$PWD/../.venv/bin/python"
cmake -S 'Phase 2/code/engine' -B build/phase2 -DCMAKE_BUILD_TYPE=Release
cmake --build build/phase2 -j 4
ctest --test-dir build/phase2 --output-on-failure
cmake -S 'Phase 2/code/engine' -B build/phase2-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/phase2-debug -j 4
ctest --test-dir build/phase2-debug --output-on-failure

build/phase2/tlsfp_phase2 -r 'Phase 2/code/pcaps/pq_ech_chrome.pcap' -v -t --pq --ech
build/phase2/tlsfp_phase2 -r 'Phase 2/code/pcaps/pq_ech_chrome.pcap' -q -j 2 --json /tmp/tlsfp-pq-new.jsonl
"$PYTHON" 'Phase 2/code/testbed/ja4t_lab.py' --out build/ja4t-lab --engine build/phase2/tlsfp_phase2
"$PYTHON" -m pytest 'Phase 1/code/python/tests' -q
"$PYTHON" -m unittest discover -s 'Phase 2/code/experiments/ech' -p test_lab.py -v

"$PYTHON" 'Phase 2/code/experiments/ech/run.py' replay \
  --engine build/phase2/tlsfp_phase2 \
  --source 'Phase 2/code/experiments/ech/results/corpus' --out /tmp/ech-replay-new
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' report \
  --pilot 'Phase 2/code/experiments/ech/results/pilot' \
  --collection 'Phase 2/code/experiments/ech/results/corpus' --out /tmp/ech-report-new
"$PYTHON" 'Phase 2/code/testbed/benchmark_modes.py' \
  --engine build/phase2/tlsfp_phase2 --out build/benchmark-phase2-new
```

Use unused JSON filenames and output directories. Rebuild after moving a checkout; existing CMake caches contain absolute source paths. Catalog lookup has a CMake-recorded fallback to the shared `Phase 1/code/` data and reports missing files or an empty load. Benchmark success alone does not verify catalog loading because quiet mode skips it.

The benchmark script explicitly enables `--pq`, tests workers 1/2/4 with ECH tracking off/on, performs one warm-up and seven rotating measured rounds per configuration, and records metadata, source/binary/workload digests, all 96 executions, counts and summary statistics. It refuses existing output directories and flags unequal work. The unchanged workload SHA-256 digests are:

```text
Phase 2/code/pcaps/stress-distinct.pcap
aef1ef7c468c6869c973e6c53e7de0200692e2928dec0966896a5b56ee770d20
Phase 2/code/pcaps/pq_ech_chrome.pcap
40ac4723bf2044cffab3666d00fd48f1499d253cad6cecb9a34b0a3644e3d792
```

The ECH `report` command recomputes the original saved evidence. `replay` separately records the selected current engine; current endpoint joins were checked using copies of the original logs. Neither command overwrites or relabels the original corpus. Offline use needs no private keys. The lab README documents the corrected build runner and optional reuse of clean pinned dependencies; fresh collection additionally needs loopback capture permission. Original checkpoint notes retain their recorded revisions and link to the current READMEs.

## References

[1] Team T014, “TLS Fingerprinting,” project repository, post-restructure base revision `2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1`, with local layout fixes identified in the verification record, 2026. [Repository snapshot](https://github.com/Ujas-PersistentCoder/TLS-Fingerprinting/tree/2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1).

[2] Team T014, “Phase 2 engine implementation and tests,” 2026. [Source, headers, build configuration and tests](https://github.com/Ujas-PersistentCoder/TLS-Fingerprinting/tree/2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1/Phase%202/code/engine). Relevant modules: `capture`, `accumulator`, `parser`, `ja3`, `ja4`, `db`, `ech_parser` and `ech_analysis`.

[3] Team T014, “JA4T and cross-layer spoofing lab,” 2026. [Implementation notes](https://github.com/Ujas-PersistentCoder/TLS-Fingerprinting/blob/2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1/Phase%202/code/engine/JA4T.md) and [testbed with saved fixtures](https://github.com/Ujas-PersistentCoder/TLS-Fingerprinting/tree/2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1/Phase%202/code/testbed). OS and attack labels are interpreted subject to the limits stated in this report.

[4] Team T014, “Reduced ECH checkpoint 3 experiment,” 2026. [Method, endpoint implementation, analysis and public evidence](https://github.com/Ujas-PersistentCoder/TLS-Fingerprinting/tree/2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1/Phase%202/code/experiments/ech). Original collection engine `dd3860a`; pinned BoringSSL revision recorded in its manifests.

[5] Team T014, “PQ-TLS checkpoint 2,” 2026. [Checkpoint evidence and limitations](https://github.com/Ujas-PersistentCoder/TLS-Fingerprinting/blob/2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1/Phase%202/report/docs/PQTLS_Checkpoint_2_Testing.md), with current `pqtls_parser` and `pqtls_analysis` source/tests in [2]. Historical checkpoint counts are distinct from this report's baseline results.

[6] E. Rescorla, “[The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446.html),” RFC 8446, August 2018. Sections 4.1, 4.2.7–4.2.8 and 5 describe hello messages, supported groups, key shares and record framing.

[7] T. Dierks and E. Rescorla, “[The Transport Layer Security (TLS) Protocol Version 1.2](https://www.rfc-editor.org/rfc/rfc5246.html),” RFC 5246, August 2008. Sections 6.2 and 7.4.1 describe record framing and hello messages.

[8] D. Benjamin, “[Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility](https://www.rfc-editor.org/rfc/rfc8701.html),” RFC 8701, January 2020.

[9] E. Rescorla, K. Oku, N. Sullivan and C. A. Wood, “[TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html),” RFC 9849, March 2026. Sections 3.2, 5 and 6.1.4 describe inner/outer hellos, the ECH extension and acceptance checks.

[10] W. Eddy, Ed., “[Transmission Control Protocol (TCP)](https://www.rfc-editor.org/rfc/rfc9293.html),” RFC 9293, August 2022. Sections 3.1–3.5 describe TCP headers, options, sequence numbers and connection setup.

## Appendix A Team Work Distribution and Member Rating

### A.1 Work Distribution

| No. | Member name | Roll number | Tasks done | Rating out of 10 |
|---:|---|---|---|---|
| 1 | Ujas Devang Shah | 24110376 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 2 | Satyakam Mishra | 24110318 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 3 | Pranjal Goyal | 24110274 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 4 | Harshal Kundanlal Rana | 24110131 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 5 | Divyansh Sharma | 24110113 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 6 | D A S K R Manognya | 24110097 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |

**[AUTHOR TO FILL: team-agreed ratings must be six distinct values on the 1–10 scale.]**

## Appendix B AI Usage Details

| No. | AI tool and model | Purpose |
|---:|---|---|
| 1 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 2 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 3 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |
| 4 | [AUTHOR TO FILL] | [AUTHOR TO FILL] |

### B.1 Prompts

**[AUTHOR TO FILL: significant prompts or chat-log links, linked to the uses above. Confirm the relevant prompt/response Markdown files are shared in the repository. Existing material is under `AI_Used/`.]**

<!--
FRESH VERIFICATION RECORD — editorial evidence, not final Word content
Revision: 1254a3f8c164ba0ffec3e3d265cc5536af5320dc; date 2026-11-06 Asia/Kolkata.
Release executable SHA-256: 1e5ded7bd0345de7dc5ba2274f77f5e71bdb7cedf2a344ed51781fb660660d3a.
Original report.docx SHA-256 (must remain unchanged):
68c2bc614a7fc9d6eaf184bb9164640a7cd77da46fdc05a02ea2d1040485f2ab.
Build root: /private/tmp/cs331-final-report-1254a3f.
Both CMake configurations used -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/private/tmp/googletest-1.14.0
to reuse the declared 1.14.0 source without a download. Release and Debug built it separately.
Release: 188/188 CTest entries, 3.38 seconds. Debug ASan/UBSan: 188/188, 10.66 seconds.
Lab unittest: 15 checks, 0.524 seconds. Saved JA4T verifier: 19 expected verdicts.
No fresh endpoint collection, hardware LRO test, Linux/Windows build or Python-engine test was run.

REPLAY RECORD: file | summaries | complete hello pairs | SHA-256
Each file was replayed with -q -t --json and Release -j1/-j4, Debug -j4.
Ordered JSON was identical across all three configurations after deleting capture_id only.
Phase 2/engine/tests/fixtures/ech_checkpoint1.pcap | 9 | 0 | 27da3e2627cb4a468eb3d8ed9a3255d6dc6b32221e790b1d634c797ea792b0f4
Phase 2/engine/tests/fixtures/ech_checkpoint2.pcap | 11 | 7 | 30e5a7bd86c8f7b28e289dfe3f05be7d498bc1c46ea5b5d8c8982f3c12b466f4
Phase 2/pcaps/gro_on.pcap | 1 | 0 | c38089128b574fe5050b7b7102e9a13d8c31eb29f192bf2d19c0a571838ca522
Phase 2/pcaps/gro_off.pcap | 6 | 6 | 059c773b5f118a26ffd77d25d4ea0091af5ac1d9f0d28a98f48865ed213f1cdf
Phase 2/pcaps/pq_ech_chrome.pcap | 45 | 18 | 40ac4723bf2044cffab3666d00fd48f1499d253cad6cecb9a34b0a3644e3d792
code/pcaps/chrome.pcap | 4 | 4 | 23bf8d61df40066a087efe1ac3e7ef60e8c9baa9bdac51f6f8c8707367ec6051
code/pcaps/curl.pcap | 1 | 1 | 7ef6ed9ac66a8b8b07b51760f3b378b797a3854e4dde9fd085d60171d1a83eee
code/pcaps/cloudflare_run1.pcap | 29 | 8 | 5a9b6ea96849f87edaf269160775073aa29c5d67b231b03dbbcc4e809027de44
Phase 2/experiments/ech/results/pilot/pilot/capture.pcap | 3 | 3 | 97c15f4a1be2bc494abd50943ae8c28f79c80b9eac54f2e1ae320f80a5b64853
Phase 2/experiments/ech/results/corpus/session-1/capture.pcap | 20 | 20 | 69edc83e2d171cd8295df0da5135dc8b5ed452ca485911973a0e0935919a620a
Phase 2/experiments/ech/results/corpus/session-2/capture.pcap | 20 | 20 | e42336a78f8a8c24367f60a7870e56dd21982aae00255029a9788a6e84572313
Phase 2/experiments/ech/results/corpus/session-3/capture.pcap | 20 | 20 | 16c01b087f0338be08881f99b0c0c9ab30f1e98627c5844664588ac14b3a1d26

Both original-evidence recomputation and current-engine replay/join reproduce the tracked ECH summary.
Current-engine replay/join retained original endpoint/capture records in a temporary copied tree;
only engine.jsonl was replaced there. Historical manifests retained their collection provenance.
Raw current replay JSON is outside the repository; original result files were not rewritten.

ORIGINAL BENCHMARK METHOD AND RAW TRIALS — superseded for VII.C by the refreshed batch below
Unmodified Release CLI command, from repo root:
<engine> -r "Phase 2/pcaps/<workload>" -q -j <1|4> <--no-ech|--ech>
No -t, -v, --json or catalog interaction. Each command ran in a fresh subprocess.
Internal elapsed time starts after capture/database/worker setup, ends after workers drain,
and precedes finish_capture finalization. Values below are the CLI-reported rounded values.
Workload order: stress-distinct, then pq_ech_chrome. Config order C0=(1,off), C1=(1,on),
C2=(4,off), C3=(4,on). Warm C0,C1,C2,C3 once, then seven rounds whose order rotates left
by (round-1) modulo 4. Runs were sequential, with no deliberate delays or process affinity.
One excluded warm-up per configuration has round 0. All 64 invocations exited successfully.
Header: workload | workers | ech | round | packets | clients | ordinary_servers | elapsed_ms | pps
stress-distinct.pcap | 1 | off | 0 | 20000 | 10000 | 10000 | 80.002 | 249993.8
stress-distinct.pcap | 1 | on | 0 | 20000 | 10000 | 10000 | 64.478 | 310183.3
stress-distinct.pcap | 4 | off | 0 | 20000 | 10000 | 10000 | 43.617 | 458536.8
stress-distinct.pcap | 4 | on | 0 | 20000 | 10000 | 10000 | 69.079 | 289523.6
stress-distinct.pcap | 1 | off | 1 | 20000 | 10000 | 10000 | 63.298 | 315965.7
stress-distinct.pcap | 1 | on | 1 | 20000 | 10000 | 10000 | 62.666 | 319152.3
stress-distinct.pcap | 4 | off | 1 | 20000 | 10000 | 10000 | 26.859 | 744629.4
stress-distinct.pcap | 4 | on | 1 | 20000 | 10000 | 10000 | 67.809 | 294946.1
stress-distinct.pcap | 1 | on | 2 | 20000 | 10000 | 10000 | 66.366 | 301359.1
stress-distinct.pcap | 4 | off | 2 | 20000 | 10000 | 10000 | 27.113 | 737653.5
stress-distinct.pcap | 4 | on | 2 | 20000 | 10000 | 10000 | 68.551 | 291753.6
stress-distinct.pcap | 1 | off | 2 | 20000 | 10000 | 10000 | 62.593 | 319524.5
stress-distinct.pcap | 4 | off | 3 | 20000 | 10000 | 10000 | 26.642 | 750694.4
stress-distinct.pcap | 4 | on | 3 | 20000 | 10000 | 10000 | 72.884 | 274408.6
stress-distinct.pcap | 1 | off | 3 | 20000 | 10000 | 10000 | 62.800 | 318471.3
stress-distinct.pcap | 1 | on | 3 | 20000 | 10000 | 10000 | 62.922 | 317853.9
stress-distinct.pcap | 4 | on | 4 | 20000 | 10000 | 10000 | 68.430 | 292269.5
stress-distinct.pcap | 1 | off | 4 | 20000 | 10000 | 10000 | 62.147 | 321817.6
stress-distinct.pcap | 1 | on | 4 | 20000 | 10000 | 10000 | 65.019 | 307602.4
stress-distinct.pcap | 4 | off | 4 | 20000 | 10000 | 10000 | 26.655 | 750328.3
stress-distinct.pcap | 1 | off | 5 | 20000 | 10000 | 10000 | 61.296 | 326285.6
stress-distinct.pcap | 1 | on | 5 | 20000 | 10000 | 10000 | 63.051 | 317203.5
stress-distinct.pcap | 4 | off | 5 | 20000 | 10000 | 10000 | 26.187 | 763737.7
stress-distinct.pcap | 4 | on | 5 | 20000 | 10000 | 10000 | 105.179 | 190152.0
stress-distinct.pcap | 1 | on | 6 | 20000 | 10000 | 10000 | 62.707 | 318943.7
stress-distinct.pcap | 4 | off | 6 | 20000 | 10000 | 10000 | 26.268 | 761382.7
stress-distinct.pcap | 4 | on | 6 | 20000 | 10000 | 10000 | 64.086 | 312080.6
stress-distinct.pcap | 1 | off | 6 | 20000 | 10000 | 10000 | 65.396 | 305829.1
stress-distinct.pcap | 4 | off | 7 | 20000 | 10000 | 10000 | 25.049 | 798435.1
stress-distinct.pcap | 4 | on | 7 | 20000 | 10000 | 10000 | 67.666 | 295569.4
stress-distinct.pcap | 1 | off | 7 | 20000 | 10000 | 10000 | 62.177 | 321662.4
stress-distinct.pcap | 1 | on | 7 | 20000 | 10000 | 10000 | 63.727 | 313838.7
pq_ech_chrome.pcap | 1 | off | 0 | 4259 | 22 | 19 | 6.374 | 668183.2
pq_ech_chrome.pcap | 1 | on | 0 | 4259 | 22 | 18 | 2.382 | 1787993.3
pq_ech_chrome.pcap | 4 | off | 0 | 4259 | 22 | 19 | 4.829 | 881963.1
pq_ech_chrome.pcap | 4 | on | 0 | 4259 | 22 | 18 | 2.496 | 1706330.1
pq_ech_chrome.pcap | 1 | off | 1 | 4259 | 22 | 19 | 2.238 | 1903038.4
pq_ech_chrome.pcap | 1 | on | 1 | 4259 | 22 | 18 | 2.441 | 1744776.7
pq_ech_chrome.pcap | 4 | off | 1 | 4259 | 22 | 19 | 2.241 | 1900490.9
pq_ech_chrome.pcap | 4 | on | 1 | 4259 | 22 | 18 | 2.665 | 1598123.8
pq_ech_chrome.pcap | 1 | on | 2 | 4259 | 22 | 18 | 2.613 | 1629927.3
pq_ech_chrome.pcap | 4 | off | 2 | 4259 | 22 | 19 | 2.691 | 1582683.0
pq_ech_chrome.pcap | 4 | on | 2 | 4259 | 22 | 18 | 5.017 | 848913.7
pq_ech_chrome.pcap | 1 | off | 2 | 4259 | 22 | 19 | 2.210 | 1927149.3
pq_ech_chrome.pcap | 4 | off | 3 | 4259 | 22 | 19 | 5.104 | 834443.6
pq_ech_chrome.pcap | 4 | on | 3 | 4259 | 22 | 18 | 2.636 | 1615705.6
pq_ech_chrome.pcap | 1 | off | 3 | 4259 | 22 | 19 | 2.300 | 1851739.1
pq_ech_chrome.pcap | 1 | on | 3 | 4259 | 22 | 18 | 2.387 | 1784248.0
pq_ech_chrome.pcap | 4 | on | 4 | 4259 | 22 | 18 | 2.584 | 1648219.8
pq_ech_chrome.pcap | 1 | off | 4 | 4259 | 22 | 19 | 2.170 | 1962672.8
pq_ech_chrome.pcap | 1 | on | 4 | 4259 | 22 | 18 | 2.592 | 1643132.7
pq_ech_chrome.pcap | 4 | off | 4 | 4259 | 22 | 19 | 2.774 | 1535328.0
pq_ech_chrome.pcap | 1 | off | 5 | 4259 | 22 | 19 | 2.210 | 1927149.3
pq_ech_chrome.pcap | 1 | on | 5 | 4259 | 22 | 18 | 2.425 | 1756288.7
pq_ech_chrome.pcap | 4 | off | 5 | 4259 | 22 | 19 | 2.572 | 1655909.8
pq_ech_chrome.pcap | 4 | on | 5 | 4259 | 22 | 18 | 2.507 | 1698843.2
pq_ech_chrome.pcap | 1 | on | 6 | 4259 | 22 | 18 | 2.611 | 1631175.8
pq_ech_chrome.pcap | 4 | off | 6 | 4259 | 22 | 19 | 2.254 | 1889529.7
pq_ech_chrome.pcap | 4 | on | 6 | 4259 | 22 | 18 | 2.634 | 1616932.4
pq_ech_chrome.pcap | 1 | off | 6 | 4259 | 22 | 19 | 2.279 | 1868802.1
pq_ech_chrome.pcap | 4 | off | 7 | 4259 | 22 | 19 | 2.274 | 1872911.2
pq_ech_chrome.pcap | 4 | on | 7 | 4259 | 22 | 18 | 3.383 | 1258941.8
pq_ech_chrome.pcap | 1 | off | 7 | 4259 | 22 | 19 | 2.219 | 1919333.0
pq_ech_chrome.pcap | 1 | on | 7 | 4259 | 22 | 18 | 2.545 | 1673477.4

SOURCE CLAIM MAP
Architecture: engine/src/capture.cpp (WorkerContext, SPSCQueue, dispatch_handshake, run,
ingest_tcp_segment, maintenance, Impl::emit); include/tlsfp/capture.hpp and types.hpp.
Record semantics: engine/src/accumulator.cpp; parser.cpp explicit cross-record unsupported path.
Fingerprint serialization: engine/src/ja3.cpp and ja4.cpp; test_fingerprints.cpp known-answer cases.
Transport interpretation: engine/src/ja4t.cpp and capture.cpp reporting; testbed/ja4t_lab.py.
ECH envelope/findings: engine/src/ech_parser.cpp and ech_analysis.cpp; JSON writer in capture.cpp.
PQ groups/lengths/correlation: engine/include/tlsfp/pqtls_parser.hpp and src/pqtls_*.
CLI precedence: engine/src/main.cpp and CaptureEngine constructor (JSON always enables ECH).
Catalog behavior: engine/src/db.cpp; capture setup skips catalog entirely in quiet mode.
Original ECH provenance: experiments/ech/results/{build-record/build.json,corpus/manifest.json}.
Corpus counts/groups: experiments/ech/results/report/{summary.json,feature-groups.json,joined.csv}.
Bench comparison exclusions: code/benchmarks/results/comparison.csv and ECH_Main_Integration.md.
Counter discrepancy: pq-on.jsonl, affected client port 51676, reports tcp_gap and HRR limitation;
TShark -o tcp.reassemble_out_of_order:TRUE shows detached frame 26 before final ServerHello frame 29.
Author review must distinguish this documented transport boundary from an independently measured
fingerprint error rate or a confirmed universal defect. No engine changes were made.
-->

<!--
REFRESHED WORKERS 1 / 2 / 4 RECORD — historical baseline batch; superseded by the current-layout record below
Date: 2026-11-06 Asia/Kolkata. This batch replaces the earlier table; its 64 raw records
above remain historical evidence and were not pooled with these trials.
Evaluated engine revision: 1254a3f8c164ba0ffec3e3d265cc5536af5320dc.
Reused original Release executable SHA-256:
1e5ded7bd0345de7dc5ba2274f77f5e71bdb7cedf2a344ed51781fb660660d3a.
No rebuild or source change was used. macOS remains 27.0.1 build 26A434.
The working tree at measurement time is 2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1.
Compared engine blob inventories: its changes beyond the baseline are the PQ CLI/default
and worker-analysis gates in main.cpp, capture.cpp and capture.hpp, plus folder relocation.
That later executable was NOT used; its default PQ workload must not be mixed with the baseline.
Workload bytes match the original SHA-256 digests. They now reside in Phase 2/code/pcaps.
Actual quiet command, from the current repo root:
/private/tmp/cs331-final-report-1254a3f/release/tlsfp_phase2 -r "Phase 2/code/pcaps/<workload>" -q -j <1|2|4> <--no-ech|--ech>
No -t, -v, --json or catalog interaction. All runs use fresh subprocesses.
Each workload warms C0=(1,off), C1=(1,on), C2=(2,off), C3=(2,on), C4=(4,off), C5=(4,on)
once, then runs seven rounds, rotating that order left by (round-1) modulo 6.
Workload order: stress-distinct.pcap then pq_ech_chrome.pcap. All 96 invocations exited
successfully, with empty stderr. Round 0 denotes excluded warm-ups. No process affinity,
deliberate delays, parallel timing runs, builds or other verification during timing.
Elapsed-time boundary and rounding are the same as the original record above.
Temporary runner, JSON trials and summary: /private/tmp/cs331-final-report-workers124/.
Header: workload | workers | ech | round | packets | clients | ordinary_servers | elapsed_ms | pps
stress-distinct.pcap | 1 | off | 0 | 20000 | 10000 | 10000 | 83.047 | 240827.5
stress-distinct.pcap | 1 | on | 0 | 20000 | 10000 | 10000 | 62.532 | 319836.2
stress-distinct.pcap | 2 | off | 0 | 20000 | 10000 | 10000 | 35.353 | 565722.9
stress-distinct.pcap | 2 | on | 0 | 20000 | 10000 | 10000 | 65.967 | 303181.9
stress-distinct.pcap | 4 | off | 0 | 20000 | 10000 | 10000 | 30.665 | 652209.4
stress-distinct.pcap | 4 | on | 0 | 20000 | 10000 | 10000 | 67.382 | 296815.2
stress-distinct.pcap | 1 | off | 1 | 20000 | 10000 | 10000 | 62.215 | 321465.9
stress-distinct.pcap | 1 | on | 1 | 20000 | 10000 | 10000 | 62.225 | 321414.2
stress-distinct.pcap | 2 | off | 1 | 20000 | 10000 | 10000 | 35.488 | 563570.8
stress-distinct.pcap | 2 | on | 1 | 20000 | 10000 | 10000 | 68.210 | 293212.1
stress-distinct.pcap | 4 | off | 1 | 20000 | 10000 | 10000 | 26.559 | 753040.4
stress-distinct.pcap | 4 | on | 1 | 20000 | 10000 | 10000 | 68.791 | 290735.7
stress-distinct.pcap | 1 | on | 2 | 20000 | 10000 | 10000 | 62.433 | 320343.4
stress-distinct.pcap | 2 | off | 2 | 20000 | 10000 | 10000 | 35.546 | 562651.2
stress-distinct.pcap | 2 | on | 2 | 20000 | 10000 | 10000 | 73.973 | 270368.9
stress-distinct.pcap | 4 | off | 2 | 20000 | 10000 | 10000 | 24.681 | 810339.9
stress-distinct.pcap | 4 | on | 2 | 20000 | 10000 | 10000 | 65.479 | 305441.4
stress-distinct.pcap | 1 | off | 2 | 20000 | 10000 | 10000 | 61.694 | 324180.6
stress-distinct.pcap | 2 | off | 3 | 20000 | 10000 | 10000 | 35.108 | 569670.7
stress-distinct.pcap | 2 | on | 3 | 20000 | 10000 | 10000 | 64.320 | 310945.3
stress-distinct.pcap | 4 | off | 3 | 20000 | 10000 | 10000 | 26.705 | 748923.4
stress-distinct.pcap | 4 | on | 3 | 20000 | 10000 | 10000 | 63.298 | 315965.7
stress-distinct.pcap | 1 | off | 3 | 20000 | 10000 | 10000 | 61.837 | 323431.0
stress-distinct.pcap | 1 | on | 3 | 20000 | 10000 | 10000 | 65.564 | 305045.5
stress-distinct.pcap | 2 | on | 4 | 20000 | 10000 | 10000 | 65.565 | 305040.8
stress-distinct.pcap | 4 | off | 4 | 20000 | 10000 | 10000 | 26.024 | 768521.4
stress-distinct.pcap | 4 | on | 4 | 20000 | 10000 | 10000 | 65.220 | 306654.4
stress-distinct.pcap | 1 | off | 4 | 20000 | 10000 | 10000 | 62.959 | 317667.1
stress-distinct.pcap | 1 | on | 4 | 20000 | 10000 | 10000 | 61.521 | 325092.2
stress-distinct.pcap | 2 | off | 4 | 20000 | 10000 | 10000 | 35.104 | 569735.6
stress-distinct.pcap | 4 | off | 5 | 20000 | 10000 | 10000 | 25.574 | 782044.3
stress-distinct.pcap | 4 | on | 5 | 20000 | 10000 | 10000 | 66.963 | 298672.4
stress-distinct.pcap | 1 | off | 5 | 20000 | 10000 | 10000 | 61.466 | 325383.1
stress-distinct.pcap | 1 | on | 5 | 20000 | 10000 | 10000 | 64.383 | 310641.0
stress-distinct.pcap | 2 | off | 5 | 20000 | 10000 | 10000 | 34.716 | 576103.2
stress-distinct.pcap | 2 | on | 5 | 20000 | 10000 | 10000 | 65.117 | 307139.5
stress-distinct.pcap | 4 | on | 6 | 20000 | 10000 | 10000 | 65.854 | 303702.1
stress-distinct.pcap | 1 | off | 6 | 20000 | 10000 | 10000 | 62.484 | 320081.9
stress-distinct.pcap | 1 | on | 6 | 20000 | 10000 | 10000 | 62.397 | 320528.2
stress-distinct.pcap | 2 | off | 6 | 20000 | 10000 | 10000 | 35.554 | 562524.6
stress-distinct.pcap | 2 | on | 6 | 20000 | 10000 | 10000 | 65.495 | 305366.8
stress-distinct.pcap | 4 | off | 6 | 20000 | 10000 | 10000 | 26.246 | 762020.9
stress-distinct.pcap | 1 | off | 7 | 20000 | 10000 | 10000 | 61.394 | 325764.7
stress-distinct.pcap | 1 | on | 7 | 20000 | 10000 | 10000 | 63.371 | 315601.8
stress-distinct.pcap | 2 | off | 7 | 20000 | 10000 | 10000 | 35.056 | 570515.7
stress-distinct.pcap | 2 | on | 7 | 20000 | 10000 | 10000 | 63.699 | 313976.7
stress-distinct.pcap | 4 | off | 7 | 20000 | 10000 | 10000 | 26.323 | 759791.8
stress-distinct.pcap | 4 | on | 7 | 20000 | 10000 | 10000 | 64.490 | 310125.6
pq_ech_chrome.pcap | 1 | off | 0 | 4259 | 22 | 19 | 5.710 | 745884.4
pq_ech_chrome.pcap | 1 | on | 0 | 4259 | 22 | 18 | 2.427 | 1754841.4
pq_ech_chrome.pcap | 2 | off | 0 | 4259 | 22 | 19 | 2.109 | 2019440.5
pq_ech_chrome.pcap | 2 | on | 0 | 4259 | 22 | 18 | 2.398 | 1776063.4
pq_ech_chrome.pcap | 4 | off | 0 | 4259 | 22 | 19 | 2.116 | 2012759.9
pq_ech_chrome.pcap | 4 | on | 0 | 4259 | 22 | 18 | 5.015 | 849252.2
pq_ech_chrome.pcap | 1 | off | 1 | 4259 | 22 | 19 | 2.154 | 1977251.6
pq_ech_chrome.pcap | 1 | on | 1 | 4259 | 22 | 18 | 2.513 | 1694787.1
pq_ech_chrome.pcap | 2 | off | 1 | 4259 | 22 | 19 | 2.239 | 1902188.5
pq_ech_chrome.pcap | 2 | on | 1 | 4259 | 22 | 18 | 2.418 | 1761373.0
pq_ech_chrome.pcap | 4 | off | 1 | 4259 | 22 | 19 | 2.276 | 1871265.4
pq_ech_chrome.pcap | 4 | on | 1 | 4259 | 22 | 18 | 2.662 | 1599924.9
pq_ech_chrome.pcap | 1 | on | 2 | 4259 | 22 | 18 | 2.453 | 1736241.3
pq_ech_chrome.pcap | 2 | off | 2 | 4259 | 22 | 19 | 2.227 | 1912438.3
pq_ech_chrome.pcap | 2 | on | 2 | 4259 | 22 | 18 | 2.720 | 1565808.8
pq_ech_chrome.pcap | 4 | off | 2 | 4259 | 22 | 19 | 5.066 | 840702.7
pq_ech_chrome.pcap | 4 | on | 2 | 4259 | 22 | 18 | 5.269 | 808312.8
pq_ech_chrome.pcap | 1 | off | 2 | 4259 | 22 | 19 | 2.255 | 1888691.8
pq_ech_chrome.pcap | 2 | off | 3 | 4259 | 22 | 19 | 2.165 | 1967205.5
pq_ech_chrome.pcap | 2 | on | 3 | 4259 | 22 | 18 | 2.836 | 1501763.0
pq_ech_chrome.pcap | 4 | off | 3 | 4259 | 22 | 19 | 6.790 | 627245.9
pq_ech_chrome.pcap | 4 | on | 3 | 4259 | 22 | 18 | 2.586 | 1646945.1
pq_ech_chrome.pcap | 1 | off | 3 | 4259 | 22 | 19 | 2.142 | 1988328.7
pq_ech_chrome.pcap | 1 | on | 3 | 4259 | 22 | 18 | 2.509 | 1697489.0
pq_ech_chrome.pcap | 2 | on | 4 | 4259 | 22 | 18 | 2.454 | 1735533.8
pq_ech_chrome.pcap | 4 | off | 4 | 4259 | 22 | 19 | 2.294 | 1856582.4
pq_ech_chrome.pcap | 4 | on | 4 | 4259 | 22 | 18 | 2.585 | 1647582.2
pq_ech_chrome.pcap | 1 | off | 4 | 4259 | 22 | 19 | 2.160 | 1971759.3
pq_ech_chrome.pcap | 1 | on | 4 | 4259 | 22 | 18 | 2.480 | 1717338.7
pq_ech_chrome.pcap | 2 | off | 4 | 4259 | 22 | 19 | 2.253 | 1890368.4
pq_ech_chrome.pcap | 4 | off | 5 | 4259 | 22 | 19 | 2.294 | 1856582.4
pq_ech_chrome.pcap | 4 | on | 5 | 4259 | 22 | 18 | 2.602 | 1636817.8
pq_ech_chrome.pcap | 1 | off | 5 | 4259 | 22 | 19 | 2.196 | 1939435.3
pq_ech_chrome.pcap | 1 | on | 5 | 4259 | 22 | 18 | 3.286 | 1296104.7
pq_ech_chrome.pcap | 2 | off | 5 | 4259 | 22 | 19 | 2.712 | 1570427.7
pq_ech_chrome.pcap | 2 | on | 5 | 4259 | 22 | 18 | 3.206 | 1328446.7
pq_ech_chrome.pcap | 4 | on | 6 | 4259 | 22 | 18 | 2.823 | 1508678.7
pq_ech_chrome.pcap | 1 | off | 6 | 4259 | 22 | 19 | 2.271 | 1875385.3
pq_ech_chrome.pcap | 1 | on | 6 | 4259 | 22 | 18 | 2.472 | 1722896.4
pq_ech_chrome.pcap | 2 | off | 6 | 4259 | 22 | 19 | 2.268 | 1877866.0
pq_ech_chrome.pcap | 2 | on | 6 | 4259 | 22 | 18 | 2.559 | 1664322.0
pq_ech_chrome.pcap | 4 | off | 6 | 4259 | 22 | 19 | 2.270 | 1876211.5
pq_ech_chrome.pcap | 1 | off | 7 | 4259 | 22 | 19 | 2.233 | 1907299.6
pq_ech_chrome.pcap | 1 | on | 7 | 4259 | 22 | 18 | 2.408 | 1768687.7
pq_ech_chrome.pcap | 2 | off | 7 | 4259 | 22 | 19 | 2.157 | 1974501.6
pq_ech_chrome.pcap | 2 | on | 7 | 4259 | 22 | 18 | 2.577 | 1652696.9
pq_ech_chrome.pcap | 4 | off | 7 | 4259 | 22 | 19 | 2.373 | 1794774.5
pq_ech_chrome.pcap | 4 | on | 7 | 4259 | 22 | 18 | 2.589 | 1645036.7

VALIDATION
All eight timed runs per configuration (including warm-up) preserve its expected counts.
Stress: (packets, clients, ordinary servers) = (20000,10000,10000) at every setting.
PQ capture: (4259,22,19) ECH-off; (4259,22,18) ECH-on, for each worker count.
The existing unequal-work/reordering caveat is retained; no between-mode speedup claimed there.
Workers=2 also replayed all 12 saved captures with -q -t --json. After capture_id removal,
ordered JSON equals the previous Release workers=1 output on every capture; previous checks
already established Release workers=4 and Debug workers=4 parity. Temporary symlinks restore
baseline relative filenames, so capture_source did not need normalization. Source PCAP hashes
were checked before each replay. This is a new worker-count replay check, not a rerun of CTest.
Author edits confirming the same collection host and clarifying VII.B were retained.
Only report.md changed in the repository. The Word document remains untouched.
-->

<!--
CURRENT LAYOUT VERIFICATION — source for the current report and VII.C table
Date: 2026-11-06 Asia/Kolkata. Base HEAD: 2f4a78bbf49b4b8e91ca919ecad86b9b79aa7ff1.
Tested source is the base plus local layout fixes. No claim is made that these fixes
are already present in that published commit; record their final commit after review.
All earlier benchmark records above are historical and are not pooled with this batch.
Engine SHA-256: e077099fa8ac14c6873051323044b9296c8dfd7e4672ce9b7a6fbb394f14a4e4.
Binary: /private/tmp/cs331-layout-fix/phase2-release/tlsfp_phase2.
Current runner: Phase 2/code/testbed/benchmark_modes.py; every invocation uses --pq.
One warm-up per configuration, seven rotating measured rounds; worker counts 1/2/4.
Each workload uses C0=(1,off), C1=(1,on), C2=(2,off), C3=(2,on), C4=(4,off), C5=(4,on).
Warm all once; rotate measured round order left by (round-1) modulo 6. No parallel trials.
No builds or verification ran during this batch. No CPU affinity, frequency lock or host-load
control was applied; the large observed ranges are retained rather than filtered.
Raw emitted timing values follow; repeat 0 is the excluded warm-up.
workload | workers | ech | repeat | packets | clients | ordinary_servers | elapsed_ms | pps
stress-distinct.pcap | 1 | off | 0 | 20000 | 10000 | 10000 | 69.257 | 288779.5
stress-distinct.pcap | 1 | on | 0 | 20000 | 10000 | 10000 | 81.906 | 244182.4
stress-distinct.pcap | 2 | off | 0 | 20000 | 10000 | 10000 | 45.637 | 438240.9
stress-distinct.pcap | 2 | on | 0 | 20000 | 10000 | 10000 | 75.580 | 264620.3
stress-distinct.pcap | 4 | off | 0 | 20000 | 10000 | 10000 | 34.196 | 584863.7
stress-distinct.pcap | 4 | on | 0 | 20000 | 10000 | 10000 | 77.668 | 257506.3
stress-distinct.pcap | 1 | off | 1 | 20000 | 10000 | 10000 | 67.097 | 298075.9
stress-distinct.pcap | 1 | on | 1 | 20000 | 10000 | 10000 | 97.631 | 204853.0
stress-distinct.pcap | 2 | off | 1 | 20000 | 10000 | 10000 | 39.190 | 510334.3
stress-distinct.pcap | 2 | on | 1 | 20000 | 10000 | 10000 | 83.754 | 238794.6
stress-distinct.pcap | 4 | off | 1 | 20000 | 10000 | 10000 | 24.188 | 826856.3
stress-distinct.pcap | 4 | on | 1 | 20000 | 10000 | 10000 | 110.906 | 180332.9
stress-distinct.pcap | 1 | on | 2 | 20000 | 10000 | 10000 | 66.072 | 302700.1
stress-distinct.pcap | 2 | off | 2 | 20000 | 10000 | 10000 | 37.516 | 533105.9
stress-distinct.pcap | 2 | on | 2 | 20000 | 10000 | 10000 | 69.434 | 288043.3
stress-distinct.pcap | 4 | off | 2 | 20000 | 10000 | 10000 | 26.762 | 747328.3
stress-distinct.pcap | 4 | on | 2 | 20000 | 10000 | 10000 | 95.983 | 208370.2
stress-distinct.pcap | 1 | off | 2 | 20000 | 10000 | 10000 | 88.717 | 225435.9
stress-distinct.pcap | 2 | off | 3 | 20000 | 10000 | 10000 | 52.642 | 379924.8
stress-distinct.pcap | 2 | on | 3 | 20000 | 10000 | 10000 | 96.181 | 207941.3
stress-distinct.pcap | 4 | off | 3 | 20000 | 10000 | 10000 | 35.377 | 565339.1
stress-distinct.pcap | 4 | on | 3 | 20000 | 10000 | 10000 | 144.937 | 137991.0
stress-distinct.pcap | 1 | off | 3 | 20000 | 10000 | 10000 | 78.565 | 254566.3
stress-distinct.pcap | 1 | on | 3 | 20000 | 10000 | 10000 | 66.636 | 300138.1
stress-distinct.pcap | 2 | on | 4 | 20000 | 10000 | 10000 | 84.352 | 237101.7
stress-distinct.pcap | 4 | off | 4 | 20000 | 10000 | 10000 | 33.258 | 601359.1
stress-distinct.pcap | 4 | on | 4 | 20000 | 10000 | 10000 | 430.765 | 46429.0
stress-distinct.pcap | 1 | off | 4 | 20000 | 10000 | 10000 | 95.525 | 209369.3
stress-distinct.pcap | 1 | on | 4 | 20000 | 10000 | 10000 | 87.125 | 229555.2
stress-distinct.pcap | 2 | off | 4 | 20000 | 10000 | 10000 | 43.827 | 456339.7
stress-distinct.pcap | 4 | off | 5 | 20000 | 10000 | 10000 | 29.504 | 677874.2
stress-distinct.pcap | 4 | on | 5 | 20000 | 10000 | 10000 | 139.108 | 143773.2
stress-distinct.pcap | 1 | off | 5 | 20000 | 10000 | 10000 | 94.869 | 210817.0
stress-distinct.pcap | 1 | on | 5 | 20000 | 10000 | 10000 | 89.265 | 224052.0
stress-distinct.pcap | 2 | off | 5 | 20000 | 10000 | 10000 | 40.963 | 488245.5
stress-distinct.pcap | 2 | on | 5 | 20000 | 10000 | 10000 | 106.169 | 188378.9
stress-distinct.pcap | 4 | on | 6 | 20000 | 10000 | 10000 | 107.607 | 185861.5
stress-distinct.pcap | 1 | off | 6 | 20000 | 10000 | 10000 | 75.704 | 264186.8
stress-distinct.pcap | 1 | on | 6 | 20000 | 10000 | 10000 | 97.116 | 205939.3
stress-distinct.pcap | 2 | off | 6 | 20000 | 10000 | 10000 | 51.236 | 390350.5
stress-distinct.pcap | 2 | on | 6 | 20000 | 10000 | 10000 | 90.534 | 220911.5
stress-distinct.pcap | 4 | off | 6 | 20000 | 10000 | 10000 | 32.816 | 609458.8
stress-distinct.pcap | 1 | off | 7 | 20000 | 10000 | 10000 | 77.501 | 258061.2
stress-distinct.pcap | 1 | on | 7 | 20000 | 10000 | 10000 | 86.810 | 230388.2
stress-distinct.pcap | 2 | off | 7 | 20000 | 10000 | 10000 | 37.846 | 528457.4
stress-distinct.pcap | 2 | on | 7 | 20000 | 10000 | 10000 | 107.563 | 185937.5
stress-distinct.pcap | 4 | off | 7 | 20000 | 10000 | 10000 | 62.783 | 318557.6
stress-distinct.pcap | 4 | on | 7 | 20000 | 10000 | 10000 | 124.347 | 160840.2
pq_ech_chrome.pcap | 1 | off | 0 | 4259 | 22 | 19 | 3.691 | 1153887.8
pq_ech_chrome.pcap | 1 | on | 0 | 4259 | 22 | 18 | 3.745 | 1137249.7
pq_ech_chrome.pcap | 2 | off | 0 | 4259 | 22 | 19 | 3.798 | 1121379.7
pq_ech_chrome.pcap | 2 | on | 0 | 4259 | 22 | 18 | 3.753 | 1134825.5
pq_ech_chrome.pcap | 4 | off | 0 | 4259 | 22 | 19 | 9.455 | 450449.5
pq_ech_chrome.pcap | 4 | on | 0 | 4259 | 22 | 18 | 3.447 | 1235567.2
pq_ech_chrome.pcap | 1 | off | 1 | 4259 | 22 | 19 | 2.899 | 1469127.3
pq_ech_chrome.pcap | 1 | on | 1 | 4259 | 22 | 18 | 2.716 | 1568114.9
pq_ech_chrome.pcap | 2 | off | 1 | 4259 | 22 | 19 | 2.277 | 1870443.6
pq_ech_chrome.pcap | 2 | on | 1 | 4259 | 22 | 18 | 2.608 | 1633052.1
pq_ech_chrome.pcap | 4 | off | 1 | 4259 | 22 | 19 | 2.238 | 1903038.4
pq_ech_chrome.pcap | 4 | on | 1 | 4259 | 22 | 18 | 3.341 | 1274768.0
pq_ech_chrome.pcap | 1 | on | 2 | 4259 | 22 | 18 | 2.661 | 1600526.1
pq_ech_chrome.pcap | 2 | off | 2 | 4259 | 22 | 19 | 2.364 | 1801607.4
pq_ech_chrome.pcap | 2 | on | 2 | 4259 | 22 | 18 | 2.725 | 1562935.8
pq_ech_chrome.pcap | 4 | off | 2 | 4259 | 22 | 19 | 2.370 | 1797046.4
pq_ech_chrome.pcap | 4 | on | 2 | 4259 | 22 | 18 | 2.745 | 1551548.3
pq_ech_chrome.pcap | 1 | off | 2 | 4259 | 22 | 19 | 2.356 | 1807725.0
pq_ech_chrome.pcap | 2 | off | 3 | 4259 | 22 | 19 | 2.352 | 1810799.3
pq_ech_chrome.pcap | 2 | on | 3 | 4259 | 22 | 18 | 2.708 | 1572747.4
pq_ech_chrome.pcap | 4 | off | 3 | 4259 | 22 | 19 | 2.500 | 1703600.0
pq_ech_chrome.pcap | 4 | on | 3 | 4259 | 22 | 18 | 3.114 | 1367694.3
pq_ech_chrome.pcap | 1 | off | 3 | 4259 | 22 | 19 | 2.387 | 1784248.0
pq_ech_chrome.pcap | 1 | on | 3 | 4259 | 22 | 18 | 2.583 | 1648857.9
pq_ech_chrome.pcap | 2 | on | 4 | 4259 | 22 | 18 | 2.948 | 1444708.3
pq_ech_chrome.pcap | 4 | off | 4 | 4259 | 22 | 19 | 2.404 | 1771630.6
pq_ech_chrome.pcap | 4 | on | 4 | 4259 | 22 | 18 | 3.262 | 1305640.7
pq_ech_chrome.pcap | 1 | off | 4 | 4259 | 22 | 19 | 2.306 | 1846921.1
pq_ech_chrome.pcap | 1 | on | 4 | 4259 | 22 | 18 | 2.550 | 1670196.1
pq_ech_chrome.pcap | 2 | off | 4 | 4259 | 22 | 19 | 2.748 | 1549854.4
pq_ech_chrome.pcap | 4 | off | 5 | 4259 | 22 | 19 | 7.861 | 541788.6
pq_ech_chrome.pcap | 4 | on | 5 | 4259 | 22 | 18 | 2.883 | 1477280.6
pq_ech_chrome.pcap | 1 | off | 5 | 4259 | 22 | 19 | 2.356 | 1807725.0
pq_ech_chrome.pcap | 1 | on | 5 | 4259 | 22 | 18 | 2.858 | 1490202.9
pq_ech_chrome.pcap | 2 | off | 5 | 4259 | 22 | 19 | 2.333 | 1825546.5
pq_ech_chrome.pcap | 2 | on | 5 | 4259 | 22 | 18 | 2.627 | 1621241.0
pq_ech_chrome.pcap | 4 | on | 6 | 4259 | 22 | 18 | 3.305 | 1288653.6
pq_ech_chrome.pcap | 1 | off | 6 | 4259 | 22 | 19 | 2.599 | 1638707.2
pq_ech_chrome.pcap | 1 | on | 6 | 4259 | 22 | 18 | 2.845 | 1497012.3
pq_ech_chrome.pcap | 2 | off | 6 | 4259 | 22 | 19 | 2.734 | 1557790.8
pq_ech_chrome.pcap | 2 | on | 6 | 4259 | 22 | 18 | 2.650 | 1607169.8
pq_ech_chrome.pcap | 4 | off | 6 | 4259 | 22 | 19 | 2.328 | 1829467.4
pq_ech_chrome.pcap | 1 | off | 7 | 4259 | 22 | 19 | 2.311 | 1842925.1
pq_ech_chrome.pcap | 1 | on | 7 | 4259 | 22 | 18 | 2.582 | 1649496.5
pq_ech_chrome.pcap | 2 | off | 7 | 4259 | 22 | 19 | 3.043 | 1399605.7
pq_ech_chrome.pcap | 2 | on | 7 | 4259 | 22 | 18 | 3.054 | 1394564.5
pq_ech_chrome.pcap | 4 | off | 7 | 4259 | 22 | 19 | 6.255 | 680895.3
pq_ech_chrome.pcap | 4 | on | 7 | 4259 | 22 | 18 | 3.146 | 1353782.6

ENGINE SOURCE DIGESTS
Phase 2/code/engine/CMakeLists.txt | d0a6dff06c4bbc322eb033beb906a28f9539349a5a2318e36cc6cb369e37027c
Phase 2/code/engine/include/tlsfp/accumulator.hpp | c6b0fec0a842474b5346ba5523b3af3c2fb0663f3ce062052ec85b3b03ed85ce
Phase 2/code/engine/include/tlsfp/byte_reader.hpp | bf3f720d34b3a5009a5b919e7e7e431cf42c683b17f9699a72045b1ceef8bfae
Phase 2/code/engine/include/tlsfp/capture.hpp | a1fa8db9a21ca3b6d194c3ff3f114dc12c42a042b6f891499e9afede14e6f569
Phase 2/code/engine/include/tlsfp/db.hpp | ea541b922d5a7cdd8df4e3e068c3218b3232753fd1bc66250bb80dd94aa04c99
Phase 2/code/engine/include/tlsfp/ech_analysis.hpp | 7a18bc71dd3e320e151238a3c9b774604c00a7562ed0c611f08041db6166c4ae
Phase 2/code/engine/include/tlsfp/ech_parser.hpp | 23dac1d55a3fdadaa5256fd70854bb54918bbb624cb821e0fd4b18fed6c1a928
Phase 2/code/engine/include/tlsfp/ja3.hpp | f255edbee98d63edc6697f2a89b12eead805bb5710d452eb07ab71008334de3f
Phase 2/code/engine/include/tlsfp/ja4.hpp | 36a7361b26b75cd03c7a3890ed4466af13ff0fbe913ce5820b6715d500db2b18
Phase 2/code/engine/include/tlsfp/ja4t.hpp | f9e0e9dc5db4e672332b59651e888491a672aba381bac0cc3b4d92bd4b43e705
Phase 2/code/engine/include/tlsfp/parser.hpp | be266ae1fd13bca6d1a1d09764d181af653adc6f728c9e5dad089ecc7b1c56c1
Phase 2/code/engine/include/tlsfp/pqtls_analysis.hpp | 7884c4a17a2a932310abe058bb8aab3471291340610df9e91b5a6daa484c0422
Phase 2/code/engine/include/tlsfp/pqtls_parser.hpp | 0570c40f0d429d2ff4ef6748ac81522f8411eabaeb3da12281852a005ccba417
Phase 2/code/engine/include/tlsfp/types.hpp | 62bf293a495afcbe0001128a1345c427c4a636edba902da1dba7788ebefbd8d9
Phase 2/code/engine/src/accumulator.cpp | b171ab0eb140a18a0052740c00e6ab71f64c1a623b8bd9ec67a1872a1f81eec8
Phase 2/code/engine/src/capture.cpp | 5b2d55881d312419f2cfbe43255d687886bbf373a7a074163fd9561d98712b27
Phase 2/code/engine/src/db.cpp | f86e5624016c95bdc974243acf8e75b0bfa587032354f2be6420178298833db2
Phase 2/code/engine/src/ech_analysis.cpp | efa95983cb02df092a004c5146f9528e599c0f523d1813104f8754eba087de09
Phase 2/code/engine/src/ech_parser.cpp | 897a7e37aa94fc22c34f33fad1868b7a1554b4efc5c1264526a9eee90aa7ae74
Phase 2/code/engine/src/ja3.cpp | 79557f9dd2f31a5fe5f50c7af1be8ce4f6e0400588a26249d72731a22bc14091
Phase 2/code/engine/src/ja4.cpp | e433242ae4ea8d3aebe411d8bf0e20de620b08c9358840e3be250ca55f2bba79
Phase 2/code/engine/src/ja4t.cpp | 52d25e00a2fa40c820239b844b7b642edf98da786c3ac09cec2dfa14b1eeb4da
Phase 2/code/engine/src/main.cpp | 687008ca922829e7268361c9255ec7cf32eb055dbbf4072d5fc654afc535f711
Phase 2/code/engine/src/parser.cpp | bcbceb420d1257e1ca32c8cf1181cc82252b160270fd14d480e7a4437175d06d
Phase 2/code/engine/src/pqtls_analysis.cpp | fa626b4f6318d5a8b866fbe1778dd9e9baa942a559ffb82925c0e1ef7c5c2127
Phase 2/code/engine/src/pqtls_parser.cpp | 0239faee45b202129962971ac03e66710b6221a366caba228b5fb98052450ca7
Phase 2/code/engine/tests/fixtures/ech_fixtures.hpp | 74855a31ab77ccb97357255fdd5fe056e33b5cfec3f82e68618032a43108b21f
Phase 2/code/engine/tests/fixtures/pqtls_fixtures.hpp | 10e98b316d73795d496bcbabe6523081d123cd9e944a3a03c4ce06b49b1043eb
Phase 2/code/engine/tests/test_ech_analysis.cpp | 4f97f9bf2c1f85e4146d6f39a6bfc51a97e7c3923d4fe56859aa2560ae88953c
Phase 2/code/engine/tests/test_ech_connections.cpp | 7a3d009e5e98d7fefa6c7166acbc7fd0a9d8927104efcd26f01810f36c36f110
Phase 2/code/engine/tests/test_ech_parser.cpp | 629d439f8a58779415cffe9134fcef5fc4e2dd5c3c98f6ac39f13b5a8961f07a
Phase 2/code/engine/tests/test_fingerprints.cpp | f1ff7069f443eadbfea08261d44a2c4d7d1a3ffd56142f97ff84e353b3a6382a
Phase 2/code/engine/tests/test_ja4t.cpp | 7ed3ab86595efd6fd670f7888d4c6042104a8b9e6b730e923c157ea594acbdb8
Phase 2/code/engine/tests/test_pqtls_analysis.cpp | 5e12b4077de650656fc0fa0d1927311bd16c17b21cd6f43cd7544733d46f89aa
Phase 2/code/engine/tests/test_pqtls_parser.cpp | 306e423b557f30edf0c44e0fe49798fdb5324d60ebb9a3f1aa065244601b81b2

CHECKS AFTER LAYOUT FIXES
Phase 2: 189/189 CTest entries in Release and ASan/UBSan Debug.
Phase 1 C++: 51/51 entries; offline test build reused local GoogleTest 1.14.0 source
instead of downloading the older declared Phase 1 dependency. No Phase 1 test edits.
Phase 1 Python: 56/56 from the repository root. ECH lab: 17/17.
JA4T: 19/19 freshly generated cases; fixed Ethernet addresses avoid neighbor discovery.
Catalog integration: both C++ libraries load 222 records and known labels from repository
root, both phase directories and an unrelated temporary directory using isolated Redis.
Phase 2 file-backed catalog loading is also exercised with Redis disabled by CTest.
GUI: constructs offscreen with the relocated file-backed catalog; no interactive flow tested.
ECH build runner completes from the relocated directory using the exact clean existing
BoringSSL pin and local GoogleTest sources, with fresh dependency/lab/engine builds.
ECH pilot/corpus offline replay and original saved report regeneration succeed.
48 replays: 12 saved captures x Release workers 1/2/4 and Debug workers 4. All preserve
prior JSON after normalizing capture_id and capture_source; input SHA-256 is checked.
Current-engine endpoint joins reproduce the original 60 accepted connections and summary.
No fresh endpoint capture, hardware-LRO validation, Linux/Windows test or latency evaluation.
Original results, manifests and PCAPs are unchanged. report.docx SHA-256 remains
68c2bc614a7fc9d6eaf184bb9164640a7cd77da46fdc05a02ea2d1040485f2ab.
Temporary logs, checksums and JSON results: /private/tmp/cs331-layout-fix/.
-->

<!--
CANONICAL WORKFLOW CHECKS
The documented build/phase2 location also configures, builds and passes 189 CTest entries.
The documented build/phase1 location builds and passes 51 CTest entries (local GoogleTest
1.14.0 source override used for the offline check). ECH runner build, corpus/pilot replay,
and report stages complete from the current source paths. Benchmark runner correctly
refuses an existing output directory before changing its contents.
-->
