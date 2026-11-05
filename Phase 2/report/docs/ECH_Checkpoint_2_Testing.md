> Historical project notes: commands, paths and test counts describe the recorded revision. For the current repository layout and runnable commands, use the [phase README](../../README.md).

# ECH checkpoint 2: correlate and summarize

Checkpoint 2 joins the first ClientHello with its final ServerHello and writes
one JSON object per tracked TLS connection generation. The terminal view remains
available alongside the file. A complete hello pair does not establish successful
TLS completion, real ECH, or acceptance.

## Build and manual replay

From the `TLS-Fingerprinting` repository root:

```sh
cmake -S 'Phase 2/engine' -B 'Phase 2/engine/build' -DCMAKE_BUILD_TYPE=Release
cmake --build 'Phase 2/engine/build' -j 4
ctest --test-dir 'Phase 2/engine/build' --output-on-failure

'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/chrome.pcap -v --json /tmp/ech-chrome-cp2.jsonl
'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/curl.pcap -v --json /tmp/ech-curl-cp2.jsonl
'Phase 2/engine/build/tlsfp_phase2' -r 'Phase 2/engine/tests/fixtures/ech_checkpoint2.pcap' -v --json /tmp/ech-synthetic-cp2.jsonl
```

Choose unused output filenames: `--json` creates a new file and refuses to
replace existing files. `-q` suppresses the detailed terminal view while retaining
explicitly requested JSON output; the existing benchmark footer still appears.
Open failures stop capture, and write failures make the command exit unsuccessfully.
Each completed line is written immediately. A failed write can leave a partial
last line; preserve the failure status when consuming such a file.

To pretty-print a replay with the existing project environment:

```sh
../.venv/bin/python -m json.tool --json-lines /tmp/ech-chrome-cp2.jsonl
```

No Python is required for the binary, fixture replay, or C++ tests. Use an existing
`.venv` for optional inspection/regeneration; do not substitute global Python.

### 1. Saved Chrome capture

Expect **four summaries**, each with `completion_reason: "final_server_hello"`,
`complete_hello_pair: true`, and negotiated version **772 / 0x0304 / TLS 1.3**.
All retain `offer_type: "unknown"` and `acceptance: "unverified"`.

For TCP client port **51984**, the ClientHello outer random is:

```text
602711cb9199d65800d3f5af27bfc8d6369cf49af0ebe316d67cdf6f80fee6cd
```

Its ECH envelope remains KDF 1, AEAD 1, config ID 139, `enc_length` 32 and
`ciphertext_length` 208. Compare frame 6's ClientHello and frame 14's ServerHello
in Wireshark; both belong to TCP stream 0. The other configuration IDs are 143,
178 and 140, correlated by their endpoint tuples rather than packet adjacency.

This capture contains an important limit demonstration: frame 12 is a later
server TCP segment captured before the SYN-aligned server prefix in frame 14.
The engine records `pre_tls_sequence_gap` as incomplete transport evidence and
waits for the exact SYN-derived sequence number before choosing a TLS boundary.
Frame 14 contains the whole ServerHello, so the hello pair is complete even
though a transport gap was observed. No detached bytes are reordered or guessed.
If that hello needed discarded bytes, it would remain incomplete.

### 2. Saved curl capture

Expect **one complete paired summary**, with `client.ech.presence: false`.
Absence follows complete ClientHello extension traversal. A missing or partial
ClientHello instead has `presence: null` and no partial client fingerprints.

### 3. Synthetic exchanges

The checked-in 50-packet fixture produces **11 summaries**, seven with complete
hello pairs. Synthetic packets establish rule behavior, not endpoint labels or
real-world ECH acceptance. Source ports identify these cases:

| Client port | Expected observation |
|---|---|
| 41011 | ECH present + TLS 1.2: `non_acceptance_observed`, evidence `I3_negotiated_below_tls13` |
| 41012 | ECH present + TLS 1.3: acceptance remains `unverified` |
| 41013 | Complete ECH absence, paired with TLS 1.3 |
| 41014 | Segmented hello, overlap, complete retransmission, then CCS + ServerHello: one paired summary |
| 41015 | Gap inside unfinished ClientHello: incomplete client, unknown presence, complete server; no I3 |
| 41016 | Unfinished record at EOF: `end_of_capture`, incomplete client and unknown presence |
| 41017 | HRR and second ClientHello: wait for final server; keep CH1 config ID 139 rather than CH2 ID 7 |
| 41018 | Detached server bytes precede the exact SYN-aligned hello: paired hello with transport gap noted |
| 41019 | Complete client followed by FIN: one unpaired summary with reason `fin` |
| 41020 | RST followed by a fresh SYN using the same tuple/ISN: two separate generations |

The HRR case sets `server.hrr_seen: true` and the limitation
`hrr_sequence_not_analyzed`. It performs no I1/I2 inference. The EOF summary may
appear after higher connection IDs because output follows completion order.
Connection IDs also count SYN-only tracking; they need not be contiguous in JSON.

To regenerate the fixture deterministically:

```sh
../.venv/bin/python 'Phase 2/engine/tests/fixtures/generate_ech_connections.py'
```

The checkpoint-1 fixture generator now accepts optional packet direction/flags;
its defaults regenerate the original checkpoint-1 PCAP byte for byte.

## JSON contract and interpretation

`schema_version` is 1. Every line has:

| Group | Fields and meaning |
|---|---|
| Identity | `capture_id`, `connection_id`, `capture_source`; capture ID is generated once per engine instance |
| Endpoints | `ip_version`, canonical `endpoint_a`/`endpoint_b`, and `client_endpoint` (`a`, `b`, or null) |
| Time/lifecycle | Unix microsecond `first_observation_us`/`last_observation_us`, `completion_reason`, `complete_hello_pair` |
| Client | Detailed framing status, owned outer random/SNI/ALPN, ECH presence/findings/occurrences, JA3/JA4 |
| Server | Detailed status, negotiated version, HRR-seen flag, final JA3S/JA4S |
| Interpretation | Unknown offer type, acceptance assessment, and named evidence |
| Limits | Analysis limitations and per-direction transport issues, each with its own status/reason |

Unknown values are JSON null, including missing numeric fields. Decoded zero
values remain numbers. Strings escape controls and invalid UTF-8 bytes while
preserving valid UTF-8. No ciphertext, keylog material, decrypted inner fields,
or independent experiment labels enter the summary.

Server version comes from an exactly two-byte, non-duplicate `supported_versions`
extension where present; otherwise it comes from the legacy version. Complete
contradictory server framing is malformed and supplies no server fingerprint or
negotiated-version evidence. Recognized TLS 1.0/1.1/1.2 negotiation after observed
ECH supplies I3 negative evidence; TLS 1.3 alone cannot establish acceptance.
See [RFC 9849 §6.1.4](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4).

Conflicting endpoint roles remain unknown. Unexpected additional ClientHellos
without HRR are flagged, and their acceptance interpretation abstains. A genuine
second ClientHello after a recognized HRR can appear in terminal fingerprint
output, but the connection summary deliberately retains CH1.

Immediate verbose ClientHello output still says acceptance is unverified: the
server has not yet supplied evidence. Read the later `[Connection summary]` line
or JSON `interpretation` for the correlated result.

## Supported transport and lifecycle limits

- Contiguous segments, overlaps, retransmissions after delivery, split headers,
  coalesced records and complete messages within one record are supported.
- Gaps after TLS framing starts stop that direction. Before framing starts, only
  the exact observed-SYN-derived prefix may anchor it; there is no reorder queue
  or general out-of-order recovery. The detached-prefix wait also expires.
- Hello messages spanning records and records above 8192 bytes including their
  headers are unsupported. Encrypted application records are not decoded as
  hellos. Compatibility CCS is validated and skipped in a retry context or a
  SYN-anchored server-start context with a TLS 1.3 offer. An offer alone cannot
  establish the negotiated version: unknown CCS context ends plaintext inspection
  conservatively, including possible TLS 1.2 encrypted Handshake-type records.
- The default cap is 1024 connection generations, including SYN hints and emitted
  completion markers. Buffers allocate only for partial records. Incomplete
  records expire after the existing three-second timeout; connection idle expiry
  is 30 seconds. Capacity eviction records `capacity_limit` for an unfinished TLS
  candidate. Non-TLS SYN-only entries produce no TLS summary.
- SYN retransmission preserves the current generation. A new ISN or SYN after
  closure starts another generation. FIN/RST payload is processed before closure.
- Summaries emit at final ServerHello, or at closure, replacement, expiry,
  eviction, EOF, interruption or capture error. Completed observations/buffers are
  released; only small lifecycle/sequence state remains until closure or expiry.
- The one-summary guarantee applies to a retained generation. Once its bounded
  state expires or is evicted, later traffic cannot always be linked to it.
- Offline expiry follows a nondecreasing packet-time watermark. Live capture uses
  nonblocking dispatch with 100 ms idle polling and periodic maintenance, even
  when no packet arrives. Idle expiry is tested with an injected monotonic clock;
  no live-interface validation is claimed by the offline tests.

## Implementation interfaces

`CaptureOptions` adds `json_filename`, `max_connections`,
`connection_timeout_seconds`, and optional `monotonic_clock` injection.
`CaptureEngine` exposes `ingest_tcp_segment`, `maintenance`, `finish_capture`, and
`retained_connection_count` for embedding and deterministic tests. These APIs
share the capture thread; `stop()` is the cross-thread stop request.

The accumulator retains compatible ready/limit callbacks, adds a structured issue
callback, and exposes directional start/stop/forget/invalidation operations.
`active_flow_count()` continues to mean unfinished buffers, not sequence markers.
ServerHello parsing keeps its boolean interface and adds detailed status, owned
random, and HRR metadata. I3 logic lives in the existing ECH analysis module.
Connection records/serialization remain in the existing capture implementation.

Endpoint labeling, measurements, QUIC, cross-record assembly, and positive HRR
acceptance inference remain outside checkpoint 2.

## Validation record — November 1, 2026

All **123 tests pass** in Release and ASan/UBSan Debug, including all 76
checkpoint-1 tests and 47 new checks. Idle expiry uses an injected clock; output
failure is exercised with a real file-size limit in a child process. A truncated
PCAP verifies capture-error finalization. Both synthetic generators reproduce
their checked-in PCAPs byte for byte.

The baseline was built separately from clean checkpoint-1 commit `ea68a83`.
Replay comparisons checked ordered endpoint/fingerprint observations. All
non-HRR fingerprint values match. JSON from Release and Debug was parsed with an
independent JSON reader and compared after normalizing the generated capture ID.
The same checks verified nulls, unique connection IDs, evidence abstention, source
paths containing Unicode, and refusal to replace an existing output file.

| Capture | CP1 fingerprint values | CP2 fingerprint values | Summaries | Complete hello pairs |
|---|---:|---:|---:|---:|
| cloudflare_run1.pcap | 44 | 38 | 29 | 8 |
| curl.pcap | 4 | 4 | 1 | 1 |
| python_requests.pcap | 4 | 4 | 1 | 1 |
| custom_client.pcap | 4 | 4 | 1 | 1 |
| chrome.pcap | 16 | 16 | 4 | 4 |
| chrome_run2.pcap | 12 | 12 | 3 | 3 |
| test_ja3.pcap | 12 | 12 | 3 | 3 |
| **Total** | **96** | **90** | **42** | **21** |

The Cloudflare count change is intentional: frames **47, 293 and 848** contain
the fixed HRR random. They previously produced six server fingerprint values
as if they were ordinary ServerHellos. An independent Wireshark/TShark extraction
of those frames accounts exactly for the removed observations. Final ServerHello
fingerprints are unchanged. The real retry ClientHello messages still retain
normal per-message terminal fingerprints.

Cloudflare also contains 21 unpaired TLS candidates. They remain visible in the
JSON rather than being counted as ECH absence, real-offer rejection, or acceptance.
This distinction separates capture coverage from the fingerprint regression check.
The 50-packet synthetic corpus separately yields 11 summaries, seven complete
pairs, one I3 observation, and one HRR sequence marked as unanalyzed.

The local sanitizer build uses the matching sanitized GoogleTest installation
prepared during checkpoint 1:

```sh
cmake -S 'Phase 2/engine' -B /private/tmp/cs331-cp2-debug-build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DGTest_DIR=/private/tmp/cs331-gtest-sanitized/lib/cmake/GTest
cmake --build /private/tmp/cs331-cp2-debug-build -j 4
ctest --test-dir /private/tmp/cs331-cp2-debug-build --output-on-failure
```

This validation establishes supported parsing, correlation, output behavior and
regression parity on these inputs. It establishes no ECH acceptance labels,
classification accuracy, general TCP reconstruction result, or live-capture result.
