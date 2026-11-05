# ECH checkpoint 1: decode and inspect

This checkpoint adds passive ClientHello ECH envelope decoding to `tlsfp_phase2`.
The new information is visible with the existing `-v` option. Offer type remains
`unknown` and acceptance remains `unverified`; neither a recognizable suite nor
the outer SNI establishes real ECH, GREASE, or acceptance.

## Build and run

Run these commands from the `TLS-Fingerprinting` repository root. Dependencies
are the existing C++17 compiler, CMake, libpcap, OpenSSL, and GoogleTest. GoogleTest
1.18.0 was installed locally to resolve the missing build dependency.

```sh
cmake -S 'Phase 2/engine' -B 'Phase 2/engine/build' -DCMAKE_BUILD_TYPE=Release
cmake --build 'Phase 2/engine/build' -j 4
ctest --test-dir 'Phase 2/engine/build' --output-on-failure

'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/chrome.pcap -v
'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/curl.pcap -v
'Phase 2/engine/build/tlsfp_phase2' -r 'Phase 2/engine/tests/fixtures/ech_checkpoint1.pcap' -v
```

The synthetic PCAP is checked in, so replay and C++ tests require no Python.
To regenerate it, use the existing project environment (from the same directory):

```sh
../.venv/bin/python 'Phase 2/engine/tests/fixtures/generate_ech_fixture.py'
```

Do not substitute global Python or create an environment if this one is absent.
The generator uses only the standard library and makes no network requests.

## Manual check 1: compare an actual envelope with Wireshark

Open `code/pcaps/chrome.pcap` in Wireshark and select frame 6. Expand
TLS → Client Hello → encrypted_client_hello. The matching engine observation has
outer random:

```text
602711cb9199d65800d3f5af27bfc8d6369cf49af0ebe316d67cdf6f80fee6cd
```

Expected output:

```text
[V-ClientHello] status=complete (complete ClientHello framing)
[V-ECH] presence=present occurrences=1
[V-ECH #1] status=complete (decoded) variant=0 kdf_id=1 aead_id=1 config_id=139 enc_length=32 ciphertext_length=208
[V-ECH findings] none
[V-ECH interpretation] offer_type=unknown acceptance=unverified
```

The visible **outer SNI** is `www.cloudflare.com`. The engine does not recover an
inner name. The record is 1990 bytes including its five-byte header, accumulated
from TCP payloads of 1388 and 602 bytes in frames 5 and 6. This saved capture
validates that particular segmented path, rather than general TCP reconstruction.

The ECH extension type/length header is `fe 0d 00 fa`. Offsets below begin at the
extension **body**, after that header. Multi-byte integers are big-endian.

| Body offset | Field | Expected wire value |
|---|---|---|
| 0 | Variant | `00` (outer) |
| 1–2 | KDF ID | `00 01` |
| 3–4 | AEAD ID | `00 01` |
| 5 | Configuration ID | `8b` (139) |
| 6–7 | Encapsulation length | `00 20` (32) |
| 8–39 | Encapsulation | 32 bytes, skipped after checking bounds |
| 40–41 | Ciphertext length | `00 d0` (208) |
| 42–249 | Ciphertext | 208 bytes, skipped after checking bounds |

The 250-byte body is fully consumed: `1 + 2 + 2 + 1 + 2 + 32 + 2 + 208`.
These are the [RFC 9849 §5](https://www.rfc-editor.org/rfc/rfc9849.html#section-5)
fields. The envelope contains no KEM identifier. No KEM or padding-policy guess
is made in this checkpoint.

For a command-line cross-check:

```sh
tshark -r code/pcaps/chrome.pcap -Y 'frame.number == 6' -V
```

Use Wireshark to compare the ECH envelope fields. Its JA4 implementation can
differ from this engine's existing behavior; checkpoint validation compares the
engine's fingerprints before and after this change.

## Manual check 2: absence and independent findings

`code/pcaps/curl.pcap`, frame 4, must show `presence=absent occurrences=0` after
complete extension traversal. The synthetic PCAP uses documentation IP addresses,
has ten fabricated packets, and contains these cases:

| Frame | TCP source port | Expected result |
|---|---|---|
| 1 | 41001 | Valid outer envelope, IDs/lengths matching the example above |
| 2 | 41002 | Two separately printed envelopes, config IDs 139 and 7; `duplicate_ech` |
| 3 | 41003 | Complete hello framing; ECH body `malformed` because ciphertext is empty |
| 4 | 41004 | Contradictory complete extension framing; presence retained; fingerprints suppressed |
| 5 | 41005 | Certificate compression (`0x001b`) alone; ECH absent |
| 6 | 41006 | Duplicate ECH, forbidden `0xfd00`, external inner marker, export-only AEAD: all four findings coexist |
| 7 | 41007 | Empty `enc` decoded; `empty_enc_context_unknown` |
| 8–9 | 41008 | Hello spans TLS records; `unsupported`; no partial fingerprint |
| 10 | 41009 | 8193-byte record exceeds supported limit; TLS-record `unsupported` diagnostic |

Frame 3 may still produce outer fingerprints: all bytes needed for those
fingerprints were observed. Frame 4 cannot, because the shared extension vector
could not be traversed. Findings are additional observations; they never overwrite
a decoded body or select one duplicate as authoritative.

## Contracts and current limits

- `parse_client_hello` retains its boolean interface. Inspect `parse_status` and
  `parse_detail` on failure. A true result means complete shared framing, rather
  than complete semantic validation of every TLS extension.
- ECH presence is optional: unknown, present, or absent. Each occurrence has its
  own body-decoding status and optional numeric fields. Real zero values remain
  distinguishable from unknown. Findings are an independent bitmask.
- Capture truncation yields `incomplete` at the parser API. Complete contradictory
  framing yields `malformed`. A record-spanning hello or a record above 8192 bytes
  including its header yields `unsupported`. The same size ceiling applies to
  fast, segmented, and split-record-header accumulator paths.
- Detailed incomplete outcomes exist at the parser API; the CLI still receives
  only delivered records and size-limit notifications. Pending/gapped/expired
  accumulation does not yet emit a connection summary. Such silence establishes
  neither ECH absence nor malformed ECH. Checkpoint 2 adds lifecycle reporting.
- An optional accumulator limit callback reports unsupported records without
  retaining their bytes. A short header may not establish the handshake type,
  so its diagnostic says **TLS record**, rather than claiming ClientHello/ECH.
- Outer random and ECH numeric observations own their retained data. Existing
  SNI/ALPN views remain valid only during immediate record processing.
- Analysis runs after traversal. Empty `enc` is allowed structurally. The analysis
  API accepts a known hello role, but capture uses `Unknown` until connection
  correlation exists. No single-hello observation proves HRR acceptance.
- Connection correlation, JSON summaries, broader record processing, endpoint
  labels, decryption, measurements, and HRR sequence analysis are later work.

## Validation record — November 1, 2026

All **76 tests pass** in Release and in Debug with AddressSanitizer and
UndefinedBehaviorSanitizer enabled. The seven baseline captures also replay
cleanly under those sanitizers. This includes 37 new ECH/parser/replay checks;
the original 39 remain green with size-preserving valid padding fixtures.

Debug compile and sanitizer-runtime flags now propagate to executable consumers
of the static engine library. The prebuilt Homebrew GoogleTest produced an ASan
container-annotation failure during test discovery, before project tests ran.
For the successful sanitizer run, official GoogleTest 1.18.0 source was built
with the same AppleClang 21 compiler and `-fsanitize=address,undefined` flags,
installed under `/private/tmp/cs331-gtest-sanitized`, and selected using:

```sh
cmake -S 'Phase 2/engine' -B /private/tmp/cs331-ech-debug-build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DGTest_DIR=/private/tmp/cs331-gtest-sanitized/lib/cmake/GTest
cmake --build /private/tmp/cs331-ech-debug-build -j 4
ctest --test-dir /private/tmp/cs331-ech-debug-build --output-on-failure
```

That temporary GoogleTest installation is local validation setup, not a new
repository dependency or an automatic download. On another machine, use a
GoogleTest build compatible with its compiler and sanitizer settings.

The original 39 tests passed before changes. Baseline sources were copied from
the clean `6c466cf` working tree and built separately. Fingerprint-bearing output,
including ordered endpoint observations, was compared against the new binary:

| Saved capture | Fingerprint values compared | Result |
|---|---:|---|
| cloudflare_run1.pcap | 44 | Identical |
| curl.pcap | 4 | Identical |
| python_requests.pcap | 4 | Identical |
| custom_client.pcap | 4 | Identical |
| chrome.pcap | 16 | Identical |
| chrome_run2.pcap | 12 | Identical |
| test_ja3.pcap | 12 | Identical |
| **Total** | **96** | **Identical** |

This is engine regression parity, not new independent validation of fingerprint
specifications or ECH acceptance. Synthetic cases establish parser/rule behavior;
the saved Chrome envelope supplies a real wire-field comparison.
