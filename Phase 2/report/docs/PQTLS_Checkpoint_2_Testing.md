> Historical project notes: commands, paths and test counts describe the recorded revision. For the current repository layout and runnable commands, use the [phase README](../../README.md).

# PQ-TLS checkpoint 2: wire checks and real-capture validation

Builds on checkpoint 1 (`PQTLS_Checkpoint_1_Testing.md`). This checkpoint adds the
wire checks from `PQTLS_DeepDive_and_Integration_Strategy.md` section 5.6 and the
"exact key share sizing" item of Track C in `Phase2_Unified_End_Goal_and_Review_Charter.md`,
and validates the engine on the real capture `Phase 2/pcaps/pq_ech_chrome.pcap`.

## What is new

**Exact key size check (per direction).** Every PQ key is compared with its RFC 10024 size:

| Group | Client key (ML-KEM public key + EC) | Server key (ML-KEM ciphertext + EC) |
| :--- | ---: | ---: |
| `0x11ec` X25519MLKEM768 | 1184 + 32 = **1216 B** | 1088 + 32 = **1120 B** |
| `0x11eb` SecP256r1MLKEM768 | 1184 + 65 = **1249 B** | 1088 + 65 = **1153 B** |
| `0x11ed` SecP384r1MLKEM1024 | 1568 + 97 = **1665 B** | 1568 + 97 = **1665 B** |
| `0x6399` / `0x639a` (Kyber-768 drafts) | 1216 B / 1249 B | 1120 B / 1153 B |

A different size gives `PQC_MALFORMED_SHARE_LENGTH`. Classical keys are not size-checked.
A HelloRetryRequest carries no key, so it is not size-checked.

**Duplicate extension guard (RFC 8446 section 4.2).** A second `key_share` (0x0033) in a
ClientHello or ServerHello, or a second `supported_groups` (0x000a) in a ClientHello,
gives `PQC_DUPLICATE_EXTENSION`. For `key_share` the first one is kept and the second is
ignored. (`supported_groups` itself is filled by the shared parser, which adds both lists;
we only flag it.)

**Output:** one new verbose line after the client lines and after the server lines:

```text
[V-PQTLS-Check]  ok
[V-PQTLS-Check]  PQC_MALFORMED_SHARE_LENGTH (0x11ec sent 1000B, expected 1216B)
[V-PQTLS-Check]  PQC_DUPLICATE_EXTENSION (key_share twice)
[V-PQTLS-Check]  PQC_MALFORMED_KEY_SHARE (key_share framing invalid)
```

**Code:** `pqtls_expected_client_len/server_len`, `pqtls_client_findings/server_findings`
and the check text in `pqtls_analysis.cpp`; duplicate flags in `pqtls_parser.cpp`
(`find_pqtls_group` now also receives the extension list). Shared files: only the two
`print_pqtls_*` functions and the `pqtls_posture(...)` call in `capture.cpp`, and one hook
argument in `parser.cpp` changed.

## Correctness fixes after review

A review of this checkpoint found that observations, validation results and final labels
were not fully connected. Three fixes:

1. **Server key_share framing is validated.** `parse_pqtls_server_key_share` now sets
   `key_share_parsed` only if the bytes match the layout exactly: for a ServerHello,
   group + length + *that many key bytes* + nothing after; for a HelloRetryRequest, the
   2-byte group only. Before, a ServerHello declaring `0x11ec` and 1120 B with no key
   bytes gave `ok` and `HYBRID_SELECTED_OBSERVED`. Now it gives `PQC_MALFORMED_KEY_SHARE`
   and `UNKNOWN (server selection not established)`.
2. **`PROACTIVE_SHARE_VALID` uses the exact size table.** The old `>= 1200 B` rule is gone.
   The share label and the size check now use the same `pqtls_expected_client_len` table,
   so a 1200 B X25519MLKEM768 key can no longer be "valid" while also flagged as
   `PQC_MALFORMED_SHARE_LENGTH`. The old `ShareModeThreshold` test (which locked in the
   1200 B rule) is replaced by `ShareModeExactLength`.
3. **Parse failures reach the findings and the outcome label.**
   - An unreadable client `key_share` gives `PQC_MALFORMED_KEY_SHARE` (it used to say `ok`).
     A *missing* `key_share` is not a parse failure (share mode `SUPPORTED_ONLY` if PQ is listed).
   - `pqtls_posture` gives the new label `UNKNOWN_SERVER_SELECTION` when the server's choice
     cannot be established: unreadable server `key_share`, hybrid group with the wrong key
     size, a group we do not recognise, or TLS 1.3 without a `key_share`.
     It still gives the classical labels for TLS 1.2 (no `key_share`, no hybrid groups)
     and for recognised classical groups (secp256r1/384r1/521r1, x25519, x448, brainpool,
     ffdhe), and `HYBRID_SELECTED_OBSERVED` for a hybrid group with its exact key size.
     `pqtls_posture` now also receives the negotiated TLS version (hook in `capture.cpp`).

New finding name: `PQC_MALFORMED_KEY_SHARE` (key_share present, framing unreadable).

## Build, run, test

```sh
cmake -S "Phase 2/engine" -B build-pq
cmake --build build-pq
ctest --test-dir build-pq --output-on-failure
build-pq/unit_tests --gtest_filter='Pqtls*'

build-pq/tlsfp_phase2 -r "Phase 2/pcaps/pq_ech_chrome.pcap" -v | grep -E "CLIENT|SERVER|V-PQTLS"
```

## Results on `Phase 2/pcaps/pq_ech_chrome.pcap` (Chrome, 5580 packets)

| | Engine | tshark 4.2.2 |
| :--- | :--- | :--- |
| ClientHellos over TCP | 22 | 22 (+4 more inside QUIC/UDP, which this TCP engine does not read) |
| Client key shares | 13 × `0x11ec` 1216 B + x25519 32 B, 6 × x25519 32 B, 3 × secp384r1 97 B | identical |
| ServerHellos | 22: 8 × `0x11ec` 1120 B, 8 × x25519 32 B, 3 × secp384r1 97 B, 3 × HRR (asks for secp384r1) | 17 with default settings; **22 and identical** with `-o tcp.reassemble_out_of_order:TRUE` |
| `[V-PQTLS-Check]` | `ok` on all 44 hellos (since the fixes this includes: all 22 server key shares fully present and correctly framed) | — |

Labels: 13 × `PROACTIVE_SHARE_VALID`; 8 × `HYBRID_SELECTED_OBSERVED` (e.g. Google services);
5 × `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER` (Chrome offered `0x11ec`, the server picked x25519);
3 × `HRR_REQUESTED_RETRY`; 6 × `CLASSICAL_NO_PQ_OFFERED`.

**Why tshark shows 5 fewer ServerHellos by default:** in those 5 connections the server's
first data segment was captured *after* a later segment. tshark does not reassemble
out-of-order segments unless `tcp.reassemble_out_of_order` is enabled. With it enabled, tshark
agrees with the engine on all 22. This is likely also behind the Phase 1 observation that
tshark counted fewer ServerHellos than our engines.

**Multi-segment hellos:** every PQ ClientHello in this capture (about 2 KB, larger than the
MSS) was assembled and parsed: 13 of 13 PQ key shares were read with the exact 1216 B size.

## What was checked

**Run after the correctness fixes** (GCC 13.3, Linux):

| Check | Result |
| :--- | :--- |
| Unit tests | **83/83 pass** (45 existing + 38 PQ-TLS). 12 new regression tests for the three fixes: 5 end-to-end on hand-built bytes in `test_pqtls_parser.cpp`, 7 in `test_pqtls_analysis.cpp` (incl. a sweep of 11 key lengths showing the share label and the size check always agree) |
| Strict build | Builds with `-Wall -Wextra -Werror`; 83/83 pass in that build |
| Before vs after the fixes | Full `-v` output identical on all 53 captures (50 in `code/pcaps/`, 3 in `Phase 2/pcaps/`): no valid result changed |
| Existing behaviour | JA3/JA4/JA3S/JA4S and every non-PQ-TLS output line identical to the `main` engine on all 53 captures |
| `pq_ech_chrome.pcap` | 22 ClientHellos, 22 ServerHellos; 44 × `ok`; 13 × `PROACTIVE_SHARE_VALID`, 9 × `NO_PQ_OFFERED`; 8 × `HYBRID_SELECTED_OBSERVED`, 5 × `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER`, 3 × `HRR_REQUESTED_RETRY`, 6 × `CLASSICAL_NO_PQ_OFFERED` (same as before the fixes) |
| Memory safety | AddressSanitizer + UBSan: 83/83 tests pass; 0 findings over all 53 captures |

**From the earlier checkpoint-2 run, not repeated after the fixes** (the engine output is
unchanged, so these still apply): the tshark comparison on `pq_ech_chrome.pcap`,
`chrome.pcap`, `curl.pcap` and `cloudflare_run1.pcap` described above, and `ok` on all
20,391 hellos across the captures.

## Update: main merged into this branch (multithreading)

`origin/main` (JA4T + multithreaded worker pool, up to `fa6560e`) was merged into
`feature/pq-tls`. Main itself was not changed. Two review points were fixed with it:

1. **Data race on `pqtls_offers`.** Main now runs several worker threads. The offers moved
   from one shared map in `Impl` into `WorkerContext` (one table per worker). Main sends both
   directions of a connection to the same worker (`compute_symmetric_flow_hash`), so a
   ClientHello and its ServerHello always meet in the same table and no lock is needed.
   The `[V-PQTLS-*]` lines are printed inside the existing `stdout_mutex` block.
2. **Unbounded offers.** New `PqtlsOfferTable` in `pqtls_analysis.hpp/.cpp`, at most
   `PQTLS_OFFER_TABLE_MAX` (65536, same as the SYN table) entries per worker. When full,
   the older half is dropped; these are flows whose ServerHello never came. A dropped flow
   that does get a ServerHello later shows `UNKNOWN_NO_CLIENT_HELLO`, which is honest.
   There is no FIN/RST eviction: TCP flags are seen on the capture thread, the table lives
   on the worker.

Not a bug (checked): TLS 1.2 posture. `parse_server_hello` falls back to `server_version`
(`0x0303`) when `supported_versions` is absent, so TLS 1.2 gets the classical label.

**Checked after the merge** (GCC 13.3, Linux, Debug build with ASan + UBSan):

| Check | Result |
| :--- | :--- |
| Unit tests | **96/96 pass** (`ctest`, includes main's JA4T tests); 44 PQ-TLS tests (38 + 6 new `PqtlsOfferTableTest`) |
| PQ-TLS output vs `9d6c057` | Identical `[V-PQTLS-*]` lines (sorted) on 48 of 49 captures with `-j 4` |
| `code/pcaps/test_new.pcap` | Differs only because main's engine now sees the 22 ClientHellos the old engine missed: was 22 × `UNKNOWN (ClientHello not seen)`, now 11 × `HYBRID_SELECTED_OBSERVED` + 11 × `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER`; same with `-j 1` and `-j 4` |
| Memory safety | 0 ASan/UBSan findings over all captures with `-j 8` |

## Still not done

- Offer table has a size bound but no time expiry, and no FIN/RST eviction (see update above).
- **Unified JSON output** (charter section 3) is deferred until integration with the JSON
  writer on `feature/ech`.
- **Shared transport work, ownership to be confirmed:** handling of sequence gaps (the
  accumulator drops the flow), handshakes spanning multiple TLS records, and segment-count
  telemetry (doc 5.7). These live in the accumulator, not in the PQ-TLS module.
- Doc 5.2 optional endpoint cache for downgrade alerts; doc 5.5 JA4T correlation; latency metrics.
- Byte lengths are checked, but the key contents are not: component order (ML-KEM vs EC part)
  and cryptographic validity of the keys are not verified.
