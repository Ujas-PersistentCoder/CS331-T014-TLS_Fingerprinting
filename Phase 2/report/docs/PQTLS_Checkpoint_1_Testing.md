> Historical project notes: commands, paths and test counts describe the recorded revision. For the current repository layout and runnable commands, use the [phase README](../../README.md).

# PQ-TLS checkpoint 1: observe and label

This checkpoint adds passive post-quantum TLS (PQ-TLS) inspection to `tlsfp_phase2`.
For every ClientHello and ServerHello it reports which key exchange groups were
offered and sent, which group the server picked, and a label for the outcome.
The new lines appear with the existing `-v` option. JA3/JA4/JA3S/JA4S are not changed.

Plan and background: `PQTLS_DeepDive_and_Integration_Strategy.md` (sections 5.1–5.3).

## Files

| File | Role |
| :--- | :--- |
| `engine/include/tlsfp/pqtls_parser.hpp`, `engine/src/pqtls_parser.cpp` | **Observe.** Reads `key_share` (0x0033) in ClientHello and ServerHello, finds the first PQ hybrid group in `supported_groups`, recognises a HelloRetryRequest by its fixed random. No memory between packets, no decisions. |
| `engine/include/tlsfp/pqtls_analysis.hpp`, `engine/src/pqtls_analysis.cpp` | **Interpret.** Share mode of one ClientHello (doc 5.3) and outcome of the connection (doc 5.2). Labels are UNKNOWN when evidence is missing. Output text. |
| `engine/tests/test_pqtls_parser.cpp`, `engine/tests/test_pqtls_analysis.cpp`, `engine/tests/fixtures/pqtls_fixtures.hpp` | 18 GoogleTest cases. Parser tests use hand-built hello bytes; analysis tests use hand-filled structs. |

Hooks in shared files: `parser.hpp` (a `pqtls` sub-struct in `ClientHelloData` and
`ServerHelloData`), `parser.cpp` (`case 0x0033` in both extension loops, one
`find_pqtls_group()` call after the client loop, ServerHello random read instead of
skipped), `capture.cpp` (`print_pqtls_client/server`, per-connection offer map),
`CMakeLists.txt` (2 sources, 2 test files).

PQ hybrid groups recognised: `0x11ec` X25519MLKEM768, `0x11eb` SecP256r1MLKEM768,
`0x11ed` SecP384r1MLKEM1024 (RFC 10024), and the older drafts `0x6399`
X25519Kyber768Draft00 and `0x639a` SecP256r1Kyber768Draft00.

## Build and run

From the repository root. GoogleTest is downloaded by CMake (first configure needs internet).

```sh
cmake -S "Phase 2/engine" -B build-pq
cmake --build build-pq
ctest --test-dir build-pq --output-on-failure

build-pq/tlsfp_phase2 -r code/pcaps/chrome.pcap -f tcp -v | grep -E "CLIENT|SERVER|V-PQTLS"
build-pq/tlsfp_phase2 -r code/pcaps/curl.pcap -f tcp -v | grep -E "CLIENT|SERVER|V-PQTLS"
build-pq/tlsfp_phase2 -r code/pcaps/cloudflare_run1.pcap -f tcp -v | grep -E "CLIENT|SERVER|V-PQTLS"
```

Only the unit tests: `build-pq/unit_tests --gtest_filter='Pqtls*'`

**macOS note:** if Homebrew `googletest` is installed, its headers are found before the
downloaded GoogleTest and `unit_tests` fails to link (`Undefined symbols ... AssertHelper`).
`brew uninstall googletest` fixes it.

## Output lines

| Line | Meaning |
| :--- | :--- |
| `[V-PQTLS-Offer]` | First PQ group in `supported_groups` and whether it is the first choice (GREASE ignored), or `no PQ group offered`. |
| `[V-PQTLS-Keys]` | Every key the client sent in `key_share`, with its size in bytes (GREASE left out). |
| `[V-PQTLS-Share]` | `PROACTIVE_SHARE_VALID` (a PQ key of at least 1200 bytes sent right away), `SUPPORTED_ONLY` (PQ listed, no PQ key sent), `RETRY_AFTER_HRR` (second hello after a HelloRetryRequest), `NO_PQ_OFFERED`, or `UNKNOWN` (key_share unreadable or PQ key too small). |
| `[V-PQTLS-Group]` | Group the server picked and its key size, or `HelloRetryRequest: asks for <group>`. |
| `[V-PQTLS-Result]` | `HYBRID_SELECTED_OBSERVED`, `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER` (also TLS 1.2), `HRR_REQUESTED_RETRY`, `CLASSICAL_NO_PQ_OFFERED`, or `UNKNOWN (ClientHello not seen)`. |

Example (`cloudflare_run1.pcap`, client port 59103):

```text
CLIENT  [V-PQTLS-Offer]  offered 0x11ec (X25519MLKEM768), first choice
        [V-PQTLS-Keys]   0x11ec (X25519MLKEM768) 1216B, 0x001d (x25519) 32B
        [V-PQTLS-Share]  PROACTIVE_SHARE_VALID
SERVER  [V-PQTLS-Group]  HelloRetryRequest: asks for 0x0017 (secp256r1)
        [V-PQTLS-Result] HRR_REQUESTED_RETRY
CLIENT  [V-PQTLS-Offer]  offered 0x11ec (X25519MLKEM768), first choice
        [V-PQTLS-Keys]   0x0017 (secp256r1) 65B
        [V-PQTLS-Share]  RETRY_AFTER_HRR
SERVER  [V-PQTLS-Group]  0x0017 (secp256r1), classical, key 65B
        [V-PQTLS-Result] CLASSICAL_SELECTED_AFTER_HYBRID_OFFER
```

## What was checked

| Check | Result |
| :--- | :--- |
| Unit tests | 63/63 pass (45 existing + 18 PQ-TLS) |
| `chrome.pcap` | 4 hellos: `0x11ec` first choice, keys 1216 B + 32 B, `PROACTIVE_SHARE_VALID`; server picks `0x11ec` with a 1120 B key, `HYBRID_SELECTED_OBSERVED` ×4 |
| `curl.pcap` | 1 hello: `NO_PQ_OFFERED`, x25519 32 B; server x25519, `CLASSICAL_NO_PQ_OFFERED` |
| `cloudflare_run1.pcap` | 11 ClientHellos / 11 ServerHellos: 3 HelloRetryRequests (ports 59103, 59104, 59107), 1 `CLASSICAL_SELECTED_AFTER_HYBRID_OFFER`, 2 `HYBRID_SELECTED_OBSERVED`, 5 `CLASSICAL_NO_PQ_OFFERED` |
| Against tshark 4.2.2 | Key share groups and sizes (`tls.handshake.extensions_key_share_group`, `..._key_exchange_length`) and the 3 HRRs (selected group 23/24) match on the three captures above. (tshark lists 3 of the 4 Chrome ServerHellos; this count difference is already known from Phase 1.) |
| Existing behaviour | JA3/JA4/JA3S/JA4S and every non-PQ-TLS output line identical to `main` on all 50 non-empty captures in `code/pcaps/` |
| Memory safety | AddressSanitizer + UBSan over the tests and all captures: 0 findings |

Observation from our own data: an HRR does not only ask for a hybrid group. In
`cloudflare_run1.pcap` the client offered `0x11ec` and the server's HRR asked for
classical secp256r1.

## Not in this checkpoint

- Doc 5.6: exact key size checks (`0x11ec` = 1216 B client / 1120 B server, etc.) and
  duplicate-extension detection. Today a PQ key below 1200 B only gives `UNKNOWN` in
  `[V-PQTLS-Share]`, and a key whose length does not fit the extension is reported as unreadable.
- Doc 5.7: TCP segment counting for the ClientHello (would touch the accumulator).
- Doc 5.2: the optional endpoint cache for "this site used to pick PQ" alerts.
- Doc 5.5: JA4T correlation (separate track).
- Live capture: if a server never answers, that connection's remembered offer stays in
  memory. Not an issue for pcap files.
- Only the plaintext handshake is read; nothing is decrypted.
