# Reduced ECH checkpoint 3

This lab produces real TLS 1.3 connections with endpoint-confirmed ECH acceptance,
captures them on loopback, and replays the packets through the passive engine.
The endpoints supply labels. Fingerprints and visible ECH metadata come from the
engine's existing packet-processing path.

## Recorded result

The delivered experiment contains a three-attempt pilot and **60 accepted ECH
connections**, collected in three sessions with 10 connections per profile in each
session. All 63 attempts have unique endpoint/passive joins. Each capture reports
zero kernel drops. There were no exclusions or HRRs.

| Feature set | Profile A distinct / 30 | Profile B distinct / 30 | Observations in groups shared by both profiles |
|---|---:|---:|---:|
| Outer JA3 | 30 | 30 | 0 / 60 |
| JA3 plus ECH fields | 30 | 30 | 0 / 60 |
| Outer JA4 | 1 | 1 | 60 / 60 |
| JA4 plus ECH fields | 1 | 1 | 60 / 60 |

The shared JA4 is `t13d0308h2_55b375c5d22e_0365bc7f0f41`. Every accepted offer
has KDF 1, AEAD 1, a 32-byte encapsulation and a 176-byte ciphertext. Adding those
four constants leaves the grouping identical. JA4 remains stable but collides
between the two profiles. JA3 retains wire extension order and varied on every
connection while permutation was enabled. Its 60 distinct hashes provide no
demonstration of recognition on a fresh connection.

The result demonstrates that the engine fingerprints confirmed ECH connections,
and that the selected ECH fields add **no discrimination in this experiment**.
Both profiles are configurations of the same BoringSSL build. This measurement
does not establish browser/device identification, recognition accuracy, behavior
across providers, or the effect of turning ECH off. No latency benchmark was run.

## Profiles and independent evidence

The dependency is the clean BoringSSL revision
`df870ed7fa51110edb872beb3357a44d20e1ce56`. Profile A offers the X25519 TLS group
(29), while profile B offers P-256 (23). Both advertise ALPN `h2`, use the same
cipher/signature settings, and enable ordinary GREASE and extension permutation.
The server supports both groups. The profiles differ in a field included in JA3
and omitted from JA4. This is a controlled test of the limits of those inputs.

The separate ECH configuration uses X25519 HPKE (KEM 32), HKDF-SHA256 (KDF 1),
AES-128-GCM (AEAD 1), config ID 42, and maximum name length 64. The inner name is
`inner.ech.test`, the cover name is `public.ech.test`, and both names appear in
the lab certificate. Connections go directly to `127.0.0.1`. DNS and system trust
changes are unnecessary. The client verifies its expected hostname and trusts
only the generated certificate through its process-local trust configuration.

The lab constructs the single-suite ECHConfig using BoringSSL's public CBB API.
The default `SSL_marshal_ech_config` at the pinned revision advertises two suites.
The generated configuration is independently decoded by the runner and accepted
by BoringSSL's client and server APIs. BoringSSL source is unmodified.

Each attempt starts a fresh client process. Resumption and reconnects are
disabled. A five-second client timeout and socket timeouts bound an attempt.
The endpoints finish TLS and send closure, without implementing an HTTP exchange.

For accepted ECH, both endpoints must report a successful handshake, ECH
acceptance, exactly one outer hello and one inner callback. The client must also
confirm certificate verification. Both must agree on the configuration digest,
version, group and ALPN. The client message callback reads the transmitted outer
random rather than assuming `SSL_get_client_random` refers to the outer hello.

The pilot's GREASE control uses profile A, no installed real configuration, and
explicit ECH GREASE mode. It must produce an ECH extension, a verified ordinary
handshake, no inner callback and no acceptance at either endpoint. This single
control verifies the distinction between extension presence and ECH acceptance.

Endpoint records are joined with the original engine JSON by session, oriented
tuple and outer random. Missing, duplicate, conflicting or unmatched evidence is
retained and prevents completion. Configuration IDs, addresses, timestamps,
outer randoms and endpoint labels never enter the augmented fingerprint.

## Fresh collection

All commands run from the `TLS-Fingerprinting` repository root. Set `PYTHON` to the existing virtual environment interpreter as described in the [root README](../../../../README.md).
The host needs CMake, Ninja, a C++17 compiler, Git, tcpdump, TShark, and the engine's
existing OpenSSL/libpcap/GoogleTest dependencies. Initial dependency retrieval
requires access to GitHub. Loopback capture/listening requires permission from
the execution environment. The current account has macOS BPF access.

Choose unused output directories. The runner refuses to replace an output
directory, including a directory containing a previous failed run.

```sh
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' build --out /tmp/ech-build-new
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' pilot --out /tmp/ech-pilot-new
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' collect \
  --pilot /tmp/ech-pilot-new --out /tmp/ech-corpus-new
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' report \
  --pilot /tmp/ech-pilot-new --collection /tmp/ech-corpus-new --out /tmp/ech-report-new
```

`build` verifies the exact clean dependency checkout, builds the standalone lab
and engine separately, runs the engine tests and records versions and binary/source
digests. To reuse existing dependencies without downloading them, pass
`build --boringssl-source /absolute/path/to/pinned-boringssl --gtest-source /absolute/path/to/googletest-1.14.0 --out NEW_DIRECTORY`.
The BoringSSL checkout must still match the pinned revision and be clean. Builds
are created under the relocated lab's `.local/`; old CMake build caches are not moved.
`pilot` generates fresh local key material and validates all three cases
against TShark before collection is allowed. `collect` preserves the pilot's
configuration/certificate and starts a new server for each of three sessions.
Profiles alternate within each session. Every attempt remains in the schedule
and attempt log even if it fails. A failed collection is not silently topped up.
Run a new explicitly named collection after diagnosing its failure.

Capture starts before clients, is restricted to the server's port, and uses
`--immediate-mode` because short loopback exchanges may otherwise remain buffered
in the capture driver until after shutdown. A readiness timeout, endpoint timeout
or other error reaps child processes and retains diagnostic files. A completed
capture with missing/unknown drop statistics fails validation.

The public artifacts include PCAPs, endpoint observations, configuration and
certificate, original engine JSON, joined CSV and derived report. Dependency
checkouts, binaries and all private keys live under ignored `.local/`. Deleting
the private material prevents further collection with that configuration but
does not prevent offline replay or reporting from the public artifacts.
The ignore rules also cover the two private-key filenames outside `.local/`,
macOS metadata, and local build/replay/preparation command transcripts. Capture
statistics, endpoint observations, public configuration/certificate, build
metadata and the recorded report are retained as experiment evidence.

## Replay the supplied evidence

These commands use the engine from the root quick start (`build/phase2/tlsfp_phase2`) and require no live capture, BoringSSL build, or private ECH keys. Use fresh output directories. Omit `--engine` to use the lab-local engine built by the `build` stage.

```sh
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' replay \
  --engine build/phase2/tlsfp_phase2 \
  --source 'Phase 2/code/experiments/ech/results/pilot' --out /tmp/ech-pilot-replay
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' replay \
  --engine build/phase2/tlsfp_phase2 \
  --source 'Phase 2/code/experiments/ech/results/corpus' --out /tmp/ech-corpus-replay
"$PYTHON" 'Phase 2/code/experiments/ech/run.py' report \
  --pilot 'Phase 2/code/experiments/ech/results/pilot' \
  --collection 'Phase 2/code/experiments/ech/results/corpus' --out /tmp/ech-report-recomputed
```

The automatic TShark pilot check compares outer randoms, endpoint tuples, ECH IDs
and lengths, offered groups, key shares, server version, JA3 and normalized JA4.
TShark 4.6.8 includes GREASE signature IDs in its raw JA4 here. The verifier strips
only those reserved IDs before hashing and retains both reference values. This
accounts for the known reference-tool discrepancy without changing the engine.

For a packet-level viva example, open `results/pilot/pilot/capture.pcap` and use
`results/pilot/tshark-validation.json` for the exact frame numbers. The first two
ClientHellos carry real accepted ECH and each has a 176-byte ciphertext. Their
group/key-share IDs differ. The third hello is the explicitly generated GREASE
control. The passive engine still reports `offer_type: unknown` and acceptance
`unverified` for TLS 1.3, while the separate endpoint logs establish the labels.

## Evaluation and verification

For JA3 and JA4 separately, the augmented key is the baseline value followed by
KDF ID, AEAD ID, encapsulation length and ciphertext length. `feature-groups.json`
records group membership counts by profile and session. `summary.json` includes
each profile's distinct count, modal share, distinct groups per session, groups
present in every session and the fraction of observations in mixed-profile groups.
The report also reconciles scheduled, attempted, endpoint-confirmed, passive,
complete-pair, joined and excluded counts. The GREASE control stays outside the
60-connection comparison.

```sh
"$PYTHON" -m unittest discover -s 'Phase 2/code/experiments/ech' -p test_lab.py -v
ctest --test-dir 'Phase 2/code/experiments/ech/.local/engine-build' --output-on-failure
```

The original checkpoint passed 15 lab checks and 123 engine tests. These are historical counts; run the commands above for the current suite. Saved-capture replay
against a separate clean build of `dd3860a` preserves all 90 ordered fingerprint
values across seven PCAPs, plus all 42 summaries after capture-ID normalization.
See `results/regressions.json`. Source inspection confirms the passive engine,
fingerprint definitions, CLI/schema and catalog implementation have no changes.

## GREASE explanation for the report and viva

A real ECH offer encrypts an inner ClientHello using an ECH configuration. A
GREASE ECH offer carries a dummy payload using the same `0xfe0d` extension.
Their visible suite IDs, configuration IDs and lengths can match. A matching
configuration ID or a plausible length therefore supplies no proof of a real
offer. Decryption failure at a receiver can result from GREASE or from a real
offer using a key that receiver does not have. Endpoint-confirmed acceptance
establishes the accepted cases in this experiment. Passive envelope inspection
alone cannot reliably establish the offer type.

Protocol background is in RFC 9849 sections 6.2.1, 7.1 and 10.10.4. The original
four-case corpus, hostname-padding sweep, browser/implementation comparison and
positive HRR inference remain deferred under the reduced checkpoint scope.
