# Encrypted Client Hello (ECH): Protocol Foundations & Integration Plan

**CS331: Computer Networks — Network Security & TLS Fingerprinting, Phase 2**

**Team T014** · **Target binary:** `tlsfp_phase2` · **Revised:** November 1, 2026

**Status:** Design and evaluation plan; the proposed ECH implementation and experiments are not yet validated.

## 1. Objective & Scope

> What client-identifying and structural information survives in observable TCP/TLS handshakes with ECH, and what do ECH fields add beyond the same outer-handshake JA3/JA4 fingerprints?

ECH conceals the intended service name and other sensitive ClientHello fields. Our contribution is a bounds-checked observer, an explanation of its visibility limits, and a small labeled evaluation. A finding that a feature adds no useful discrimination is a valid result.

**Required scope:** TCP capture; ECH extension decoding; correlation of ClientHello with the server's initial response; structured output; four labeled cases (accepted real ECH, rejected real ECH, GREASE ECH, and ECH absent); and controlled measurements of lengths and suite fields. Preserve standard JA3/JA3S and existing JA4/JA4S behavior, including extension permutation and GREASE handling. The project's JA3/JA3S validation requirement remains a prerequisite to fingerprint scope expansion.

**Optional scope:** HRR sequence analysis and live HRR experiments, cross-connection `config_id` analysis, and broader browser comparisons. Retain HRR theory below, but do not make it a prerequisite for the core deliverable. QUIC and a general-purpose TCP/TLS reconstruction framework are outside this implementation's scope.

Three rules govern the design:

1. **Observe first:** Decode wire fields without classifying the offer as real or GREASE.
2. **Explain interpretations:** Every inference names its evidence and may abstain.
3. **Label independently:** Endpoint instrumentation supplies experimental ground truth. Passive output never labels its own evaluation data.

### Governing References

- [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html): ECH wire format, client/server behavior, and privacy limits.
- [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html) and [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html): ECH configuration delivery through DNS SVCB/HTTPS records.
- [RFC 9850](https://www.rfc-editor.org/rfc/rfc9850.html): SSLKEYLOGFILE, especially §§2.1 and 2.3.
- [RFC 9846](https://www.rfc-editor.org/info/rfc9846/): current TLS 1.3 specification; ClientHello §4.2.2, ServerHello §4.2.3, HRR §4.2.4, extensions §4.3, and records §5. It obsoletes RFC 8446; older section numbers must not be silently carried across.
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): HPKE; [RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html): certificate compression; [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html): GREASE.

## 2. Protocol Foundations & Observability

### 2.1 Outer and Inner ClientHello

A real ECH client constructs a private `ClientHelloInner`, encodes and pads it, and encrypts it with HPKE Base mode using a server ECHConfig. It sends a normal TLS-framed `ClientHelloOuter` containing the ciphertext in an ECH extension. The outer SNI normally carries the configuration's `public_name`; it is not the inner destination SNI.

The visible ClientHello retains ordinary TLS framing. ECH requires specialized extension decoding, not a second implementation of ClientHello framing. Decrypting and reconstructing the inner hello is a separate, endpoint-assisted lab task.

| Extension | Codepoint | Meaning at our client-facing capture point |
| :--- | :--- | :--- |
| `encrypted_client_hello` | `0xfe0d` / 65037 | Decode the ECH body. Presence alone does not establish real ECH or acceptance. |
| `ech_outer_extensions` | `0xfd00` / 64768 | Compression references used only in `EncodedClientHelloInner`; forbidden in the outer and reconstructed inner hello. Flag its presence in the outer hello. |
| `compress_certificate` | `0x001b` / 27 | Certificate compression, never ECH. |

The current ECHConfig version is also `0xfe0d`. This plan supports that format, without attempting historical draft-format compatibility. An ECH `inner` marker (`type = 1`, no variant-specific data) is valid in the inner hello, including on an internal split-mode link. Seeing it at our external client-facing tap is a contextual protocol anomaly. See RFC 9849 §§5–5.1 and §7.

### 2.2 ECH Outer Extension Fields

The following layout describes the **extension body**, after the ordinary TLS extension type and length header:

| Field, in wire order | Encoding | Observable meaning |
| :--- | :--- | :--- |
| `type` | 1 byte, `0` for outer | Selects the outer variant. |
| `kdf_id` | 2 bytes | HPKE KDF identifier. |
| `aead_id` | 2 bytes | HPKE AEAD identifier. |
| `config_id` | 1 byte | Configuration selector; not a globally unique key or provider identifier. |
| `enc` | 2-byte length, then bytes | KEM encapsulation; empty on the accepted-ECH post-HRR path. |
| `payload` | 2-byte length, then at least 1 byte | Ciphertext of the encoded, padded inner hello. |

All multi-byte integers use network byte order. The decoder must validate declared lengths and complete consumption of the extension body. Export-only AEAD `0xffff` cannot seal ECH; report the violation separately from structural decoding. Unknown algorithm identifiers should remain visible as numeric values, without inventing an algorithm or treating unfamiliarity alone as malformed data.

The extension does **not** carry `kem_id`. A 32-byte `enc` is consistent with X25519 in known profiles, but length is not an explicit KEM identification. Empty `enc` after HRR does not mean that no KEM was used. An endpoint-correlated ECHConfig can supply the actual KEM identifier in the lab.

For real ECH, the suite must be selected from the ECHConfig's advertised suites. A fixed single-suite configuration leaves no suite-selection variation to identify clients. GREASE suite and length choices should be studied separately. See RFC 9849 §§4–6 and RFC 9180 §7.3.

### 2.3 Ciphertext Length & Padding

Let `L` be the encoded inner length **after name-dependent and other extension padding, but before final 32-byte rounding**, and let `T` be the selected AEAD's ciphertext expansion. Under the recommended scheme:

$$\text{ciphertext\_len} = 32\left\lceil\frac{L}{32}\right\rceil + T.$$

For the common AEADs with a 16-byte tag, this gives `ciphertext_len % 32 == 16`, for example 336, 368, or 400 bytes. This is a conditional padding-policy check, not a validity rule or a real-versus-GREASE discriminator. GREASE is designed to mimic the same sizes.

For an inner hostname of byte length `D`, the recommended name padding adds `max(0, M - D)` bytes, where `M` is the configuration's `maximum_name_length`. If `M = 0`, name length can affect ciphertext buckets when other contents remain fixed. This does not reveal an exact hostname or its exact length. Other extension padding still matters. Read `M` from the configuration used in the experiment rather than assuming a provider's deployed value. See RFC 9849 §§6.1.3 and 6.2.1.

### 2.4 Acceptance, Rejection & HRR

**Ordinary ServerHello:** Acceptance confirmation occupies the last 8 bytes of `ServerHello.random` and depends on the inner random and inner transcript. A passive observer without that information cannot verify the confirmation. TLS 1.3 completion alone therefore does not establish ECH acceptance. Resolve the negotiated version from `supported_versions` when present; the legacy ServerHello version field alone cannot distinguish TLS 1.3 from TLS 1.2.

**Observable non-acceptance:** Negotiation below TLS 1.3 rules out ECH acceptance. An HRR without the ECH extension also indicates non-acceptance. These observations do not distinguish GREASE from a rejected real offer. Count a connection as **rejected real ECH** only with an independent real-offer label.

**HRR recognition:** Use the fixed ServerHello random, SHA-256 of `HelloRetryRequest`:

```text
CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
```

An HRR ECH body has length 8 and a different format from the ClientHello ECH body. Presence is insufficient: a rejecting server may send 8 random bytes. The client checks the confirmation internally.

**Corrected retry distinction:** GREASE copies its ECH extension unchanged after HRR. A real offer rejected at HRR follows the outer-handshake path and can also repeat it unchanged. Thus repetition is an observation, not a GREASE classification. On the accepted-inner path, the client reuses its HPKE context, keeps the suite and `config_id`, sends empty `enc`, and generates a fresh ciphertext.

For a compliant client, that second-hello pattern is evidence that **the client concluded the HRR accepted ECH**. It is a narrow behavioral inference, not passive cryptographic verification, and does not prove that the final handshake completed successfully. See RFC 9849 §§6.1.4–6.1.6, 6.2.1, and 7.1.1; TLS retry restrictions are in RFC 9846 §4.2.2.

After rejection, retry configurations and certificates are encrypted in TLS 1.3. The client authenticates the public name before using authenticated recovery information; recovery can retry ECH or, where permitted, disable it. A quick reconnect or absent application traffic is not sufficient evidence of rejection and is not a core classifier.

### 2.5 DNS & Remaining Visibility

DNS HTTPS/SVCB records can publish ECHConfigList through the `ech` parameter. A separate DNS lookup records available configurations, not necessarily the one selected by a browser. Matching public name and `config_id` supplies context, not proof of encryption or acceptance.

Plaintext DNS and destination IPs can expose information that ECH conceals in TLS. Encrypted DNS addresses the DNS disclosure channel; DNSSEC provides authenticity, not confidentiality. Filtering HTTPS records does not universally force plaintext fallback: client policy and previously learned configuration matter, and RFC 9848 §5.1 restricts fallback after successful discovery in the specified circumstances.

ECH does not expose HTTP User-Agent headers or establish human presence. Its HPKE KEM is distinct from the TLS key exchange; a hybrid TLS key share does not establish post-quantum ECH encryption. TCP options and JA4T belong to a separate transport analysis.

## 3. Integration Architecture

This section defines responsibilities and essential contracts. Function signatures, classes, enum layouts, hashes, and parser code are intentionally left to implementation.

### 3.1 Keep the Existing Engine, Add Two Focused Modules

| Component | Responsibility |
| :--- | :--- |
| Existing `parser.cpp` | Parse shared ClientHello/ServerHello framing, dispatch ECH bodies, retain the outer random, and expose negotiated version and optional HRR metadata. |
| New `ech_parser.cpp` | Decode ECH-specific bodies using the existing bounded reader. No connection state, classification, DNS lookup, or secrets. |
| New `ech_analysis.cpp` | Evaluate contextual validity and evidence over observations. Keep experimental signals separate from offer classification. |
| Existing `accumulator.cpp` | Deliver complete supported records with sequence-aware accumulation; preserve remaining bytes and report incomplete/unsupported input. |
| Existing `capture.cpp` | Correlate directions in a small connection record and emit a structured summary. |
| External experiment harness | Correlate endpoint labels, configurations, and passive output; perform any secret-assisted decryption outside the engine. |

The current Phase 2 tree has no standalone `flow` or `output` module. Add the small connection record and JSON output within the existing capture implementation rather than assuming those modules exist or introducing a parallel framework.

Proposed additions, relative to `Phase 2/`:

```text
engine/include/tlsfp/   ech_parser.hpp  ech_analysis.hpp
engine/src/             ech_parser.cpp  ech_analysis.cpp
engine/tests/           test_ech_parser.cpp  test_ech_analysis.cpp  fixtures/
experiments/ech/        README.md  label_join.py  features.py  manifests/  results/
```

Keep ECH observation types with the ECH headers. Extend existing tests and build declarations as needed. Do not split or move stable fingerprint, database, or capture modules merely for this feature. The script names describe planned harness responsibilities; no implementation or decryption-effort estimate is implied.

### 3.2 Parse Once, Interpret After the Needed Evidence Arrives

Within one hello, decode extension-local facts first and finalize cross-extension checks after the complete extension vector. This preserves independence from randomized extension ordering. Retain raw extension order for standard fingerprints; ECH metadata is an additional feature set, not a modified JA3/JA4 definition.

Across messages, keep one bidirectional connection record, using IP version and endpoint addresses/ports with a consistent client/server orientation. Record CH1, its outer random, the first server response, timestamps, and completion status. Add CH2 and HRR metadata only if optional HRR analysis is implemented. An accumulator entry is not this record: it is currently discarded after record completion.

Retransmitted bytes must not create a second hello. A new connection SYN starts fresh connection state. Emit one summary at the final ServerHello, or an incomplete summary at FIN/RST, expiry, or end of capture. HRR is not the final ServerHello. Retain only the owned fields needed for the summary; packet-buffer views must not outlive their bytes. Release hello buffers after summarization, retaining enough completion/sequence state to suppress duplicate summaries until close or expiry. Keep connection storage bounded.

### 3.3 Minimal Observation Contract

Use a parsing/completeness status plus independent findings flags. Preserve a structurally decoded body even when another extension creates an anomaly. Duplicate ECH, forbidden outer `0xfd00`, inappropriate inner markers, and contextual empty-`enc` violations must not overwrite one another or silently select a duplicate as authoritative.

- **Absent:** established only after the complete ClientHello extension vector was examined.
- **Incomplete:** capture bytes are missing, including an unfinished hello. Presence can be known from a header while body fields remain unavailable.
- **Unsupported:** a known implementation limit was reached.
- **Malformed:** complete available framing proves a structural contradiction; packet loss or a size limit alone is not malformed ECH.

Decode empty `enc` as a fact, then check its message context in analysis. Keep KEM guesses and padding-policy annotations out of the decoder; derive them for analysis/reporting with explicit assumptions. Missing values stay unknown rather than becoming zero-valued observations.

## 4. Evidence Rules & Output

| Rule | Evidence | Allowed result |
| :--- | :--- | :--- |
| **I1 — optional HRR** | Correlated CH1 → HRR → CH2, with identical ECH bytes. | `extension_repeated_unchanged`; compatible with GREASE and rejected real ECH. Offer type remains unknown. |
| **I2 — optional HRR** | Valid CH1 → HRR → CH2; CH2 has empty `enc`, unchanged suite and `config_id`, and changed payload; HRR ECH framing is valid. | Likely real offer; a compliant client inferred HRR acceptance. Keep this separate from endpoint-verified acceptance and final handshake success. |
| **I3** | ECH observed, then negotiated version below TLS 1.3; optionally HRR without ECH. | Non-acceptance observed. Real-offer rejection statistics require endpoint labels. |
| **I4 — experimental** | Repeated connections show stable or changing `config_id`. | A signal only; never sets offer type. |
| **I5 — experimental** | Outer SNI exactly matches a recorded public name. | A contextual match with provenance; never sets offer type or acceptance. No suffix-based classification. |

I4 analysis can be performed offline, grouped by client IP, destination IP and destination port within a recorded observation window. Record sample count and return insufficient data where appropriate. Do not build a live cross-connection cache for the core deliverable. Neither I4 nor I5 becomes reliable merely because I1 is inconclusive.

The structured connection summary contains:

- Capture/session identity, endpoint tuple, timestamp, outer random, and completion reason.
- ECH presence, parse status, findings, outer SNI, decoded suite/configuration identifiers, and `enc`/ciphertext lengths where available.
- Passive interpretation and named evidence; default offer type is unknown and acceptance is unverified. With HRR omitted, the core has no positive real-versus-GREASE classifier.
- Optional derived KEM/padding annotations and experimental signals, clearly marked as such.
- The ordinary outer JA3/JA4 baseline; server fingerprints only when the corresponding complete ServerHello is available.

Emit one JSON line per connection summary for offline joins. Endpoint labels belong to a separate harness result, with their source recorded. No endpoint secrets enter passive-engine output.

## 5. Transport Contract & Supported Limits

TCP segmentation, TLS record framing, and handshake-message framing are different boundaries. PQ key shares and ECH can increase ClientHello size, but this document has no measured size distribution. Measure actual lengths and packet counts; do not claim a universal two-packet handshake or that the 8 KB buffer proves correct reassembly.

Make targeted changes in the existing accumulator/parser path:

1. Preserve sequence-offset, overlap, and gap checks. Gaps must produce incomplete results rather than guessed bytes.
2. Iterate over every complete record in contiguous input, preserving any partial tail. Coalesced records and compatibility ChangeCipherSpec records must not hide the ServerHello/HRR or cause premature connection eviction.
3. Parse only supported plaintext handshake framing; encrypted records are not plaintext extensions.
4. For the core, support complete hello messages within one TLS record, including records split across TCP segments. If a hello spans records, detect and report the unsupported case rather than producing a partial fingerprint. Add cross-record handshake assembly only if pilot captures require it.
5. Document and consistently enforce the retained 8 KB accumulation/hello bound and connection-state limits. Oversized valid input is unsupported, not malformed.

Record the capture point and relevant offload settings with any packetization measurements. General out-of-order recovery and a separate TLS-framer module are deferred. Validate the supported path against actual captures before describing it as working.

## 6. Experiments & Evaluation

### 6.1 Small Evaluation Matrix

| Study | Controlled comparison | What may be concluded |
| :--- | :--- | :--- |
| **H1 — optional second client** | Repeat Chrome and Firefox captures against the same destination/configuration. Analyze real ECH and GREASE separately. Add an impersonation client only if available. | Describe observed length distributions; do not promise universal browser identification. |
| **H2 — controlled length study** | One scripted client, fixed ECHConfig and suite, fixed non-SNI inner structure and padding policy; vary only inner hostname byte length. Record `M` and compare with §2.3. | Test the predicted length buckets, including `M = 0` where available. A cross-host correlation alone does not isolate SNI length. |
| **H3 — incremental feature value** | Same captures and target labels: outer JA3/JA4 alone versus those fingerprints plus ECH suite/length features. Separate real and GREASE offers. | Report additional variation or discrimination. A single-suite real-ECH configuration may contribute no suite information. |
| **H4 — limits of separation** | Compare passive conclusions with real/GREASE labels. If HRR is implemented, test I1/I2 with labeled sequences. | Report abstention and demonstrated coverage. I1 is not a GREASE detector; untested HRR behavior remains theory. |

For H2, an instrumented client may construct offers for synthetic inner names without those names being hosted, provided it can vary inner SNI while keeping the cover name/configuration and other inputs fixed. These measure **client-generated length**, not successful service connections or accepted ECH. Keep them separate from the four-case connection corpus. If the selected client cannot hold these variables fixed, report the limitation rather than claim a controlled H2 result.

### 6.2 Minimum Reporting

Keep a per-connection manifest with client/build and OS versions, session/run ID, timestamp, destination, intended inner hostname where known, exact configuration and source, client offer mode, and independently observed acceptance state. Keep raw configuration bytes plus decoded `config_id`, `public_name`, KEM, suites and `maximum_name_length` when available. A DNS snapshot is marked as advertised configuration unless selection is independently established.

Repeat captures in independent sessions. Record session reuse/resumption settings and keep them consistent within each comparison. A separate resumption study and held-out providers/configurations are optional.

Report attempted connections, capture/parse outcomes, and endpoint-labeled ECH outcomes separately; do not count only accepted connections. Unknown labels remain visible. State counts per case, feature distributions, and the baseline comparison. For any classifier, report accuracy on classified labeled cases **and coverage**; unknowns must not disappear from the denominator. If fitting or tuning a classifier, split by capture session before tuning. Descriptive tables do not require a train/test pipeline.

An ECH-off comparison with the same client helps demonstrate lost visibility, but disabling real ECH may leave GREASE enabled. Verify extension absence before calling a capture the no-ECH control. Bound conclusions to the measured clients and configuration.

## 7. Lab Corpus & Ground Truth

### 7.1 Pilot Before Scaling

Use a dedicated client process/profile, TCP transport with QUIC disabled and verified in the capture, packet capture started before connection establishment, and endpoint logging enabled before launch. Start with one accepted-ECH connection. Verify the exact client build's instrumentation and configuration logging before collecting repetitions; setting SSLKEYLOGFILE alone does not guarantee ECH-specific labels.

A public diagnostic endpoint can corroborate an accepted case, but associate its response with the actual connection and retain supporting endpoint evidence. One navigation may create several connections or retries. Store pcaps, manifests, and label provenance for repeatable analysis; public-service behavior is not guaranteed reproducible later.

### 7.2 Four Required Cases

| Case | How to obtain it | Label requirement |
| :--- | :--- | :--- |
| Accepted real ECH | Verified ECH-capable client using a usable configuration and endpoint. | Positive, connection-correlated acceptance evidence. |
| Rejected real ECH | Instrumented scripted client makes a real offer using a deliberately unusable configuration, preserving a valid public name and supported suite. A stale configuration is a candidate, not a guarantee of rejection. | Establish the real offer and its non-acceptance from endpoint evidence; record retries as separate connections. No controlled server is required if this public-endpoint recipe works in the pilot. |
| GREASE ECH | Verified client GREASE mode, or instrumentation establishing that no usable configuration was used and a dummy offer was generated. | Extension presence or a separate `dig` result alone is insufficient. |
| ECH absent | Client configured to omit both real ECH and GREASE. | Complete ClientHello confirms absence. |

If a collection recipe fails, mark the case missing and its associated claim unvalidated; do not relabel an unknown flow to fill the matrix. HRR captures are optional. For an accepted-ECH HRR experiment, use a verified ECH-capable server/configuration and a mutually supported group that forces HRR. Merely restricting a server's groups does not enable ECH.

### 7.3 Keylog Correlation

RFC 9850 §2.3 keys `ECH_CONFIG` and `ECH_SECRET` by the **outer random**. The former records the selected configuration; the latter is the HPKE KEM shared secret. Neither label alone proves acceptance. Under §2.1, TLS 1.3 handshake/application secret labels use the **inner random on acceptance**, otherwise the outer random.

The harness first joins ECH labels to the captured outer random. Prefer a directly correlated endpoint acceptance result. Where using the secret-based route, authenticated ECH decryption with the logged configuration/shared secret and correctly constructed outer-hello AAD recovers the inner random; associate the resulting TLS handshake with its secret rows or verify its acceptance confirmation. Use a verified tool or independently checked harness, not the passive classifier being evaluated.

For an independently established real offer, a corresponding outer-handshake secret record supports non-acceptance. Absence of such a row is **not** proof of acceptance; logs may be incomplete. Missing labels, failed decryption, or ambiguous joins yield an unknown outcome. Decryption and key handling remain outside the passive C++ engine. Do not assume a particular script size or that generic TLS traffic secrets can decrypt the ECH payload.

## 8. Delivery Order & Validation Gates

1. **Pilot and decoder:** verify capture/label feasibility; implement isolated extension decoding and fixtures. Cross-check a real envelope manually against the wire layout and with an independent dissector where supported.
2. **Core integration:** add minimal bidirectional summaries, structured output, and the targeted record-processing fixes. Verify both client and server directions and preserve existing fingerprint parity on saved captures.
3. **Labeled corpus:** collect the four cases with provenance and repeat sessions. Publish missing/unlabeled counts rather than treating them as successful validation.
4. **Measurements:** run the controlled H2 study and H3 baseline comparison; add a second browser when practical. Record null results and limits.
5. **Optional extensions:** only after the core works, add validated HRR analysis or offline I4/I5 signals. Omit untested features from demonstrated capability claims.

Required parser fixtures include `0x001b` without ECH, a valid outer body, truncated capture, contradictory complete lengths, trailing bytes, duplicate ECH, cleartext `0xfd00`, inner marker at the external tap, and empty `enc` with known/unknown message context. Integration checks cover segmented records, coalesced server records, retransmission deduplication, unsupported sizes, and absence versus incomplete capture. Optional analysis fixtures cover CH1/HRR/CH2, including unchanged rejected-real and GREASE cases; synthetic fixtures establish rule behavior, not empirical real-versus-GREASE accuracy.

## 9. Presentation & Defensible Claims

Present the visible wire layout, observation/interpretation/ground-truth distinction, labeled corpus, controlled length result, incremental feature comparison, and a results-and-limits slide. Include sample counts, classification coverage where applicable, and supported transport limits. HRR behavior is theory unless separately validated.

Use these statements consistently in the report and viva:

- **Acceptance:** ordinary ServerHello confirmation is not passively verifiable without inner-handshake information. Optional I2 can reveal a compliant client's HRR acceptance conclusion; it does not prove final success.
- **Real versus GREASE:** extension presence, padding buckets, unchanged HRR copies, familiar public names, and configuration-ID matches do not prove a real offer. The core may correctly abstain on every offer-type classification.
- **Lengths and KEM:** ciphertext length includes encoded inner content, padding and AEAD expansion. KEM length annotations are guesses unless supplied by correlated configuration evidence.
- **Privacy and identity:** ECH conceals inner fields, not every destination disclosure channel. TLS fingerprints characterize client-stack behavior, not human intent or guaranteed application identity.
- **Implementation status:** evidence from actual runs is required for claims of correct reassembly, successful labeling, or identification accuracy. This plan and synthetic tests alone establish none of those results.
