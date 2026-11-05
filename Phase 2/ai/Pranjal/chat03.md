# Review ECH integration plan

> Read [ECH_DeepDive_and_Integration_Strategy.md](<TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md>) carefully and review the high level plan. Only focus on flaws in the plan itself and don't worry about minor bugs in the code. In fact, once you're satisfied with the approach itself, we will remove the implementation-level details from this document just so you can write the code yourself later on. One change in the code structure that I would suggest is that we should create a new ech_parser.cpp where the functions to parse ECH will go. The way I understand it, ECH parsing will significantly differ from regular counterpart so it makes sense to keep the logic in two separate files. Let me know if you think otherwise. Apart from that, feel free to suggest any other changes in the code structure (based on your understanding of similar systems projects written in C++), and propose a final folder structure in this chat for me to review. Don't write to any file yet, read only everywhere.

<details><summary>6 previous messages</summary>

> I’ll read the strategy and the current parser structure, then review the architectural assumptions and propose a folder layout. I’ll keep everything read-only.
>
> <details><summary>Explored 2 files, 2 lists, ran a command</summary>
>
> <details><summary>Explored a file</summary>
>
> - Read `~/.agents/skills/engineering/architecture/SKILL.md`
>
> </details>
>
> - Ran `pwd; rg --files -g AGENTS.md -g CONTEXT.md -g '*ECH*' -g '*ech*' -g '*parser*' -g CMakeLists.txt -g '*.hpp' -g '*.h' 'TLS-Fingerprinting/Phase 2' .agents`
>
> <details><summary>Explored 4 files, 2 lists</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md`
> - Read `~/.codex/plugins/cache/claude-cowork/engineering/1.2.0/skills/architecture/SKILL.md`
> - Read `~/.agents/skills/brainstorming/SKILL.md`
> - Read `./.agents/CONTEXT.md`
> - Listed files
> - Listed files in `engine`
>
> </details>
>
> </details>
>
> I’m using the architecture and brainstorming skills for this review. The document’s separation of wire facts, inference, and endpoint ground truth is a sound starting point; I’m checking whether the proposed parser boundaries and experiments preserve that separation.
>
> <details><summary>Explored 5 files, a search, ran a command, searched the web</summary>
>
> <details><summary>Explored a file</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md`
>
> </details>
>
> - Ran `cat 'TLS-Fingerprinting/Phase 2/engine/include/tlsfp/parser.hpp' 'TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp' 'TLS-Fingerprinting/Phase 2/engine/include/tlsfp/types.hpp'; cat 'TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt'; cat AGENTS.md`
>
> <details><summary>Explored 4 files, a search</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/parser.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/capture.hpp`
> - Searched for `parse_|accumul|FlowKey|hello|callback|fingerprint|cout` in `capture.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md`
>
> </details>
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc9849.html`
>
> Searched the web for `'second ClientHelloOuter'`
>
> <details><summary>Explored 3 files</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/parser.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp`
>
> </details>
>
> </details>
>
> Two significant gaps have emerged: the HRR rules need to account for a real ECH offer being rejected, and the transport plan needs to distinguish TCP reassembly from TLS record and handshake assembly. I’m also checking the lab setup, since the real-versus-GREASE evaluation depends on reliable labels.
>
> <details><summary>Explored a file, a list, searched the web</summary>
>
> <details><summary>Explored 2 files, a list</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md`
> - Read `./TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md`
> - Listed files in `Phase 2`
>
> </details>
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2`
>
> Searched the web for `'same ClientHello without modification'`
>
> </details>
</details>

The overall direction is sound, but **I would revise several high-level assumptions before treating the plan as ready for implementation**. I read the full document and inspected the current engine boundaries. Everything remained read-only.

**I agree with adding `ech_parser.cpp`.** One distinction matters: ECH does not require a separate parser for the entire visible ClientHello. The outer ClientHello still uses normal TLS framing; its ECH extension has a specialized body. Keep the shared ClientHello parser and delegate ECH extension decoding to the new file.

The main issues in the plan are:

1. **The HRR copy test can misclassify rejected real ECH as GREASE.**
   Sections 2.5 and 3.6 treat an unchanged ECH extension after HRR as evidence of GREASE. However, real ECH that was rejected follows the outer-handshake path; ordinary TLS retry rules preserve extensions except for permitted changes. My reading of those rules is that identical ECH bytes are therefore compatible with both GREASE and rejected real ECH. The empty-`enc`, fresh-payload behavior belongs to the accepted-inner path. [ECH retry behavior](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.5), [TLS ClientHello retry rules](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2).

   **Recommendation:** record “ECH extension repeated unchanged” as an observation, and abstain on real-versus-GREASE unless additional evidence supports the distinction. Add rejected-real-ECH-with-HRR to the validation matrix.

2. **The plan needs an explicit connection state machine.**
   “Two-pass finalization” is appropriate for dependencies within one ClientHello, such as ECH and SNI appearing in either order. It cannot, by itself, handle evidence arriving later from the server or second ClientHello.

   Introduce a connection tracker that correlates both directions and distinguishes:

   - Initial ClientHello.
   - HRR.
   - Second ClientHello.
   - Final ServerHello.
   - Incomplete capture, termination, and expiry.

   Retransmissions must not advance this sequence. Reused connection tuples must start fresh state. Define whether output emits later updates or waits for a connection summary; otherwise an initial `UNKNOWN` result may never acquire its later evidence.

3. **Section 5 overstates what the accumulator establishes.**
   An 8 KB buffer covering typical observed ClientHellos does not establish general handshake reassembly correctness. The architecture must distinguish:

   ```text
   TCP segments → contiguous stream → TLS records → handshake messages
   ```

   A handshake can cross record boundaries, and one segment can contain several records. These boundaries are independent of Ethernet MTU.

   The current accumulator is centered on completing one TLS record, so this is a prerequisite architectural gap for the proposed analysis. Keep bounded buffering, but specify supported limits, total state limits, timeouts, and explicit outcomes for gaps or oversized messages. An operational limit should produce “unsupported/incomplete,” rather than “malformed ECH.”

4. **The observation model still mixes facts with interpretation.**
   `inferred_kem`, padding-policy judgments, and handshake-role validation should not all live inside extension decoding. Similarly, one `parse_status` cannot cleanly represent a valid ECH body alongside duplicate extensions or a forbidden `0xfd00` elsewhere in the hello.

   I suggest separate concepts for:

   - Capture completeness.
   - Structural decoding.
   - Protocol findings, allowing multiple findings.
   - Interpretation and its supporting evidence.

   “ECH absent” should require enough of the ClientHello to establish absence. A missed portion of the capture is unknown. Empty `enc` should remain a decoded fact until connection context establishes whether it is appropriate.

5. **I4 and I5 should initially be experimental features, not classification rules.**
   Stable `config_id` values and familiar cover names may be useful research signals, but the proposed rules lack a defined population, observation window, conflict policy, and measured error rate.

   In particular, grouping by destination IP can combine unrelated clients and services. A suffix match also does not establish that a hostname is the actual configured public name.

   **Recommendation:** retain these signals in experimental output, but do not let either independently set `OFFERED_LIKELY_REAL`. Evaluate them against endpoint labels first, including cases where stronger and weaker evidence disagree.

6. **The lab recipe cannot yet provide all the promised ground truth.**
   A generic HRR-capable server does not establish the accepted-ECH HRR case. The lab needs a verified ECH-capable endpoint, provisioned configuration, and a supported group that forces HRR.

   Likewise, a separate `dig` lookup does not establish which configuration the browser used. Browser automation establishes navigation intent, but that intent still needs correlation to the particular connection being labeled.

   ECH keylog entries may be emitted for an offer regardless of acceptance. Standard TLS secret labels use the inner random upon successful ECH negotiation, but an unmatched random in a shared log is insufficient without connection correlation. [RFC 9850 §§2.1–2.3](https://www.rfc-editor.org/rfc/rfc9850.html#section-2.3).

   I would require controlled cases for accepted ECH, rejected real ECH, GREASE, and absent ECH, with HRR variants where applicable. Public websites can supplement those cases.

7. **The experiments need stronger controls to answer the research question.**
   H1–H3 risk identifying destination configuration or session state instead of client software. H2, especially, needs an experiment that varies inner hostname length while holding the remaining inner structure and ECH configuration fixed.

   Specify repeated independent sessions, fresh versus resumed connections, held-out destinations/configurations, and comparison against the same outer JA3/JA4 baseline. For abstaining classification, report both accuracy and coverage.

   Keep standard JA3/JA4 calculations unchanged and attach ECH features separately. Preserve extension permutation and GREASE behavior.

For code organization, I would choose **small, focused modules within the existing layout**. Keeping everything in `parser.cpp` would blur responsibilities; creating an independent ECH handshake stack would duplicate TLS framing. Separate extension parsing plus shared connection tracking gives the clearest boundary.

My proposed final layout under [Phase 2](<./TLS-Fingerprinting/Phase 2>) is:

```text
Phase 2/
├── docs/
│   ├── ECH_DeepDive_and_Integration_Strategy.md
│   └── ... existing documents
├── engine/
│   ├── CMakeLists.txt
│   ├── engine_roadmap.md
│   ├── include/tlsfp/
│   │   ├── byte_reader.hpp
│   │   ├── types.hpp
│   │   ├── flow.hpp
│   │   ├── capture.hpp
│   │   ├── accumulator.hpp
│   │   ├── tls_framer.hpp
│   │   ├── hello.hpp
│   │   ├── parser.hpp
│   │   ├── connection_tracker.hpp
│   │   ├── ech_types.hpp
│   │   ├── ech_parser.hpp
│   │   ├── ech_analysis.hpp
│   │   ├── ja3.hpp
│   │   ├── ja4.hpp
│   │   ├── db.hpp
│   │   └── output.hpp
│   ├── src/
│   │   ├── main.cpp
│   │   ├── capture.cpp
│   │   ├── accumulator.cpp
│   │   ├── tls_framer.cpp
│   │   ├── parser.cpp
│   │   ├── connection_tracker.cpp
│   │   ├── ech_parser.cpp
│   │   ├── ech_analysis.cpp
│   │   ├── ja3.cpp
│   │   ├── ja4.cpp
│   │   ├── db.cpp
│   │   └── output.cpp
│   └── tests/
│       ├── test_fingerprints.cpp
│       ├── test_accumulator.cpp
│       ├── test_tls_framer.cpp
│       ├── test_parser.cpp
│       ├── test_connection_tracker.cpp
│       ├── test_ech_parser.cpp
│       ├── test_ech_analysis.cpp
│       ├── test_ech_integration.cpp
│       └── fixtures/
└── experiments/
    └── ech/
        ├── README.md
        ├── manifests/
        └── results/
```

The important responsibilities are:

| Module | Responsibility |
|---|---|
| `accumulator` | TCP sequence handling and contiguous bytes |
| `tls_framer` | Record framing and handshake assembly |
| `parser` | Shared ClientHello/ServerHello decoding and extension dispatch |
| `ech_parser` | Stateless, bounded decoding of ECH-specific bodies |
| `connection_tracker` | Bidirectional lifecycle and handshake sequence |
| `ech_analysis` | Contextual validation, inference, and evidence |
| `output` | Consistent presentation/export of observations and updates |
| `experiments/ech` | Endpoint labels, capture provenance, and research evaluation |

Use context-specific ECH decoding for ClientHello and HRR; their extension bodies differ. Keep endpoint-secret processing outside the passive engine initially.

After resolving these points, I agree with removing the embedded implementation snippets. **Keep the wire layouts, component contracts, state transitions, evidence rules, resource limits, and validation criteria**—those are the design decisions the later implementation must satisfy.

> The above are results from another independent analysis of the plan. Fact-check and subjectively judge each one of them. Flag over-engineered suggestions and ignore niche edge-case handling for now. Read only
>
> User context
>
> Attachments:
> - Your parser and protocol facts are in good shape. The plan around them is the w…: `~/.codex/attachments/d42ba720-e795-43d7-ac48-9b80da9179df/Pasted text.txt`

<details><summary>4 previous messages</summary>

> I’ll read the independent review, check each claim against the plan and relevant protocol rules, and flag suggestions that add more complexity than this project needs. Everything will remain read-only.
>
> <details><summary>Explored 2 files, a search, searched the web</summary>
>
> <details><summary>Explored a file</summary>
>
> - Read `~/.codex/attachments/d42ba720-e795-43d7-ac48-9b80da9179df/Pasted text.txt`
>
> </details>
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc9846.html`
>
> <details><summary>Explored a file, a search</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp`
> - Searched for `H[1-4]|I[1-5]|HRR|CF 21|deadline|Nov|November|sequence` in `ECH_DeepDive_and_Integration_Strategy.md`
>
> </details>
>
> Searched the web for `site.rfc-editor.org RFC 9846 TLS 1.3 July 2026 ...`
>
> Searched the web for `https://openssl-library.org/post/2026-03-11-ech/`
>
> </details>
>
> The review catches a real error in the HRR constant, which I also missed earlier. It also contains two claims that need correction: the current accumulator does track sequence offsets and gaps, and OpenSSL now has ECH support in version 4.0. I’m separating those factual issues from suggestions that are useful but unnecessary for a small project evaluation.
>
> <details><summary>Searched the web</summary>
>
> Searched the web for `'4.0'`
>
> </details>
</details>

The independent review is useful, particularly on evaluation and labeling, but **some criticisms are overstated, two factual claims need correction, and several recommendations exceed what you need now**.

I checked the pasted review against the document, current accumulator, and primary specifications. Everything remained read-only.

**1. “There is no evaluation design” — substantially right, literally overstated.**

| Claim | Judgment |
|---|---|
| Only four one-line hypotheses | Correct. They provide an outline, not an executable evaluation plan. |
| Prediction targets are undefined | Partly correct. H1 names browser families and H4 names real/GREASE; the missing part is precise labels and measurement criteria. |
| No baseline specification | Overstated. H3 explicitly compares outer JA3/JA4 against JA3/JA4 plus ECH fields. That comparison needs extending and operationalizing. |
| No split, coverage, abstention, or uncertainty reporting | Correct. Coverage and abstention matter immediately. Train/test splits matter **only if you fit or tune a classifier**; they are unnecessary for simple descriptive measurements. |
| Need an ECH-off control | Useful for claiming what ECH hides or changes. Optional if the narrower question is what extra information ECH metadata adds. |
| Group splits by installation and session | Sensible for predictive evaluation. **Multiple installations are excessive as a prerequisite for this project**; independent capture sessions are a reasonable minimum. |
| Account for unsuccessful and unparseable connections | Agree. Use separate dimensions: capture/parse outcome and endpoint-labeled ECH outcome. Those categories overlap and should not form one mutually exclusive list. |

**Keep:** explicit experiment targets, a baseline comparison, repeated sessions, sample counts, and coverage. A full machine-learning evaluation framework would be over-engineered unless you actually build a classifier.

**2. “The lab recipe cannot test the hypotheses” — mostly correct.**

- **Client/provider coverage:** Correct. The recipe does not explain how to obtain the Firefox, impersonation-client, or varying-hostname captures that its hypotheses require. However, one provider is adequate for an explicitly provider-scoped demonstration.
- **Rejected ECH:** Correct. There is no controlled rejection recipe. Add one if rejection detection remains a demonstrated feature; otherwise mark it untested and omit the reconnect heuristic from evaluated claims.
- **HRR server:** The underlying concern is correct, but “OpenSSL won’t support ECH” is outdated as a blanket statement. **OpenSSL 4.0 supports ECH.** Merely restricting groups still does not provision ECH keys or give the client a usable configuration. Pin a concrete version and setup. [OpenSSL ECH announcement](https://openssl-library.org/post/2026-03-11-ech/).
- **“The rig can only test I1”:** Too confident. It can produce an HRR scenario, but that does not validate I1’s real-versus-GREASE conclusion. The rejected-real-ECH ambiguity from my earlier review still needs resolving.
- **Label oracle:** Correct in principle: TLS secret labels use the inner random when ECH succeeds and the outer random otherwise. ECH-specific labels can be logged even when an offer is rejected, so their presence alone does not establish acceptance. Correlation to the particular connection is essential. [RFC 9850 §§2.1–2.3](https://www.rfc-editor.org/rfc/rfc9850.html#section-2.1).
- **Verify logging first:** Agree with an early pilot. “First hour” is an arbitrary scheduling suggestion.
- **Server-log fallback:** Useful if you already have a controlled server. **Building a separate server infrastructure solely as a fallback is excessive** before testing available browser instrumentation.
- **Reproducibility:** Correct. Stored captures, labels, versions, configuration, and timestamps support repeatable analysis. They do not guarantee identical future behavior from a public service.

**3. “The headline contribution has almost no natural coverage” — a valid concern expressed too strongly.**

- **HRR dependence:** Correct for I1/I2. Their natural coverage is unmeasured, so “almost no” is not yet a supported quantitative conclusion.
- **I4 needs history:** Correct. It cannot classify an isolated handshake.
- **Only I5 fires on ordinary flows:** Correct only for *single-connection offer-type inference without HRR*. Ordinary flows still yield the ECH observations studied in H1–H3.
- **I5 is effectively Cloudflare-only:** The example is Cloudflare-specific; the proposed mechanism is not inherently limited to it.
- **Contradiction with §9:** There is tension, but not a strict contradiction: “likely” differs from “proven.” The real problem is the absence of measured reliability.
- **Precision/recall and another provider:** Necessary if promoting I5 as a classifier. **Unnecessary if you keep it as contextual metadata**, which is my recommendation.
- **Report coverage:** Agree. Distinguish deliberately forced HRR examples from naturally occurring captures.

I would remove I5’s automatic `LIKELY_REAL` promotion for now. That avoids spending the project on validating a cover-domain heuristic.

**4. “Cheaper signals are missing” — useful suggestions, with one major overclaim.**

- **“Any client talking to any non-ECH site emits GREASE”: Incorrect.** GREASE depends on client support and behavior; the specification recommends it rather than guaranteeing universal emission. [RFC 9849 §6.2.1](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.2.1).
- **Study GREASE separately:** Agree. Separate real ECH and GREASE when examining lengths and suites. The document does not explicitly say to pool them, but it fails to require separation.
- **H3 is predicted null with one advertised suite:** Reasonable under a fixed configuration: there is no suite-selection variation to distinguish clients. That does not invalidate H3 across other configurations.
- **Decode captured ECHConfig:** Strong, practical suggestion. Save the raw configuration and decoded fields as experiment metadata. An offline decoder is sufficient; **a production DNS-correlation subsystem is unnecessary**.
- **Replace inferred KEM and assumed `M=0`:** Only when the configuration is reliably associated with the connection. A nearby DNS response does not establish that the browser selected it.
- **Matching `config_id` and `public_name` proves real ECH:** Reject this proposed upgrade. These are consistency checks, not cryptographic proof; `config_id` is only one byte and is not globally unique. [RFC 9849 §§4–4.1](https://www.rfc-editor.org/rfc/rfc9849.html#section-4.1).
- **Use the Phase 1 manifest:** Reasonable reuse, not a requirement. A small Phase 2 experiment manifest is equally appropriate and avoids changing an established schema unnecessarily.

**5. “Architecture gaps” — mixed accuracy.**

- **Ground truth drawn inside the engine:** The diagram is ambiguous, but external provenance does not forbid software from importing labels. Clarify that the passive parser produces observations and the experiment harness attaches endpoint labels.
- **Missing label schema/harness:** Agree on a minimal deliverable: one manifest format and one repeatable correlation procedure. **A generalized labeling framework would be over-engineered.**
- **“Phase 2 stripped sequence tracking”: Incorrect for the current code.** [accumulator.cpp](<./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp>) uses sequence offsets, detects forward gaps, ignores fully duplicated buffered segments, and trims overlaps.
- **Accumulator contract is missing:** Still correct. Existing sequence handling does not establish complete TLS handshake assembly. Specify what reaches the parser and how unsupported/incomplete input is reported. Full recovery from arbitrary packet reordering can wait.
- **Unmeasured size claims:** Agree that the document supplies no capture evidence. That does not prove the numbers false; label them estimates or replace them with measurements.
- **“`enc` is only 32 bytes”:** Relevant clarification, not a rebuttal. The quoted extension size includes ciphertext and framing as well as `enc`.
- **Capture vantage/offloads:** Worth recording as a few metadata fields because packet-count claims depend on them. An extensive offload experiment matrix is unnecessary.
- **I3 on GREASE:** Agree for rejection statistics. Keep the passive statement “ECH was not accepted,” but reserve **“real ECH offer rejected”** for endpoint-labeled real offers.

**6. “No schedule, ownership or gates” — useful project management, not an architectural flaw.**

- **No minimum deliverable or pilot gate:** Fair. Define a small core deliverable and verify capture/label feasibility early.
- **No ownership/workstream split:** Optional coordination detail; it need not belong in the technical strategy.
- **No QUIC entry condition:** Disagree. Declaring TCP-only scope is sufficient. Adding a QUIC gate introduces unnecessary scope.
- **Cut browser-family comparisons:** Conditional advice. A small Chrome-versus-Firefox comparison may be cheaper and more relevant than a carefully controlled H2 hostname-length experiment.
- **Proposed priority order:** I would change it. Prioritize parser validation, labeled captures, then a small descriptive comparison. H2 requires careful controls and should not automatically outrank everything else.
- **Results/limits slide:** Agree.
- **Three-day deadline:** The review asserts November 4, but I have not independently established that deadline. Its schedule-driven cuts should remain conditional.

**7. “Confirm scope with the professor” — optional, not a blocker.**

Destination privacy and residual client identification are compatible research questions. The document explicitly chooses the latter. Asking the professor is sensible if assessment expectations are ambiguous, but **redirecting the project toward destination deanonymization would be scope expansion**. Describe residual leakage as context unless the assignment requires more.

**The four factual fixes:**

| Proposed fix | Verdict |
|---|---|
| HRR constant is wrong | **Correct and important.** The supplied replacement bytes match the specification. I missed this in my earlier review. [HRR constant](https://www.rfc-editor.org/info/rfc9846/#section-4.2.3). |
| Update TLS reference to RFC 9846 | **Correct.** It obsoletes RFC 8446. Section numbering changed: ServerHello is §4.2.3, HRR §4.2.4, and extensions §4.3. Historical citations to RFC 8446 remain valid when explicitly identified. [RFC 9846](https://www.rfc-editor.org/info/rfc9846/). |
| Qualify enterprise DNS blocking | **Correct.** Blocking records does not universally guarantee plaintext fallback; behavior depends on client policy and previously obtained configuration. RFC 9848 explicitly restricts fallback in relevant cases. This deserves one qualified sentence, not a new workstream. [RFC 9848 §5.1](https://www.rfc-editor.org/rfc/rfc9848.html#section-5.1). |
| Replace “mathematically false” | **Agree.** Say “a passive observer cannot verify acceptance from that confirmation without the required inner-handshake information.” The suggested “inner random” wording alone omits the transcript dependency. |

My recommendation is to accept the review’s **evaluation, provenance, and claim-calibration improvements**, while deferring multi-installation studies, provider-wide heuristic validation, generalized DNS correlation, elaborate scheduling machinery, and QUIC. The core should remain a well-explained ECH observer with a small, honestly labeled evaluation corpus.

> Short verdict: #1 is correct and the most important, and it exposes an error I made. #2–#3 are real gaps but over-built as proposed. #4–#5 are right, scaled down. #6–#7 are mostly right but partly overlap what I already told you. The proposed layout is a sensible direction but over-split for three days.
>
> | # | Claim | Fact-check | Scale |
> |---|---|---|---|
> | 1 | HRR copy test misclassifies rejected real ECH | Correct | Do now |
> | 2 | Need a connection state machine | Need is real; machinery is over-built | Minimal per-flow record |
> | 3 | Accumulator ≠ handshake reassembly | Partly valid | Targeted fix, no new module |
> | 4 | Observation model mixes facts and interpretation | Mostly valid | Trim |
> | 5 | I4/I5 should be experimental | Correct | Do now |
> | 6 | Lab can't deliver ground truth | Mostly valid | Core four cases only |
> | 7 | Stronger experiment controls | Valid, partly niche | Keep H2 control and baselines |
>
> ## 1. HRR copy test: correct, and I got this wrong earlier
>
> - RFC 8446 §4.1.2 requires the client to resend the same ClientHello after an HRR, changing only key_share, early_data, cookie, PSK and padding.
> - If the HRR has no ECH extension, or a mismatched confirmation, the client treats ECH as rejected and handshakes with ClientHelloOuter (§6.1.4, §6.1.6). That path has no ECH-specific modification, so a rejected real offer repeats its ECH extension unchanged, like GREASE.
> - The empty-`enc` behavior comes from §6.1.5, which applies only when the server accepted ECH. §7.1.1 says a rejecting server doesn't decrypt the second payload "if there is one".
> - §6.2.1 says the copy reveals a fake extension, but it never claims real ECH can't repeat.
> - I wrote that "a real client's second hello has an empty `enc`" without saying accepted-only. My Claude Doc has the same I1 error in §2.2 and the viva Q&A.
> - **Fix:** I1 becomes an observation ("ECH extension repeated unchanged"), compatible with GREASE and rejected real ECH. I2 stays sound and is stronger than we thought. A client only reuses its HPKE context with empty `enc` after its own acceptance check passes, so empty `enc` in the second hello shows a compliant client concluded ECH was accepted. That is a narrow exception to "acceptance is unobservable passively".
> - **Consequence:** after this fix, I2 is the only sound real-vs-GREASE rule. Slide 4 and H4 should present the result as a limit: passive GREASE/real separation mostly isn't possible.
>
> ## 2. State machine: need is real, proposal over-built
>
> - I1–I4 all need CH1, then HRR or ServerHello, then CH2 correlated per flow. I3 needs the server direction at all, and the plan never says how that joins to the ClientHello.
> - Over-engineered: a full lifecycle with retransmission semantics, tuple reuse, expiry and update-versus-summary output.
> - **Minimal version:**
>   - One record per 4-tuple, extending the existing flow tracker rather than adding a second one.
>   - Fields: CH1 observation, server first-message kind (ServerHello, HRR, or below TLS 1.3), HRR ECH extension present and its length, CH2 observation.
>   - Dedupe by TCP seq in the accumulator. A new SYN starts a fresh record.
>   - Emit one summary per flow at ServerHello, FIN/RST, timeout, or end of pcap.
>
> ## 3. Accumulator: wording fix plus one targeted change
>
> - "Reassembles cleanly" is unproven, so reword it. An 8 KB buffer doesn't establish handshake reassembly.
> - The ClientHello is almost certainly one TLS record spanning TCP segments, so record-spanning handshakes are a rare edge case for you.
> - The real risk is the server direction. ServerHello often arrives coalesced with other records, and I3 and HRR detection depend on parsing it. Your Phase 1 C++ engine already had a bug of exactly this kind: it erased the flow after any Handshake-type record.
> - Require the existing code to loop over every record in a buffer, and make gaps or oversize return INCOMPLETE/UNSUPPORTED, never MALFORMED.
> - A separate `tls_framer` module with state limits and timeouts is over-engineered this week.
>
> ## 4. Observation model: agree on three points, skip the four-way split
>
> - ABSENT must mean the whole ClientHello was parsed. A partial hello gives INCOMPLETE.
> - Use a findings bitmask instead of one enum. In the draft, DUPLICATE and `0xfd00` overwrite each other and the valid-body status.
> - Compute `inferred_kem` and the 32-byte-padding check at output time, not inside the decoder.
> - Treat `enc_len == 0` as a decoded fact, and check its context (CH1 vs CH2) in analysis.
> - Four separate concept types are more than you need. A status enum, a flags field and derived fields are enough.
>
> ## 5. I4/I5 as experimental: correct
>
> - RFC 9849 §10.10.4 lists config_id value and outer SNI as out-of-scope differentiators. That makes them research signals, not rules.
> - With I1 gone, they're the only remaining GREASE/real hints besides I2, so don't let them write `offer_type`.
> - Expose them as separate signal fields: `config_id_stable` (yes, no, or insufficient) and `public_name_match` (provider tag, exact match only).
> - Key the I4 state by (client IP, destination IP, port), not destination alone.
>
> ## 6. Ground truth: mostly valid
>
> - **Which config was used:** `dig` only approximates it. RFC 9850's `ECH_CONFIG` logs the exact ECHConfig the client used. Use that.
> - **Join key:** The ECH labels always use the outer ClientHello random, and the TLS secret labels use the inner random if ECH was accepted. The doc's oracle ("no secret matches the outer random, so accepted") is therefore incomplete.
> - **Simple labelling rule:**
>   - Handshake-secret rows keyed by the outer random mean rejected, or no ECH.
>   - No such rows, plus an `ECH_SECRET` row, means accepted, but confirm it. Decrypt the payload with `ECH_SECRET` and the outer-hello AAD (RFC 9849 §5.2, §6.1.1), read the inner random, and match a secret row.
>   - That decryption is about 100 lines in a Python harness.
> - **Core cases to cover:** accepted, rejected, GREASE and absent. Rejected real ECH needs no server of your own. Use a scripted ECH client with a deliberately stale config against a provider that sends retry_configs **[I]**.
> - **Drop the HRR variants for now.** They are niche and need an ECH-capable server you control. The local-OpenSSL HRR rig can only produce a GREASE-with-HRR trace, which per #1 can't be told apart from rejected real ECH. It buys nothing you can currently label, so cut it.
>
> ## 7. Experiment controls: valid, partly niche
>
> - **Keep:**
>   - The H2 name-length sweep. Ciphertext length is fixed client-side, so synthetic names of varying length suffice and the server needn't host them **[I]**. Check measured lengths against the RFC 9849 §6.1.3 formula: round up to 32, plus the tag.
>   - The same outer JA3/JA4 baseline.
>   - Accuracy plus coverage.
>   - Session-grouped splits.
> - **Niche for now:** fresh-versus-resumed connections and held-out configurations. You have one provider and one config.
>
> ## Proposed layout
>
> I haven't seen your actual tree, so check this against it. The direction is good:
> - Keep key-handling out of the passive engine.
> - Add an `experiments/ech/` area.
> - Separate decoding from analysis.
>
> It is over-split for three days. Moving or splitting stable Phase 1 modules risks your 7-PCAP parity. Leave `accumulator`, `parser`, `ja3`, `ja4`, `db`, `capture` and the existing `flow` where they are. Add only this:
>
> ```text
> engine/include/tlsfp/   ech.hpp  ech_analysis.hpp
> engine/src/             ech.cpp  ech_analysis.cpp
> engine/tests/           test_ech.cpp  test_ech_analysis.cpp  (+ fixtures/)
> experiments/ech/        label_join.py  features.py  manifests/  README.md
> ```
>
> - **`ech`** holds the decoder, the findings flags, and the HRR check. The HRR check is just "ECH extension present and length 8", so a separate context-specific decoder is overkill.
> - **`ech_analysis`** runs the rules over a flow summary.
> - **Extend, don't add modules:**
>   - Extend `flow` for the per-flow record.
>   - Extend the ServerHello parser with `is_hrr` and an extension-ID list.
>   - Extend `output` to emit one JSON line per flow, with observation, interpretation and signal fields. The Python scripts need that.
> - **`test_ech`** fixtures: certificate-compression-only (0x001b, no ECH), truncated, trailing bytes, duplicate, and cleartext `0xfd00`.
> - **`test_ech_analysis`:** synthetic CH1, HRR, CH2 sequences.
> - Skip `tls_framer`, `hello.hpp`, `ech_types.hpp` and `connection_tracker` unless you find the existing code needs them.
> - **Harness:** `label_join.py` joins the keylog to the pcap on the outer random and runs the accepted/rejected rule from #6.
> - **Hand-decoding:** the ECH decode is also worth cross-checking by hand against RFC 9849 §5 if tshark doesn't dissect the extension.
>
> ======================================
>
> Now we have compiled all the feedback from all sources. Time to clean up the document accordingly. Apply the suggested fixes from your analysis and the other analysis. Keep it simple and respect the fundamental theory. Remove the code details from section 3, unless any part of it is non-negotiable and deserves a spot in the final doc. Clarify any remaining conflicts with me by asking questions.

<details><summary>9 previous messages</summary>

> I’ll consolidate the feedback into a simpler design document, remove the code snippets, and keep the protocol rules and evidence limits explicit. I’ll also check the remaining claims before incorporating them, especially I2’s acceptance inference and the proposed labeling shortcut. I’m using the documentation skill for this revision.
>
> For this implementation, should HRR handling remain an optional extension described in the document, or be part of the required deliverable? I recommend keeping the theory and corrected I1/I2 rules, while making HRR implementation and lab validation optional.
> - HRR optional; retain corrected theory
> - HRR required, including validation
>
> <details><summary>Explored 2 files, ran 2 commands</summary>
>
> <details><summary>Explored 3 files</summary>
>
> - Read `~/.codex/plugins/cache/claude-cowork/engineering/1.2.0/skills/documentation/SKILL.md`
> - Read `./AGENTS.md`
> - Read `./.agents/CONTEXT.md`
>
> </details>
>
> - Ran `rg --files 'TLS-Fingerprinting/Phase 2/engine' -g '!build/**'; cat 'TLS-Fingerprinting/Phase 2/engine/include/tlsfp/capture.hpp' 'TLS-Fingerprinting/Phase 2/engine/include/tlsfp/parser.hpp' 'TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp'`
>
> - Ran `git status --short; cat 'TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'`
>
> </details>
>
> **For this implementation, should HRR handling remain an optional extension described in the document, or be part of the required deliverable? I recommend keeping the theory and corrected I1/I2 rules, while making HRR implementation and lab validation optional.**
>
> HRR optional; retain corrected theory
>
> <details><summary>Ran a command, searched the web</summary>
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc9849.html`
>
> - Ran `git -C TLS-Fingerprinting rev-parse --show-toplevel; rg -n 'struct Impl|struct CaptureEngine::Impl|FlowKey|flags|TH_SYN|FIN|RST|seq|record' 'TLS-Fingerprinting/Phase 2/engine/src/capture.cpp'; rg --files -g AGENTS.md 'TLS-Fingerprinting' .agents`
>
> </details>
>
> HRR will remain optional, with the corrected theory retained. I’ll keep `ech_parser.cpp` as you requested and place the small connection-summary record in the existing capture code—the current tree has no separate flow or output module to extend. I’ll also replace the “missing keylog row means accepted” shortcut with a requirement for positive, connection-correlated evidence.
>
> <details><summary>Ran 3 commands</summary>
>
> - Ran `git status --short -- 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; git ls-files -- 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; wc -l 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'`
> - Ran `cp 'TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md' /tmp/ech-integration-strategy.before.md`
> - Ran ````cat > 'TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md' <<'EOF'
> # Encrypted Client Hello (ECH): Protocol Foundations & Integration Plan
>
> **CS331: Computer Networks — Network Security & TLS Fingerprinting, Phase 2**  
> **Team T014** · **Target binary:** `tlsfp_phase2` · **Revised:** November 1, 2026  
> **Status:** Design and evaluation plan; the proposed ECH implementation and experiments are not yet validated.
>
> ## 1. Objective & Scope
>
> > What client-identifying and structural information survives in observable TCP/TLS handshakes with ECH, and what do ECH fields add beyond the same outer-handshake JA3/JA4 fingerprints?
>
> ECH conceals the intended service name and other sensitive ClientHello fields. Our contribution is a bounds-checked observer, an explanation of its visibility limits, and a small labeled evaluation. A finding that a feature adds no useful discrimination is a valid result.
>
> **Required scope:** TCP capture; ECH extension decoding; correlation of ClientHello with the server's initial response; structured output; four labeled cases (accepted real ECH, rejected real ECH, GREASE ECH, and ECH absent); and controlled measurements of lengths and suite fields. Preserve standard JA3/JA3S and existing JA4/JA4S behavior, including extension permutation and GREASE handling. The project's JA3/JA3S validation requirement remains a prerequisite to fingerprint scope expansion.
>
> **Optional scope:** HRR sequence analysis and live HRR experiments, cross-connection `config_id` analysis, and broader browser comparisons. Retain HRR theory below, but do not make it a prerequisite for the core deliverable. QUIC and a general-purpose TCP/TLS reconstruction framework are outside this implementation's scope.
>
> Three rules govern the design:
>
> 1. **Observe first:** Decode wire fields without classifying the offer as real or GREASE.
> 2. **Explain interpretations:** Every inference names its evidence and may abstain.
> 3. **Label independently:** Endpoint instrumentation supplies experimental ground truth. Passive output never labels its own evaluation data.
>
> ### Governing References
>
> - [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html): ECH wire format, client/server behavior, and privacy limits.
> - [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html) and [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html): ECH configuration delivery through DNS SVCB/HTTPS records.
> - [RFC 9850](https://www.rfc-editor.org/rfc/rfc9850.html): SSLKEYLOGFILE, especially §§2.1 and 2.3.
> - [RFC 9846](https://www.rfc-editor.org/info/rfc9846/): current TLS 1.3 specification; ClientHello §4.2.2, ServerHello §4.2.3, HRR §4.2.4, extensions §4.3, and records §5. It obsoletes RFC 8446; older section numbers must not be silently carried across.
> - [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): HPKE; [RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html): certificate compression; [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html): GREASE.
>
> ## 2. Protocol Foundations & Observability
>
> ### 2.1 Outer and Inner ClientHello
>
> A real ECH client constructs a private `ClientHelloInner`, encodes and pads it, and encrypts it with HPKE Base mode using a server ECHConfig. It sends a normal TLS-framed `ClientHelloOuter` containing the ciphertext in an ECH extension. The outer SNI normally carries the configuration's `public_name`; it is not the inner destination SNI.
>
> The visible ClientHello retains ordinary TLS framing. ECH requires specialized extension decoding, not a second implementation of ClientHello framing. Decrypting and reconstructing the inner hello is a separate, endpoint-assisted lab task.
>
> | Extension | Codepoint | Meaning at our client-facing capture point |
> | :--- | :--- | :--- |
> | `encrypted_client_hello` | `0xfe0d` / 65037 | Decode the ECH body. Presence alone does not establish real ECH or acceptance. |
> | `ech_outer_extensions` | `0xfd00` / 64768 | Compression references used only in `EncodedClientHelloInner`; forbidden in the outer and reconstructed inner hello. Flag its presence in the outer hello. |
> | `compress_certificate` | `0x001b` / 27 | Certificate compression, never ECH. |
>
> The current ECHConfig version is also `0xfe0d`. This plan supports that format, without attempting historical draft-format compatibility. An ECH `inner` marker (`type = 1`, no variant-specific data) is valid in the inner hello, including on an internal split-mode link. Seeing it at our external client-facing tap is a contextual protocol anomaly. See RFC 9849 §§5–5.1 and §7.
>
> ### 2.2 ECH Outer Extension Fields
>
> The following layout describes the **extension body**, after the ordinary TLS extension type and length header:
>
> | Field, in wire order | Encoding | Observable meaning |
> | :--- | :--- | :--- |
> | `type` | 1 byte, `0` for outer | Selects the outer variant. |
> | `kdf_id` | 2 bytes | HPKE KDF identifier. |
> | `aead_id` | 2 bytes | HPKE AEAD identifier. |
> | `config_id` | 1 byte | Configuration selector; not a globally unique key or provider identifier. |
> | `enc` | 2-byte length, then bytes | KEM encapsulation; empty on the accepted-ECH post-HRR path. |
> | `payload` | 2-byte length, then at least 1 byte | Ciphertext of the encoded, padded inner hello. |
>
> All multi-byte integers use network byte order. The decoder must validate declared lengths and complete consumption of the extension body. Export-only AEAD `0xffff` cannot seal ECH; report the violation separately from structural decoding. Unknown algorithm identifiers should remain visible as numeric values, without inventing an algorithm or treating unfamiliarity alone as malformed data.
>
> The extension does **not** carry `kem_id`. A 32-byte `enc` is consistent with X25519 in known profiles, but length is not an explicit KEM identification. Empty `enc` after HRR does not mean that no KEM was used. An endpoint-correlated ECHConfig can supply the actual KEM identifier in the lab.
>
> For real ECH, the suite must be selected from the ECHConfig's advertised suites. A fixed single-suite configuration leaves no suite-selection variation to identify clients. GREASE suite and length choices should be studied separately. See RFC 9849 §§4–6 and RFC 9180 §7.3.
>
> ### 2.3 Ciphertext Length & Padding
>
> Let `L` be the encoded inner length **after name-dependent and other extension padding, but before final 32-byte rounding**, and let `T` be the selected AEAD's ciphertext expansion. Under the recommended scheme:
>
> $$\text{ciphertext\_len} = 32\left\lceil\frac{L}{32}\right\rceil + T.$$
>
> For the common AEADs with a 16-byte tag, this gives `ciphertext_len % 32 == 16`, for example 336, 368, or 400 bytes. This is a conditional padding-policy check, not a validity rule or a real-versus-GREASE discriminator. GREASE is designed to mimic the same sizes.
>
> For an inner hostname of byte length `D`, the recommended name padding adds `max(0, M - D)` bytes, where `M` is the configuration's `maximum_name_length`. If `M = 0`, name length can affect ciphertext buckets when other contents remain fixed. This does not reveal an exact hostname or its exact length. Other extension padding still matters. Read `M` from the configuration used in the experiment rather than assuming a provider's deployed value. See RFC 9849 §§6.1.3 and 6.2.1.
>
> ### 2.4 Acceptance, Rejection & HRR
>
> **Ordinary ServerHello:** Acceptance confirmation occupies the last 8 bytes of `ServerHello.random` and depends on the inner random and inner transcript. A passive observer without that information cannot verify the confirmation. TLS 1.3 completion alone therefore does not establish ECH acceptance. Resolve the negotiated version from `supported_versions` when present; the legacy ServerHello version field alone cannot distinguish TLS 1.3 from TLS 1.2.
>
> **Observable non-acceptance:** Negotiation below TLS 1.3 rules out ECH acceptance. An HRR without the ECH extension also indicates non-acceptance. These observations do not distinguish GREASE from a rejected real offer. Count a connection as **rejected real ECH** only with an independent real-offer label.
>
> **HRR recognition:** Use the fixed ServerHello random, SHA-256 of `HelloRetryRequest`:
>
> ```text
> CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
> C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
> ```
>
> An HRR ECH body has length 8 and a different format from the ClientHello ECH body. Presence is insufficient: a rejecting server may send 8 random bytes. The client checks the confirmation internally.
>
> **Corrected retry distinction:** GREASE copies its ECH extension unchanged after HRR. A real offer rejected at HRR follows the outer-handshake path and can also repeat it unchanged. Thus repetition is an observation, not a GREASE classification. On the accepted-inner path, the client reuses its HPKE context, keeps the suite and `config_id`, sends empty `enc`, and generates a fresh ciphertext.
>
> For a compliant client, that second-hello pattern is evidence that **the client concluded the HRR accepted ECH**. It is a narrow behavioral inference, not passive cryptographic verification, and does not prove that the final handshake completed successfully. See RFC 9849 §§6.1.4–6.1.6, 6.2.1, and 7.1.1; TLS retry restrictions are in RFC 9846 §4.2.2.
>
> After rejection, retry configurations and certificates are encrypted in TLS 1.3. The client authenticates the public name before using authenticated recovery information; recovery can retry ECH or, where permitted, disable it. A quick reconnect or absent application traffic is not sufficient evidence of rejection and is not a core classifier.
>
> ### 2.5 DNS & Remaining Visibility
>
> DNS HTTPS/SVCB records can publish ECHConfigList through the `ech` parameter. A separate DNS lookup records available configurations, not necessarily the one selected by a browser. Matching public name and `config_id` supplies context, not proof of encryption or acceptance.
>
> Plaintext DNS and destination IPs can expose information that ECH conceals in TLS. Encrypted DNS addresses the DNS disclosure channel; DNSSEC provides authenticity, not confidentiality. Filtering HTTPS records does not universally force plaintext fallback: client policy and previously learned configuration matter, and RFC 9848 §5.1 restricts fallback after successful discovery in the specified circumstances.
>
> ECH does not expose HTTP User-Agent headers or establish human presence. Its HPKE KEM is distinct from the TLS key exchange; a hybrid TLS key share does not establish post-quantum ECH encryption. TCP options and JA4T belong to a separate transport analysis.
>
> ## 3. Integration Architecture
>
> This section defines responsibilities and essential contracts. Function signatures, classes, enum layouts, hashes, and parser code are intentionally left to implementation.
>
> ### 3.1 Keep the Existing Engine, Add Two Focused Modules
>
> | Component | Responsibility |
> | :--- | :--- |
> | Existing `parser.cpp` | Parse shared ClientHello/ServerHello framing, dispatch ECH bodies, retain the outer random, and expose negotiated version and optional HRR metadata. |
> | New `ech_parser.cpp` | Decode ECH-specific bodies using the existing bounded reader. No connection state, classification, DNS lookup, or secrets. |
> | New `ech_analysis.cpp` | Evaluate contextual validity and evidence over observations. Keep experimental signals separate from offer classification. |
> | Existing `accumulator.cpp` | Deliver complete supported records with sequence-aware accumulation; preserve remaining bytes and report incomplete/unsupported input. |
> | Existing `capture.cpp` | Correlate directions in a small connection record and emit a structured summary. |
> | External experiment harness | Correlate endpoint labels, configurations, and passive output; perform any secret-assisted decryption outside the engine. |
>
> The current Phase 2 tree has no standalone `flow` or `output` module. Add the small connection record and JSON output within the existing capture implementation rather than assuming those modules exist or introducing a parallel framework.
>
> Proposed additions, relative to `Phase 2/`:
>
> ```text
> engine/include/tlsfp/   ech_parser.hpp  ech_analysis.hpp
> engine/src/             ech_parser.cpp  ech_analysis.cpp
> engine/tests/           test_ech_parser.cpp  test_ech_analysis.cpp  fixtures/
> experiments/ech/        README.md  label_join.py  features.py  manifests/  results/
> ```
>
> Keep ECH observation types with the ECH headers. Extend existing tests and build declarations as needed. Do not split or move stable fingerprint, database, or capture modules merely for this feature. The script names describe planned harness responsibilities; no implementation or decryption-effort estimate is implied.
>
> ### 3.2 Parse Once, Interpret After the Needed Evidence Arrives
>
> Within one hello, decode extension-local facts first and finalize cross-extension checks after the complete extension vector. This preserves independence from randomized extension ordering. Retain raw extension order for standard fingerprints; ECH metadata is an additional feature set, not a modified JA3/JA4 definition.
>
> Across messages, keep one bidirectional connection record, using IP version and endpoint addresses/ports with a consistent client/server orientation. Record CH1, its outer random, the first server response, timestamps, and completion status. Add CH2 and HRR metadata only if optional HRR analysis is implemented. An accumulator entry is not this record: it is currently discarded after record completion.
>
> Retransmitted bytes must not create a second hello. A new SYN starts fresh connection state. Emit one summary at the final ServerHello, or an incomplete summary at FIN/RST, expiry, or end of capture. HRR is not the final ServerHello. Retain only the owned fields needed for the summary; packet-buffer views must not outlive their bytes. Keep connection storage bounded and reclaim it after summarization/expiry.
>
> ### 3.3 Minimal Observation Contract
>
> Use a parsing/completeness status plus independent findings flags. Preserve a structurally decoded body even when another extension creates an anomaly. Duplicate ECH, forbidden outer `0xfd00`, inappropriate inner markers, and contextual empty-`enc` violations must not overwrite one another or silently select a duplicate as authoritative.
>
> - **Absent:** established only after the complete ClientHello extension vector was examined.
> - **Incomplete:** capture bytes are missing, including an unfinished hello. Presence can be known from a header while body fields remain unavailable.
> - **Unsupported:** a known implementation limit was reached.
> - **Malformed:** complete available framing proves a structural contradiction; packet loss or a size limit alone is not malformed ECH.
>
> Decode empty `enc` as a fact, then check its message context in analysis. Keep KEM guesses and padding-policy annotations out of the decoder; derive them for analysis/reporting with explicit assumptions. Missing values stay unknown rather than becoming zero-valued observations.
>
> ## 4. Evidence Rules & Output
>
> | Rule | Evidence | Allowed result |
> | :--- | :--- | :--- |
> | **I1 — optional HRR** | Correlated CH1 → HRR → CH2, with identical ECH bytes. | `extension_repeated_unchanged`; compatible with GREASE and rejected real ECH. Offer type remains unknown. |
> | **I2 — optional HRR** | Valid CH1 → HRR → CH2; CH2 has empty `enc`, unchanged suite and `config_id`, and changed payload; HRR ECH framing is valid. | Likely real offer; a compliant client inferred HRR acceptance. Keep this separate from endpoint-verified acceptance and final handshake success. |
> | **I3** | ECH observed, then negotiated version below TLS 1.3; optionally HRR without ECH. | Non-acceptance observed. Real-offer rejection statistics require endpoint labels. |
> | **I4 — experimental** | Repeated connections show stable or changing `config_id`. | A signal only; never sets offer type. |
> | **I5 — experimental** | Outer SNI exactly matches a recorded public name. | A contextual match with provenance; never sets offer type or acceptance. No suffix-based classification. |
>
> I4 analysis can be performed offline, grouped by client IP, destination IP and destination port within a recorded observation window. Record sample count and return insufficient data where appropriate. Do not build a live cross-connection cache for the core deliverable. Neither I4 nor I5 becomes reliable merely because I1 is inconclusive.
>
> The structured connection summary contains:
>
> - Capture/session identity, endpoint tuple, timestamp, outer random, and completion reason.
> - ECH presence, parse status, findings, outer SNI, decoded suite/configuration identifiers, and `enc`/ciphertext lengths where available.
> - Passive interpretation and named evidence; default offer type is unknown and acceptance is unverified. With HRR omitted, the core has no positive real-versus-GREASE classifier.
> - Optional derived KEM/padding annotations and experimental signals, clearly marked as such.
> - The ordinary outer JA3/JA4 baseline; server fingerprints only when the corresponding complete ServerHello is available.
>
> Emit one JSON line per connection summary for offline joins. Endpoint labels belong to a separate harness result, with their source recorded. No endpoint secrets enter passive-engine output.
>
> ## 5. Transport Contract & Supported Limits
>
> TCP segmentation, TLS record framing, and handshake-message framing are different boundaries. PQ key shares and ECH can increase ClientHello size, but this document has no measured size distribution. Measure actual lengths and packet counts; do not claim a universal two-packet handshake or that the 8 KB buffer proves correct reassembly.
>
> Make targeted changes in the existing accumulator/parser path:
>
> 1. Preserve sequence-offset, overlap, and gap checks. Gaps must produce incomplete results rather than guessed bytes.
> 2. Iterate over every complete record in contiguous input, preserving any partial tail. Coalesced records and compatibility ChangeCipherSpec records must not hide the ServerHello/HRR or cause premature connection eviction.
> 3. Parse only supported plaintext handshake framing; encrypted records are not plaintext extensions.
> 4. For the core, support complete hello messages within one TLS record, including records split across TCP segments. If a hello spans records, detect and report the unsupported case rather than producing a partial fingerprint. Add cross-record handshake assembly only if pilot captures require it.
> 5. Document and consistently enforce the retained 8 KB accumulation/hello bound and connection-state limits. Oversized valid input is unsupported, not malformed.
>
> Record the capture point and relevant offload settings with any packetization measurements. General out-of-order recovery and a separate TLS-framer module are deferred. Validate the supported path against actual captures before describing it as working.
>
> ## 6. Experiments & Evaluation
>
> ### 6.1 Small Evaluation Matrix
>
> | Study | Controlled comparison | What may be concluded |
> | :--- | :--- | :--- |
> | **H1 — optional second client** | Repeat Chrome and Firefox captures against the same destination/configuration. Analyze real ECH and GREASE separately. Add an impersonation client only if available. | Describe observed length distributions; do not promise universal browser identification. |
> | **H2 — controlled length study** | One scripted client, fixed ECHConfig and suite, fixed non-SNI inner structure and padding policy; vary only inner hostname byte length. Record `M` and compare with §2.3. | Test the predicted length buckets, including `M = 0` where available. A cross-host correlation alone does not isolate SNI length. |
> | **H3 — incremental feature value** | Same captures and target labels: outer JA3/JA4 alone versus those fingerprints plus ECH suite/length features. Separate real and GREASE offers. | Report additional variation or discrimination. A single-suite real-ECH configuration may contribute no suite information. |
> | **H4 — limits of separation** | Compare passive conclusions with real/GREASE labels. If HRR is implemented, test I1/I2 with labeled sequences. | Report abstention and demonstrated coverage. I1 is not a GREASE detector; untested HRR behavior remains theory. |
>
> For H2, an instrumented client may construct offers for synthetic inner names without those names being hosted, provided it can vary inner SNI while keeping the cover name/configuration and other inputs fixed. These measure **client-generated length**, not successful service connections or accepted ECH. Keep them separate from the four-case connection corpus. If the selected client cannot hold these variables fixed, report the limitation rather than claim a controlled H2 result.
>
> ### 6.2 Minimum Reporting
>
> Keep a per-connection manifest with client/build and OS versions, session/run ID, timestamp, destination, intended inner hostname where known, exact configuration and source, client offer mode, and independently observed acceptance state. Keep raw configuration bytes plus decoded `config_id`, `public_name`, KEM, suites and `maximum_name_length` when available. A DNS snapshot is marked as advertised configuration unless selection is independently established.
>
> Repeat captures in independent sessions. Record session reuse/resumption settings and keep them consistent within each comparison. A separate resumption study and held-out providers/configurations are optional.
>
> Report attempted connections, capture/parse outcomes, and endpoint-labeled ECH outcomes separately; do not count only accepted connections. Unknown labels remain visible. State counts per case, feature distributions, and the baseline comparison. For any classifier, report accuracy on classified labeled cases **and coverage**; unknowns must not disappear from the denominator. If fitting or tuning a classifier, split by capture session before tuning. Descriptive tables do not require a train/test pipeline.
>
> An ECH-off comparison with the same client helps demonstrate lost visibility, but disabling real ECH may leave GREASE enabled. Verify extension absence before calling a capture the no-ECH control. Bound conclusions to the measured clients and configuration.
>
> ## 7. Lab Corpus & Ground Truth
>
> ### 7.1 Pilot Before Scaling
>
> Use a dedicated client process/profile, TCP transport with QUIC disabled and verified in the capture, packet capture started before connection establishment, and endpoint logging enabled before launch. Start with one accepted-ECH connection. Verify the exact client build's instrumentation and configuration logging before collecting repetitions; setting SSLKEYLOGFILE alone does not guarantee ECH-specific labels.
>
> A public diagnostic endpoint can corroborate an accepted case, but associate its response with the actual connection and retain supporting endpoint evidence. One navigation may create several connections or retries. Store pcaps, manifests, and label provenance for repeatable analysis; public-service behavior is not guaranteed reproducible later.
>
> ### 7.2 Four Required Cases
>
> | Case | How to obtain it | Label requirement |
> | :--- | :--- | :--- |
> | Accepted real ECH | Verified ECH-capable client using a usable configuration and endpoint. | Positive, connection-correlated acceptance evidence. |
> | Rejected real ECH | Instrumented scripted client makes a real offer using a deliberately unusable configuration, preserving a valid public name and supported suite. A stale configuration is a candidate, not a guarantee of rejection. | Establish the real offer and its non-acceptance from endpoint evidence; record retries as separate connections. No controlled server is required if this public-endpoint recipe works in the pilot. |
> | GREASE ECH | Verified client GREASE mode, or instrumentation establishing that no usable configuration was used and a dummy offer was generated. | Extension presence or a separate `dig` result alone is insufficient. |
> | ECH absent | Client configured to omit both real ECH and GREASE. | Complete ClientHello confirms absence. |
>
> If a collection recipe fails, mark the case missing and its associated claim unvalidated; do not relabel an unknown flow to fill the matrix. HRR captures are optional. For an accepted-ECH HRR experiment, use a verified ECH-capable server/configuration and a mutually supported group that forces HRR. Merely restricting a server's groups does not enable ECH.
>
> ### 7.3 Keylog Correlation
>
> RFC 9850 §2.3 keys `ECH_CONFIG` and `ECH_SECRET` by the **outer random**. The former records the selected configuration; the latter is the HPKE KEM shared secret. Neither label alone proves acceptance. Under §2.1, TLS 1.3 handshake/application secret labels use the **inner random on acceptance**, otherwise the outer random.
>
> The harness first joins ECH labels to the captured outer random. Prefer a directly correlated endpoint acceptance result. Where using the secret-based route, authenticated ECH decryption with the logged configuration/shared secret and correctly constructed outer-hello AAD recovers the inner random; associate the resulting TLS handshake with its secret rows or verify its acceptance confirmation. Use a verified tool or independently checked harness, not the passive classifier being evaluated.
>
> For an independently established real offer, a corresponding outer-handshake secret record supports non-acceptance. Absence of such a row is **not** proof of acceptance; logs may be incomplete. Missing labels, failed decryption, or ambiguous joins yield an unknown outcome. Decryption and key handling remain outside the passive C++ engine. Do not assume a particular script size or that generic TLS traffic secrets can decrypt the ECH payload.
>
> ## 8. Delivery Order & Validation Gates
>
> 1. **Pilot and decoder:** verify capture/label feasibility; implement isolated extension decoding and fixtures. Cross-check a real envelope manually against the wire layout and with an independent dissector where supported.
> 2. **Core integration:** add minimal bidirectional summaries, structured output, and the targeted record-processing fixes. Verify both client and server directions and preserve existing fingerprint parity on saved captures.
> 3. **Labeled corpus:** collect the four cases with provenance and repeat sessions. Publish missing/unlabeled counts rather than treating them as successful validation.
> 4. **Measurements:** run the controlled H2 study and H3 baseline comparison; add a second browser when practical. Record null results and limits.
> 5. **Optional extensions:** only after the core works, add validated HRR analysis or offline I4/I5 signals. Omit untested features from demonstrated capability claims.
>
> Required parser fixtures include `0x001b` without ECH, a valid outer body, truncated capture, contradictory complete lengths, trailing bytes, duplicate ECH, cleartext `0xfd00`, inner marker at the external tap, and empty `enc` with known/unknown message context. Integration checks cover segmented records, coalesced server records, retransmission deduplication, unsupported sizes, and absence versus incomplete capture. Optional analysis fixtures cover CH1/HRR/CH2, including unchanged rejected-real and GREASE cases; synthetic fixtures establish rule behavior, not empirical real-versus-GREASE accuracy.
>
> ## 9. Presentation & Defensible Claims
>
> Present the visible wire layout, observation/interpretation/ground-truth distinction, labeled corpus, controlled length result, incremental feature comparison, and a results-and-limits slide. Include sample counts, classification coverage where applicable, and supported transport limits. HRR behavior is theory unless separately validated.
>
> Use these statements consistently in the report and viva:
>
> - **Acceptance:** ordinary ServerHello confirmation is not passively verifiable without inner-handshake information. Optional I2 can reveal a compliant client's HRR acceptance conclusion; it does not prove final success.
> - **Real versus GREASE:** extension presence, padding buckets, unchanged HRR copies, familiar public names, and configuration-ID matches do not prove a real offer. The core may correctly abstain on every offer-type classification.
> - **Lengths and KEM:** ciphertext length includes encoded inner content, padding and AEAD expansion. KEM length annotations are guesses unless supplied by correlated configuration evidence.
> - **Privacy and identity:** ECH conceals inner fields, not every destination disclosure channel. TLS fingerprints characterize client-stack behavior, not human intent or guaranteed application identity.
> - **Implementation status:** evidence from actual runs is required for claims of correct reassembly, successful labeling, or identification accuracy. This plan and synthetic tests alone establish none of those results.
> EOF````
>
> </details>
>
> The rewrite is in place. Section 3 now describes responsibilities and essential contracts without C++ snippets. The HRR copy rule is corrected, I2 is framed as evidence of a compliant client’s acceptance conclusion, and HRR validation is optional. I’m checking the document for contradictions and will then update the project context as required by `AGENTS.md`.
>
> <details><summary>Edited a file, explored a file, ran 4 commands</summary>
>
> - Ran `sed -n '151,330p' 'TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; git -C TLS-Fingerprinting status --short`
>
> - Ran `git diff --check; git diff --stat -- 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; wc -lw 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; sed -n '1,150p' 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md` (+5 -3)
>
> - Ran ``cat >> .agents/CONTEXT.md <<'EOF'
>
> ## 6. Phase 2 ECH Design Decisions — November 1, 2026
>
> - Revised `TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md` as a protocol and integration plan; removed embedded C++ implementations. This records design decisions, not completed implementation or experimental validation.
> - Keep shared TLS framing in `parser.cpp`. Plan only `ech_parser.hpp/.cpp` and `ech_analysis.hpp/.cpp` plus focused tests and an external `experiments/ech/` harness. Keep minimal bidirectional connection summaries and structured output in existing `capture.cpp`; the current Phase 2 tree has no standalone flow/output module. Defer a broader module split.
> - HRR implementation and live validation are optional by explicit user decision; retain corrected theory. Identical ECH bytes after HRR can mean GREASE or rejected real ECH (I1). Empty enc with unchanged suite/config ID and fresh ciphertext after a valid HRR supports a compliant client's acceptance conclusion (I2), not cryptographic proof or final success. I4/I5 remain experimental signals and never set offer type.
> - Keep observation status and independent findings separate; absence requires a complete hello. Gaps are incomplete and implementation limits unsupported. Preserve standard fingerprint behavior. Target existing TCP/record handling; cross-record hello assembly is deferred unless pilot captures require it.
> - Plan four independently labeled cases (accepted real, rejected real, GREASE, absent), a controlled H2 hostname-length study and outer JA3/JA4 baseline comparisons. Keep endpoint secrets and decryption outside the passive engine. Missing keylog rows do not prove acceptance; require positive connection-correlated evidence. No ECH capture, accuracy, or reassembly result is established by this document update.
> EOF``
>
> <details><summary>Explored a file</summary>
>
> - Read `./.agents/CONTEXT.md`
>
> </details>
>
> - Ran ````git diff --check; git diff --numstat -- 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; git status --short; sed -n '185,242p' 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; rg -n '^```|CF 21|I[1-5]|HRR|^## ' 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'````
>
> </details>
</details>

Updated the [ECH strategy document](<./TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md>).

- Removed C++ snippets; retained protocol facts and essential contracts.
- Simplified the architecture around `ech_parser.cpp` and `ech_analysis.cpp`.
- Corrected I1/I2 and kept HRR optional.
- Clarified ground truth, transport limits, and evaluation controls.
- Updated project context as required.

Documentation checks passed. No implementation files changed.

> "Across messages, keep one bidirectional connection record, using IP version and endpoint addresses/ports with a consistent client/server orientation. Record CH1, its outer random, the first server response, timestamps, and completion status. Add CH2 and HRR metadata only if optional HRR analysis is implemented. An accumulator entry is not this record: it is currently discarded after record completion."
>
> I have a doubt - does the existing information stored in headers of certain layers of the network stack not provide a enough details to maintain the connection record?
>
> Also, can you explain which layer of the network stack does our tool as a whole operate in? Can it be installed in routers or switches as a utility?

<details><summary>4 previous messages</summary>

> I’ll check the capture path so I can distinguish what packet headers already tell us from what the tool needs to remember across packets, and explain where it could run.
>
> <details><summary>Explored 3 files</summary>
>
> - Read `~/.codex/plugins/cache/claude-cowork/anthropic-skills/1.0.0/skills/learn/SKILL.md`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp`
>
> </details>
>
> I’m using the learning skill to explain this through a packet example. The key distinction is that headers identify which connection a packet belongs to, while the connection record remembers what we observed earlier on that connection.
>
> <details><summary>Searched the web</summary>
>
> Searched the web for `site.tcpdump.org manpages pcap live capture network interface ...`
>
> </details>
</details>

**Yes—the headers give us enough information to identify the connection. But we still need a small record to remember what happened on it.** Those are two different jobs.

IP headers provide source/destination addresses and the transport protocol. TCP headers provide ports, sequence numbers, acknowledgments, and flags. Together, these let us associate packets with a TCP connection and reconstruct its bytes.

Consider this exchange:

```text
Client → Server:  ClientHello containing ECH
Server → Client:  ServerHello negotiating TLS 1.2
```

When the second packet arrives, its headers identify the connection—but they do not repeat the earlier ECH offer. To conclude “ECH was offered but could not have been accepted,” our tool must remember the first observation.

| Information | Where it comes from |
|---|---|
| Which endpoints are communicating? | IP addresses and TCP ports |
| Where do these bytes belong in the stream? | TCP sequence numbers |
| Did this client previously offer ECH? | Our saved ClientHello observation |
| What server response followed that offer? | Our connection record joining both directions |

So we **reuse header information as the record’s key**, and store only the additional history needed for analysis. We do not need to duplicate every header or implement a complete TCP endpoint.

The endpoints’ operating systems already maintain their own TCP connection state. Our passive sniffer, however, receives captured packets—not access to those remote operating systems’ connection records. Even a router’s connection-tracking table would not normally contain our parsed ECH observations.

**Our tool runs as a user-space application and inspects several protocol layers.** It does not occupy one exclusive network-stack layer:

| Protocol level | What our tool does |
|---|---|
| Link layer: Ethernet/VLAN | Finds the encapsulated IP packet |
| Network layer: IPv4/IPv6 | Extracts addresses and locates TCP |
| Transport layer: TCP | Extracts ports and sequence information; accumulates payload |
| Above TCP: TLS | Parses visible handshake fields and computes fingerprints |

TLS sits above TCP and below application protocols such as HTTP. It does not map perfectly onto a single OSI layer. The most useful description of our tool is **a passive packet analyzer performing TLS handshake inspection**.

In the current implementation, libpcap supplies live packets or saved PCAP data; our code walks through those layers in [capture.cpp](<./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp:190>). It observes traffic without terminating TLS or participating in the connection.

**It could run on a router or switch if that device supports suitable applications and exposes the traffic to them.** Installation is therefore device-dependent:

- A programmable router with a compatible operating system could potentially run a compiled build with the required libraries and capture permissions.
- A conventional switch generally needs a supported application environment to run arbitrary C++ utilities. Seeing traffic in its forwarding hardware does not automatically make that traffic available to a user-space process.
- A straightforward deployment is to run our tool on a separate computer receiving mirrored traffic from the switch. SPAN/port mirroring copies selected traffic to an analyzer port. [Cisco SPAN documentation](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/mgmt/management-configuration-guide/span.html).

```text
Client ───── Switch ───── Server
               │
          mirrored copies
               │
        Computer running
            our tool
```

For the proposed bidirectional analysis, that capture must include **both directions**. The analyzer’s physical location does not change the protocol layer it examines: a switch can forward Ethernet frames while our attached application inspects the TLS carried inside them.

> "Our project works at data link layer so this can also be deployed at a router or a switch"
> How much of it is true, and how to interpret it? How to frame it better in front of the professor?

**It is partly true, but the reasoning is misleading.** Capturing Ethernet frames does not make the entire project a data-link-layer tool, and it does not automatically make it deployable on every router or switch.

There are three separate ideas:

- **Capture point:** On an Ethernet interface, we obtain link-layer frames through libpcap.
- **Analysis:** We inspect Ethernet, IP, TCP, and finally TLS handshake fields.
- **Deployment:** The device must support our executable, dependencies, and access to the relevant packets. Its ability to forward packets alone is insufficient.

A better way to explain it to the professor is:

“Our project is a passive TLS fingerprinting application. It captures packets through libpcap and parses Ethernet, IP, and TCP to extract the visible TLS handshake fields.

It can monitor traffic passing through a router or switch. One deployment option is to run it directly on a compatible programmable network device. Another is to run it on a separate monitoring computer receiving mirrored traffic from a switch.

Therefore, its deployment depends on traffic visibility and device support, rather than simply on capturing at the data link layer.”

If asked **“Which layer does it work at?”**, the short answer is:

**“It captures at the link layer on Ethernet networks, but performs analysis across layers up to TLS, above TCP.”**

Also distinguish **monitoring traffic passing through a switch** from **running the application on the switch itself**. Your project can support the former without requiring the latter.

> The capture happens at the data link layer, so what new doors does that open for us, and what doors does it close for us

**Capturing at the data link layer gives us access to the packet as observed on an interface—including its headers and payload. It expands what we can inspect, but we must reconstruct and interpret more of it ourselves.**

It opens these possibilities:

| Opportunity | What it means for our project |
|---|---|
| **Observe traffic without being an endpoint** | With a mirror port or network tap, we can fingerprint connections between other machines. |
| **Analyze multiple layers together** | We can combine TLS fingerprints with IP/TCP characteristics, packet sizes, timing, and locally visible Ethernet/VLAN information. |
| **Inspect connection establishment** | We can observe TCP SYNs and visible TLS handshakes without modifying client applications. |
| **Study fragmentation and retransmissions** | We can examine how bytes arrive across packets, rather than receiving only an already assembled application stream. |
| **Replay captured traffic** | Saved PCAPs let us repeat analysis and compare implementations against the same input. |

**It does not inherently close off higher-layer analysis:** TLS and HTTP bytes are carried inside lower-layer packets. The limitations come from encryption, visibility, and the work required to interpret those bytes.

| Limitation | Consequence |
|---|---|
| **We receive packets, not a ready-made TCP stream** | Our tool must handle sequence numbers, segmentation, retransmissions, and TLS framing. |
| **We see only traffic reaching the capture interface** | Promiscuous mode alone does not reveal every connection on a switched network; mirroring or another suitable capture point is needed. |
| **Encryption remains intact** | Capturing all ciphertext bytes does not reveal ECH’s inner SNI or encrypted HTTP headers. |
| **Packets do not identify local processes** | A fingerprint can suggest a client stack, but packets alone do not tell us the originating PID or executable. |
| **Link-layer information is local to the observed link** | Across a router, the Ethernet source MAC normally identifies the adjacent sender/router—not the original remote client. |
| **Capture can lose packets** | Missing bytes can prevent reconstruction. We must distinguish incomplete observations from malformed traffic. |

For our project, the central trade-off is **broad, passive visibility versus limited application context and responsibility for reconstruction**. Capturing lower in the stack gives us more packet detail; it does not give us more decryption capability.

> Capturing at data link layer has nothing to do with whether we can deploy this as a binary on a router or switch, which also operate at L2

**Correct—the capture layer does not determine whether the binary can run on a device.** Deployment depends on the device’s operating system, CPU architecture, available libraries, permissions, and access to captured traffic.

One correction: **switches typically forward at L2; routers forward at L3.** Neither role implies support for arbitrary applications.

The two independent questions are:

- **Can the device run our binary?** A platform compatibility question.
- **Can our application observe the relevant traffic?** A capture-access question—even traffic forwarded by the device may not be exposed to its application environment.

Link-layer capture helps us inspect packets visible at a suitable monitoring point. It does **not** establish router/switch installability. My earlier explanation should have separated those points more sharply.
