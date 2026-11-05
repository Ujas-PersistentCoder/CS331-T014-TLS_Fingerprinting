# Plan ECH implementation checkpoint

> Time to start implementation of the ECH functionality. Your primary reference will be [ECH_DeepDive_and_Integration_Strategy.md](<TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md>). We will be working on the `feature/ech` branch, which is currently active in the TLS-Fingerprinting repo.
> Pick relevant findings from [@Review ECH integration plan](thread://01a19675-cf4a-7e73-a61d-c7854ec670c6?hostId=local) (one of them being the decided folder structure).&#x20;
>
> I want to divide the entire implementation into checkpoints. I manually test our work after each checkpoint. Follow a very intuitive and pedagogical flow. Starting off with the core logic, and slowly making our way towards more coverage and robustness. Make sure there is something new and tangible to test after every checkpoint, so avoid making too many checkpoints. Unless you find a critical blocker or inconsistency that requires immediate resolution, write the plan for the first checkpoint.

<details><summary>7 previous messages</summary>

> I’ll read the strategy, the referenced review chat, and the current branch, then define a first checkpoint with something concrete you can test manually.
>
> <details><summary>Explored 4 lists, ran 2 commands</summary>
>
> - Ran `pwd; rg --files -g 'AGENTS.md' -g 'CONTEXT.md' -g '*ECH*' -g '*ech*' -g 'CMakeLists.txt' -g 'pyproject.toml' -g 'package.json' -g 'Cargo.toml' -g 'Makefile' -g '!ja3/**' -g '!node_modules/**' -g '!build/**'`
>
> <details><summary>Explored a file</summary>
>
> - Read `~/.agents/skills/brainstorming/SKILL.md`
>
> </details>
>
> Tool call
>
> Tool: read_thread
> Status: completed
>
> <details><summary>Explored 4 lists</summary>
>
> - Listed files in `TLS-Fingerprinting`
> - Listed files
> - Listed files in `Phase 2`
> - Listed files in `engine`
>
> </details>
>
> - Ran `cat AGENTS.md; cat .agents/CONTEXT.md; git -C TLS-Fingerprinting status --short --branch; git -C TLS-Fingerprinting log -5 --oneline; cat 'TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'`
>
> </details>
>
> I’m using the brainstorming skill to shape the checkpoints. The strategy already fixes the module layout; I’m checking how to make the first decoder work visible in the current engine.
>
> <details><summary>Explored 4 files, a list, ran 5 commands</summary>
>
> - Ran `cat 'Phase 2/engine/include/tlsfp/types.hpp' 'Phase 2/engine/include/tlsfp/byte_reader.hpp' 'Phase 2/engine/include/tlsfp/parser.hpp' 'Phase 2/engine/src/parser.cpp' 'Phase 2/engine/CMakeLists.txt'`
>
> - Ran `cat 'Phase 2/engine/src/main.cpp' 'Phase 2/engine/include/tlsfp/capture.hpp' 'Phase 2/engine/include/tlsfp/accumulator.hpp' 'Phase 2/engine/src/accumulator.cpp'; rg -n 'parse_|verbose|json|ClientHello|ServerHello|accum|printf|cout' 'Phase 2/engine/src/capture.cpp'; cat 'Phase 2/engine/tests/test_fingerprints.cpp'`
>
> Tool call
>
> Tool: read_thread
> Status: completed
>
> - Ran `cat 'Phase 2/engine/include/tlsfp/types.hpp' 'Phase 2/engine/include/tlsfp/byte_reader.hpp' 'Phase 2/engine/include/tlsfp/parser.hpp' 'Phase 2/engine/CMakeLists.txt'`
>
> <details><summary>Explored 4 files, a list</summary>
>
> - Read `./Phase 2/engine/src/parser.cpp`
> - Read `./Phase 2/engine/src/main.cpp`
> - Read `./Phase 2/engine/src/capture.cpp`
> - Read `./Phase 2/engine/include/tlsfp/accumulator.hpp`
> - Listed files
>
> </details>
>
> Tool call
>
> Tool: read_thread
> Status: completed
>
> - Ran `cat 'Phase 2/engine/include/tlsfp/types.hpp' 'Phase 2/engine/include/tlsfp/parser.hpp' 'Phase 2/engine/CMakeLists.txt'`
>
> - Ran `sed -n '1,165p' 'Phase 2/engine/src/parser.cpp'; sed -n '430,510p' 'Phase 2/engine/src/capture.cpp'; cat 'Phase 2/engine/include/tlsfp/byte_reader.hpp'; ls -a 'Phase 2/engine'; command -v cmake tshark clang++ ctest`
>
> </details>
>
> The review confirms the smaller layout: shared TLS framing in `parser.cpp`, ECH decoding in `ech_parser.cpp`, and later interpretation in `ech_analysis.cpp`, with HRR optional.
>
> For checkpoint 1, I recommend decoding the ClientHello ECH envelope and showing its fields through the existing verbose output. That gives you a wire-level result to compare with Wireshark before we add connection correlation and experiments. One prerequisite belongs in this checkpoint: the extension walker currently stops silently on bad lengths, so it needs to report completeness before we can safely say “ECH absent.”
>
> <details><summary>Explored a search, a list, ran 5 commands, searched the web</summary>
>
> <details><summary>Explored a search</summary>
>
> - Searched for `parity|7.PCAP|seven|build|ctest|pcap` in `engine_roadmap.md`
>
> </details>
>
> - Ran `tshark -r code/pcaps/firefox.pcap -Y 'tls.handshake.type == 1' -T fields -e frame.number -e tls.handshake.extension.type -e tls.handshake.random`
>
> - Ran `tshark -r code/pcaps/chrome.pcap -Y 'tls.handshake.type == 1' -T fields -e frame.number -e tls.handshake.extension.type -e tls.handshake.random`
>
> - Ran `cmake -S 'Phase 2/engine' -B /private/tmp/cs331-ech-plan-baseline -DCMAKE_BUILD_TYPE=Release`
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc9849.html`
>
> <details><summary>Explored a list</summary>
>
> - Listed files in `CS 331 CN 2026`
>
> </details>
>
> - Ran `tshark -r code/pcaps/curl.pcap -Y 'tls.handshake.type == 1' -T fields -e frame.number -e tls.handshake.extension.type`
>
> - Ran `tshark -r code/pcaps/chrome.pcap -Y 'frame.number == 6' -V`
>
> Searched the web for `'opaque enc'`
>
> </details>
>
> Plan
>
> # Checkpoint 1 — Decode ECH and inspect its visible fields
>
> ## Summary
>
> The first checkpoint answers: **“What exactly can we read from an ECH-bearing ClientHello?”**
>
> You will be able to replay a PCAP using `tlsfp_phase2 -r <capture> -v` and compare the decoded ECH fields with Wireshark.
>
> Use three required checkpoints overall:
>
> 1. **Decode and inspect:** ClientHello ECH fields and basic validity findings.
> 2. **Correlate and report:** Client/server observations, targeted transport fixes, and connection-level JSON output.
> 3. **Validate and measure:** Independently labeled cases, controlled length measurements, and fingerprint baseline comparisons.
>
> HRR analysis remains optional after these checkpoints. Stop after checkpoint 1 for your manual testing.
>
> ## Implementation
>
> **Follow the agreed module boundaries.**
>
> - Add the `ech_parser` header/source pair under the existing engine include/source directories. Reuse `ByteReader`; shared TLS framing stays in `parser.cpp`.
> - Add a small `ech_analysis` header/source pair for single-hello contextual findings. Connection analysis comes in checkpoint 2.
> - Add focused parser/analysis tests under `engine/tests`, with fixtures in its `fixtures/` directory. Register them with the existing CMake targets.
> - Keep capture and presentation changes in `capture.cpp`. Defer the experiment harness until it has usable connection summaries.
>
> **Decode the extension body.**
>
> For `0xfe0d`, extract the variant, KDF ID, AEAD ID, configuration ID, encapsulation length, and ciphertext length. Validate vector boundaries, nonempty ciphertext, and complete body consumption. Recognize the one-byte inner marker. These follow the [RFC 9849 extension format](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
>
> Keep unknown algorithm identifiers numeric. Do not infer a KEM, decrypt ciphertext, or classify an offer as real/GREASE or accepted/rejected.
>
> **Extend the existing parser contract additively.**
>
> - Add ECH observations and an owned copy of the 32-byte outer random to `ClientHelloData`; reset them in `clear()`.
> - Preserve the existing boolean parser interface, with an additional detailed outcome available to callers: complete, incomplete, unsupported, or malformed.
> - Record presence separately from decoding status and independent findings. Missing fields remain unknown.
> - Make the extension walker report framing failures instead of silently stopping. Establish absence only after examining the complete extension vector.
> - Retain duplicate ECH occurrences for diagnosis; do not select one as authoritative. Finalize cross-extension findings after traversal so extension order cannot change the result.
> - Report duplicate ECH, forbidden outer `0xfd00`, an externally observed inner marker, and export-only AEAD as separate findings.
> - Decode empty `enc` without rejecting it. With no established hello role, report its context as unknown.
>
> Support complete hellos contained within one TLS record, including the existing TCP segmentation path. Detect record-spanning hellos and inputs above the retained 8 KiB limit as unsupported. Broader accumulation and lifecycle changes belong to checkpoint 2.
>
> ## Tangible output and manual testing
>
> Extend existing verbose ClientHello output with ECH presence/status, numeric fields, lengths, findings, and outer random. Label the visible SNI explicitly as **outer SNI**.
>
> For failed hello framing, print a concise verbose diagnostic and suppress fingerprints from partial data. Pending accumulator entries will gain incomplete connection summaries in checkpoint 2.
>
> Supply these replay checks:
>
> | Input | Expected observation |
> |---|---|
> | Existing `chrome.pcap`, frame 6 | Outer variant; KDF `1`; AEAD `1`; config ID `139`; `enc` length `32`; ciphertext length `208` |
> | Existing `curl.pcap`, frame 4 | ECH absent after complete extension traversal |
> | Small synthetic fixture PCAP | Valid envelope, duplicate ECH, and malformed-body examples with documented expected output |
>
> The Chrome example already spans two TCP segments. Document its byte layout and Wireshark comparison. Its offer type and acceptance remain unknown.
>
> ## Validation and completion gate
>
> - Test valid outer/inner bodies, unknown IDs, empty `enc`, zero-length ciphertext, contradictory lengths, trailing bytes, duplicate ECH, forbidden `0xfd00`, and `0x001b` without ECH.
> - Distinguish missing capture bytes from contradictions inside complete framing; test unsupported cross-record and oversized hellos.
> - Verify findings survive extension reordering and scratchpad reuse clears all previous observations.
> - Run existing tests and compare before/after fingerprints across the seven documented PCAP baselines. Preserve valid-input fingerprint behavior, extension order, and GREASE handling.
> - Where existing synthetic tests use arbitrary bytes as extensions, replace those bytes with valid padding extensions while preserving their original size and segmentation purpose.
> - Resolve the currently missing GoogleTest dependency before running the suite; the initial local CMake check stopped there.
> - Add a short checkpoint testing guide and update project context with implemented behavior, validation results, and remaining limits.
>
> Checkpoint 1 is complete when automated checks pass and the replay examples are ready for your manual review. Synthetic fixtures and existing captures establish decoding behavior; endpoint labeling and acceptance validation remain checkpoint 3 work.
</details>

There’s already a useful manual test: Wireshark decodes an ECH envelope in `chrome.pcap`, frame 6, with KDF 1, AEAD 1, config ID 139, a 32-byte `enc`, and a 208-byte ciphertext. The hello spans two TCP segments, so it also exercises the existing accumulation path. `curl.pcap` provides an ECH-absent comparison. These establish test inputs for decoding; they don’t label real ECH, GREASE, or acceptance.

The local build check stopped because GoogleTest is missing. I’ll include that as a validation prerequisite in the plan.

> PLEASE IMPLEMENT THIS PLAN:
> # Checkpoint 1 — Decode ECH and inspect its visible fields
>
> ## Summary
>
> The first checkpoint answers: **“What exactly can we read from an ECH-bearing ClientHello?”**
>
> You will be able to replay a PCAP using `tlsfp_phase2 -r <capture> -v` and compare the decoded ECH fields with Wireshark.
>
> Use three required checkpoints overall:
>
> 1. **Decode and inspect:** ClientHello ECH fields and basic validity findings.
> 2. **Correlate and report:** Client/server observations, targeted transport fixes, and connection-level JSON output.
> 3. **Validate and measure:** Independently labeled cases, controlled length measurements, and fingerprint baseline comparisons.
>
> HRR analysis remains optional after these checkpoints. Stop after checkpoint 1 for your manual testing.
>
> ## Implementation
>
> **Follow the agreed module boundaries.**
>
> - Add the `ech_parser` header/source pair under the existing engine include/source directories. Reuse `ByteReader`; shared TLS framing stays in `parser.cpp`.
> - Add a small `ech_analysis` header/source pair for single-hello contextual findings. Connection analysis comes in checkpoint 2.
> - Add focused parser/analysis tests under `engine/tests`, with fixtures in its `fixtures/` directory. Register them with the existing CMake targets.
> - Keep capture and presentation changes in `capture.cpp`. Defer the experiment harness until it has usable connection summaries.
>
> **Decode the extension body.**
>
> For `0xfe0d`, extract the variant, KDF ID, AEAD ID, configuration ID, encapsulation length, and ciphertext length. Validate vector boundaries, nonempty ciphertext, and complete body consumption. Recognize the one-byte inner marker. These follow the [RFC 9849 extension format](https://www.rfc-editor.org/rfc/rfc9849.html#section-5).
>
> Keep unknown algorithm identifiers numeric. Do not infer a KEM, decrypt ciphertext, or classify an offer as real/GREASE or accepted/rejected.
>
> **Extend the existing parser contract additively.**
>
> - Add ECH observations and an owned copy of the 32-byte outer random to `ClientHelloData`; reset them in `clear()`.
> - Preserve the existing boolean parser interface, with an additional detailed outcome available to callers: complete, incomplete, unsupported, or malformed.
> - Record presence separately from decoding status and independent findings. Missing fields remain unknown.
> - Make the extension walker report framing failures instead of silently stopping. Establish absence only after examining the complete extension vector.
> - Retain duplicate ECH occurrences for diagnosis; do not select one as authoritative. Finalize cross-extension findings after traversal so extension order cannot change the result.
> - Report duplicate ECH, forbidden outer `0xfd00`, an externally observed inner marker, and export-only AEAD as separate findings.
> - Decode empty `enc` without rejecting it. With no established hello role, report its context as unknown.
>
> Support complete hellos contained within one TLS record, including the existing TCP segmentation path. Detect record-spanning hellos and inputs above the retained 8 KiB limit as unsupported. Broader accumulation and lifecycle changes belong to checkpoint 2.
>
> ## Tangible output and manual testing
>
> Extend existing verbose ClientHello output with ECH presence/status, numeric fields, lengths, findings, and outer random. Label the visible SNI explicitly as **outer SNI**.
>
> For failed hello framing, print a concise verbose diagnostic and suppress fingerprints from partial data. Pending accumulator entries will gain incomplete connection summaries in checkpoint 2.
>
> Supply these replay checks:
>
> | Input | Expected observation |
> |---|---|
> | Existing `chrome.pcap`, frame 6 | Outer variant; KDF `1`; AEAD `1`; config ID `139`; `enc` length `32`; ciphertext length `208` |
> | Existing `curl.pcap`, frame 4 | ECH absent after complete extension traversal |
> | Small synthetic fixture PCAP | Valid envelope, duplicate ECH, and malformed-body examples with documented expected output |
>
> The Chrome example already spans two TCP segments. Document its byte layout and Wireshark comparison. Its offer type and acceptance remain unknown.
>
> ## Validation and completion gate
>
> - Test valid outer/inner bodies, unknown IDs, empty `enc`, zero-length ciphertext, contradictory lengths, trailing bytes, duplicate ECH, forbidden `0xfd00`, and `0x001b` without ECH.
> - Distinguish missing capture bytes from contradictions inside complete framing; test unsupported cross-record and oversized hellos.
> - Verify findings survive extension reordering and scratchpad reuse clears all previous observations.
> - Run existing tests and compare before/after fingerprints across the seven documented PCAP baselines. Preserve valid-input fingerprint behavior, extension order, and GREASE handling.
> - Where existing synthetic tests use arbitrary bytes as extensions, replace those bytes with valid padding extensions while preserving their original size and segmentation purpose.
> - Resolve the currently missing GoogleTest dependency before running the suite; the initial local CMake check stopped there.
> - Add a short checkpoint testing guide and update project context with implemented behavior, validation results, and remaining limits.
>
> Checkpoint 1 is complete when automated checks pass and the replay examples are ready for your manual review. Synthetic fixtures and existing captures establish decoding behavior; endpoint labeling and acceptance validation remain checkpoint 3 work.

<details><summary>12 previous messages</summary>

> I’ll implement checkpoint 1 on `feature/ech`, validate the decoder and fingerprint parity, and leave the replay examples ready for your manual testing.
>
> <details><summary>Created 4 files, explored 3 files, ran 3 commands</summary>
>
> - Ran `git status --short --branch; cat 'Phase 2/engine/include/tlsfp/types.hpp'; cat 'Phase 2/engine/src/parser.cpp'; sed -n '1,190p' 'Phase 2/engine/src/capture.cpp'; cat 'Phase 2/engine/src/accumulator.cpp'`
>
> <details><summary>Explored 4 files</summary>
>
> - Read `./Phase 2/engine/tests/test_fingerprints.cpp`
> - Read `./.gitignore`
> - Read `./Phase 2/engine/engine_roadmap.md`
> - Read `~/.agents/skills/code-review-and-quality/SKILL.md`
>
> </details>
>
> - Ran `brew install googletest`
>
> - Ran `cp -R 'Phase 2/engine' /private/tmp/cs331-ech-original-engine`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/ech_analysis.hpp` (+24 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/ech_parser.hpp` (+48 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/ech_analysis.cpp` (+19 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/ech_parser.cpp` (+61 -0)
>
> </details>
>
> GoogleTest is installed. The isolated ECH decoder now retains numeric fields and lengths without keeping packet-buffer references. Next I’m adding explicit framing outcomes and verbose output so incomplete input can’t be reported as “ECH absent.”
>
> <details><summary>Edited 4 files, ran 4 commands</summary>
>
> - Ran `cmake -S /private/tmp/cs331-ech-original-engine -B /private/tmp/cs331-ech-original-build -DCMAKE_BUILD_TYPE=Release`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/parser.hpp` (+14 -1)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/parser.cpp` (+18 -4)
> - Ran `cmake --build /private/tmp/cs331-ech-original-build -j 4`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt` (+11 -2)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/parser.cpp` (+53 -20)
> - Ran `ctest --test-dir /private/tmp/cs331-ech-original-build --output-on-failure`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+60 -1)
> - Ran `rg -n 'diagnostic|print_ech|else if \(hs_type' 'Phase 2/engine/src/capture.cpp'; ls ../.venv/bin/python*; rg -n 'vector<uint8_t>\((300|400|500)|extensions\((900|1600|2800|6800|3000)' 'Phase 2/engine/tests/test_fingerprints.cpp'`
>
> </details>
>
> The parser now distinguishes complete hello framing from a malformed ECH body. That lets it report an invalid ECH envelope while preserving fingerprints from fully observed outer fields; failed shared framing suppresses fingerprints.
>
> The original 39 tests pass in a separate baseline build. I’m adding fixtures for the new statuses, independent findings, and replay output.
>
> <details><summary>Created 4 files, edited 2 files, ran 9 commands</summary>
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/ech_fixtures.hpp` (+71 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_analysis.cpp` (+87 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_parser.cpp` (+260 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/ech_fixtures.hpp` (+1 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/generate_ech_fixture.py` (+81 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_fingerprints.cpp` (+20 -10)
> - Ran `../.venv/bin/python 'Phase 2/engine/tests/fixtures/generate_ech_fixture.py'`
> - Ran `cmake -S 'Phase 2/engine' -B 'Phase 2/engine/build' -DCMAKE_BUILD_TYPE=Release`
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure`
> - Ran `git diff --stat; git diff --check; sed -n '1,65p' 'Phase 2/engine/src/parser.cpp'; sed -n '200,345p' 'Phase 2/engine/src/parser.cpp'`
> - Ran `'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/chrome.pcap -v`
> - Ran `../.venv/bin/python - <<'PY'
> import json, re, subprocess
> from pathlib import Path
> old = '/private/tmp/cs331-ech-original-build/tlsfp_phase2'
> new = str(Path('Phase 2/engine/build/tlsfp_phase2').resolve())
> files = ['cloudflare_run1.pcap','curl.pcap','python_requests.pcap','custom_client.pcap','chrome.pcap','chrome_run2.pcap','test_ja3.pcap']
> ansi = re.compile(r'\x1b\[[0-9;]*m')
> results = []
> for filename in files:
>     captures = []
>     for binary in [old, new]:
>         output = ansi.sub('', subprocess.run([binary, '-r', 'code/pcaps/'+filename], check=True, text=True, capture_output=True).stdout)
>         lines = [line.strip() for line in output.splitlines() if re.search(r'\b(?:CLIENT|SERVER)\s|\bJA[34]S?:', line)]
>         captures.append(lines)
>     result = {'pcap':filename, 'same':captures[0] == captures[1], 'fingerprints':sum(bool(re.search(r'\bJA[34]S?:', line)) for line in captures[1])}
>     results.append(result)
>     if not result['same']:
>         print(json.dumps({'before':captures[0], 'after':captures[1]}))
> print(json.dumps(results, indent=2))
> assert all(result['same'] for result in results)
> PY`
> - Ran `git status --short; git diff -- 'Phase 2/engine/CMakeLists.txt'; tshark -r 'Phase 2/engine/tests/fixtures/ech_checkpoint1.pcap' -Y 'tls.handshake.type == 1' -T fields -e frame.number -e tcp.srcport -e tls.handshake.extension.type`
> - Ran `cmake -S 'Phase 2/engine' -B 'Phase 2/engine/build-debug' -DCMAKE_BUILD_TYPE=Debug`
>
> </details>
>
> All 72 tests pass. The seven baseline captures also produce identical endpoint and fingerprint output before and after the change—96 fingerprint values in total. The Chrome example matches Wireshark’s ECH fields, including config ID 139 and lengths 32/208.
>
> I’m checking memory safety and reviewing the error paths, then I’ll finish the manual testing guide and project context update.
>
> <details><summary>Ran 6 commands</summary>
>
> - Ran `rm -rf 'Phase 2/engine/build-debug'`
> - Ran `cmake -S 'Phase 2/engine' -B /private/tmp/cs331-ech-debug-build -DCMAKE_BUILD_TYPE=Debug`
> - Ran `../.venv/bin/python - <<'PY'
> import re,subprocess
> binary = 'Phase 2/engine/build/tlsfp_phase2'
> for pcap in ['code/pcaps/curl.pcap','Phase 2/engine/tests/fixtures/ech_checkpoint1.pcap']:
>     output=subprocess.check_output([binary,'-r',pcap,'-v'],text=True)
>     output=re.sub(r'\x1b\[[0-9;]*m','',output)
>     print(pcap)
>     print('\n'.join(line for line in output.splitlines() if '[V-ECH' in line or 'diagnostic' in line or '[V-ClientHello]' in line))
> PY`
> - Ran `cmake --build /private/tmp/cs331-ech-debug-build -j 4`
> - Ran `ctest --test-dir /private/tmp/cs331-ech-debug-build --output-on-failure`
> - Ran `cat 'Phase 2/engine/include/tlsfp/ech_parser.hpp' 'Phase 2/engine/include/tlsfp/ech_analysis.hpp'; git diff -- 'Phase 2/engine/src/capture.cpp' 'Phase 2/engine/include/tlsfp/parser.hpp'; git status --short`
>
> </details>
>
> The sanitizer build stopped during GoogleTest startup, before any project tests ran. I’m checking the test-build setup so the memory-safety check can run meaningfully; the release tests and capture comparisons have passed.
>
> I’m also using the code-review-and-quality skill to review the parser boundaries, retained data, and failure output.
>
> <details><summary>Created a file, edited 5 files, explored 2 files, a list, ran 11 commands</summary>
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt` (+2 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_parser.cpp` (+36 -1)
>
> <details><summary>Explored a file, a list</summary>
>
> - Listed files in `1.18.0`
> - Read `/opt/homebrew/Cellar/googletest/1.18.0/INSTALL_RECEIPT.json`
>
> </details>
>
> - Ran `cmake --build /private/tmp/cs331-ech-debug-build -j 4`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_parser.cpp` (+1 -1)
>
> - Ran `curl --fail --location https://github.com/google/googletest/archive/refs/tags/v1.18.0.tar.gz --output /private/tmp/cs331-googletest-1.18.0.tar.gz`
>
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
>
> - Ran `curl --fail --location https://github.com/google/googletest/archive/refs/tags/v1.18.0.tar.gz --output /private/tmp/cs331-googletest-1.18.0.tar.gz`
>
> <details><summary>Explored a file</summary>
>
> - Read `./.agents/CONTEXT.md`
>
> </details>
>
> - Ran `tar -xzf /private/tmp/cs331-googletest-1.18.0.tar.gz -C /private/tmp`
>
> - Ran `cmake -S /private/tmp/googletest-1.18.0 -B /private/tmp/cs331-gtest-source-build -DCMAKE_BUILD_TYPE=Debug -DBUILD_GMOCK=OFF -DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -DCMAKE_INSTALL_PREFIX=/private/tmp/cs331-gtest-sanitized`
>
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure --quiet`
>
> - Ran `cmake --build /private/tmp/cs331-gtest-source-build -j 4`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp` (+4 -2)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp` (+14 -8)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+19 -8)
>
> - Ran `cmake --install /private/tmp/cs331-gtest-source-build`
>
> - Ran `cmake -S 'Phase 2/engine' -B /private/tmp/cs331-ech-debug-build -DCMAKE_BUILD_TYPE=Debug -DGTest_DIR=/private/tmp/cs331-gtest-sanitized/lib/cmake/GTest`
>
> - Ran `cmake --build /private/tmp/cs331-ech-debug-build -j 4`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/docs/ECH_Checkpoint_1_Testing.md` (+157 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_parser.cpp` (+34 -0)
>
> </details>
>
> Review caught one inconsistency: oversized records could be reported as unsupported on the fast path but silently dropped on a segmented path. I added a small limit notification so all three accumulation paths report the same boundary.
>
> GoogleTest now builds with the same compiler and sanitizer settings as the engine, resolving the startup failure. I’m running the final checks with that setup.
>
> <details><summary>Edited a file, ran 8 commands</summary>
>
> - Ran `git diff --check; git diff -- 'Phase 2/engine/src/accumulator.cpp' 'Phase 2/engine/include/tlsfp/accumulator.hpp'; rg -n 'TEST\(' 'Phase 2/engine/tests/test_ech_parser.cpp' 'Phase 2/engine/tests/test_ech_analysis.cpp'`
> - Ran `cmake --build /private/tmp/cs331-ech-debug-build -j 4`
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure`
> - Ran `ctest --test-dir /private/tmp/cs331-ech-debug-build --output-on-failure`
> - Ran `../.venv/bin/python - <<'PY'
> import json, re, subprocess
> from pathlib import Path
> old = '/private/tmp/cs331-ech-original-build/tlsfp_phase2'
> new = str(Path('Phase 2/engine/build/tlsfp_phase2').resolve())
> debug = '/private/tmp/cs331-ech-debug-build/tlsfp_phase2'
> files = ['cloudflare_run1.pcap','curl.pcap','python_requests.pcap','custom_client.pcap','chrome.pcap','chrome_run2.pcap','test_ja3.pcap']
> ansi = re.compile(r'\x1b\[[0-9;]*m')
> total = 0
> for filename in files:
>     rows = []
>     for binary in [old, new, debug]:
>         run = subprocess.run([binary, '-r', 'code/pcaps/'+filename, '-v'], check=True, text=True, capture_output=True)
>         assert not run.stderr, run.stderr
>         output = ansi.sub('', run.stdout)
>         rows.append([line.strip() for line in output.splitlines() if re.search(r'\b(?:CLIENT|SERVER)\s|\bJA[34]S?:', line)])
>     assert rows[0] == rows[1] == rows[2], filename
>     count = sum(bool(re.search(r'\bJA[34]S?:', line)) for line in rows[1])
>     total += count
>     print(f'{filename}: {count} fingerprint values and endpoint rows identical; sanitizer replay clean')
> print(f'Total: {total} fingerprint values across seven captures')
> fixture = Path('Phase 2/engine/tests/fixtures/ech_checkpoint1.pcap')
> before = fixture.read_bytes()
> subprocess.run(['../.venv/bin/python', str(fixture.with_name('generate_ech_fixture.py'))], check=True, capture_output=True)
> assert fixture.read_bytes() == before
> print('Synthetic PCAP regeneration is byte-for-byte deterministic')
> PY`
> - Wrote `./TLS-Fingerprinting/Phase 2/docs/ECH_Checkpoint_1_Testing.md` (+24 -0)
> - Ran ``cat <<'EOF' >> '/Users/pranjal/Projects/CS 331 CN 2026/.agents/CONTEXT.md'
>
> ## 7. Phase 2 ECH Checkpoint 1 — November 1, 2026
>
> - Implemented checkpoint 1 on `TLS-Fingerprinting` branch `feature/ech`: ECH envelope decoding and immediate verbose inspection. Stop here for user manual testing. Required next checkpoints are (2) bidirectional correlation, targeted record/lifecycle fixes and JSON summaries; (3) independently labeled cases and controlled measurements. HRR sequence analysis remains optional.
> - Added `ech_parser.hpp/.cpp` for bounded RFC 9849 extension-body decoding and owned optional numeric fields; `ech_analysis.hpp/.cpp` for independent single-hello findings. Shared framing stays in `parser.cpp`; presentation stays in `capture.cpp`. No experiment harness, secrets, decryption or positive offer/acceptance classifier was added.
> - `ClientHelloData` now carries detailed framing status/diagnostic, an owned outer random and ECH observations. The boolean parser API is preserved: true means complete shared framing, while an individual ECH body can still be malformed. Failed shared framing suppresses fingerprints. ECH absence requires complete traversal; unavailable values remain unknown, duplicates remain separate, and findings coexist regardless of extension order.
> - The retained limit is 8192 bytes including the TLS record header. Oversize is unsupported on fast, segmented and split-record-header paths via an optional accumulator limit callback. Cross-record hellos are unsupported. Pending/gapped/expired accumulation still lacks connection summaries; silence does not establish absence or malformed ECH. Existing broader record/lifecycle limitations remain checkpoint 2 work.
> - Added `Phase 2/docs/ECH_Checkpoint_1_Testing.md`, focused tests, a deterministic ten-packet synthetic PCAP and its standard-library generator under `engine/tests/fixtures/`. Use the existing project `.venv` for regeneration; replay and C++ tests require no Python. Existing arbitrary extension bytes in accumulation tests were replaced with same-size valid padding extensions.
> - Validation: original 39 tests passed before edits; all 76 tests (37 new) pass in Release and ASan/UBSan Debug. Seven saved PCAPs preserve all 96 ordered fingerprint values and endpoint observations against clean baseline `6c466cf`; all seven also replay cleanly under sanitizers. This is regression parity, not new independent fingerprint-spec or ECH acceptance validation.
> - Actual saved `code/pcaps/chrome.pcap` frame 6 matches Wireshark: KDF 1, AEAD 1, config ID 139, enc length 32, ciphertext length 208; its 1990-byte record spans TCP payloads of 1388 and 602 bytes. `curl.pcap` frame 4 confirms complete ECH absence. These establish wire decoding, not real-versus-GREASE or acceptance labels.
> - Local build prerequisite GoogleTest 1.18.0 was installed. Its prebuilt Homebrew library failed ASan test discovery before project tests; rebuilding official GoogleTest source with AppleClang 21 and the same sanitizer flags resolved that. Compatible sanitized GTest is temporarily installed at `/private/tmp/cs331-gtest-sanitized`; debug engine build is `/private/tmp/cs331-ech-debug-build`. CMake now propagates sanitizer compile/link flags to static-library consumers. No findings were suppressed to obtain a passing run.
> EOF``
> - Ran `git diff --check; git status --short --branch; git diff --stat; wc -l 'Phase 2/engine/src/ech_parser.cpp' 'Phase 2/engine/src/ech_analysis.cpp' 'Phase 2/engine/tests/test_ech_parser.cpp' 'Phase 2/engine/tests/test_ech_analysis.cpp'; tail -12 '../.agents/CONTEXT.md'`
>
> </details>
</details>

Implemented checkpoint 1 on `feature/ech`, ready for your manual testing.

- Added ECH decoding, independent findings, and verbose output.
- All **76 tests pass**, including ASan/UBSan checks.
- All **96 fingerprint values across seven baseline captures remain unchanged**.
- Added synthetic replay fixtures and updated project context.

The [manual testing guide](<./TLS-Fingerprinting/Phase 2/docs/ECH_Checkpoint_1_Testing.md>) includes commands, expected output, and the Wireshark comparison.

Changes are uncommitted. Checkpoint 2 has not started.

> Plan for next

<details><summary>6 previous messages</summary>

> I’ll check the current checkpoint-1 code and strategy, then plan checkpoint 2 around a concrete result you can test: client/server correlation and one structured summary per connection.
>
> <details><summary>Explored 4 files, 2 searches, a list, ran 3 commands</summary>
>
> <details><summary>Explored 4 files</summary>
>
> - Read `./Phase 2/engine/src/capture.cpp`
> - Read `./Phase 2/engine/src/capture.cpp`
> - Read `./Phase 2/engine/include/tlsfp/parser.hpp`
> - Read `./Phase 2/engine/src/parser.cpp`
>
> </details>
>
> - Ran `sed -n '115,265p' 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; tail -35 '../.agents/CONTEXT.md'; cat 'Phase 2/engine/include/tlsfp/ech_analysis.hpp'; cat 'Phase 2/engine/include/tlsfp/ech_parser.hpp'; cat 'Phase 2/engine/CMakeLists.txt'; sed -n '1,105p' 'Phase 2/engine/src/main.cpp'`
>
> - Ran `git status --short --branch; cat 'Phase 2/engine/include/tlsfp/capture.hpp'; cat 'Phase 2/engine/include/tlsfp/accumulator.hpp'; cat 'Phase 2/engine/src/accumulator.cpp'`
>
> - Ran `sed -n '295,355p' 'Phase 2/engine/src/capture.cpp'; sed -n '430,490p' 'Phase 2/engine/src/capture.cpp'; sed -n '320,425p' 'Phase 2/engine/src/parser.cpp'; sed -n '116,190p' 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; git log -2 --oneline`
>
> <details><summary>Explored a file, 2 searches, a list</summary>
>
> - Searched for `json|escape|write` in `db.cpp`
> - Read `./Phase 2/engine/src/ech_analysis.cpp`
> - Listed files in `tests`
> - Searched for `SYN|FIN|RST|first_alpn|selected_version` in `capture.cpp`
>
> </details>
>
> </details>
>
> Checkpoint 1 is now committed on `feature/ech`. The main gaps are still in the capture path: it discards SYN/FIN/RST packets, forgets completed records, and processes only the first record in coalesced input. Those need targeted fixes before connection summaries can be reliable.
>
> For checkpoint 2, I recommend keeping the current terminal view and adding a JSON Lines output file, so you can inspect both during manual testing.
>
> <details><summary>Explored 2 files, a search, a list, ran a command, searched the web</summary>
>
> <details><summary>Explored 2 files, a search, a list</summary>
>
> - Read `./Phase 2/engine/include/tlsfp/types.hpp`
> - Read `./Phase 2/engine/tests/fixtures/generate_ech_fixture.py`
> - Searched for `TEST\(|76|parity` in `test_ech_parser.cpp`
> - Listed files in `GTest`
>
> </details>
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4`
>
> Searched the web for `'If the server does not negotiate TLS 1.3'`
>
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure --quiet; git status --porcelain`
>
> </details>
>
> The summaries will go to a file alongside the existing terminal output.
>
> I’ll keep HRR support minimal: recognize it so it doesn’t prematurely end the summary, then wait for the final ServerHello. Positive HRR acceptance inference stays optional. The main new interpretation will be the limited I3 rule: ECH observed with negotiation below TLS 1.3 rules out acceptance; TLS 1.3 alone leaves acceptance unverified.
>
> Plan
>
> # Checkpoint 2 — Correlate both directions and write connection summaries
>
> ## Summary
>
> This checkpoint answers: **“What did the client offer, what did the server respond, and what can we conclude from that exchange?”**
>
> Add `--json <file>` alongside the existing terminal output. Each tracked TLS connection produces one JSON Lines summary containing its client observation, final ServerHello, fingerprints, and evidence limits.
>
> Work on `feature/ech`, using checkpoint-1 commit `ea68a83` as the baseline. Stop after this checkpoint for manual testing.
>
> ## Implementation changes
>
> ### 1. Preserve records and connection history
>
> - Keep connection records and JSON serialization in the existing capture implementation. Extend the existing accumulator; add no separate flow, output, or framing modules.
> - Identify connections by IP version and both address/port pairs, independent of direction. Establish client/server roles from SYN or parsed hello types, never port numbers. Preserve unknown orientation when evidence is insufficient.
> - Process SYN/FIN/RST before discarding packets without payload. Account for SYN’s sequence-number consumption; process accompanying payload before closure.
> - Retain the first ClientHello’s owned observations, outer random, copied SNI/ALPN, fingerprints, timestamps, and final server observation.
> - A retransmitted SYN must not reset an open connection. A new initial sequence number or SYN after closure starts a new connection generation.
>
> ### 2. Fix the supported transport path
>
> - Iterate through all complete TLS records in contiguous TCP input, preserving partial headers and trailing records across segments.
> - Handle compatibility ChangeCipherSpec records through the same record loop, replacing the current single-prefix stripping.
> - Retain per-direction sequence progress after record completion. Suppress duplicate bytes, including retransmissions after a hello has already been delivered; trim partial overlaps.
> - Report gaps and capture truncation as incomplete. Stop parsing that direction after a gap rather than guessing a new record boundary.
> - Preserve the 8192-byte record limit and explicit unsupported outcome. Support complete hello messages inside one record; cross-record hello assembly remains deferred.
> - Walk complete handshake messages within supported plaintext records. Encrypted records must never be interpreted as plaintext hellos.
> - Extend accumulator notifications to report incomplete, unsupported, and malformed framing with reasons. Preserve the existing callback interface through compatible defaults; `active_flow_count()` continues to count unfinished record buffers.
>
> ### 3. Finalize one bounded summary
>
> - Emit at the final ServerHello. Otherwise finalize on FIN/RST, timeout, connection replacement, capacity eviction, capture end, interruption, or capture error.
> - Recognize HRR using its fixed random, retain the original ClientHello, and wait for the final ServerHello. Mark HRR sequence analysis as unsupported; do not implement I1/I2 classification or retain ciphertext for comparison.
> - After emission, release owned hello data and buffers. Retain a small completion marker and sequence progress to suppress duplicate output until closure or expiry.
> - Default to **1024 retained connection generations**, a **30-second connection idle timeout**, and the existing **3-second unfinished-record timeout**. Include completion markers and SYN-only tracking in the cap; emit summaries only for TLS candidates.
> - Evict the least recently observed connection when capacity is reached, recording `capacity_limit` for an unfinished TLS candidate.
> - Use packet-time progression for offline expiry. Use nonblocking live dispatch with maintenance at least every 100 ms while idle. Tests use an injected clock.
>
> ### 4. Interpret server evidence conservatively
>
> - Give ServerHello parsing the same detailed completeness contract as ClientHello parsing. Require complete extension framing; validate `supported_versions` before using it.
> - Resolve negotiated version from `supported_versions`, falling back to the legacy version when that extension is absent.
> - For correlated ECH presence and a recognized negotiated version below TLS 1.3, report `non_acceptance_observed` with named I3 evidence. TLS 1.3 alone leaves acceptance `unverified`; offer type remains `unknown`. [RFC 9849 §6.1.4](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4).
> - Apply initial-hello findings only when connection history establishes that role. Keep unknown context explicit.
> - Preserve independent findings and per-occurrence ECH statuses. Missing client data must never become ECH absence.
> - Summary completeness describes the observed hello pair, not successful TLS completion or application traffic.
>
> ## Output and interfaces
>
> Add `CaptureOptions.json_filename` and parse `--json <file>` while retaining existing options. Create a new output file at startup; report existing-file/open failures clearly. Flush each summary and fail the run on write errors. Explicitly requested JSON output remains enabled with `-q`.
>
> Use a versioned summary containing:
>
> | Group | Contents |
> |---|---|
> | Identity | Schema version, generated capture ID, connection ID, capture source |
> | Connection | Endpoint tuple, known roles, first/last observation timestamps, completion reason |
> | Client | Hello status, outer random/SNI, ECH presence, occurrences, findings, JA3/JA4 |
> | Server | Hello status, negotiated version, HRR-seen flag, final JA3S/JA4S |
> | Interpretation | Offer type, acceptance assessment, evidence, transport/analysis limitations |
>
> Unavailable values use JSON `null`. Serialize copied data with correct string escaping; include no ciphertext, endpoint secrets, or experimental ground-truth labels.
>
> ## Testing and manual acceptance
>
> - Keep all 76 existing tests passing. Add focused accumulator and connection/replay tests with deterministic fixtures.
> - Cover segmented/coalesced records, split headers, trailing partial records, compatibility CCS, complete retransmissions, overlaps, gaps, sequence wraparound, truncation, and size boundaries.
> - Cover SYN retransmission, tuple reuse, FIN/RST with payload, timeout without new packets, capacity eviction, server-only capture, EOF/interruption, and HRR followed by final ServerHello.
> - Verify one summary per retained connection generation, unknown-versus-absent behavior, JSON escaping/nulls, quiet mode, and output failures.
> - Run Release and ASan/UBSan checks using compatible GoogleTest builds. Compare matching hello fingerprints against checkpoint 1 across the seven baseline captures; investigate count changes separately from hash changes.
>
> Provide these tangible manual checks:
>
> 1. **Chrome capture:** four paired summaries, preserving the known ECH fields and showing the correlated server version.
> 2. **curl capture:** one paired summary with confirmed ECH absence.
> 3. **Synthetic exchanges:** ECH plus TLS 1.2 produces I3 non-acceptance; ECH plus TLS 1.3 remains unverified.
> 4. **Incomplete/retransmitted exchanges:** explicit reasons and no duplicate summaries.
>
> Add a checkpoint-2 testing guide and update project context with validation results and remaining limits. Endpoint labeling, controlled measurements, general out-of-order recovery, cross-record assembly, and positive HRR inference remain later work.
</details>

> PLEASE IMPLEMENT THIS PLAN:
> # Checkpoint 2 — Correlate both directions and write connection summaries
>
> ## Summary
>
> This checkpoint answers: **“What did the client offer, what did the server respond, and what can we conclude from that exchange?”**
>
> Add `--json <file>` alongside the existing terminal output. Each tracked TLS connection produces one JSON Lines summary containing its client observation, final ServerHello, fingerprints, and evidence limits.
>
> Work on `feature/ech`, using checkpoint-1 commit `ea68a83` as the baseline. Stop after this checkpoint for manual testing.
>
> ## Implementation changes
>
> ### 1. Preserve records and connection history
>
> - Keep connection records and JSON serialization in the existing capture implementation. Extend the existing accumulator; add no separate flow, output, or framing modules.
> - Identify connections by IP version and both address/port pairs, independent of direction. Establish client/server roles from SYN or parsed hello types, never port numbers. Preserve unknown orientation when evidence is insufficient.
> - Process SYN/FIN/RST before discarding packets without payload. Account for SYN’s sequence-number consumption; process accompanying payload before closure.
> - Retain the first ClientHello’s owned observations, outer random, copied SNI/ALPN, fingerprints, timestamps, and final server observation.
> - A retransmitted SYN must not reset an open connection. A new initial sequence number or SYN after closure starts a new connection generation.
>
> ### 2. Fix the supported transport path
>
> - Iterate through all complete TLS records in contiguous TCP input, preserving partial headers and trailing records across segments.
> - Handle compatibility ChangeCipherSpec records through the same record loop, replacing the current single-prefix stripping.
> - Retain per-direction sequence progress after record completion. Suppress duplicate bytes, including retransmissions after a hello has already been delivered; trim partial overlaps.
> - Report gaps and capture truncation as incomplete. Stop parsing that direction after a gap rather than guessing a new record boundary.
> - Preserve the 8192-byte record limit and explicit unsupported outcome. Support complete hello messages inside one record; cross-record hello assembly remains deferred.
> - Walk complete handshake messages within supported plaintext records. Encrypted records must never be interpreted as plaintext hellos.
> - Extend accumulator notifications to report incomplete, unsupported, and malformed framing with reasons. Preserve the existing callback interface through compatible defaults; `active_flow_count()` continues to count unfinished record buffers.
>
> ### 3. Finalize one bounded summary
>
> - Emit at the final ServerHello. Otherwise finalize on FIN/RST, timeout, connection replacement, capacity eviction, capture end, interruption, or capture error.
> - Recognize HRR using its fixed random, retain the original ClientHello, and wait for the final ServerHello. Mark HRR sequence analysis as unsupported; do not implement I1/I2 classification or retain ciphertext for comparison.
> - After emission, release owned hello data and buffers. Retain a small completion marker and sequence progress to suppress duplicate output until closure or expiry.
> - Default to **1024 retained connection generations**, a **30-second connection idle timeout**, and the existing **3-second unfinished-record timeout**. Include completion markers and SYN-only tracking in the cap; emit summaries only for TLS candidates.
> - Evict the least recently observed connection when capacity is reached, recording `capacity_limit` for an unfinished TLS candidate.
> - Use packet-time progression for offline expiry. Use nonblocking live dispatch with maintenance at least every 100 ms while idle. Tests use an injected clock.
>
> ### 4. Interpret server evidence conservatively
>
> - Give ServerHello parsing the same detailed completeness contract as ClientHello parsing. Require complete extension framing; validate `supported_versions` before using it.
> - Resolve negotiated version from `supported_versions`, falling back to the legacy version when that extension is absent.
> - For correlated ECH presence and a recognized negotiated version below TLS 1.3, report `non_acceptance_observed` with named I3 evidence. TLS 1.3 alone leaves acceptance `unverified`; offer type remains `unknown`. [RFC 9849 §6.1.4](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4).
> - Apply initial-hello findings only when connection history establishes that role. Keep unknown context explicit.
> - Preserve independent findings and per-occurrence ECH statuses. Missing client data must never become ECH absence.
> - Summary completeness describes the observed hello pair, not successful TLS completion or application traffic.
>
> ## Output and interfaces
>
> Add `CaptureOptions.json_filename` and parse `--json <file>` while retaining existing options. Create a new output file at startup; report existing-file/open failures clearly. Flush each summary and fail the run on write errors. Explicitly requested JSON output remains enabled with `-q`.
>
> Use a versioned summary containing:
>
> | Group | Contents |
> |---|---|
> | Identity | Schema version, generated capture ID, connection ID, capture source |
> | Connection | Endpoint tuple, known roles, first/last observation timestamps, completion reason |
> | Client | Hello status, outer random/SNI, ECH presence, occurrences, findings, JA3/JA4 |
> | Server | Hello status, negotiated version, HRR-seen flag, final JA3S/JA4S |
> | Interpretation | Offer type, acceptance assessment, evidence, transport/analysis limitations |
>
> Unavailable values use JSON `null`. Serialize copied data with correct string escaping; include no ciphertext, endpoint secrets, or experimental ground-truth labels.
>
> ## Testing and manual acceptance
>
> - Keep all 76 existing tests passing. Add focused accumulator and connection/replay tests with deterministic fixtures.
> - Cover segmented/coalesced records, split headers, trailing partial records, compatibility CCS, complete retransmissions, overlaps, gaps, sequence wraparound, truncation, and size boundaries.
> - Cover SYN retransmission, tuple reuse, FIN/RST with payload, timeout without new packets, capacity eviction, server-only capture, EOF/interruption, and HRR followed by final ServerHello.
> - Verify one summary per retained connection generation, unknown-versus-absent behavior, JSON escaping/nulls, quiet mode, and output failures.
> - Run Release and ASan/UBSan checks using compatible GoogleTest builds. Compare matching hello fingerprints against checkpoint 1 across the seven baseline captures; investigate count changes separately from hash changes.
>
> Provide these tangible manual checks:
>
> 1. **Chrome capture:** four paired summaries, preserving the known ECH fields and showing the correlated server version.
> 2. **curl capture:** one paired summary with confirmed ECH absence.
> 3. **Synthetic exchanges:** ECH plus TLS 1.2 produces I3 non-acceptance; ECH plus TLS 1.3 remains unverified.
> 4. **Incomplete/retransmitted exchanges:** explicit reasons and no duplicate summaries.
>
> Add a checkpoint-2 testing guide and update project context with validation results and remaining limits. Endpoint labeling, controlled measurements, general out-of-order recovery, cross-record assembly, and positive HRR inference remain later work.

<details><summary>12 previous messages</summary>

> I’ll implement checkpoint 2 on `feature/ech`, starting with record handling and connection tracking, then add JSON output and the replay tests. I’ll stop when the manual checks are ready.
>
> <details><summary>Edited 3 files, explored a file, 2 lists, ran 6 commands</summary>
>
> - Ran `git status --short --branch; cat 'Phase 2/engine/include/tlsfp/accumulator.hpp'; cat 'Phase 2/engine/include/tlsfp/capture.hpp'; cat 'Phase 2/engine/include/tlsfp/parser.hpp'; cat 'Phase 2/engine/src/capture.cpp'`
>
> <details><summary>Explored 2 files, 2 lists</summary>
>
> - Read `./AGENTS.md`
> - Read `~/.agents/skills/code-review-and-quality/SKILL.md`
> - Listed files in `GTest`
> - Listed files in `python`
>
> </details>
>
> - Ran `cp -R 'Phase 2/engine' /private/tmp/cs331-cp2-baseline-engine`
>
> - Ran `cmake -S /private/tmp/cs331-cp2-baseline-engine -B /private/tmp/cs331-cp2-baseline-build -DCMAKE_BUILD_TYPE=Release`
>
> - Ran `cat > 'Phase 2/engine/include/tlsfp/accumulator.hpp' <<'EOF'
> #ifndef TLSFP_ACCUMULATOR_HPP
> #define TLSFP_ACCUMULATOR_HPP
>
> #include "tlsfp/types.hpp"
> #include "tlsfp/ech_parser.hpp"
> #include <functional>
> #include <memory>
> #include <unordered_map>
> #include <vector>
> #include <ctime>
>
> namespace tlsfp {
>
> // Only unfinished records allocate storage. Completed streams retain a sequence
> // watermark so retransmission after record delivery cannot produce another hello.
> struct FragmentedHandshake {
>     std::vector<uint8_t> bytes;
>     size_t expected{0};
>     time_t last_seen{0};
> };
>
> class TwoTierAccumulator {
> public:
>     using HandshakeCallback = std::function<void(const FlowKey &, const uint8_t *, size_t)>;
>     using RecordLimitCallback = std::function<void(const FlowKey &)>;
>     using IssueCallback = std::function<void(const FlowKey &, ParseStatus, const char *,
>                                              const uint8_t *, size_t)>;
>
>     explicit TwoTierAccumulator(HandshakeCallback ready, RecordLimitCallback limit = {},
>                                 IssueCallback issue = {}, size_t max_streams = 2048)
>         : ready_(std::move(ready)), limit_(std::move(limit)), issue_(std::move(issue)),
>           max_streams_(max_streams) {}
>
>     void process_segment(const FlowKey &, uint32_t seq, const uint8_t *, size_t, time_t);
>     void start_flow(const FlowKey &, uint32_t first_data_seq, time_t);
>     void stop_flow(const FlowKey &); // Call outside a record callback; frees any partial buffer.
>     void forget_flow(const FlowKey &);
>     void invalidate_flow(const FlowKey &, const char *reason);
>     void cleanup_stale_flows(time_t);
>     void flush_pending(const char *reason);
>     [[nodiscard]] size_t active_flow_count() const noexcept;
>
> private:
>     struct Stream {
>         uint32_t next_seq{0};
>         bool stopped{false};
>         bool tls_started{false};
>         std::unique_ptr<FragmentedHandshake> partial;
>     };
>     void report(const FlowKey &, Stream &, ParseStatus, const char *);
>     HandshakeCallback ready_;
>     RecordLimitCallback limit_;
>     IssueCallback issue_;
>     size_t max_streams_;
>     std::unordered_map<FlowKey, Stream, FlowHash> streams_;
> };
> } // namespace tlsfp
> #endif
> EOF
> cat > 'Phase 2/engine/src/accumulator.cpp' <<'EOF'
> #include "tlsfp/accumulator.hpp"
> #include <algorithm>
>
> namespace tlsfp {
> namespace {
> bool tls_type(uint8_t value) { return value >= 20 && value <= 24; }
> }
>
> void TwoTierAccumulator::report(const FlowKey &key, Stream &stream, ParseStatus status,
>                                  const char *reason) {
>     stream.stopped = true;
>     const auto *partial = stream.partial.get();
>     if (issue_) issue_(key, status, reason, partial ? partial->bytes.data() : nullptr,
>                       partial ? partial->bytes.size() : 0);
>     if (status == ParseStatus::Unsupported && limit_) limit_(key);
>     stream.partial.reset();
> }
>
> void TwoTierAccumulator::start_flow(const FlowKey &key, uint32_t seq, time_t) {
>     forget_flow(key);
>     if (streams_.size() < max_streams_) streams_[key].next_seq = seq;
> }
>
> void TwoTierAccumulator::forget_flow(const FlowKey &key) { streams_.erase(key); }
> void TwoTierAccumulator::stop_flow(const FlowKey &key) {
>     auto it = streams_.find(key);
>     if (it != streams_.end()) {
>         it->second.stopped = true;
>         it->second.partial.reset();
>     }
> }
>
> void TwoTierAccumulator::invalidate_flow(const FlowKey &key, const char *reason) {
>     auto it = streams_.find(key);
>     if (it != streams_.end() && !it->second.stopped)
>         report(key, it->second, ParseStatus::Incomplete, reason);
> }
>
> void TwoTierAccumulator::process_segment(const FlowKey &key, uint32_t seq,
>                                          const uint8_t *payload, size_t length, time_t now) {
>     if (!payload || length == 0) return;
>     auto it = streams_.find(key);
>     if (it == streams_.end()) {
>         if (!tls_type(payload[0])) return;
>         if (streams_.size() >= max_streams_) {
>             if (issue_) issue_(key, ParseStatus::Unsupported, "stream_capacity", nullptr, 0);
>             return;
>         }
>         it = streams_.try_emplace(key).first;
>         it->second.next_seq = seq;
>     }
>     Stream &stream = it->second;
>     if (stream.stopped) return;
>     const int32_t distance = static_cast<int32_t>(seq - stream.next_seq);
>     if (distance > 0) {
>         report(key, stream, ParseStatus::Incomplete, "tcp_gap");
>         return;
>     }
>     if (distance < 0) {
>         const auto overlap = static_cast<uint32_t>(stream.next_seq - seq);
>         if (overlap >= length) return;
>         payload += overlap;
>         length -= overlap;
>     }
>     stream.next_seq += static_cast<uint32_t>(length);
>
>     while (length != 0 && !stream.stopped) {
>         if (!stream.partial) {
>             if (!stream.tls_started && !tls_type(payload[0])) {
>                 stream.stopped = true; // A SYN hint was for non-TLS traffic.
>                 return;
>             }
>             stream.tls_started = true;
>             // Fast path: deliver one bounded complete record without copying.
>             if (length >= 5 && tls_type(payload[0]) && payload[1] == 3 && payload[2] <= 4) {
>                 const size_t total = 5 + (size_t{payload[3]} << 8) + payload[4];
>                 if (total > ACCUMULATOR_BUFFER_SIZE) {
>                     report(key, stream, ParseStatus::Unsupported, "record_size_limit");
>                     return;
>                 }
>                 if (length >= total) {
>                     if (ready_) ready_(key, payload, total);
>                     payload += total;
>                     length -= total;
>                     continue;
>                 }
>             }
>             stream.partial = std::make_unique<FragmentedHandshake>();
>         }
>         auto &partial = *stream.partial;
>         const size_t target = partial.expected ? partial.expected : 5;
>         const size_t count = std::min(length, target - partial.bytes.size());
>         partial.bytes.insert(partial.bytes.end(), payload, payload + count);
>         partial.last_seen = now;
>         payload += count;
>         length -= count;
>         if (!partial.expected && partial.bytes.size() == 5) {
>             const auto &header = partial.bytes;
>             if (!tls_type(header[0]) || header[1] != 3 || header[2] > 4) {
>                 report(key, stream, ParseStatus::Malformed, "invalid_tls_record_header");
>                 return;
>             }
>             partial.expected = 5 + (size_t{header[3]} << 8) + header[4];
>             if (partial.expected > ACCUMULATOR_BUFFER_SIZE) {
>                 report(key, stream, ParseStatus::Unsupported, "record_size_limit");
>                 return;
>             }
>         }
>         if (partial.expected && partial.bytes.size() == partial.expected) {
>             if (ready_) ready_(key, partial.bytes.data(), partial.bytes.size());
>             stream.partial.reset();
>         }
>     }
> }
>
> void TwoTierAccumulator::cleanup_stale_flows(time_t now) {
>     for (auto &[key, stream] : streams_) {
>         if (stream.partial && now > stream.partial->last_seen &&
>             now - stream.partial->last_seen > FLOW_TIMEOUT_SECONDS)
>             report(key, stream, ParseStatus::Incomplete, "record_timeout");
>     }
> }
>
> void TwoTierAccumulator::flush_pending(const char *reason) {
>     for (auto &[key, stream] : streams_)
>         if (stream.partial) report(key, stream, ParseStatus::Incomplete, reason);
> }
>
> size_t TwoTierAccumulator::active_flow_count() const noexcept {
>     size_t count = 0;
>     for (const auto &[key, stream] : streams_) if (stream.partial) ++count;
>     return count;
> }
> } // namespace tlsfp
> EOF`
>
> - Ran `cmake --build /private/tmp/cs331-cp2-baseline-build -j 4`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/parser.hpp` (+8 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/parser.cpp` (+9 -7)
>
> - Ran `../.venv/bin/python - <<'PY'
> from pathlib import Path
> p=Path('Phase 2/engine/src/parser.cpp')
> s=p.read_text(); start=s.index('bool parse_server_hello(')
> s=s[:start]+'''bool parse_server_hello(const uint8_t *record, size_t record_len, ServerHelloData &out) {
>     out.clear();
>     const auto fail = [&out](ParseStatus status, const char *detail) {
>         out.parse_status = status;
>         out.parse_detail = detail;
>         return false;
>     };
>     if (!record || record_len < 5) return fail(ParseStatus::Incomplete, "missing TLS record header");
>     ByteReader root{record, record_len};
>     uint8_t type = 0;
>     uint16_t version = 0, length = 0;
>     root.read_u8(type); root.read_u16_be(version); root.read_u16_be(length);
>     if (type != TLS_RECORD_HANDSHAKE || (version >> 8) != 3 || (version & 255) > 4)
>         return fail(ParseStatus::Malformed, "invalid handshake record header");
>     if (size_t{5} + length > ACCUMULATOR_BUFFER_SIZE)
>         return fail(ParseStatus::Unsupported, "TLS record exceeds 8192-byte supported limit");
>     if (!root.has_bytes(length)) return fail(ParseStatus::Incomplete, "missing TLS record bytes");
>     auto body = *root.spawn_sub_reader(length);
>     uint8_t hello_type = 0;
>     uint32_t hello_length = 0;
>     if (!body.read_u8(hello_type) || hello_type != TLS_HANDSHAKE_SERVER_HELLO)
>         return fail(ParseStatus::Malformed, "expected ServerHello handshake type");
>     if (!body.read_u24_be(hello_length) || !body.has_bytes(hello_length))
>         return fail(ParseStatus::Unsupported, "ServerHello spans TLS records");
>     auto hello = *body.spawn_sub_reader(hello_length);
>     const uint8_t *random = nullptr;
>     if (!hello.read_u16_be(out.server_version) || !hello.read_bytes(32, random))
>         return fail(ParseStatus::Malformed, "missing ServerHello version or random");
>     out.random.emplace();
>     std::copy_n(random, 32, out.random->begin());
>     // RFC 8446 HRR sentinel; this is not an ordinary final ServerHello.
>     constexpr std::array<uint8_t, 32> hrr{{
>         0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
>         0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c}};
>     out.is_hrr = *out.random == hrr;
>     uint8_t session_length = 0, compression = 0;
>     if (!hello.read_u8(session_length) || session_length > 32 || !hello.skip(session_length) ||
>         !hello.read_u16_be(out.selected_cipher) || !hello.read_u8(compression))
>         return fail(ParseStatus::Malformed, "invalid ServerHello fixed fields");
>     if (hello.remaining()) {
>         uint16_t extensions_length = 0;
>         if (!hello.read_u16_be(extensions_length) || hello.remaining() != extensions_length)
>             return fail(ParseStatus::Malformed, "extension vector does not consume ServerHello");
>         auto extensions = *hello.spawn_sub_reader(extensions_length);
>         if (!parse_server_extensions(extensions, out))
>             return fail(ParseStatus::Malformed, "invalid server extension framing or supported_versions");
>     }
>     const bool has_version = std::find(out.extensions.begin(), out.extensions.end(), 43) != out.extensions.end();
>     if (!has_version) out.selected_version = out.server_version;
>     out.parse_status = ParseStatus::Complete;
>     out.parse_detail = "complete ServerHello framing";
>     return true;
> }
>
> } // namespace tlsfp
> '''
> p.write_text(s)
> PY`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/capture.hpp` (+18 -1)
>
> </details>
>
> The accumulator now walks contiguous records and retains sequence progress after delivery, so retransmissions can’t produce a second hello. ServerHello parsing also has explicit completeness outcomes and HRR recognition.
>
> Next I’m connecting those observations into bounded connection records, then adding the JSON writer.
>
> <details><summary>Edited 3 files, explored 2 files, a search, ran 7 commands</summary>
>
> - Ran `cat > /private/tmp/cs331-cp2-capture-model.txt <<'EOF'
> FlowKey reverse_flow(FlowKey key) {
>     std::swap(key.src_ip, key.dst_ip);
>     std::swap(key.src_port, key.dst_port);
>     return key;
> }
>
> FlowKey canonical_flow(const FlowKey &key) {
>     const size_t length = key.ip_version == 4 ? 4 : 16;
>     const int order = std::memcmp(&key.src_ip, &key.dst_ip, length);
>     return order > 0 || (order == 0 && ntohs(key.src_port) > ntohs(key.dst_port))
>         ? reverse_flow(key) : key;
> }
>
> std::string json_string(std::string_view value) {
>     std::string out{"\""};
>     for (unsigned char byte : value) {
>         if (byte == '"' || byte == '\\') { out += '\\'; out += static_cast<char>(byte); }
>         else if (byte < 32 || byte >= 127) {
>             char escaped[7];
>             std::snprintf(escaped, sizeof(escaped), "\\u%04x", byte);
>             out += escaped;
>         } else out += static_cast<char>(byte);
>     }
>     return out + '"';
> }
>
> template <typename T>
> std::string json_number(const std::optional<T> &value) {
>     if (!value) return "null";
>     if constexpr (std::is_same_v<T, bool>) return *value ? "true" : "false";
>     return std::to_string(*value);
> }
>
> std::string json_text(const std::string &value) {
>     return value.empty() ? "null" : json_string(value);
> }
>
> std::string random_hex(const std::optional<std::array<uint8_t, 32>> &value) {
>     if (!value) return {};
>     std::string out;
>     for (uint8_t byte : *value) {
>         char hex[3]; std::snprintf(hex, sizeof(hex), "%02x", byte); out += hex;
>     }
>     return out;
> }
>
> std::string endpoint_json(const FlowKey &key, bool source) {
>     char address[INET6_ADDRSTRLEN]{};
>     inet_ntop(key.ip_version == 4 ? AF_INET : AF_INET6,
>               source ? &key.src_ip : &key.dst_ip, address, sizeof(address));
>     return "{\"ip\":" + json_string(address) + ",\"port\":" +
>         std::to_string(ntohs(source ? key.src_port : key.dst_port)) + "}";
> }
>
> std::string ech_json(const EchObservation &ech) {
>     std::string out = "{\"presence\":" + json_number(ech.present) + ",\"findings\":[";
>     bool comma = false;
>     for (const auto &finding : {
>             std::pair{DuplicateEch, "duplicate_ech"},
>             std::pair{ForbiddenOuterExtensions, "forbidden_outer_extensions"},
>             std::pair{ExternalInnerMarker, "external_inner_marker"},
>             std::pair{ExportOnlyAead, "export_only_aead"},
>             std::pair{EmptyEncContextUnknown, "empty_enc_context_unknown"},
>             std::pair{EmptyEncInInitialHello, "empty_enc_in_initial_hello"}}) {
>         if (!(ech.findings & finding.first)) continue;
>         if (comma) out += ',';
>         comma = true; out += json_string(finding.second);
>     }
>     out += "],\"occurrences\":[";
>     comma = false;
>     for (const auto &body : ech.occurrences) {
>         if (comma) out += ',';
>         comma = true;
>         out += "{\"status\":" + json_string(parse_status_name(body.status)) +
>             ",\"detail\":" + json_string(body.detail) +
>             ",\"variant\":" + json_number(body.variant) + ",\"kdf_id\":" + json_number(body.kdf_id) +
>             ",\"aead_id\":" + json_number(body.aead_id) + ",\"config_id\":" + json_number(body.config_id) +
>             ",\"enc_length\":" + json_number(body.enc_length) +
>             ",\"ciphertext_length\":" + json_number(body.payload_length) + "}";
>     }
>     return out + "]}";
> }
>
> struct ClientObservation {
>     ParseStatus status{ParseStatus::NotExamined};
>     std::string detail, random, sni, alpn, ja3, ja4;
>     EchObservation ech;
> };
> struct ServerObservation {
>     ParseStatus status{ParseStatus::NotExamined};
>     std::string detail, ja3s, ja4s;
>     std::optional<uint16_t> version;
> };
> struct Connection {
>     FlowKey key;
>     uint64_t id{0}, first_us{0}, last_us{0}, recency{0};
>     double idle_at{0};
>     std::optional<bool> client_at_a;
>     std::optional<uint32_t> syn_seq[2];
>     bool tls_candidate{false}, emitted{false}, closed{false}, hrr_seen{false}, role_conflict{false};
>     bool protected_direction[2]{false, false};
>     bool tls13_offered{false};
>     std::optional<ClientObservation> client;
>     std::optional<ServerObservation> server;
>     ParseStatus direction_status[2]{ParseStatus::NotExamined, ParseStatus::NotExamined};
>     std::vector<std::string> issues[2];
>
>     int direction(const FlowKey &flow) const { return flow == key ? 0 : 1; }
>     void orient(bool client_a) {
>         if (client_at_a && *client_at_a != client_a) role_conflict = true;
>         else client_at_a = client_a;
>     }
> };
>
> std::string client_json(const Connection &connection) {
>     const ClientObservation empty;
>     const auto &client = connection.client ? *connection.client : empty;
>     ParseStatus status = client.status;
>     if (!connection.client && connection.client_at_a)
>         status = connection.direction_status[*connection.client_at_a ? 0 : 1];
>     return "{\"status\":" + json_string(parse_status_name(status)) + ",\"detail\":" + json_text(client.detail) +
>         ",\"outer_random\":" + json_text(client.random) + ",\"outer_sni\":" + json_text(client.sni) +
>         ",\"alpn\":" + json_text(client.alpn) + ",\"ech\":" + ech_json(client.ech) +
>         ",\"ja3\":" + json_text(client.ja3) + ",\"ja4\":" + json_text(client.ja4) + "}";
> }
>
> std::string server_json(const Connection &connection) {
>     const ServerObservation empty;
>     const auto &server = connection.server ? *connection.server : empty;
>     ParseStatus status = server.status;
>     if (!connection.server && connection.client_at_a)
>         status = connection.direction_status[*connection.client_at_a ? 1 : 0];
>     return "{\"status\":" + json_string(parse_status_name(status)) + ",\"detail\":" + json_text(server.detail) +
>         ",\"negotiated_version\":" + json_number(server.version) +
>         ",\"hrr_seen\":" + (connection.hrr_seen ? "true" : "false") +
>         ",\"ja3s\":" + json_text(server.ja3s) + ",\"ja4s\":" + json_text(server.ja4s) + "}";
> }
>
> bool non_acceptance_observed(const Connection &connection) {
>     if (connection.role_conflict || connection.hrr_seen || !connection.client || !connection.server ||
>         connection.client->status != ParseStatus::Complete ||
>         connection.server->status != ParseStatus::Complete || connection.client->ech.present != true)
>         return false;
>     const auto version = connection.server->version;
>     return version && (*version == 0x0301 || *version == 0x0302 || *version == 0x0303);
> }
> EOF
> ../.venv/bin/python - <<'PY'
> from pathlib import Path
> p=Path('Phase 2/engine/src/capture.cpp'); s=p.read_text()
> s=s.replace('#include <filesystem>', '''#include <filesystem>
> #include <fcntl.h>
> #include <unistd.h>
> #include <cerrno>
> #include <thread>
> #include <sstream>
> #include <type_traits>
> #include <algorithm>''')
> insert=Path('/private/tmp/cs331-cp2-capture-model.txt').read_text()
> s=s.replace('} // anonymous namespace\n\nstruct CaptureEngine::Impl',insert+'\n} // anonymous namespace\n\nstruct CaptureEngine::Impl',1)
> p.write_text(s)
> PY`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+95 -8)
>
> - Ran `cat > /private/tmp/cs331-cp2-lifecycle.txt <<'EOF'
> void CaptureEngine::maintenance() {
>     impl_->now = options_.read_filename.empty() ? impl_->clock_now() : impl_->watermark_us / 1000000.0;
>     accumulator_->cleanup_stale_flows(static_cast<time_t>(impl_->now));
>     for (auto it = impl_->connections.begin(); it != impl_->connections.end();) {
>         if (impl_->now - it->second.idle_at > options_.connection_timeout_seconds) {
>             impl_->emit(it->second, "timeout");
>             accumulator_->forget_flow(it->first);
>             accumulator_->forget_flow(reverse_flow(it->first));
>             it = impl_->connections.erase(it);
>         } else ++it;
>     }
> }
>
> size_t CaptureEngine::retained_connection_count() const noexcept { return impl_->connections.size(); }
>
> bool CaptureEngine::finish_capture(const char *reason) {
>     accumulator_->flush_pending(reason);
>     std::vector<Connection *> ordered;
>     for (auto &[key, connection] : impl_->connections) ordered.push_back(&connection);
>     std::sort(ordered.begin(), ordered.end(), [](const auto *a, const auto *b) { return a->id < b->id; });
>     for (auto *connection : ordered) {
>         impl_->emit(*connection, reason);
>         accumulator_->forget_flow(connection->key);
>         accumulator_->forget_flow(reverse_flow(connection->key));
>     }
>     impl_->connections.clear();
>     return !impl_->failed;
> }
>
> void CaptureEngine::record_issue(const FlowKey &key, ParseStatus status, const char *reason,
>                                   const uint8_t *prefix, size_t length) {
>     auto it = impl_->connections.find(canonical_flow(key));
>     if (it == impl_->connections.end() || it->second.emitted) return;
>     auto &connection = it->second;
>     connection.tls_candidate = true;
>     const int direction = connection.direction(key);
>     auto &issues = connection.issues[direction];
>     if (std::find(issues.begin(), issues.end(), reason) != issues.end()) return;
>     issues.emplace_back(reason);
>     connection.direction_status[direction] = status;
>     if (prefix && length >= 6 && prefix[0] == TLS_RECORD_HANDSHAKE) {
>         if (prefix[5] == TLS_HANDSHAKE_CLIENT_HELLO) {
>             connection.orient(direction == 0);
>             if (!connection.client) {
>                 ClientObservation observation;
>                 observation.status = status; observation.detail = reason;
>                 connection.client = std::move(observation);
>             }
>         } else if (prefix[5] == TLS_HANDSHAKE_SERVER_HELLO) {
>             connection.orient(direction != 0);
>         }
>     }
>     if (options_.verbose && !options_.quiet) {
>         print_parse_diagnostic(key, "TLS record");
>         std::cout << "   │  status=" << parse_status_name(status) << " (" << reason << ")\n";
>     }
> }
>
> void CaptureEngine::ingest_tcp_segment(const FlowKey &key, uint32_t seq, uint8_t flags,
>                                         const uint8_t *payload, size_t length, uint64_t timestamp_us,
>                                         bool truncated) {
>     if (impl_->failed) return;
>     impl_->watermark_us = std::max(impl_->watermark_us, timestamp_us);
>     maintenance();
>     const FlowKey canonical = canonical_flow(key);
>     const int direction = key == canonical ? 0 : 1;
>     const bool initial_syn = (flags & TH_SYN) && !(flags & TH_ACK);
>     auto it = impl_->connections.find(canonical);
>     if (it != impl_->connections.end() && initial_syn &&
>         (it->second.closed || !it->second.syn_seq[direction] || *it->second.syn_seq[direction] != seq)) {
>         accumulator_->invalidate_flow(canonical, "connection_replaced");
>         accumulator_->invalidate_flow(reverse_flow(canonical), "connection_replaced");
>         impl_->emit(it->second, "connection_replaced");
>         accumulator_->forget_flow(canonical); accumulator_->forget_flow(reverse_flow(canonical));
>         impl_->connections.erase(it);
>         it = impl_->connections.end();
>     }
>     const bool tls_start = payload && length && payload[0] >= 20 && payload[0] <= 24;
>     if (it == impl_->connections.end()) {
>         if (!(flags & TH_SYN) && !tls_start) return;
>         if (impl_->connections.size() >= options_.max_connections) {
>             auto oldest = std::min_element(impl_->connections.begin(), impl_->connections.end(),
>                 [](const auto &a, const auto &b) { return a.second.recency < b.second.recency; });
>             if (oldest == impl_->connections.end()) return;
>             accumulator_->invalidate_flow(oldest->first, "capacity_limit");
>             accumulator_->invalidate_flow(reverse_flow(oldest->first), "capacity_limit");
>             impl_->emit(oldest->second, "capacity_limit");
>             accumulator_->forget_flow(oldest->first); accumulator_->forget_flow(reverse_flow(oldest->first));
>             impl_->connections.erase(oldest);
>         }
>         Connection connection;
>         connection.key = canonical;
>         connection.id = ++impl_->next_id;
>         connection.first_us = timestamp_us;
>         it = impl_->connections.emplace(canonical, std::move(connection)).first;
>     }
>     auto &connection = it->second;
>     connection.last_us = timestamp_us;
>     connection.idle_at = impl_->now;
>     connection.recency = ++impl_->recency;
>     if (initial_syn) connection.orient(direction == 0);
>     if ((flags & TH_SYN) && !connection.syn_seq[direction]) {
>         connection.syn_seq[direction] = seq;
>         accumulator_->start_flow(key, seq + 1, static_cast<time_t>(impl_->now));
>     }
>     connection.tls_candidate |= tls_start;
>     if (!connection.emitted && !connection.closed && length) {
>         if (truncated) {
>             record_issue(key, ParseStatus::Incomplete, "capture_truncated", payload, length);
>             accumulator_->invalidate_flow(key, "capture_truncated");
>         } else {
>             accumulator_->process_segment(key, seq + ((flags & TH_SYN) ? 1 : 0), payload,
>                                           length, static_cast<time_t>(impl_->now));
>         }
>     }
>     if (flags & (TH_FIN | TH_RST)) {
>         accumulator_->invalidate_flow(key, "connection_closed");
>         accumulator_->invalidate_flow(reverse_flow(key), "connection_closed");
>         impl_->emit(connection, flags & TH_RST ? "rst" : "fin");
>         connection.closed = true;
>     }
>     if (connection.emitted || connection.closed) {
>         accumulator_->stop_flow(canonical);
>         accumulator_->stop_flow(reverse_flow(canonical));
>     }
> }
>
> void CaptureEngine::process_assembled_handshake(const FlowKey &key, const uint8_t *record, size_t length) {
>     auto it = impl_->connections.find(canonical_flow(key));
>     if (it == impl_->connections.end() || it->second.emitted || length < 5) return;
>     auto &connection = it->second;
>     const int direction = connection.direction(key);
>     if (connection.protected_direction[direction]) return;
>     if (record[0] == TLS_RECORD_CHANGE_CIPHER_SPEC) {
>         if (!connection.tls13_offered && !connection.hrr_seen) {
>             connection.protected_direction[direction] = true;
>             record_issue(key, ParseStatus::Unsupported, "ccs_plaintext_context_unknown", nullptr, 0);
>         }
>         return;
>     }
>     if (record[0] == 23) {
>         connection.protected_direction[direction] = true;
>         record_issue(key, ParseStatus::Unsupported, "encrypted_record_before_final_hello", nullptr, 0);
>         return;
>     }
>     if (record[0] != TLS_RECORD_HANDSHAKE) return;
>     size_t offset = 5;
>     while (offset < length && !connection.emitted) {
>         const size_t available = length - offset;
>         size_t message_length = available;
>         bool complete = false;
>         if (available >= 4) {
>             message_length = 4 + (size_t{record[offset+1]} << 16) +
>                 (size_t{record[offset+2]} << 8) + record[offset+3];
>             complete = message_length <= available;
>         }
>         const bool hello = record[offset] == 1 || record[offset] == 2;
>         if (hello) {
>             // Reuse the shared record parser for each message, bounded to this
>             // message's bytes. Synthetic framing owns no data beyond the callback.
>             const size_t count = complete ? message_length : available;
>             std::vector<uint8_t> framed(record, record + 5);
>             framed[3] = static_cast<uint8_t>(count >> 8); framed[4] = static_cast<uint8_t>(count);
>             framed.insert(framed.end(), record + offset, record + offset + count);
>             process_hello(key, framed.data(), framed.size());
>         }
>         if (!complete) {
>             record_issue(key, ParseStatus::Unsupported, "handshake_spans_records", nullptr, 0);
>             connection.protected_direction[direction] = true;
>             return;
>         }
>         offset += message_length;
>     }
> }
>
> EOF
> ../.venv/bin/python - <<'PY'
> from pathlib import Path
> p=Path('Phase 2/engine/src/capture.cpp');s=p.read_text()
> pos=s.index('void CaptureEngine::process_assembled_handshake(')
> s=s[:pos]+Path('/private/tmp/cs331-cp2-lifecycle.txt').read_text()+s[pos:].replace('void CaptureEngine::process_assembled_handshake(', 'void CaptureEngine::process_hello(',1)
> p.write_text(s)
> PY`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp` (+2 -0)
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+77 -20)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/main.cpp` (+8 -2)
>
> <details><summary>Explored 2 files, a search</summary>
>
> - Searched for `tls_candidate|process_hello|ServerHello|return false|bool parse_server_extensions|return true` in `capture.cpp`
> - Read `./Phase 2/engine/src/parser.cpp`
> - Read `./Phase 2/engine/src/capture.cpp`
>
> </details>
>
> - Ran `cmake -S 'Phase 2/engine' -B 'Phase 2/engine/build' -DCMAKE_BUILD_TYPE=Release; cmake --build 'Phase 2/engine/build' -j 4`
>
> - Ran `git diff --check; wc -l 'Phase 2/engine/src/capture.cpp'; rg -n 'AGENTS' ../AGENTS.md`
>
> - Ran `'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/chrome.pcap -q --json /private/tmp/cs331-cp2-chrome-first.jsonl; ../.venv/bin/python - <<'PY'
> import json
> from pathlib import Path
> rows=[json.loads(x) for x in Path('/private/tmp/cs331-cp2-chrome-first.jsonl').read_text().splitlines()]
> for x in rows: print(x['connection_id'],x['completion_reason'], x['complete_hello_pair'],x['client']['ech']['presence'],x['server']['negotiated_version'])
> print(len(rows))
> PY`
>
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure`
>
> - Ran `../.venv/bin/python - <<'PY'
> import json
> from pathlib import Path
> for row in map(json.loads,Path('/private/tmp/cs331-cp2-chrome-first.jsonl').read_text().splitlines()):
>  if not row['complete_hello_pair']: print(json.dumps(row,indent=2))
> PY
> tshark -r code/pcaps/chrome.pcap -Y 'tcp.stream == 0 and (tcp.len > 0 or tcp.flags.syn == 1)' -T fields -e frame.number -e tcp.seq_raw -e tcp.len -e tcp.flags -e tls.record.content_type -e tls.handshake.type`
>
> </details>
>
> The real Chrome replay exposed a case the synthetic tests missed: a later server segment appears in the capture before the SYN-aligned segment containing ServerHello. Strict gap handling currently leaves that pair incomplete.
>
> I’ll handle this narrowly: wait for the exact SYN-derived start before beginning TLS framing, without reconstructing the earlier out-of-order segment. Gaps after framing starts will still stop that direction and remain incomplete. This should preserve the visible hello without adding general out-of-order recovery.
>
> <details><summary>Edited 5 files, ran 2 commands</summary>
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp` (+2 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp` (+21 -1)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+2 -4)
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp` (+1 -1)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp` (+6 -3)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+10 -8)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/ech_fixtures.hpp` (+26 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/ech_fixtures.hpp` (+1 -0)
> - Ran `cat > 'Phase 2/engine/tests/test_ech_connections.cpp' <<'EOF'
> #include <gtest/gtest.h>
> #include "tlsfp/capture.hpp"
> #include "tlsfp/parser.hpp"
> #include "fixtures/ech_fixtures.hpp"
> #include <arpa/inet.h>
> #include <netinet/tcp.h>
> #include <unistd.h>
> #include <sys/resource.h>
> #include <csignal>
> #include <filesystem>
> #include <fstream>
> #include <iterator>
>
> using namespace tlsfp;
> using namespace ech_fixture;
> namespace {
> FlowKey flow(uint16_t port = 41000) {
>     FlowKey key;
>     inet_pton(AF_INET, "192.0.2.10", &key.src_ip.v4);
>     inet_pton(AF_INET, "198.51.100.20", &key.dst_ip.v4);
>     key.src_port = htons(port); key.dst_port = htons(443);
>     return key;
> }
> FlowKey reverse(FlowKey key) {
>     std::swap(key.src_ip, key.dst_ip); std::swap(key.src_port, key.dst_port); return key;
> }
> std::string unused_path() {
>     std::string path = (std::filesystem::temp_directory_path() / "tlsfp-cp2-XXXXXX").string();
>     int fd = mkstemp(path.data());
>     if (fd < 0) throw std::runtime_error("cannot reserve temporary filename");
>     close(fd); unlink(path.c_str()); return path;
> }
> std::vector<std::string> read_rows(const std::string &path) {
>     std::ifstream input(path); std::vector<std::string> rows; std::string line;
>     while (std::getline(input, line)) rows.push_back(line);
>     return rows;
> }
> class ConnectionTest : public ::testing::Test {
> protected:
>     std::string path;
>     double now{0};
>     std::unique_ptr<CaptureEngine> engine;
>     void SetUp() override { path = unused_path(); create(); }
>     void TearDown() override { engine.reset(); unlink(path.c_str()); }
>     void create(size_t capacity = 1024) {
>         engine.reset(); unlink(path.c_str());
>         CaptureOptions options; options.json_filename = path; options.quiet = true;
>         options.max_connections = capacity; options.monotonic_clock = [this] { return now; };
>         engine = std::make_unique<CaptureEngine>(options);
>     }
>     void send(const Bytes &bytes, bool server_direction = false, uint32_t seq = 100,
>               uint8_t flags = TH_ACK, FlowKey key = flow(), bool truncated = false) {
>         if (server_direction) key = reverse(key);
>         engine->ingest_tcp_segment(key, seq, flags, bytes.data(), bytes.size(),
>                                    static_cast<uint64_t>((now + 1) * 1000000), truncated);
>     }
>     void start(FlowKey key = flow()) {
>         send({}, false, 99, TH_SYN, key); send({}, true, 999, TH_SYN | TH_ACK, key);
>     }
>     std::vector<std::string> rows() { return read_rows(path); }
> };
> }
>
> TEST_F(ConnectionTest, Tls13PairsBothDirectionsAndFlushesImmediately) {
>     start(); send(client()); send(server(), true, 1000);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"negotiated_version\":772"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"acceptance\":\"unverified\""), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"client_endpoint\":\"a\""), std::string::npos);
>     EXPECT_TRUE(engine->finish_capture()); EXPECT_EQ(rows().size(), 1u);
> }
> TEST_F(ConnectionTest, Tls12NonAcceptanceHasI3EvidenceAndUnknownOfferType) {
>     start(); send(client()); send(server(0x0303), true, 1000);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("I3_negotiated_below_tls13"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"acceptance\":\"non_acceptance_observed\""), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"offer_type\":\"unknown\""), std::string::npos);
> }
> TEST_F(ConnectionTest, CompleteAbsenceIsFalseRatherThanNull) {
>     send(client(false)); send(server(), true, 1000);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"presence\":false"), std::string::npos);
> }
> TEST_F(ConnectionTest, ServerOnlyHasUnknownClientAndNoI3) {
>     send(server(0x0303), true, 1000);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"presence\":null"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"complete_hello_pair\":false"), std::string::npos);
>     EXPECT_EQ(rows()[0].find("I3_"), std::string::npos);
> }
> TEST_F(ConnectionTest, RetransmittedHellosAndSynDoNotDuplicateOrReset) {
>     start(); const auto ch = client(); send(ch); send({}, false, 99, TH_SYN); send(ch);
>     send(server(), true, 1000); send(ch); send(server(), true, 1000);
>     EXPECT_TRUE(engine->finish_capture()); EXPECT_EQ(rows().size(), 1u);
>     EXPECT_EQ(engine->stats().client_hellos, 1u); EXPECT_EQ(engine->stats().server_hellos, 1u);
> }
> TEST_F(ConnectionTest, SynWithPayloadConsumesOneSequenceNumber) {
>     send(client(), false, 99, TH_SYN); send(server(), true, 1000);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
> }
> TEST_F(ConnectionTest, NewSynSeparatesConnectionGenerations) {
>     start(); send(client()); send({}, false, 499, TH_SYN);
>     send(client(), false, 500); send(server(), true, 2000);
>     ASSERT_EQ(rows().size(), 2u);
>     EXPECT_NE(rows()[0].find("connection_replaced"), std::string::npos);
>     EXPECT_NE(rows()[1].find("\"complete_hello_pair\":true"), std::string::npos);
> }
> TEST_F(ConnectionTest, SynAfterClosureStartsFreshEvenWithSameInitialSequence) {
>     start(); send(client()); send({}, false, 400, TH_RST);
>     start(); send(client()); send(server(), true, 1000);
>     EXPECT_EQ(rows().size(), 2u);
> }
> TEST_F(ConnectionTest, FinWithPayloadIsProcessedBeforeFinalization) {
>     start(); send(client(), false, 100, TH_FIN | TH_ACK);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"completion_reason\":\"fin\""), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"presence\":true"), std::string::npos);
> }
> TEST_F(ConnectionTest, ResetWithServerPayloadStillEmitsFinalHelloOnce) {
>     send(client()); send(server(), true, 1000, TH_RST | TH_ACK);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("final_server_hello"), std::string::npos);
>     engine->finish_capture(); EXPECT_EQ(rows().size(), 1u);
> }
> TEST_F(ConnectionTest, PureTcpSynAndFinDoNotProduceTlsSummary) {
>     start(); send({}, false, 100, TH_FIN); engine->finish_capture(); EXPECT_TRUE(rows().empty());
> }
> TEST_F(ConnectionTest, CapacityIncludesSynHintsAndEmittedMarkers) {
>     create(1); send(client()); send({}, false, 100, TH_SYN, flow(41001));
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("capacity_limit"), std::string::npos);
>     EXPECT_EQ(engine->retained_connection_count(), 1u);
>     send(client(), false, 101, TH_ACK, flow(41001)); send(server(), true, 1000, TH_ACK, flow(41001));
>     EXPECT_EQ(engine->retained_connection_count(), 1u);
>     send({}, false, 100, TH_SYN, flow(41002));
>     EXPECT_EQ(rows().size(), 2u); EXPECT_EQ(engine->retained_connection_count(), 1u);
> }
> TEST_F(ConnectionTest, IdleTimeoutRunsWithoutAnotherPacket) {
>     send(client()); now = 31; engine->maintenance();
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"completion_reason\":\"timeout\""), std::string::npos);
>     EXPECT_EQ(engine->retained_connection_count(), 0u);
> }
> TEST_F(ConnectionTest, PartialRecordTimeoutKeepsUnknownPresence) {
>     auto ch = client(); ch.resize(40); send(ch); now = 4; engine->maintenance();
>     EXPECT_TRUE(rows().empty()); EXPECT_TRUE(engine->finish_capture());
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("record_timeout"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"presence\":null"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"ja3\":null"), std::string::npos);
> }
> TEST_F(ConnectionTest, ActiveGapStopsParsingWithoutGuessingAnotherBoundary) {
>     auto ch = client(); send(Bytes(ch.begin(), ch.begin()+30));
>     send(ch, false, 200); send(ch, false, 130); engine->finish_capture();
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("tcp_gap"), std::string::npos);
>     EXPECT_EQ(engine->stats().client_hellos, 0u);
> }
> TEST_F(ConnectionTest, SynAlignedHelloCanArriveAfterDetachedServerSegment) {
>     start(); send(client()); send({0xa4,0xb5,0xc6}, true, 4000); send(server(), true, 1000);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("pre_tls_sequence_gap"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
> }
> TEST_F(ConnectionTest, CaptureTruncationStopsDirectionEvenIfPrefixLooksLikeHello) {
>     send(client(), false, 100, TH_ACK, flow(), true); send(client(), false, 100);
>     engine->finish_capture(); ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("capture_truncated"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"presence\":null"), std::string::npos);
>     EXPECT_EQ(engine->stats().client_hellos, 0u);
> }
> TEST_F(ConnectionTest, HrrWaitsForFinalServerAndKeepsOriginalClient) {
>     start(); auto ch = client(); send(ch); const auto retry = server(0x0304, true); send(retry, true, 1000);
>     EXPECT_TRUE(rows().empty());
>     auto second = client(false); send(second, false, 100 + static_cast<uint32_t>(ch.size()));
>     send(server(), true, 1000 + static_cast<uint32_t>(retry.size()));
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"hrr_seen\":true"), std::string::npos);
>     EXPECT_NE(rows()[0].find("hrr_sequence_not_analyzed"), std::string::npos);
>     EXPECT_NE(rows()[0].find("\"presence\":true"), std::string::npos);
>     EXPECT_EQ(engine->stats().server_hellos, 1u);
> }
> TEST_F(ConnectionTest, CompatibilityCcsAndCoalescedServerRecordsAreWalked) {
>     start(); send(client()); Bytes bytes{20,3,3,0,1,1}; const auto sh = server();
>     bytes.insert(bytes.end(), sh.begin(), sh.end()); send(bytes, true, 1000);
>     ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
> }
> TEST_F(ConnectionTest, MultipleHandshakeMessagesWithinRecordAreWalked) {
>     send(client()); auto sh = server();
>     sh.insert(sh.begin()+5, {0,0,0,0}); record_length(sh); send(sh, true, 1000);
>     ASSERT_EQ(rows().size(), 1u); EXPECT_EQ(engine->stats().server_hellos, 1u);
> }
> TEST_F(ConnectionTest, EncryptedRecordPayloadIsNotParsedAsHello) {
>     send(client()); auto sh = server(); sh[0] = 23; send(sh, true, 1000);
>     engine->finish_capture(); ASSERT_EQ(rows().size(), 1u);
>     EXPECT_NE(rows()[0].find("encrypted_record_before_final_hello"), std::string::npos);
>     EXPECT_EQ(engine->stats().server_hellos, 0u);
> }
> TEST_F(ConnectionTest, UnknownCcsContextDoesNotExposeEncryptedHandshakeAsHello) {
>     send(with_ech()); Bytes bytes{20,3,3,0,1,1}; const auto sh = server(0x0303);
>     bytes.insert(bytes.end(),sh.begin(),sh.end()); send(bytes,true,1000); engine->finish_capture();
>     ASSERT_EQ(rows().size(),1u); EXPECT_EQ(engine->stats().server_hellos,0u);
>     EXPECT_NE(rows()[0].find("ccs_plaintext_context_unknown"),std::string::npos);
> }
> TEST_F(ConnectionTest, JsonEscapesPacketStringsAndOwnsTheirBytes) {
>     const Bytes name{'a','"','\\','\n',0xff}; Bytes sni; u16(sni,name.size()+3); sni.push_back(0); u16(sni,name.size());
>     sni.insert(sni.end(),name.begin(),name.end()); Bytes extra; extension(extra,0,sni);
>     auto ch=client(true,extra); send(ch); std::fill(ch.begin(),ch.end(),0); send(server(),true,1000);
>     ASSERT_EQ(rows().size(),1u);
>     EXPECT_NE(rows()[0].find("a\\\"\\\\\\u000a\\u00ff"),std::string::npos);
> }
> TEST_F(ConnectionTest, IncompleteCaptureFlushesExactlyOnceOnInterruption) {
>     auto ch=client(); ch.resize(30); send(ch); EXPECT_TRUE(engine->finish_capture("interrupted"));
>     EXPECT_TRUE(engine->finish_capture("interrupted")); ASSERT_EQ(rows().size(),1u);
>     EXPECT_NE(rows()[0].find("\"completion_reason\":\"interrupted\""),std::string::npos);
>     EXPECT_NE(rows()[0].find("\"presence\":null"),std::string::npos);
> }
> TEST_F(ConnectionTest, EndpointOrientationDoesNotDependOnPortOrAddressOrder) {
>     auto key=flow(); std::swap(key.src_ip,key.dst_ip); key.src_port=htons(443); key.dst_port=htons(32000);
>     send(client(),false,100,TH_ACK,key); send(server(),true,1000,TH_ACK,key);
>     ASSERT_EQ(rows().size(),1u);
>     EXPECT_NE(rows()[0].find("\"client_endpoint\":\"b\""),std::string::npos);
> }
> TEST_F(ConnectionTest, Ipv6CorrelatesReversedEndpoints) {
>     auto key=flow(); key.ip_version=6;
>     inet_pton(AF_INET6,"2001:db8::1",&key.src_ip.v6); inet_pton(AF_INET6,"2001:db8::2",&key.dst_ip.v6);
>     send(client(),false,100,TH_ACK,key); send(server(),true,1000,TH_ACK,key);
>     ASSERT_EQ(rows().size(),1u); EXPECT_NE(rows()[0].find("\"ip_version\":6"),std::string::npos);
> }
> TEST_F(ConnectionTest, ExistingOutputFileIsNotOverwritten) {
>     { std::ofstream out(path); out << "preserve\n"; }
>     CaptureOptions options; options.quiet=true; options.json_filename=path;
>     CaptureEngine other(options); EXPECT_FALSE(other.run());
>     ASSERT_EQ(rows().size(),1u); EXPECT_EQ(rows()[0],"preserve");
> }
> TEST_F(ConnectionTest, OutputWriteFailureMakesCaptureFail) {
>     ASSERT_EXIT({
>         std::signal(SIGXFSZ,SIG_IGN); struct rlimit limit{}; getrlimit(RLIMIT_FSIZE,&limit);
>         limit.rlim_cur=1; if (setrlimit(RLIMIT_FSIZE,&limit)) _exit(2);
>         send(client()); send(server(),true,1000); _exit(engine->finish_capture()?1:0);
>     }, ::testing::ExitedWithCode(0), "JSON output write failed");
> }
>
> TEST(ServerObservationTest, SupportedVersionsMustHaveExactLengthAndNoDuplicate) {
>     Bytes bad; extension(bad,43,{3}); auto record=server(0x0303,false,bad); ServerHelloData out;
>     EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out)); EXPECT_EQ(out.parse_status,ParseStatus::Malformed);
>     bad.clear(); extension(bad,43,{3,4}); record=server(0x0304,false,bad);
>     EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out)); EXPECT_EQ(out.parse_status,ParseStatus::Malformed);
> }
> TEST(ServerObservationTest, TruncationCrossRecordAndContradictoryCompleteFramingDiffer) {
>     auto record=server(); ServerHelloData out; record.pop_back();
>     EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out)); EXPECT_EQ(out.parse_status,ParseStatus::Incomplete);
>     record_length(record); EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out));
>     EXPECT_EQ(out.parse_status,ParseStatus::Unsupported);
>     handshake_length(record); EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out));
>     EXPECT_EQ(out.parse_status,ParseStatus::Malformed);
> }
> TEST(ServerObservationTest, UnknownVersionRemainsNumericAndHrrResetsWithScratchpad) {
>     auto record=server(0x9999,true); ServerHelloData out;
>     ASSERT_TRUE(parse_server_hello(record.data(),record.size(),out)); EXPECT_TRUE(out.is_hrr); EXPECT_EQ(out.selected_version,0x9999);
>     record=server(0x0303); ASSERT_TRUE(parse_server_hello(record.data(),record.size(),out));
>     EXPECT_FALSE(out.is_hrr); EXPECT_EQ(out.selected_version,0x0303);
> }
>
> TEST(RecordStreamTest, CoalescedRecordsAndPartialTailSurviveAllHeaderSplits) {
>     auto first=client(), second=server(); Bytes combined=first; combined.insert(combined.end(),second.begin(),second.end());
>     for (size_t split=1;split<first.size()+5;++split) {
>         SCOPED_TRACE(split); std::vector<Bytes> records;
>         TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t *p,size_t n){ records.emplace_back(p,p+n); });
>         auto key=flow(); accumulator.process_segment(key,100,combined.data(),split,0);
>         accumulator.process_segment(key,100+static_cast<uint32_t>(split),combined.data()+split,combined.size()-split,0);
>         ASSERT_EQ(records.size(),2u); EXPECT_EQ(records[0],first); EXPECT_EQ(records[1],second);
>         EXPECT_EQ(accumulator.active_flow_count(),0u);
>     }
> }
> TEST(RecordStreamTest, SequenceWraparoundAndCompletedRetransmissions) {
>     const auto record=client(); int count=0;
>     TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t*,size_t){++count;}); auto key=flow();
>     accumulator.process_segment(key,0xfffffff0,record.data(),30,0);
>     accumulator.process_segment(key,14,record.data()+30,record.size()-30,0);
>     accumulator.process_segment(key,0xfffffff0,record.data(),record.size(),0); EXPECT_EQ(count,1);
> }
> TEST(RecordStreamTest, InvalidHeaderAndStreamCapacityHaveExplicitOutcomes) {
>     std::vector<ParseStatus> issues;
>     TwoTierAccumulator accumulator([](const FlowKey&,const uint8_t*,size_t){}, {},
>         [&](const FlowKey&,ParseStatus status,const char*,const uint8_t*,size_t){issues.push_back(status);},1);
>     const Bytes invalid{22,4,0,0,0}; accumulator.process_segment(flow(),1,invalid.data(),invalid.size(),0);
>     const auto record=client(); accumulator.process_segment(flow(41001),1,record.data(),record.size(),0);
>     ASSERT_EQ(issues.size(),2u); EXPECT_EQ(issues[0],ParseStatus::Malformed); EXPECT_EQ(issues[1],ParseStatus::Unsupported);
> }
> EOF`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt` (+1 -0)
>
> </details>
>
> The first connection-level tests are in place. They cover I3 evidence, unknown versus absent ECH, SYN reuse, retransmissions, closure with payload, idle expiry, capacity limits, HRR, and output failures.
>
> I’m running those tests now and checking the real captures against checkpoint 1, with count changes reviewed separately from fingerprint changes.
>
> <details><summary>Edited 2 files, explored a file, a search, ran 11 commands</summary>
>
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
>
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure --quiet`
>
> - Ran `../.venv/bin/python - <<'PY'
> import re,subprocess,json,tempfile
> from pathlib import Path
> old='/private/tmp/cs331-cp2-baseline-build/tlsfp_phase2'; new='Phase 2/engine/build/tlsfp_phase2'
> ansi=re.compile(r'\x1b\[[0-9;]*m')
> for name in ['cloudflare_run1','curl','python_requests','custom_client','chrome','chrome_run2','test_ja3']:
>  outs=[]
>  for binary in [old,new]:
>   s=ansi.sub('',subprocess.check_output([binary,'-r',f'code/pcaps/{name}.pcap'],text=True))
>   outs.append([x.strip() for x in s.splitlines() if re.search(r'\b(CLIENT|SERVER)\s|\bJA[34]S?:',x)])
>  print(name,'same=',outs[0]==outs[1],len(outs[0]),len(outs[1]))
>  if outs[0]!=outs[1]: print('missing', sorted(set(outs[0])-set(outs[1]))[:8]); print('extra', sorted(set(outs[1])-set(outs[0]))[:8])
> p=Path(tempfile.mkdtemp())/'chrome.jsonl'; subprocess.run([new,'-q','-r','code/pcaps/chrome.pcap','--json',str(p)],check=True,capture_output=True)
> for x in map(json.loads,p.read_text().splitlines()): print(x['connection_id'],x['complete_hello_pair'],x['completion_reason'],x['transport'])
> PY`
>
> <details><summary>Explored a file, a search</summary>
>
> - Read `./Phase 2/engine/build/Testing/Temporary/LastTestsFailed.log`
> - Searched for `Failure|FAILED|Error|Exception` in `LastTest.log`
>
> </details>
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/generate_ech_fixture.py` (+6 -2)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_connections.cpp` (+3 -1)
>
> - Ran `cat > 'Phase 2/engine/tests/fixtures/generate_ech_connections.py' <<'EOF'
> """Deterministic synthetic TCP/TLS exchanges for checkpoint 2, not endpoint labels."""
> from pathlib import Path
> import struct
> import generate_ech_fixture as wire
>
>
> def client(ech=True, config=139):
>     extensions = wire.extension(43, b"\x04\x03\x04\x03\x03")
>     if ech:
>         extensions += wire.extension(0xfe0d, wire.outer(config=config))
>     return wire.hello(extensions)
>
>
> def server(version=0x0304, hrr=False):
>     random = (bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
>               if hrr else b"\x42" * 32)
>     extensions = wire.extension(43, wire.u16(version)) if version >= 0x0304 else b""
>     body = b"\x03\x03" + random + b"\x00\x13\x01\x00" + wire.u16(len(extensions)) + extensions
>     return wire.record(b"\x02" + len(body).to_bytes(3, "big") + body)
>
>
> def generate():
>     packets = []
>     def send(port, data=b"", seq=100, flags=0x18, reverse=False):
>         packets.append(wire.packet(data, port, seq, flags, reverse))
>     def start(port):
>         send(port, seq=99, flags=0x02)
>         send(port, seq=999, flags=0x12, reverse=True)
>     for port, ech, version in [(41011, True, 0x0303), (41012, True, 0x0304), (41013, False, 0x0304)]:
>         start(port); send(port, client(ech)); send(port, server(version), 1000, reverse=True)
>     start(41014)
>     ch = client()
>     send(41014, ch[:80]); send(41014, ch[50:150], 150); send(41014, ch[150:], 250)
>     send(41014, ch)  # Complete retransmission after record delivery.
>     send(41014, b"\x14\x03\x03\x00\x01\x01" + server(), 1000, reverse=True)
>     start(41015); send(41015, ch[:50]); send(41015, ch[70:], 170)
>     send(41015, server(), 1000, reverse=True)
>     start(41016); send(41016, ch[:40])
>     start(41017); send(41017, ch)
>     retry = server(hrr=True); send(41017, retry, 1000, reverse=True)
>     send(41017, client(config=7), 100 + len(ch))
>     send(41017, server(), 1000 + len(retry), reverse=True)
>     start(41018); send(41018, ch); send(41018, b"\xa4\xb5\xc6", 4000, reverse=True)
>     send(41018, server(), 1000, reverse=True)
>     start(41019); send(41019, ch); send(41019, seq=100 + len(ch), flags=0x11)
>     start(41020); send(41020, ch); send(41020, seq=100 + len(ch), flags=0x14)
>     start(41020); send(41020, client(False)); send(41020, server(), 1000, reverse=True)
>     output = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
>     for index, frame in enumerate(packets):
>         output.extend(struct.pack("<IIII", 1700000000, index * 1000, len(frame), len(frame)))
>         output.extend(frame)
>     target = Path(__file__).with_name("ech_checkpoint2.pcap")
>     target.write_bytes(output)
>     print(f"Wrote {len(packets)} packets to {target}")
>
>
> if __name__ == "__main__":
>     generate()
> EOF
> ../.venv/bin/python 'Phase 2/engine/tests/fixtures/generate_ech_connections.py'`
>
> - Ran `../.venv/bin/python - <<'PY'
> import re,subprocess,collections
> ansi=re.compile(r'\x1b\[[0-9;]*m')
> for binary in ['/private/tmp/cs331-cp2-baseline-build/tlsfp_phase2','Phase 2/engine/build/tlsfp_phase2']:
>  output=ansi.sub('',subprocess.check_output([binary,'-r','code/pcaps/cloudflare_run1.pcap'],text=True))
>  rows=[x.strip() for x in output.splitlines() if re.search(r'\b(CLIENT|SERVER)\s|\bJA[34]S?:',x)]
>  counts=collections.Counter(tuple(rows[i:i+3]) for i in range(0,len(rows),3))
>  print(binary, sum(counts.values()),len(counts))
>  print([(record,count) for record,count in counts.items() if count>1])
> PY`
>
> - Ran `../.venv/bin/python - <<'PY'
> import re,subprocess,collections
> ansi=re.compile(r'\x1b\[[0-9;]*m'); allcounts=[]
> for binary in ['/private/tmp/cs331-cp2-baseline-build/tlsfp_phase2','Phase 2/engine/build/tlsfp_phase2']:
>  s=ansi.sub('',subprocess.check_output([binary,'-r','code/pcaps/cloudflare_run1.pcap'],text=True)); rows=[x.strip() for x in s.splitlines() if re.search(r'\b(CLIENT|SERVER)\s|\bJA[34]S?:',x)]; allcounts.append(collections.Counter(tuple(rows[i:i+3]) for i in range(0,len(rows),3)))
> print('missing',list((allcounts[0]-allcounts[1]).items())); print('extra',list((allcounts[1]-allcounts[0]).items()))
> PY
> tshark -r code/pcaps/cloudflare_run1.pcap -Y 'tls.handshake.type == 1 or tls.handshake.type == 2' -T fields -e frame.number -e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.seq_raw -e tls.handshake.type -e tls.handshake.random`
>
> - Ran `cmake -S 'Phase 2/engine' -B /private/tmp/cs331-cp2-debug-build -DCMAKE_BUILD_TYPE=Debug -DGTest_DIR=/private/tmp/cs331-gtest-sanitized/lib/cmake/GTest`
>
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
>
> - Ran `cmake --build /private/tmp/cs331-cp2-debug-build -j 4`
>
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure -R 'ConnectionTest|ServerObservationTest|RecordStreamTest'`
>
> - Ran `'Phase 2/engine/build/tlsfp_phase2' -q -r 'Phase 2/engine/tests/fixtures/ech_checkpoint2.pcap' --json /private/tmp/cs331-cp2-synthetic-first.jsonl; ../.venv/bin/python - <<'PY'
> import json
> from pathlib import Path
> rows=list(map(json.loads,Path('/private/tmp/cs331-cp2-synthetic-first.jsonl').read_text().splitlines()))
> for r in rows: print(r['connection_id'],r['endpoint_a']['port'],r['endpoint_b']['port'],r['completion_reason'],r['complete_hello_pair'],r['client']['ech']['presence'],r['interpretation']['acceptance'],r['server']['hrr_seen'])
> print(len(rows))
> PY`
>
> </details>
>
> Chrome now produces four paired summaries, and the synthetic capture produces the expected I3, HRR, closure, and incomplete cases.
>
> The baseline comparison found an expected count change in `cloudflare_run1.pcap`: checkpoint 1 printed three HRRs as ServerHello fingerprints. Those are now recognized as retries and excluded from final-server output. I’m recording that distinction in the validation notes.
>
> <details><summary>Edited 5 files, ran 10 commands</summary>
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/ech_analysis.hpp` (+5 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+18 -8)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/ech_analysis.cpp` (+6 -0)
> - Ran `cat >> 'Phase 2/engine/tests/test_ech_connections.cpp' <<'EOF'
>
> TEST_F(ConnectionTest, InvalidCompatibilityCcsDoesNotHideItsFramingError) {
>     send(client()); send({20,3,3,0,1,2},true,1000); engine->finish_capture();
>     ASSERT_EQ(rows().size(),1u); EXPECT_NE(rows()[0].find("invalid_change_cipher_spec"),std::string::npos);
> }
> TEST_F(ConnectionTest, MalformedServerVersionNeverSuppliesI3Evidence) {
>     send(client()); Bytes extra; extension(extra,43,{3}); send(server(0x0303,false,extra),true,1000);
>     engine->finish_capture(); ASSERT_EQ(rows().size(),1u);
>     EXPECT_NE(rows()[0].find("\"negotiated_version\":null"),std::string::npos);
>     EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
> }
> TEST_F(ConnectionTest, UnknownNegotiatedVersionAbstains) {
>     send(client()); send(server(0x9999),true,1000);
>     ASSERT_EQ(rows().size(),1u); EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
>     EXPECT_NE(rows()[0].find("\"negotiated_version\":39321"),std::string::npos);
> }
> TEST_F(ConnectionTest, MissingOutputDirectoryFailsBeforeCapture) {
>     CaptureOptions options; options.quiet=true; options.json_filename=path+"/missing/result.jsonl";
>     CaptureEngine other(options); EXPECT_FALSE(other.run());
> }
> TEST(RecordStreamTest, CompletedPrefixOverlapCanDeliverNextRecordWithoutRepeatingFirst) {
>     const auto first=client(), second=server(); int count=0;
>     TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t*,size_t){++count;});
>     accumulator.process_segment(flow(),100,first.data(),first.size(),0);
>     Bytes overlap(first.end()-10,first.end()); overlap.insert(overlap.end(),second.begin(),second.end());
>     accumulator.process_segment(flow(),static_cast<uint32_t>(100+first.size()-10),overlap.data(),overlap.size(),0);
>     EXPECT_EQ(count,2);
> }
> TEST(RecordStreamTest, MissingSynAlignedStartTimesOutWithoutResynchronizing) {
>     int records=0; std::vector<std::string> issues;
>     TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t*,size_t){++records;},{},
>         [&](const FlowKey&,ParseStatus,const char *reason,const uint8_t*,size_t){issues.emplace_back(reason);});
>     accumulator.start_flow(flow(),100,0); const auto record=client();
>     accumulator.process_segment(flow(),200,record.data(),record.size(),0);
>     accumulator.cleanup_stale_flows(4); accumulator.process_segment(flow(),100,record.data(),record.size(),4);
>     EXPECT_EQ(records,0); ASSERT_EQ(issues.size(),2u); EXPECT_EQ(issues.back(),"initial_data_timeout");
> }
> TEST(ConnectionReplayTest, SyntheticPcapProducesElevenIndependentSummaries) {
>     const auto path=unused_path(); CaptureOptions options; options.quiet=true; options.json_filename=path;
>     options.read_filename=std::string(TLSFP_FIXTURES_DIR)+"/ech_checkpoint2.pcap";
>     CaptureEngine engine(options); EXPECT_TRUE(engine.run()); const auto rows=read_rows(path); unlink(path.c_str());
>     ASSERT_EQ(rows.size(),11u);
>     EXPECT_EQ(std::count_if(rows.begin(),rows.end(),[](const auto &row){return row.find("I3_negotiated_below_tls13")!=std::string::npos;}),1);
>     EXPECT_EQ(std::count_if(rows.begin(),rows.end(),[](const auto &row){return row.find("\"complete_hello_pair\":true")!=std::string::npos;}),7);
> }
> TEST(ConnectionReplayTest, PcapReadErrorFlushesPendingObservationsAndFails) {
>     const auto input_path=unused_path(), output_path=unused_path();
>     {
>         std::ifstream input(std::string(TLSFP_FIXTURES_DIR)+"/ech_checkpoint1.pcap",std::ios::binary);
>         std::ofstream output(input_path,std::ios::binary); output << input.rdbuf();
>         const uint32_t header[4]{1700000001,0,100,100};
>         output.write(reinterpret_cast<const char*>(header),sizeof(header)); output.put('x');
>     }
>     CaptureOptions options; options.quiet=true; options.read_filename=input_path; options.json_filename=output_path;
>     CaptureEngine engine(options); EXPECT_FALSE(engine.run()); const auto rows=read_rows(output_path);
>     unlink(input_path.c_str()); unlink(output_path.c_str()); ASSERT_FALSE(rows.empty());
>     for (const auto &row:rows) EXPECT_NE(row.find("\"completion_reason\":\"capture_error\""),std::string::npos);
> }
> EOF`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_analysis.cpp` (+12 -0)
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
> - Ran `cmake --build /private/tmp/cs331-cp2-debug-build -j 4`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp` (+1 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+4 -2)
> - Ran `'Phase 2/engine/build/unit_tests' --gtest_filter='ConnectionReplayTest.*'`
> - Ran `git diff --check; git status --short; git diff --stat`
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+1 -2)
> - Ran `../.venv/bin/python - <<'PY'
> import hashlib,subprocess
> from pathlib import Path
> for name,script in [('ech_checkpoint1.pcap','generate_ech_fixture.py'),('ech_checkpoint2.pcap','generate_ech_connections.py')]:
>  p=Path('Phase 2/engine/tests/fixtures')/name
>  before=hashlib.sha256(p.read_bytes()).hexdigest()
>  subprocess.run(['../.venv/bin/python',str(p.with_name(script))],check=True,capture_output=True)
>  assert hashlib.sha256(p.read_bytes()).hexdigest()==before
>  print(name, before)
> PY`
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
> - Ran `cmake --build /private/tmp/cs331-cp2-debug-build -j 4`
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure`
> - Ran `ctest --test-dir /private/tmp/cs331-cp2-debug-build --output-on-failure`
>
> </details>
>
> All 119 tests pass in both Release and the sanitizer build, including the capture-read and output-write failure tests.
>
> I’m finishing the JSON review and manual guide. The guide will call out the narrow SYN-aligned-start handling and the HRR-related count change, alongside the replay commands and expected results.
>
> <details><summary>Edited 4 files, explored a file, ran 19 commands</summary>
>
> <details><summary>Explored 4 files</summary>
>
> - Read `./Phase 2/engine/src/capture.cpp`
> - Read `./Phase 2/engine/src/capture.cpp`
> - Read `./Phase 2/engine/src/capture.cpp`
> - Read `./Phase 2/engine/src/capture.cpp`
>
> </details>
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+25 -3)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/main.cpp` (+4 -0)
>
> - Ran `cat >> 'Phase 2/engine/tests/test_ech_connections.cpp' <<'EOF'
> TEST_F(ConnectionTest, ConflictingRolesRemainUnknownAndSuppressI3) {
>     start(); send(client(),true,1000); send(server(0x0303),false,100);
>     ASSERT_EQ(rows().size(),1u); EXPECT_NE(rows()[0].find("\"client_endpoint\":null"),std::string::npos);
>     EXPECT_NE(rows()[0].find("conflicting_endpoint_roles"),std::string::npos);
>     EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
> }
> TEST_F(ConnectionTest, UnexpectedSecondClientWithoutHrrSuppressesI3) {
>     const auto first=client(); send(first); send(client(false),false,100+static_cast<uint32_t>(first.size()));
>     send(server(0x0303),true,1000); ASSERT_EQ(rows().size(),1u);
>     EXPECT_NE(rows()[0].find("unexpected_additional_client_hello"),std::string::npos);
>     EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
> }
> TEST_F(ConnectionTest, ValidUtf8SurvivesJsonSerialization) {
>     const Bytes name{'t',0xc3,0xa9,'s','t'}; Bytes sni; u16(sni,name.size()+3); sni.push_back(0); u16(sni,name.size());
>     sni.insert(sni.end(),name.begin(),name.end()); Bytes extra; extension(extra,0,sni);
>     send(client(true,extra)); send(server(),true,1000); ASSERT_EQ(rows().size(),1u);
>     EXPECT_NE(rows()[0].find(std::string(name.begin(),name.end())),std::string::npos);
> }
> EOF`
>
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
>
> - Ran `cmake --build /private/tmp/cs331-cp2-debug-build -j 4`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/capture.hpp` (+2 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+1 -1)
>
> - Ran ````cat > 'Phase 2/docs/ECH_Checkpoint_2_Testing.md' <<'EOF'
> # ECH checkpoint 2: correlate and summarize
>
> Checkpoint 2 joins the first ClientHello with its final ServerHello and writes
> one JSON object per tracked TLS connection generation. The terminal view remains
> available alongside the file. A complete hello pair does not establish successful
> TLS completion, real ECH, or acceptance.
>
> ## Build and manual replay
>
> From the `TLS-Fingerprinting` repository root:
>
> ```sh
> cmake -S 'Phase 2/engine' -B 'Phase 2/engine/build' -DCMAKE_BUILD_TYPE=Release
> cmake --build 'Phase 2/engine/build' -j 4
> ctest --test-dir 'Phase 2/engine/build' --output-on-failure
>
> 'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/chrome.pcap -v --json /tmp/ech-chrome-cp2.jsonl
> 'Phase 2/engine/build/tlsfp_phase2' -r code/pcaps/curl.pcap -v --json /tmp/ech-curl-cp2.jsonl
> 'Phase 2/engine/build/tlsfp_phase2' -r 'Phase 2/engine/tests/fixtures/ech_checkpoint2.pcap' -v --json /tmp/ech-synthetic-cp2.jsonl
> ```
>
> Choose unused output filenames: `--json` creates a new file and refuses to
> replace existing files. `-q` suppresses the detailed terminal view while retaining
> explicitly requested JSON output; the existing benchmark footer still appears.
> Open failures stop capture, and write failures make the command exit unsuccessfully.
> Each completed line is written immediately. A failed write can leave a partial
> last line; preserve the failure status when consuming such a file.
>
> To pretty-print a replay with the existing project environment:
>
> ```sh
> ../.venv/bin/python -m json.tool --json-lines /tmp/ech-chrome-cp2.jsonl
> ```
>
> No Python is required for the binary, fixture replay, or C++ tests. Use an existing
> `.venv` for optional inspection/regeneration; do not substitute global Python.
>
> ### 1. Saved Chrome capture
>
> Expect **four summaries**, each with `completion_reason: "final_server_hello"`,
> `complete_hello_pair: true`, and negotiated version **772 / 0x0304 / TLS 1.3**.
> All retain `offer_type: "unknown"` and `acceptance: "unverified"`.
>
> For TCP client port **51984**, the ClientHello outer random is:
>
> ```text
> 602711cb9199d65800d3f5af27bfc8d6369cf49af0ebe316d67cdf6f80fee6cd
> ```
>
> Its ECH envelope remains KDF 1, AEAD 1, config ID 139, `enc_length` 32 and
> `ciphertext_length` 208. Compare frame 6's ClientHello and frame 14's ServerHello
> in Wireshark; both belong to TCP stream 0. The other configuration IDs are 143,
> 178 and 140, correlated by their endpoint tuples rather than packet adjacency.
>
> This capture contains an important limit demonstration: frame 12 is a later
> server TCP segment captured before the SYN-aligned server prefix in frame 14.
> The engine records `pre_tls_sequence_gap` as incomplete transport evidence and
> waits for the exact SYN-derived sequence number before choosing a TLS boundary.
> Frame 14 contains the whole ServerHello, so the hello pair is complete even
> though a transport gap was observed. No detached bytes are reordered or guessed.
> If that hello needed discarded bytes, it would remain incomplete.
>
> ### 2. Saved curl capture
>
> Expect **one complete paired summary**, with `client.ech.presence: false`.
> Absence follows complete ClientHello extension traversal. A missing or partial
> ClientHello instead has `presence: null` and no partial client fingerprints.
>
> ### 3. Synthetic exchanges
>
> The checked-in 50-packet fixture produces **11 summaries**, seven with complete
> hello pairs. Synthetic packets establish rule behavior, not endpoint labels or
> real-world ECH acceptance. Source ports identify these cases:
>
> | Client port | Expected observation |
> |---|---|
> | 41011 | ECH present + TLS 1.2: `non_acceptance_observed`, evidence `I3_negotiated_below_tls13` |
> | 41012 | ECH present + TLS 1.3: acceptance remains `unverified` |
> | 41013 | Complete ECH absence, paired with TLS 1.3 |
> | 41014 | Segmented hello, overlap, complete retransmission, then CCS + ServerHello: one paired summary |
> | 41015 | Gap inside unfinished ClientHello: incomplete client, unknown presence, complete server; no I3 |
> | 41016 | Unfinished record at EOF: `end_of_capture`, incomplete client and unknown presence |
> | 41017 | HRR and second ClientHello: wait for final server; keep CH1 config ID 139 rather than CH2 ID 7 |
> | 41018 | Detached server bytes precede the exact SYN-aligned hello: paired hello with transport gap noted |
> | 41019 | Complete client followed by FIN: one unpaired summary with reason `fin` |
> | 41020 | RST followed by a fresh SYN using the same tuple/ISN: two separate generations |
>
> The HRR case sets `server.hrr_seen: true` and the limitation
> `hrr_sequence_not_analyzed`. It performs no I1/I2 inference. The EOF summary may
> appear after higher connection IDs because output follows completion order.
> Connection IDs also count SYN-only tracking; they need not be contiguous in JSON.
>
> To regenerate the fixture deterministically:
>
> ```sh
> ../.venv/bin/python 'Phase 2/engine/tests/fixtures/generate_ech_connections.py'
> ```
>
> The checkpoint-1 fixture generator now accepts optional packet direction/flags;
> its defaults regenerate the original checkpoint-1 PCAP byte for byte.
>
> ## JSON contract and interpretation
>
> `schema_version` is 1. Every line has:
>
> | Group | Fields and meaning |
> |---|---|
> | Identity | `capture_id`, `connection_id`, `capture_source`; capture ID is generated once per engine instance |
> | Endpoints | `ip_version`, canonical `endpoint_a`/`endpoint_b`, and `client_endpoint` (`a`, `b`, or null) |
> | Time/lifecycle | Unix microsecond `first_observation_us`/`last_observation_us`, `completion_reason`, `complete_hello_pair` |
> | Client | Detailed framing status, owned outer random/SNI/ALPN, ECH presence/findings/occurrences, JA3/JA4 |
> | Server | Detailed status, negotiated version, HRR-seen flag, final JA3S/JA4S |
> | Interpretation | Unknown offer type, acceptance assessment, and named evidence |
> | Limits | Analysis limitations and per-direction transport issues, each with its own status/reason |
>
> Unknown values are JSON null, including missing numeric fields. Decoded zero
> values remain numbers. Strings escape controls and invalid UTF-8 bytes while
> preserving valid UTF-8. No ciphertext, keylog material, decrypted inner fields,
> or independent experiment labels enter the summary.
>
> Server version comes from an exactly two-byte, non-duplicate `supported_versions`
> extension where present; otherwise it comes from the legacy version. Complete
> contradictory server framing is malformed and supplies no server fingerprint or
> negotiated-version evidence. Recognized TLS 1.0/1.1/1.2 negotiation after observed
> ECH supplies I3 negative evidence; TLS 1.3 alone cannot establish acceptance.
> See [RFC 9849 §6.1.4](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4).
>
> Conflicting endpoint roles remain unknown. Unexpected additional ClientHellos
> without HRR are flagged, and their acceptance interpretation abstains. A genuine
> second ClientHello after a recognized HRR can appear in terminal fingerprint
> output, but the connection summary deliberately retains CH1.
>
> Immediate verbose ClientHello output still says acceptance is unverified: the
> server has not yet supplied evidence. Read the later `[Connection summary]` line
> or JSON `interpretation` for the correlated result.
>
> ## Supported transport and lifecycle limits
>
> - Contiguous segments, overlaps, retransmissions after delivery, split headers,
>   coalesced records and complete messages within one record are supported.
> - Gaps after TLS framing starts stop that direction. Before framing starts, only
>   the exact observed-SYN-derived prefix may anchor it; there is no reorder queue
>   or general out-of-order recovery. The detached-prefix wait also expires.
> - Hello messages spanning records and records above 8192 bytes including their
>   headers are unsupported. Encrypted application records are not decoded as
>   hellos. Compatibility CCS is validated and skipped in TLS-1.3-capable context;
>   unknown CCS context ends plaintext inspection conservatively.
> - The default cap is 1024 connection generations, including SYN hints and emitted
>   completion markers. Buffers allocate only for partial records. Incomplete
>   records expire after the existing three-second timeout; connection idle expiry
>   is 30 seconds. Capacity eviction records `capacity_limit` for an unfinished TLS
>   candidate. Non-TLS SYN-only entries produce no TLS summary.
> - SYN retransmission preserves the current generation. A new ISN or SYN after
>   closure starts another generation. FIN/RST payload is processed before closure.
> - Summaries emit at final ServerHello, or at closure, replacement, expiry,
>   eviction, EOF, interruption or capture error. Completed observations/buffers are
>   released; only small lifecycle/sequence state remains until closure or expiry.
> - The one-summary guarantee applies to a retained generation. Once its bounded
>   state expires or is evicted, later traffic cannot always be linked to it.
> - Offline expiry follows a nondecreasing packet-time watermark. Live capture uses
>   nonblocking dispatch with 100 ms idle polling and periodic maintenance, even
>   when no packet arrives. Idle expiry is tested with an injected monotonic clock;
>   no live-interface validation is claimed by the offline tests.
>
> ## Implementation interfaces
>
> `CaptureOptions` adds `json_filename`, `max_connections`,
> `connection_timeout_seconds`, and optional `monotonic_clock` injection.
> `CaptureEngine` exposes `ingest_tcp_segment`, `maintenance`, `finish_capture`, and
> `retained_connection_count` for embedding and deterministic tests. These APIs
> share the capture thread; `stop()` is the cross-thread stop request.
>
> The accumulator retains compatible ready/limit callbacks, adds a structured issue
> callback, and exposes directional start/stop/forget/invalidation operations.
> `active_flow_count()` continues to mean unfinished buffers, not sequence markers.
> ServerHello parsing keeps its boolean interface and adds detailed status, owned
> random, and HRR metadata. I3 logic lives in the existing ECH analysis module.
> Connection records/serialization remain in the existing capture implementation.
>
> Endpoint labeling, measurements, QUIC, cross-record assembly, and positive HRR
> acceptance inference remain outside checkpoint 2.
> EOF````
>
> - Ran `cmake --build /private/tmp/cs331-cp2-debug-build -j 4`
>
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
>
> - Ran `cat > /private/tmp/cs331-verify-cp2.py <<'PY'
> import collections
> import json
> import re
> import shutil
> import subprocess
> import tempfile
> from pathlib import Path
>
> root = Path.cwd()
> old = Path('/private/tmp/cs331-cp2-baseline-build/tlsfp_phase2')
> release = root / 'Phase 2/engine/build/tlsfp_phase2'
> debug = Path('/private/tmp/cs331-cp2-debug-build/tlsfp_phase2')
> output_dir = Path(tempfile.mkdtemp(prefix='tlsfp-cp2-verification-'))
> ansi = re.compile(r'\x1b\[[0-9;]*m')
>
> def run(binary, source, destination=None):
>     arguments = [str(binary), '-r', str(source)]
>     if destination:
>         arguments += ['--json', str(destination)]
>     result = subprocess.run(arguments, check=True, text=True, capture_output=True)
>     assert not result.stderr, result.stderr
>     lines = [line.strip() for line in ansi.sub('', result.stdout).splitlines()
>              if re.search(r'\b(CLIENT|SERVER)\s|\bJA[34]S?:', line)]
>     assert len(lines) % 3 == 0
>     return [tuple(lines[i:i+3]) for i in range(0, len(lines), 3)]
>
> def load_rows(path):
>     rows = [json.loads(line) for line in path.read_text().splitlines()]
>     assert len({(row['capture_id'], row['connection_id']) for row in rows}) == len(rows)
>     for row in rows:
>         assert row['schema_version'] == 1
>         assert row['interpretation']['offer_type'] == 'unknown'
>         assert row['interpretation']['acceptance'] in ['unverified', 'non_acceptance_observed']
>         if row['client']['ech']['presence'] is False:
>             assert row['client']['status'] == 'complete'
>         if row['client']['status'] != 'complete':
>             assert row['client']['ja3'] is None and row['client']['ja4'] is None
>         if row['server']['status'] != 'complete':
>             assert row['server']['negotiated_version'] is None and row['server']['ja3s'] is None
>     return rows
>
> cloudflare = root / 'code/pcaps/cloudflare_run1.pcap'
> hellos = subprocess.check_output(['tshark', '-r', str(cloudflare), '-Y', 'tls.handshake.type == 2',
>                                  '-T', 'fields', '-e', 'frame.number', '-e', 'tls.handshake.random'], text=True)
> sentinel = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'
> frames = [line.split('\t')[0] for line in hellos.splitlines() if sentinel in line]
> assert frames == ['47', '293', '848'], frames
> subset = output_dir / 'hrr-only.pcapng'
> subprocess.run(['tshark', '-r', str(cloudflare), '-Y', ' || '.join('frame.number == '+n for n in frames),
>                 '-w', str(subset)], check=True, capture_output=True)
> hrr_records = collections.Counter(run(old, subset))
> assert sum(hrr_records.values()) == 3
> report = []
> for name in ['cloudflare_run1','curl','python_requests','custom_client','chrome','chrome_run2','test_ja3']:
>     source = root / f'code/pcaps/{name}.pcap'
>     old_records = run(old, source)
>     new_records = run(release, source, output_dir / f'{name}-release.jsonl')
>     debug_records = run(debug, source, output_dir / f'{name}-debug.jsonl')
>     assert new_records == debug_records
>     if name == 'cloudflare_run1':
>         assert collections.Counter(old_records) == collections.Counter(new_records) + hrr_records
>     else:
>         assert old_records == new_records
>     rows = load_rows(output_dir / f'{name}-release.jsonl')
>     sanitized_rows = load_rows(output_dir / f'{name}-debug.jsonl')
>     for row in rows + sanitized_rows:
>         row['capture_id'] = 'normalized'
>     assert rows == sanitized_rows
>     if name == 'chrome':
>         assert len(rows) == 4 and all(row['complete_hello_pair'] for row in rows)
>         assert all(row['server']['negotiated_version'] == 772 for row in rows)
>         first = next(row for row in rows if row['client']['ech']['occurrences'][0]['config_id'] == 139)
>         assert first['client']['ech']['occurrences'][0]['enc_length'] == 32
>         assert first['client']['ech']['occurrences'][0]['ciphertext_length'] == 208
>     if name == 'curl':
>         assert len(rows) == 1 and rows[0]['complete_hello_pair'] and rows[0]['client']['ech']['presence'] is False
>     report.append({'pcap':name+'.pcap', 'before_fingerprint_values':len(old_records)*2,
>                    'after_fingerprint_values':len(new_records)*2,
>                    'summaries':len(rows), 'complete_pairs':sum(row['complete_hello_pair'] for row in rows)})
>
> source = root / 'Phase 2/engine/tests/fixtures/ech_checkpoint2.pcap'
> for binary, mode in [(release, 'release'), (debug, 'debug')]:
>     destination = output_dir / f'synthetic-{mode}.jsonl'
>     run(binary, source, destination)
>     rows = load_rows(destination)
>     assert len(rows) == 11 and sum(row['complete_hello_pair'] for row in rows) == 7
>     assert sum(row['interpretation']['acceptance'] == 'non_acceptance_observed' for row in rows) == 1
>     assert sum(row['server']['hrr_seen'] for row in rows) == 1
>
> unicode_source = output_dir / 'हिंदी-curl.pcap'
> shutil.copyfile(root / 'code/pcaps/curl.pcap', unicode_source)
> run(release, unicode_source, output_dir / 'unicode-source.jsonl')
> assert load_rows(output_dir / 'unicode-source.jsonl')[0]['capture_source'] == str(unicode_source)
> empty = subprocess.run([str(release), '-r', str(source), '--json', ''], capture_output=True)
> assert empty.returncode == 1
> existing = output_dir / 'synthetic-release.jsonl'
> before = existing.read_bytes()
> refusal = subprocess.run([str(release), '-r', str(source), '--json', str(existing)], capture_output=True)
> assert refusal.returncode == 1 and existing.read_bytes() == before
> (output_dir / 'verification.json').write_text(json.dumps(report, indent=2))
> print(json.dumps(report, indent=2))
> print('All JSON parsed, one summary per generation, release/debug parity verified, CLI failure checks passed.')
> print('Artifacts:', output_dir)
> PY`
>
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure`
>
> - Ran `../.venv/bin/python /private/tmp/cs331-verify-cp2.py`
>
> - Ran `ctest --test-dir /private/tmp/cs331-cp2-debug-build --output-on-failure`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+8 -1)
>
> - Ran `cat >> 'Phase 2/engine/tests/test_ech_connections.cpp' <<'EOF'
> TEST_F(ConnectionTest, Tls13OfferAloneDoesNotMakeUnknownCcsPlaintext) {
>     send(client()); Bytes bytes{20,3,3,0,1,1}; const auto encoded=server(0x0303);
>     bytes.insert(bytes.end(),encoded.begin(),encoded.end()); send(bytes,true,1000); engine->finish_capture();
>     ASSERT_EQ(rows().size(),1u); EXPECT_EQ(engine->stats().server_hellos,0u);
>     EXPECT_NE(rows()[0].find("ccs_plaintext_context_unknown"),std::string::npos);
> }
> EOF`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/docs/ECH_Checkpoint_2_Testing.md` (+4 -2)
>
> - Ran `cmake --build /private/tmp/cs331-cp2-debug-build -j 4`
>
> - Ran `cmake --build 'Phase 2/engine/build' -j 4`
>
> - Ran `ctest --test-dir 'Phase 2/engine/build' --output-on-failure`
>
> - Ran `../.venv/bin/python /private/tmp/cs331-verify-cp2.py`
>
> - Ran `ctest --test-dir /private/tmp/cs331-cp2-debug-build --output-on-failure`
>
> - Ran ````cat >> 'Phase 2/docs/ECH_Checkpoint_2_Testing.md' <<'EOF'
>
> ## Validation record — November 1, 2026
>
> All **123 tests pass** in Release and ASan/UBSan Debug, including all 76
> checkpoint-1 tests and 47 new checks. Idle expiry uses an injected clock; output
> failure is exercised with a real file-size limit in a child process. A truncated
> PCAP verifies capture-error finalization. Both synthetic generators reproduce
> their checked-in PCAPs byte for byte.
>
> The baseline was built separately from clean checkpoint-1 commit `ea68a83`.
> Replay comparisons checked ordered endpoint/fingerprint observations. All
> non-HRR fingerprint values match. JSON from Release and Debug was parsed with an
> independent JSON reader and compared after normalizing the generated capture ID.
> The same checks verified nulls, unique connection IDs, evidence abstention, source
> paths containing Unicode, and refusal to replace an existing output file.
>
> | Capture | CP1 fingerprint values | CP2 fingerprint values | Summaries | Complete hello pairs |
> |---|---:|---:|---:|---:|
> | cloudflare_run1.pcap | 44 | 38 | 29 | 8 |
> | curl.pcap | 4 | 4 | 1 | 1 |
> | python_requests.pcap | 4 | 4 | 1 | 1 |
> | custom_client.pcap | 4 | 4 | 1 | 1 |
> | chrome.pcap | 16 | 16 | 4 | 4 |
> | chrome_run2.pcap | 12 | 12 | 3 | 3 |
> | test_ja3.pcap | 12 | 12 | 3 | 3 |
> | **Total** | **96** | **90** | **42** | **21** |
>
> The Cloudflare count change is intentional: frames **47, 293 and 848** contain
> the fixed HRR random. They previously produced six server fingerprint values
> as if they were ordinary ServerHellos. An independent Wireshark/TShark extraction
> of those frames accounts exactly for the removed observations. Final ServerHello
> fingerprints are unchanged. The real retry ClientHello messages still retain
> normal per-message terminal fingerprints.
>
> Cloudflare also contains 21 unpaired TLS candidates. They remain visible in the
> JSON rather than being counted as ECH absence, real-offer rejection, or acceptance.
> This distinction separates capture coverage from the fingerprint regression check.
> The 50-packet synthetic corpus separately yields 11 summaries, seven complete
> pairs, one I3 observation, and one HRR sequence marked as unanalyzed.
>
> The local sanitizer build uses the matching sanitized GoogleTest installation
> prepared during checkpoint 1:
>
> ```sh
> cmake -S 'Phase 2/engine' -B /private/tmp/cs331-cp2-debug-build \
>   -DCMAKE_BUILD_TYPE=Debug \
>   -DGTest_DIR=/private/tmp/cs331-gtest-sanitized/lib/cmake/GTest
> cmake --build /private/tmp/cs331-cp2-debug-build -j 4
> ctest --test-dir /private/tmp/cs331-cp2-debug-build --output-on-failure
> ```
>
> This validation establishes supported parsing, correlation, output behavior and
> regression parity on these inputs. It establishes no ECH acceptance labels,
> classification accuracy, general TCP reconstruction result, or live-capture result.
> EOF````
>
> - Ran ``cat <<'EOF' >> '/Users/pranjal/Projects/CS 331 CN 2026/.agents/CONTEXT.md'
>
> ## 8. Phase 2 ECH Checkpoint 2 — November 1, 2026
>
> - Implemented checkpoint 2 on `TLS-Fingerprinting` branch `feature/ech`, against clean checkpoint-1 baseline `ea68a83`. Stop for user manual testing; checkpoint 3 (independent labels and measurements) is not started. Changes remain uncommitted at handoff.
> - Added `--json <file>` alongside terminal output, including with `-q`. Output uses exclusive creation, one flushed JSON line per tracked TLS connection generation, versioned identity/tuple/timestamp fields, client and final-server observations/fingerprints, interpretation, and independent transport issues. Unknown values are null; valid UTF-8 is preserved and invalid/control bytes are escaped. Open/write failures fail the run. No secrets, ciphertext, inner fields or experimental labels enter output.
> - Kept connection state and serialization in existing `capture.cpp`; no new flow/output/framing modules. Records own outer random/SNI/ALPN and ECH metadata. Default capacity is 1024 retained generations including SYN hints and emitted markers; idle expiry is 30 seconds, partial-record expiry remains 3 seconds. SYN retransmissions preserve state; new ISNs or SYN after closure start fresh generations. FIN/RST payload is processed before closure. Final ServerHello, closure, replacement, capacity eviction, timeout, EOF, interruption and capture errors finalize observations. Emitted records release observations/buffers, retaining small completion/sequence state until expiry/closure.
> - Reworked the existing accumulator to walk coalesced records, preserve partial tails, trim overlaps and suppress retransmissions after delivery. It retains compatible ready/limit callbacks and adds explicit issue/start/stop/forget APIs; active_flow_count still counts unfinished buffers. Gaps during framing stop the direction. Cross-record hellos and records above 8192 bytes remain unsupported. Protected records and ambiguous CCS contexts are not decoded as plaintext hellos.
> - A narrowly bounded real-capture adjustment was necessary: Chrome frame 12 contains detached later server data before the SYN-aligned ServerHello in frame 14. Before TLS framing starts, the engine may wait for the exact SYN-derived prefix while recording pre_tls_sequence_gap. It keeps no reorder queue and reconstructs no discarded bytes. Both full hellos can therefore be observed while transport remains incomplete; a hello needing discarded bytes stays incomplete. General out-of-order recovery remains deferred.
> - ServerHello parsing now has detailed status, owned random, strict extension framing and supported_versions length/duplicate checks, and HRR recognition. HRR never finalizes the connection or masquerades as final-server fingerprints. CH1 remains the summary baseline across retries; HRR sequence analysis stays unsupported and I1/I2 remain optional. I3 logic lives in ech_analysis: complete consistent ECH-present pairs with recognized TLS 1.0/1.1/1.2 negotiation yield non_acceptance_observed; TLS 1.3 alone remains unverified, offer type remains unknown, and conflicting roles/unexpected extra hellos abstain.
> - Added `Phase 2/docs/ECH_Checkpoint_2_Testing.md`, connection/record/parser/replay tests, and deterministic `engine/tests/fixtures/ech_checkpoint2.pcap` plus generator. Public CaptureEngine TCP ingestion/maintenance/finalization APIs and an injected monotonic clock support deterministic tests. Live dispatch is nonblocking with 100 ms idle maintenance; no live interface test was performed.
> - Validation: all 123 tests pass in Release and ASan/UBSan Debug (the original 76 plus 47 new). Both generators reproduce their PCAPs byte for byte. Seven saved captures preserve all 90 non-HRR fingerprint values; six captures have exact old output parity. Cloudflare changes from 44 to 38 values because three real HRRs (frames 47/293/848, independently extracted with TShark) no longer emit six ordinary server fingerprint values. This is intentional semantic cleanup, not a fingerprint hash change.
> - JSON from Release and sanitized Debug was independently parsed and matched after capture-ID normalization. Across seven captures: 42 summaries, 21 complete pairs; Cloudflare contributes 29 summaries with 8 complete pairs and 21 unpaired candidates retained explicitly. Chrome yields four complete pairs (known config 139, enc 32, ciphertext 208 preserved); curl yields one complete ECH-absent pair. The 50-packet synthetic fixture yields 11 summaries, seven complete pairs, one I3 observation and one explicitly unanalyzed HRR sequence. These are parsing/correlation results, not acceptance ground truth or classification accuracy.
> - Local sanitizer build: `/private/tmp/cs331-cp2-debug-build`, using compatible sanitized GTest at `/private/tmp/cs331-gtest-sanitized/lib/cmake/GTest`. Release binary is `TLS-Fingerprinting/Phase 2/engine/build/tlsfp_phase2`. The checkpoint-2 testing guide records replay commands, schema, boundaries and regression-count explanations.
> EOF``
>
> - Ran `git diff --check; git status --short --branch; git diff --stat; git log -1 --oneline; tail -8 '../.agents/CONTEXT.md'`
>
> </details>
</details>

Implemented checkpoint 2 on `feature/ech`. `--json <file>` now writes correlated connection summaries alongside terminal output.

- **123 tests pass** in Release and ASan/UBSan.
- All **90 non-HRR fingerprint values** match checkpoint 1.
- Chrome produces four paired summaries; curl produces one ECH-absent pair.
- Three HRRs are now correctly excluded from final-server fingerprint output.

The [manual testing guide](<./TLS-Fingerprinting/Phase 2/docs/ECH_Checkpoint_2_Testing.md>) includes commands, expected results, and supported limits. Live capture remains unvalidated.

Changes are uncommitted. Stopped before checkpoint 3.

> Short summary of what's done and what remains

**Done — checkpoints 1–2:**

- ECH field decoding and validity findings.
- Client/server correlation, record handling, and JSON connection summaries.
- **123 tests pass**, including sanitizer checks; existing non-HRR fingerprints are preserved.

**Remaining:**

- Your manual checkpoint-2 testing, including live capture.
- Checkpoint 3: independently labeled accepted/rejected/GREASE/absent cases, controlled length experiments, and comparison against fingerprint baselines.
- HRR acceptance inference remains optional; general out-of-order recovery and cross-record assembly remain deferred.

Current changes are uncommitted.

> Plan the next checkpoint

<details><summary>8 previous messages</summary>

> I’ll check the experiment strategy and available client tools, then plan checkpoint 3 around what we can independently label and measure.
>
> <details><summary>Ran 3 commands, searched the web</summary>
>
> <details><summary>Explored 2 files</summary>
>
> - Read `~/.agents/skills/brainstorming/SKILL.md`
> - Read `~/.codex/plugins/cache/claude-cowork/data/1.1.0/skills/analyze/SKILL.md`
>
> </details>
>
> - Ran `git status --short --branch; git log -3 --oneline; sed -n '190,300p' 'Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'; rg --files 'Phase 2' -g '*experiment*' -g '*ech*' -g '*ECH*' -g '*requirements*' -g '*pyproject*'; tail -32 '../.agents/CONTEXT.md'`
>
> - Ran `command -v curl openssl tshark tcpdump dig google-chrome chromium firefox; curl --version; openssl version; ls /Applications; rg --files .venv/bin -g 'python*' -g '*curl*'; rg -n 'ECH|ech|BoringSSL|keylog|SSLKEYLOGFILE' TLS-Fingerprinting -g '*.py' -g '*.sh' -g '*requirements*' -g '*CMake*' -g '!**/build/**' -g '!**/.git/**'`
>
> - Ran `openssl s_client -help 2>&1 | rg -i 'ech|keylog'; curl --help all | rg -i 'ech|doh'; rg --files /opt/homebrew/bin /opt/local/bin -g '*ech*' -g '*bssl*' -g 'curl*' -g '*openssl*'; /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' '/Applications/Google Chrome.app/Contents/Info.plist'`
>
> Searched the web for `site.boringssl.googlesource.com boringssl SSL_ech_accepted SSL_set_enable_ech_grease SSL_ECH_KEYS ...`
>
> </details>
>
> The next checkpoint is the evaluation work: collect independently labeled cases, join them to the engine’s JSON, and run the controlled measurements.
>
> The installed curl exposes `--ech`, but its build does not advertise ECH support; OpenSSL’s client also exposes no ECH controls. I recommend a small BoringSSL client/server lab outside the passive engine. It would give us explicit offer modes, direct endpoint acceptance evidence, and fixed configurations for the length study.
>
> <details><summary>Ran 2 commands, searched the web</summary>
>
> - Ran `rg --files .venv/lib -g 'METADATA' | rg '/(pandas|matplotlib|numpy|pytest|cryptography|scapy|dpkt)-'; command -v cmake ninja go perl clang++ ; rg -n 'maximum_name_length|padding|H2|H3|client' 'TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md' | head -35; cat 'TLS-Fingerprinting/Phase 2/engine/src/main.cpp' | head -85`
>
> Searched the web for `https://boringssl.googlesource.com/boringssl/+/refs/heads/main/include/openssl/ssl.h`
>
> Searched the web for `https://boringssl.googlesource.com/boringssl/+/refs/heads/main`
>
> - Ran `.venv/bin/python - <<'PY'
> from importlib.metadata import version,PackageNotFoundError
> for p in ['pytest','numpy','pandas','matplotlib','cryptography','scapy','dpkt']:
>  try: print(p, version(p))
>  except PackageNotFoundError: print(p, 'not installed')
> PY
> cmake --version | head -1; ninja --version`
>
> </details>
>
> The local lab can label acceptance directly through BoringSSL’s endpoint API, and distinguish authenticated ECH rejection from a generic connection failure. That avoids building keylog decryption just to establish ground truth. [BoringSSL ECH API](https://boringssl.googlesource.com/boringssl/+/df870ed7fa51110edb872beb3357a44d20e1ce56/include/openssl/ssl.h).
>
> For the fingerprint comparison, I recommend two clearly named configurations of the same lab client and a descriptive comparison. That can show whether ECH fields add observable variation, while keeping browser-identification claims out of the result.
>
> <details><summary>Searched the web</summary>
>
> Searched the web for `https://boringssl.googlesource.com/boringssl/+/df870ed7fa51110edb872beb3357a44d20e1ce56/include/openssl/ssl.h`
>
> Searched the web for `https://github.com/google/boringssl/blob/df870ed7fa51110edb872beb3357a44d20e1ce56/include/openssl/ssl.h`
>
> </details>
>
> Checkpoint 3 will use the controlled lab and two named profiles, with no browser requirement. The four-case corpus will use endpoint labels; the length study will be a separate set of client-generated offers.
>
> For the length study, I’ll include a small lab-only trace of the padded inner length and AEAD overhead, so we can compare the predicted ciphertext size with the captured size. The regular corpus will retain GREASE and extension permutation; the length study will hold those settings fixed.
>
> Plan
>
> # Checkpoint 3 — Build a labeled ECH lab and measure what survives
>
> ## Summary
>
> This checkpoint answers: **“How do our passive observations compare with known endpoint behavior, and what information do ECH fields add?”**
>
> Use the chosen controlled local lab and two documented client profiles. Deliver a reproducible four-case corpus, controlled length measurements, and a comparison against outer JA3/JA4. Browser validation and positive HRR inference remain optional.
>
> This is one checkpoint; the pilot below is an internal validation gate.
>
> ## 1. Build the lab and verify four cases
>
> Place the standalone lab, orchestration, manifests and analysis under `Phase 2/experiments/ech`. Keep the passive engine’s CLI and JSON schema unchanged.
>
> - Build separate C++ client/server processes against pinned BoringSSL revision `df870ed7fa51110edb872beb3357a44d20e1ce56`. Verify checkout, required APIs and RFC 9849 wire compatibility during the pilot.
> - Keep BoringSSL isolated from the engine’s existing OpenSSL dependency. Store dependency builds and generated private keys in ignored local directories.
> - Use IPv4 loopback, an automatically selected server port, and process-local certificate trust. Use `public.ech.test` as the cover name and `inner.ech.test` as the normal inner name.
> - Create a single-suite ECH configuration using X25519, HKDF-SHA256 and AES-128-GCM. Generate a second configuration with a different key but the same configuration ID, public name, suite and padding settings.
> - Use fresh client processes, TLS 1.3, no resumption, no automatic reconnects, and a five-second attempt timeout.
>
> The pilot must produce these independently established cases:
>
> | Case | Control and required evidence |
> |---|---|
> | Accepted real ECH | Client uses the server’s configuration; authenticated handshake succeeds and endpoint acceptance results agree |
> | Rejected real ECH | Client constructs a real offer using the mismatched key; require authenticated `SSL_R_ECH_REJECTED`, not a generic failure |
> | GREASE | No real configuration installed; explicit GREASE mode generates an envelope and the ordinary handshake succeeds |
> | Absent | Both real ECH and ECH GREASE disabled; complete captured ClientHello confirms absence |
>
> BoringSSL supplies explicit configuration/GREASE controls and endpoint acceptance reporting. Its rejection error distinguishes authenticated ECH rejection from unrelated failures. [BoringSSL ECH API](https://boringssl.googlesource.com/boringssl/+/refs/heads/main/include/openssl/ssl.h).
>
> Capture before connecting, using a filter restricted to the lab port. Verify the outer random, tuple, envelope fields and negotiated version against Wireshark/TShark. Do not scale collection until all four pilot cases are correctly labeled and joined.
>
> ## 2. Collect and join the corpus
>
> Use three independently captured sessions, restarting endpoints between sessions while preserving the comparison configuration.
>
> Collect **240 attempts**: three sessions × two profiles × four cases × ten repetitions.
>
> - **Profile A:** X25519 TLS key share, ALPN `h2`.
> - **Profile B:** P-256 TLS key share, ALPN `http/1.1`.
> - The server supports both profiles without forcing HRR. Both profiles retain ordinary TLS GREASE and extension permutation.
> - These are configurations of one implementation, not Chrome/Firefox impersonations.
>
> Provide runner stages for `pilot`, `corpus`, `lengths` and `report`. Use the existing project `.venv` for Python orchestration and analysis.
>
> Keep separate artifacts for:
>
> - Session/build/configuration manifests.
> - Client and server endpoint observations.
> - Raw PCAPs and unchanged engine JSON.
> - Joined measurements and derived reports.
>
> Endpoint records include requested mode, actual offer-construction evidence, handshake result, acceptance result, tuple, outer random, configuration digest, profile and timestamps. Obtain the outer random from the outgoing outer handshake callback; distinguish it from the separate inner-message callback.
>
> Join using the session/capture mapping, normalized endpoint tuple and outer random. Preserve unmatched attempts, unmatched passive rows, ambiguous joins and unknown outcomes. Requested mode alone must never establish a successful case label.
>
> Keep public configuration bytes and decoded settings with the manifest. Private keys and any secret logs remain outside exported results.
>
> ## 3. Run controlled measurements
>
> ### H2: hostname length and padding
>
> Use Profile A with fixed non-SNI settings and one selected ECH configuration per condition:
>
> - `maximum_name_length` **0** and **64**.
> - Valid ASCII inner names of every byte length **16–96**, inclusive.
> - One fresh offer for each length/condition in each of three sessions: **486 offers**.
> - Disable general TLS GREASE and extension permutation only for this controlled study; retain fresh cryptographic randomness.
>
> Use a first-flight-only client mode. These are client-generated offers, not successful service connections, and must stay separate from the four-case corpus.
>
> Add a narrowly guarded lab-only BoringSSL trace recording numeric encoded length after name/extension padding but before final rounding, plus AEAD overhead. Log no inner-message bytes or secrets. Verify the trace does not alter protocol behavior.
>
> Compare captured ciphertext length against:
>
> ```text
> 32 × ceil(pre_rounding_length / 32) + AEAD_overhead
> ```
>
> Produce measured-versus-predicted CSV data and a staircase plot for both padding conditions. Report mismatches and uncontrolled variation explicitly.
>
> ### H3: incremental feature information
>
> Compare JA3 and JA4 separately against their corresponding augmented feature sets:
>
> ```text
> baseline fingerprint + KDF ID + AEAD ID + enc length + ciphertext length
> ```
>
> Report per-profile variation, distinct feature groups and groups containing multiple profile or case labels. Analyze real and GREASE offers separately.
>
> Use descriptive comparisons only. Do not equate unique fingerprints with recognition accuracy, or turn observed correlations into new engine rules. A result showing no added information is valid.
>
> ## 4. Validate and prepare manual acceptance
>
> - Keep the existing 123 engine tests and saved-capture regression checks passing.
> - Test configuration generation, explicit mode selection, authenticated rejection, fresh-connection controls and cleanup.
> - Test joins with missing records, duplicate identifiers, tuple reuse, conflicting endpoint evidence and unknown outcomes.
> - Verify generic failures never become rejected-real labels; GREASE and absent cases never become real-offer rejection.
> - Check H2 trace/formula agreement and confirm non-SNI structure stays fixed.
> - Recompute report totals from manifests: attempted, endpoint-labeled, captured, parsed, joined and excluded counts must reconcile.
> - Report passive abstention and coverage with all attempts visible. Do not invent accuracy results when the engine abstains.
>
> Deliver a manual guide, four-case pilot replay, joined corpus, measurement CSVs, standalone plots and a results-and-limits report. Update project context with actual validation and remaining gaps.
>
> Completion requires a verified four-case pilot, repeated corpus and reproducible measurements. If a gate fails, retain the failed evidence and report the blocker rather than filling missing cases with inferred labels. Stop for manual review after checkpoint 3.
</details>

> Before you begin implementing this plan, I have some concerns with your Checkpoint 2 implementation. The `accumulator` module seems to be significantly refactored. Can you briefly explained what you changed?

<details><summary>2 previous messages</summary>

> I’ll compare the accumulator with checkpoint 1 and briefly explain the changes and their trade-offs.
>
> <details><summary>Ran a command</summary>
>
> - Ran `git status --short --branch; git diff ea68a83 -- 'Phase 2/engine/include/tlsfp/accumulator.hpp' 'Phase 2/engine/src/accumulator.cpp'; cat 'Phase 2/engine/include/tlsfp/accumulator.hpp'; sed -n '1,230p' 'Phase 2/engine/src/accumulator.cpp'`
>
> </details>
</details>

Yes—it was a substantial refactor. I changed the accumulator from **a temporary buffer for one fragmented record** into **a small TLS record-stream tracker for each TCP direction**.

The main changes were:

- **Retain sequence progress after delivery:** prevents a retransmitted complete record from producing another hello.
- **Process multiple records:** walks coalesced records and preserves unfinished trailing bytes, including around ChangeCipherSpec records.
- **Separate state from buffering:** small stream metadata persists; partial records use a dynamically allocated vector instead of the fixed 8 KB array.
- **Add lifecycle/error hooks:** capture code can start, stop, reset and remove streams, and receive explicit incomplete/unsupported/malformed outcomes.
- **Add the narrow SYN-start exception:** waits for the exact expected prefix when later server bytes arrive first, as observed in the Chrome capture. It does not reorder those bytes.

The direct, no-copy path for complete records remains, but **every segment now requires stream bookkeeping**, and partial buffering introduces heap allocations. I verified correctness with tests; **I have not established performance parity**.

The larger rewrite came from connection summaries and transport handling. It was broader than simply adding ECH parsing, and I should have highlighted that architectural and performance trade-off more explicitly.

<details><summary>1 previous message</summary>

> Context compaction
>
> Source: automatic
> Status: completed
</details>

> Can you add further details on both what's done and what remains, in very simple words, explaining why we did what we did and why we plan to do the remaining tasks. Simple language, but explain every technical detail encountered on the way

<details><summary>4 previous messages</summary>

> I’ll check the checkpoint notes and current code, then explain what each change does, why we needed it, and what the remaining tests will establish.
>
> <details><summary>Explored a file, a list, ran 3 commands</summary>
>
> - Ran `git status --short --branch`
>
> <details><summary>Explored 2 files, a list</summary>
>
> - Listed files in `.agents`
> - Read `~/.codex/plugins/cache/claude-cowork/anthropic-skills/1.0.0/skills/learn/SKILL.md`
> - Read `./.agents/CONTEXT.md`
>
> </details>
>
> - Ran `cat 'Phase 2/docs/ECH_Checkpoint_1_Testing.md' 'Phase 2/docs/ECH_Checkpoint_2_Testing.md'`
>
> - Ran `git log -3 --oneline`
>
> Tool call
>
> Tool: read_thread
> Status: completed
>
> </details>
>
> One correction to the earlier summary: checkpoint 2 is now committed, and the working tree is clean. I’m using the learning skill to explain the work step by step, including the difference between reading ECH fields correctly and proving whether ECH was accepted.
>
> <details><summary>Explored 2 files, a search, ran 2 commands, searched the web</summary>
>
> <details><summary>Explored a file</summary>
>
> - Read `./Phase 2/docs/ECH_Checkpoint_2_Testing.md`
>
> </details>
>
> - Ran `cat 'Phase 2/engine/include/tlsfp/ech_parser.hpp' 'Phase 2/engine/src/ech_analysis.cpp' 'Phase 2/engine/include/tlsfp/accumulator.hpp'`
>
> - Ran `git log -3 --oneline`
>
> <details><summary>Explored a search</summary>
>
> - Searched for `H2|H3|padding|length|baseline|label|acceptance|checkpoint` in `ECH_DeepDive_and_Integration_Strategy.md`
>
> </details>
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc9849.html#section-5`
>
> <details><summary>Explored a file</summary>
>
> - Read `./Phase 2/engine/src/accumulator.cpp`
>
> </details>
>
> </details>
</details>

**Checkpoints 1 and 2 give us a tool that can read visible ECH information, connect the client’s message to the server’s reply, and save an honest account of what it observed. Checkpoint 3 will test those observations against connections whose ECH behavior we know independently.** :codex-annotation{index="1"}

One correction to the earlier summary: checkpoint 2 is now committed as `dd3860a`. The `feature/ech` working tree is clean.

**First, what information are we trying to observe?**

TLS is the protocol used to establish an encrypted connection. Its opening exchange is called the **handshake**:

- The client sends a **ClientHello**, describing the versions, cryptographic algorithms, and other options it supports.
- The server responds with a **ServerHello**, selecting how the connection will proceed.

ECH means **Encrypted Client Hello**. It protects an inner ClientHello while leaving an outer ClientHello visible. Our program is a **passive observer**: it reads captured traffic without participating in the connection or possessing the endpoints’ secrets.

That distinction matters throughout the project. We can report visible bytes accurately while still being unable to determine what happened inside the encrypted exchange.

**Checkpoint 1: we can now read the visible ECH fields.**

A ClientHello contains **extensions**: numbered sections carrying additional options. ECH uses extension number `0xfe0d`; the `0x` simply means the number is written in hexadecimal.

We added a decoder that reads the following fields:

| Field | Simple meaning | Why we retain it |
|---|---|---|
| Variant | Whether the body describes an outer ECH offer or an inner marker | The two forms have different layouts |
| KDF ID | Number identifying the key derivation algorithm, which derives cryptographic keys | Records the advertised algorithm |
| AEAD ID | Number identifying authenticated encryption, which encrypts data and detects changes | Records the advertised encryption choice |
| Configuration ID | Small number referring to an ECH configuration | Helps compare observations; it does not prove acceptance |
| `enc` length | Size of the key-establishment material carried by the offer | Makes its visible size available for inspection |
| Ciphertext length | Size of the encrypted payload | Supports inspection and later length experiments |

An **ID** is an identifier, not the key itself. We preserve unfamiliar IDs as numbers rather than rejecting them merely because our code does not recognize them.

The decoder checks each field’s declared length before reading it. For example, if the body says “32 bytes follow” but only 10 remain inside the complete body, it reports a contradiction.

It also checks that no unexplained bytes remain after decoding. This prevents a valid-looking beginning from hiding an invalid ending.

We retain the identifiers and lengths, **not the encrypted payload bytes**. We do not decrypt the inner ClientHello or guess its hostname.

**We also made “missing,” “invalid,” and “unsupported” mean different things.**

Previously, a simple success/failure result could hide several different situations. We now distinguish:

| Status | Meaning |
|---|---|
| Complete | We received and examined the required structure |
| Incomplete | Required bytes were missing from our observation |
| Malformed | The available structure contradicts its own format |
| Unsupported | The input exceeds what this implementation handles |
| Not examined | This information has not been parsed |

These descriptions apply at different levels. A ClientHello’s overall structure can be complete while its ECH extension body is malformed.

We separately record ECH **presence**:

- **Present:** we observed the ECH extension.
- **Absent:** we examined the entire extension list and found no ECH.
- **Unknown:** we lack enough information to establish either conclusion.

We made this separation because **failing to observe ECH must not automatically become evidence that ECH was absent**.

If the shared ClientHello structure is incomplete or contradictory, we suppress its fingerprints. Otherwise, we could produce a convincing-looking result from only part of the message.

**Suspicious details remain separate findings.**

The parser now preserves multiple findings together:

- **Duplicate ECH extensions:** retain every occurrence instead of arbitrarily choosing one.
- **An outer `0xfd00` extension:** flag an inner-message compression reference appearing in the externally visible message.
- **An externally visible inner marker:** flag that unusual context while preserving what was decoded.
- **Export-only AEAD:** report an algorithm choice that cannot encrypt the ECH payload.
- **Empty `enc`:** record it, then consider the message’s role. Without enough connection history, its context stays unknown.

This avoids collapsing everything into a single “bad ECH” label. It also ensures that rearranging extensions cannot hide a finding.

**The terminal output now exposes those observations.**

Verbose output includes the decoded ECH fields, statuses, findings, and the **outer random**: the ClientHello’s 32-byte random value.

We keep our own copy of that value because captured packet memory is temporary. Later processing must not depend on memory that has already been reused.

The visible hostname is explicitly called **outer SNI**. SNI means **Server Name Indication**, the hostname field in a ClientHello. Calling it “outer” prevents readers from assuming that we recovered the protected inner hostname.

For the saved Chrome example, the decoder reports:

```text
KDF ID:             1
AEAD ID:            1
Configuration ID:   139
enc length:         32 bytes
Ciphertext length:  208 bytes
```

Those fields match Wireshark. The saved curl example establishes ECH absence after complete extension traversal.

**Checkpoint 2: we can now follow both directions of a connection.**

Reading a ClientHello tells us what the client sent. Understanding the exchange also requires finding the corresponding server response.

We now identify a connection using both endpoints’ IP addresses and TCP ports. We match packets regardless of their direction.

We establish which endpoint is the client using connection-opening packets or parsed hello messages. We do not assume that a particular port number always identifies the server.

The connection record keeps the first ClientHello’s information until the server response arrives. It owns copies of the relevant random value, hostname, protocol information, ECH observations, and fingerprints.

**This required the accumulator changes you asked about.**

The accumulator is the component that collects TCP bytes until a complete TLS record is available.

Three boundaries matter:

```text
TCP segments carry bytes
        ↓
TLS records organize those bytes
        ↓
Handshake messages sit inside TLS records
```

They do not necessarily line up. One TLS record can arrive across several TCP segments. One TCP segment can contain several TLS records.

The earlier accumulator mainly handled collecting one fragmented record. The revised version:

- Reads every complete record available in the incoming bytes.
- Saves an unfinished record or partial header for the next segment.
- Remembers sequence progress after delivering a record.
- Reports missing bytes and unsupported inputs explicitly.

A **TCP sequence number** identifies a byte’s position in the stream. Remembering our progress lets us recognize:

- **Retransmissions:** bytes sent again; we avoid delivering the same hello twice.
- **Overlaps:** some old bytes followed by new bytes; we skip the old portion.
- **Gaps:** bytes that should have arrived are missing; we stop that direction rather than guess where the next record begins.

A complete record can still be processed directly without copying it into an accumulation buffer. Partial records use dynamically allocated storage.

However, every segment now requires stream-state bookkeeping. **Correctness was tested; equivalent speed and memory performance have not been established.** That remains an unresolved tradeoff of the refactor.

There is one narrow exception for bytes arriving before the expected beginning: when we observed the TCP opening exchange, we can wait for the exact expected starting position. We record the gap and do not retain a general queue for rearranging packets. This handles the particular ordering seen in the saved Chrome capture without claiming general recovery.

**We also made connection lifetime explicit.**

TCP uses several control flags:

- **SYN:** starts a connection.
- **FIN:** requests an orderly close.
- **RST:** abruptly resets it.

We now process these even when a packet carries no application data. If a closing packet also carries data, we process its data first.

A repeated opening SYN does not erase an existing connection. A genuinely new connection using the same addresses and ports gets a new **generation**—a separate tracked instance.

Tracking is bounded:

- At most **1,024 retained connection generations** by default.
- **30 seconds** of connection inactivity before expiry.
- The existing **3-second timeout** for an unfinished record.

These limits prevent abandoned or incomplete connections from accumulating forever. If capacity is reached, we remove the least recently observed connection and record why an unfinished TLS observation ended.

After a summary is emitted, large observations and buffers are released. Small completion markers remain temporarily to suppress duplicate output.

**Server parsing now supports cautious conclusions.**

The ServerHello parser checks complete framing and validates the version-selection extension before using it. This matters because the older version field alone cannot identify TLS 1.3 reliably.

Our implemented inference is deliberately narrow: **observed ECH followed by a recognized negotiated version below TLS 1.3 establishes non-acceptance. TLS 1.3 alone does not establish acceptance.** The code names that negative evidence `I3`. It still cannot distinguish a rejected real offer from GREASE. [RFC 9849, acceptance rules](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4)

**GREASE ECH** means deliberately sending an ECH-looking offer without attempting usable ECH, helping keep implementations tolerant of the extension.

We also recognize **HelloRetryRequest**, or **HRR**: a server request for the client to send another ClientHello. We retain the original ClientHello and wait for the final ServerHello. We do not yet analyze the retry sequence to infer ECH acceptance.

**Each connection can now produce a saved summary.**

The new `--json <file>` option writes **JSON Lines**: one structured JSON object per line.

Each summary contains endpoint information, observation times, client and server statuses, ECH fields, fingerprints, interpretation, and limitations. Unavailable values use `null`, meaning “unknown.”

A summary is emitted when the final ServerHello arrives, or when tracking ends through closure, timeout, eviction, capture end, interruption, or capture error.

We refuse to overwrite an existing output file and report writing failures. This makes failed or incomplete output visible.

A **complete hello pair** means we observed both required hello messages. It does not mean that TLS finished successfully or that ECH was accepted.

**What the completed testing establishes.**

The recorded checkpoint validation passed **123 automated tests** in both the normal optimized build and a diagnostic build using:

- **AddressSanitizer:** checks for memory-access errors.
- **UndefinedBehaviorSanitizer:** checks for certain invalid operations in C++.

Tests cover parsing, segmentation, retransmissions, overlaps, gaps, connection reuse, timeouts, output behavior, and other supported cases.

We also compared seven saved captures against checkpoint 1. **All 90 non-HRR fingerprint values were preserved.**

Fingerprints—JA3/JA4 for clients and JA3S/JA4S for servers—are compact signatures derived from selected visible hello fields. Preserving them checks that adding ECH support did not unintentionally change existing results.

The previous total was 96 values. Six disappeared because three HRRs had previously been treated as ordinary final ServerHellos, producing two server fingerprints each. That is an intentional interpretation change.

These checks establish behavior on the tested inputs. They do not establish ECH acceptance accuracy, live-capture reliability, or performance parity.

**What remains immediately: your checkpoint-2 review.**

Your manual testing should confirm that the output is understandable and agrees with Wireshark, especially for:

- Chrome: four paired summaries with the expected ECH fields.
- curl: one paired summary with confirmed ECH absence.
- Synthetic examples: explicit incomplete cases and no duplicate summaries.
- Live capture: behavior on an actual interface, including stopping and waiting without incoming packets.

Live capture has not yet been manually validated. Synthetic examples are packets we constructed to exercise particular rules; they do not prove how real endpoints behaved.

**Checkpoint 3 will give us independently known ECH outcomes.**

We plan a controlled local client/server lab, kept outside the passive engine.

The endpoints will report what they actually attempted and observed. Those reports provide **ground truth**: independent evidence against which we can compare our passive observations.

We need four cases:

| Case | Why we need it |
|---|---|
| Real ECH accepted | Demonstrates an actual successful ECH exchange |
| Real ECH rejected | Tests real offers that were not accepted |
| GREASE ECH | Tests offers that look like ECH without being usable real offers |
| ECH absent | Provides a clear comparison case |

A connection failure alone will not establish ECH rejection. It might instead be a certificate, network, or other TLS error.

We will match endpoint reports to captured connections using their endpoint information and outer random. Ambiguous or missing matches stay unknown.

This separation prevents circular reasoning: our observer must not create the labels used to evaluate itself.

The planned lab uses **BoringSSL**, a TLS implementation with ECH support, for separate client and server programs. The passive engine keeps its existing dependencies. We first need a small pilot proving that all four cases can be produced and labeled reliably.

**Then we will measure what visible lengths actually tell us.**

Ciphertext size includes encoded inner-message content, padding, and encryption overhead. Padding adds extra bytes to conceal some size differences.

The controlled experiment varies the inner hostname length while holding other relevant inputs fixed. We will compare different configured name-padding settings and check the resulting size steps. The recommended scheme rounds padded inner content in 32-byte units before encryption expansion. Such sizes do not prove real ECH or reveal an exact hostname. [RFC 9849, padding scheme](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.3)

We do this because comparing unrelated websites changes too many things at once. A controlled experiment can show whether hostname length caused the observed change.

**Finally, we will ask whether ECH fields add useful information beyond existing fingerprints.**

We will compare:

- Existing outer JA3/JA4 fingerprints.
- Those fingerprints together with ECH algorithm IDs and visible lengths.

We will repeat captures across sessions and controlled client configurations to see which differences remain consistent.

If every real offer uses the same algorithm configuration, those algorithm IDs may add no distinguishing information. That is a valid result. Likewise, differences between controlled client configurations would not establish universal browser identification.

**Some work remains deliberately deferred.**

General out-of-order recovery would require storing and rearranging TCP segments. Cross-record assembly would join one handshake message split across multiple TLS records. Both need broader buffering and lifecycle work.

Currently, complete hellos must fit inside one supported TLS record, although that record may span TCP segments. The record limit remains **8,192 bytes including its header**.

Positive HRR acceptance inference remains optional. Performance comparison of the accumulator also remains unmeasured.

The existing replay instructions and detailed limits are recorded in the [checkpoint-1 guide](<./TLS-Fingerprinting/Phase 2/docs/ECH_Checkpoint_1_Testing.md>) and [checkpoint-2 guide](<./TLS-Fingerprinting/Phase 2/docs/ECH_Checkpoint_2_Testing.md>).
