# Add Phase 2 design comments

> Add comments to our code in Phase 2, wherever design decisions were made, or factual/conceptual TLS or ECH understanding was implemented in code. Keep the comments pedagogical, moderate verbosity, and standard/professional. Frequency of comments is dynamic and depends on if a snippet of code actually reflects a design decision for the high-level architecture, or is super important conceptually, or is very sensitive. Use [ECH_DeepDive_and_Integration_Strategy.md](<TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md>) as reference for this.

I’ll review the Phase 2 code alongside the ECH strategy document, then add comments where protocol concepts or design decisions need explanation. I’ll keep routine code uncluttered and preserve behavior.

<details><summary>5 previous messages</summary>

> <details><summary>Explored a file, ran 2 commands</summary>
>
> <details><summary>Explored a file</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp`
>
> </details>
>
> - Ran `sed -n '1020,1120p' 'TLS-Fingerprinting/Phase 2/engine/src/capture.cpp'; cat 'TLS-Fingerprinting/Phase 2/engine/src/'{ja3,ja4}.cpp`
>
> - Ran `cat 'TLS-Fingerprinting/Phase 2/engine/include/tlsfp/'{types,accumulator,byte_reader}.hpp; cat 'TLS-Fingerprinting/Phase 2/engine/CMakeLists.txt'; sed -n '1,145p' 'TLS-Fingerprinting/Phase 2/docs/ECH_DeepDive_and_Integration_Strategy.md'`
>
> </details>
>
> The code already separates ECH decoding from interpretation and keeps incomplete captures distinct from malformed input. I’ll focus the comments on why those boundaries matter, along with field meanings, TCP/TLS framing, retry handling, and the limits of passive acceptance evidence. There are existing uncommitted changes, so I’ll preserve them and verify my additions separately.
>
> <details><summary>Edited 15 files, explored 5 files, a search, a list, ran 5 commands</summary>
>
> <details><summary>Explored 4 files, a search, a list</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/parser.cpp`
> - Searched for `^//|^[A-Za-z].*\(|^[ ]+//|^class|^struct` in `db.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/db.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/db.cpp`
> - Listed files in `engine`
>
> </details>
>
> - Ran `mkdir -p /private/tmp/cs331-comment-baseline; cp -R 'TLS-Fingerprinting/Phase 2/engine/src' 'TLS-Fingerprinting/Phase 2/engine/include' /private/tmp/cs331-comment-baseline/`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/accumulator.hpp` (+2 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/byte_reader.hpp` (+2 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/ech_analysis.hpp` (+2 -2)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/ech_parser.hpp` (+2 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/types.hpp` (+4 -2)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp` (+10 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/ech_analysis.cpp` (+10 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/ech_parser.cpp` (+12 -0)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/parser.cpp` (+18 -5)
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/capture.cpp` (+40 -1)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/ja3.cpp` (+8 -1)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/ja4.cpp` (+6 -0)
>
> <details><summary>Explored 3 files</summary>
>
> - Read `./TLS-Fingerprinting/Phase 2/engine/src/db.cpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/ech_fixtures.hpp`
> - Read `./TLS-Fingerprinting/Phase 2/engine/tests/test_ech_connections.cpp`
>
> </details>
>
> - Ran `cp -R 'TLS-Fingerprinting/Phase 2/engine/tests' /private/tmp/cs331-comment-baseline/; rg -n 'R"|//|^#' 'TLS-Fingerprinting/Phase 2/engine/tests/fixtures/'*.py; cat 'TLS-Fingerprinting/Phase 2/engine/src/main.cpp'`
>
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/include/tlsfp/parser.hpp` (+3 -1)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/src/db.cpp` (+7 -1)
> - Wrote `./TLS-Fingerprinting/Phase 2/engine/tests/fixtures/ech_fixtures.hpp` (+4 -0)
>
> - Ran `ruby <<'RUBY'
> root = 'TLS-Fingerprinting/Phase 2/engine'
> baseline = '/private/tmp/cs331-comment-baseline'
> # Preserve literals while removing comments and insignificant whitespace.
> lexical = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/\/[^\n]*|\/\*.*?\*\/|\s+/m
> strip = ->(text) { text.gsub(lexical) { |part| part.start_with?('"', "'") ? part : '' } }
> changed = []
> Dir.glob("#{baseline}/**/*").select { |f| File.file?(f) }.each do |old_path|
>   relative = old_path.delete_prefix("#{baseline}/")
>   current = File.binread("#{root}/#{relative}")
>   original = File.binread(old_path)
>   next if current == original
>   abort "Non-comment change: #{relative}" unless strip.call(current) == strip.call(original)
>   changed << relative
> end
> puts "Verified comments-only edits in #{changed.length} files:"
> puts changed
> RUBY`
>
> - Ran `diff -u /private/tmp/cs331-comment-baseline/src/capture.cpp 'TLS-Fingerprinting/Phase 2/engine/src/capture.cpp'; diff -u /private/tmp/cs331-comment-baseline/src/parser.cpp 'TLS-Fingerprinting/Phase 2/engine/src/parser.cpp'`
>
> - Ran `cmake --build 'TLS-Fingerprinting/Phase 2/engine/build' -j 4`
>
> </details>
>
> The comments now cover the ECH wire fields, passive-evidence limits, buffer ownership, connection lifecycle, and TCP/TLS boundaries. I also corrected a few existing comments that overstated size guarantees or described an earlier checkpoint. A comparison against the starting files confirms that only comments changed; the build passed, and I’m running the existing tests now.
>
> <details><summary>Ran 2 commands</summary>
>
> - Ran `ctest --test-dir 'TLS-Fingerprinting/Phase 2/engine/build' --output-on-failure`
> - Ran `git -C TLS-Fingerprinting diff --check; diff -u /private/tmp/cs331-comment-baseline/src/ech_parser.cpp 'TLS-Fingerprinting/Phase 2/engine/src/ech_parser.cpp'; diff -u /private/tmp/cs331-comment-baseline/src/accumulator.cpp 'TLS-Fingerprinting/Phase 2/engine/src/accumulator.cpp'`
>
> </details>
</details>

Added pedagogical comments across 15 Phase 2 files, covering ECH/TLS concepts, design decisions, framing, ownership, and evidence limits, using the ECH strategy document as reference.

Verified comments-only changes. Build succeeded and all 123 tests passed.
