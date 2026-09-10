# Benchmarking & Stress Testing — AI Usage Details

## Tools Used

1. ChatGPT (OpenAI)
2. Claude.ai (Anthropic)

## Prompts

The prompts below are representative prompts used during the benchmarking and stress-testing work. Minor conversational follow-ups have been omitted for readability.

### ChatGPT

1. Review the current TLS fingerprinting repository and tell me what still needs to be tested before benchmarking.
2. Help me compare the C++ and Python engines fairly using the same PCAPs and separate core engine time from process-startup, database, and GUI overhead.
3. Check my benchmark scripts and result CSVs one last time before I push them to the team repository.
4. Explain why the C++ and Python implementations report different packet counts on the same PCAP and how throughput should be calculated fairly.
5. Help me verify that the Python benchmark is actually timing JA3, JA3S, JA4, and JA4S computation, not only parsing and reassembly.
6. Review the latest repository state and help me plan a live stress test without duplicating tests already added by teammates.
7. Guide me through live-capture stress testing with `tcpreplay` on macOS, including choosing a safe interface and increasing the offered packet rate gradually.
8. Review the stress-test results and help me distinguish supported conclusions from overclaims before adding them to the report.

### Claude.ai

1. Review the pre-benchmark testing notes comparing C++, Python, and TShark and point out any correctness issues or weak conclusions.
2. Re-check previously reported C++ issues after recent commits, including JA4 extension counting and missed ClientHello handling.
3. Help set up the benchmarking workflow and validate real client captures before using them for performance comparison.
4. Help debug benchmarking scripts and check whether the C++ and Python results are being compared using equivalent metrics.
5. Suggest a practical stress-testing scope covering noisy traffic, malformed TLS inputs, corrupted PCAP files, and live-capture load.
6. Review the final stress-testing write-up and check whether the conclusions are supported by the collected data.

## Thought Process

AI was used mainly as a review, debugging, and verification partner. I used it to understand trade-offs, inspect benchmark methodology, interpret terminal output, and identify places where a result could be misleading.

I did not treat AI output as ground truth. Benchmark and stress-test conclusions were based on locally executed commands, generated CSVs, PCAP captures, engine output, and TShark comparisons. When an AI suggestion conflicted with actual results, the scripts or wording were corrected using the measured data.

The main goal was to keep the comparison fair: both implementations should process the same input captures, perform the same fingerprinting work, and clearly separate engine performance from unrelated costs such as Redis lookup, GUI rendering, and interpreter/process startup.

## Step-by-Step Details

1. Reviewed the existing C++ and Python engines and verified important JA3/JA3S/JA4/JA4S correctness issues before benchmarking.
2. Captured real client traffic for curl, Python clients, and Chrome, then checked that the resulting PCAPs were valid and suitable for comparison.
3. Built benchmark scripts for C++ and Python using repeated runs and warm-up runs, and stored the results in CSV files with a comparison graph.
4. Used AI review to catch methodology issues, including Python initially not computing all fingerprints inside the timed section and the two engines using different packet-count definitions for throughput.
5. Performed robustness testing with noisy traffic, targeted malformed ClientHello mutations, sanitizer-enabled C++ runs, and corrupted/truncated PCAP files.
6. Performed live-capture load testing with `tcpreplay` on an isolated `bridge0` interface at increasing packet rates, then compared packet capture and TLS handshake detection between the C++ and Python implementations.
7. Reviewed the final benchmark and stress-test write-ups to remove unsupported claims and keep the reported conclusions consistent with the actual measurements.
