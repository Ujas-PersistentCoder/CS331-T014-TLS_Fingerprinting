# Session 4 — Stress Testing and Live Capture

## Stress-test scope

Four classes of tests were discussed and run:

1. noisy/mixed real-world traffic,
2. targeted malformed ClientHello mutations,
3. corrupted/truncated PCAP handling,
4. live capture under increasing replay load.

---

# 1. Noisy mixed traffic

A `noisy_capture.pcap` containing 1,333 mixed packets was used.

Results:

| Source | ClientHello | ServerHello |
|---|---:|---:|
| TShark | 22 | 20 |
| C++ | 22 | 22 |
| Python | 22 | 22 |

The two additional ServerHellos found by both engines were investigated rather than dismissed.

Matching fingerprints and reassembled lengths strongly suggested genuine ServerHellos that TShark did not dissect because of stricter stream-reassembly behavior after capture gaps.

The final wording was kept cautious rather than claiming absolute proof.

---

# 2. Targeted malformed-input testing

Sixteen cases were created:

- one valid baseline,
- fifteen malformed mutations.

Cases included impossible lengths, truncations, zero payloads, and malformed SNI/cipher-suite structures.

C++ was tested under:

- AddressSanitizer,
- UndefinedBehaviorSanitizer.

Result:

- no hangs,
- no crashes,
- no sanitizer-detected violations for the tested cases.

The wording was intentionally changed from broad “fuzzing” to **targeted malformed-input / mutation testing**.

---

# 3. Corrupted/truncated PCAPs

Cases:

- cut-in-half file,
- header only,
- partial packet header,
- empty file,
- random garbage,
- nonexistent path.

### C++

Generally returned clean errors and sensible exit behavior.

### Python

Handled some truncated cases but exposed uncaught exceptions for:

- empty PCAP,
- random non-PCAP input.

This was documented as a robustness/usability gap.

---

# 4. Live load via tcpreplay

## Why tcpreplay

TRex was discussed but judged impractical for the macOS/laptop environment.

`tcpreplay` was used instead.

## Safety setup

The inactive `bridge0` interface was selected rather than active Wi-Fi.

A 5-packet replay was first validated with TShark:

- sent: 5
- captured: 5

This confirmed the replay/capture path.

## Load PCAP

`cloudflare_run1.pcap`

Expected C++ baseline:

- 2,655 packets,
- 11 ClientHellos,
- 11 ServerHellos.

---

## C++ rate sweep

The C++ engine remained perfect across many rates from 100 pps upward into the hundreds of thousands of packets per second.

Successful rates included:

100, 500, 1k, 5k, 10k, 25k, 50k, 100k, 200k, 300k, 400k, 500k, 550k, 565k, and approximately 574k pps.

### Example topspeed run

- actual replay: ~584,673 pps
- packets captured: 2448 / 2655
- CH: 11/11
- SH: 11/11

Raw packet loss appeared but handshake detection stayed complete.

### Example lossy high-rate run

Around ~570k pps:

- packets captured: 1907 / 2655
- CH: 9/11
- SH: 9/11

This showed the extreme region was variable rather than a clean threshold.

### Repeated ~574k runs

| Run | Packets | CH | SH |
|---|---:|---:|---:|
| 1 | 2652/2655 | 11/11 | 11/11 |
| 2 | 2655/2655 | 11/11 | 11/11 |
| 3 | 2655/2655 | 11/11 | 11/11 |

Aggregate packet completeness across the three was about 99.96%, with 100% handshake detection.

---

## Verbatim user prompt

> so final cpp results?

### Response head

The defensible result was that C++ performed very strongly but the extreme short-burst region was variable; no exact hard failure threshold should be claimed.

---

## Verbatim user prompt

> ohk

### Response head

The next step was Python live testing using the same PCAP/interface/rate methodology.

---

## Verbatim user prompt

> ➜  ~ sudo python3 py_live_stress.py bridge0  
> Password:  
> /Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python: can't open file '/Users/manognya/py_live_stress.py': [Errno 2] No such file or directory

The user also pasted an automated C++ `tcpreplay` loop.

### Response

The immediate problem was only the Python script path. The automated loop itself was a better reproducibility pattern than manual Ctrl-C timing because it consistently:

- launches the engine,
- waits for initialization,
- runs one replay,
- waits for processing,
- sends SIGINT,
- collects one trial's final summary.

---

## Python live-test results retained in the final write-up

Python's known-good baseline was **1,877 processed packets**, not 2,655, because its counter skips some packets such as pure ACKs.

Representative results:

| Rate | Python processed | Handshakes |
|---|---:|---:|
| 1k | 1,877 | 22 |
| 10k | 1,877 | 22 |
| 100k | 234 | 4 |
| 300k | 232 | 9 |
| topspeed (~570k) | 178 | 4 |

A 30-second cooldown did not materially recover the missing data compared with a shorter cooldown.

Therefore, the final wording was:

- not “we stopped too soon,”
- consistent with capture-buffer loss or the Python live consumer being unable to drain packets quickly enough,
- exact responsible layer not uniquely proven.

---

## Final methodological distinction

The session repeatedly separated:

- offline benchmark speed,
- parser robustness,
- live offered load,
- raw packet completeness,
- handshake detection completeness.

These were not collapsed into one claim.
