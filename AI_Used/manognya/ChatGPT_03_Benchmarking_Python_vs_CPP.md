# Session 3 — Python vs C++ Benchmarking

## Verbatim user prompt

> in the meet ujas said we need scripts to benchmark  
> Benchmarking -  
> Python  
> Cpp  
> Python vs cpp  
> Check can we use some other lib for Python (cuz that shi slow) Or like another lib in general  
> and like to showcase how our thing handles the stress  
> also if i give you the github link can you check the structure and code??

### Response head

The work was split into a correctness gate, a core engine benchmark, investigation of Python overhead/library choices, and a separate live stress test.

---

## Verbatim user prompt

> benchmark scripts

### Response head

Both engines should run on the same PCAPs, perform equivalent fingerprint work, use repeated runs, and keep Redis/GUI/output overhead out of the core timing.

---

## Benchmark scope

Included:

- packet parsing,
- TCP reassembly needed by the engine,
- TLS ClientHello/ServerHello parsing,
- JA3,
- JA3S,
- JA4,
- JA4S.

Excluded from the core engine benchmark:

- Redis lookup,
- GUI rendering,
- terminal-heavy output,
- unrelated startup/application logic where possible.

The main cross-engine metric became **median engine execution time**.

---

## Why raw packets/second was not enough

The two engines did not define packet counters identically.

- C++ counted all scanned PCAP packets.
- Python skipped some packets such as pure ACKs.

Therefore, direct packets-per-second comparison could be misleading.

---

## Real-client PCAPs

Fresh captures were made because several repository placeholders were empty.

Useful captures included:

- `curl.pcap`
- `python_requests.pcap`
- `custom_client.pcap`
- `chrome.pcap`
- `chrome_run2.pcap`
- `cloudflare_run1.pcap`

A Firefox attempt was effectively empty and was not treated as a valid benchmark case.

---

## Important Python benchmark correction

An early Python benchmark was not doing all fingerprint computation inside the timed section.

The timed work was corrected to include:

- JA3
- JA4
- JA3S
- JA4S

That made the Python timing more comparable to C++.

---

## Scripts used

- `benchmark_cpp.py`
- `benchmark_python.py`
- `_py_bench_worker.py`
- `benchmark_compare.py`

Outputs:

- CSV results,
- comparison CSV,
- comparison graph.

---

## Final normal-PCAP timing snapshot

| PCAP | C++ median | Python median | Approx. speedup |
|---|---:|---:|---:|
| cloudflare_run1 | 1.1661 ms | 19.9464 ms | 17.1× |
| curl | 0.8880 ms | 8.1962 ms | 9.2× |
| python_requests | 0.7047 ms | 2.5465 ms | 3.6× |
| custom_client | 0.6744 ms | 1.2855 ms | 1.9× |
| chrome | 0.7586 ms | 4.4442 ms | 5.9× |
| chrome_run2 | 0.7327 ms | 4.2564 ms | 5.8× |

---

## Synthetic x100 caveat

A repeated synthetic workload produced:

- C++: 1100 CH / 1100 SH
- Python: 1100 CH / 1001 SH

Because the handshake counts differed, this case was not presented as a clean apples-to-apples performance result.

The likely issue was repeated identical flows/sequence numbers interacting with reassembly/deduplication state.

## Final benchmark conclusion

C++ was consistently faster on the verified normal PCAP set.

Recommended framing:

- headline: median engine time,
- throughput: supporting metric with counter-definition caveat,
- synthetic repeated-flow result: separate, with correctness warning.
