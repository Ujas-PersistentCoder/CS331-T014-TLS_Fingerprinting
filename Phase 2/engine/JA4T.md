# JA4T in the Phase 2 Engine (Track A)

## What JA4T is

JA4T (FoxIO, JA4+ family) fingerprints the **TCP SYN** a client sends to open a connection. JA4TS does the same for the server's **SYN-ACK**. Both use the same format:

```
<window size>_<TCP option kinds, wire order>_<MSS>_<window scale>
64240_2-1-3-1-1-4_1460_8          Windows 10/11
64240_2-4-8-1-3_1460_7            Linux
65535_2-1-3-1-1-8-4-0-0_1460_6    macOS / iOS
```

Option kinds: 0 EOL, 1 NOP, 2 MSS, 3 Window Scale, 4 SACK-permitted, 8 Timestamps. Absent fields are written as `00`, and MSS is zero-padded to two digits (`8192_2_09_00`). The format follows FoxIO's Rust/Wireshark implementation, which keeps every EOL padding byte. The unit tests in `tests/test_ja4t.cpp` use FoxIO's own vectors.

**Why it matters.** JA3/JA4 describe the ClientHello, which the *application* writes, so a tool like `curl-impersonate` can copy any browser's. The SYN is written by the *OS kernel*: the window, option order, window scale and IP TTL (Linux and macOS start at 64, Windows at 128) are stack defaults. JA4T therefore identifies the sender's OS. Comparing it with the TLS fingerprint is how a passive sensor spots TLS impersonation.

Layer note: the window and options are L4 (TCP header). The TTL used alongside them is L3 (IP header).

## How the engine uses it

JA4T/JA4TS collection is opt-in with the CLI `-t` flag. Without `-t`, the engine continues computing JA3/JA3S and JA4/JA4S but skips TCP SYN tracking and cross-layer checks.

1. With `-t`, `capture.cpp` records SYN and SYN-ACK headers in a bounded table, before the "no payload" early exit. Only pure SYN / SYN-ACK flag combinations count (ECE/CWR allowed, as in FoxIO's `is_initial_syn`); SYN+FIN and SYN+RST scan probes are ignored. The key is the directional 4-tuple, so a SYN is found under the same `FlowKey` as its ClientHello, and a SYN-ACK under the same key as its ServerHello. Retransmissions with the same initial sequence number preserve the first SYN's options: macOS/iOS can strip options from later retransmissions. A changed initial sequence number replaces the entry as a new connection reusing that 4-tuple. Entries expire after 30 s (measured in either direction, so merged pcaps whose clock steps backwards still drain); the table is pre-sized and capped at 64 K entries and fails open under a SYN flood, so new flows may have no JA4T.
2. A malformed option block (bad option length, non-zero bytes after EOL) does **not** drop the SYN. The option kinds read up to the fault are kept in the JA4T and the SYN is flagged. Dropping it would let a hand-crafted SYN, which kernels still accept, hide from every cross-layer check.
3. When the Hello arrives, the engine takes the matching entry and prints `JA4T:` / `JA4TS:` with a catalog label or an inferred OS, plus the TTL and hop count.
4. `ja4t.cpp: infer_os()` gives a p0f-style verdict from the option layout (Linux / Apple / Windows defaults) and the initial-TTL estimate.

## Alerts

| Alert | Layer | Fires when | Meaning |
|---|---|---|---|
| `IMPERSONATION_MISMATCH` | L7 vs L4 | The TLS fingerprint's catalog record has `expected_os` and the SYN's OS disagrees with it | The client's TLS stack claims an OS its kernel doesn't run |
| `TTL_MISMATCH` | L3 | SYN TTL and ClientHello TTL on the same flow differ by more than 1 (same for SYN-ACK vs ServerHello) | The packets came from different hosts or paths: an injected or spoofed packet |
| `STACK_ANOMALY` | L3 vs L4 | Client SYN option layout and TTL point to incompatible OSes, or the SYN carries malformed options | A hand-crafted SYN (raw socket) or a rewritten TTL |

The 1-hop `TTL_MISMATCH` tolerance comes from real traffic: Cloudflare connections in `Phase 2/pcaps/pq_ech_chrome.pcap` show a SYN-ACK at TTL 111 and the ServerHello at 112 (a SYN proxy one hop closer). An injector at exactly ±1 hop goes unnoticed.

`STACK_ANOMALY` is limited to client SYNs. CDN and load-balancer SYN-ACKs in `code/pcaps` routinely pair a Linux option layout with TTL 128 or 255.

### Why `expected_os` and not `os`

The catalog's `os` field records where a fingerprint was *captured*. Chrome, Firefox, curl and Python all use the same TLS stack on every OS, so their JA4 says nothing about the OS. `chrome.pcap` shows the catalogued "Chromium (linux)" JA4 sent from a Mac. A check based on `os` would raise false alarms on real traffic. `expected_os` is opt-in: set it only on fingerprints of **OS-bound** TLS stacks, such as Windows SChannel (Edge legacy, .NET, PowerShell) or Apple's Network.framework (Safari). JA4T records may use plain `os`, since a TCP stack is inherently tied to its OS.

```json
{ "ja4": [ { "hash": "t13d...", "client": "Safari", "os": "macos", "expected_os": "macos", "category": "browser" } ],
  "ja4t": [ { "hash": "64240_2-1-3-1-1-4_1460_8", "client": "Windows 11", "os": "windows" } ] }
```

## Running it

```bash
./tlsfp_phase2 -r code/pcaps/chrome.pcap -t -v        # JA4T/JA4TS + [V-TCP-*] dissection
./tlsfp_phase2 -r capture.pcap -t -c lab_catalog.json # extra catalog with expected_os records
ctest --test-dir build                               # JA4T unit tests
python "Phase 2/testbed/ja4t_lab.py" --engine build/tlsfp_phase2   # invokes the engine with -t -v
```

`ja4t_lab.py` synthesises spoofing and honest-control scenarios, including retransmission, rapid 4-tuple reuse, and missing/expired SYNs, then checks the engine's verdict for each.

## Limits (worth stating in the report)

- **The impersonated identity must be OS-bound.** `curl-impersonate` on Linux posing as Chrome is invisible: real Chrome on Linux produces the same SYN and the same ClientHello. Detection works when the claimed client cannot run on the attacker's OS. Examples: Safari or SChannel from a Linux box, or a "Windows Chrome" claim backed by out-of-band knowledge (an all-Windows fleet, or a User-Agent seen at a TLS-terminating proxy).
- **SYN spoofing is possible, just more expensive.** An attacker with root can set the TTL (`sysctl net.ipv4.ip_default_ttl=128`) and craft SYNs with raw sockets or a userspace TCP stack. JA4T raises the cost; it is not proof.
- **Proxies, VPNs and NAT64 terminate TCP.** The SYN then belongs to the proxy, not the client. MSS shrinks on tunnels (1380/1420/1436 in `code/pcaps`), so `infer_os` ignores MSS.
- **No SYN, no JA4T.** Connections already open when capture starts print `SYN not captured`.
- **Unknown TTL is not guessed.** A zero TTL/Hop Limit does not produce an OS inference from TTL alone; a recognized TCP option layout may still identify the stack.
- **License.** JA4T/JA4TS are under the FoxIO License 1.1, which permits academic use. JA4 itself is BSD-3.
