# JA4 fingerprinting implementation in Python

**Created:** 9/6/2026 14:49:37  
**Updated:** 9/6/2026 23:01:59  
**Exported:** 9/13/2026 14:58:29  
**Link:** [https://claude.ai/chat/58df6c2d-536b-4e23-8882-b779b2b58c10](https://claude.ai/chat/58df6c2d-536b-4e23-8882-b779b2b58c10)  

## User:

> 9/6/2026 14:49:42

Discuss the approach for JA4 fingerprinting in the Python engine. You can refer to the C++ implementation of the same. We *can* copy their exact approach in Python too, but only if it makes perfect sense. Stay flexible, we're only discussing right now

## Assistant:

> 9/6/2026 14:50:57

> Planning raw-versus-hashed variants and cross-language validation strategy.
>
> - Planning raw-versus-hashed variants and cross-language validation strategy.
> - **Done**

Good news: your Python `ClientHelloFields` already carries everything JA4 needs (`alpn`, `signature_algorithms`, `supported_versions`) — that was clearly built with JA4 in mind. The bad news: `ServerHelloFields` is missing ALPN, which you'll need for JA4S. Let's go through this properly.

**What the C++ code does (mechanically):**

- **JA4_a** (10 chars, client): `t` + version (priority-scanned from `supported_versions`, else `client_version`) + `d`/`i` (SNI is hostname vs literal IP) + cipher count (2-digit, GREASE-excluded, capped 99) + extension count (2-digit, GREASE + SNI + ALPN excluded, capped 99) + first/last char of negotiated ALPN (lowercased, non-alnum → `0`).
- **JA4_b**: ciphers, GREASE-filtered, **sorted** (not wire order — this is the key JA3→JA4 difference), hex-joined, SHA256 truncated to 12 hex chars (first 6 bytes).
- **JA4_c**: extensions (GREASE + SNI + ALPN excluded), **sorted**, hex-joined, then `_` + signature algorithms in **original wire order** (not sorted), SHA256 truncated to 12 hex.
- JA4S mirrors this but simpler: no sorting needed (single cipher), no sigalgs component.

That extension-count exclusion (SNI/ALPN dropped from both the count *and* the hash list) matches my recollection of the FoxIO spec, but you should not take my word for it — pull the actual test vectors from FoxIO's ja4 repo and use them as an oracle, the same way you're using Salesforce/ja3 for JA3. This is graded on correctness, not vibes.

**Can you copy the approach 1:1? Mostly yes, with three real gaps to fix:**

1. **GREASE filtering location.** C++ filters GREASE at *parse time* — `parser.cpp` never lets a GREASE value into `ClientHelloData`. Your Python `parser.py` deliberately does the opposite (see the comment in `test_parser.py`: "Parser should preserve GREASE values; JA3 module will filter them out later"). That's the right call architecturally — don't change it for JA4. It just means `ja4.py` has to do its own `filter_grease` calls (reuse from `ja3.py`) rather than trusting the parser output. Don't let JA4 reach into raw parser tuples assuming they're clean.

2. **ALPN GREASE check operates on bytes, not strings.** C++'s `is_alpn_grease` checks the raw 2-byte ALPN identifier. Your parser already decodes ALPN to `str` via UTF-8. GREASE bytes like `0x0a0a` happen to decode cleanly as two `\n`-ish control chars, so round-tripping via `.encode('utf-8')` back to bytes and checking will work — but this is fragile and worth a one-line comment explaining why, or better, do the GREASE-ALPN check before decoding, inside `parse_client_hello`, and store a cleaned list. Actually — simplest fix: don't touch parser.py, just re-encode in `ja4.py` when checking. It's ugly but doesn't require touching a module that's already tested and stable.

3. **`ServerHelloFields` has no ALPN field.** This is a real, unavoidable parser change — not a `ja4.py`-only problem. You need to add an ALPN extension parse branch to `parse_server_hello` (extension type `0x0010`, same TLV logic already in `parse_client_hello`) and add `alpn: str | None` to the dataclass. Do this before writing `ja4s.py` logic, and add a `test_parser.py` case for it, mirroring the existing ClientHello ALPN test.

**Proposed module shape for `ja4.py`**, mirroring your `ja3.py` two-tier pattern (raw string / hash):

```
compute_ja4_a(fields) -> str          # 10-char plaintext prefix
compute_ja4_b_raw(fields) -> str      # sorted-cipher hex string (pre-hash)
compute_ja4_b(fields) -> str          # sha256[:12] of above
compute_ja4_c_raw(fields) -> str
compute_ja4_c(fields) -> str
compute_ja4_string(fields) -> str     # a_b_c fully hashed — what you store/match
```

Keep the `_raw` variants around even though you won't hash-match on them — they're free report material, same as JA3's raw string, and let you show *why* two clients differ instead of just that they differ (this is the kind of thing the professor is grading for).

**One more thing worth doing for free validation:** `code/db/seed_fingerprints.json` already has JA4/JA4S hashes computed by the C++ engine on your real captured pcaps (`t13i3111h2_...` etc., labeled "verify against reference"). Once your Python pipeline processes the same pcaps, those are a ready-made cross-language oracle — if Python's JA4 for `curl_test2` doesn't match `t13i3111h2_e8f1e7e78f70_b26ce05bbdd6`, you know immediately whether the bug is in Python or was already wrong in C++. That's a stronger validation story for the report than "matches the RFC on paper."

Want to actually sketch the `parse_server_hello` ALPN addition next, or work through the sorted-cipher/extension logic first?

## User:

> 9/6/2026 14:52:54

Before we move forward, a quick detour. You should also know that I'm yet to implement live capture functionality in the Python engine, like how C++ already does. Do you think I should work on that before or after this JA4 work?

## Assistant:

> 9/6/2026 14:53:10

> Weighing project scope against deadline and grading priorities.
>
> - Weighing project scope against deadline and grading priorities.
> - **Done**

After, and honestly — deprioritize it hard, maybe drop it entirely. Here's the reasoning, not just the verdict:

**Priority order should be:**
1. Fix the critical bugs you already identified (state machine continuation, ref DB contamination, buffer draining) — these make your *existing* pcap results wrong. Broken JA4 on top of a broken capture pipeline is worthless.
2. JA4 — it's your stated stretch goal, directly extends the JA3 work you're graded on, and gives you the "distinguish clients" demo with more resolution.
3. Report write-up — due Sept 11, non-negotiable, and per your own notes several findings are already half-drafted.
4. Live capture in Python — only if there's slack after all that.

**Why live capture specifically doesn't deserve priority, even ahead of "after":**

- Your rubric rewards *demonstrated CN understanding*, not feature parity with the C++ engine. Live capture on the Python side doesn't teach anything new about TLS or TCP — it's the same `TCPReassembler` logic, just fed from a live socket/interface instead of `read_pcap()`. You've already built and tested the hard part.
- You already have a working, deliberately chosen **offline pcap-first** workflow (that's literally documented in your own approach notes as the right call). C++ having live capture doesn't create an obligation for Python to match it — they're not required to have symmetric feature sets, especially since Python is your primary submission and C++ is explicitly stretch.
- Live capture needs root/raw sockets or scapy sniffing, plus `tc netem` interface wrangling you've already flagged as finicky (no loopback support, manual qdisc teardown). That's real setup/debugging time for a feature that doesn't move the needle on grading.
- Time budget: you're at Sept 6, deadline Sept 11. Bugs + JA4 + report is already a full plate for 6 people in the remaining days.

If you want live capture in the deliverable at all, the cheapest correct move is: mention in the report that `main.py`'s `live` subcommand already stubs the interface intentionally deferred, and that C++ demonstrates the live-capture code path is understood at the architecture level (FlowKey/StreamBuffer/pcap_loop) even if not duplicated in Python. That's honest scoping, and scoping decisions read well to a CN grader — same principle as your TCP-depth exclusions.

Want to jump into the parser.py ALPN change for ServerHello now, or knock out one of the three critical bugs first?

## User:

> 9/6/2026 14:53:55

Not in terms of priority, but in terms of its effect on the JA4 work. Will it have any?

## Assistant:

> 9/6/2026 14:54:03

> Assessing whether live capture design impacts JA4 architecture.
>
> - Assessing whether live capture design impacts JA4 architecture.
> - **Done**

None, functionally. They're orthogonal by design.

JA4 operates on `ClientHelloFields`/`ServerHelloFields` — dataclasses produced by `parser.py`. Live capture would just be a different feeder into `TCPReassembler.process_packet()` (raw socket/scapy sniff loop instead of `dpkt` reading a file). Once a `TLSHandshakeResult` comes out the other end, JA4 doesn't know or care whether it originated from a pcap or a live NIC. Same fields, same GREASE filtering, same hashing.

The only way live capture *could* touch JA4 is indirectly, through capture-quality issues:
- Snaplen truncation on live interfaces could hand you an incomplete ClientHello (missing extensions) → JA4 computed on partial data. But this is equally possible reading a truncated pcap, so it's not live-specific.
- If you ever did real-time fingerprinting (flag-as-you-go during a long capture), you might care about latency of the SHA256 calls, but at your data volumes that's irrelevant.

So: build order doesn't matter for correctness, only for your time budget — which is why I said after. There's no dependency in either direction.

## User:

> 9/6/2026 14:58:56

Coming back, can you formally lay out the plan of action for expansion to JA4 in the Python engine?

## Assistant:

> 9/6/2026 15:00:06

> Planning server-side JA4S rules and team task splitting.
>
> - Planning server-side JA4S rules and team task splitting.
> - **Done**

Here's the formal plan, phased by dependency:

**Phase 0 — Parser prerequisite (blocking for JA4S only)**
- Add ALPN extension parsing (`0x0010`) to `parse_server_hello` — single decoded string, not a tuple (server negotiates exactly one protocol, unlike client's offered list).
- Add `alpn: str | None` to `ServerHelloFields`.
- New `test_parser.py` case: ServerHello with ALPN ext → `fields.alpn == "h2"`.
- This doesn't block client-side JA4, so it can run in parallel with Phase 1 if you're splitting across teammates.

**Phase 1 — JA4 (client-side), no dependency on Phase 0**
Build these in `ja4.py`, reusing `filter_grease`/`is_grease` from `ja3.py`:
1. `is_literal_ip(hostname) -> bool` — use stdlib `ipaddress.ip_address()` in a try/except, don't reimplement `inet_pton` logic like C++ does.
2. `resolve_ja4_version(fields) -> str` — priority-scan `supported_versions` (13 > 12 > 11 > 10), fallback to `tls_version` mapped to the two-char codes.
3. `resolve_alpn_chars(alpn) -> tuple[str, str]` — first/last char, lowercased, `'0'` if non-alnum or absent.
4. `compute_ja4_a(fields)` — assemble the 10-char prefix.
5. `compute_ja4_b_raw` / `compute_ja4_b` — GREASE-filter ciphers, **sort** (this is the JA3→JA4 delta, worth flagging explicitly), hex4-join, SHA256 truncated to 12 hex chars. Empty list → sentinel `"000000000000"`.
6. `compute_ja4_c_raw` / `compute_ja4_c` — GREASE-filter extensions, additionally drop SNI (`0x0000`) and ALPN (`0x0010`), **sort**, join, then append `_` + `signature_algorithms` in **wire order** (not sorted) if present. Same empty-sentinel rule.
7. `compute_ja4_string(fields)` — `a_b_c`.

**Phase 2 — JA4 validation**
- Get FoxIO's actual reference test vectors before trusting any of the above — the C++ code is your only current source for these mechanics, and its own `seed_fingerprints.json` entries are self-labeled `"JA4 best-effort, verify against reference"`, meaning the team doesn't trust it either. Don't propagate an unverified implementation into a second language and call it validated.
- Mirror `test_fingerprints.py` structure: known-vector test, GREASE-filter test, empty-extensions test, no-SNI test, no-ALPN test.
- Cross-check Python output against C++ output on the same pcaps (`curl_test2`, `chrome_headless`, etc.) via `seed_fingerprints.json`. Treat mismatches as "investigate," not "Python is wrong" — C++ hasn't been confirmed correct either.

**Phase 3 — JA4S (server-side), depends on Phase 0**
1. `compute_ja4s_a(fields)` — version from `supported_version` (ext `0x002b`) if present else `tls_version`; extension count excludes ALPN only (no SNI exclusion — ServerHello has no SNI); ALPN chars from the new `fields.alpn`.
2. `compute_ja4s_b(fields)` — just `hex4(cipher_suite)`, **no hashing** — single cipher doesn't need it.
3. `compute_ja4s_c_raw` / `compute_ja4s_c` — GREASE + ALPN filtered extensions, sorted, hashed. No sigalgs component.
4. `compute_ja4s_string(fields)`.

**Phase 4 — JA4S validation**
Same structure as Phase 2, against `chrome_headless` and `controlled_curl` JA4S entries in the seed file.

**Phase 5 — Integration**
- `main.py`: add JA4/JA4S compute + `db.lookup(hash, "ja4")` + print, alongside the existing JA3 block.
- `db.py`: no changes needed — `FINGERPRINT_KINDS` and `load_seed_files` already handle `ja4`/`ja4s`.

**Phase 6 — Report**
- JA3 (wire-order) vs JA4 (sorted ciphers/extensions) is a genuinely good "why JA4 exists" point — write it up.
- Document the version-resolution priority logic as a deliberate design decision, cited to spec once you've pulled it.
- If you don't fully solve the ALPN-GREASE-on-decoded-string edge case, scope it out explicitly rather than silently ignoring it — same framing that worked for your TCP-reassembly exclusions.

Want to start with Phase 0 (parser.py ALPN addition) or Phase 1 (client-side ja4.py) first?

## User:

> 9/6/2026 15:09:57

What all does foxio's ja4 repo has for our project? Do I need to clone it as a submodule?

## Assistant:

> 9/6/2026 15:09:59

> Searched the web
>
> - FoxIO ja4 github repo test vectors python implementation
> - **Done**

---

**Sources:**

- [ja4/python/README.md at main · FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4/blob/main/python/README.md)
- [Releases · FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4/releases)
- [ja4/python/ja4.py at main · FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py)
- [Workflow runs · FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4/actions)
- [ja4/technical_details at main · FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4/tree/main/technical_details)
- [ja4/python/common.py at main · FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py)
- [github.com](https://github.com/MasterKia/ja4)
- [pypi.org](https://pypi.org/project/ja4plus/0.2.0/)
- [JA4+ network fingerprinting library for TLS, TCP, HTTP, SSH, X.509, and DHCP analysis](https://pypi.org/project/ja4plus/)
- [pypi.org](https://pypi.org/project/ja4plus/1.1.1/)

## User:

> 9/6/2026 22:57:07

Regarding the issues you found with the C++ engine, there have been recent pushes to the repository, have a look at the updated code and let me know if these issues have now been resolved. Also review all the code in general to look for any kind of critical bugs or mismatches.

## Assistant:

> 9/6/2026 23:01:59

> Tracing whether stale buffered fragments corrupt later records.
>
> - Tracing whether stale buffered fragments corrupt later records.
> - **Done**

Quick correction before I answer: the five issues in your memory (state machine continuation, ref-DB contamination, buffer poisoning, single-record extraction, reassembler scope) were all found in the **Python** engine (`capture.py`/`db.py`), not C++. Also — I don't have a live connection to your repo (no URL was ever given, no GitHub connector is active here), so I can't diff "before vs after a push." What I *can* do is check the current documents in front of me against those five specific bug descriptions and tell you honestly what's fixed and what isn't. If this snapshot doesn't reflect your latest push, paste the changed files and I'll redo this.

## Status of the 5 known Python bugs

**Fixed — non-handshake record draining.** `_extract_tls` now does `del flow.stream[:total_record_size]; continue` for `content_type != 22`. Properly drains before moving on.

**Fixed — single record per packet.** `while len(flow.stream) >= 5:` now drains all complete records per call, not just one.

**Partially fixed, still broken — state machine continuation.** The record-header-trusting design (always reading declared `content_type`/length rather than scanning for stray `0x16` bytes) sidesteps most of the original phantom-handshake scenario. But there's a real residual bug — compare these two branches in `_extract_tls`:

```python
if content_type not in (20, 21, 22, 23):
    flow.stream.clear()
    flow.pending_handshake = b''   # cleared
    break
...
if record_len > MAX_TLS_RECORD_LEN:
    flow.stream.clear()
    break                          # pending_handshake NOT cleared
```

The oversized-length branch — which is exactly the guard against the "7–16M byte phantom length" scenario you described — clears `stream` but leaves `pending_handshake` populated. Next time a legitimate record completes on that flow, the stale fragment gets silently prepended:

```python
if flow.pending_handshake:
    fragment = flow.pending_handshake + fragment
```

corrupting the next real handshake's field boundaries. One-line fix (`flow.pending_handshake = b''` in the second branch), but it's not fixed yet.

**Still present — reference DB contamination.** This is real and I can point to it concretely. `db.py::_enrich_from_manifest` matches by filename prefix against `capture_manifest.json` without checking `record.kind`/`role` first. Take the JA3S entry for hash `f4febc55ea12b31ae17cfb7e614afda8` (source: `chrome_headless_20260831_061717.pcap`, `role="server"`). It matches manifest label `"chrome_headless"`, whose fields describe *Chrome the client*:

```json
"chrome_headless": {"role": "client", "name": "Chrome", "version": "headless, current stable", "os": "linux", "category": "browser"}
```

`category` survives correctly (the JSON entry already sets `"category": "server"` before enrichment runs, and the loop only fills *empty* fields). But `version` is empty on the raw entry, so enrichment sets it to `"headless, current stable"` — a description of the client — onto a server-role record. Anyone looking up this JA3S hash sees a server fingerprint labeled with the browser's version string. Fix: skip enrichment fields that describe the client role when `record.role == "server"`, or just don't pull `version`/`os` from the manifest for `ja3s`/`ja4s` kinds at all.

**Still present — reassembler scope.** `process_packet` does `if key not in self.flows: self.flows[key] = FlowState(...)` unconditionally — no gate on first-byte-is-0x16 the way C++'s `packet_callback` has (`if (payload[0] != 0x16) return;`). Any TCP flow, TLS or not, gets tracked and inflates `flows_tracked`/`gaps_unresolved`. Untouched.

## New finding in C++ — this is the one worth your attention

You asked me to review everything, and this is a genuine functional gap I hadn't flagged before: **the C++ engine only ever extracts one handshake message per flow-direction, period.**

```cpp
if (handshake_type == 0x01) { ... }
else if (handshake_type == 0x02) { ... }
ctx->active_flows.erase(key); // Remove flow after processing handshake
```

That erase runs unconditionally — after *any* complete Handshake-type (0x16) record, regardless of `handshake_type`, and regardless of whether parsing even succeeded. Consequences:

- If a server coalesces ServerHello + Certificate + ServerKeyExchange into multiple TLS records within one buffered read (extremely common for TLS 1.2), only the ServerHello gets processed; the rest of `buf.bytes` is discarded when the flow is erased.
- There's no equivalent of your Python `test_multiple_handshakes_in_one_record` case — two ServerHellos packed into one record would only ever yield one result in C++, not two.
- It happens to work fine for the plain "one ClientHello, one packet" case, which is most of your lab captures — that's probably why it hasn't shown up yet.

This isn't a crash risk, just silent data loss on any capture with realistic TLS 1.2 handshake coalescing. Worth deciding: document it as a scoped C++ limitation in the report (consistent with how you've framed other C++ simplifications), or actually fix it by looping over records in `buf` the way Python does before erasing.

Two smaller things:
- **`parser.py` asymmetry**: `parse_client_hello` raises `ValueError` on truncated extensions; `parse_server_hello` silently clamps via `end_offset = min(offset + ext_total_len, len(data))`. Not a crash bug, but it means malformed ServerHello extensions fail differently than malformed ClientHello ones — pick one behavior and be consistent, or justify the difference in the report.
- **C++ OOO handling** (`if (diff > 0) { erase; return; }`) drops the whole flow on any gap — confirmed intentional by your own `OutOfOrderPacketDropsFlow` test, not a bug, just a documented scope difference from Python's buffered reordering. Worth a one-line mention in the report's cross-engine comparison section since it directly affects capture completeness under packet loss.

Want me to write the actual fixes for the two confirmed Python bugs (`pending_handshake` reset + the role-aware manifest enrichment), or keep moving on JA4?

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
