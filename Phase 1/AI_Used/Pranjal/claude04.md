# TLS fingerprinting analysis results

**Created:** 9/5/2026 14:58:11  
**Updated:** 9/6/2026 10:21:16  
**Exported:** 9/13/2026 14:57:37  
**Link:** [https://claude.ai/chat/45f09659-6ea8-477a-bc79-18092452511f](https://claude.ai/chat/45f09659-6ea8-477a-bc79-18092452511f)  

## User:

> 9/5/2026 14:58:16

> File: 

This is regarding the TLS Fingerprinting project.

I have made a local change in the code to wire my python implementation with the JSONs already there in main. My fingerprints.json might be better, but in the long run we'll be using those other two JSONs. That rewiring won't be visible to you, but assume it's there. 

Now, after those changes, I tested my code on a PCAP I recorded using tcpdump, in which I used a browser, a urllib request and requests library request to search for cloudflare.com

Here are the results. I want you to analyse them and report your observations

## Assistant:

> 9/5/2026 14:59:48

> Planning a concise technical writeup of the key findings.
>
> - Planning a concise technical writeup of the key findings.
> - **Done**

Good test run — a few real findings here, one of which is a genuine bug.

**1. GREASE filtering is working correctly.** The verbose printout (raw parsed fields) still contains GREASE values like `47802` (0xBABA), `14906`/`60138`/`64250` (variants of 0x3A3A/0xEAEA/0xFAFA), `56026` (0xDADA) — that's expected, since `main.py --verbose` prints the *unfiltered* dataclass fields. The JA3 raw string next to it correctly excludes all of them. Don't mistake this for a leak; it's the intended separation between "parsed" and "fingerprinted."

**2. Real bug: your merged reference DB has cross-contaminated JA3/JA3S roles.** Look at these two:

- `main.vscode-cdn.net` ServerHello → JA3S `15af977c...` → labeled **"curl legacy test capture 2 (linux, cli)"**
- `telemetry.individual.githubcopilot.com` ServerHello → JA3S `f4febc55...` → labeled **"Chrome headless, current stable (linux, browser)"**

Both hashes are real, valid entries — but pulled from `seed_fingerprints.json`'s `ja3s` section (`"15af977c...": {"server": "curl_test2"}`, `"f4febc55...": {"server": "chrome_headless"}`). Your merge into `fingerprints.json`/lookup flattened everything into a single `hash -> label` dict and grabbed the **client-side** label/category from `capture_manifest.json` (role: client, category: browser/cli) instead of the server-side one. So you're printing "Match: Chrome headless (browser)" for what is actually the *server's* TLS stack fingerprint on a ServerHello. This will actively mislead your report — fix the merge so JA3 and JA3S entries carry their own role/category, not a shared client-labeled lookup.

**3. You've captured a HelloRetryRequest, and your parser handled it correctly — this is worth putting in the report.** Look at flow `10.53.189.105:59104 -> 20.50.201.200:443`: two ClientHellos and two ServerHellos on the *exact same 4-tuple*, back to back. That's not a bug or a stray retransmission — TLS 1.3 HelloRetryRequest is structurally a ServerHello (same handshake type 0x02, special random per RFC 8446), and your parser has no reason to distinguish it from a normal ServerHello. The two ClientHellos differ by exactly extension `21` (padding) — consistent with the client sending a larger initial `key_share` guess (needing padding to avoid middlebox issues), getting an HRR telling it to use a different group, and resending a shorter, better-targeted ClientHello. This is a legitimate, non-trivial protocol behavior your pipeline is transparently exposing. Bring it up explicitly in the report — it demonstrates you understand you're not always looking at 1 CH + 1 SH per flow, and it's evidence you're actually reading wire behavior, not just running the tool.

**4. Design gap: your Python reassembler tracks every TCP flow, not just TLS ones.** Your C++ engine explicitly gates flow creation on `payload[0] == 0x16`. Your Python `TCPReassembler.process_packet` does not — it creates a `FlowState` for any TCP segment (`read_pcap` only filters on "has data or control flags," not content or port). Combined with no BPF-style port filter (unlike the C++ `tcp port 443` compile), this is why you're tracking 63 flows for what's presumably a handful of actual HTTPS connections, and why `gaps_unresolved: 31` is so high — you're buffering/reordering ordinary HTTP/2 bulk data on long-lived connections that have nothing to do with the handshake anymore. Two fixes, either is fine for the report:
   - Gate flow creation on first byte == `0x16` (mirrors your C++ engine, keeps behavior symmetric across languages — good for the report's cross-language section).
   - Or: once both ClientHello and ServerHello are extracted for a flow, drop it from `self.flows` instead of continuing to reassemble encrypted application data you'll never use.

Either way, right now your Python stats are counting reassembly effort spent on traffic that's structurally irrelevant to JA3/JA3S, which inflates `gaps_unresolved` and `flows_tracked` in a way that makes your Tier-1 reassembler look leakier than it is.

**5. Minor note for completeness:** cipher/extension/curve orderings and specific GREASE slot placement differing between the Chrome-family and curl/requests flows track exactly what you'd expect (Chrome puts GREASE first in each list; curl/requests don't GREASE at all) — nothing wrong there, just confirms your reference captures are behaving as documented.

Priority for the Sept 11 deadline: fix #2 (mislabeling) since it directly undermines your "distinguish clients from handshake metadata" deliverable if a grader spot-checks it, then #4 if time permits — #3 is free narrative material, no code changes needed.

## User:

> 9/6/2026 10:21:05

A draft pointer for #3 for the report

## Assistant:

> 9/6/2026 10:21:16

Here's a draft you can drop into the report (adjust flow specifics if needed):

---

**Observation: HelloRetryRequest handling (flow `10.53.189.105:59104 ↔ 20.50.201.200:443`)**

During analysis of the Cloudflare capture, one flow produced two ClientHello/ServerHello pairs on the same 4-tuple within milliseconds of each other. Initially this could be mistaken for a parser bug (duplicate handshake extraction), but inspection of the two ClientHellos shows they are not identical: the first includes extension 21 (`padding`) and a GREASE-prefixed `supported_versions` list, while the second omits the padding extension. Both ServerHello responses carry TLS version 0x0304 (TLS 1.3) via the `supported_versions` extension.

This is consistent with a TLS 1.3 HelloRetryRequest (RFC 8446, §4.1.4). Structurally, an HRR is indistinguishable from an ordinary ServerHello at the handshake-type level (both use `msg_type = 0x02`); it is only distinguished by a fixed sentinel value in the 32-byte Random field, which our parser does not currently inspect since Random is skipped during ClientHello/ServerHello parsing and is irrelevant to JA3/JA3S computation. Our capture pipeline therefore transparently records both round trips as two independent JA3/JA3S pairs rather than a single logical handshake — which is the technically correct behavior for a fingerprinting tool operating purely on wire metadata, since JA3/JA3S are defined per-handshake-message, not per-logical-connection.

Practically, this occurs when the client's initial `key_share` guess doesn't match a group the server is willing to negotiate (commonly seen with large initial ClientHellos that include padding to avoid middlebox interference on the first attempt), forcing a second, more targeted ClientHello. This validates that our TCP reassembly and TLS record extraction correctly handle multiple independent handshake messages within a single tracked flow, and demonstrates working knowledge of TLS 1.3's handshake retry mechanism rather than treating it as an artifact of the tool.

---

If your professor is scoring for "demonstrated CN understanding," explicitly naming the RFC section and stating *why* you didn't misinterpret it as a bug is the part that earns credit — the observation alone is table stakes, the diagnosis is what's worth points. If you want, I can also help you add a code snippet showing where you'd add HRR sentinel detection (comparing Random against the fixed value) as a stretch/future-work note.

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
