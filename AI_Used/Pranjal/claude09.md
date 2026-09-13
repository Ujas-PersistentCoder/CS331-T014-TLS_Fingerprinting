# TLS fingerprinting project report structure

**Created:** 9/7/2026 18:58:35  
**Updated:** 9/7/2026 21:25:06  
**Exported:** 9/13/2026 15:02:48  
**Link:** [https://claude.ai/chat/3931992d-1bcc-47bc-a78f-2e29f6690064](https://claude.ai/chat/3931992d-1bcc-47bc-a78f-2e29f6690064)  

## User:

> 9/7/2026 19:00:55

I'm starting to write the report for TLS fingerprinting project. Here is a rough list of areas to discuss in the report (not exhaustive):

* Introduction of the project (what is TLS fingerprinting. )
* History/theory
* What have we done
   * Our approach
   * Our design decisions and why we made them (instances of working towards one approach and switching to another for some reasons, if there are any instances)
* C++ and Python high-level implementation details and a subjective comparison of the two engines
* Benchmarks and results (important)
* Future scope
    * One of the points: client and server hashes can be combined to get even broader set of information and stronger malware detection

   * "Understanding on the fingerprinting's role in security monitoring (malware C2 detection, client identification) and its limitations, including fingerprint randomization in modern browsers as an evasion technique." This exact line is in the description of the project list, so we need a well-written answer for that.

## Assistant:

> 9/7/2026 19:01:22

Good outline. A few blunt observations before you start writing, then concrete content for the two sections you flagged as needing real substance.

**Structural issues with your list first:**

1. You're missing an explicit "Limitations" section separate from "Future scope." Your professor's rubric line explicitly wants evasion/limitations discussed — don't bury it as a future-scope bullet, give it its own section. Future scope = "what we'd build next." Limitations = "what JA3 fundamentally cannot do, demonstrated by our own data." You have the actual evidence for this (Chrome extension permutation, GREASE) — use it as a section, not an afterthought.

2. "History/theory" is vague. Be specific: this should cover (a) why fingerprinting exists — TLS handshakes are unencrypted metadata even though the payload isn't, (b) JA3's origin (Salesforce, 2017, John Althouse et al.), (c) why JA3 was designed the way it was (order-preserving, no semantic understanding needed, just structural), (d) JA4's motivation as a fix to JA3's weaknesses (SHA256 vs MD5, sorted fields, richer feature set). Don't just say "TLS fingerprinting has a history" — trace the actual lineage since it directly sets up your limitations section later.

3. "What have we done" — you said "design decisions and why we made them, instances of switching approaches." Do you actually have such an instance? From memory, I don't see one recorded — your implementation has been fairly linear (bugs found and fixed, not architectural pivots). If you don't have a real pivot, don't manufacture one; just document the decisions as *decisions* (e.g., dpkt over Scapy, JSON-backed dict over Redis-only, minimal reassembly over duplicate-detection). Fabricating a "we tried X then switched to Y" narrative when it didn't happen is exactly the kind of thing that reads as fake rigor to a grader who asks follow-up questions.

---

**On the security-monitoring/limitations paragraph** — since this is graded verbatim, here's a tight version you can expand:

TLS fingerprinting's value in security monitoring comes from a specific fact: TLS payload is encrypted, but the *handshake metadata* — cipher suite order, extension order, supported groups — is sent in cleartext and is a near-invariant of the client software's TLS library, not the user's identity or intent. This lets a passive observer classify traffic without decryption. Two dominant use cases:

- **C2/malware detection**: malware families often use non-standard TLS libraries (Go's crypto/tls, custom OpenSSL builds, hardcoded stacks) that produce distinctive, rarely-seen JA3 hashes. Since malware authors rarely bother randomizing their TLS stack's handshake construction, a JA3 hash that's common in the wild for known malware (e.g., the FoxIO/Abuse.ch-style catalogs) becomes a cheap, decryption-free IOC — you can flag "this beacon is TLS-fingerprinted as Cobalt Strike" from a firewall log alone.
- **Client identification / policy enforcement**: distinguishing curl from browsers from scripted bots hitting an API endpoint, even over TLS, using JA3/JA3S pairs — useful for bot detection, shadow IT discovery (is this actually Chrome or something impersonating Chrome's User-Agent over a non-Chrome TLS stack?).

**Limitations — this is where you cash in your own findings:**

- **JA3 has no semantic understanding, only structural fingerprinting.** It doesn't know what a cipher suite *means*, just its position in a list. This is a feature (library-agnostic) and a bug (trivially gamed by anyone controlling handshake construction).
- **Extension order instability (your actual data)**: You demonstrated that Chrome doesn't just insert GREASE values — it randomizes extension order per-connection (Chrome's "TLS ClientHello Extension Permutation," rolled out ~2023 specifically as an anti-fingerprinting measure). This means the *same physical Chrome process* produces different JA3 hashes across connections. This is strictly worse for JA3 than GREASE alone, since GREASE values are filtered out deterministically, but permutation changes the actual ordered field JA3 hashes over. Cite this as your primary empirical limitation — you have real captures showing it.
- **This is why JA4 exists**: JA4 sorts cipher suites and extensions before hashing specifically to neutralize order-based instability, trading positional information for stability. That's a completeness/robustness tradeoff — sorted fields can no longer trivially distinguish two clients that used the same set of extensions in different orders for legitimate configuration reasons, if such a case existed (rare, but the tradeoff is real).
- **Evasion is a straightforward engineering problem for adversaries**: `curl-impersonate`, JA3-spoofing libraries (`utls` in Go, `curl_cffi`) let malware trivially clone a legitimate browser's JA3/JA4 exactly. Fingerprinting raises attacker cost slightly but is not robust against a motivated adversary who fingerprint-matches on purpose. This is worth stating plainly: **JA3/JA4 are population-level heuristics for lazy/uninstrumented traffic, not cryptographic identity.** They catch unsophisticated malware and passive misconfiguration, not targeted evasion.
- **False positives/CDN collapse problem** (worth a line even if you didn't measure it): many unrelated clients behind the same library version (e.g., every Go binary using default `net/http`) collapse to identical JA3/JA4 hashes, so a hash match is population-level evidence, not individual attribution.

One structural suggestion for the report: pair "limitations" directly with your HelloRetryRequest finding and RFC 8446 §4.1.4 citation as a demonstration that you understand handshake mechanics deeply enough to know what's a protocol quirk vs. an actual limitation of the fingerprinting method — that distinction is exactly what "demonstrated CN understanding" rubric language is fishing for.

Want me to draft the benchmarks/results section structure too, or do you have that data collected already?

## User:

> 9/7/2026 21:23:03

Limitations (not an exhaustive list):

1. C++ engine only works on POSIX machines (libpcap is made for POSIX)
2. We are only matching for certain number of clients, not many

Regarding history/theory - stick to theory, not much of history. The *how* of TLS fingerprinting, down to the byte level.  Instances of switching approaches: Why we using dpkt over Scapy (most important one).  Early prototyping used Scapy for pcap parsing, since it offers built-in TLS dissection (scapy.layers.tls). This was abandoned in favor of dpkt combined with manual struct.unpack-based field extraction. The reasons were both pedagogical and practical: Scapy's TLS layer performs stateful, session-aware dissection, attempting to track negotiated cipher state across a flow. Without the actual session keys, this guessing proved unreliable on real captures — the same encrypted post-handshake traffic was inconsistently labeled across packets (TLS, Padding, _TLSEncryptedContent, even SSLv2 on plain TLS 1.2/1.3 flows), and in at least one observed case, calling bytes() on an already-dissected Scapy TLS object appeared to return re-serialized bytes rather than the original wire bytes, corrupting the record header and causing a ServerHello to be missed entirely during early reassembly testing. The assignment is graded on demonstrated understanding of TLS record and handshake framing, not on library integration. Manually walking the TLV structure (record header → handshake header → cipher suite / extension vectors) is the actual deliverable; letting Scapy dissect it away defeats the purpose even where it works correctly. dpkt performs no interpretation — it exposes raw packet/record bytes and leaves all TLS-specific parsing to our own code, which is byte-for-byte deterministic and independently auditable against RFC 8446 §4 field offsets. For live capture (where dpkt has no native equivalent to Scapy's sniff()), Scapy is retained strictly as a packet delivery mechanism: bytes(pkt.original) is extracted immediately inside the capture callback and handed to the same manual parser used for offline pcap analysis, with no Scapy-level TLS dissection invoked at any point. This preserves a single, consistent parsing code path across both offline and live capture modes. In the C++ engine, we initially generated fingerprints without proper TCP reassembly. We observed that some clienthellos and serverhellos were getting dropped. Initially we were not giving TCP reassembly enough importance. But later we decided to do that, and it made a significant difference! Change cipherspec, at the start of the new packet, we were not counting that, so our parsing was wrong. After a more elaborate look, we identified this issue and updated the parsing logic accordingly.  Most of the pipeline was about reproduction of a well-documented elaborate calculation, so there wasn't much scope of making novel design decisions. I've just dumped whatever context I could gather in an unstructured manner. Based on the assignment spec, the codebase, and whatever context you have so far, generate a complete draft for the report. Note that whatever I've given you is not exhaustive, and also not necessarily in the exact name of the sections or the order. You decide how to structure the report.

## Assistant:

> 9/7/2026 21:25:06

> Drafting a full structured report on the codebase.
>
> - Drafting a full structured report on the codebase.
> - Draft TLS fingerprinting project report combining all sections
> - **Done**

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
