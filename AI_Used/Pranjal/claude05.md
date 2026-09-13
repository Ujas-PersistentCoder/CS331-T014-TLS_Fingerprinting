# Recording noisy PCAP for pipeline testing

**Created:** 9/6/2026 10:22:28  
**Updated:** 9/6/2026 11:00:31  
**Exported:** 9/13/2026 14:57:57  
**Link:** [https://claude.ai/chat/4586d6c9-221a-4bc7-ad41-4a4b5129e456](https://claude.ai/chat/4586d6c9-221a-4bc7-ad41-4a4b5129e456)  

## User:

> 9/6/2026 10:22:30

I wanna rigorously test my pipeline through a real-world noisy PCAP. Help me record one using tcpdump or any other tool if that's better

## Assistant:

> 9/6/2026 10:22:57

> Planning a real-world pcap capture for TLS fingerprint testing.
>
> - Planning a real-world pcap capture for TLS fingerprint testing.
> - **Done**

Direct answer, no fluff:

**tcpdump is right, Wireshark/tshark are for later inspection, not capture.** Here's the actual capture command:

```bash
sudo tcpdump -i wlan0 -s 0 -w noisy_capture.pcap 'tcp port 443'
```

Notes on the flags, since they matter:
- `-s 0` — full snaplen, don't truncate. Your parser needs complete handshake bytes; a truncated capture defeats the point of testing your reassembler.
- `-i wlan0` — **use your actual Wi-Fi interface, not `lo` or `any`.** You already noted this in your netem plan — loopback delivers packets with essentially zero jitter and zero real reordering. Real noise (retransmits, OOO, congestion-triggered reordering) only shows up on a real interface with real queueing behavior.
- Drop the port filter if you want non-TLS traffic mixed in too — that's actually useful, since it stress-tests your non-handshake-record-skip fix (Bug #1). `tcp port 443` will still include SYN/FIN/ACK control packets, which is what you want for lifecycle testing.

**Now, "noisy" doesn't happen by asking nicely — you have to manufacture load.** A clean campus Ethernet capture will look almost identical to your synthetic test fixtures: no reordering, no retransmits, no partial overlaps. To get genuine noise:

1. **Congest the link concurrently.** Run a big download or `iperf3` against a public server in the background while capturing, saturating the same NIC. This is what actually produces queuing-induced reordering and drops on Wi-Fi.
2. **Use Wi-Fi, not wired.** Wireless retransmits and reorders far more than Ethernet due to the MAC layer's own ARQ interacting badly with TCP's.
3. **Open many concurrent TLS connections.** Load 15-20 tabs simultaneously, or script parallel `curl` calls to different hosts. This tests whether your per-flow `FlowState` dict in `capture.py` correctly isolates state — a bug where flows leak into each other's buffers won't show up with one connection at a time.
4. **Include large ClientHellos deliberately.** Modern Chrome with many extensions (post-quantum key shares, ECH, etc.) can push the ClientHello past a single MTU, forcing genuine cross-segment TLS record splits — this is the real-world analog of your `test_tls_record_split_across_two_segments` test, and you want to confirm it happens *organically*, not just synthetically.
5. **Capture over a flaky link if you can** — phone hotspot, poor Wi-Fi corner of your dorm — real loss and RTT variance are far better test fuel than a clean uni network.

**Then layer `tc netem` on top for the controllable, reproducible part** (this is what you already scoped as your validation step #2 in memory) — netem gives you *deterministic* reordering/loss percentages so you can write regression tests around specific edge cases (e.g., "does a 50ms reorder-delay with 25% probability ever break `_flush_ooo`"). The organic noisy capture and the netem-controlled capture serve different purposes: organic tells you real traffic doesn't break you; netem tells you *why* if it did, and lets you turn a repro into a permanent test fixture.

One gap I'll flag directly: nothing above gives you IPv6 noise. If your reference DB and grading criteria care about dual-stack correctness, capture at least one round against an IPv6-only or dual-stack endpoint (`curl -6`), since your `parser.py`/`capture.py` code path doesn't currently look IP-version-aware in the reassembly key — worth checking that a 4-tuple isn't accidentally colliding across v4/v6 pairs with the same ports.

## User:

> 9/6/2026 10:27:30

Tell me some other clients to test as well. Like curl, python requests etc

## Assistant:

> 9/6/2026 10:27:49

Your `capture_manifest.json` already lists a lot of good candidates — but a chunk of them are placeholders you haven't actually captured yet (chrome_headless_playwright, node_https_default, go_net_http, java_https_urlconnection, sslyze_scan, testssl_sh_scan, nmap_ssl_enum_ciphers). Prioritize by what gives you the most **pedagogically distinct** fingerprints per unit effort, not just raw count:

**Tier 1 — do these first, they're trivial and maximally distinct:**
- `curl` (default) vs `curl --tlsv1.3` vs `curl` with `--ciphers` restricted — you already have this idea in the manifest, good. Shows the *same binary* produces different JA3 depending on runtime flags, which is a great point for your report (JA3 fingerprints the negotiation, not the binary).
- `openssl s_client` — different TLS stack config surface than curl even though both often link OpenSSL.
- Python `ssl` module raw vs `requests`/`urllib3` — these frequently differ because `requests` sets its own cipher list/context defaults on top of `ssl`. Worth confirming they're actually distinct in your captures, not just assumed to be.
- **wget** — cheap to add, different libcurl/OpenSSL invocation pattern than curl itself; good "same underlying library, different tool" example.

**Tier 2 — meaningfully different TLS stacks (not just OpenSSL wrappers):**
- **Go's `net/http`** — Go has its own from-scratch TLS implementation (`crypto/tls`), not OpenSSL-based. This is one of your best distinguishing examples since the extension ordering/cipher list is structurally different from every OpenSSL-based client above.
- **Node.js `https`** — uses BoringSSL-derived stack via V8's OpenSSL fork, distinct again.
- **Java `HttpsURLConnection`** or `HttpClient` — JSSE stack, very recognizably different JA3 (Java clients are notorious for looking "weird" in JA3 corpora, good report material).
- Rust `reqwest` (rustls backend) if anyone on your team has Rust experience — rustls has a deliberately minimal, very GREASE-free ClientHello, a nice contrast case.

**Tier 3 — browsers, for GREASE narrative:**
- Chrome, Firefox headless — you have these.
- Add **one Chromium-based non-Chrome browser** (Brave/Edge) specifically to demonstrate the point already in your memory notes: Chromium engine → same JA3 skeleton, GREASE causes hash instability across runs regardless of brand. This is a good "same engine, different product" pair to explicitly contrast against your Go/Java "different engine entirely" pairs.

**Tier 4 — the fun evasion angle, since you already scoped it as category "evasion":**
- `curl-impersonate` (Chrome and Firefox mimic builds) — these are specifically built to reproduce browser JA3/JA4, so capturing them and diffing against real Chrome/Firefox is a strong "can JA3 be spoofed, and how well" section for your report. Directly useful for the "limitations" part of your grading criteria.

**Don't bother with**, given your Sept 11 deadline: SSLyze/testssl.sh/nmap scanner fingerprints (interesting but low marginal value vs. effort — scanners get their own signature but don't add pedagogical range over what curl/openssl already show), and the public malware reference PCAPs (legal/sourcing overhead not worth it in the time you have).

Realistic minimum to beat your "≥5 known clients" deliverable with actual variety, in priority order: **curl (default), curl (TLS1.3 forced), Python requests, Chrome headless, Firefox headless, Go net/http, curl-impersonate-chrome**. That's 7, covers 3 genuinely different TLS stack families (OpenSSL/BoringSSL/crypto-go), and gives you both the "config changes fingerprint" and "spoofing" narratives for the report almost for free.

## User:

> 9/6/2026 10:37:29

Give me the commands

## Assistant:

> 9/6/2026 10:37:44

Straight commands, assuming you're capturing per-client with tcpdump running in background then killing it (matches your `capture_harness.sh` labeling convention — label + timestamp).

**Start capture (run this first, one per client, then trigger the request):**
```bash
sudo tcpdump -i wlan0 -s 0 -w pcaps/<label>_$(date +%Y%m%d_%H%M%S).pcap 'tcp port 443' &
TCPDUMP_PID=$!
sleep 1   # let tcpdump actually attach before firing the request
```

Then run the client, then:
```bash
sleep 2   # let final ACKs/FINs land
sudo kill $TCPDUMP_PID
```

Wrap that pattern around each of these:

**1. curl (default)**
```bash
curl -sS https://example.com -o /dev/null
```

**2. curl (TLS 1.3 forced)**
```bash
curl -sS --tlsv1.3 https://example.com -o /dev/null
```

**3. curl (cipher-restricted)**
```bash
curl -sS --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://example.com -o /dev/null
```

**4. openssl s_client**
```bash
echo | openssl s_client -connect example.com:443 -brief 2>/dev/null
```

**5. wget**
```bash
wget -q https://example.com -O /dev/null
```

**6. Python requests**
```bash
pip install requests --break-system-packages   # if not already installed
python3 -c "import requests; requests.get('https://example.com')"
```

**7. Python raw ssl module**
```bash
python3 -c "
import socket, ssl
ctx = ssl.create_default_context()
with socket.create_connection(('example.com', 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname='example.com') as ssock:
        ssock.send(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
        ssock.recv(1)
"
```

**8. Chrome headless**
```bash
google-chrome --headless=new --disable-gpu --dump-dom https://example.com > /dev/null 2>&1
```
(if Chrome isn't installed: `sudo apt install google-chrome-stable` or grab chromium via `sudo apt install chromium-browser`)

**9. Firefox headless**
```bash
firefox --headless --screenshot /tmp/out.png https://example.com
```

**10. Go net/http** — needs a one-line Go program since there's no CLI equivalent:
```bash
cat > /tmp/go_https_test.go << 'EOF'
package main
import ("net/http")
func main() {
    resp, _ := http.Get("https://example.com")
    if resp != nil { resp.Body.Close() }
}
EOF
go run /tmp/go_https_test.go
```
(needs Go installed: `sudo apt install golang-go`)

**11. Node.js https**
```bash
node -e "require('https').get('https://example.com', res => res.resume())"
```

**12. curl-impersonate (Chrome mimic)** — this one needs setup, not a package-manager install:
```bash
# grab the prebuilt binary release
wget https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.1/curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz
tar xzf curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz -C /tmp/curl-impersonate
/tmp/curl-impersonate/curl_chrome116 -sS https://example.com -o /dev/null
```

Practical notes:
- Change `example.com` to whatever your `openssl_s_server`/nginx local target is if you're testing against your own server rather than a live SNI target — matters for whether SNI shows up as populated or absent in your reference DB entries.
- Run these **one at a time**, not concurrently, for your first pass — you want one clean handshake per pcap so labeling in `capture_manifest.json` stays unambiguous. Save the "many concurrent connections" stress test as a separate noisy capture, per what I said earlier.
- After each capture, verify it actually caught a ClientHello before moving on: `tshark -r pcaps/<file>.pcap -Y "tls.handshake.type==1"` — cheap sanity check, saves you from discovering 20 minutes in that your BPF filter or timing was off.

## User:

> 9/6/2026 10:55:49

ok

## Assistant:

> 9/6/2026 10:55:49

Good luck with the captures — ping me if a fingerprint comes out looking wrong or a client won't cooperate.

## User:

> 9/6/2026 10:58:44

> File: 

## Assistant:

> 9/6/2026 11:00:31

> Reviewing timeouts, reassembly stats, and JA3 hash instability causes.
>
> - Reviewing timeouts, reassembly stats, and JA3 hash instability causes.
> - **Done**

Good, real noisy capture — and it surfaced an actual bug, not just artifacts. Breaking down what's in there:

**What's working correctly:**
- GREASE filtering: verbose output prints raw `cipher_suites`/`extensions`/`curves` from the parser (which *deliberately* preserves GREASE), but every JA3 hash correctly excludes it. `64250` (0xFAFA) sitting at the front of the raw ciphers list but absent from the JA3 string confirms `filter_grease` is doing its job end-to-end.
- Reassembly stats are non-trivial and real: `segments_reordered: 13`, `retransmissions_dropped: 5`. That's your Tier 1 reassembler actually exercising the OOO/retransmit paths against genuine network jitter, not synthetic test fixtures. Good evidence for the report.
- `packets_skipped: 0` — no pcap-level dpkt parse failures.

**The actual bug — this is the important one:**

```
src.capture: Handshake type 244 spans records, 32/7268923 bytes buffered
src.capture: Handshake type 101 spans records, 32/11408461 bytes buffered
src.capture: Handshake type 9 spans records, 32/15991401 bytes buffered
```

Handshake type 244 doesn't exist (valid types top out around 24-25, plus 254 for MessageHash). A claimed length of **7.2 million bytes** for a handshake message is nonsense — no real TLS message is that large. You're not parsing a genuine handshake header here; you're parsing random bytes and calling them one.

Here's the mechanism: every connection you captured negotiated TLS 1.3 (`Sup. Ver: 0x0304`). In TLS 1.3, **everything after ServerHello is encrypted** — EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket — and all of it is wrapped at the record layer with `content_type = 23` (Application Data) specifically so middleboxes can't see it's still handshake traffic. Your `_extract_tls` loop correctly skips `content_type != 22` records. The problem is ciphertext is effectively random bytes, and **1 in 256 of those bytes will just happen to equal `0x16`**. When that coincidence lands at a position your loop treats as a fresh record boundary, it reads a garbage "record length," then garbage "handshake type," then garbage "handshake length" — and that's your 7-million-byte phantom message.

Your `content_type not in (20,21,22,23): clear stream` check is actually catching *most* of these false positives (that's why you see `"Non-TLS content type 191, clearing stream"` — a random ciphertext byte landing outside the valid range). But roughly 1-in-64 chance any given ciphertext byte lands specifically on `0x16`, survives that filter, and cascades into a bogus handshake parse that then poisons `pending_handshake` with a length that can never be satisfied — permanently wedging that flow's state until timeout eviction.

**The fix isn't a parsing bug in `parse_handshake_header` — it's architectural.** You have no business running the TLS record/handshake state machine on a flow direction after you've already extracted what you need from it. Once you've pulled a ClientHello from client→server or a ServerHello from server→client, that direction should be marked done and excluded from further record parsing — not fed byte-by-byte into a parser that has no way to distinguish "real TLS 1.2 Certificate chain" from "opaque TLS 1.3 ciphertext that happens to look TLS-record-shaped for a few bytes."

Quick way to confirm this diagnosis before you patch anything: log `flow.lifecycle` state and whether you've already found a ClientHello/ServerHello for that flow key at the moment you hit "spans records" — I'd bet all four garbage cases occur strictly *after* a `[ClientHello]` or `[ServerHello]` was already printed for that same 4-tuple.

**Bonus finding for your report, unrelated to bugs:** look at the four `f-log-extension.grammarly.io` ClientHellos (54675/54678/54679/54683) — same SNI, presumably same Chrome process, four completely different JA3 hashes, and the extensions aren't just reordered by GREASE placement, the *entire extension sequence* is shuffled (`18-65037-23-45...` vs `35-0-45-51764...` vs `0-27-23-11...`). That's Chrome's ClientHello extension permutation feature, not just GREASE insertion. It's a stronger and more citable limitation than GREASE alone: even after stripping GREASE, JA3 still can't stably fingerprint modern Chrome because Chrome randomizes real extension order, not just where GREASE sits in it.

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
