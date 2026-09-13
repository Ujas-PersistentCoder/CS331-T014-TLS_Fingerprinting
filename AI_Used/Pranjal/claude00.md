# Evaluating course projects for networking concepts and team differentiation

**Created:** 8/21/2026 23:21:01  
**Updated:** 8/27/2026 21:09:26  
**Exported:** 9/13/2026 15:10:41  
**Link:** [https://claude.ai/chat/eb48beda-d0ae-4b1a-b66b-85f8040638be](https://claude.ai/chat/eb48beda-d0ae-4b1a-b66b-85f8040638be)  

## User:

> 8/21/2026 23:21:04

> File: CN_Project_list.csv

These are the options we have for course's first half-semester project. I have close to zero conceptual background for any of these projects. We are a team of 5 competent CS students. All of us slightly inclined towards ML/AI background, so of course we have a slight preference for the project ID 5, but analyse each project in an unbiased manner. 
According to the professor, the project will be evaluated more on our understanding of computer networks that we have gained and showcased through this project, not just on the demo and how beautifully we showcase it. 
I want you to dive into each project, skip over the technical details (unless something is abnormally advanced according to you) as we are willing to learn whatever is needed for that project. Focus on the bird's eye view of what we'll be working on and what the end result might look like from a not-so-very technical standpoint, ignoring the implementation-level differences that might occur across teams working on that particular project.
For some of these projects, public GitHub repos or papers might already be available, and the professor is fine with reproducing that, as long as we can showcase our understanding from it very well. 
"Multiple teams may select the same project . There's no cap per project, so don't feel pressure to rush a submission just to claim one. (Except for the SONIC project where only 1-2 teams can select)." That means certain projects might become popular, and while there's no statement regarding whether this will affect our grading, but we as a team really want to make something which stands apart from others' implementations, in case we do end up picking one of the more popular projects. Again, still without deviating much from the original problem statement.
Rate each project in terms of:
networking concepts explainability
"coolness"/wow factor
flexibility of the problem statement (how much novelty / innovation / gimmicks we can introduce in the project without deviating from the problem statement)
difficulty (steep learning curve/time-taking/effortful/error prone)
resume value
modern-day relevance

## Assistant:

> 8/21/2026 23:27:00

> Evaluated seventeen networking projects across six dimensions, flagged project five's weakness.
>
> - View the CN project list CSV
> - I need to work through all 17 projects, giving each a concise overview and then scoring them across the six dimensions the user asked for, while staying objective even though the team seems to favor the ML/AI project.
>   
>   Project 5 is worth flagging specifically since it leans more toward MCP/AI agent work than deep networking, and the professor emphasized grading on CN understanding rather than demo polish. I also want to address the popularity trade-off and note that SONIC (project 10) is capped at 1-2 teams, which could limit that option.
>   
>   Starting with project 0, the DDoS/port-scan detector using AF_XDP, I'm noting it involves deep kernel-level networking work — packet path handling, XDP sockets, and parsing — which gives it strong technical substance to rate against the other projects.
>   
>   Coolness is medium since the ciphertext demo is neat but conceptually familiar, and flexibility is moderate with room for multi-hop or NAT traversal extensions. Difficulty and resume value are both medium-common territory given how many "build your own VPN" tutorials exist, though the concepts stay relevant.
>   
>   Moving to the Blitzping DPDK port with a traceroute GUI, I'm noting it scores high on networking concepts with packet crafting and TTL/traceroute mechanics.
>   
>   This one is high on coolness with a real-time GUI showing hardware-accelerated packet paths, but difficulty is very high given DPDK's notoriously painful setup with driver binding, hugepages, and NUMA configuration plus GUI integration. Resume value is strong since DPDK is a rarer, differentiating skill widely used in telco and cloud dataplanes.
>   
>   Turning to the Network Telemetry Framework option, it's more plumbing-heavy—building a monitoring stack with gRPC, SNMP, REST, and Grafana—so networking depth is medium and coolness is only medium since dashboards are common in every ops demo. …
> - **Done**

Here's a bird's-eye pass on all 17, then a ratings table, then the parts you actually need for the decision (including a hard look at #5).

## What you'd actually end up demoing

**0. AF_XDP DDoS/Port-Scan Detector** — You launch a simulated SYN-flood/port-scan at a machine; your kernel-bypass detector flags and drops it near-instantly while a side-by-side naive Scapy detector visibly chokes. Demo is literally "attack in, defense reacts, here's the latency/CPU graph proving it." Needs Pi5s (course-provided, presumably).

**1. Minimal VPN Tunnel** — Two Pi5s over "hostile" WiFi; Wireshark shows pure ciphertext on the wire while your app traffic works fine underneath, plus a throughput/CPU cost bar chart for encryption vs plaintext.

**2. Blitzping on DPDK + traceroute GUI** — A packet tool that fires at wire-speed bypassing the kernel, with a live GUI lighting up each hop's latency — a souped-up traceroute, benchmarked against stock tools.

**3. Network Telemetry Framework** — A Grafana-style dashboard: live bandwidth/latency across devices, threshold alerts, REST API for history.

**4. Per-Process Bandwidth Tracker (eBPF)** — A homemade "nethogs": live view of which process talks to which IP, how much, over TCP/UDP, with stored history.

**5. MCP Config Assistant** — You type "block outbound traffic except port 443," it translates that to iptables/tc rules, applies them, verifies with ping/iperf3.

**6. MP-QUIC vs MPTCP** — Graphs/tables showing how two multipath transport protocols hold up under induced loss/jitter/path failure for streaming, file transfer, VoIP — ending in a "use X for Y" recommendation.

**7. K8s Self-Healing for Networking** — You deliberately kill CoreDNS / crash the CNI / break a NetworkPolicy, and a custom controller detects and fixes it with no human touching kubectl.

**8. DNS Resolver via AF_XDP** — A resolver that crafts raw packets straight through the NIC, benchmarked against a normal UDP-socket resolver.

**9. Digital Twin for DC Networks** — A simulated data center (routers/switches/servers) in NVIDIA Air where you inject failures and visualize traffic/latency, optionally with an ML load predictor bolted on.

**10. SoNIC Traffic Engineering** *(capped, 1–2 teams)* — An SDN-controlled network that live-monitors load and dynamically reroutes traffic around congestion/failure.

**11. TLS Fingerprinting (JA3/JA3S)** — You sniff HTTPS and, from the handshake shape alone (no ports, no payload), correctly guess Chrome vs curl vs your own script — a party trick that's literally how Cloudflare/Akamai spot bots.

**12. QUIC/MASQUE VPN Comparison** — Multiple implementations of the "new VPN built on HTTP/3" (the tech behind iCloud Private Relay) benchmarked under identical impaired-network conditions, ending in a use-case recommendation.

**13. select → io_uring** — Four versions of the same TCP echo server, benchmarked from 10 to thousands of connections, showing exactly where select/poll fall over.

**14. eTRAN paper reproduction** — Reproduce an NSDI'25 paper's eBPF kernel-transport-bypass results, then push it into a scenario the paper didn't test.

**15. Host stack overhead paper reproduction** — Same idea, older paper, measuring exactly where CPU cycles go in the Linux network stack.

**16. Mini-Katran** — A toy version of Facebook's production L4 load balancer: packets get 5-tuple hashed and rewritten entirely in-kernel via eBPF/XDP, never touching the normal stack, benchmarked against a naive userspace LB.

## Ratings (1–5, higher = more of that quality; for Difficulty, 5 = hardest)

| ID | Project | Net. Depth | Wow | Flexibility | Difficulty | Resume | Modern Relevance |
|---|---|---|---|---|---|---|---|
| 0 | AF_XDP DDoS Detector | 5 | 4 | 3 | 5 | 5 | 5 |
| 1 | Minimal VPN | 3 | 3 | 3 | 3 | 3 | 3 |
| 2 | Blitzping/DPDK | 4 | 4 | 3 | 5 | 4 | 4 |
| 3 | Telemetry Framework | 2 | 3 | 5 | 2 | 3 | 4 |
| 4 | eBPF Bandwidth Tracker | 3 | 3 | 4 | 3 | 4 | 4 |
| 5 | MCP Config Assistant | 2 | 4 | 5 | 2 | 3 | 4 |
| 6 | MP-QUIC vs MPTCP | 5 | 3 | 4 | 3 | 5 | 5 |
| 7 | K8s Self-Healing | 3 | 3 | 4 | 4 | 4 | 4 |
| 8 | DNS Resolver (AF_XDP) | 5 | 4 | 2 | 5 | 4 | 3 |
| 9 | Digital Twin DC | 2 | 4 | 5 | 2 | 3 | 4 |
| 10 | SoNIC Traffic Eng. | 5 | 4 | 4 | 5 | 4 | 3 |
| 11 | TLS Fingerprinting | 4 | 4 | 4 | 3 | 4 | 5 |
| 12 | QUIC/MASQUE Comparison | 5 | 3 | 4 | 4 | 5 | 5 |
| 13 | select→io_uring | 3 | 2 | 3 | 4 | 4 | 4 |
| 14 | eTRAN Paper Repro | 5 | 2 | 2 | 5 | 4 | 4 |
| 15 | Stack Overhead Paper Repro | 4 | 2 | 2 | 3 | 3 | 3 |
| 16 | Mini-Katran | 5 | 5 | 4 | 5 | 5 | 5 |

## The part you need to hear about #5

Be honest with yourself about what #5 actually is: an LLM parses a command, and a rule engine translates it into `iptables`/`tc` calls you'd write in an afternoon. The natural-language interpretation is entirely outsourced to the LLM — you're not implementing anything novel there, you're prompting one. The "flexibility" score is real (you can bolt on any feature you want), but that flexibility lives entirely on the AI/agent side, not the networking side. You could build an extremely polished version of this and demonstrate almost no new networking understanding beyond "I know what `iptables -A INPUT -p tcp --dport 443 -j ACCEPT` does" — which is week-2 material, not a half-semester project's worth.

Given your professor explicitly said grading hinges on CN understanding, not demo polish, this is your weakest option on the axis that matters most, despite being the one your team is drawn to. That's worth sitting with before you commit, especially since your stated reason for leaning toward it (ML/AI inclination) doesn't actually get exercised here — MCP tool-calling isn't ML/AI work in any technical sense, it's API integration.

If you still want it: force real networking content in by having the "rule-based automation" do something non-trivial — detect and resolve conflicting/overlapping rules, reason about rule ordering effects on iptables' first-match semantics, or model the actual effect of `tc` queueing disciplines rather than just applying a bandwidth cap and eyeballing it. Otherwise you're demoing a chatbot with a rules file attached.

## Three other things worth knowing before you pick

**Projects 3, 5, 9 have "choose your own depth" risk.** Nothing about their tooling forces you into hard networking territory — you can finish any of them with a nice dashboard and shallow understanding, or push deliberately into the hard parts (e.g., in #9, actually simulate routing protocol convergence during failures instead of just clicking through NVIDIA Air's demo scenarios). If you pick one of these, the depth is a decision you have to keep making, not something the project hands you.

**#10 (SoNIC) is capped at 1–2 teams** — that's a structural guarantee of differentiation you don't get anywhere else on this list. It's also genuinely hard to stand up (SoNiC + ONOS + OpenFlow, likely all in Mininet since real switches probably aren't available). Worth it only if your team is confident about eating that setup cost early.

**If you want an ML angle without gutting the networking depth**, there are legitimate places to put it: #0 explicitly invites comparing your heuristic detector against something better — swap in a lightweight classifier and you get a real "heuristics vs. learned model" discussion. #11 could use clustering to auto-discover fingerprint families instead of a hand-built DB. #6 could use a classifier to predict which multipath scheduler performs best under given network conditions. All three keep the CN work as the main course and the ML as a genuine addition, not a redirection.

## My actual take, ranked

If it were my team: **#11 (TLS Fingerprinting)** first — deep protocol content, achievable by a team with zero background in one half-semester, a demo that's legible to non-technical viewers, and real modern security relevance. **#6 (MP-QUIC vs MPTCP)** and **#0 (AF_XDP DDoS Detector)** next — both hit hard on depth and resume value, #0 carries more setup risk. **#16 (Mini-Katran)** is the single most impressive project on this list if you have the appetite for eBPF/XDP pain — highest ceiling, highest risk of running out of time.

## User:

> 8/23/2026 23:50:08

I've shortlisted 0,4,5,9,13,16. Help me decide which one to pick for these.

1. 3 weeks time, other course load as well
2. Team of 5
3. We don't know anything in networks, learning for the first time this semester as part of this course.
4. We are good in Python, C/C++ (and vibecoding lol)
5. If any of these projects has been taken up by many other teams, what efforts would we have to put to make our project stand out?

## Assistant:

> 8/23/2026 23:52:20

> Weighed constraints and ranked projects by feasibility.
>
> - I'm weighing the six shortlisted projects against the real constraint of only three weeks alongside other coursework, which means I need to de-risk or eliminate the more ambitious options.
>   
>   A team of five gives room to parallelize but adds coordination overhead, and since everyone is starting with zero networking background this semester, projects needing deep kernel-level plumbing like AF_XDP or DPDK carry steep learning curves that make 0 and 16 especially risky, with 4 and 13 somewhat less so. On the plus side, strong Python/C/C++ skills plus effective use of LLM-assisted coding could speed things up significantly given how much eBPF/XDP tooling and tutorial material already exists.
>   
>   That said, verifier errors and kernel-side debugging remain genuinely hard regardless of LLM help, since they hinge on understanding kernel constraints rather than just writing more code. I'm now reconsidering whether project 0 truly requires full AF_XDP socket programming with UMEM rings, or whether it could be satisfied more simply through basic XDP packet dropping/redirection, which would substantially lower its difficulty.
>   
>   Debugging checksum errors silently drops packets with no clear messages, making this risky. Given the 3-week window with zero networking background and concurrent coursework, both projects 0 and 16 risk consuming the whole time fighting kernel verifier issues rather than showcasing CN understanding—an honest, calibrated warning worth raising given the instruction not to gloss over risks. I'm now weighing project 4's eBPF bandwidth tracker as a less kernel-heavy alternative.
>   
>   Given zero background but three weeks and solid Python/C skills, project 4 seems quite achievable. Project 5, the MCP config assistant, carries the lowest technical risk since it's mostly iptables/tc scripting plus MCP tool wrapping, well-suited to vibecoding. …
> - **Done**

Three weeks, concurrent coursework, and zero networking background changes this a lot from a "which is intellectually richest" question to a "which can we actually finish and defend" question. That reshuffles things — notably, my two favorites from before (0 and 16) both drop hard.

## Why the constraints reshuffle things

**AF_XDP and Mini-Katran (0, 16) get riskier, not just "hard."** Both involve kernel-space debugging — BPF verifier rejections, silent checksum/packet-rewrite bugs — where failures don't give you a clean error message, they give you a dropped packet and you spend a day figuring out why. This is also where "vibecoding" helps you least: an LLM can write plausible BPF code, but verifier errors and kernel memory-model constraints usually need you to actually understand what's happening, not paste-and-retry. With zero prior exposure and 3 weeks split across 5 courses, realistic risk is burning half your timeline just getting a packet to flow correctly, with nothing left for the actual "detect attacks" or "load balance" logic that's the point of the project.

**13 (select→io_uring) benefits most from your specific skillset.** It's pure userspace C/C++ systems programming — no kernel verifier, no BPF bytecode restrictions, just syscalls. This is exactly where vibecoding is most effective (io_uring boilerplate, benchmark harnesses are well-documented) and exactly where your stated C/C++ strength pays off directly.

**4 (bandwidth tracker) is the "real eBPF, but survivable" middle ground.** It attaches to existing kernel tracepoints via bcc/libbpf rather than doing full packet parsing/rewriting — there's a lot of existing reference code (bcc's own `tcptop`-style tools) to build from, so you get genuine eBPF exposure without the AF_XDP-level plumbing.

**9 (digital twin) has a hidden schedule risk**: NVIDIA Air needs external account registration/access before you can even start. On a 3-week clock, any approval delay is dead time you can't get back — worth checking day one, not week two.

**5 (MCP assistant) has zero technical risk and the same grading risk I flagged last time** — that risk doesn't shrink just because time is tight; if anything, it means you have less slack to add the "real depth" layer that makes it defensible.

## Ranked for your actual situation

1. **13 (select→io_uring)** — best fit. Splits cleanly 4 ways across your 5 people (one server implementation each + one person on the benchmarking harness), no kernel-level failure modes, plays to your exact strengths, and it's still solid explainable CN content (socket lifecycle, TCP under load, C10K problem).
2. **4 (bandwidth tracker)** — second choice. Real eBPF/networking exposure, contained scope, good reference material to build from, parallelizes reasonably (hook program / storage / UI / protocol filtering).
3. **5 (MCP assistant)** — safe to finish, but only pick this if you commit *from day one* to building real logic (rule-conflict detection, policy validation against actual test traffic) rather than a chatbot-to-iptables wrapper. If you're doing this as a time-safety pick, budget for that extra layer explicitly — don't treat it as a stretch goal you'll get to "if there's time," because there won't be.
4. **9 (digital twin)** — fine if the NVIDIA Air access is already sorted and you pick one specific hard question to answer deeply (see below), risky otherwise given the external dependency.
5. **0 (AF_XDP DDoS detector)** — I'd only take this if at least two of your five people are genuinely confident with low-level C and comfortable debugging without hand-holding. Otherwise the timeline math doesn't work.
6. **16 (Mini-Katran)** — drop it for this cycle. It was my top unconstrained pick, but it's the single worst fit for "3 weeks, first exposure, other coursework." No partial-credit fallback if the core checksum/rewrite logic doesn't work by deadline.

## Standing out, per project (if it gets popular)

Sequencing note first: with 3 weeks, get the core working and correctly explained *before* spending any time on differentiation. A broken "stand out" feature demoed badly costs you more than a plain, correct, well-understood baseline does.

- **13**: Most teams will stop at throughput-vs-connections graphs. Add syscall-level profiling (`strace`/`perf` counting context switches per request) to show *why* io_uring wins, not just that it does — and test under slow/partial-read clients, where completion-based I/O should show a bigger gap than clean benchmarks reveal.
- **4**: Most versions will just show "process X used Y MB." Add anomaly detection (flag a process suddenly sending 100x its baseline) — turns a monitor into a security tool, which most won't bother with.
- **5**: Everyone will have a chatbot-to-iptables wrapper — that's the commodity part, don't compete there. Differentiate on actual rule-conflict detection/resolution logic and verifying policy correctness against real test traffic, not just "the command ran."
- **9**: Generic "we simulated some scenarios" will be the median submission. Pick one specific, hard question — e.g., how OSPF convergence time scales with topology size, or where your ML predictor actually beats a moving-average baseline — and answer it rigorously instead of demoing breadth.
- **0**: Most teams will demo one obvious flood and call it done. Test against multiple distinct attack shapes (including a slow/low-rate stealth scan) and report false-positive rate under bursty-but-legitimate traffic — that's the part almost everyone skips.
- **16**: Least likely to be crowded, but if it is: most simplified versions hard-code backends and skip failure handling — add real health-checking/failover, and benchmark against an actual serious LB (HAProxy/nginx) instead of a strawman, since beating a real tool fairly is a much stronger claim than beating a naive one.

## User:

> 8/27/2026 21:08:57

No. 11 TLS fingerprinting is the project we have finalised.

## Assistant:

> 8/27/2026 21:09:26

> Validated project choice and architected technical implementation roadmap.
>
> - They picked project 11, which wasn't on their original shortlist but was actually my top recommendation earlier, so this is a solid choice. I should acknowledge it briefly without gushing and pivot to practical next steps given their real constraints — 3 weeks, team of 5, no networking background, strong Python/C/C++ skills.
>   
>   For TLS fingerprinting, the core work breaks down into capturing packets to grab handshake data, parsing the ClientHello/ServerHello fields, computing JA3/JA3S hashes from cipher suites and extensions, building a reference database of known fingerprints, and demonstrating classification on live traffic — with JA4 or ML-based clustering as possible stretch goals.…
> - **Done**

Good call — it was my top pick for exactly your situation: real protocol depth, no kernel-space landmines, achievable from zero background in three weeks, and a demo anyone (including a non-networking professor in a good mood) immediately gets.

One flag since it's not on your original shortlist: make sure the whole team is on board and someone's checked hardware/OS requirements aren't an issue (it's just packet capture + hashing, so should be fine on laptops — no Pi5/DPDK dependency here, which is a genuine plus over your shortlisted options).

**Reality check on scope for 3 weeks / zero background:**

The project has a natural three-layer structure that splits well across 5 people:

1. **Capture + parse** (1–2 people) — get libpcap/Scapy hooked in, pull out ClientHello/ServerHello, and actually understand the byte layout (TLS version, cipher suite list, extensions, elliptic curves, EC point formats). This is where you'll spend most of week 1 — reading RFC 8446 sections on handshake structure, staring at Wireshark's TLS dissector.
2. **JA3/JA3S computation + reference DB** (1–2 people) — the JA3 algorithm itself is trivial (concatenate fields, MD5 hash), the actual work is validating your hashes against published reference values and curating a DB of 5+ distinct clients (browsers, curl, a couple of custom scripts using different TLS libraries — try Python's `ssl`, `requests`, `curl`, maybe a Go or Rust HTTP client to get genuinely different fingerprints).
3. **Stretch / analysis** (1 person, or whoever finishes early) — JA4/JA4S, or the evasion angle.

**The one technical gotcha worth knowing now, not week 3:** modern Chrome/Firefox randomize the *order* of extensions in ClientHello (GREASE) specifically to defeat JA3 fingerprinting. If you naively capture "Chrome" traffic across multiple runs, you'll get different JA3 hashes for the same browser and your demo will look broken. This is actually a gift for your report — "we hit fingerprint instability, here's why, here's how JA4 or extension-sorting addresses it" is exactly the kind of understanding-over-demo-polish story your professor wants. Don't let the team discover this in a panic the night before the demo.

**Suggested 3-week shape:**
- Week 1: TLS handshake structure + working capture/parse pipeline
- Week 2: JA3/JA3S hashing + reference DB, validated against known hashes
- Week 3: Handle the randomization gotcha, stretch goal (JA4 or a clustering angle if you want to sneak ML in tastefully), polish + report

Want me to help with anything concrete next — a more detailed week-by-week task split by name, or a starting point for the capture/parsing code?

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
