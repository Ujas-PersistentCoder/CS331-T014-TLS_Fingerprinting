# Understanding packet layer encapsulation in Wireshark

**Created:** 8/30/2026 18:07:55  
**Updated:** 8/30/2026 18:08:22  
**Exported:** 9/13/2026 14:56:51  
**Link:** [https://claude.ai/chat/31ae64cb-2e09-4eb3-bbe3-3aa3f8e07608](https://claude.ai/chat/31ae64cb-2e09-4eb3-bbe3-3aa3f8e07608)  

## User:

> 8/30/2026 18:07:58

1 0.000000 10.7.17.176 1.1.1.1 ICMP 58 Echo (ping) request id=0xc415, seq=0/0, ttl=64 (reply in 2)
2 0.008944 1.1.1.1 10.7.17.176 ICMP 60 Echo (ping) reply id=0xc415, seq=0/0, ttl=128 (request in 1)
3 0.052783 10.7.17.176 224.0.0.251 MDNS 85 Standard query 0x0000 A homeassistant.local, "QM" question AAAA homeassistant.local, "QM" question
4 0.052861 fe80::1852:eaf4:c7c4:4ec7 ff02::fb MDNS 105 Standard query 0x0000 A homeassistant.local, "QM" question AAAA homeassistant.local, "QM" question
5 1.000212 10.7.17.176 1.1.1.1 ICMP 58 Echo (ping) request id=0xc415, seq=0/0, ttl=64 (reply in 6)
6 1.009060 1.1.1.1 10.7.17.176 ICMP 60 Echo (ping) reply id=0xc415, seq=0/0, ttl=128 (request in 5)
7 1.995136 10.7.17.176 1.1.1.1 ICMP 58 Echo (ping) request id=0xc415, seq=0/0, ttl=64 (reply in 8)
8 2.002842 1.1.1.1 10.7.17.176 ICMP 60 Echo (ping) reply id=0xc415, seq=0/0, ttl=128 (request in 7)
9 2.616332 10.7.17.176 13.67.9.5 TLSv1.2 906 Application Data
10 2.622003 13.200.41.143 10.7.17.176 TLSv1.2 110 Application Data
11 2.622194 10.7.17.176 13.200.41.143 TCP 66 57664 → 443 [ACK] Seq=1 Ack=45 Win=2048 Len=0 TSval=1976399836 TSecr=2677342945
12 2.702241 13.67.9.5 10.7.17.176 TLSv1.2 463 Application Data
13 2.702392 10.7.17.176 13.67.9.5 TCP 66 59281 → 443 [ACK] Seq=841 Ack=398 Win=2042 Len=0 TSval=2424050407 TSecr=1012240416
14 2.777274 10.7.17.176 104.20.23.154 TCP 78 59332 → 443 [SYN, ECE, CWR] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 TSval=679156093 TSecr=0 SACK_PERM
15 2.813483 104.20.23.154 10.7.17.176 TCP 74 443 → 59332 [SYN, ACK, ECE] Seq=0 Ack=1 Win=65535 Len=0 MSS=1400 SACK_PERM TSval=4243021639 TSecr=679156093 WS=8192
16 2.813569 10.7.17.176 104.20.23.154 TCP 66 59332 → 443 [ACK] Seq=1 Ack=1 Win=131904 Len=0 TSval=679156130 TSecr=4243021639
17 2.814722 10.7.17.176 104.20.23.154 TCP 1454 59332 → 443 [ACK] Seq=1 Ack=1 Win=131904 Len=1388 TSval=679156131 TSecr=4243021639 [TCP PDU reassembled in 18]
18 2.814733 10.7.17.176 104.20.23.154 TLSv1.3 245 Client Hello (SNI=example.com)

This is part of a reading I've copy-pasted from Wireshark. I don't understand how to interpret the layer encapsulation in this. Why are packets tied to protocols? Why is there a separate TCP packet and separate TLS packet? Can a single packet not contain both TCP (in Layer 4) and TLS (in layer 5)? Or are these packets not the same as what we call packets in the following sense:

```
┌───────────────────────────┐
│ Ethernet Header           │
├───────────────────────────┤
│ IP Header                 │
│ TCP Header                │
│ TCP Payload               │
└───────────────────────────┘
```

## Assistant:

> 8/30/2026 18:08:22

> Clarified protocol layering and Wireshark's display conventions.
>
> - This is a conceptual networking question about how Wireshark displays and labels captured frames. Every frame does contain all the encapsulated layers - Ethernet, IP, TCP, and payload - but Wireshark's Protocol column just shows the highest-layer protocol it recognizes for that frame, not the full stack.
>   
>   So a frame labeled TLSv1.3 still has a TCP header underneath - it's simply a TCP segment carrying a TLS ClientHello, and Wireshark shows the more interesting top-layer name for readability. A pure ACK with no payload gets labeled TCP since there's nothing above it to dissect, while frames carrying parseable TLS data get labeled TLS. I should also mention the "[TCP PDU reassembled in 18]" note, which reflects a single TLS record split across multiple TCP segments that Wireshark stitches back together for display, and clarify the frame/packet/segment terminology hierarchy since this connects directly to their TLS fingerprinting project work with manual byte extraction.…
> - **Done**

Good question, and the confusion is legitimate — it's a labeling issue in Wireshark, not a difference in what's actually captured.

**Every single frame Wireshark shows you contains all the layers below whatever protocol name it displays.** Frame 18 is not "just a TLS packet" — it's the full stack:

```
┌───────────────────────────┐
│ Ethernet Header           │
├───────────────────────────┤
│ IP Header                 │
├───────────────────────────┤
│ TCP Header                │
├───────────────────────────┤
│ TLS Record (ClientHello)  │  ← this is the "TCP Payload"
└───────────────────────────┘
```

The "Protocol" column in Wireshark's summary view just shows the **highest-layer protocol it managed to dissect** for that frame — not the only protocol present. Wireshark parses top-down: Ethernet → IP → TCP → and then, if the TCP payload looks like something it recognizes (TLS handshake, HTTP, DNS, etc.), it labels the row with that instead of just saying "TCP." It's a display convenience, nothing more.

So why do some rows say "TCP" and others say "TLSv1.2" or "TLSv1.3"?

- Rows 11, 13, 16 say **TCP** because they carry `Len=0` — pure ACKs with no payload. There's nothing above the TCP header for Wireshark to dissect, so TCP is the deepest layer it can name.
- Rows 9, 10, 12, 18 say **TLSv1.2/TLSv1.3** because they carry a TCP payload that Wireshark's TLS dissector successfully parsed as a TLS record. Underneath, the TCP header is still fully there — you'll see it if you expand the packet detail pane, just not in the one-line summary.

The `[TCP PDU reassembled in 18]` note on packet 17 is the other piece worth understanding for your project: a single TLS record (here, the ClientHello) was too big for one TCP segment, so it got split across packets 17 and 18 at the IP/TCP level. Wireshark buffers and reassembles the TCP stream before it can hand a complete TLS record to its TLS dissector — which is exactly the "manual TCP reassembly buffering" step you've already planned for your pipeline. This is also why your parser can't just read one packet at a time and assume it has a full ClientHello — you need to reassemble the TCP byte stream first, then slice out TLS records from that stream, since a ClientHello with a lot of extensions (which is common with Chrome/GREASE) routinely spans multiple TCP segments.

One more terminology nuance since you'll want it precise for your report: strictly speaking, "frame" = the Ethernet-layer capture unit (what each Wireshark row is), "packet" = the IP-layer PDU inside it, "segment" = the TCP-layer PDU inside that, and "TLS record" = the layer above TCP. People say "packet" loosely for all of these, but your write-up will look sharper if you use the precise terms when discussing reassembly.

Powered by Claude Exporter (https://www.ai-chat-exporter.net)
