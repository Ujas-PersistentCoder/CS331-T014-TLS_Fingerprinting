#!/usr/bin/env python3
"""JA4T cross-layer spoofing lab (Phase 2, Track A).

Synthesises a pcap in which each TCP flow plays one spoofing scenario, plus a lab
catalog that marks the synthetic TLS client as Windows-only (expected_os). Running
the C++ engine over both must raise exactly the expected verdict per flow.

Spoofing that must be detected:
    impersonation_linux     Linux SYN    + Windows-only TLS      -> IMPERSONATION_MISMATCH
    impersonation_macos     macOS SYN    + Windows-only TLS      -> IMPERSONATION_MISMATCH
    impersonation_freebsd   FreeBSD SYN  + Windows-only TLS      -> IMPERSONATION_MISMATCH
    forged_windows_syn      Windows options sent with Linux TTL   -> STACK_ANOMALY
    linux_ttl_rewrite       Linux options, TTL set to 128         -> STACK_ANOMALY
                            (sysctl net.ipv4.ip_default_ttl=128 changes TTL, not options)
    rapid_tuple_reuse       New SYN with a different ISN on the same 4-tuple -> new JA4T
    malformed_syn           Zero-length option (Windows TTL)      -> STACK_ANOMALY
    window_scale_15         Window scale shift 15 (RFC 7323 max 14) -> STACK_ANOMALY
    injected_hello          SYN TTL 120, ClientHello TTL 47       -> TTL_MISMATCH
    injected_server_hello   SYN-ACK TTL 52, ServerHello TTL 200   -> TTL_MISMATCH (server side)

Honest traffic that must NOT alert (false-positive guards):
    honest_windows          Windows SYN  + Windows-only TLS      -> CROSS-LAYER OK
    honest_windows_ts       Windows SYN with timestamps on        -> CROSS-LAYER OK
    honest_windows_ipv6     Windows SYN over IPv6                 -> CROSS-LAYER OK
    ttl_jitter              SYN TTL 120, ClientHello TTL 119      -> CROSS-LAYER OK (1-hop tolerance)
    cdn_synack              Linux SYN-ACK options with TTL 128    -> no alert (normal for CDNs)
    retransmitted_syn       Full SYN, then option-stripped resend -> JA4T of the first SYN

Known limit (documented, not a bug):
    full_spoof              Raw-socket SYN copying Windows options AND TTL -> CROSS-LAYER OK
                            JA4T raises the cost of spoofing; it cannot see a perfect copy.

Correlation edge cases:
    mid_flow                ClientHello without a captured SYN    -> no JA4T
    expired_syn             ClientHello 30+ seconds after SYN      -> no JA4T

Usage:
    python ja4t_lab.py [--out DIR] [--engine PATH/TO/tlsfp_phase2]

With --engine the script runs the engine (with -t -v) and exits non-zero on any mismatch,
checking both the alert and, where listed, the verbose JA4T diagnostics.
The lab catalog is loaded with `-c`; like `-u` enrollments, its single JA3 record is
written to Redis when Redis is running.
"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

from scapy.all import IP, IPv6, TCP, Ether, Raw, wrpcap

CLIENT_IP = "10.13.37.10"
SERVER_IP = "93.184.216.34"
CLIENT_IP6 = "2001:db8::10"
SERVER_IP6 = "2001:db8::443"

# Kernel SYN option layouts, as scapy option lists (see tlsfp/ja4t.cpp KNOWN_LAYOUTS)
WINDOWS_SYN = dict(window=64240, options=[("MSS", 1460), ("NOP", None), ("WScale", 8),
                                          ("NOP", None), ("NOP", None), ("SAckOK", b"")])
# Same stack over IPv6: the 40-byte IPv6 header lowers MSS to 1440 on a 1500-byte link
WINDOWS_V6_SYN = dict(window=64800, options=[("MSS", 1440), ("NOP", None), ("WScale", 8),
                                             ("NOP", None), ("NOP", None), ("SAckOK", b"")])
WINDOWS_TS_SYN = dict(window=64240, options=[("MSS", 1460), ("NOP", None), ("WScale", 8), ("NOP", None),
                                             ("NOP", None), ("Timestamp", (1, 0)), ("NOP", None),
                                             ("NOP", None), ("SAckOK", b"")])
LINUX_SYN = dict(window=64240, options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
                                        ("NOP", None), ("WScale", 7)])
# 22 option bytes; scapy pads with two EOL bytes, exactly like macOS (2-1-3-1-1-8-4-0-0)
MACOS_SYN = dict(window=65535, options=[("MSS", 1460), ("NOP", None), ("WScale", 6), ("NOP", None),
                                        ("NOP", None), ("Timestamp", (1, 0)), ("SAckOK", b"")])
FREEBSD_SYN = dict(window=65535, options=[("MSS", 1460), ("NOP", None), ("WScale", 6), ("SAckOK", b""),
                                          ("Timestamp", (1, 0))])
# MSS, then Window Scale with a zero length byte: kernels stop parsing and accept the SYN
MALFORMED_SYN = dict(window=64240, raw_options=bytes([2, 4, 0x05, 0xB4, 3, 0, 0, 0]))
# Windows layout with an impossible window scale shift (RFC 7323 caps it at 14)
WS15_SYN = dict(window=64240, options=[("MSS", 1460), ("NOP", None), ("WScale", 15),
                                       ("NOP", None), ("NOP", None), ("SAckOK", b"")])
# BSD-style retransmission that drops everything but MSS; JA4T must keep the first SYN
RETRANSMITTED_SYN = dict(WINDOWS_SYN, retransmit_options=[("MSS", 1460)])
# Linux server SYN-ACK (as sent by most CDN / cloud front ends)
LINUX_SYNACK = dict(window=65160, options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 1)),
                                           ("NOP", None), ("WScale", 7)])


def scenario(name, port, syn, syn_ttl, hello_ttl, expect, **extra):
    defaults = dict(role="client", ipv6=False, verbose=())
    return {**defaults, **extra, "name": name, "port": port, "syn": syn, "syn_ttl": syn_ttl,
            "hello_ttl": hello_ttl, "expect": expect}


# expect: alert tag, "CROSS-LAYER OK", "SYN not captured" or a JA4T string that must appear.
# verbose: substrings that must appear in the same block of the -v output.
SCENARIOS = [
    scenario("honest_windows",        50001, WINDOWS_SYN,   120, 120, "CROSS-LAYER OK",
             verbose=("Corroborated: layout and TTL agree", "MTU 1500")),
    scenario("impersonation_linux",   50002, LINUX_SYN,      57,  57, "IMPERSONATION_MISMATCH"),
    scenario("injected_hello",        50003, WINDOWS_SYN,   120,  47, "TTL_MISMATCH"),
    scenario("forged_windows_syn",    50004, WINDOWS_SYN,    57,  57, "STACK_ANOMALY",
             verbose=("ANOMALY: Incompatible layout & TTL",)),
    scenario("mid_flow",              50005, None,            0, 120, "SYN not captured"),
    scenario("expired_syn",           50006, WINDOWS_SYN,   120, 120, "SYN not captured"),
    scenario("malformed_syn",         50007, MALFORMED_SYN, 120, 120, "STACK_ANOMALY",
             verbose=("MALFORMED",)),
    scenario("retransmitted_syn",     50008, RETRANSMITTED_SYN, 120, 120, "64240_2-1-3-1-1-4_1460_8"),
    scenario("rapid_tuple_reuse",    50019, WINDOWS_SYN,       120,  57, "IMPERSONATION_MISMATCH",
             reused_syn=LINUX_SYN, reused_syn_ttl=57),
    scenario("impersonation_macos",   50009, MACOS_SYN,         64,  64, "IMPERSONATION_MISMATCH",
             verbose=("layout: macOS/iOS",)),
    scenario("impersonation_freebsd", 50010, FREEBSD_SYN,    57,  57, "IMPERSONATION_MISMATCH",
             verbose=("layout: Unix-like",)),
    scenario("linux_ttl_rewrite",     50011, LINUX_SYN,     120, 120, "STACK_ANOMALY",
             verbose=("layout: Linux | TTL family: Windows",)),
    scenario("window_scale_15",       50012, WS15_SYN,      120, 120, "STACK_ANOMALY",
             verbose=("invalid: RFC 7323", "MALFORMED")),
    scenario("honest_windows_ts",     50013, WINDOWS_TS_SYN, 120, 120, "CROSS-LAYER OK",
             verbose=("Timestamps: enabled",)),
    scenario("honest_windows_ipv6",   50014, WINDOWS_V6_SYN, 120, 120, "CROSS-LAYER OK", ipv6=True,
             verbose=("MTU 1500 over IPv6",)),
    scenario("ttl_jitter",            50015, WINDOWS_SYN,   120, 119, "CROSS-LAYER OK"),
    scenario("full_spoof",            50016, WINDOWS_SYN,   128, 128, "CROSS-LAYER OK"),
    # Server side: the verdict is read from the SERVER block of the same connection
    scenario("injected_server_hello", 50017, WINDOWS_SYN,   120, 120, "TTL_MISMATCH", role="server",
             synack=LINUX_SYNACK, synack_ttl=52, server_hello_ttl=200),
    scenario("cdn_synack",            50018, WINDOWS_SYN,   120, 120, "JA4TS: 65160_2-4-8-1-3_1460_7",
             role="server", synack=LINUX_SYNACK, synack_ttl=120, server_hello_ttl=120,
             verbose=("normal for CDN / load-balancer SYN-ACKs",)),
]
ALERT_TAGS = ("IMPERSONATION_MISMATCH", "TTL_MISMATCH", "STACK_ANOMALY")

CIPHERS = (0xC02C, 0xC02B, 0xC030, 0xC02F, 0x009F, 0x009E)
GROUPS = (0x001D, 0x0017, 0x0018)
SIGALGS = (0x0804, 0x0401, 0x0403)


def build_client_hello(sni: str) -> tuple[bytes, str]:
    """Returns a TLS 1.2 ClientHello record and its JA3 MD5."""
    host = sni.encode()
    extensions = [
        (0x0000, struct.pack("!HBH", len(host) + 3, 0, len(host)) + host),
        (0x000A, struct.pack("!H", 2 * len(GROUPS)) + b"".join(struct.pack("!H", g) for g in GROUPS)),
        (0x000B, bytes([1, 0])),
        (0x000D, struct.pack("!H", 2 * len(SIGALGS)) + b"".join(struct.pack("!H", s) for s in SIGALGS)),
    ]
    ext_bytes = b"".join(struct.pack("!HH", kind, len(data)) + data for kind, data in extensions)
    body = (struct.pack("!H", 0x0303) + bytes(32) + b"\x00"
            + struct.pack("!H", 2 * len(CIPHERS)) + b"".join(struct.pack("!H", c) for c in CIPHERS)
            + b"\x01\x00" + struct.pack("!H", len(ext_bytes)) + ext_bytes)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    ja3 = ",".join([
        str(0x0303),
        "-".join(str(c) for c in CIPHERS),
        "-".join(str(kind) for kind, _ in extensions),
        "-".join(str(g) for g in GROUPS),
        "0",
    ])
    return record, hashlib.md5(ja3.encode()).hexdigest()


def build_server_hello() -> bytes:
    """Returns a TLS 1.2 ServerHello record (ECDHE-RSA-AES128-GCM, renegotiation_info only)."""
    ext = struct.pack("!HHB", 0xFF01, 1, 0)
    body = (struct.pack("!H", 0x0303) + bytes(32) + b"\x00" + struct.pack("!H", 0xC02F) + b"\x00"
            + struct.pack("!H", len(ext)) + ext)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def ip_layer(sc: dict, ttl: int, to_server: bool):
    if sc["ipv6"]:
        src, dst = (CLIENT_IP6, SERVER_IP6) if to_server else (SERVER_IP6, CLIENT_IP6)
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IPv6(src=src, dst=dst, hlim=ttl)
    src, dst = (CLIENT_IP, SERVER_IP) if to_server else (SERVER_IP, CLIENT_IP)
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst, ttl=ttl)


def build_tcp(sc: dict, stack: dict, ttl: int, flags: str, seq: int, ack: int = 0, options=None,
              to_server: bool = True):
    sport, dport = (sc["port"], 443) if to_server else (443, sc["port"])
    ip = ip_layer(sc, ttl, to_server)
    raw_options = stack.get("raw_options", b"")
    if raw_options:
        # scapy would re-encode a malformed option, so write it raw behind a matching data offset
        tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=stack["window"],
                  dataofs=5 + len(raw_options) // 4)
        return ip / tcp / Raw(raw_options)
    return ip / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=stack["window"],
                    options=stack["options"] if options is None else options)


def build_pcap(path: Path, hello: bytes, server_hello: bytes) -> None:
    packets = []
    t = 1_700_000_000.0

    def add(pkt, at):
        pkt.time = at
        packets.append(pkt)

    for sc in SCENARIOS:
        isn, server_isn = 1000 * sc["port"], 7000 * sc["port"]
        hello_isn = isn
        stack = sc["syn"]
        if stack is not None:
            add(build_tcp(sc, stack, sc["syn_ttl"], "S", isn), t)
            if "retransmit_options" in stack:
                add(build_tcp(sc, stack, sc["syn_ttl"], "S", isn, options=stack["retransmit_options"]), t + 0.02)
            if "reused_syn" in sc:
                hello_isn += 1
                add(build_tcp(sc, sc["reused_syn"], sc["reused_syn_ttl"], "S", hello_isn), t + 0.02)
        if "synack" in sc:
            add(build_tcp(sc, sc["synack"], sc["synack_ttl"], "SA", server_isn, hello_isn + 1, to_server=False), t + 0.03)
        hello_at = t + (31.0 if sc["name"] == "expired_syn" else 0.05)
        add(ip_layer(sc, sc["hello_ttl"], True) / TCP(
            sport=sc["port"], dport=443, flags="PA", seq=hello_isn + 1, ack=server_isn + 1, window=1026) / Raw(hello),
            hello_at)
        if "server_hello_ttl" in sc:
            add(ip_layer(sc, sc["server_hello_ttl"], False) / TCP(
                sport=443, dport=sc["port"], flags="PA", seq=server_isn + 1, ack=hello_isn + 1 + len(hello),
                window=501) / Raw(server_hello), hello_at + 0.03)
        t += 32.0 if sc["name"] == "expired_syn" else 1.0
    wrpcap(str(path), packets)


def build_catalog(path: Path, ja3: str) -> None:
    catalog = {"ja3": [{
        "hash": ja3,
        "client": "Lab: Windows-only TLS client (synthetic)",
        "version": "ja4t_lab.py",
        "os": "windows",
        "expected_os": "windows",
        "category": "lab",
        "source": "synthetic: Phase 2/code/testbed/ja4t_lab.py",
        "notes": "Stands in for an OS-bound TLS stack such as Windows SChannel.",
    }]}
    path.write_text(json.dumps(catalog, indent=2) + "\n")


def find_block(blocks: list[str], sc: dict) -> str:
    role = " CLIENT " if sc["role"] == "client" else " SERVER "
    for block in blocks:
        header = block.lstrip("\n").splitlines()[0] if block.strip() else ""
        if not (" " + header.strip()).startswith(role):
            continue
        # Client: "<client>:<port> ──▶ ...", server: "... ──▶ <client>:<port>"
        if (sc["role"] == "client" and f":{sc['port']} ──▶" in header) or \
           (sc["role"] == "server" and header.rstrip().endswith(f":{sc['port']}")):
            return block
    return ""


def verify(engine: Path, pcap: Path, catalog: Path) -> bool:
    result = subprocess.run([str(engine.resolve()), "-r", str(pcap), "-t", "-v", "-c", str(catalog)],
                            capture_output=True, text=True, check=False)
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    blocks = re.split(r"\n(?= CLIENT | SERVER |=== )", output)

    ok = result.returncode == 0
    for sc in SCENARIOS:
        block = find_block(blocks, sc)
        raised = [tag for tag in ALERT_TAGS if f"⚠ {tag}" in block or f"✖ {tag}" in block]
        unexpected = [tag for tag in raised if tag != sc["expect"]]
        missing_verbose = [v for v in sc["verbose"] if v not in block]
        passed = bool(block) and sc["expect"] in block and not unexpected and not missing_verbose
        ok &= passed
        detail = f"  missing verbose {missing_verbose}" if missing_verbose else ""
        print(f"[{'PASS' if passed else 'FAIL'}] {sc['name']:22s} expected {sc['expect']:32s} "
              f"raised {raised or '-'}{detail}")
    if not ok:
        print(output)
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[3] / "build/ja4t-lab")
    parser.add_argument("--engine", type=Path, help="Path to tlsfp_phase2; verifies verdicts when given")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    pcap, catalog = args.out / "ja4t_lab.pcap", args.out / "ja4t_lab_catalog.json"

    hello, ja3 = build_client_hello("lab.example")
    build_pcap(pcap, hello, build_server_hello())
    build_catalog(catalog, ja3)
    print(f"Wrote {pcap} ({len(SCENARIOS)} scenarios)\nWrote {catalog} (JA3 {ja3})")

    if args.engine:
        return 0 if verify(args.engine, pcap, catalog) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
