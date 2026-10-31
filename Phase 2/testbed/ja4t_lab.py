#!/usr/bin/env python3
"""JA4T cross-layer spoofing lab (Phase 2, Track A).

Synthesises a pcap in which each TCP flow plays one spoofing scenario, plus a lab
catalog that marks the synthetic TLS client as Windows-only (expected_os). Running
the C++ engine over both must raise exactly the expected verdict per flow:

    honest_windows          Windows SYN  + Windows-only TLS      -> CROSS-LAYER OK
    impersonation_linux     Linux SYN    + Windows-only TLS      -> IMPERSONATION_MISMATCH
    injected_hello          SYN TTL 120, ClientHello TTL 47       -> TTL_MISMATCH
    forged_windows_syn      Windows options sent with Linux TTL   -> STACK_ANOMALY
    mid_flow                ClientHello without a captured SYN    -> no JA4T

Usage:
    python ja4t_lab.py [--out DIR] [--engine PATH/TO/tlsfp_phase2]

With --engine the script runs the engine itself and exits non-zero on any mismatch.
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

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT_IP = "10.13.37.10"
SERVER_IP = "93.184.216.34"

# Kernel SYN option layouts, as scapy option lists (see tlsfp/ja4t.cpp KNOWN_LAYOUTS)
WINDOWS_SYN = dict(window=64240, options=[("MSS", 1460), ("NOP", None), ("WScale", 8),
                                          ("NOP", None), ("NOP", None), ("SAckOK", b"")])
LINUX_SYN = dict(window=64240, options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
                                        ("NOP", None), ("WScale", 7)])

# name, client port, SYN stack (None = SYN not captured), SYN TTL, ClientHello TTL, expected tag
SCENARIOS = [
    ("honest_windows",      50001, WINDOWS_SYN, 120, 120, "CROSS-LAYER OK"),
    ("impersonation_linux", 50002, LINUX_SYN,    57,  57, "IMPERSONATION_MISMATCH"),
    ("injected_hello",      50003, WINDOWS_SYN, 120,  47, "TTL_MISMATCH"),
    ("forged_windows_syn",  50004, WINDOWS_SYN,  57,  57, "STACK_ANOMALY"),
    ("mid_flow",            50005, None,          0, 120, "SYN not captured"),
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


def build_pcap(path: Path, hello: bytes) -> None:
    packets = []
    t = 1_700_000_000.0
    for _, port, stack, syn_ttl, hello_ttl, _ in SCENARIOS:
        isn = 1000 * port
        if stack is not None:
            syn = Ether() / IP(src=CLIENT_IP, dst=SERVER_IP, ttl=syn_ttl) / TCP(
                sport=port, dport=443, flags="S", seq=isn, window=stack["window"], options=stack["options"])
            syn.time = t
            packets.append(syn)
        ch = Ether() / IP(src=CLIENT_IP, dst=SERVER_IP, ttl=hello_ttl) / TCP(
            sport=port, dport=443, flags="PA", seq=isn + 1, ack=1, window=1026) / Raw(hello)
        ch.time = t + 0.05
        packets.append(ch)
        t += 1.0
    wrpcap(str(path), packets)


def build_catalog(path: Path, ja3: str) -> None:
    catalog = {"ja3": [{
        "hash": ja3,
        "client": "Lab: Windows-only TLS client (synthetic)",
        "version": "ja4t_lab.py",
        "os": "windows",
        "expected_os": "windows",
        "category": "lab",
        "source": "synthetic: Phase 2/testbed/ja4t_lab.py",
        "notes": "Stands in for an OS-bound TLS stack such as Windows SChannel.",
    }]}
    path.write_text(json.dumps(catalog, indent=2) + "\n")


def verify(engine: Path, pcap: Path, catalog: Path) -> bool:
    result = subprocess.run([str(engine), "-r", str(pcap), "-c", str(catalog)],
                            capture_output=True, text=True, check=False)
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    blocks = re.split(r"\n(?= CLIENT | SERVER |=== )", output)

    ok = True
    for name, port, _, _, _, expected in SCENARIOS:
        block = next((b for b in blocks if f":{port} ──▶" in b), "")
        raised = [tag for tag in ALERT_TAGS if tag in block]
        unexpected = [tag for tag in raised if tag != expected]
        passed = bool(block) and expected in block and not unexpected
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] {name:22s} expected {expected:24s} raised {raised or '-'}")
    if not ok:
        print(output)
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "generated")
    parser.add_argument("--engine", type=Path, help="Path to tlsfp_phase2; verifies verdicts when given")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    pcap, catalog = args.out / "ja4t_lab.pcap", args.out / "ja4t_lab_catalog.json"

    hello, ja3 = build_client_hello("lab.example")
    build_pcap(pcap, hello)
    build_catalog(catalog, ja3)
    print(f"Wrote {pcap}\nWrote {catalog} (JA3 {ja3})")

    if args.engine:
        return 0 if verify(args.engine, pcap, catalog) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
