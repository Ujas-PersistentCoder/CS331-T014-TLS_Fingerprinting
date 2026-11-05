"""Deterministic synthetic TCP/TLS exchanges for checkpoint 2, not endpoint labels."""
from pathlib import Path
import struct
import generate_ech_fixture as wire


def client(ech=True, config=139):
    extensions = wire.extension(43, b"\x04\x03\x04\x03\x03")
    if ech:
        extensions += wire.extension(0xfe0d, wire.outer(config=config))
    return wire.hello(extensions)


def server(version=0x0304, hrr=False):
    random = (bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
              if hrr else b"\x42" * 32)
    extensions = wire.extension(43, wire.u16(version)) if version >= 0x0304 else b""
    body = b"\x03\x03" + random + b"\x00\x13\x01\x00" + wire.u16(len(extensions)) + extensions
    return wire.record(b"\x02" + len(body).to_bytes(3, "big") + body)


def generate():
    packets = []
    def send(port, data=b"", seq=100, flags=0x18, reverse=False):
        packets.append(wire.packet(data, port, seq, flags, reverse))
    def start(port):
        send(port, seq=99, flags=0x02)
        send(port, seq=999, flags=0x12, reverse=True)
    for port, ech, version in [(41011, True, 0x0303), (41012, True, 0x0304), (41013, False, 0x0304)]:
        start(port); send(port, client(ech)); send(port, server(version), 1000, reverse=True)
    start(41014)
    ch = client()
    send(41014, ch[:80]); send(41014, ch[50:150], 150); send(41014, ch[150:], 250)
    send(41014, ch)  # Complete retransmission after record delivery.
    send(41014, b"\x14\x03\x03\x00\x01\x01" + server(), 1000, reverse=True)
    start(41015); send(41015, ch[:50]); send(41015, ch[70:], 170)
    send(41015, server(), 1000, reverse=True)
    start(41016); send(41016, ch[:40])
    start(41017); send(41017, ch)
    retry = server(hrr=True); send(41017, retry, 1000, reverse=True)
    send(41017, client(config=7), 100 + len(ch))
    send(41017, server(), 1000 + len(retry), reverse=True)
    start(41018); send(41018, ch); send(41018, b"\xa4\xb5\xc6", 4000, reverse=True)
    send(41018, server(), 1000, reverse=True)
    start(41019); send(41019, ch); send(41019, seq=100 + len(ch), flags=0x11)
    start(41020); send(41020, ch); send(41020, seq=100 + len(ch), flags=0x14)
    start(41020); send(41020, client(False)); send(41020, server(), 1000, reverse=True)
    output = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(packets):
        output.extend(struct.pack("<IIII", 1700000000, index * 1000, len(frame), len(frame)))
        output.extend(frame)
    target = Path(__file__).with_name("ech_checkpoint2.pcap")
    target.write_bytes(output)
    print(f"Wrote {len(packets)} packets to {target}")


if __name__ == "__main__":
    generate()
