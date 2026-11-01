"""Regenerate the synthetic checkpoint-1 PCAP; no network access or endpoint secrets.

Run with the project's existing virtual environment. Each TCP source port maps to
one documented test case. These fabricated packets carry no real/acceptance label.
"""

from pathlib import Path
import struct


def u16(value):
    return struct.pack("!H", value)


def extension(kind, body):
    return u16(kind) + u16(len(body)) + body


def outer(enc_length=32, payload_length=208, aead=1, config=139):
    return (b"\x00" + u16(1) + u16(aead) + bytes([config])
            + u16(enc_length) + b"\xab" * enc_length
            + u16(payload_length) + b"\xcd" * payload_length)


def record(body):
    return b"\x16\x03\x01" + u16(len(body)) + body


def hello(extensions):
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00\x00\x02\x13\x01\x01\x00"
            + u16(len(extensions)) + extensions)
    return record(b"\x01" + len(body).to_bytes(3, "big") + body)


def checksum(data):
    data += b"\x00" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(payload, port, sequence=1000):
    source, destination = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 20])
    tcp = struct.pack("!HHIIBBHHH", port, 443, sequence, 1, 0x50, 0x18, 65535, 0, 0)
    pseudo = source + destination + b"\x00\x06" + u16(len(tcp) + len(payload))
    tcp = tcp[:16] + u16(checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0x4000,
                     64, 6, 0, source, destination)
    ip = ip[:10] + u16(checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ip + tcp + payload


def generate():
    ech = lambda body: extension(0xfe0d, body)
    split = hello(ech(outer()))[5:]
    packets = [
        packet(hello(ech(outer())), 41001),
        packet(hello(ech(outer()) + ech(outer(config=7))), 41002),
        packet(hello(ech(outer(payload_length=0))), 41003),
        packet(hello(bytes.fromhex("fe0d000201")), 41004),
        packet(hello(extension(27, b"\x02\x00\x02")), 41005),
        packet(hello(ech(outer(payload_length=1, aead=0xffff)) + ech(b"\x01")
                     + extension(0xfd00, b"\x00")), 41006),
        packet(hello(ech(outer(enc_length=0))), 41007),
        packet(record(split[:80]), 41008),
        packet(record(split[80:]), 41008, sequence=1085),
        packet(hello(extension(21, bytes(8193 - len(hello(b"")) - 4))), 41009),
    ]
    output = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(packets):
        output.extend(struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)))
        output.extend(frame)
    target = Path(__file__).with_name("ech_checkpoint1.pcap")
    target.write_bytes(output)
    print(f"Wrote {len(packets)} synthetic packets to {target}")


if __name__ == "__main__":
    generate()
