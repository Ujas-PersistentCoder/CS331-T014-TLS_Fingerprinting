"""Independent TShark wire checks, including its GREASE signature-ID behavior."""

import hashlib
import json
import subprocess


def grease(value):
    return value >> 8 == value & 255 and value & 0x0f0f == 0x0a0a


def normalize_ja4(raw):
    prefix, ciphers, extensions, *signatures = raw.split("_")
    signature_ids = [value for value in signatures[0].split(",") if value and not grease(int(value, 16))] if signatures else []
    ext_input = extensions + ("_" + ",".join(signature_ids) if signature_ids else "")
    cipher_hash = hashlib.sha256(ciphers.encode()).hexdigest()[:12]
    ext_hash = hashlib.sha256(ext_input.encode()).hexdigest()[:12]
    return f"{prefix}_{cipher_hash}_{ext_hash}"


def tshark_fields(pcap, display_filter, fields):
    args = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        args += ["-e", field]
    process = subprocess.run(args, capture_output=True, text=True, check=True)
    return [dict(zip(fields, line.split("\t"))) for line in process.stdout.splitlines()]


def verify_pilot(path):
    engine = [json.loads(line) for line in (path / "engine.jsonl").read_text().splitlines()]
    fields = ["frame.number", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tls.handshake.random",
              "tls.ech.hpke.keyconfig.cipher_suite.kdf_id", "tls.ech.hpke.keyconfig.cipher_suite.aead_id",
              "tls.ech.config_id", "tls.ech.enc_length", "tls.ech.payload_length",
              "tls.handshake.extensions_supported_group", "tls.handshake.extensions_key_share_group",
              "tls.handshake.ja3", "tls.handshake.ja4", "tls.handshake.ja4_r"]
    hellos = tshark_fields(path / "capture.pcap", "tls.handshake.type == 1", fields)
    servers = tshark_fields(path / "capture.pcap", "tls.handshake.type == 2",
                           ["tcp.dstport", "tls.handshake.extensions.supported_version"])
    clients = {row["outer_random"]: row for row in
               [json.loads(line) for line in (path / "clients.jsonl").read_text().splitlines()]}
    checks, errors = [], []
    for wire in hellos:
        random = wire["tls.handshake.random"]
        matches = [row for row in engine if row["client"].get("outer_random") == random]
        if len(matches) != 1 or random not in clients:
            errors.append(f"frame {wire['frame.number']} has no unique independent join")
            continue
        observation, client = matches[0], clients[random]
        side = observation["client_endpoint"]
        src, dst = observation[f"endpoint_{side}"], observation["endpoint_b" if side == "a" else "endpoint_a"]
        if (wire["ip.src"], int(wire["tcp.srcport"]), wire["ip.dst"], int(wire["tcp.dstport"])) != (src["ip"], src["port"], dst["ip"], dst["port"]):
            errors.append("wire tuple mismatch")
        body = observation["client"]["ech"]["occurrences"][0]
        for name, field in zip(("kdf_id", "aead_id", "config_id", "enc_length", "ciphertext_length"), fields[6:11]):
            if int(wire[field]) != body[name]:
                errors.append(f"wire {name} mismatch")
        for field in fields[11:13]:
            values = [int(value, 0) for value in wire[field].split(",")]
            groups = [value for value in values if not grease(value)]
            if groups != [{"A": 29, "B": 23}[client["profile"]]]:
                errors.append("wire TLS group/key-share mismatch")
        normalized = normalize_ja4(wire["tls.handshake.ja4_r"])
        if wire["tls.handshake.ja3"] != observation["client"]["ja3"]:
            errors.append("wire JA3 mismatch")
        if normalized != observation["client"]["ja4"]:
            errors.append("normalized wire JA4 mismatch")
        versions = [row for row in servers if int(row["tcp.dstport"]) == src["port"]]
        if len(versions) != 1 or int(versions[0]["tls.handshake.extensions.supported_version"], 0) != 772:
            errors.append("wire server version mismatch or retry")
        checks.append({"frame": int(wire["frame.number"]), "outer_random": random,
                       "tshark_ja4": wire["tls.handshake.ja4"], "normalized_ja4": normalized,
                       "profile": client["profile"], "ech": body})
    if len(checks) != len(engine) or len(checks) != 3:
        errors.append("pilot must have exactly three verified hello pairs")
    return {"passed": not errors, "errors": errors, "checks": checks}
