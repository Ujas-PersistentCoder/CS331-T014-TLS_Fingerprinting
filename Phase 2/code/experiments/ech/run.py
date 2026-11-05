#!/usr/bin/env python3
"""Reproducible local ECH experiments. Run with the project's existing .venv."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import struct
import subprocess
import sys
import threading
import time
import uuid

from analysis import compare, join_session
from verify import verify_pilot

LAB = Path(__file__).resolve().parent
REPO = LAB.parents[2]
LOCAL = LAB / ".local"
PIN = "df870ed7fa51110edb872beb3357a44d20e1ce56"
BINARY = LOCAL / "build/ech_lab"
ENGINE = LOCAL / "engine-build/tlsfp_phase2"


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def append_json(path, value):
    with path.open("a") as output:
        output.write(json.dumps(value, sort_keys=True) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, log):
    with log.open("a") as output:
        output.write(json.dumps([str(value) for value in args]) + "\n")
        output.flush()
        subprocess.run([str(value) for value in args], stdout=output, stderr=subprocess.STDOUT, check=True)


def tools_manifest():
    versions = {}
    for name, args in {"cmake": ["cmake", "--version"], "compiler": ["c++", "--version"],
                       "tshark": ["tshark", "--version"], "tcpdump": ["tcpdump", "--version"]}.items():
        process = subprocess.run(args, text=True, capture_output=True, check=True)
        versions[name] = (process.stdout + process.stderr).splitlines()[0]
    return {"boringssl_revision": PIN, "python": sys.version, "tools": versions,
            "sources": {name: digest(LAB / name) for name in ("lab.cpp", "run.py", "analysis.py", "verify.py")},
            "lab_sha256": digest(BINARY), "engine_sha256": digest(ENGINE),
            "engine_revision": subprocess.check_output(["git", "-C", REPO, "rev-parse", "HEAD"], text=True).strip()}


def build(out):
    source, dependency_build = LOCAL / "boringssl", LOCAL / "boringssl-build"
    LOCAL.mkdir(exist_ok=True)
    log = out / "build.log"
    if not source.exists():
        command(["git", "init", source], log)
        command(["git", "-C", source, "remote", "add", "origin", "https://github.com/google/boringssl.git"], log)
        command(["git", "-C", source, "fetch", "--depth", "1", "origin", PIN], log)
        command(["git", "-C", source, "checkout", "--detach", PIN], log)
    revision = subprocess.check_output(["git", "-C", source, "rev-parse", "HEAD"], text=True).strip()
    changes = subprocess.check_output(["git", "-C", source, "status", "--porcelain"], text=True)
    if revision != PIN or changes.strip():
        raise RuntimeError("BoringSSL must be the exact clean pinned checkout")
    command(["cmake", "-S", source, "-B", dependency_build, "-GNinja", "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTING=OFF"], log)
    command(["cmake", "--build", dependency_build, "--target", "ssl", "crypto", "-j", "4"], log)
    command(["cmake", "-S", LAB, "-B", LOCAL / "build", "-GNinja", "-DCMAKE_BUILD_TYPE=Release"], log)
    command(["cmake", "--build", LOCAL / "build", "-j", "4"], log)
    command(["cmake", "-S", REPO / "Phase 2/engine", "-B", LOCAL / "engine-build", "-DCMAKE_BUILD_TYPE=Release"], log)
    command(["cmake", "--build", LOCAL / "engine-build", "-j", "4"], log)
    command(["ctest", "--test-dir", LOCAL / "engine-build", "--output-on-failure"], log)
    write_json(out / "build.json", tools_manifest())


class LiveProcess:
    """Drain readiness/evidence output continuously and always reap the child."""

    def __init__(self, args, log, stderr=False):
        self.lines = queue.Queue()
        self.log = log
        self.errors = None
        if stderr:
            self.process = subprocess.Popen([str(value) for value in args], text=True,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            stream = self.process.stderr
        else:
            self.errors = log.with_suffix(".stderr").open("w")
            self.process = subprocess.Popen([str(value) for value in args], text=True,
                                            stdout=subprocess.PIPE, stderr=self.errors)
            stream = self.process.stdout
        self.thread = threading.Thread(target=self._drain, args=(stream,), daemon=True)
        self.thread.start()

    def _drain(self, stream):
        with stream, self.log.open("w") as output:
            for line in stream:
                output.write(line)
                output.flush()
                self.lines.put(line)

    def ready(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=0.1)
            except queue.Empty:
                if self.process.poll() is not None:
                    break
                continue
            value = predicate(line)
            if value:
                return value
        raise RuntimeError(f"process failed to become ready; inspect {self.log}")

    def stop(self, sig=signal.SIGTERM):
        if self.process.poll() is None:
            self.process.send_signal(sig)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.thread.join(timeout=3)
        if self.errors:
            self.errors.close()
        return self.process.returncode


def run_client(args, timeout=5):
    """subprocess.run kills and waits for the endpoint when a timeout expires."""
    try:
        process = subprocess.run([str(value) for value in args], text=True, capture_output=True, timeout=timeout)
        return {"returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr, "timeout": False}
    except subprocess.TimeoutExpired as error:
        def decode(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
        return {"returncode": None, "stdout": decode(error.stdout), "stderr": decode(error.stderr), "timeout": True}


def replay_capture(pcap, output, log):
    command([ENGINE, "-r", pcap, "-q", "--json", output], log)


def run_session(out, material, schedule):
    out.mkdir()
    write_json(out / "schedule.json", schedule)
    (out / "attempts.jsonl").touch()
    (out / "clients.jsonl").touch()
    server = capture = None
    try:
        server = LiveProcess([BINARY, "server", material, len(schedule), out.name], out / "server.jsonl")
        ready = server.ready(lambda line: json.loads(line) if json.loads(line).get("event") == "ready" else None)
        port = ready["port"]
        capture = LiveProcess(["tcpdump", "--immediate-mode", "-i", "lo0", "-n", "-s", "0", "-U", "-w", out / "capture.pcap",
                               f"ip and tcp port {port} and host 127.0.0.1"], out / "capture.log", stderr=True)
        capture.ready(lambda line: "listening on" in line)
        for spec in schedule:
            result = run_client([BINARY, "client", material, port, spec["profile"], spec["mode"], out.name, spec["attempt_id"]])
            append_json(out / "attempts.jsonl", {**spec, **result})
            for line in result["stdout"].splitlines():
                event = json.loads(line)
                append_json(out / "clients.jsonl", event)
            # Wait for the independent server result before starting another client.
            server.ready(lambda line: json.loads(line).get("event") == "connection", timeout=7)
        server.process.wait(timeout=5)
        if server.process.returncode:
            raise RuntimeError("server failed; inspect endpoint logs")
        # Let the local capture process drain shutdown packets before SIGINT.
        time.sleep(0.3)
    finally:
        if capture:
            capture_rc = capture.stop(signal.SIGINT)
            text = (out / "capture.log").read_text()
            drops = re.search(r"(\d+) packets dropped by kernel", text)
            write_json(out / "capture-status.json", {"returncode": capture_rc,
                       "dropped": int(drops[1]) if drops else None})
        if server:
            server.stop()
    replay_capture(out / "capture.pcap", out / "engine.jsonl", out / "replay.log")


def session_rows(path):
    attempts = json_lines(path / "attempts.jsonl")
    servers = [row for row in json_lines(path / "server.jsonl") if row.get("event") == "connection"]
    rows, anomalies = join_session(path.name, read_json(path / "schedule.json"), attempts,
                                   json_lines(path / "clients.jsonl"), servers, json_lines(path / "engine.jsonl"))
    capture = read_json(path / "capture-status.json")
    if capture != {"returncode": 0, "dropped": 0}:
        anomalies.append({"source": "capture", "reason": "capture_failed_or_loss_unknown", "records": capture})
        for row in rows:
            row["eligible"] = False
            row["label"] = "unknown"
            row["errors"].append("capture_failed_or_loss_unknown")
    return rows, anomalies


def decode_config(data):
    """Decode the generated public ECHConfig independently of BoringSSL."""
    offset = 0

    def number(size):
        nonlocal offset
        value = int.from_bytes(data[offset:offset+size], "big")
        if offset + size > len(data):
            raise ValueError("truncated ECHConfig")
        offset += size
        return value

    def vector(size):
        nonlocal offset
        length = number(size)
        value = data[offset:offset+length]
        if len(value) != length:
            raise ValueError("truncated ECHConfig vector")
        offset += length
        return value

    version, length = number(2), number(2)
    if version != 0xfe0d or length != len(data) - 4:
        raise ValueError("invalid ECHConfig framing")
    config_id, kem_id = number(1), number(2)
    public_key, suites = vector(2), vector(2)
    maximum_name_length, public_name, extensions = number(1), vector(1), vector(2)
    if len(public_key) != 32 or len(suites) != 4 or extensions or offset != len(data):
        raise ValueError("configuration must have a single suite and no extensions")
    kdf_id, aead_id = struct.unpack("!HH", suites)
    return {"config_id": config_id, "kem_id": kem_id, "kdf_id": kdf_id, "aead_id": aead_id,
            "maximum_name_length": maximum_name_length, "public_name": public_name.decode("ascii")}


def pilot_passed(rows, anomalies):
    expected = [("A", "accepted", "accepted_real"), ("B", "accepted", "accepted_real"),
                ("A", "grease", "grease")]
    return (not anomalies and len(rows) == 3 and all(row["eligible"] for row in rows)
            and [(row["profile"], row["mode"], row["label"]) for row in rows] == expected)


def pilot(out):
    material_id = uuid.uuid4().hex
    material = LOCAL / "materials" / material_id
    material.parent.mkdir(parents=True, exist_ok=True)
    command([BINARY, "prepare", material], out / "prepare.log")
    manifest = {**tools_manifest(), "material_id": material_id,
                "config_sha256": digest(material / "ech-config.bin"),
                "certificate_sha256": digest(material / "cert.pem"),
                "config": decode_config((material / "ech-config.bin").read_bytes())}
    if manifest["config"] != {"config_id": 42, "kem_id": 32, "kdf_id": 1, "aead_id": 1,
                               "maximum_name_length": 64, "public_name": "public.ech.test"}:
        raise RuntimeError("generated configuration violates experiment settings")
    for filename in ("ech-config.bin", "ech-config-list.bin", "cert.pem"):
        (out / filename).write_bytes((material / filename).read_bytes())
    write_json(out / "manifest.json", manifest)
    schedule = [{"attempt_id": "pilot-A", "profile": "A", "mode": "accepted"},
                {"attempt_id": "pilot-B", "profile": "B", "mode": "accepted"},
                {"attempt_id": "pilot-grease", "profile": "A", "mode": "grease"}]
    run_session(out / "pilot", material, schedule)
    rows, anomalies = session_rows(out / "pilot")
    reference = verify_pilot(out / "pilot")
    write_json(out / "tshark-validation.json", reference)
    passed = pilot_passed(rows, anomalies) and reference["passed"]
    write_json(out / "pilot-validation.json", {"passed": passed, "rows": rows, "anomalies": anomalies})
    if not passed:
        raise RuntimeError("pilot evidence failed validation")


def collect(pilot_path, out):
    rows, anomalies = session_rows(pilot_path / "pilot")
    if not pilot_passed(rows, anomalies) or not verify_pilot(pilot_path / "pilot")["passed"]:
        raise RuntimeError("collection requires a valid three-case pilot")
    manifest = read_json(pilot_path / "manifest.json")
    current_build = tools_manifest()
    if current_build != {key: manifest[key] for key in current_build}:
        raise RuntimeError("build changed since pilot; run a new pilot")
    material = LOCAL / "materials" / manifest["material_id"]
    if (digest(material / "ech-config.bin") != manifest["config_sha256"]
            or digest(material / "cert.pem") != manifest["certificate_sha256"]):
        raise RuntimeError("ECH configuration changed since pilot")
    write_json(out / "manifest.json", {**manifest, "pilot": os.path.relpath(pilot_path, out), "expected_attempts": 60})
    for number in range(1, 4):
        schedule = [{"attempt_id": f"s{number}-{repeat:02}-{profile}", "profile": profile, "mode": "accepted"}
                    for repeat in range(1, 11) for profile in ("A", "B")]
        run_session(out / f"session-{number}", material, schedule)
        rows, anomalies = session_rows(out / f"session-{number}")
        write_json(out / f"validation-{number}.json", {"rows": rows, "anomalies": anomalies})


def report(pilot_path, collection, out):
    pilot_rows, anomalies = session_rows(pilot_path / "pilot")
    rows, census = [], []
    for number in range(1, 4):
        path = collection / f"session-{number}"
        if not (path / "engine.jsonl").exists():
            anomalies.append({"source": str(path), "reason": "missing_session"})
            continue
        session, extra = session_rows(path)
        expected = [{"attempt_id": f"s{number}-{repeat:02}-{profile}", "profile": profile, "mode": "accepted"}
                    for repeat in range(1, 11) for profile in ("A", "B")]
        if read_json(path / "schedule.json") != expected:
            extra.append({"source": str(path), "reason": "unexpected_schedule"})
        endpoint_clients = json_lines(path / "clients.jsonl")
        endpoint_servers = [row for row in json_lines(path / "server.jsonl") if row.get("event") == "connection"]
        passive = json_lines(path / "engine.jsonl")
        census.append({"session": path.name, "scheduled": len(expected),
                       "attempted": len(json_lines(path / "attempts.jsonl")),
                       "client_records": len(endpoint_clients), "server_records": len(endpoint_servers),
                       "passive_rows": len(passive), "complete_pairs": sum(row["complete_hello_pair"] for row in passive),
                       "eligible": sum(row["eligible"] for row in session)})
        server_keys = {}
        for endpoint in endpoint_servers:
            key = (endpoint["client_port"], endpoint["outer_random"])
            server_keys.setdefault(key, []).append(endpoint)
        census[-1]["endpoint_accepted_agreements"] = sum(
            endpoint.get("handshake_success") and endpoint.get("accepted") and endpoint.get("certificate_verified")
            and len(server_keys.get((endpoint["client_port"], endpoint["outer_random"]), [])) == 1
            and server_keys[(endpoint["client_port"], endpoint["outer_random"])][0].get("accepted")
            and server_keys[(endpoint["client_port"], endpoint["outer_random"])][0].get("handshake_success")
            for endpoint in endpoint_clients)
        rows.extend(session)
        anomalies.extend(extra)
    pilot_manifest = read_json(pilot_path / "manifest.json")
    corpus_manifest = read_json(collection / "manifest.json")
    if any(pilot_manifest[key] != corpus_manifest[key] for key in
           ("config_sha256", "certificate_sha256", "material_id", "sources", "lab_sha256", "engine_sha256", "boringssl_revision")):
        anomalies.append({"source": "manifest", "reason": "pilot_collection_mismatch"})
    accepted = [row for row in rows if row["eligible"] and row["label"] == "accepted_real"]
    measurements, groups = compare(accepted)
    for path in [pilot_path / "pilot"] + [collection / f"session-{number}" for number in range(1, 4)]:
        if not path.exists():
            continue
        endpoint_records = json_lines(path / "clients.jsonl") + [row for row in json_lines(path / "server.jsonl")
                                                                 if row.get("event") == "connection"]
        if any(row.get("config_sha256") != pilot_manifest["config_sha256"] for row in endpoint_records):
            anomalies.append({"source": str(path), "reason": "configuration_digest_mismatch"})
    reference = verify_pilot(pilot_path / "pilot")
    write_json(out / "tshark-validation.json", reference)
    complete = (len(rows) == len(accepted) == 60 and pilot_passed(pilot_rows, [])
                and reference["passed"] and not anomalies)
    fields = ["session", "attempt_id", "profile", "mode", "eligible", "label", "errors", "client_port",
              "server_port", "outer_random", "ja3", "ja4", "kdf_id", "aead_id", "enc_length", "ciphertext_length"]
    with (out / "joined.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in pilot_rows + rows:
            writer.writerow({**row, "errors": ";".join(row["errors"])})
    summary = {"complete": complete, "expected_attempts": 60, "scheduled": len(rows), "accepted_joined": len(accepted),
               "excluded": len(rows) - len(accepted), "pilot_attempts": len(pilot_rows),
               "session_counts": census, "anomalies": anomalies, "comparisons": measurements}
    write_json(out / "summary.json", summary)
    write_json(out / "feature-groups.json", groups)
    lines = ["# Reduced ECH checkpoint 3 results", "", f"Complete experiment: **{complete}**.", "",
             f"Corpus attempts {len(rows)}, confirmed accepted and joined {len(accepted)}, excluded {len(rows)-len(accepted)}.", "",
             "| Features | Groups | Shared groups | Observations in shared groups | A distinct / modal share | B distinct / modal share |",
             "|---|---:|---:|---:|---|---|"]
    for item in measurements:
        profiles = item["profiles"]
        cells = [f"{profiles[p]['distinct']} / {profiles[p]['modal_share']}" for p in ("A", "B")]
        lines.append(f"| {item['features']} | {item['distinct_groups']} | {item['shared_groups']} | "
                     f"{item['shared_observation_fraction']} | {cells[0]} | {cells[1]} |")
    lines += ["", "The feature groups and per-session variation are recorded in the accompanying JSON files.", "",
              "These are two configurations of the same pinned BoringSSL implementation. "
              "Supported TLS groups differ, while ALPN, ECH configuration, cipher and signature settings match. "
              "Ordinary GREASE and extension permutation remain enabled. JA3 variation is an observed behavior.", "",
              "Endpoint observations establish ECH labels. The passive engine continues to emit unknown offer type "
              "and unverified TLS 1.3 ECH acceptance. An ECH envelope alone cannot reliably separate GREASE "
              "from a real offer. Rejected real offers can resemble GREASE, including decryption failure at a server.", "",
              "The comparisons describe grouping and repeatability on this corpus. They establish neither "
              "recognition accuracy nor identification of browsers, devices or arbitrary applications. "
              "No ECH-off comparison or latency benchmark was performed."]
    (out / "report.md").write_text("\n".join(lines) + "\n")
    if not complete:
        raise RuntimeError("report written, but experiment completion criteria were not met")


def replay(source, out):
    captures = sorted(source.rglob("capture.pcap"))
    if not captures:
        raise RuntimeError("no captures found")
    for index, pcap in enumerate(captures):
        replay_capture(pcap, out / f"{index}-{pcap.parent.name}.jsonl", out / "replay.log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="stage", required=True)
    for name in ("build", "pilot", "collect", "report", "replay"):
        stage = subcommands.add_parser(name)
        stage.add_argument("--out", required=True, type=Path)
        if name in ("collect", "report"):
            stage.add_argument("--pilot", required=True, type=Path)
        if name == "report":
            stage.add_argument("--collection", required=True, type=Path)
        if name == "replay":
            stage.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    try:
        if args.stage == "build":
            build(out)
        elif args.stage == "pilot":
            pilot(out)
        elif args.stage == "collect":
            collect(args.pilot.resolve(), out)
        elif args.stage == "report":
            report(args.pilot.resolve(), args.collection.resolve(), out)
        else:
            replay(args.source.resolve(), out)
    except Exception as error:
        write_json(out / "failure.json", {"stage": args.stage, "error": str(error)})
        print(f"{args.stage} failed; evidence retained at {out}: {error}", file=sys.stderr)
        return 1
    print(f"{args.stage} complete: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
