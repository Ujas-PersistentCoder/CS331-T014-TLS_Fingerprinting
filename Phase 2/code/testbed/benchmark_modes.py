#!/usr/bin/env python3
"""Offline 1/2/4-worker comparison with explicit PQ analysis and ECH tracking modes.

All results go to a new output directory. This never rewrites saved captures or
historical results. It measures the CLI's internal interval, not handshake latency.
"""

import argparse
import hashlib
import itertools
import json
import platform
import re
import statistics
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def run(engine, pcap, workers, ech):
    command = [str(engine), "-r", str(pcap), "-q", "-j", str(workers),
               "--pq", "--ech" if ech else "--no-ech"]
    process = subprocess.run(command, cwd=REPO, capture_output=True, text=True, check=True)
    output = ANSI.sub("", process.stdout)

    def field(pattern, kind):
        match = re.search(pattern, output)
        if not match:
            raise ValueError(f"missing benchmark field {pattern!r}: {output}")
        return kind(match[1])

    return {"pcap": pcap.name, "workers": workers, "ech": ech, "pq": True,
            "command": command, "stderr": process.stderr,
            "packets": field(r"Total Packets Scanned\s*:\s*(\d+)", int),
            "clients": field(r"ClientHellos Found\s*:\s*(\d+)", int),
            "servers": field(r"ServerHellos Found\s*:\s*(\d+)", int),
            "ms": field(r"Execution Time\s*:\s*([\d.]+) ms", float),
            "pps": field(r"Processing Throughput\s*:\s*([\d.]+) packets/s", float)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path, help="New directory for metadata, trials and summary")
    parser.add_argument("--runs", type=positive, default=7)
    parser.add_argument("--pcap", action="append", type=Path, help="Override the two default workloads")
    args = parser.parse_args()
    engine = args.engine.resolve()
    pcaps = [p.resolve() for p in args.pcap] if args.pcap else [
        REPO / "Phase 2/code/pcaps" / name for name in ("stress-distinct.pcap", "pq_ech_chrome.pcap")]
    if not engine.is_file() or any(not p.is_file() for p in pcaps):
        parser.error("engine and all captures must exist")
    if len({p.name for p in pcaps}) != len(pcaps):
        parser.error("capture filenames must be distinct")
    out = args.out.resolve()
    if out.exists():
        parser.error(f"output already exists: {out}")
    out.mkdir(parents=True)
    engine_dir = REPO / "Phase 2/code/engine"
    source_files = [engine_dir / "CMakeLists.txt"] + sorted(
        p for part in ("src", "include", "tests") for p in (engine_dir / part).rglob("*")
        if p.is_file() and p.suffix in (".cpp", ".hpp"))
    sources = {str(p.relative_to(REPO)): digest(p) for p in source_files}
    revision = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    metadata = {"base_revision": revision, "engine_sha256": digest(engine),
                "engine_sources": sources, "python": sys.version, "platform": platform.platform(),
                "pcaps": {str(p): digest(p) for p in pcaps}, "runs": args.runs,
                "warmups_per_configuration": 1, "workers": [1, 2, 4], "pq": True}
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    configurations = list(itertools.product((1, 2, 4), (False, True)))
    trials = []
    try:
        with (out / "trials.jsonl").open("w") as log:
            for pcap in pcaps:
                for repeat in range(args.runs + 1):
                    shift = max(0, repeat - 1) % len(configurations)
                    order = configurations[shift:] + configurations[:shift]
                    for workers, ech in order:
                        trial = {**run(engine, pcap, workers, ech), "repeat": repeat}
                        trials.append(trial)
                        log.write(json.dumps(trial) + "\n")
                        log.flush()
        summary = []
        for pcap in pcaps:
            for workers, ech in configurations:
                rows = [r for r in trials if (r["pcap"], r["workers"], r["ech"]) == (pcap.name, workers, ech)]
                counts = {(r["packets"], r["clients"], r["servers"]) for r in rows}
                if len(counts) != 1:
                    raise ValueError(f"unstable counts for {pcap.name}, workers={workers}, ech={ech}")
                measured = [r for r in rows if r["repeat"]]
                pps = [r["pps"] for r in measured]
                summary.append({"pcap": pcap.name, "workers": workers, "ech": ech, "pq": True,
                                "counts": list(next(iter(counts))), "median_pps": statistics.median(pps),
                                "min_pps": min(pps), "max_pps": max(pps),
                                "median_ms": statistics.median(r["ms"] for r in measured)})
        for item in summary:
            same_mode = {tuple(r["counts"]) for r in summary
                         if r["pcap"] == item["pcap"] and r["ech"] == item["ech"]}
            if len(same_mode) != 1:
                raise ValueError(f"unequal work across worker counts: {item['pcap']}")
            item["equal_counts_across_ech_modes"] = len({tuple(r["counts"]) for r in summary
                                                          if r["pcap"] == item["pcap"]}) == 1
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        for row in summary:
            print(f"{row['pcap']} workers={row['workers']} ech={row['ech']}: "
                  f"{row['median_pps']/1000:.1f} kpps ({row['min_pps']/1000:.1f}–{row['max_pps']/1000:.1f}), "
                  f"counts={row['counts']}")
    except Exception as error:
        (out / "failure.json").write_text(json.dumps({"error": str(error)}, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
