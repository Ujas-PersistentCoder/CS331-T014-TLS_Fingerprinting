"""
Python engine benchmark. Mirrors benchmark_cpp.py's methodology exactly so
the two CSVs are directly comparable:
  - same PCAPS list, same RUNS / WARMUP_RUNS
  - "engine_ms"  = time inside the parse/reassemble/fingerprint loop only
                   (measured in-process here, no interpreter-startup cost --
                   the fairest comparison to C++'s internally reported
                   "Execution Time")
  - "wall_ms"    = a full subprocess run of _py_bench_worker.py, i.e.
                   interpreter boot + import + the same loop -- the fairest
                   comparison to C++'s subprocess wall time
  - NO database / Redis lookup in either metric, matching the C++ -q path
    and the team's decision to benchmark DB cost separately.
"""
import csv
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PY_DIR = ROOT / "code" / "python"
WORKER = Path(__file__).resolve().parent / "_py_bench_worker.py"
PCAP_DIR = ROOT / "code" / "pcaps"
RESULTS = ROOT / "code" / "benchmarks" / "results" / "python_results.csv"

sys.path.insert(0, str(PY_DIR))
from src.capture import read_pcap, CaptureStats  # noqa: E402
from src.ja3 import compute_ja3_hash, compute_ja3s_hash
from src.ja4 import compute_ja4_string, compute_ja4s_string

# Keep this list identical to benchmark_cpp.py's PCAPS for a fair comparison.
PCAPS = [
    "cloudflare_run1.pcap",
    "curl.pcap",
    "python_requests.pcap",
    "custom_client.pcap",
    "chrome.pcap",
    "chrome_run2.pcap",
    "stress_test.pcap",
]

RUNS = 30
WARMUP_RUNS = 3


def engine_once(pcap_path):
    """In-process timing: parse + reassemble + fingerprint loop only."""
    stats = CaptureStats()
    client_hellos = 0
    server_hellos = 0

    start = time.perf_counter()
    for result in read_pcap(str(pcap_path), stats):
        if result.client_hello is not None:
            client_hellos += 1

            ch = result.client_hello
            compute_ja3_hash(ch)
            compute_ja4_string(ch)

        if result.server_hello is not None:
            server_hellos += 1

            sh = result.server_hello
            compute_ja3s_hash(sh)
            compute_ja4s_string(sh)
    engine_ms = (time.perf_counter() - start) * 1000

    return {
        "engine_ms": engine_ms,
        "packets": stats.packets_processed,
        "client_hellos": client_hellos,
        "server_hellos": server_hellos,
    }


def wall_once(pcap_path):
    """Subprocess timing: interpreter boot + import + the same loop."""
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, str(WORKER), str(pcap_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    wall_ms = (time.perf_counter() - start) * 1000

    line = next(
        (l for l in result.stdout.splitlines() if l.startswith("RESULT")), None
    )
    if line is None:
        raise RuntimeError(f"Could not parse worker output for {pcap_path}\n\n{result.stdout}")

    fields = dict(part.split("=") for part in line.split()[1:])
    return {
        "wall_ms": wall_ms,
        "packets": int(fields["packets"]),
        "client_hellos": int(fields["client_hellos"]),
        "server_hellos": int(fields["server_hellos"]),
    }


def stats_of(values):
    return {
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


rows = []

for filename in PCAPS:
    pcap = PCAP_DIR / filename

    if not pcap.exists():
        print(f"Skipping missing PCAP: {pcap}")
        continue

    print(f"\nBenchmarking {filename}")

    for _ in range(WARMUP_RUNS):
        engine_once(pcap)
        wall_once(pcap)

    engine_times, wall_times = [], []
    reference_counts = None

    for i in range(RUNS):
        e = engine_once(pcap)
        w = wall_once(pcap)

        engine_times.append(e["engine_ms"])
        wall_times.append(w["wall_ms"])

        counts = (e["packets"], e["client_hellos"], e["server_hellos"])
        w_counts = (w["packets"], w["client_hellos"], w["server_hellos"])

        if counts != w_counts:
            raise RuntimeError(
                f"In-process and subprocess results disagree for {filename}: "
                f"{counts} vs {w_counts}"
            )

        if reference_counts is None:
            reference_counts = counts
        elif counts != reference_counts:
            raise RuntimeError(
                f"Inconsistent results for {filename}: "
                f"expected {reference_counts}, got {counts}"
            )

        print(
            f"  run {i + 1:02d}/{RUNS}: "
            f"engine={e['engine_ms']:.4f} ms, "
            f"wall={w['wall_ms']:.4f} ms"
        )

    engine = stats_of(engine_times)
    wall = stats_of(wall_times)
    packets, client_hellos, server_hellos = reference_counts

    rows.append({
        "pcap": filename,
        "runs": RUNS,
        "packets": packets,
        "client_hellos": client_hellos,
        "server_hellos": server_hellos,

        "engine_mean_ms": engine["mean"],
        "engine_median_ms": engine["median"],
        "engine_stdev_ms": engine["stdev"],
        "engine_min_ms": engine["min"],
        "engine_max_ms": engine["max"],

        "wall_mean_ms": wall["mean"],
        "wall_median_ms": wall["median"],
        "wall_stdev_ms": wall["stdev"],
        "wall_min_ms": wall["min"],
        "wall_max_ms": wall["max"],
    })

    print("\n  Engine timing:")
    print(f"    median: {engine['median']:.4f} ms")
    print(f"    mean:   {engine['mean']:.4f} ms")
    print(f"    stdev:  {engine['stdev']:.4f} ms")

    print("  Wall-clock timing:")
    print(f"    median: {wall['median']:.4f} ms")
    print(f"    mean:   {wall['mean']:.4f} ms")
    print(f"    stdev:  {wall['stdev']:.4f} ms")

    print(
        f"  Correctness: "
        f"{packets} packets, "
        f"{client_hellos} CH, "
        f"{server_hellos} SH"
    )

RESULTS.parent.mkdir(parents=True, exist_ok=True)

if rows:
    with RESULTS.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved results to {RESULTS}")
else:
    print("\nNo benchmark results generated.")
