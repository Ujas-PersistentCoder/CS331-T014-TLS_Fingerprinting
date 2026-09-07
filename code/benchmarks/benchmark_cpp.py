import csv
import re
import statistics
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

CPP = ROOT / "code" / "cpp" / "build" / "tlsfp_engine"
PCAP_DIR = ROOT / "code" / "pcaps"
RESULTS = ROOT / "code" / "benchmarks" / "results" / "cpp_results.csv"


PCAPS = [
    "test_reassembly.pcap",
    "captured_handshakes.pcap",
    "cloudflare_run1.pcap",
    "curl.pcap",
    "python_requests.pcap",
    "custom_client.pcap",
    "chrome.pcap",
    "chrome_run2.pcap",
    "benchmark/cloudflare_x100.pcap",
]

RUNS = 30
WARMUP_RUNS = 3


# Parse C++ quiet-mode output
time_re = re.compile(r"Execution Time\s*:\s*([\d.]+)\s*ms")
packets_re = re.compile(r"Total Packets Scanned\s*:\s*(\d+)")
ch_re = re.compile(r"ClientHellos Found\s*:\s*(\d+)")
sh_re = re.compile(r"ServerHellos Found\s*:\s*(\d+)")


def run_once(pcap):
    start = time.perf_counter()

    result = subprocess.run(
        [str(CPP), "-r", str(pcap), "-q"],
        capture_output=True,
        text=True,
        check=True,
    )

    wall_ms = (time.perf_counter() - start) * 1000

    output = result.stdout

    time_match = time_re.search(output)
    packets_match = packets_re.search(output)
    ch_match = ch_re.search(output)
    sh_match = sh_re.search(output)

    if not all([time_match, packets_match, ch_match, sh_match]):
        raise RuntimeError(
            f"Could not parse benchmark output for {pcap}\n\n{output}"
        )

    return {
        "engine_ms": float(time_match.group(1)),
        "wall_ms": wall_ms,
        "packets": int(packets_match.group(1)),
        "client_hellos": int(ch_match.group(1)),
        "server_hellos": int(sh_match.group(1)),
    }


def stats(values):
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

    # Warm-up runs are not included in results
    for _ in range(WARMUP_RUNS):
        run_once(pcap)

    engine_times = []
    wall_times = []

    reference_counts = None

    for i in range(RUNS):
        result = run_once(pcap)

        engine_times.append(result["engine_ms"])
        wall_times.append(result["wall_ms"])

        counts = (
            result["packets"],
            result["client_hellos"],
            result["server_hellos"],
        )

        # Ensure every benchmark run processes the same workload
        if reference_counts is None:
            reference_counts = counts
        elif counts != reference_counts:
            raise RuntimeError(
                f"Inconsistent results for {filename}: "
                f"expected {reference_counts}, got {counts}"
            )

        print(
            f"  run {i + 1:02d}/{RUNS}: "
            f"engine={result['engine_ms']:.4f} ms, "
            f"wall={result['wall_ms']:.4f} ms"
        )

    engine = stats(engine_times)
    wall = stats(wall_times)

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
        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys(),
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved results to {RESULTS}")
else:
    print("\nNo benchmark results generated.")