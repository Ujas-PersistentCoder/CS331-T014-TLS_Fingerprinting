"""
Compare the C++ and Python engine benchmarks head-to-head.

Reads results/cpp_results.csv and results/python_results.csv (produced by
benchmark_cpp.py and benchmark_python.py -- run BOTH on the same machine),
joins them per pcap, and reports:
  * engine median time for each language (parse+reassemble+fingerprint only,
    no interpreter/process startup, no DB) -- the primary, unambiguous
    comparison, independent of how each engine counts packets
  * throughput in packets/sec, using EACH engine's own packet count --
    C++'s "Total Packets Scanned" counts every packet libpcap reads;
    Python's "packets_processed" counts only TCP segments carrying payload
    or a SYN/FIN/RST flag (pure ACKs are intentionally skipped). The two
    counts can legitimately differ on real captures; throughput here is
    each engine's own rate against its own definition, not a shared one.
  * speedup = python_engine_median / cpp_engine_median (packet-count
    independent, the headline number)

Writes results/comparison.csv and, if matplotlib is available,
results/comparison_throughput.png.
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT / "code" / "benchmarks" / "results"
CPP_CSV = RESULTS_DIR / "cpp_results.csv"
PY_CSV = RESULTS_DIR / "python_results.csv"
OUT_CSV = RESULTS_DIR / "comparison.csv"
OUT_PNG = RESULTS_DIR / "comparison_throughput.png"


def load(path):
    with path.open() as f:
        return {row["pcap"]: row for row in csv.DictReader(f)}


def fmt_pps(pps):
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f} M/s"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f} k/s"
    return f"{pps:.0f}/s"


def main():
    if not CPP_CSV.exists() or not PY_CSV.exists():
        missing = CPP_CSV if not CPP_CSV.exists() else PY_CSV
        raise SystemExit(f"Missing {missing}. Run both benchmark scripts first.")

    cpp = load(CPP_CSV)
    py = load(PY_CSV)

    rows = []
    for pcap in cpp:
        if pcap not in py:
            print(f"Note: {pcap} present in cpp_results.csv but not python_results.csv, skipping")
            continue
        c, p = cpp[pcap], py[pcap]
        cpp_packets = int(c["packets"])
        py_packets = int(p["packets"])
        cpp_ms = float(c["engine_median_ms"])
        py_ms = float(p["engine_median_ms"])
        cpp_pps = cpp_packets / (cpp_ms / 1000.0) if cpp_ms > 0 else 0.0
        py_pps = py_packets / (py_ms / 1000.0) if py_ms > 0 else 0.0
        speedup = py_ms / cpp_ms if cpp_ms > 0 else 0.0
        cpp_ch = int(c["client_hellos"])
        py_ch = int(p["client_hellos"])
        cpp_sh = int(c["server_hellos"])
        py_sh = int(p["server_hellos"])

        handshakes_match = (
            cpp_ch == py_ch and
            cpp_sh == py_sh
        )
        rows.append({
            "pcap": pcap,
            "cpp_packets": cpp_packets,
            "py_packets": py_packets,
            "cpp_engine_median_ms": round(cpp_ms, 4),
            "py_engine_median_ms": round(py_ms, 4),
            "cpp_pkts_per_sec": round(cpp_pps, 1),
            "py_pkts_per_sec": round(py_pps, 1),
            "cpp_speedup_x": round(speedup, 1),
            "cpp_client_hellos": cpp_ch,
            "py_client_hellos": py_ch,
            "cpp_server_hellos": cpp_sh,
            "py_server_hellos": py_sh,
            "handshakes_match": handshakes_match,
        })

    if not rows:
        raise SystemExit("No matching pcaps between the two result files -- nothing to compare.")

    # ---- console table ----
    hdr = (f"{'pcap':<30}{'C++ pkts':>9}{'Py pkts':>9}{'C++ ms':>9}{'Py ms':>10}"
        f"{'C++ thru':>11}{'Py thru':>11}{'Speedup':>9}{'Match?':>8}")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        match_str = "✅" if r["handshakes_match"] else "❌"
        print(
            f"{r['pcap']:<30}{r['cpp_packets']:>9}{r['py_packets']:>9}"
            f"{r['cpp_engine_median_ms']:>9.3f}{r['py_engine_median_ms']:>10.3f}"
            f"{fmt_pps(r['cpp_pkts_per_sec']):>11}{fmt_pps(r['py_pkts_per_sec']):>11}"
            f"{r['cpp_speedup_x']:>8.1f}x{match_str:>7}"
        )

    # ---- csv ----
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    print(f"\nSaved {OUT_CSV}")

    # ---- chart (improved) ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # Include ALL traces so stress tests are never hidden
        plot_rows = rows
        labels = [
            r["pcap"].replace("benchmark/", "").replace(".pcap", "")
            for r in plot_rows
        ]
        cpp_thru = [r["cpp_pkts_per_sec"] for r in plot_rows]
        py_thru = [r["py_pkts_per_sec"] for r in plot_rows]
        speedups = [r["cpp_speedup_x"] for r in plot_rows]

        x = list(range(len(labels)))
        width = 0.38

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

        # Panel 1: Throughput Comparison (Log Scale)
        ax1.bar([i - width/2 for i in x], cpp_thru, width, label="C++17 (Zero-Copy)", color="#2563eb")
        ax1.bar([i + width/2 for i in x], py_thru, width, label="Python (Stateful dpkt)", color="#f59e0b")
        ax1.set_yscale("log")
        ax1.set_ylabel("Throughput (packets/sec, log scale)")
        ax1.set_title("Engine Parsing Throughput")
        ax1.set_xticks(x)
        ax1.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
        ax1.legend(loc="upper left")
        ax1.grid(axis="y", which="both", linestyle=":", alpha=0.4)

        # Highlight mismatch/loss on cloudflare_x100
        for i, r in enumerate(plot_rows):
            if not r["handshakes_match"]:
                ax1.annotate(
                    "Lossy Reassembly\n(4KB Cap)",
                    xy=(i - width/2, cpp_thru[i]),
                    xytext=(i - 0.5, cpp_thru[i] * 1.8),
                    arrowprops=dict(arrowstyle="->", color="#dc2626", lw=1.2),
                    fontsize=8,
                    fontweight="bold",
                    color="#dc2626"
                )

        # Panel 2: Speedup Scaling Factor
        bars2 = ax2.bar(x, speedups, width=0.5, color="#059669")
        ax2.set_ylabel("C++ Speedup Factor (x)")
        ax2.set_title("C++ Speedup Scaling vs. Trace Complexity")
        ax2.set_xticks(x)
        ax2.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
        ax2.grid(axis="y", linestyle=":", alpha=0.4)

        # Add value labels on top of speedup bars
        for bar, val in zip(bars2, speedups):
            ax2.text(
                bar.get_x() + bar.get_width()/2,
                bar.get_height() + 0.5,
                f"{val:.1f}x",
                ha="center",
                va="bottom",
                fontsize=8,
                fontweight="bold"
            )

        fig.tight_layout()
        fig.savefig(OUT_PNG, dpi=160)
        print(f"Saved enhanced comparison chart to {OUT_PNG}")
    except ImportError:
        print("matplotlib not installed - skipped chart (pip install matplotlib)")


if __name__ == "__main__":
    main()
