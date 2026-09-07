"""
Standalone worker invoked as a subprocess by benchmark_python.py to measure
true wall-clock cost (interpreter start + import + parse + reassemble +
fingerprint), with NO database/Redis involvement -- mirrors the C++ engine's
-q (quiet) mode, which also skips Redis. Keeping DB out of both benchmarks
is intentional (team decision): DB/Redis lookup cost is measured separately,
never mixed into the core engine comparison.

Prints one line of machine-parsable output; benchmark_python.py parses it.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

from src.capture import read_pcap, CaptureStats  # noqa: E402
from src.ja3 import compute_ja3_hash, compute_ja3s_hash
from src.ja4 import compute_ja4_string, compute_ja4s_string

def main():
    pcap_path = sys.argv[1]
    stats = CaptureStats()
    client_hellos = 0
    server_hellos = 0

    for result in read_pcap(pcap_path, stats):
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

    print(
        f"RESULT packets={stats.packets_processed} "
        f"client_hellos={client_hellos} server_hellos={server_hellos}"
    )


if __name__ == "__main__":
    main()
