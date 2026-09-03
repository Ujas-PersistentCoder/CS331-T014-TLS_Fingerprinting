import argparse
import logging
import sys
from pathlib import Path

# Allow running as `python main.py` without PYTHONPATH=.
sys.path.insert(0, str(Path(__file__).parent))

from src.capture import read_pcap, CaptureStats
from src.ja3 import compute_ja3_string, compute_ja3_hash, compute_ja3s_string, compute_ja3s_hash
from src.db import FingerprintDB


def main():
    parser = argparse.ArgumentParser(description="TLS Fingerprint Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="subcommands")

    pcap_parser = subparsers.add_parser("pcap", help="Analyze a pcap file")
    pcap_parser.add_argument("filepath", help="Path to the pcap/pcapng file")
    pcap_parser.add_argument("--db", default="fingerprints.json",
                             help="Path to fingerprints JSON DB")
    pcap_parser.add_argument("--verbose", action="store_true",
                             help="Print detailed parsed fields and debug logs")

    live_parser = subparsers.add_parser("live", help="Live capture (requires root)")
    live_parser.add_argument("interface", help="Network interface to sniff on")
    live_parser.add_argument("--db", default="fingerprints.json",
                             help="Path to fingerprints JSON DB")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Configure logging
    log_level = logging.DEBUG if getattr(args, 'verbose', False) else logging.WARNING
    logging.basicConfig(level=log_level, format="%(name)s: %(message)s")

    db = FingerprintDB(args.db)

    if args.command == "pcap":
        if not Path(args.filepath).exists():
            print(f"Error: {args.filepath} not found.")
            sys.exit(1)

        print(f"Analyzing PCAP: {args.filepath}")
        print()

        stats = CaptureStats()
        for result in read_pcap(args.filepath, stats):
            if result.client_hello:
                ch = result.client_hello
                ja3_raw = compute_ja3_string(ch)
                ja3_hash = compute_ja3_hash(ch)
                match = db.lookup(ja3_hash)

                print(f"[ClientHello] {result.src_ip}:{result.src_port}"
                      f" -> {result.dst_ip}:{result.dst_port}")
                if ch.server_name:
                    print(f"  SNI:     {ch.server_name}")
                print(f"  JA3:     {ja3_hash}")
                print(f"  JA3 raw: {ja3_raw}")
                if match:
                    print(f"  Match:   {match} (from DB)")
                else:
                    print("  Match:   Unknown")

                if args.verbose:
                    print(f"  Version:    {ch.tls_version} (0x{ch.tls_version:04x})")
                    print(f"  Ciphers:    {', '.join(str(c) for c in ch.cipher_suites)}")
                    print(f"  Extensions: {', '.join(str(e) for e in ch.extensions)}")
                    print(f"  Curves:     {', '.join(str(c) for c in ch.elliptic_curves)}")
                    print(f"  Formats:    {', '.join(str(f) for f in ch.ec_point_formats)}")
                    if ch.alpn:
                        print(f"  ALPN:       {', '.join(ch.alpn)}")
                    if ch.supported_versions:
                        print(f"  Sup. Vers:  "
                              f"{', '.join(f'0x{v:04x}' for v in ch.supported_versions)}")

                print()

            if result.server_hello:
                sh = result.server_hello
                ja3s_raw = compute_ja3s_string(sh)
                ja3s_hash = compute_ja3s_hash(sh)
                match = db.lookup(ja3s_hash)

                print(f"[ServerHello] {result.src_ip}:{result.src_port}"
                      f" -> {result.dst_ip}:{result.dst_port}")
                print(f"  JA3S:     {ja3s_hash}")
                print(f"  JA3S raw: {ja3s_raw}")
                if match:
                    print(f"  Match:   {match} (from DB)")

                if args.verbose:
                    print(f"  Version:    {sh.tls_version} (0x{sh.tls_version:04x})")
                    print(f"  Cipher:     {sh.cipher_suite}")
                    print(f"  Extensions: {', '.join(str(e) for e in sh.extensions)}")
                    if sh.supported_version:
                        print(f"  Sup. Ver:   0x{sh.supported_version:04x}")

                print()

        # Always print capture statistics
        print(stats.summary())

    elif args.command == "live":
        print("Live capture is currently out of scope per phase plan.")
        sys.exit(1)


if __name__ == "__main__":
    main()
