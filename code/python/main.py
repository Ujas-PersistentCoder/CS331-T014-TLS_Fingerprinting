import argparse
import sys
from pathlib import Path

from src.capture import read_pcap
from src.ja3 import compute_ja3_string, compute_ja3_hash, compute_ja3s_string, compute_ja3s_hash
from src.db import FingerprintDB

def main():
    parser = argparse.ArgumentParser(description="TLS Fingerprint Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="subcommands")
    
    pcap_parser = subparsers.add_parser("pcap", help="Analyze a pcap file")
    pcap_parser.add_argument("filepath", help="Path to the pcap/pcapng file")
    pcap_parser.add_argument("--db", default="fingerprints.json", help="Path to fingerprints JSON DB")
    pcap_parser.add_argument("--verbose", action="store_true", help="Print detailed parsed fields")
    
    live_parser = subparsers.add_parser("live", help="Live capture (requires root)")
    live_parser.add_argument("interface", help="Network interface to sniff on")
    live_parser.add_argument("--db", default="fingerprints.json", help="Path to fingerprints JSON DB")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    db = FingerprintDB(args.db)
    
    if args.command == "pcap":
        if not Path(args.filepath).exists():
            print(f"Error: {args.filepath} not found.")
            sys.exit(1)
            
        print(f"Analyzing PCAP: {args.filepath}")
        for result in read_pcap(args.filepath):
            if result.client_hello:
                ja3_raw = compute_ja3_string(result.client_hello)
                ja3_hash = compute_ja3_hash(result.client_hello)
                match = db.lookup(ja3_hash)
                
                print(f"[ClientHello] {result.src_ip}:{result.src_port} -> {result.dst_ip}:{result.dst_port}")
                if result.client_hello.server_name:
                    print(f"  SNI:     {result.client_hello.server_name}")
                print(f"  JA3:     {ja3_hash}")
                print(f"  JA3 raw: {ja3_raw}")
                if match:
                    print(f"  Match:   {match} (from DB)")
                else:
                    print("  Match:   Unknown")
                print()
                
            if result.server_hello:
                ja3s_raw = compute_ja3s_string(result.server_hello)
                ja3s_hash = compute_ja3s_hash(result.server_hello)
                match = db.lookup(ja3s_hash)
                
                print(f"[ServerHello] {result.src_ip}:{result.src_port} -> {result.dst_ip}:{result.dst_port}")
                print(f"  JA3S:     {ja3s_hash}")
                print(f"  JA3S raw: {ja3s_raw}")
                if match:
                    print(f"  Match:   {match} (from DB)")
                print()

    elif args.command == "live":
        print("Live capture is currently out of scope per phase plan.")
        sys.exit(1)

if __name__ == "__main__":
    main()
