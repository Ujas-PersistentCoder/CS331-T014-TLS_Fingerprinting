import pytest
from pathlib import Path
from src.capture import read_pcap, CaptureStats
from src.ja4 import compute_ja4_string, compute_ja4s_string

# Ensure we're relative to the project root
PCAPS_DIR = Path(__file__).parent.parent.parent / 'pcaps'

def test_integration_sigalg_grease():
    pcap_path = PCAPS_DIR / 'sigalg-grease.pcapng'
    assert pcap_path.exists(), f"PCAP not found: {pcap_path}"
    
    results = list(read_pcap(str(pcap_path), CaptureStats()))
    
    client_hellos = [r for r in results if r.client_hello]
    server_hellos = [r for r in results if r.server_hello]
    
    assert len(client_hellos) >= 1
    assert len(server_hellos) >= 1
    
    ja4 = compute_ja4_string(client_hellos[0].client_hello)
    ja4s = compute_ja4s_string(server_hellos[0].server_hello)
    
    assert ja4 == "t13d1517h2_8daaf6152771_cb7bf5808d99"
    assert ja4s == "t130200_1302_a56c5b993250"

def test_integration_tls_non_ascii_alpn():
    pcap_path = PCAPS_DIR / 'tls-non-ascii-alpn.pcapng'
    assert pcap_path.exists(), f"PCAP not found: {pcap_path}"
    
    results = list(read_pcap(str(pcap_path), CaptureStats()))
    
    client_hellos = [r for r in results if r.client_hello]
    server_hellos = [r for r in results if r.server_hello]
    
    assert len(client_hellos) >= 1
    assert len(server_hellos) >= 1
    
    ja4 = compute_ja4_string(client_hellos[0].client_hello)
    ja4s = compute_ja4s_string(server_hellos[0].server_hello)
    
    # Note: 00 at the end of ja4 prefix because non-ascii ALPN maps to '00'
    assert ja4 == "t13d151600_8daaf6152771_e5627efa2ab1"
    assert ja4s == "t130200_1301_a56c5b993250"
