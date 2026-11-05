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
    
    # Both match FoxIO's expected output (python/test/testdata/sigalg-grease.pcapng.json)
    assert ja4 == "t13d1517h2_8daaf6152771_cb7bf5808d99"
    assert ja4s == "t130200_1302_234ea6891581"

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
    
    # First ALPN value is 0xBA 0xAD: not alphanumeric, so the spec takes the first and last
    # characters of its hex "baad" -> "bd". (FoxIO's reference tool still prints "99" here;
    # this follows technical_details/JA4.md.)
    assert ja4 == "t13d1516bd_8daaf6152771_e5627efa2ab1"
    # Matches FoxIO's expected JA4S (python/test/testdata/tls-non-ascii-alpn.pcapng.json)
    assert ja4s == "t130200_1301_234ea6891581"
