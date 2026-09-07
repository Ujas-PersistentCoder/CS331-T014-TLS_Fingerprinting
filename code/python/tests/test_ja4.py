import pytest
from src.parser import ClientHelloFields, ServerHelloFields
from src.ja4 import (
    compute_ja4_string,
    compute_ja4s_string,
    is_literal_ip,
    resolve_ja4_version,
    resolve_alpn_chars
)

def test_is_literal_ip():
    assert is_literal_ip("192.168.1.1")
    assert is_literal_ip("10.0.0.1")
    assert is_literal_ip("2001:db8::1")
    assert not is_literal_ip("example.com")
    assert not is_literal_ip("localhost")
    assert not is_literal_ip(None)
    assert not is_literal_ip("")

def test_resolve_ja4_version():
    # TLS 1.3
    fields13 = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(), extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
        supported_versions=(0x0304, 0x0303)
    )
    assert resolve_ja4_version(fields13) == "13"
    
    # TLS 1.2 via supported_versions
    fields12 = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(), extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
        supported_versions=(0x0303,)
    )
    assert resolve_ja4_version(fields12) == "12"
    
    # GREASE filtering in supported_versions
    fields_grease = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(), extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
        supported_versions=(0x4a4a, 0x0303)
    )
    assert resolve_ja4_version(fields_grease) == "12"
    
    # Fallback to tls_version
    fields_fallback = ClientHelloFields(
        tls_version=0x0301, # TLS 1.0
        cipher_suites=(), extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
    )
    assert resolve_ja4_version(fields_fallback) == "10"

def test_resolve_alpn_chars():
    assert resolve_alpn_chars(("h2", "http/1.1")) == "h2"
    assert resolve_alpn_chars(("http/1.1",)) == "h1"
    assert resolve_alpn_chars(("H3",)) == "h3"
    assert resolve_alpn_chars(None) == "00"
    assert resolve_alpn_chars(()) == "00"
    assert resolve_alpn_chars(("",)) == "00"
    # Non-alphanumeric shortcut
    assert resolve_alpn_chars(("\xea\xea",)) == "00"

def test_ja4_known_vector_controlled_curl():
    # Derived from controlled_curl.pcap.
    # Note: original seed DB had 't13d3110h2' due to the C++ stripping SNI/ALPN.
    # The correct extension count is 12, so the prefix is 't13d3112h2'
    fields = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(
            4866, 4867, 4865, 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199, 158, 
            49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 
            157, 156, 61, 60, 53, 47, 255
        ),
        extensions=(0, 11, 10, 16, 22, 23, 49, 13, 43, 45, 51, 21),
        elliptic_curves=(), # irrelevant for ja4
        ec_point_formats=(), # irrelevant for ja4
        server_name="localhost",
        alpn=("h2", "http/1.1"),
        # The actual signature algorithms from controlled_curl.pcap:
        signature_algorithms=(1027, 1283, 1539, 2055, 2056, 2057, 2058, 2059, 2052, 2053, 2054, 1025, 1281, 1537, 771, 769, 770, 1026, 1282, 1538),
        supported_versions=(0x0304, 0x0303)
    )
    ja4 = compute_ja4_string(fields)
    assert ja4 == "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6"

def test_ja4_cipher_grease_filter():
    # Adding a GREASE cipher (0x1a1a) shouldn't change hash or count
    fields = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(0x1a1a, 0xc02b),
        extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
    )
    ja4 = compute_ja4_string(fields)
    # Count should be 01, ja4_b should match hash of "c02b"
    assert ja4.startswith("t12i010000_")
    import hashlib
    assert hashlib.sha256(b"c02b").hexdigest()[:12] in ja4

def test_ja4_extension_grease_filter():
    fields = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(0xc02b,),
        extensions=(0x2a2a, 0x000a, 0x3a3a),
        elliptic_curves=(), ec_point_formats=(), server_name=None,
    )
    ja4 = compute_ja4_string(fields)
    # Ext count should be 01
    assert ja4.startswith("t12i010100_")
    import hashlib
    assert hashlib.sha256(b"000a").hexdigest()[:12] in ja4

def test_ja4_empty_extensions():
    fields = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(0xc02b,),
        extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
    )
    ja4 = compute_ja4_string(fields)
    # ja4_c should be the empty sentinel
    assert ja4.endswith("_000000000000")

def test_ja4_ip_literal_sni():
    fields = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(0xc02b,),
        extensions=(0x0000,), # SNI
        elliptic_curves=(), ec_point_formats=(),
        server_name="192.168.1.1" # IP literal
    )
    ja4 = compute_ja4_string(fields)
    # SNI character should be 'i', not 'd', because it's an IP literal
    assert ja4.startswith("t12i010100_")

def test_ja4s_known_vector_controlled_curl():
    # Derived from controlled_curl.pcap in seed db
    # t130200_1302_a56c5b993250
    fields = ServerHelloFields(
        tls_version=0x0303,
        cipher_suite=0x1302,
        extensions=(0x002b, 0x0033),
        supported_version=0x0304
    )
    ja4s = compute_ja4s_string(fields)
    assert ja4s == "t130200_1302_a56c5b993250"

def test_ja4s_alpn_in_output():
    fields = ServerHelloFields(
        tls_version=0x0303,
        cipher_suite=0x1302,
        extensions=(0x0010, 0x002b), # ALPN, supported_versions
        supported_version=0x0304,
        alpn="h2"
    )
    ja4s = compute_ja4s_string(fields)
    # 'h2' is in ALPN fields. Excount is 2 (0x0010 and 0x002b are both non-GREASE).
    assert ja4s.startswith("t1302h2_")
    import hashlib
    # ALPN (0010) is stripped from ja4s_c hash, leaving only 002b
    assert hashlib.sha256(b"002b").hexdigest()[:12] in ja4s

def test_ja4s_version_fallback():
    fields = ServerHelloFields(
        tls_version=0x0303,
        cipher_suite=0xc02b,
        extensions=(0x00ff,)
    )
    ja4s = compute_ja4s_string(fields)
    assert ja4s.startswith("t120100_")
