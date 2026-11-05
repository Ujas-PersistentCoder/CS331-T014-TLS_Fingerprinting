import pytest
from src.parser import ClientHelloFields, ServerHelloFields
from src.ja4 import (
    compute_ja4_string,
    compute_ja4s_string,
    resolve_ja4_version,
    resolve_alpn_chars
)

# FoxIO reference vectors: values from FoxIO-LLC/ja4 python/test/testdata/*.json
FOXIO_CIPHERS = (0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035)
FOXIO_SIGALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)

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

    # Highest supported_versions value decides, even if it is unknown (FoxIO reference)
    fields_unknown = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(), extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
        supported_versions=(0x0303, 0x7f1c)
    )
    assert resolve_ja4_version(fields_unknown) == "00"

    # SSL 2.0 is 0x0002 in the spec table
    fields_ssl2 = ClientHelloFields(
        tls_version=0x0002,
        cipher_suites=(), extensions=(), elliptic_curves=(), ec_point_formats=(), server_name=None,
    )
    assert resolve_ja4_version(fields_ssl2) == "s2"

def test_resolve_alpn_chars():
    assert resolve_alpn_chars(("h2", "http/1.1")) == "h2"
    assert resolve_alpn_chars(("http/1.1",)) == "h1"
    assert resolve_alpn_chars(("H3",)) == "H3"  # Characters are used as-is, no case folding
    assert resolve_alpn_chars(("x",)) == "xx"    # A single character is both ends
    assert resolve_alpn_chars(None) == "00"
    assert resolve_alpn_chars(()) == "00"
    assert resolve_alpn_chars(("",)) == "00"
    assert resolve_alpn_chars(("", "h2")) == "00"  # Only the FIRST value counts, even if empty
    assert resolve_alpn_chars(("\x0a\x0a", "h2")) == "0a"  # GREASE first value is used, as hex

@pytest.mark.parametrize("raw, expected", [
    # Every example from technical_details/JA4.md, "ALPN Extension Value"
    (b"\xab", "ab"),
    (b"\x20", "20"),
    (b"\xab\xcd", "ad"),
    (b"\x20\x61", "21"),
    (b"\x30\xab", "3b"),
    (b"\x61\x20", "60"),
    (b"\x30\x31\xab\xcd", "3d"),
    (b"\x30\xab\xcd\x31", "01"),
])
def test_resolve_alpn_chars_spec_hex_examples(raw, expected):
    assert resolve_alpn_chars((raw.decode("latin-1"),)) == expected

def test_ja4_foxio_reference_vector():
    # tls-handshake.pcapng stream 0, wire order from JA4_ro.1
    fields = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=FOXIO_CIPHERS,
        extensions=(0xff01, 0x0033, 0x002d, 0x0005, 0x4469, 0x000d, 0x0010, 0x0023, 0x001b,
                    0x002b, 0x0000, 0x0012, 0x000a, 0x0017, 0x000b, 0x0015),
        elliptic_curves=(), ec_point_formats=(), server_name="example.com",
        alpn=("h2", "http/1.1"),
        signature_algorithms=FOXIO_SIGALGS,
        supported_versions=(0x0304, 0x0303),
    )
    assert compute_ja4_string(fields) == "t13d1516h2_8daaf6152771_e5627efa2ab1"

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

def test_ja4_sni_flag_follows_extension_presence():
    # Spec: 'd' if the SNI extension exists, whatever it holds (even an IP literal)
    with_sni = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(0xc02b,),
        extensions=(0x0000,), # SNI
        elliptic_curves=(), ec_point_formats=(),
        server_name="192.168.1.1"
    )
    assert compute_ja4_string(with_sni).startswith("t12d010100_")

    # No SNI extension -> 'i', even if a name was somehow recorded
    without_sni = ClientHelloFields(
        tls_version=0x0303,
        cipher_suites=(0xc02b,),
        extensions=(0x000a,),
        elliptic_curves=(), ec_point_formats=(),
        server_name="example.com"
    )
    assert compute_ja4_string(without_sni).startswith("t12i010100_")

@pytest.mark.parametrize("version, cipher, extensions, alpn, expected", [
    # FoxIO tls-handshake.pcapng streams 0 and 31: same extensions, different order
    (0x0304, 0x1301, (0x0033, 0x002b), None, "t130200_1301_234ea6891581"),
    (0x0304, 0x1301, (0x002b, 0x0033, 0x0029), None, "t130300_1301_0ee26285a86f"),
    # FoxIO badcurveball.pcap: TLS 1.2, ALPN kept in the hash and in wire order
    (None, 0xc02b, (0x0000, 0xff01, 0x000b, 0x0023, 0x0010), "http/1.1", "t1205h1_c02b_845f7282a956"),
])
def test_ja4s_foxio_reference_vectors(version, cipher, extensions, alpn, expected):
    fields = ServerHelloFields(
        tls_version=0x0303,
        cipher_suite=cipher,
        extensions=extensions,
        supported_version=version,
        alpn=alpn
    )
    assert compute_ja4s_string(fields) == expected

def test_ja4s_extensions_hashed_in_wire_order():
    import hashlib
    fields = ServerHelloFields(
        tls_version=0x0303,
        cipher_suite=0x1302,
        extensions=(0x0010, 0x002b), # ALPN, supported_versions
        supported_version=0x0304,
        alpn="h2"
    )
    ja4s = compute_ja4s_string(fields)
    assert ja4s.startswith("t1302h2_")
    # Not sorted, and ALPN is NOT removed
    assert ja4s.endswith(hashlib.sha256(b"0010,002b").hexdigest()[:12])

def test_ja4s_keeps_grease():
    # FoxIO reference: server extensions include GREASE in both the count and the hash
    import hashlib
    fields = ServerHelloFields(
        tls_version=0x0303,
        cipher_suite=0x1301,
        extensions=(0x0a0a, 0x002b),
        supported_version=0x0304,
    )
    assert compute_ja4s_string(fields) == "t130200_1301_" + hashlib.sha256(b"0a0a,002b").hexdigest()[:12]

def test_ja4s_version_fallback():
    fields = ServerHelloFields(
        tls_version=0x0303,
        cipher_suite=0xc02b,
        extensions=(0x00ff,)
    )
    ja4s = compute_ja4s_string(fields)
    assert ja4s.startswith("t120100_")
