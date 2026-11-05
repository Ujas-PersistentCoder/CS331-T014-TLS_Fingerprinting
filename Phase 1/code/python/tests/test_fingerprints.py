import pytest
from src.parser import ClientHelloFields, ServerHelloFields
from src.ja3 import (
    compute_ja3_string,
    compute_ja3_hash,
    compute_ja3s_string,
    compute_ja3s_hash,
    filter_grease
)

def test_filter_grease():
    values = (0x0000, 0x0a0a, 0x0010, 0x1a1a, 0xc02b)
    filtered = filter_grease(values)
    assert filtered == (0x0000, 0x0010, 0xc02b)

def test_ja3_known_fingerprint_1():
    # 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5
    fields = ClientHelloFields(
        tls_version=769,
        cipher_suites=(47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4),
        extensions=(0, 10, 11),
        elliptic_curves=(23, 24, 25),
        ec_point_formats=(0,),
        server_name=None
    )
    
    ja3_str = compute_ja3_string(fields)
    assert ja3_str == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    
    ja3_hash = compute_ja3_hash(fields)
    assert ja3_hash == "ada70206e40642a3e4461f35503241d5"

def test_ja3_known_fingerprint_empty_sections():
    # 769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6
    fields = ClientHelloFields(
        tls_version=769,
        cipher_suites=(4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99),
        extensions=(),
        elliptic_curves=(),
        ec_point_formats=(),
        server_name=None
    )
    
    ja3_str = compute_ja3_string(fields)
    assert ja3_str == "769,4-5-10-9-100-98-3-6-19-18-99,,,"
    
    ja3_hash = compute_ja3_hash(fields)
    assert ja3_hash == "de350869b8c85de67a350c8d186f11e6"

def test_ja3_with_grease_values():
    # Test that grease values in the struct are correctly filtered out
    fields = ClientHelloFields(
        tls_version=771,
        cipher_suites=(0x1a1a, 47, 53, 0x2a2a),
        extensions=(0x3a3a, 0, 10, 11, 0x4a4a),
        elliptic_curves=(23, 0x5a5a, 24),
        ec_point_formats=(0, 0x6a6a),
        server_name=None
    )
    ja3_str = compute_ja3_string(fields)
    assert ja3_str == "771,47-53,0-10-11,23-24,0"

def test_ja3s_known_fingerprint():
    # Typical JA3S string: TLSVersion,Cipher,Extensions
    fields = ServerHelloFields(
        tls_version=771,
        cipher_suite=49199,
        extensions=(0, 11, 16)
    )
    
    ja3s_str = compute_ja3s_string(fields)
    assert ja3s_str == "771,49199,0-11-16"
    
    ja3s_hash = compute_ja3s_hash(fields)
    import hashlib
    expected_hash = hashlib.md5(b"771,49199,0-11-16").hexdigest()
    assert ja3s_hash == expected_hash

def test_ja3s_with_grease():
    fields = ServerHelloFields(
        tls_version=771,
        cipher_suite=49199,
        extensions=(0x1a1a, 0, 11, 0x2a2a, 16)
    )
    
    ja3s_str = compute_ja3s_string(fields)
    assert ja3s_str == "771,49199,0-11-16"
