import struct
import pytest
from src.parser import (
    ClientHelloFields,
    ServerHelloFields,
    parse_tls_record,
    parse_handshake_header,
    parse_client_hello,
    parse_server_hello,
)

def build_client_hello_body(
    version: bytes,
    ciphers: list[int],
    extensions: bytes = b''
) -> bytes:
    """Helper to build a ClientHello handshake body."""
    # version (2) + random (32) + session_id_len (1)
    body = version + (b'\x00' * 32) + b'\x00'
    
    # cipher suites
    body += struct.pack('!H', len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack('!H', c)
        
    # compression methods (1 byte len + 1 byte method=00)
    body += b'\x01\x00'
    
    if extensions:
        body += struct.pack('!H', len(extensions)) + extensions
        
    return body

def test_parse_tls_record():
    record = b'\x16\x03\x03\x00\x04\x01\x02\x03\x04'
    content_type, version, fragment, next_offset = parse_tls_record(record)
    assert content_type == 22
    assert version == 0x0303
    assert fragment == b'\x01\x02\x03\x04'
    assert next_offset == 9

def test_parse_tls_record_truncated():
    record = b'\x16\x03\x03\x00\x05\x01\x02\x03\x04' # claims 5 bytes, only 4 exist
    with pytest.raises(ValueError, match="Truncated TLS record fragment"):
        parse_tls_record(record)

def test_parse_handshake_header():
    header = b'\x01\x00\x01\x00' # type 1, length 256
    msg_type, length, next_offset = parse_handshake_header(header)
    assert msg_type == 1
    assert length == 256
    assert next_offset == 4

def test_parse_minimal_client_hello():
    body = build_client_hello_body(b'\x03\x03', [0xc02b, 0xc02f])
    fields = parse_client_hello(body)
    
    assert fields.tls_version == 0x0303
    assert fields.cipher_suites == (0xc02b, 0xc02f)
    assert fields.extensions == ()
    assert fields.elliptic_curves == ()
    assert fields.ec_point_formats == ()
    assert fields.server_name is None
    assert fields.alpn is None
    assert fields.signature_algorithms is None
    assert fields.supported_versions is None

def test_parse_client_hello_with_extensions():
    # SNI extension (0x0000): example.com
    # ext_type (00 00), ext_len (00 10), list_len (00 0e), name_type (00), name_len (00 0b)
    sni = b'\x00\x00\x00\x10\x00\x0e\x00\x00\x0bexample.com'
    
    # Supported groups (0x000a): X25519 (0x001d), SECP256R1 (0x0017)
    groups = b'\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17'
    
    # EC point formats (0x000b): uncompressed (0)
    formats = b'\x00\x0b\x00\x02\x01\x00'
    
    # ALPN (0x0010): h2, http/1.1
    alpn = b'\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1'
    
    extensions = sni + groups + formats + alpn
    
    body = build_client_hello_body(b'\x03\x03', [0xc02b], extensions)
    fields = parse_client_hello(body)
    
    assert fields.extensions == (0x0000, 0x000a, 0x000b, 0x0010)
    assert fields.server_name == "example.com"
    assert fields.elliptic_curves == (0x001d, 0x0017)
    assert fields.ec_point_formats == (0,)
    assert fields.alpn == ("h2", "http/1.1")

def test_parse_client_hello_with_grease():
    # GREASE cipher: 0x2a2a
    # GREASE extension: 0x3a3a, empty data
    # GREASE curve: 0x4a4a
    ciphers = [0x2a2a, 0xc02b]
    
    grease_ext = b'\x3a\x3a\x00\x00'
    groups_ext = b'\x00\x0a\x00\x06\x00\x04\x4a\x4a\x00\x17'
    
    body = build_client_hello_body(b'\x03\x03', ciphers, grease_ext + groups_ext)
    fields = parse_client_hello(body)
    
    # Parser should preserve GREASE values; JA3 module will filter them out later
    assert fields.cipher_suites == (0x2a2a, 0xc02b)
    assert fields.extensions == (0x3a3a, 0x000a)
    assert fields.elliptic_curves == (0x4a4a, 0x0017)

def test_parse_server_hello():
    # version (2) + random (32) + session_id_len (1)
    body = b'\x03\x03' + (b'\x00' * 32) + b'\x00'
    # single cipher (2 bytes) + compression method (1 byte)
    body += struct.pack('!H', 0xc02f) + b'\x00'
    
    # supported versions extension (0x002b)
    exts = b'\x00\x2b\x00\x02\x03\x04' # supported version TLS 1.3 (0x0304)
    body += struct.pack('!H', len(exts)) + exts
    
    fields = parse_server_hello(body)
    
    assert fields.tls_version == 0x0303
    assert fields.cipher_suite == 0xc02f
    assert fields.extensions == (0x002b,)
    assert fields.supported_version == 0x0304
