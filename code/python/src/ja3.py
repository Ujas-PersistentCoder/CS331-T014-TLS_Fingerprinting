import hashlib
from src.parser import ClientHelloFields, ServerHelloFields

# RFC 8701 GREASE values
GREASE_VALUES = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
})

def is_grease(value: int) -> bool:
    return value in GREASE_VALUES

def filter_grease(values: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(v for v in values if not is_grease(v))

def serialize_field(values: tuple[int, ...]) -> str:
    """Format tuple into hyphen-separated string of decimals."""
    return "-".join(str(v) for v in values)

def compute_ja3_string(fields: ClientHelloFields) -> str:
    """
    Build the raw JA3 string:
    TLSVersion,Ciphers,Extensions,Curves,PointFormats
    """
    version_str = str(fields.tls_version)
    
    ciphers_str = serialize_field(filter_grease(fields.cipher_suites))
    extensions_str = serialize_field(filter_grease(fields.extensions))
    curves_str = serialize_field(filter_grease(fields.elliptic_curves))
    formats_str = serialize_field(filter_grease(fields.ec_point_formats))
    
    return f"{version_str},{ciphers_str},{extensions_str},{curves_str},{formats_str}"

def compute_ja3_hash(fields: ClientHelloFields) -> str:
    """MD5 hex digest of the JA3 string."""
    ja3_str = compute_ja3_string(fields)
    return hashlib.md5(ja3_str.encode('utf-8')).hexdigest()

def compute_ja3s_string(fields: ServerHelloFields) -> str:
    """
    Build the raw JA3S string:
    TLSVersion,Cipher,Extensions
    """
    version_str = str(fields.tls_version)
    cipher_str = str(fields.cipher_suite)
    extensions_str = serialize_field(filter_grease(fields.extensions))
    
    return f"{version_str},{cipher_str},{extensions_str}"

def compute_ja3s_hash(fields: ServerHelloFields) -> str:
    """MD5 hex digest of the JA3S string."""
    ja3s_str = compute_ja3s_string(fields)
    return hashlib.md5(ja3s_str.encode('utf-8')).hexdigest()
