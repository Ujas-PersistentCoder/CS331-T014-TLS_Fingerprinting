import hashlib
import string
from src.parser import ClientHelloFields, ServerHelloFields
from src.ja3 import filter_grease, is_grease

# JA4 spec version table (technical_details/JA4.md, "TLS and DTLS Version")
JA4_VERSION_CODES = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2",
    0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3",
}
ASCII_ALNUM = frozenset(string.ascii_letters + string.digits)

def ja4_version_code(version: int) -> str:
    return JA4_VERSION_CODES.get(version, "00")

def resolve_ja4_version(fields: ClientHelloFields) -> str:
    # Highest non-GREASE supported_versions value, else the ClientHello legacy_version.
    # An unknown highest value maps to "00", as in FoxIO's reference.
    versions = filter_grease(fields.supported_versions or ())
    if versions:
        return ja4_version_code(max(versions))
    return ja4_version_code(fields.tls_version)

def resolve_alpn_chars(alpn: tuple[str, ...] | None) -> str:
    """First and last character of the FIRST ALPN value as sent (GREASE included).

    Values are latin-1 decoded, so each character is one wire byte. If either end is not
    ASCII alphanumeric, use the first and last characters of the value's hex encoding
    (spec examples: 0xAB -> "ab", 0x30 0xAB -> "3b", 0x61 0x20 -> "60").
    """
    if not alpn or not alpn[0]:
        return "00"
    first_alpn = alpn[0]
    f, l = first_alpn[0], first_alpn[-1]
    if f in ASCII_ALNUM and l in ASCII_ALNUM:
        return f + l
    hex_value = first_alpn.encode("latin-1").hex()
    return hex_value[0] + hex_value[-1]

def _sha256_hex12(data: str) -> str:
    if not data:
        return "000000000000"
    return hashlib.sha256(data.encode('utf-8')).hexdigest()[:12]

def _ja4_ext_count(extensions: tuple[int, ...]) -> int:
    return len(filter_grease(extensions))

def compute_ja4_a(fields: ClientHelloFields) -> str:
    protocol = 't' # TCP
    version = resolve_ja4_version(fields)
    
    # 'd' whenever the SNI extension is present, whatever it contains (spec: "If the SNI
    # extension (0x0000) exists, then the destination of the connection is a domain")
    sni = 'd' if 0x0000 in fields.extensions else 'i'
        
    ciphers_count = min(len(filter_grease(fields.cipher_suites)), 99)
    # The Python implementation follows the JA4 test vectors, counting all
    # non-GREASE extensions in the prefix.
    exts_count = min(_ja4_ext_count(fields.extensions), 99)
    alpn_chars = resolve_alpn_chars(fields.alpn)
    
    return f"{protocol}{version}{sni}{ciphers_count:02d}{exts_count:02d}{alpn_chars}"

def compute_ja4_b_raw(fields: ClientHelloFields) -> str:
    ciphers = filter_grease(fields.cipher_suites)
    return ",".join(f"{c:04x}" for c in sorted(ciphers))

def compute_ja4_b(fields: ClientHelloFields) -> str:
    raw = compute_ja4_b_raw(fields)
    return _sha256_hex12(raw) if raw else "000000000000"

def compute_ja4_c_raw(fields: ClientHelloFields) -> str:
    exts = filter_grease(fields.extensions)
    filtered = [e for e in exts if e not in (0x0000, 0x0010)]
    exts_str = ",".join(f"{e:04x}" for e in sorted(filtered))
    
    if fields.signature_algorithms:
        sigalgs = filter_grease(fields.signature_algorithms)
        if sigalgs:
            sigalgs_str = ",".join(f"{s:04x}" for s in sigalgs)
            if exts_str:
                return exts_str + "_" + sigalgs_str
            return "_" + sigalgs_str
            
    return exts_str

def compute_ja4_c(fields: ClientHelloFields) -> str:
    raw = compute_ja4_c_raw(fields)
    return _sha256_hex12(raw) if raw else "000000000000"

def compute_ja4_string(fields: ClientHelloFields) -> str:
    ja4_a = compute_ja4_a(fields)
    ja4_b = compute_ja4_b(fields)
    ja4_c = compute_ja4_c(fields)
    return f"{ja4_a}_{ja4_b}_{ja4_c}"

# --- JA4S (Server-Side) ---

def compute_ja4s_a(fields: ServerHelloFields) -> str:
    protocol = 't' # TCP
    
    sv = fields.supported_version
    version = ja4_version_code(sv if sv and not is_grease(sv) else fields.tls_version)

    # Every extension the server sent, ALPN and GREASE included (FoxIO reference to_ja4s:
    # "extensions ... in the order they are present (include grease values)")
    exts_count = min(len(fields.extensions), 99)
    alpn_chars = resolve_alpn_chars((fields.alpn,) if fields.alpn else None)

    return f"{protocol}{version}{exts_count:02d}{alpn_chars}"

def compute_ja4s_b(fields: ServerHelloFields) -> str:
    return f"{fields.cipher_suite:04x}"

def compute_ja4s_c_raw(fields: ServerHelloFields) -> str:
    # Wire order, nothing sorted or removed: the server's extension order is its fingerprint
    return ",".join(f"{e:04x}" for e in fields.extensions)

def compute_ja4s_c(fields: ServerHelloFields) -> str:
    raw = compute_ja4s_c_raw(fields)
    return _sha256_hex12(raw) if raw else "000000000000"

def compute_ja4s_string(fields: ServerHelloFields) -> str:
    ja4s_a = compute_ja4s_a(fields)
    ja4s_b = compute_ja4s_b(fields)
    ja4s_c = compute_ja4s_c(fields)
    return f"{ja4s_a}_{ja4s_b}_{ja4s_c}"