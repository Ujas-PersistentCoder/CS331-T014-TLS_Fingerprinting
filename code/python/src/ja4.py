import hashlib
import ipaddress
from src.parser import ClientHelloFields, ServerHelloFields
from src.ja3 import filter_grease, is_grease

def is_literal_ip(hostname: str | None) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def resolve_ja4_version(fields: ClientHelloFields) -> str:
    if fields.supported_versions:
        filtered = filter_grease(fields.supported_versions)
        if 0x0304 in filtered: return "13"
        if 0x0303 in filtered: return "12"
        if 0x0302 in filtered: return "11"
        if 0x0301 in filtered: return "10"
        
    v = fields.tls_version
    if v == 0x0304: return "13"
    if v == 0x0303: return "12"
    if v == 0x0302: return "11"
    if v == 0x0301: return "10"
    if v == 0x0300: return "s3"
    if v == 0x0200: return "s2"
    if v == 0x0100: return "s1"
    return "00"

def resolve_alpn_chars(alpn: tuple[str, ...] | None) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first_alpn = alpn[0]
    
    f = first_alpn[0]
    l = first_alpn[-1]
    
    f_char = f.lower() if (f.isalnum() and f.isascii()) else '0'
    l_char = l.lower() if (l.isalnum() and l.isascii()) else '0'
    return f_char + l_char

def _sha256_hex12(data: str) -> str:
    if not data:
        return "000000000000"
    return hashlib.sha256(data.encode('utf-8')).hexdigest()[:12]

def _ja4_ext_count(extensions: tuple[int, ...]) -> int:
    return len(filter_grease(extensions))

def compute_ja4_a(fields: ClientHelloFields) -> str:
    protocol = 't' # TCP
    version = resolve_ja4_version(fields)
    
    if fields.server_name and not is_literal_ip(fields.server_name):
        sni = 'd'
    else:
        sni = 'i'
        
    ciphers_count = min(len(filter_grease(fields.cipher_suites)), 99)
    # The count includes ALPN and SNI but excludes GREASE.
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
    
    ver = fields.supported_version if fields.supported_version and not is_grease(fields.supported_version) else fields.tls_version
    
    if ver == 0x0304: version = "13"
    elif ver == 0x0303: version = "12"
    elif ver == 0x0302: version = "11"
    elif ver == 0x0301: version = "10"
    else: version = "00"
    
    exts_count = min(_ja4_ext_count(fields.extensions), 99)
    alpn_chars = resolve_alpn_chars((fields.alpn,) if fields.alpn else None)
    
    return f"{protocol}{version}{exts_count:02d}{alpn_chars}"

def compute_ja4s_b(fields: ServerHelloFields) -> str:
    return f"{fields.cipher_suite:04x}"

def compute_ja4s_c_raw(fields: ServerHelloFields) -> str:
    exts = filter_grease(fields.extensions)
    filtered = [e for e in exts if e != 0x0010]
    return ",".join(f"{e:04x}" for e in sorted(filtered))

def compute_ja4s_c(fields: ServerHelloFields) -> str:
    raw = compute_ja4s_c_raw(fields)
    return _sha256_hex12(raw) if raw else "000000000000"

def compute_ja4s_string(fields: ServerHelloFields) -> str:
    ja4s_a = compute_ja4s_a(fields)
    ja4s_b = compute_ja4s_b(fields)
    ja4s_c = compute_ja4s_c(fields)
    return f"{ja4s_a}_{ja4s_b}_{ja4s_c}"