from dataclasses import dataclass
import struct

@dataclass(frozen=True)
class ClientHelloFields:
    """All fields extracted from a TLS ClientHello, in original wire order."""
    tls_version: int                     # Handshake body version (e.g. 0x0303 = 771)
    cipher_suites: tuple[int, ...]       # All cipher suite values (pre-GREASE-filter)
    extensions: tuple[int, ...]          # Extension type codes, wire order
    elliptic_curves: tuple[int, ...]     # From supported_groups (ext 0x000a)
    ec_point_formats: tuple[int, ...]    # From ec_point_formats (ext 0x000b)
    server_name: str | None              # SNI hostname, if present
    # Fields for JA4 (future):
    alpn: tuple[str, ...] | None = None
    signature_algorithms: tuple[int, ...] | None = None
    supported_versions: tuple[int, ...] | None = None

@dataclass(frozen=True)
class ServerHelloFields:
    """All fields extracted from a TLS ServerHello."""
    tls_version: int                     # Handshake body version
    cipher_suite: int                    # Single selected cipher
    extensions: tuple[int, ...]          # Extension type codes, wire order
    # Field for JA4S (future):
    supported_version: int | None = None


def parse_tls_record(data: bytes, offset: int = 0) -> tuple[int, int, bytes, int]:
    """
    Parse a TLS record header from `data` at `offset`.
    Returns (content_type, version, fragment_bytes, next_offset).

    Every TLS message is wrapped in a Record layer (5 bytes):
    - Byte 0: Content Type (22 means Handshake, 23 is Application Data, etc.)
    - Bytes 1-2: Legacy Record Version (e.g., 0x0301 for TLS 1.0). JA3 explicitly ignores this version.
    - Bytes 3-4: Fragment Length.
    """
    if len(data) - offset < 5:
        raise ValueError("Insufficient data for TLS record header")
    
    content_type = data[offset]
    version = struct.unpack('!H', data[offset+1:offset+3])[0]
    fragment_length = struct.unpack('!H', data[offset+3:offset+5])[0]
    
    next_offset = offset + 5 + fragment_length
    if len(data) < next_offset:
        raise ValueError("Truncated TLS record fragment")
        
    fragment = data[offset+5:next_offset]
    return content_type, version, fragment, next_offset


def parse_handshake_header(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """
    Parse a Handshake header from `data` at `offset`.
    Returns (msg_type, length, next_offset).

    Every Handshake message is wrapped in a Handshake layer (4 bytes):
    - Byte 0: Message Type (1 = ClientHello, 2 = ServerHello)
    - Bytes 1-3: Message Length (3 bytes)
    """
    if len(data) - offset < 4:
        raise ValueError("Insufficient data for Handshake header")
        
    msg_type = data[offset]
    # Length is 3 bytes, unpack by padding it to 4 bytes
    length_bytes = b'\x00' + data[offset+1:offset+4]
    length = struct.unpack('!I', length_bytes)[0]
    
    return msg_type, length, offset + 4


def parse_client_hello(data: bytes) -> ClientHelloFields:
    """
    Parse the ClientHello handshake body (after the 4-byte handshake header).

    This is where the JA3 components are extracted. TLS is essentially a massive chain of Type-Length-Value (TLV) structures.

    1. Version (2 bytes): The true TLS handshake version (e.g., 0x0303 for TLS 1.2). This is the first field in a JA3 hash.
    2. Random (32 bytes): We skip this by advancing our offset pointer by 32.
    3. Session ID (Variable): We read 1 byte for the length (N), then skip the next N bytes.
    4. Cipher Suites (Variable): We read 2 bytes for the total length of the cipher suites list (M), then loop M/2 times, unpacking 2-byte chunks (!H). This forms the second field of JA3.
    5. Compression Methods (Variable): Read 1 byte for length, skip that many bytes.
    6. Extensions (Variable): We read 2 bytes for the total extensions length, then enter a while loop.
        - Every extension has a 2-byte Type and 2-byte Length.
        - We record the Extension Type (the third field of JA3).
        - If the Type is 0x0000 (SNI), we parse the hostname to print it in the CLI.
        - If the Type is 0x000a (Supported Groups/Curves), we parse the 2-byte curve IDs (the fourth field of JA3).
        - If the Type is 0x000b (EC Point Formats), we parse the 1-byte formats (the fifth field of JA3).
    """
    
    # Minimum size: version (2) + random (32) + session_id_len (1) = 35 bytes
    if len(data) < 35:
        raise ValueError("ClientHello too short")
        
    tls_version = struct.unpack('!H', data[0:2])[0]
    
    offset = 34 # Skip version(2) and random(32)
    session_id_len = data[offset]
    offset += 1 + session_id_len
    
    if len(data) - offset < 2:
        raise ValueError("Truncated at cipher suites length")
        
    cipher_suites_len = struct.unpack('!H', data[offset:offset+2])[0]
    offset += 2

    if cipher_suites_len % 2 != 0:
        raise ValueError("Invalid cipher suites length")
    
    if len(data) - offset < cipher_suites_len:
        raise ValueError("Truncated cipher suites")
        
    cipher_suites = []
    for i in range(0, cipher_suites_len, 2):
        cipher_suite = struct.unpack('!H', data[offset+i:offset+i+2])[0]
        cipher_suites.append(cipher_suite)
    offset += cipher_suites_len
    
    if len(data) - offset < 1:
        raise ValueError("Truncated at compression methods length")
        
    comp_methods_len = data[offset]
    offset += 1 + comp_methods_len
    if offset > len(data):
        raise ValueError("Truncated compression methods")
    extensions = []
    elliptic_curves = []
    ec_point_formats = []
    server_name = None
    alpn = []
    signature_algorithms = []
    supported_versions = []
    
    # If there is data left, parse extensions
    if offset < len(data):
        if len(data) - offset < 2:
            raise ValueError("Truncated at extensions total length")
            
        ext_total_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2

        if offset + ext_total_len > len(data):
            raise ValueError("Truncated extensions data")

        end_offset = offset + ext_total_len
        while offset + 4 <= end_offset:
            ext_type = struct.unpack('!H', data[offset:offset+2])[0]
            ext_len = struct.unpack('!H', data[offset+2:offset+4])[0]
            offset += 4
            
            if offset + ext_len > end_offset:
                break # Truncated extension data, stop parsing
                
            extensions.append(ext_type)
            ext_data = data[offset:offset+ext_len]
            
            if ext_type == 0x0000: # SNI (0)
                if len(ext_data) >= 5: # list len (2), type (1), name len (2)
                    name_type = ext_data[2]
                    if name_type == 0: # Hostname
                        name_len = struct.unpack('!H', ext_data[3:5])[0]
                        if len(ext_data) >= 5 + name_len:
                            server_name = ext_data[5:5+name_len].decode('utf-8', errors='ignore')
                            
            elif ext_type == 0x000a: # supported_groups (10)
                if len(ext_data) >= 2:
                    grp_list_len = struct.unpack('!H', ext_data[0:2])[0]
                    for i in range(0, grp_list_len, 2):
                        if 2+i+2 <= len(ext_data):
                            curve = struct.unpack('!H', ext_data[2+i:4+i])[0]
                            elliptic_curves.append(curve)
                            
            elif ext_type == 0x000b: # ec_point_formats (11)
                if len(ext_data) >= 1:
                    fmt_list_len = ext_data[0]
                    for i in range(fmt_list_len):
                        if 1+i < len(ext_data):
                            ec_point_formats.append(ext_data[1+i])
                            
            elif ext_type == 0x0010: # ALPN (16)
                if len(ext_data) >= 2:
                    alpn_len = struct.unpack('!H', ext_data[0:2])[0]
                    end = min(len(ext_data), 2 + alpn_len)
                    p = 2
                    while p < end:
                        s_len = ext_data[p]
                        p += 1
                        if p + s_len <= end:
                            alpn_str = ext_data[p:p+s_len].decode('utf-8', errors='ignore')
                            alpn.append(alpn_str)
                        p += s_len
                        
            elif ext_type == 0x000d: # signature_algorithms (13)
                if len(ext_data) >= 2:
                    sig_len = struct.unpack('!H', ext_data[0:2])[0]
                    for i in range(0, sig_len, 2):
                        if 2+i+2 <= len(ext_data):
                            sig_alg = struct.unpack('!H', ext_data[2+i:4+i])[0]
                            signature_algorithms.append(sig_alg)
                            
            elif ext_type == 0x002b: # supported_versions (43)
                if len(ext_data) >= 1:
                    v_len = ext_data[0]
                    for i in range(0, v_len, 2):
                        if 1+i+2 <= len(ext_data):
                            sv = struct.unpack('!H', ext_data[1+i:3+i])[0]
                            supported_versions.append(sv)
                            
            offset += ext_len

    return ClientHelloFields(
        tls_version=tls_version,
        cipher_suites=tuple(cipher_suites),
        extensions=tuple(extensions),
        elliptic_curves=tuple(elliptic_curves),
        ec_point_formats=tuple(ec_point_formats),
        server_name=server_name,
        alpn=tuple(alpn) if alpn else None,
        signature_algorithms=tuple(signature_algorithms) if signature_algorithms else None,
        supported_versions=tuple(supported_versions) if supported_versions else None
    )


def parse_server_hello(data: bytes) -> ServerHelloFields:
    """
    Parse the ServerHello handshake body (after the 4-byte handshake header).
    """
    if len(data) < 38:
        raise ValueError("ServerHello too short")
        
    tls_version = struct.unpack('!H', data[0:2])[0]
    
    offset = 34 # Skip version(2) and random(32)
    session_id_len = data[offset]
    offset += 1 + session_id_len
    
    if len(data) - offset < 2:
        raise ValueError("Truncated at cipher suite")
        
    cipher_suite = struct.unpack('!H', data[offset:offset+2])[0]
    offset += 2
    
    if len(data) - offset < 1:
        raise ValueError("Truncated at compression method")
    offset += 1
    
    extensions = []
    supported_version = None
    
    # If there is data left, parse extensions
    if offset < len(data):
        if len(data) - offset < 2:
            raise ValueError("Truncated at extensions total length")
            
        ext_total_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        
        end_offset = min(offset + ext_total_len, len(data))
            
        while offset + 4 <= end_offset:
            ext_type = struct.unpack('!H', data[offset:offset+2])[0]
            ext_len = struct.unpack('!H', data[offset+2:offset+4])[0]
            offset += 4
            
            if offset + ext_len > end_offset:
                break
                
            extensions.append(ext_type)
            ext_data = data[offset:offset+ext_len]
            
            if ext_type == 0x002b: # supported_versions (43) in ServerHello is just 2 bytes
                if len(ext_data) >= 2:
                    supported_version = struct.unpack('!H', ext_data[0:2])[0]
                    
            offset += ext_len

    return ServerHelloFields(
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        extensions=tuple(extensions),
        supported_version=supported_version
    )
