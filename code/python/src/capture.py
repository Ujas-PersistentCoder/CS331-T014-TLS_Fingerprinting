import dpkt
import socket
from dataclasses import dataclass
from typing import Iterator

from src.parser import (
    ClientHelloFields, 
    ServerHelloFields,
    parse_tls_record,
    parse_handshake_header,
    parse_client_hello,
    parse_server_hello
)

@dataclass
class TLSHandshakeResult:
    """Complete result from processing a single handshake message."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    client_hello: ClientHelloFields | None = None
    server_hello: ServerHelloFields | None = None


def _inet_to_str(inet: bytes) -> str:
    """Convert inet object to a string."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


class TCPReassembler:
    """
    Minimal TCP reassembly to handle TLS records split across segments.
    """
    def __init__(self):
        # Buffer keyed by (src_ip, src_port, dst_ip, dst_port)
        self.buffers: dict[tuple, bytes] = {}
        
    def process_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> list[TLSHandshakeResult]:
        if not payload:
            return []
            
        key = (src_ip, src_port, dst_ip, dst_port)
        
        if key not in self.buffers:
            self.buffers[key] = payload
        else:
            self.buffers[key] += payload
            
        buf = self.buffers[key]
        results = []
        
        while buf:
            # We need at least 5 bytes for a TLS record header
            if len(buf) < 5:
                break
                
            if buf[0] != 22: # 22 == Handshake
                # Not a handshake record. This buffer is probably app data or something else.
                # We can't parse it, so clear the buffer and stop to prevent memory bloat.
                buf = b''
                break
                
            try:
                content_type, version, fragment, next_offset = parse_tls_record(buf)
            except ValueError as e:
                if "Truncated" in str(e) or "Insufficient" in str(e):
                    # We have a valid header but we don't have the full fragment yet. Wait for more packets.
                    break
                else:
                    # Malformed record, abandon buffer
                    buf = b''
                    break
                    
            # We successfully parsed a full TLS record containing handshake(s).
            # We process the fragment, then advance the buffer.
            buf = buf[next_offset:]
            
            # A single fragment can contain multiple handshake messages (e.g. ServerHello + Certificate)
            # or a single handshake message (ClientHello).
            frag_offset = 0
            while frag_offset < len(fragment):
                try:
                    msg_type, length, hs_offset = parse_handshake_header(fragment, frag_offset)
                except ValueError:
                    break
                    
                if frag_offset + 4 + length > len(fragment):
                    # Handshake message spans across multiple TLS records! This is rare but possible.
                    # For this implementation, we skip handling record-spanning handshakes.
                    break
                    
                handshake_data = fragment[hs_offset:hs_offset+length]
                
                try:
                    if msg_type == 1: # ClientHello
                        ch = parse_client_hello(handshake_data)
                        results.append(TLSHandshakeResult(src_ip, dst_ip, src_port, dst_port, client_hello=ch))
                    elif msg_type == 2: # ServerHello
                        sh = parse_server_hello(handshake_data)
                        results.append(TLSHandshakeResult(src_ip, dst_ip, src_port, dst_port, server_hello=sh))
                except ValueError:
                    # Failed to parse specific handshake message, continue to next
                    pass
                    
                frag_offset = hs_offset + length
                
        # Update buffer
        if buf:
            self.buffers[key] = buf
        elif key in self.buffers:
            del self.buffers[key]
            
        return results


def read_pcap(filepath: str) -> Iterator[TLSHandshakeResult]:
    """Read a pcap/pcapng file, yield TLSHandshakeResult for each handshake found."""
    with open(filepath, 'rb') as f:
        # Check magic to distinguish pcap vs pcapng
        magic = f.read(4)
        f.seek(0)
        
        if magic == b'\x0a\x0d\x0d\x0a':
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)
            
        datalink = getattr(reader, 'datalink', lambda: dpkt.pcap.DLT_EN10MB)()
        reassembler = TCPReassembler()
        
        for ts, buf in reader:
            try:
                if datalink == dpkt.pcap.DLT_EN10MB: # Ethernet
                    eth = dpkt.ethernet.Ethernet(buf)
                    network_layer = eth.data
                elif datalink == dpkt.pcap.DLT_LINUX_SLL: # Linux cooked capture
                    sll = dpkt.sll.SLL(buf)
                    network_layer = sll.data
                elif datalink == dpkt.pcap.DLT_NULL: # Loopback
                    loopback = dpkt.loopback.Loopback(buf)
                    network_layer = loopback.data
                else:
                    continue # Unsupported link layer
                    
                # Ensure it's IP
                if not isinstance(network_layer, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                    
                ip = network_layer
                
                # Ensure it's TCP
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                    
                tcp = ip.data
                if not tcp.data:
                    continue
                    
                src_ip = _inet_to_str(ip.src)
                dst_ip = _inet_to_str(ip.dst)
                
                results = reassembler.process_packet(src_ip, dst_ip, tcp.sport, tcp.dport, tcp.data)
                for res in results:
                    yield res
                    
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception):
                # Safely ignore malformed packets
                continue
