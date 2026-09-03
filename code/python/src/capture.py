"""
TLS Handshake capture and TCP reassembly module.

Provides two entrypoints:
- read_pcap(): Parse pcap/pcapng files offline
- (future) live_capture(): Scapy-based live sniffing

The TCPReassembler performs sequence-aware stream reassembly with:
- Out-of-order segment buffering with a capped reorder window
- Overlap resolution (trim partial retransmissions, not drop)
- Per-flow lifecycle tracking (SYN -> ESTABLISHED -> CLOSED via FIN/RST)
- Cross-record handshake message reassembly
- Non-handshake TLS record skipping
- Capture-level statistics

Limitations (documented, not bugs):
- Does not handle TCP window scaling or congestion control
- Does not handle sequence number wraparound (2^32)
- Reorder window is capped; persistent gaps beyond the cap are lost
- TCP Fast Open (SYN with payload) may lose the first data byte
"""

import logging
import struct
from dataclasses import dataclass, field
from typing import Iterator

import dpkt
import socket

from src.parser import (
    ClientHelloFields,
    ServerHelloFields,
    parse_handshake_header,
    parse_client_hello,
    parse_server_hello,
)

logger = logging.getLogger(__name__)

# --- Constants ---

MAX_OOO_SEGMENTS = 10       # Max out-of-order segments buffered per flow
MAX_OOO_BYTES = 65536       # Max total OOO buffer size per flow (64 KB)
FLOW_TIMEOUT = 30.0         # Seconds of inactivity before flow eviction
MAX_TLS_RECORD_LEN = 16384 + 2048  # TLS max fragment + generous slack

# TCP flag masks
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


# --- Data structures ---

@dataclass
class CaptureStats:
    """Capture-level statistics, aggregated across all flows."""
    packets_processed: int = 0
    tls_handshakes_found: int = 0
    flows_tracked: int = 0
    flows_completed: int = 0       # FIN or RST seen
    flows_timed_out: int = 0       # Evicted by timeout
    segments_reordered: int = 0    # OOO segments successfully flushed into stream
    retransmissions_dropped: int = 0
    overlaps_trimmed: int = 0
    gaps_unresolved: int = 0       # OOO segments still buffered at flow close/eviction
    packets_skipped: int = 0       # Malformed packets in read_pcap

    def summary(self) -> str:
        """Format a human-readable summary string."""
        flows_open = self.flows_tracked - self.flows_completed - self.flows_timed_out
        lines = [
            "--- Capture Statistics ---",
            f"  Packets processed:      {self.packets_processed}",
            f"  TLS handshakes found:   {self.tls_handshakes_found}",
            f"  Flows tracked:          {self.flows_tracked}"
            f" ({self.flows_completed} completed, {self.flows_timed_out} timed out"
            f", {max(0, flows_open)} still open)",
            f"  Segments reordered:     {self.segments_reordered}",
            f"  Retransmissions dropped: {self.retransmissions_dropped}",
            f"  Overlaps trimmed:       {self.overlaps_trimmed}",
            f"  Gaps unresolved:        {self.gaps_unresolved}",
            f"  Packets skipped:        {self.packets_skipped}",
        ]
        return "\n".join(lines)


@dataclass
class FlowState:
    """Per-flow TCP reassembly state."""
    expected_seq: int | None = None             # Next expected sequence number
    stream: bytearray = field(default_factory=bytearray)  # Reassembled in-order bytes
    ooo_segments: dict[int, bytes] = field(default_factory=dict)  # seq -> payload
    lifecycle: str = "NEW"                      # NEW | SYN_SEEN | ESTABLISHED | CLOSED
    last_seen_ts: float = 0.0                   # For timeout eviction
    pending_handshake: bytes = b''              # Partial handshake spanning TLS records


@dataclass
class TLSHandshakeResult:
    """Complete result from processing a single handshake message."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    client_hello: ClientHelloFields | None = None
    server_hello: ServerHelloFields | None = None


# --- Helpers ---

def _inet_to_str(inet: bytes) -> str:
    """Convert packed IP address to string."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


# --- TCPReassembler ---

class TCPReassembler: 
    """
    Sequence-aware TCP stream reassembler for TLS handshake extraction.

    Handles out-of-order segments, partial-overlap retransmissions,
    flow lifecycle (SYN/FIN/RST), and cross-record handshake reassembly.
    """

    def __init__(self, stats: CaptureStats | None = None):
        self.flows: dict[tuple, FlowState] = {}
        self.stats = stats or CaptureStats()

    def process_packet(
        self,
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
        seq: int,
        flags: int,
        payload: bytes,
        timestamp: float,
    ) -> list[TLSHandshakeResult]:
        """
        Feed a TCP segment into the reassembler.

        Returns a list of TLSHandshakeResult for any complete handshakes
        that became parseable after this segment was processed.
        """
        self.stats.packets_processed += 1
        key = (src_ip, src_port, dst_ip, dst_port)

        # Evict stale flows before processing
        self._evict_stale(timestamp)

        # --- RST: tear down immediately ---
        if flags & TCP_RST:
            if key in self.flows:
                flow = self.flows.pop(key)
                self.stats.gaps_unresolved += len(flow.ooo_segments)
                self.stats.flows_completed += 1
            return []

        # --- Get or create flow ---
        if key not in self.flows:
            self.flows[key] = FlowState(last_seen_ts=timestamp)
            self.stats.flows_tracked += 1

        flow = self.flows[key]
        flow.last_seen_ts = timestamp

        # --- SYN handling ---
        # The sequence number for data starts at seq + 1 (SYN consumes 1 seq byte).
        data_seq = seq
        if flags & TCP_SYN:
            flow.expected_seq = seq + 1
            flow.lifecycle = "ESTABLISHED" if (flags & TCP_ACK) else "SYN_SEEN"
            if not payload:
                return []
            # SYN with payload (TCP Fast Open): data starts at seq + 1
            data_seq = seq + 1

        results = []

        # --- Payload processing ---
        if payload:
            # If we missed the SYN, initialize on first data packet
            if flow.expected_seq is None:
                flow.expected_seq = data_seq
                flow.lifecycle = "ESTABLISHED"

            self._insert_segment(flow, data_seq, payload)
            results = self._extract_tls(flow, src_ip, dst_ip, src_port, dst_port)
            self.stats.tls_handshakes_found += len(results)

        # --- FIN handling ---
        if flags & TCP_FIN:
            flow.lifecycle = "CLOSED"
            # One last extraction attempt
            if flow.stream:
                more = self._extract_tls(flow, src_ip, dst_ip, src_port, dst_port)
                results.extend(more)
                self.stats.tls_handshakes_found += len(more)
            self.stats.gaps_unresolved += len(flow.ooo_segments)
            self.stats.flows_completed += 1
            self.flows.pop(key, None)

        return results

    # --- Segment insertion ---

    def _insert_segment(self, flow: FlowState, seq: int, payload: bytes) -> None:
        """Insert a TCP segment into the flow's reassembly buffer, handling
        in-order append, retransmission detection, overlap trimming, and
        out-of-order buffering."""

        if seq == flow.expected_seq:
            # In-order: append directly to the stream
            flow.stream.extend(payload)
            flow.expected_seq += len(payload)
            # Check if any buffered OOO segments are now contiguous
            self._flush_ooo(flow)

        elif seq < flow.expected_seq:
            # Retransmission or partial overlap
            end = seq + len(payload)
            if end <= flow.expected_seq:
                # Pure retransmission: every byte already received
                self.stats.retransmissions_dropped += 1
            else:
                # Partial overlap: trim the leading bytes we already have,
                # keep the new tail
                new_data = payload[flow.expected_seq - seq:]
                flow.stream.extend(new_data)
                flow.expected_seq += len(new_data)
                self.stats.overlaps_trimmed += 1
                self._flush_ooo(flow)

        else:
            # Out-of-order: seq > expected_seq (gap in the stream)
            self._buffer_ooo(flow, seq, payload)

    def _buffer_ooo(self, flow: FlowState, seq: int, payload: bytes) -> None:
        """Buffer an out-of-order segment, respecting per-flow caps."""
        total_ooo = sum(len(v) for v in flow.ooo_segments.values())

        # Enforce caps: evict oldest (lowest-seq) if necessary
        if (len(flow.ooo_segments) >= MAX_OOO_SEGMENTS
                or total_ooo + len(payload) > MAX_OOO_BYTES):
            if flow.ooo_segments:
                oldest_seq = min(flow.ooo_segments)
                del flow.ooo_segments[oldest_seq]
                self.stats.gaps_unresolved += 1

        flow.ooo_segments[seq] = payload

    def _flush_ooo(self, flow: FlowState) -> None:
        """Flush buffered out-of-order segments that are now contiguous
        with the reassembled stream."""
        while flow.ooo_segments:
            next_seq = min(flow.ooo_segments)

            if next_seq > flow.expected_seq:
                break  # Gap still exists

            segment = flow.ooo_segments.pop(next_seq)
            end_seq = next_seq + len(segment)

            if end_seq <= flow.expected_seq:
                # Fully covered by data already in stream (buffered retransmit)
                self.stats.retransmissions_dropped += 1
                continue

            # Has new data — trim any leading overlap
            if next_seq < flow.expected_seq:
                segment = segment[flow.expected_seq - next_seq:]
                self.stats.overlaps_trimmed += 1

            flow.stream.extend(segment)
            flow.expected_seq += len(segment)
            self.stats.segments_reordered += 1

    # --- TLS record extraction ---

    def _extract_tls(
        self, flow: FlowState,
        src_ip: str, dst_ip: str,
        src_port: int, dst_port: int,
    ) -> list[TLSHandshakeResult]:
        """Extract complete TLS handshake messages from the reassembled stream.

        Handles non-handshake record skipping, cross-record handshake
        reassembly, and multiple handshake messages within a single record.
        """
        results = []

        while len(flow.stream) >= 5:
            content_type = flow.stream[0]

            # Validate content type looks like TLS
            if content_type not in (20, 21, 22, 23):
                # Not a recognized TLS record type — likely non-TLS data
                # in the stream. Clear it to avoid infinite loops.
                logger.debug("Non-TLS content type %d, clearing stream", content_type)
                flow.stream.clear()
                flow.pending_handshake = b''
                break

            # Read the declared record length from header bytes [3:5]
            try:
                record_len = struct.unpack('!H', flow.stream[3:5])[0]
            except struct.error:
                break

            # Sanity check: TLS records can't exceed ~16 KB
            if record_len > MAX_TLS_RECORD_LEN:
                logger.debug("Implausible TLS record length %d, clearing stream", record_len)
                flow.stream.clear()
                break

            total_record_size = 5 + record_len
            if len(flow.stream) < total_record_size:
                break  # Incomplete record, wait for more data

            if content_type != 22:
                # Non-handshake record (ChangeCipherSpec, Alert, AppData):
                # skip past it entirely so we don't lose any handshake data
                # that follows in the same stream.
                del flow.stream[:total_record_size]
                continue

            # --- Handshake record ---
            fragment = bytes(flow.stream[5:total_record_size])
            del flow.stream[:total_record_size]

            # Prepend any pending partial handshake from a previous record
            if flow.pending_handshake:
                fragment = flow.pending_handshake + fragment
                flow.pending_handshake = b''

            # Parse handshake messages within the fragment
            frag_offset = 0
            while frag_offset < len(fragment):
                # Need at least 4 bytes for a handshake header
                if frag_offset + 4 > len(fragment):
                    flow.pending_handshake = fragment[frag_offset:]
                    break

                try:
                    msg_type, length, hs_data_offset = parse_handshake_header(
                        fragment, frag_offset
                    )
                except ValueError:
                    break

                if frag_offset + 4 + length > len(fragment):
                    # Handshake message spans multiple TLS records.
                    # Save the partial bytes and reassemble when the
                    # next Handshake record arrives.
                    flow.pending_handshake = fragment[frag_offset:]
                    logger.debug(
                        "Handshake type %d spans records, %d/%d bytes buffered",
                        msg_type, len(fragment) - frag_offset, 4 + length,
                    )
                    break

                handshake_data = fragment[hs_data_offset:hs_data_offset + length]

                try:
                    if msg_type == 1:  # ClientHello
                        ch = parse_client_hello(handshake_data)
                        results.append(TLSHandshakeResult(
                            src_ip, dst_ip, src_port, dst_port, client_hello=ch
                        ))
                    elif msg_type == 2:  # ServerHello
                        sh = parse_server_hello(handshake_data)
                        results.append(TLSHandshakeResult(
                            src_ip, dst_ip, src_port, dst_port, server_hello=sh
                        ))
                except ValueError as e:
                    logger.debug("Failed to parse handshake type %d: %s", msg_type, e)

                frag_offset = hs_data_offset + length

        return results

    # --- Flow eviction ---

    def _evict_stale(self, current_ts: float) -> None:
        """Remove flows that have been idle longer than FLOW_TIMEOUT."""
        stale_keys = [
            key for key, flow in self.flows.items()
            if current_ts - flow.last_seen_ts > FLOW_TIMEOUT
        ]
        for key in stale_keys:
            flow = self.flows.pop(key)
            self.stats.gaps_unresolved += len(flow.ooo_segments)
            self.stats.flows_timed_out += 1


# --- Pcap reader ---

def read_pcap(
    filepath: str,
    stats: CaptureStats | None = None,
) -> Iterator[TLSHandshakeResult]:
    """
    Read a pcap/pcapng file, yield TLSHandshakeResult for each handshake found.

    If a CaptureStats object is provided, it will be populated with
    capture-level statistics as the file is processed.
    """
    if stats is None:
        stats = CaptureStats()

    reassembler = TCPReassembler(stats)

    with open(filepath, 'rb') as f:
        magic = f.read(4)
        f.seek(0)

        if magic == b'\x0a\x0d\x0d\x0a':
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)

        datalink = getattr(reader, 'datalink', lambda: dpkt.pcap.DLT_EN10MB)()

        for ts, buf in reader:
            try:
                # --- Link layer ---
                if datalink == dpkt.pcap.DLT_EN10MB:
                    eth = dpkt.ethernet.Ethernet(buf)
                    network_layer = eth.data
                elif datalink == dpkt.pcap.DLT_LINUX_SLL:
                    sll = dpkt.sll.SLL(buf)
                    network_layer = sll.data
                elif datalink == dpkt.pcap.DLT_NULL:
                    loopback = dpkt.loopback.Loopback(buf)
                    network_layer = loopback.data
                else:
                    continue

                # --- Network layer ---
                if not isinstance(network_layer, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                ip = network_layer
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                tcp = ip.data

                # Skip pure ACK packets (no data, no control flags)
                has_data = bool(tcp.data)
                has_control = bool(tcp.flags & (TCP_SYN | TCP_FIN | TCP_RST))
                if not has_data and not has_control:
                    continue

                src_ip = _inet_to_str(ip.src)
                dst_ip = _inet_to_str(ip.dst)

                results = reassembler.process_packet(
                    src_ip, dst_ip,
                    tcp.sport, tcp.dport,
                    tcp.seq, tcp.flags,
                    bytes(tcp.data) if has_data else b'',
                    ts,
                )
                for res in results:
                    yield res

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError,
                    struct.error, ValueError) as e:
                logger.debug("Skipping malformed packet: %s: %s",
                             type(e).__name__, e)
                stats.packets_skipped += 1
                continue
