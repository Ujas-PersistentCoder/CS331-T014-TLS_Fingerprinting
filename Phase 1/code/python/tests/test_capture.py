"""
Tests for the TCPReassembler and TLS record extraction logic.

These tests construct synthetic TCP segments containing hand-crafted
TLS records and feed them directly into TCPReassembler.process_packet,
validating reassembly correctness without requiring pcap files or
network access.
"""

import struct
import pytest

from src.capture import (
    TCPReassembler,
    CaptureStats,
    TCP_SYN, TCP_FIN, TCP_RST, TCP_ACK,
)


# --- Helpers to build synthetic TLS data ---

def build_client_hello_body(ciphers=None):
    """Build a minimal ClientHello handshake body."""
    if ciphers is None:
        ciphers = [0xc02b, 0xc02f]
    body = b'\x03\x03' + (b'\x00' * 32) + b'\x00'  # version + random + session_id_len=0
    body += struct.pack('!H', len(ciphers) * 2)
    for c in ciphers:
        body += struct.pack('!H', c)
    body += b'\x01\x00'  # compression methods: 1 method, null
    return body


def build_server_hello_body(cipher=0xc02f):
    """Build a minimal ServerHello handshake body."""
    body = b'\x03\x03' + (b'\x00' * 32) + b'\x00'  # version + random + session_id_len=0
    body += struct.pack('!H', cipher)
    body += b'\x00'  # compression method: null
    return body


def wrap_handshake(msg_type, body):
    """Wrap a handshake body in a 4-byte handshake header."""
    return bytes([msg_type]) + struct.pack('!I', len(body))[1:] + body


def wrap_tls_record(content_type, fragment):
    """Wrap a fragment in a 5-byte TLS record header."""
    return bytes([content_type]) + b'\x03\x01' + struct.pack('!H', len(fragment)) + fragment


def make_client_hello_record(ciphers=None):
    """Build a complete TLS record containing a ClientHello."""
    body = build_client_hello_body(ciphers)
    handshake = wrap_handshake(0x01, body)
    return wrap_tls_record(22, handshake)


def make_server_hello_record(cipher=0xc02f):
    """Build a complete TLS record containing a ServerHello."""
    body = build_server_hello_body(cipher)
    handshake = wrap_handshake(0x02, body)
    return wrap_tls_record(22, handshake)


def make_change_cipher_spec_record():
    """Build a ChangeCipherSpec record (content type 20, 1 byte payload)."""
    return wrap_tls_record(20, b'\x01')


# Default flow parameters for tests
SRC = "10.0.0.1"
DST = "10.0.0.2"
SPORT = 12345
DPORT = 443
T = 1000.0  # base timestamp


# ============================================================
# Test: Single-packet ClientHello
# ============================================================

class TestBasicParsing:
    def test_single_packet_client_hello(self):
        """A complete ClientHello in one TCP segment yields one result."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()

        results = r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record, T)

        assert len(results) == 1
        assert results[0].client_hello is not None
        assert results[0].client_hello.cipher_suites == (0xc02b, 0xc02f)
        assert results[0].src_ip == SRC
        assert results[0].dst_port == DPORT
        assert stats.tls_handshakes_found == 1

    def test_single_packet_server_hello(self):
        """A complete ServerHello in one TCP segment yields one result."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_server_hello_record(0xc02b)

        results = r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record, T)

        assert len(results) == 1
        assert results[0].server_hello is not None
        assert results[0].server_hello.cipher_suite == 0xc02b

    def test_multiple_handshakes_in_one_record(self):
        """Two ServerHello messages packed into one TLS record fragment."""
        stats = CaptureStats()
        r = TCPReassembler(stats)

        body1 = build_server_hello_body(0xc02b)
        body2 = build_server_hello_body(0xc02f)
        hs1 = wrap_handshake(0x02, body1)
        hs2 = wrap_handshake(0x02, body2)
        record = wrap_tls_record(22, hs1 + hs2)

        results = r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record, T)

        assert len(results) == 2
        assert results[0].server_hello.cipher_suite == 0xc02b
        assert results[1].server_hello.cipher_suite == 0xc02f


# ============================================================
# Test: TLS record split across TCP segments
# ============================================================

class TestStreamBuffering:
    def test_tls_record_split_across_two_segments(self):
        """A ClientHello TLS record split across two TCP segments."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()
        split = len(record) // 2

        first_half = record[:split]
        second_half = record[split:]

        # First segment: incomplete record, no result yet
        r1 = r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, first_half, T)
        assert len(r1) == 0

        # Second segment: completes the record
        r2 = r.process_packet(
            SRC, DST, SPORT, DPORT,
            len(first_half), TCP_ACK, second_half, T + 0.1,
        )
        assert len(r2) == 1
        assert r2[0].client_hello is not None


# ============================================================
# Test: Non-handshake record skipping (Issue #1)
# ============================================================

class TestNonHandshakeSkip:
    def test_change_cipher_spec_before_handshake(self):
        """A ChangeCipherSpec record followed by a Handshake record.
        The CCS must be skipped, the handshake must still be found."""
        stats = CaptureStats()
        r = TCPReassembler(stats)

        ccs = make_change_cipher_spec_record()
        ch = make_client_hello_record()
        payload = ccs + ch

        results = r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, payload, T)

        assert len(results) == 1
        assert results[0].client_hello is not None


# ============================================================
# Test: Out-of-order arrival
# ============================================================

class TestOutOfOrder:
    def test_two_segments_out_of_order(self):
        """Segment 2 arrives before segment 1. After segment 1 arrives,
        the full TLS record should be parseable."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()
        split = len(record) // 2

        seg1 = record[:split]
        seg2 = record[split:]
        seg1_seq = 1001  # First data byte after SYN
        seg2_seq = 1001 + split

        # SYN establishes expected_seq = 1001
        r.process_packet(SRC, DST, SPORT, DPORT, 1000, TCP_SYN, b'', T)

        # Segment 2 arrives first (out of order)
        r1 = r.process_packet(SRC, DST, SPORT, DPORT, seg2_seq, TCP_ACK, seg2, T + 0.1)
        assert len(r1) == 0  # Can't parse yet, gap at front

        # Segment 1 arrives (fills the gap)
        r2 = r.process_packet(SRC, DST, SPORT, DPORT, seg1_seq, TCP_ACK, seg1, T + 0.2)
        assert len(r2) == 1
        assert r2[0].client_hello is not None
        assert stats.segments_reordered == 1

    def test_three_segments_reversed(self):
        """Segments arrive in reverse order: 3, 2, 1."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()
        third = len(record) // 3
        base = 1001

        seg1 = record[:third]
        seg2 = record[third:2*third]
        seg3 = record[2*third:]

        # SYN establishes expected_seq
        r.process_packet(SRC, DST, SPORT, DPORT, 1000, TCP_SYN, b'', T)

        # Arrive in reverse order
        r.process_packet(SRC, DST, SPORT, DPORT, base + 2*third, TCP_ACK, seg3, T + 0.1)
        r.process_packet(SRC, DST, SPORT, DPORT, base + third, TCP_ACK, seg2, T + 0.2)
        results = r.process_packet(SRC, DST, SPORT, DPORT, base, TCP_ACK, seg1, T + 0.3)

        assert len(results) == 1
        assert results[0].client_hello is not None
        assert stats.segments_reordered == 2


# ============================================================
# Test: Retransmission and overlap
# ============================================================

class TestRetransmissionAndOverlap:
    def test_pure_retransmission(self):
        """Same segment delivered twice. Second is dropped."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()

        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record, T)
        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record, T + 0.1)

        assert stats.retransmissions_dropped == 1
        assert stats.tls_handshakes_found == 1  # Only parsed once

    def test_partial_overlap_trim(self):
        """A retransmission that overlaps the end of already-received data
        but extends past it. The new tail should be kept."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()

        # Deliver first 20 bytes
        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record[:20], T)

        # Deliver bytes 10..end (overlaps bytes 10..19, new from 20 onward)
        r.process_packet(SRC, DST, SPORT, DPORT, 10, TCP_ACK, record[10:], T + 0.1)

        assert stats.overlaps_trimmed == 1
        assert stats.tls_handshakes_found == 1


# ============================================================
# Test: Flow lifecycle (FIN / RST)
# ============================================================

class TestFlowLifecycle:
    def test_fin_cleans_up_flow(self):
        """After FIN, the flow state is removed."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()

        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record, T)
        key = (SRC, SPORT, DST, DPORT)
        assert key in r.flows

        # FIN with no payload
        r.process_packet(
            SRC, DST, SPORT, DPORT,
            len(record), TCP_FIN | TCP_ACK, b'', T + 0.1,
        )
        assert key not in r.flows
        assert stats.flows_completed == 1

    def test_rst_cleans_up_flow(self):
        """After RST, the flow state is removed."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()

        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, record, T)
        key = (SRC, SPORT, DST, DPORT)
        assert key in r.flows

        r.process_packet(SRC, DST, SPORT, DPORT, len(record), TCP_RST, b'', T + 0.1)
        assert key not in r.flows
        assert stats.flows_completed == 1

    def test_syn_initializes_expected_seq(self):
        """SYN sets expected_seq = seq + 1."""
        stats = CaptureStats()
        r = TCPReassembler(stats)

        r.process_packet(SRC, DST, SPORT, DPORT, 1000, TCP_SYN, b'', T)
        key = (SRC, SPORT, DST, DPORT)
        assert r.flows[key].expected_seq == 1001
        assert r.flows[key].lifecycle == "SYN_SEEN"


# ============================================================
# Test: Timeout eviction
# ============================================================

class TestTimeoutEviction:
    def test_stale_flow_evicted(self):
        """A flow with no activity for >FLOW_TIMEOUT is evicted."""
        stats = CaptureStats()
        r = TCPReassembler(stats)

        # Create a flow
        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, b'\x00', T)
        key = (SRC, SPORT, DST, DPORT)
        assert key in r.flows

        # Process a packet on a DIFFERENT flow 60 seconds later
        r.process_packet("9.9.9.9", DST, 9999, DPORT, 0, TCP_ACK, b'\x00', T + 60)
        assert key not in r.flows
        assert stats.flows_timed_out == 1


# ============================================================
# Test: OOO cap enforcement
# ============================================================

class TestOOOCap:
    def test_ooo_segment_cap(self):
        """More than MAX_OOO_SEGMENTS out-of-order segments causes eviction."""
        from src.capture import MAX_OOO_SEGMENTS

        stats = CaptureStats()
        r = TCPReassembler(stats)

        # First packet establishes expected_seq = 0 + 10 = 10
        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, b'\x00' * 10, T)
        key = (SRC, SPORT, DST, DPORT)

        # Buffer MAX_OOO_SEGMENTS + 1 OOO segments at seq 100, 200, ...
        for i in range(MAX_OOO_SEGMENTS + 1):
            seq = 100 + i * 100
            r.process_packet(SRC, DST, SPORT, DPORT, seq, TCP_ACK, b'\xAA' * 10, T)

        flow = r.flows[key]
        # Should have evicted 1 segment to make room
        assert len(flow.ooo_segments) == MAX_OOO_SEGMENTS
        assert stats.gaps_unresolved >= 1


# ============================================================
# Test: Cross-record handshake reassembly (Issue #4)
# ============================================================

class TestCrossRecordHandshake:
    def test_handshake_spanning_two_tls_records(self):
        """A handshake message that spans two TLS Handshake records."""
        stats = CaptureStats()
        r = TCPReassembler(stats)

        # Build a ClientHello handshake message (header + body)
        body = build_client_hello_body()
        handshake = wrap_handshake(0x01, body)

        # Split the handshake at an arbitrary point
        split = len(handshake) // 2
        frag1 = handshake[:split]
        frag2 = handshake[split:]

        # Wrap each fragment in its own TLS Handshake record
        record1 = wrap_tls_record(22, frag1)
        record2 = wrap_tls_record(22, frag2)

        payload = record1 + record2

        results = r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, payload, T)

        assert len(results) == 1
        assert results[0].client_hello is not None
        assert results[0].client_hello.cipher_suites == (0xc02b, 0xc02f)


# ============================================================
# Test: Stats counters
# ============================================================

class TestStatsSummary:
    def test_stats_after_mixed_scenario(self):
        """Run a scenario with in-order, OOO, and retransmit segments,
        then verify the stats match."""
        stats = CaptureStats()
        r = TCPReassembler(stats)
        record = make_client_hello_record()
        third = len(record) // 3

        seg1 = record[:third]
        seg2 = record[third:2*third]
        seg3 = record[2*third:]

        # Segment 1 in order
        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, seg1, T)
        # Segment 3 out of order
        r.process_packet(SRC, DST, SPORT, DPORT, 2*third, TCP_ACK, seg3, T + 0.1)
        # Retransmit segment 1
        r.process_packet(SRC, DST, SPORT, DPORT, 0, TCP_ACK, seg1, T + 0.2)
        # Segment 2 fills the gap
        r.process_packet(SRC, DST, SPORT, DPORT, third, TCP_ACK, seg2, T + 0.3)

        assert stats.packets_processed == 4
        assert stats.segments_reordered == 1
        assert stats.retransmissions_dropped == 1
        assert stats.tls_handshakes_found == 1

    def test_summary_string(self):
        """CaptureStats.summary() produces a non-empty string."""
        stats = CaptureStats(packets_processed=100, tls_handshakes_found=5)
        s = stats.summary()
        assert "100" in s
        assert "5" in s
        assert "Capture Statistics" in s
