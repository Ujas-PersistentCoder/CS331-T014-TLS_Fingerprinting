#include <gtest/gtest.h>
#include "tlsfp/parser.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/capture.hpp"
#include <cstring>
#include <vector>
#include <netinet/in.h>
#include <pcap.h>

using namespace tlsfp;

// ------------------------------------------------------------------------------
// Packet Construction Helpers for Pipeline Testing
// ------------------------------------------------------------------------------
static std::vector<uint8_t> build_ipv4_tcp_packet(uint32_t seq, const std::vector<uint8_t> &payload) {
    constexpr size_t ETH_HLEN = 14;
    constexpr size_t IP_HLEN = 20;
    constexpr size_t TCP_HLEN = 20;
    size_t total_size = ETH_HLEN + IP_HLEN + TCP_HLEN + payload.size();

    std::vector<uint8_t> pkt(total_size, 0);

    // Ethernet (IPv4 = 0x0800)
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IPv4 Header
    pkt[14] = 0x45; // Version 4, Header Length 5 (20 bytes)
    uint16_t ip_len = htons(static_cast<uint16_t>(IP_HLEN + TCP_HLEN + payload.size()));
    std::memcpy(&pkt[16], &ip_len, 2);
    pkt[23] = IPPROTO_TCP;
    pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 100; // Src IP
    pkt[30] = 192; pkt[31] = 168; pkt[32] = 1; pkt[33] = 200; // Dst IP

    // TCP Header
    uint16_t sport = htons(54321);
    uint16_t dport = htons(443);
    uint32_t net_seq = htonl(seq);
    std::memcpy(&pkt[34], &sport, 2);
    std::memcpy(&pkt[36], &dport, 2);
    std::memcpy(&pkt[38], &net_seq, 4);
    pkt[46] = 0x50; // Data offset = 5 words (20 bytes)

    // Append TCP Payload
    if (!payload.empty()) {
        std::memcpy(&pkt[ETH_HLEN + IP_HLEN + TCP_HLEN], payload.data(), payload.size());
    }

    return pkt;
}

static std::vector<uint8_t> build_minimal_client_hello() {
    return std::vector<uint8_t>{
        // TLS Record Header (5 bytes)
        0x16,       // ContentType: Handshake
        0x03, 0x03, // Record Version: TLS 1.2
        0x00, 0x2D, // Record Length: 45 bytes

        // Handshake Header (4 bytes)
        0x01,             // Type: ClientHello
        0x00, 0x00, 0x29, // Handshake Length: 41 bytes

        // ClientHello Body (41 bytes)
        0x03, 0x03,       // Client Version: TLS 1.2
        // 32-byte Random
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
        0x00,             // Session ID Length: 0
        0x00, 0x02,       // Cipher Suites Length: 2
        0x00, 0x2F,       // Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (47)
        0x01,             // Compression Methods Length: 1
        0x00,             // Compression Method: null
        0x00, 0x00        // Extensions Length: 0
    };
}

// ------------------------------------------------------------------------------
// Strict Boundary & Stream Tests
// ------------------------------------------------------------------------------

TEST(StrictTLSParserTest, MinimalClientHelloParsing) {
    std::vector<uint8_t> payload = build_minimal_client_hello();
    ClientHelloData data;

    // Direct parser invocation
    bool parsed = parse_client_hello(payload.data(), payload.size(), data);

    EXPECT_TRUE(parsed);
    EXPECT_EQ(data.client_version, 771);
    ASSERT_EQ(data.cipher_suites.size(), 1);
    EXPECT_EQ(data.cipher_suites[0], 47);
    EXPECT_FALSE(data.has_sni);
}

TEST(StrictTLSParserTest, MaximumAllowedPayloadBounds) {
    std::vector<uint8_t> payload = build_minimal_client_hello();
    
    // Expand payload to exact maximum capacity (StreamBuffer::MAX_BUF_SIZE = 4096)
    size_t extra_padding = StreamBuffer::MAX_BUF_SIZE - payload.size();
    payload.insert(payload.end(), extra_padding, 0x00);

    // Update TLS record length bytes to match
    uint16_t padded_rec_len = static_cast<uint16_t>(payload.size() - 5);
    payload[3] = static_cast<uint8_t>(padded_rec_len >> 8);
    payload[4] = static_cast<uint8_t>(padded_rec_len & 0xFF);

    CaptureContext ctx;
    ctx.link_type = DLT_EN10MB;

    auto pkt_bytes = build_ipv4_tcp_packet(1000, payload);
    struct pcap_pkthdr hdr{};
    hdr.caplen = static_cast<bpf_u_int32>(pkt_bytes.size());
    hdr.len = hdr.caplen;

    packet_callback(reinterpret_cast<u_char*>(&ctx), &hdr, pkt_bytes.data());

    // Overflow check: oversized payload exceeding MAX_BUF_SIZE must be evicted
    std::vector<uint8_t> overflow_payload(StreamBuffer::MAX_BUF_SIZE + 1, 0x16);
    auto overflow_pkt = build_ipv4_tcp_packet(2000, overflow_payload);
    hdr.caplen = static_cast<bpf_u_int32>(overflow_pkt.size());
    hdr.len = hdr.caplen;

    packet_callback(reinterpret_cast<u_char*>(&ctx), &hdr, overflow_pkt.data());
    
    // The overflow flow must be dropped
    EXPECT_EQ(ctx.active_flows.size(), 0);
}

TEST(StrictReassemblyTest, MultiPacketHandshakeReassembly) {
    CaptureContext ctx;
    ctx.link_type = DLT_EN10MB;

    std::vector<uint8_t> full_tls = build_minimal_client_hello();
    
    // Split 50-byte payload into two segments: 20 bytes and 30 bytes
    std::vector<uint8_t> seg1(full_tls.begin(), full_tls.begin() + 20);
    std::vector<uint8_t> seg2(full_tls.begin() + 20, full_tls.end());

    auto pkt1 = build_ipv4_tcp_packet(1000, seg1);
    auto pkt2 = build_ipv4_tcp_packet(1000 + static_cast<uint32_t>(seg1.size()), seg2);

    struct pcap_pkthdr hdr1{}, hdr2{};
    hdr1.caplen = static_cast<bpf_u_int32>(pkt1.size());
    hdr1.len = hdr1.caplen;
    hdr2.caplen = static_cast<bpf_u_int32>(pkt2.size());
    hdr2.len = hdr2.caplen;

    // Segment 1: Incomplete record, flow should remain active in buffer
    packet_callback(reinterpret_cast<u_char*>(&ctx), &hdr1, pkt1.data());
    EXPECT_EQ(ctx.active_flows.size(), 1);

    // Segment 2: Completes record, handshake parsed, active flow evicted
    packet_callback(reinterpret_cast<u_char*>(&ctx), &hdr2, pkt2.data());
    EXPECT_EQ(ctx.active_flows.size(), 0);
}

TEST(StrictReassemblyTest, RejectsOutOfOrderPacketGaps) {
    CaptureContext ctx;
    ctx.link_type = DLT_EN10MB;

    std::vector<uint8_t> seg1 = {0x16, 0x03, 0x03, 0x00, 0x10}; // Header bytes
    std::vector<uint8_t> seg2 = {0x01, 0x00, 0x00, 0x0C};       // Fragment

    auto pkt1 = build_ipv4_tcp_packet(1000, seg1);
    // Introduce a gap: SEQ starts at 1050 instead of 1005
    auto pkt2_out_of_order = build_ipv4_tcp_packet(1050, seg2);

    struct pcap_pkthdr hdr1{}, hdr2{};
    hdr1.caplen = static_cast<bpf_u_int32>(pkt1.size());
    hdr1.len = hdr1.caplen;
    hdr2.caplen = static_cast<bpf_u_int32>(pkt2_out_of_order.size());
    hdr2.len = hdr2.caplen;

    // Establish initial stream sequence state
    packet_callback(reinterpret_cast<u_char*>(&ctx), &hdr1, pkt1.data());
    EXPECT_EQ(ctx.active_flows.size(), 1);

    // Out-of-order segment gap must reset stream state to avoid corruption
    packet_callback(reinterpret_cast<u_char*>(&ctx), &hdr2, pkt2_out_of_order.data());
    EXPECT_EQ(ctx.active_flows.size(), 0);
}

// ------------------------------------------------------------------------------
// Existing Unit Tests
// ------------------------------------------------------------------------------

TEST(ParserUtilsTest, IdentifiesGreaseValues) {
    EXPECT_TRUE(is_grease(0x0a0a));
    EXPECT_TRUE(is_grease(0x1a1a));
    EXPECT_FALSE(is_grease(0x002b));
}

TEST(JA3Test, FormatsClientHelloFingerprint) {
    ClientHelloData client;
    client.client_version = 771;
    client.cipher_suites = {4865, 4866};
    client.extensions = {0, 10, 11};
    client.supported_groups = {29, 23};
    client.ec_point_formats = {0};

    JA3Fingerprint ja3 = compute_ja3(client);
    EXPECT_EQ(ja3.raw_string, "771,4865-4866,0-10-11,29-23,0");
    EXPECT_EQ(ja3.md5_hash.length(), 32);
}

TEST(FlowTrackerTest, EvictsStaleFlows) {
    CaptureContext ctx;
    time_t current_time = 1000;

    FlowKey active_key{}, stale_key{};
    active_key.ip_version = 4; active_key.src_port = 1000;
    stale_key.ip_version = 4;  stale_key.src_port = 2000;

    ctx.active_flows[active_key].last_seen = current_time - 10;
    ctx.active_flows[stale_key].last_seen = current_time - 45;

    ctx.cleanup_stale_flows(current_time);
    EXPECT_EQ(ctx.active_flows.size(), 1);
}