#include <gtest/gtest.h>

#include "tlsfp/capture.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/parser.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <pcap.h>
#include <vector>

using namespace tlsfp;

class FlowTrackingTest : public ::testing::Test {
protected:
    FlowKey make_ipv4_key(const char* src,
                        const char* dst,
                        uint16_t sport,
                        uint16_t dport) {
        FlowKey key{};
        key.ip_version = 4;

        EXPECT_EQ(inet_pton(AF_INET, src, &key.src_ip.v4), 1);
        EXPECT_EQ(inet_pton(AF_INET, dst, &key.dst_ip.v4), 1);

        key.src_port = sport;
        key.dst_port = dport;

        return key;
    }

    FlowKey make_ipv6_key(const char* src,
                        const char* dst,
                        uint16_t sport,
                        uint16_t dport) {
        FlowKey key{};
        key.ip_version = 6;

        EXPECT_EQ(inet_pton(AF_INET6, src, &key.src_ip.v6), 1);
        EXPECT_EQ(inet_pton(AF_INET6, dst, &key.dst_ip.v6), 1);

        key.src_port = sport;
        key.dst_port = dport;

        return key;
    }
};

TEST_F(FlowTrackingTest, IPv4Equality) {
    auto key1 = make_ipv4_key(
        "192.168.1.1", "10.0.0.1", 4444, 443);

    auto key2 = make_ipv4_key(
        "192.168.1.1", "10.0.0.1", 4444, 443);

    auto key3_diff_port = make_ipv4_key(
        "192.168.1.1", "10.0.0.1", 4445, 443);

    auto key4_diff_ip = make_ipv4_key(
        "192.168.1.2", "10.0.0.1", 4444, 443);

    EXPECT_TRUE(key1 == key2);
    EXPECT_FALSE(key1 == key3_diff_port);
    EXPECT_FALSE(key1 == key4_diff_ip);
}

TEST_F(FlowTrackingTest, IPv4DifferentDestinationPort) {
    auto key1 = make_ipv4_key(
        "192.168.1.1", "10.0.0.1", 4444, 443);

    auto key2 = make_ipv4_key(
        "192.168.1.1", "10.0.0.1", 4444, 8443);

    EXPECT_FALSE(key1 == key2);
}

TEST_F(FlowTrackingTest, IPv6Equality) {
    auto key1 = make_ipv6_key(
        "2001:db8::1", "2001:db8::2", 5555, 443);

    auto key2 = make_ipv6_key(
        "2001:db8::1", "2001:db8::2", 5555, 443);

    auto key3_diff_ip = make_ipv6_key(
        "2001:db8::3", "2001:db8::2", 5555, 443);

    EXPECT_TRUE(key1 == key2);
    EXPECT_FALSE(key1 == key3_diff_ip);
}

TEST_F(FlowTrackingTest, VersionMismatchRejection) {
    auto key_v4 = make_ipv4_key(
        "192.168.1.1", "10.0.0.1", 4444, 443);

    FlowKey key_fake_v6{};
    key_fake_v6.ip_version = 6;

    std::memcpy(
        &key_fake_v6.src_ip,
        &key_v4.src_ip,
        sizeof(key_fake_v6.src_ip));

    std::memcpy(
        &key_fake_v6.dst_ip,
        &key_v4.dst_ip,
        sizeof(key_fake_v6.dst_ip));

    key_fake_v6.src_port = 4444;
    key_fake_v6.dst_port = 443;

    EXPECT_FALSE(key_v4 == key_fake_v6);
}

TEST_F(FlowTrackingTest, HashDeterminism) {
    FlowHash hasher;

    auto key1 = make_ipv4_key(
        "192.168.1.100", "8.8.8.8", 12345, 443);

    auto key2 = make_ipv4_key(
        "192.168.1.100", "8.8.8.8", 12345, 443);

    EXPECT_EQ(hasher(key1), hasher(key2))
        << "Identical keys must yield identical hashes";
}

TEST_F(FlowTrackingTest, EqualKeysHaveEqualHashes) {
    FlowHash hasher;

    auto key1 = make_ipv4_key(
        "192.168.1.100", "8.8.8.8", 12345, 443);

    auto key2 = make_ipv4_key(
        "192.168.1.100", "8.8.8.8", 12345, 443);

    EXPECT_TRUE(key1 == key2);
    EXPECT_EQ(hasher(key1), hasher(key2))
        << "Equal keys must have equal hashes";
}

TEST_F(FlowTrackingTest, HashDistinguishesReverseFlows) {
    FlowHash hasher;

    auto key_fwd = make_ipv4_key(
        "1.1.1.1", "2.2.2.2", 1000, 2000);

    auto key_rev = make_ipv4_key(
        "2.2.2.2", "1.1.1.1", 2000, 1000);

    EXPECT_NE(hasher(key_fwd), hasher(key_rev))
        << "Reverse flows should ideally hash differently";
}

TEST_F(FlowTrackingTest, StaleFlowCleanupStrictBoundaries) {
    CaptureContext ctx;

    time_t base_time = 100000;

    auto key_active = make_ipv4_key(
        "1.1.1.1", "2.2.2.2", 1000, 443);

    auto key_edge = make_ipv4_key(
        "1.1.1.1", "3.3.3.3", 1000, 443);

    auto key_stale = make_ipv4_key(
        "1.1.1.1", "4.4.4.4", 1000, 443);

    ctx.active_flows[key_active].last_seen = base_time - 15;
    ctx.active_flows[key_edge].last_seen = base_time - 30;
    ctx.active_flows[key_stale].last_seen = base_time - 31;

    ctx.cleanup_stale_flows(base_time);

    // <= 30 seconds should survive.
    // > 30 seconds should be removed.
    EXPECT_EQ(ctx.active_flows.size(), 2);

    EXPECT_TRUE(
        ctx.active_flows.find(key_active) != ctx.active_flows.end());

    EXPECT_TRUE(
        ctx.active_flows.find(key_edge) != ctx.active_flows.end());

    EXPECT_TRUE(
        ctx.active_flows.find(key_stale) == ctx.active_flows.end());
}


class LinkLayerDemuxTest : public ::testing::Test {
protected:
    CaptureContext ctx;

    void SetUp() override {
        ctx.active_flows.clear();
    }

    std::vector<uint8_t> build_ip_tcp_payload(
        const std::vector<uint8_t>& payload,
        uint32_t sequence = 1000) {

        constexpr size_t ip_len = 20;
        constexpr size_t tcp_len = 20;

        std::vector<uint8_t> pkt(
            ip_len + tcp_len + payload.size(), 0);

        pkt[0] = 0x45;

        uint16_t total_len =
            htons(static_cast<uint16_t>(pkt.size()));

        std::memcpy(
            &pkt[2],
            &total_len,
            sizeof(total_len));

        pkt[9] = IPPROTO_TCP;

        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1;

        pkt[16] = 10;
        pkt[17] = 0;
        pkt[18] = 0;
        pkt[19] = 2;

        uint16_t sport = htons(12345);
        uint16_t dport = htons(443);

        uint32_t net_seq = htonl(sequence);

        std::memcpy(&pkt[20], &sport, 2);
        std::memcpy(&pkt[22], &dport, 2);
        std::memcpy(&pkt[24], &net_seq, 4);

        pkt[32] = 0x50;

        if (!payload.empty()) {
            std::memcpy(
                &pkt[40],
                payload.data(),
                payload.size());
        }

        return pkt;
    }

    void inject_packet(const std::vector<uint8_t>& pkt) {
        struct pcap_pkthdr hdr{};

        hdr.caplen = static_cast<bpf_u_int32>(pkt.size());
        hdr.len = static_cast<bpf_u_int32>(pkt.size());

        hdr.ts.tv_sec = 1000;
        hdr.ts.tv_usec = 0;

        packet_callback(
            reinterpret_cast<u_char*>(&ctx),
            &hdr,
            pkt.data());
    }
};


// DLT_RAW has no link-layer header.
// The packet starts directly with the IP header.
TEST_F(LinkLayerDemuxTest, HandlesDltRaw) {
    ctx.link_type = DLT_RAW;

    std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    std::vector<uint8_t> pkt =
        build_ip_tcp_payload(payload);

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 1);
}


// DLT_NULL contains a 4-byte loopback header
// followed by the IP packet.
TEST_F(LinkLayerDemuxTest, HandlesDltNullLoopback) {
    ctx.link_type = DLT_NULL;

    std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    std::vector<uint8_t> ip_pkt =
        build_ip_tcp_payload(payload);

    std::vector<uint8_t> pkt(
        sizeof(uint32_t) + ip_pkt.size(), 0);

    // AF_INET is stored in the 4-byte NULL header.
    uint32_t family = AF_INET;

    std::memcpy(
        pkt.data(),
        &family,
        sizeof(family));

    std::memcpy(
        pkt.data() + sizeof(family),
        ip_pkt.data(),
        ip_pkt.size());

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 1);
}


// DLT_LINUX_SLL uses a 16-byte Linux cooked capture header.
TEST_F(LinkLayerDemuxTest, HandlesLinuxSLL) {
    ctx.link_type = DLT_LINUX_SLL;

    std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    std::vector<uint8_t> ip_pkt =
        build_ip_tcp_payload(payload);

    constexpr size_t sll_header_len = 16;

    std::vector<uint8_t> pkt(
        sll_header_len + ip_pkt.size(), 0);

    // Linux SLL protocol/ethertype is at bytes 14-15.
    // 0x0800 = IPv4.
    pkt[14] = 0x08;
    pkt[15] = 0x00;

    std::memcpy(
        pkt.data() + sll_header_len,
        ip_pkt.data(),
        ip_pkt.size());

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 1);
}


// Unknown/unhandled DLT should be ignored safely.
TEST_F(LinkLayerDemuxTest, RejectsUnknownDlt) {
    // Arbitrary unsupported link-layer type.
    ctx.link_type = 138;

    std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    std::vector<uint8_t> pkt =
        build_ip_tcp_payload(payload);

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0);
}

TEST_F(LinkLayerDemuxTest, HandlesEthernet) {
    ctx.link_type = DLT_EN10MB;

    const std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    const auto ip_pkt =
        build_ip_tcp_payload(payload);

    std::vector<uint8_t> pkt(
        14 + ip_pkt.size(), 0);

    // Destination MAC
    pkt[0] = 0x00;
    pkt[1] = 0x11;
    pkt[2] = 0x22;
    pkt[3] = 0x33;
    pkt[4] = 0x44;
    pkt[5] = 0x55;

    // Source MAC
    pkt[6] = 0x66;
    pkt[7] = 0x77;
    pkt[8] = 0x88;
    pkt[9] = 0x99;
    pkt[10] = 0xaa;
    pkt[11] = 0xbb;

    // IPv4 EtherType.
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    std::memcpy(
        pkt.data() + 14,
        ip_pkt.data(),
        ip_pkt.size());

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 1u);
}

TEST_F(LinkLayerDemuxTest, HandlesLinuxSLL2) {
    ctx.link_type = DLT_LINUX_SLL2;

    const std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    const auto ip_pkt =
        build_ip_tcp_payload(payload);

    std::vector<uint8_t> pkt(
        20 + ip_pkt.size(), 0);

    // SLL2 protocol is bytes 0-1.
    pkt[0] = 0x08;
    pkt[1] = 0x00;

    std::memcpy(
        pkt.data() + 20,
        ip_pkt.data(),
        ip_pkt.size());

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 1u);
}

TEST_F(LinkLayerDemuxTest, RejectsTruncatedRawPacket) {
    ctx.link_type = DLT_RAW;

    std::vector<uint8_t> pkt = {
        0x45
    };

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsNonIPv4Version) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x16, 0x03, 0x01, 0x00, 0x50
    });

    pkt[0] = 0x65;

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsUDP) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x16, 0x03, 0x01, 0x00, 0x50
    });

    pkt[9] = IPPROTO_UDP;

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsTruncatedTCPHeader) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x16, 0x03, 0x01, 0x00, 0x50
    });

    pkt.resize(35);

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsInvalidTCPDataOffset) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x16, 0x03, 0x01, 0x00, 0x50
    });

    // TCP data offset = 4 words = 16 bytes.
    pkt[32] = 0x40;

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, IgnoresEmptyTCPPayload) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({});

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsNonTLSPayload) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        'G', 'E', 'T', ' '
    });

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}

TEST_F(LinkLayerDemuxTest, RejectsInvalidTLSRecordType) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x15, 0x03, 0x03, 0x00, 0x04
    });

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsInvalidTLSMajorVersion) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x16, 0x02, 0x03, 0x00, 0x04
    });

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsTLSVersionAbove0304) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x16, 0x03, 0x05, 0x00, 0x04
    });

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}


TEST_F(LinkLayerDemuxTest, RejectsOversizedTLSRecord) {
    ctx.link_type = DLT_RAW;

    auto pkt = build_ip_tcp_payload({
        0x16, 0x03, 0x03, 0x40, 0x01
    });

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}

TEST_F(LinkLayerDemuxTest, TLSRecordCanBeSplitAcrossTCPPackets) {
    ctx.link_type = DLT_RAW;

    const std::vector<uint8_t> part1 = {
        0x16, 0x03, 0x03
    };

    const std::vector<uint8_t> part2 = {
        0x00, 0x04,
        0x01, 0x00, 0x00, 0x00
    };

    auto pkt1 =
        build_ip_tcp_payload(part1, 1000);

    auto pkt2 =
        build_ip_tcp_payload(part2, 1003);

    inject_packet(pkt1);

    // First packet only contains an incomplete TLS header.
    EXPECT_EQ(ctx.active_flows.size(), 1u);

    inject_packet(pkt2);

    // The TLS record should now be complete.
    EXPECT_EQ(ctx.active_flows.size(), 0u);
}

TEST_F(LinkLayerDemuxTest, OutOfOrderPacketDropsFlow) {
    ctx.link_type = DLT_RAW;

    const std::vector<uint8_t> first = {
        0x16, 0x03, 0x03
    };

    const std::vector<uint8_t> future = {
        0x00, 0x04
    };

    inject_packet(
        build_ip_tcp_payload(first, 1000));

    ASSERT_EQ(ctx.active_flows.size(), 1u);

    // Expected sequence is now 1003.
    // Sending 1010 creates a gap.
    inject_packet(
        build_ip_tcp_payload(future, 1010));

    EXPECT_EQ(ctx.active_flows.size(), 0u);
}

TEST_F(LinkLayerDemuxTest, EntireRetransmissionIsIgnored) {
    ctx.link_type = DLT_RAW;

    const std::vector<uint8_t> payload = {
        0x16, 0x03, 0x03
    };

    inject_packet(
        build_ip_tcp_payload(payload, 1000));

    ASSERT_EQ(ctx.active_flows.size(), 1u);

    auto it = ctx.active_flows.begin();

    const uint16_t len_after_first =
        it->second.len;

    inject_packet(
        build_ip_tcp_payload(payload, 1000));

    it = ctx.active_flows.find(it->first);

    ASSERT_NE(it, ctx.active_flows.end());

    EXPECT_EQ(
        it->second.len,
        len_after_first);
}

// ============================================================
// MD5 TESTS - source RFC 1321
// ============================================================

TEST(MD5Test, EmptyString) {
    EXPECT_EQ(
        md5_hex(""),
        "d41d8cd98f00b204e9800998ecf8427e");
}

TEST(MD5Test, ABC) {
    EXPECT_EQ(
        md5_hex("abc"),
        "900150983cd24fb0d6963f7d28e17f72");
}

TEST(MD5Test, Deterministic) {
    const std::string input =
        "The quick brown fox jumps over the lazy dog";

    const std::string first = md5_hex(input);
    const std::string second = md5_hex(input);

    EXPECT_EQ(first, second);
}

TEST(MD5Test, DifferentInputsProduceDifferentHashes) {
    EXPECT_NE(
        md5_hex("abc"),
        md5_hex("abd"));
}

TEST(MD5Test, Produces32LowercaseHexCharacters) {
    const std::string digest = md5_hex("test");

    ASSERT_EQ(digest.size(), 32u);

    for (char c : digest) {
        EXPECT_TRUE(
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f'))
            << "Unexpected character: " << c;
    }
}

// ============================================================
// Official Salesforce tests
// ============================================================

TEST(JA3Test, SalesforceOfficialVector1) {
    ClientHelloData client{};

    client.client_version = 769;

    client.cipher_suites = {
        47, 53, 5, 10,
        49161, 49162, 49171, 49172,
        50, 56, 19, 4
    };

    client.extensions = {
        0, 10, 11
    };

    client.supported_groups = {
        23, 24, 25
    };

    client.ec_point_formats = {
        0
    };

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,"
        "0-10-11,23-24-25,0");

    EXPECT_EQ(
        fp.md5_hash,
        "ada70206e40642a3e4461f35503241d5");
}


TEST(JA3Test, SalesforceOfficialVector2) {
    ClientHelloData client{};

    client.client_version = 769;

    client.cipher_suites = {
        4, 5, 10, 9, 100, 98, 3,
        6, 19, 18, 99
    };

    client.extensions = {};
    client.supported_groups = {};
    client.ec_point_formats = {};

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "769,4-5-10-9-100-98-3-6-19-18-99,,,");

    EXPECT_EQ(
        fp.md5_hash,
        "de350869b8c85de67a350c8d186f11e6");
}

// ============================================================
// JA3 formatting tests - source Documentation
// ============================================================

TEST(JA3Test, EmptyFieldsArePreserved) {
    ClientHelloData client{};

    client.client_version = 771;

    client.cipher_suites = {
        4865, 4866, 4867
    };

    client.extensions = {};
    client.supported_groups = {};
    client.ec_point_formats = {};

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,4865-4866-4867,,,");
}


TEST(JA3Test, ExtensionOnly) {
    ClientHelloData client{};

    client.client_version = 771;

    client.extensions = {
        0, 10, 11
    };

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,,0-10-11,,");
}


TEST(JA3Test, SupportedGroupsOnly) {
    ClientHelloData client{};

    client.client_version = 771;

    client.supported_groups = {
        23, 24, 25
    };

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,,,23-24-25,");
}


TEST(JA3Test, PointFormatsOnly) {
    ClientHelloData client{};

    client.client_version = 771;

    client.ec_point_formats = {
        0, 1, 2
    };

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,,,,0-1-2");
}

// ============================================================
// Ordering tests - source Documentation
// ============================================================

TEST(JA3Test, CipherOrderIsPreserved) {
    ClientHelloData client{};

    client.client_version = 771;
    client.cipher_suites = { 1, 2, 3 };

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,1-2-3,,,");
}


TEST(JA3Test, ExtensionOrderIsPreserved) {
    ClientHelloData client{};

    client.client_version = 771;
    client.extensions = { 11, 10, 0 };

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,,11-10-0,,");
}


TEST(JA3Test, ChangingOrderChangesFingerprint) {
    ClientHelloData a{};
    ClientHelloData b{};

    a.client_version = 771;
    b.client_version = 771;

    a.cipher_suites = { 1, 2, 3 };
    b.cipher_suites = { 3, 2, 1 };

    const JA3Fingerprint fp_a = compute_ja3(a);
    const JA3Fingerprint fp_b = compute_ja3(b);

    EXPECT_NE(fp_a.raw_string, fp_b.raw_string);
    EXPECT_NE(fp_a.md5_hash, fp_b.md5_hash);
}

static std::vector<uint8_t> build_client_hello(
    const std::vector<uint16_t>& cipher_suites,
    const std::vector<uint8_t>& extensions) {

    std::vector<uint8_t> handshake;

    // ClientHello version: TLS 1.2
    handshake.push_back(0x03);
    handshake.push_back(0x03);

    // Random: 32 bytes
    handshake.insert(handshake.end(), 32, 0x00);

    // Session ID length = 0
    handshake.push_back(0x00);

    // Cipher suites
    const uint16_t cipher_len =
        static_cast<uint16_t>(cipher_suites.size() * 2);

    handshake.push_back(
        static_cast<uint8_t>(cipher_len >> 8));
    handshake.push_back(
        static_cast<uint8_t>(cipher_len & 0xff));

    for (uint16_t cipher : cipher_suites) {
        handshake.push_back(
            static_cast<uint8_t>(cipher >> 8));
        handshake.push_back(
            static_cast<uint8_t>(cipher & 0xff));
    }

    // Compression methods: one method, null compression.
    handshake.push_back(0x01);
    handshake.push_back(0x00);

    // Extensions length
    const uint16_t extensions_len =
        static_cast<uint16_t>(extensions.size());

    handshake.push_back(
        static_cast<uint8_t>(extensions_len >> 8));
    handshake.push_back(
        static_cast<uint8_t>(extensions_len & 0xff));

    handshake.insert(
        handshake.end(),
        extensions.begin(),
        extensions.end());

    // TLS Handshake header.
    std::vector<uint8_t> record;

    record.push_back(0x16); // Handshake
    record.push_back(0x03);
    record.push_back(0x01); // TLS record version

    const uint16_t record_len =
        static_cast<uint16_t>(4 + handshake.size());

    record.push_back(
        static_cast<uint8_t>(record_len >> 8));
    record.push_back(
        static_cast<uint8_t>(record_len & 0xff));

    // ClientHello handshake type.
    record.push_back(0x01);

    const uint32_t handshake_len =
        static_cast<uint32_t>(handshake.size());

    record.push_back(
        static_cast<uint8_t>(handshake_len >> 16));
    record.push_back(
        static_cast<uint8_t>(handshake_len >> 8));
    record.push_back(
        static_cast<uint8_t>(handshake_len & 0xff));

    record.insert(
        record.end(),
        handshake.begin(),
        handshake.end());

    return record;
}

// ============================================================
// GREASE tests - source Documentation
// ============================================================
TEST(JA3Test, GreaseCipherIsIgnored) {
    const std::vector<uint16_t> ciphers = {
        0x0a0a,
        4865,
        0x1a1a,
        4866,
        4867
    };

    const auto client_hello =
        build_client_hello(ciphers, {});

    ClientHelloData client{};

    ASSERT_TRUE(
        parse_client_hello(
            client_hello.data(),
            client_hello.size(),
            client));

    EXPECT_EQ(
        client.cipher_suites,
        std::vector<uint16_t>({
            4865,
            4866,
            4867
        }));

    const JA3Fingerprint fp =
        compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,4865-4866-4867,,,");
}


TEST(JA3Test, GreaseExtensionIsIgnored) {
    const std::vector<uint8_t> extensions = {
        // GREASE extension 0x0a0a
        0x0a, 0x0a,
        0x00, 0x00,

        // Extension 0
        0x00, 0x00,
        0x00, 0x00,

        // GREASE extension 0x1a1a
        0x1a, 0x1a,
        0x00, 0x00,

        // Extension 10
        0x00, 0x0a,
        0x00, 0x00,

        // Extension 11
        0x00, 0x0b,
        0x00, 0x00
    };

    const auto client_hello =
        build_client_hello(
            {4865, 4866, 4867},
            extensions);

    ClientHelloData client{};

    ASSERT_TRUE(
        parse_client_hello(
            client_hello.data(),
            client_hello.size(),
            client));

    EXPECT_EQ(
        client.extensions,
        std::vector<uint16_t>({
            0,
            10,
            11
        }));

    const JA3Fingerprint fp =
        compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,4865-4866-4867,0-10-11,,");
}


TEST(JA3Test, GreaseSupportedGroupIsIgnored) {
    const std::vector<uint8_t> extensions = {
        // Extension 0x000a: Supported Groups
        0x00, 0x0a,

        // Extension length = 10
        0x00, 0x0a,

        // Supported groups vector length = 8
        0x00, 0x08,

        // GREASE 0x0a0a
        0x0a, 0x0a,

        // secp256r1 = 23
        0x00, 0x17,

        // GREASE 0x1a1a
        0x1a, 0x1a,

        // secp384r1 = 24
        0x00, 0x18
    };

    const auto client_hello =
        build_client_hello(
            {4865, 4866, 4867},
            extensions);

    ClientHelloData client{};

    ASSERT_TRUE(
        parse_client_hello(
            client_hello.data(),
            client_hello.size(),
            client));

    EXPECT_EQ(
        client.supported_groups,
        std::vector<uint16_t>({
            23,
            24
        }));

    const JA3Fingerprint fp =
        compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,4865-4866-4867,10,23-24,");
}


TEST(JA3Test, GreasePointFormatIsIgnored) {
    ClientHelloData client{};

    client.client_version = 771;

    client.ec_point_formats = {
        0x0a,
        1
    };

    // This test is NOT a GREASE test.
    // Point-format values are one-byte values.
    // Keep it as a normal serialization test.

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(
        fp.raw_string,
        "771,,,,10-1");
}
// ============================================================
// JA3S tests tests - source Documentation
// ============================================================
TEST(JA3STest, BasicServerHello) {
    ServerHelloData server{};

    server.server_version = 771;
    server.selected_cipher = 4865;
    server.extensions = {
        43, 51
    };

    const JA3Fingerprint fp =
        compute_ja3s(server);

    EXPECT_EQ(
        fp.raw_string,
        "771,4865,43-51");
}


TEST(JA3STest, EmptyExtensions) {
    ServerHelloData server{};

    server.server_version = 771;
    server.selected_cipher = 4865;
    server.extensions = {};

    const JA3Fingerprint fp =
        compute_ja3s(server);

    EXPECT_EQ(
        fp.raw_string,
        "771,4865,");
}


TEST(JA3STest, ExtensionOrderingPreserved) {
    ServerHelloData a{};
    ServerHelloData b{};

    a.server_version = 771;
    b.server_version = 771;

    a.selected_cipher = 4865;
    b.selected_cipher = 4865;

    a.extensions = { 43, 51 };
    b.extensions = { 51, 43 };

    const JA3Fingerprint fp_a =
        compute_ja3s(a);

    const JA3Fingerprint fp_b =
        compute_ja3s(b);

    EXPECT_NE(fp_a.raw_string, fp_b.raw_string);
    EXPECT_NE(fp_a.md5_hash, fp_b.md5_hash);
}
// ============================================================
// VLAN tests tests
// ============================================================
TEST_F(LinkLayerDemuxTest, HandlesSingleVLAN) {
    ctx.link_type = DLT_EN10MB;

    const std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    const auto ip_pkt =
        build_ip_tcp_payload(payload);

    // Ethernet + 802.1Q + IPv4/TCP.
    std::vector<uint8_t> pkt(
        14 + 4 + ip_pkt.size(), 0);

    // EtherType = 802.1Q.
    pkt[12] = 0x81;
    pkt[13] = 0x00;

    // VLAN TCI.
    pkt[14] = 0x00;
    pkt[15] = 0x01;

    // Inner EtherType = IPv4.
    pkt[16] = 0x08;
    pkt[17] = 0x00;

    std::memcpy(
        pkt.data() + 18,
        ip_pkt.data(),
        ip_pkt.size());

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 1u);
}

TEST_F(LinkLayerDemuxTest, HandlesDoubleVLAN) {
    ctx.link_type = DLT_EN10MB;

    const std::vector<uint8_t> payload = {
        0x16, 0x03, 0x01, 0x00, 0x50
    };

    const auto ip_pkt =
        build_ip_tcp_payload(payload);

    std::vector<uint8_t> pkt(
        14 + 8 + ip_pkt.size(), 0);

    // Outer 802.1ad.
    pkt[12] = 0x88;
    pkt[13] = 0xa8;

    // Outer VLAN TCI.
    pkt[14] = 0x00;
    pkt[15] = 0x01;

    // Inner 802.1Q.
    pkt[16] = 0x81;
    pkt[17] = 0x00;

    // Inner VLAN TCI.
    pkt[18] = 0x00;
    pkt[19] = 0x02;

    // IPv4.
    pkt[20] = 0x08;
    pkt[21] = 0x00;

    std::memcpy(
        pkt.data() + 22,
        ip_pkt.data(),
        ip_pkt.size());

    inject_packet(pkt);

    EXPECT_EQ(ctx.active_flows.size(), 1u);
}