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
        const std::vector<uint8_t>& payload) {

        constexpr size_t ip_len = 20;
        constexpr size_t tcp_len = 20;

        std::vector<uint8_t> pkt(
            ip_len + tcp_len + payload.size(), 0);

        // IPv4 header
        pkt[0] = 0x45;  // IPv4, IHL = 5

        uint16_t total_len =
            htons(static_cast<uint16_t>(
                ip_len + tcp_len + payload.size()));

        std::memcpy(&pkt[2], &total_len, sizeof(total_len));

        pkt[9] = IPPROTO_TCP;

        // Source IP: 10.0.0.1
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1;

        // Destination IP: 10.0.0.2
        pkt[16] = 10;
        pkt[17] = 0;
        pkt[18] = 0;
        pkt[19] = 2;

        // TCP header
        uint16_t sport = htons(12345);
        uint16_t dport = htons(443);

        uint32_t net_seq = htonl(1000);

        std::memcpy(&pkt[20], &sport, sizeof(sport));
        std::memcpy(&pkt[22], &dport, sizeof(dport));
        std::memcpy(&pkt[24], &net_seq, sizeof(net_seq));

        // TCP data offset = 5 words = 20 bytes
        pkt[32] = 0x50;

        // TCP payload
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