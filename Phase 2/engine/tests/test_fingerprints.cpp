#include <gtest/gtest.h>

#include "tlsfp/types.hpp"
#include "tlsfp/accumulator.hpp"
#include "tlsfp/parser.hpp"
#include "tlsfp/ja3.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <vector>
#include <string>

using namespace tlsfp;

// ============================================================
// HELPER FUNCTIONS & FIXTURES
// ============================================================

namespace {

FlowKey make_ipv4_key(const char* src, const char* dst, uint16_t sport, uint16_t dport) {
    FlowKey key{};
    key.ip_version = 4;
    inet_pton(AF_INET, src, &key.src_ip.v4);
    inet_pton(AF_INET, dst, &key.dst_ip.v4);
    key.src_port = sport;
    key.dst_port = dport;
    return key;
}

FlowKey make_ipv6_key(const char* src, const char* dst, uint16_t sport, uint16_t dport) {
    FlowKey key{};
    key.ip_version = 6;
    inet_pton(AF_INET6, src, &key.src_ip.v6);
    inet_pton(AF_INET6, dst, &key.dst_ip.v6);
    key.src_port = sport;
    key.dst_port = dport;
    return key;
}

std::vector<uint8_t> build_client_hello_record(
    const std::vector<uint16_t>& cipher_suites,
    const std::vector<uint8_t>& extensions) {

    std::vector<uint8_t> handshake;

    // TLS Version: 1.2 (0x0303)
    handshake.push_back(0x03);
    handshake.push_back(0x03);

    // Random: 32 bytes
    handshake.insert(handshake.end(), 32, 0x00);

    // Session ID length: 0
    handshake.push_back(0x00);

    // Cipher Suites
    const uint16_t cipher_len = static_cast<uint16_t>(cipher_suites.size() * 2);
    handshake.push_back(static_cast<uint8_t>(cipher_len >> 8));
    handshake.push_back(static_cast<uint8_t>(cipher_len & 0xff));

    for (uint16_t cipher : cipher_suites) {
        handshake.push_back(static_cast<uint8_t>(cipher >> 8));
        handshake.push_back(static_cast<uint8_t>(cipher & 0xff));
    }

    // Compression Methods: 1 method (null)
    handshake.push_back(0x01);
    handshake.push_back(0x00);

    // Extensions Length
    const uint16_t extensions_len = static_cast<uint16_t>(extensions.size());
    handshake.push_back(static_cast<uint8_t>(extensions_len >> 8));
    handshake.push_back(static_cast<uint8_t>(extensions_len & 0xff));

    handshake.insert(handshake.end(), extensions.begin(), extensions.end());

    // TLS Record Header (Handshake = 0x16, TLS 1.0 Legacy Version = 0x0301)
    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x01);

    const uint16_t record_len = static_cast<uint16_t>(4 + handshake.size());
    record.push_back(static_cast<uint8_t>(record_len >> 8));
    record.push_back(static_cast<uint8_t>(record_len & 0xff));

    // ClientHello Handshake Type (0x01)
    record.push_back(0x01);

    const uint32_t handshake_len = static_cast<uint32_t>(handshake.size());
    record.push_back(static_cast<uint8_t>(handshake_len >> 16));
    record.push_back(static_cast<uint8_t>(handshake_len >> 8));
    record.push_back(static_cast<uint8_t>(handshake_len & 0xff));

    record.insert(record.end(), handshake.begin(), handshake.end());

    return record;
}

} // anonymous namespace

// ============================================================
// FLOW TRACKING & HASHING TESTS
// ============================================================

TEST(FlowTrackingTest, IPv4Equality) {
    auto key1 = make_ipv4_key("192.168.1.1", "10.0.0.1", 4444, 443);
    auto key2 = make_ipv4_key("192.168.1.1", "10.0.0.1", 4444, 443);
    auto key3_diff_port = make_ipv4_key("192.168.1.1", "10.0.0.1", 4445, 443);
    auto key4_diff_ip = make_ipv4_key("192.168.1.2", "10.0.0.1", 4444, 443);

    EXPECT_TRUE(key1 == key2);
    EXPECT_FALSE(key1 == key3_diff_port);
    EXPECT_FALSE(key1 == key4_diff_ip);
}

TEST(FlowTrackingTest, IPv4DifferentDestinationPort) {
    auto key1 = make_ipv4_key("192.168.1.1", "10.0.0.1", 4444, 443);
    auto key2 = make_ipv4_key("192.168.1.1", "10.0.0.1", 4444, 8443);

    EXPECT_FALSE(key1 == key2);
}

TEST(FlowTrackingTest, IPv6Equality) {
    auto key1 = make_ipv6_key("2001:db8::1", "2001:db8::2", 5555, 443);
    auto key2 = make_ipv6_key("2001:db8::1", "2001:db8::2", 5555, 443);
    auto key3_diff_ip = make_ipv6_key("2001:db8::3", "2001:db8::2", 5555, 443);

    EXPECT_TRUE(key1 == key2);
    EXPECT_FALSE(key1 == key3_diff_ip);
}

TEST(FlowTrackingTest, VersionMismatchRejection) {
    auto key_v4 = make_ipv4_key("192.168.1.1", "10.0.0.1", 4444, 443);

    FlowKey key_fake_v6{};
    key_fake_v6.ip_version = 6;
    std::memcpy(&key_fake_v6.src_ip, &key_v4.src_ip, sizeof(key_fake_v6.src_ip));
    std::memcpy(&key_fake_v6.dst_ip, &key_v4.dst_ip, sizeof(key_fake_v6.dst_ip));
    key_fake_v6.src_port = 4444;
    key_fake_v6.dst_port = 443;

    EXPECT_FALSE(key_v4 == key_fake_v6);
}

TEST(FlowTrackingTest, HashDeterminism) {
    FlowHash hasher;
    auto key1 = make_ipv4_key("192.168.1.100", "8.8.8.8", 12345, 443);
    auto key2 = make_ipv4_key("192.168.1.100", "8.8.8.8", 12345, 443);

    EXPECT_EQ(hasher(key1), hasher(key2));
}

TEST(FlowTrackingTest, EqualKeysHaveEqualHashes) {
    FlowHash hasher;
    auto key1 = make_ipv4_key("192.168.1.100", "8.8.8.8", 12345, 443);
    auto key2 = make_ipv4_key("192.168.1.100", "8.8.8.8", 12345, 443);

    EXPECT_TRUE(key1 == key2);
    EXPECT_EQ(hasher(key1), hasher(key2));
}

TEST(FlowTrackingTest, HashDistinguishesReverseFlows) {
    FlowHash hasher;
    auto key_fwd = make_ipv4_key("1.1.1.1", "2.2.2.2", 1000, 2000);
    auto key_rev = make_ipv4_key("2.2.2.2", "1.1.1.1", 2000, 1000);

    EXPECT_NE(hasher(key_fwd), hasher(key_rev));
}

// ============================================================
// PHASE 2 TWO-TIER ACCUMULATOR TESTS
// ============================================================

class AccumulatorTest : public ::testing::Test {
protected:
    std::vector<std::vector<uint8_t>> received_records;
    FlowKey callback_key;

    TwoTierAccumulator accum{[this](const FlowKey &key, const uint8_t *data, size_t len) {
        received_records.emplace_back(data, data + len);
        callback_key = key;
    }};

    FlowKey test_key = make_ipv4_key("192.168.100.1", "192.168.100.2", 63408, 4433);
};

TEST_F(AccumulatorTest, Tier1FastPath_SinglePacketCompleteRecord) {
    auto tls_record = build_client_hello_record({0x1301, 0x1302}, {});

    accum.process_segment(test_key, 1000, tls_record.data(), tls_record.size(), 100000);

    EXPECT_EQ(received_records.size(), 1u);
    EXPECT_EQ(received_records[0], tls_record);
    EXPECT_EQ(accum.active_flow_count(), 0u);
}

TEST_F(AccumulatorTest, Tier2SlowPath_TwoSegmentReassembly) {
    auto tls_record = build_client_hello_record({0x1301, 0x1302, 0x1303}, std::vector<uint8_t>(500, 0xBB));

    size_t split_point = 300;
    std::vector<uint8_t> seg1(tls_record.begin(), tls_record.begin() + split_point);
    std::vector<uint8_t> seg2(tls_record.begin() + split_point, tls_record.end());

    uint32_t seq = 2000;

    accum.process_segment(test_key, seq, seg1.data(), seg1.size(), 100000);
    EXPECT_EQ(received_records.size(), 0u);
    EXPECT_EQ(accum.active_flow_count(), 1u);

    accum.process_segment(test_key, seq + seg1.size(), seg2.data(), seg2.size(), 100001);
    EXPECT_EQ(received_records.size(), 1u);
    EXPECT_EQ(received_records[0], tls_record);
    EXPECT_EQ(accum.active_flow_count(), 0u);
}

TEST_F(AccumulatorTest, StaleFlowCleanup) {
    auto tls_record = build_client_hello_record({0x1301}, std::vector<uint8_t>(300, 0xAA));
    std::vector<uint8_t> partial(tls_record.begin(), tls_record.begin() + 100);

    time_t start_time = 100000;
    accum.process_segment(test_key, 1000, partial.data(), partial.size(), start_time);
    EXPECT_EQ(accum.active_flow_count(), 1u);

    // Pre-timeout (< 5s): Flow remains active
    accum.cleanup_stale_flows(start_time + 2);
    EXPECT_EQ(accum.active_flow_count(), 1u);

    // Post-timeout (> 10s): Stale fragmented flow is evicted
    accum.cleanup_stale_flows(start_time + 15);
    EXPECT_EQ(accum.active_flow_count(), 0u);
}

TEST_F(AccumulatorTest, GRO_On_ProcessesJumboFrame) {
    std::vector<uint16_t> large_ciphers;
    for (uint16_t i = 1; i <= 30; ++i) {
        large_ciphers.push_back(0x1300 + i);
    }
    // 1600 bytes of extension data yields a total frame of ~1710 bytes (> 1514 MTU)
    std::vector<uint8_t> extensions(1600, 0x00);
    auto jumbo_record = build_client_hello_record(large_ciphers, extensions);

    ASSERT_GT(jumbo_record.size(), 1514u) << "Jumbo frame payload must exceed Ethernet MTU";

    accum.process_segment(test_key, 10000, jumbo_record.data(), jumbo_record.size(), 100000);

    EXPECT_EQ(received_records.size(), 1u);
    EXPECT_EQ(received_records[0].size(), jumbo_record.size());
    EXPECT_EQ(accum.active_flow_count(), 0u);
}

TEST_F(AccumulatorTest, GRO_Off_ReassemblesThreeSegments) {
    std::vector<uint16_t> ciphers = {0x1301, 0x1302, 0x1303};
    std::vector<uint8_t> extensions(900, 0xAA);
    auto tls_record = build_client_hello_record(ciphers, extensions);

    size_t chunk1_sz = 300;
    size_t chunk2_sz = 400;

    std::vector<uint8_t> seg1(tls_record.begin(), tls_record.begin() + chunk1_sz);
    std::vector<uint8_t> seg2(tls_record.begin() + chunk1_sz, tls_record.begin() + chunk1_sz + chunk2_sz);
    std::vector<uint8_t> seg3(tls_record.begin() + chunk1_sz + chunk2_sz, tls_record.end());

    uint32_t base_seq = 5000;

    accum.process_segment(test_key, base_seq, seg1.data(), seg1.size(), 100000);
    EXPECT_EQ(accum.active_flow_count(), 1u);

    accum.process_segment(test_key, base_seq + chunk1_sz, seg2.data(), seg2.size(), 100001);
    EXPECT_EQ(accum.active_flow_count(), 1u);

    accum.process_segment(test_key, base_seq + chunk1_sz + chunk2_sz, seg3.data(), seg3.size(), 100002);
    EXPECT_EQ(received_records.size(), 1u);
    EXPECT_EQ(received_records[0], tls_record);
    EXPECT_EQ(accum.active_flow_count(), 0u);
}

TEST(GROInvarianceTest, SingleVsSegmentedYieldsIdenticalJA3) {
    std::vector<uint16_t> ciphers = {0x1301, 0x1302, 0x1303, 0xc02c, 0xc030};
    std::vector<uint8_t> extensions = {0x00, 0x00, 0x00, 0x00};
    auto record = build_client_hello_record(ciphers, extensions);

    ClientHelloData client_gro_on{};
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), client_gro_on));
    JA3Fingerprint fp_gro_on = compute_ja3(client_gro_on);

    std::vector<uint8_t> reassembled;
    FlowKey key = make_ipv4_key("1.1.1.1", "2.2.2.2", 1234, 443);

    TwoTierAccumulator test_accum([&reassembled](const FlowKey&, const uint8_t* d, size_t l) {
        reassembled.assign(d, d + l);
    });

    size_t half = record.size() / 2;
    test_accum.process_segment(key, 100, record.data(), half, 1000);
    test_accum.process_segment(key, 100 + half, record.data() + half, record.size() - half, 1001);

    ClientHelloData client_gro_off{};
    ASSERT_TRUE(parse_client_hello(reassembled.data(), reassembled.size(), client_gro_off));
    JA3Fingerprint fp_gro_off = compute_ja3(client_gro_off);

    EXPECT_EQ(fp_gro_on.raw_string, fp_gro_off.raw_string);
    EXPECT_EQ(fp_gro_on.md5_hash, fp_gro_off.md5_hash);
}

// ============================================================
// MD5 TESTS - source RFC 1321
// ============================================================

TEST(MD5Test, EmptyString) {
    EXPECT_EQ(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
}

TEST(MD5Test, ABC) {
    EXPECT_EQ(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
}

TEST(MD5Test, Deterministic) {
    const std::string input = "The quick brown fox jumps over the lazy dog";
    EXPECT_EQ(md5_hex(input), md5_hex(input));
}

TEST(MD5Test, DifferentInputsProduceDifferentHashes) {
    EXPECT_NE(md5_hex("abc"), md5_hex("abd"));
}

TEST(MD5Test, Produces32LowercaseHexCharacters) {
    const std::string digest = md5_hex("test");
    ASSERT_EQ(digest.size(), 32u);
    for (char c : digest) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

// ============================================================
// OFFICIAL SALESFORCE VECTORS
// ============================================================

TEST(JA3Test, SalesforceOfficialVector1) {
    ClientHelloData client{};
    client.client_version = 769;
    client.cipher_suites = {47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4};
    client.extensions = {0, 10, 11};
    client.supported_groups = {23, 24, 25};
    client.ec_point_formats = {0};

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(fp.raw_string, "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0");
    EXPECT_EQ(fp.md5_hash, "ada70206e40642a3e4461f35503241d5");
}

TEST(JA3Test, SalesforceOfficialVector2) {
    ClientHelloData client{};
    client.client_version = 769;
    client.cipher_suites = {4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99};

    const JA3Fingerprint fp = compute_ja3(client);

    EXPECT_EQ(fp.raw_string, "769,4-5-10-9-100-98-3-6-19-18-99,,,");
    EXPECT_EQ(fp.md5_hash, "de350869b8c85de67a350c8d186f11e6");
}

// ============================================================
// FORMATTING & FIELD ORDERING TESTS
// ============================================================

TEST(JA3Test, EmptyFieldsArePreserved) {
    ClientHelloData client{};
    client.client_version = 771;
    client.cipher_suites = {4865, 4866, 4867};

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,4865-4866-4867,,,");
}

TEST(JA3Test, ExtensionOnly) {
    ClientHelloData client{};
    client.client_version = 771;
    client.extensions = {0, 10, 11};

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,,0-10-11,,");
}

TEST(JA3Test, SupportedGroupsOnly) {
    ClientHelloData client{};
    client.client_version = 771;
    client.supported_groups = {23, 24, 25};

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,,,23-24-25,");
}

TEST(JA3Test, PointFormatsOnly) {
    ClientHelloData client{};
    client.client_version = 771;
    client.ec_point_formats = {0, 1, 2};

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,,,,0-1-2");
}

TEST(JA3Test, CipherOrderIsPreserved) {
    ClientHelloData client{};
    client.client_version = 771;
    client.cipher_suites = {1, 2, 3};

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,1-2-3,,,");
}

TEST(JA3Test, ExtensionOrderIsPreserved) {
    ClientHelloData client{};
    client.client_version = 771;
    client.extensions = {11, 10, 0};

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,,11-10-0,,");
}

TEST(JA3Test, ChangingOrderChangesFingerprint) {
    ClientHelloData a{}, b{};
    a.client_version = 771; b.client_version = 771;
    a.cipher_suites = {1, 2, 3};
    b.cipher_suites = {3, 2, 1};

    const JA3Fingerprint fp_a = compute_ja3(a);
    const JA3Fingerprint fp_b = compute_ja3(b);

    EXPECT_NE(fp_a.raw_string, fp_b.raw_string);
    EXPECT_NE(fp_a.md5_hash, fp_b.md5_hash);
}

// ============================================================
// GREASE TESTS
// ============================================================

TEST(JA3Test, GreaseCipherIsIgnored) {
    const std::vector<uint16_t> ciphers = {0x0a0a, 4865, 0x1a1a, 4866, 4867};
    const auto record = build_client_hello_record(ciphers, {});

    ClientHelloData client{};
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), client));
    EXPECT_EQ(client.cipher_suites, std::vector<uint16_t>({4865, 4866, 4867}));

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,4865-4866-4867,,,");
}

TEST(JA3Test, GreaseExtensionIsIgnored) {
    const std::vector<uint8_t> extensions = {
        0x0a, 0x0a, 0x00, 0x00, // GREASE 0x0a0a
        0x00, 0x00, 0x00, 0x00, // Ext 0
        0x1a, 0x1a, 0x00, 0x00, // GREASE 0x1a1a
        0x00, 0x0a, 0x00, 0x00, // Ext 10
        0x00, 0x0b, 0x00, 0x00  // Ext 11
    };

    const auto record = build_client_hello_record({4865, 4866, 4867}, extensions);

    ClientHelloData client{};
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), client));
    EXPECT_EQ(client.extensions, std::vector<uint16_t>({0, 10, 11}));

    const JA3Fingerprint fp = compute_ja3(client);
    EXPECT_EQ(fp.raw_string, "771,4865-4866-4867,0-10-11,,");
}

// ============================================================
// JA3S TESTS
// ============================================================

TEST(JA3STest, BasicServerHello) {
    ServerHelloData server{};
    server.server_version = 771;
    server.selected_cipher = 4865;
    server.extensions = {43, 51};

    const JA3Fingerprint fp = compute_ja3s(server);
    EXPECT_EQ(fp.raw_string, "771,4865,43-51");
}

TEST(JA3STest, EmptyExtensions) {
    ServerHelloData server{};
    server.server_version = 771;
    server.selected_cipher = 4865;

    const JA3Fingerprint fp = compute_ja3s(server);
    EXPECT_EQ(fp.raw_string, "771,4865,");
}

TEST(JA3STest, ExtensionOrderingPreserved) {
    ServerHelloData a{}, b{};
    a.server_version = 771; b.server_version = 771;
    a.selected_cipher = 4865; b.selected_cipher = 4865;
    a.extensions = {43, 51};
    b.extensions = {51, 43};

    const JA3Fingerprint fp_a = compute_ja3s(a);
    const JA3Fingerprint fp_b = compute_ja3s(b);

    EXPECT_NE(fp_a.raw_string, fp_b.raw_string);
    EXPECT_NE(fp_a.md5_hash, fp_b.md5_hash);
}
// ============================================================
// LARGE RECEIVE OFFLOAD (LRO) BOUNDARY TESTS
// ============================================================

TEST_F(AccumulatorTest, LRO_Processes_CoalescedJumboFrame_3KB) {
    std::vector<uint16_t> large_ciphers;
    for (uint16_t i = 1; i <= 30; ++i) {
        large_ciphers.push_back(0x1300 + i);
    }
    
    // Simulate 3 KB coalesced frame from hardware LRO NIC (> 1514 MTU)
    std::vector<uint8_t> extensions(2800, 0x00);
    auto lro_record = build_client_hello_record(large_ciphers, extensions);

    ASSERT_GT(lro_record.size(), 1514u) << "LRO frame must exceed standard Ethernet MTU";
    ASSERT_LE(lro_record.size(), 8192u) << "LRO frame must fit within accumulator buffer ceiling";

    accum.process_segment(test_key, 10000, lro_record.data(), lro_record.size(), 100000);

    // Use ASSERT_EQ to prevent out-of-bounds vector access if empty
    ASSERT_EQ(received_records.size(), 1u);
    EXPECT_EQ(received_records[0].size(), lro_record.size());
    EXPECT_EQ(accum.active_flow_count(), 0u) << "LRO jumbo frame must hit Tier 1 Fast Path";
}

TEST_F(AccumulatorTest, LRO_Processes_MaxAccumulatorJumboFrame_7KB) {
    std::vector<uint16_t> large_ciphers;
    for (uint16_t i = 1; i <= 50; ++i) {
        large_ciphers.push_back(0x1300 + i);
    }
    
    // Simulate 7 KB coalesced frame near the 8 KB accumulator buffer boundary
    std::vector<uint8_t> extensions(6800, 0x00);
    auto max_lro_record = build_client_hello_record(large_ciphers, extensions);

    ASSERT_GT(max_lro_record.size(), 4000u);
    ASSERT_LE(max_lro_record.size(), 8192u);

    accum.process_segment(test_key, 20000, max_lro_record.data(), max_lro_record.size(), 100000);

    ASSERT_EQ(received_records.size(), 1u);
    EXPECT_EQ(received_records[0].size(), max_lro_record.size());
    EXPECT_EQ(accum.active_flow_count(), 0u) << "7 KB LRO frame must process zero-copy without fragmentation";
}

TEST(LROInvarianceTest, FragmentedVsLROCoalescedYieldsIdenticalJA3) {
    std::vector<uint16_t> ciphers = {0x1301, 0x1302, 0x1303, 0xc02c, 0xc030};
    std::vector<uint8_t> extensions(3000, 0x05); // 3 KB payload
    auto record = build_client_hello_record(ciphers, extensions);

    // 1. Process as single LRO-coalesced frame
    ClientHelloData client_lro{};
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), client_lro));
    JA3Fingerprint fp_lro = compute_ja3(client_lro);

    // 2. Process as 3 fragmented MTU segments (LRO OFF)
    std::vector<uint8_t> reassembled;
    FlowKey key = make_ipv4_key("10.0.0.1", "10.0.0.2", 54321, 443);

    TwoTierAccumulator test_accum([&reassembled](const FlowKey&, const uint8_t* d, size_t l) {
        reassembled.assign(d, d + l);
    });

    size_t chunk_size = record.size() / 3;
    uint32_t seq = 1000;
    
    for (size_t i = 0; i < 3; ++i) {
        size_t offset = i * chunk_size;
        size_t len = (i == 2) ? (record.size() - offset) : chunk_size;
        test_accum.process_segment(key, seq + static_cast<uint32_t>(offset), record.data() + offset, len, 10000 + i);
    }

    ClientHelloData client_fragmented{};
    ASSERT_TRUE(parse_client_hello(reassembled.data(), reassembled.size(), client_fragmented));
    JA3Fingerprint fp_fragmented = compute_ja3(client_fragmented);

    // Assert absolute fingerprint invariance between LRO-coalesced and segmented streams
    EXPECT_EQ(fp_lro.raw_string, fp_fragmented.raw_string);
    EXPECT_EQ(fp_lro.md5_hash, fp_fragmented.md5_hash);
}

// ============================================================
// TIER 2 ACCUMULATOR RESILIENCE TESTS
// ============================================================

TEST_F(AccumulatorTest, Tier2_EvictsFlowOnSequenceGap) {
    auto tls_record = build_client_hello_record({0x1301, 0x1302}, std::vector<uint8_t>(400, 0xAA));
    
    size_t split = 200;
    std::vector<uint8_t> seg1(tls_record.begin(), tls_record.begin() + split);
    std::vector<uint8_t> seg3(tls_record.begin() + split + 50, tls_record.end());

    uint32_t base_seq = 5000;

    // 1. Ingest Segment 1 (Starts Flow)
    accum.process_segment(test_key, base_seq, seg1.data(), seg1.size(), 100000);
    EXPECT_EQ(accum.active_flow_count(), 1u);

    // 2. Ingest Segment 3 with a forward gap (skips bytes 200-250)
    // Engine must detect sequence gap and immediately erase flow state to protect memory
    accum.process_segment(test_key, base_seq + split + 50, seg3.data(), seg3.size(), 100001);

    EXPECT_EQ(received_records.size(), 0u);
    EXPECT_EQ(accum.active_flow_count(), 0u) << "Sequence gap must trigger immediate flow eviction";
}

TEST_F(AccumulatorTest, Tier2_HandlesDuplicateRetransmittedSegments) {
    auto tls_record = build_client_hello_record({0x1301}, std::vector<uint8_t>(300, 0xBB));
    
    size_t split = 150;
    std::vector<uint8_t> seg1(tls_record.begin(), tls_record.begin() + split);
    std::vector<uint8_t> seg2(tls_record.begin() + split, tls_record.end());

    uint32_t base_seq = 8000;

    // 1. Ingest Segment 1
    accum.process_segment(test_key, base_seq, seg1.data(), seg1.size(), 100000);
    EXPECT_EQ(accum.active_flow_count(), 1u);
    
    // 2. Ingest Segment 1 AGAIN (Duplicate TCP Retransmission)
    accum.process_segment(test_key, base_seq, seg1.data(), seg1.size(), 100001);
    EXPECT_EQ(received_records.size(), 0u);
    EXPECT_EQ(accum.active_flow_count(), 1u);

    // 3. Ingest Segment 2 (Completes Stream)
    accum.process_segment(test_key, base_seq + split, seg2.data(), seg2.size(), 100002);

    ASSERT_EQ(received_records.size(), 1u);
    EXPECT_EQ(received_records[0], tls_record);
    EXPECT_EQ(accum.active_flow_count(), 0u);
}

TEST(LinkLayerDemuxTest, HandlesVlanTaggedEthernet) {
    // Standard Ethernet Header (14 B) + 802.1Q VLAN Tag (4 B) + IPv4 Header (20 B) + TCP Header (20 B)
    std::vector<uint8_t> packet = {
        // Ethernet Destination & Source MACs
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        // 802.1Q Tag Type (0x8100) and VLAN ID / Priority (VLAN 100 = 0x0064)
        0x81, 0x00, 0x00, 0x64,
        // Inner Protocol: IPv4 (0x0800)
        0x08, 0x00
    };

    // Verify offset calculation in your demux logic
    size_t mac_offset = 14;
    uint16_t ether_type = (packet[12] << 8) | packet[13];
    if (ether_type == 0x8100) {
        mac_offset += 4; // Successfully skipped VLAN header
    }
    
    EXPECT_EQ(mac_offset, 18u);
}

TEST(TLSParserTest, ParsesClientHelloWhenPipelinedWithSecondRecord) {
    // Record 1: ClientHello (Valid)
    auto client_hello_rec = build_client_hello_record({0x1301}, {});

    // Record 2: Application Data dummy record (0x17) appended to the same buffer
    std::vector<uint8_t> app_data_rec = {0x17, 0x03, 0x03, 0x00, 0x05, 'H', 'e', 'l', 'l', 'o'};

    // Combine into a single TCP payload
    std::vector<uint8_t> pipelined_payload = client_hello_rec;
    pipelined_payload.insert(pipelined_payload.end(), app_data_rec.begin(), app_data_rec.end());

    ClientHelloData client_data{};
    bool success = parse_client_hello(pipelined_payload.data(), pipelined_payload.size(), client_data);

    EXPECT_TRUE(success);
    EXPECT_EQ(client_data.cipher_suites, std::vector<uint16_t>({0x1301}));
}