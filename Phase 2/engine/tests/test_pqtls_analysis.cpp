// PQ-TLS interpretation tests (pqtls_analysis.cpp) on hand-filled observation structs.
// Byte-level parsing is covered in test_pqtls_parser.cpp.

#include <gtest/gtest.h>
#include <arpa/inet.h>

#include "tlsfp/pqtls_analysis.hpp"

using namespace tlsfp;

// ============================================================
// FLOW OFFER
// ============================================================

// Offer snapshot from ClientHello observation
TEST(PqtlsAnalysisTest, MakeOfferFromClientHello) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;
    client.key_share_groups = {0x11ec, 0x001d};
    client.key_share_lens = {1216, 32};

    PqtlsOffer offer = make_pqtls_offer(client);

    EXPECT_TRUE(offer.seen);
    EXPECT_EQ(offer.pq_group, 0x11ec);
    EXPECT_TRUE(offer.pq_key_sent);
}

// PQ listed, classical key only
TEST(PqtlsAnalysisTest, MakeOfferWithoutPQKey) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;
    client.key_share_groups = {0x001d};
    client.key_share_lens = {32};

    PqtlsOffer offer = make_pqtls_offer(client);

    EXPECT_EQ(offer.pq_group, 0x11ec);
    EXPECT_FALSE(offer.pq_key_sent);
}

// ============================================================
// POSTURE (PQ-TLS doc Sec. 5.2)
// ============================================================

TEST(PqtlsAnalysisTest, PostureRules) {
    PqtlsOffer pq_offer;
    pq_offer.seen = true;
    pq_offer.pq_group = 0x11ec;
    pq_offer.pq_key_sent = true;

    PqtlsOffer classical_offer;
    classical_offer.seen = true;

    PqtlsOffer not_seen;   // seen = false

    PqtlsServerObservation hybrid;
    hybrid.has_key_share = true;
    hybrid.key_share_parsed = true;
    hybrid.selected_group = 0x11ec;
    hybrid.server_share_len = 1120;

    PqtlsServerObservation classical;
    classical.has_key_share = true;
    classical.key_share_parsed = true;
    classical.selected_group = 0x001d;
    classical.server_share_len = 32;

    PqtlsServerObservation hrr;
    hrr.has_key_share = true;
    hrr.key_share_parsed = true;
    hrr.is_hrr = true;
    hrr.selected_group = 0x0017;

    PqtlsServerObservation tls12;   // No key_share

    const uint16_t TLS13 = 0x0304;
    const uint16_t TLS12 = 0x0303;

    EXPECT_EQ(pqtls_posture(not_seen, hybrid, TLS13), PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO);
    EXPECT_EQ(pqtls_posture(pq_offer, hrr, TLS13), PqtlsPosture::HRR_REQUESTED_RETRY);
    EXPECT_EQ(pqtls_posture(pq_offer, hybrid, TLS13), PqtlsPosture::HYBRID_SELECTED_OBSERVED);
    EXPECT_EQ(pqtls_posture(pq_offer, classical, TLS13), PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER);
    EXPECT_EQ(pqtls_posture(pq_offer, tls12, TLS12), PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER);
    EXPECT_EQ(pqtls_posture(classical_offer, classical, TLS13), PqtlsPosture::CLASSICAL_NO_PQ_OFFERED);
}

// ============================================================
// OUTPUT TEXT
// ============================================================

// Verbose line text
TEST(PqtlsAnalysisTest, OutputText) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;
    client.pq_first_choice = true;
    client.has_key_share = true;
    client.key_share_parsed = true;
    client.key_share_groups = {0x11ec, 0x001d};
    client.key_share_lens = {1216, 32};

    EXPECT_EQ(pqtls_offer_text(client), "offered 0x11ec (X25519MLKEM768), first choice");
    EXPECT_EQ(pqtls_keys_text(client), "0x11ec (X25519MLKEM768) 1216B, 0x001d (x25519) 32B");

    PqtlsServerObservation server;
    server.has_key_share = true;
    server.key_share_parsed = true;
    server.selected_group = 0x11ec;
    server.server_share_len = 1120;
    EXPECT_EQ(pqtls_server_text(server), "0x11ec (X25519MLKEM768), post-quantum hybrid, key 1120B");

    PqtlsServerObservation hrr;
    hrr.has_key_share = true;
    hrr.key_share_parsed = true;
    hrr.is_hrr = true;
    hrr.selected_group = 0x0017;
    EXPECT_EQ(pqtls_server_text(hrr), "HelloRetryRequest: asks for 0x0017 (secp256r1)");

    PqtlsClientObservation plain;
    EXPECT_EQ(pqtls_offer_text(plain), "no PQ group offered");
    EXPECT_EQ(pqtls_keys_text(plain), "<none>");
}

// Posture names
TEST(PqtlsAnalysisTest, PostureNames) {
    EXPECT_STREQ(pqtls_posture_name(PqtlsPosture::HYBRID_SELECTED_OBSERVED), "HYBRID_SELECTED_OBSERVED");
    EXPECT_STREQ(pqtls_posture_name(PqtlsPosture::HRR_REQUESTED_RETRY), "HRR_REQUESTED_RETRY");
    EXPECT_STREQ(pqtls_posture_name(PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO), "UNKNOWN (ClientHello not seen)");
}

// ============================================================
// SHARE MODE (PQ-TLS doc Sec. 5.3)
// ============================================================

// One case per rule
TEST(PqtlsAnalysisTest, ShareModeRules) {
    // Chrome-style: 1216 B PQ key
    PqtlsClientObservation proactive;
    proactive.pq_group = 0x11ec;
    proactive.has_key_share = true;
    proactive.key_share_parsed = true;
    proactive.key_share_groups = {0x11ec, 0x001d};
    proactive.key_share_lens = {1216, 32};
    EXPECT_EQ(pqtls_share_mode(proactive, false), PqtlsShareMode::PROACTIVE_SHARE_VALID);

    // PQ listed, x25519 key only
    PqtlsClientObservation supported_only;
    supported_only.pq_group = 0x11ec;
    supported_only.has_key_share = true;
    supported_only.key_share_parsed = true;
    supported_only.key_share_groups = {0x001d};
    supported_only.key_share_lens = {32};
    EXPECT_EQ(pqtls_share_mode(supported_only, false), PqtlsShareMode::SUPPORTED_ONLY);

    // Same hello after HRR
    EXPECT_EQ(pqtls_share_mode(supported_only, true), PqtlsShareMode::RETRY_AFTER_HRR);

    // curl-style: no PQ group (with and without HRR)
    PqtlsClientObservation classical;
    classical.has_key_share = true;
    classical.key_share_parsed = true;
    classical.key_share_groups = {0x001d};
    classical.key_share_lens = {32};
    EXPECT_EQ(pqtls_share_mode(classical, false), PqtlsShareMode::NO_PQ_OFFERED);
    EXPECT_EQ(pqtls_share_mode(classical, true), PqtlsShareMode::NO_PQ_OFFERED);

    // PQ key of 100 B
    PqtlsClientObservation too_small;
    too_small.pq_group = 0x11ec;
    too_small.has_key_share = true;
    too_small.key_share_parsed = true;
    too_small.key_share_groups = {0x11ec};
    too_small.key_share_lens = {100};
    EXPECT_EQ(pqtls_share_mode(too_small, false), PqtlsShareMode::UNKNOWN_SHARE);

    // Unreadable key_share
    PqtlsClientObservation unreadable;
    unreadable.pq_group = 0x11ec;
    unreadable.has_key_share = true;
    unreadable.key_share_parsed = false;
    EXPECT_EQ(pqtls_share_mode(unreadable, false), PqtlsShareMode::UNKNOWN_SHARE);
}

// Exact RFC 10024 size required (replaces former >= 1200 B rule)
TEST(PqtlsAnalysisTest, ShareModeExactLength) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;
    client.has_key_share = true;
    client.key_share_parsed = true;
    client.key_share_groups = {0x11ec};

    client.key_share_lens = {1216};
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::PROACTIVE_SHARE_VALID);

    client.key_share_lens = {1200};   // Previously accepted
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::UNKNOWN_SHARE);

    client.key_share_lens = {1217};
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::UNKNOWN_SHARE);

    // SecP256r1MLKEM768: 1249 B
    client.pq_group = 0x11eb;
    client.key_share_groups = {0x11eb};
    client.key_share_lens = {1249};
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::PROACTIVE_SHARE_VALID);
    client.key_share_lens = {1216};
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::UNKNOWN_SHARE);
}

// Share mode names
TEST(PqtlsAnalysisTest, ShareModeNames) {
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::PROACTIVE_SHARE_VALID), "PROACTIVE_SHARE_VALID");
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::SUPPORTED_ONLY), "SUPPORTED_ONLY");
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::RETRY_AFTER_HRR), "RETRY_AFTER_HRR");
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::NO_PQ_OFFERED), "NO_PQ_OFFERED");
}

// ============================================================
// WIRE CHECKS (PQ-TLS doc Sec. 5.6)
// ============================================================

// RFC 10024 Sec. 3 sizes per direction
TEST(PqtlsAnalysisTest, ExpectedKeySizes) {
    EXPECT_EQ(pqtls_expected_client_len(0x11ec), 1216);
    EXPECT_EQ(pqtls_expected_server_len(0x11ec), 1120);
    EXPECT_EQ(pqtls_expected_client_len(0x11eb), 1249);
    EXPECT_EQ(pqtls_expected_server_len(0x11eb), 1153);
    EXPECT_EQ(pqtls_expected_client_len(0x11ed), 1665);
    EXPECT_EQ(pqtls_expected_server_len(0x11ed), 1665);
    EXPECT_EQ(pqtls_expected_client_len(0x001d), 0);   // Non-PQ group
    EXPECT_EQ(pqtls_expected_server_len(0x001d), 0);
}

// Client size check (classical keys not checked)
TEST(PqtlsAnalysisTest, ClientSizeCheck) {
    PqtlsClientObservation good;
    good.key_share_groups = {0x11ec, 0x001d};
    good.key_share_lens = {1216, 32};
    EXPECT_EQ(pqtls_client_findings(good), PQTLS_FINDING_NONE);
    EXPECT_EQ(pqtls_client_check_text(good), "ok");

    PqtlsClientObservation bad;
    bad.key_share_groups = {0x11ec};
    bad.key_share_lens = {1000};
    EXPECT_EQ(pqtls_client_findings(bad), PQTLS_MALFORMED_SHARE_LENGTH);
    EXPECT_EQ(pqtls_client_check_text(bad), "PQC_MALFORMED_SHARE_LENGTH (0x11ec sent 1000B, expected 1216B) ");
}

// Server size check (HRR not checked)
TEST(PqtlsAnalysisTest, ServerSizeCheck) {
    PqtlsServerObservation good;
    good.selected_group = 0x11ec;
    good.server_share_len = 1120;
    EXPECT_EQ(pqtls_server_findings(good), PQTLS_FINDING_NONE);

    PqtlsServerObservation bad;
    bad.selected_group = 0x11ec;
    bad.server_share_len = 1216;   // Client-sized key in ServerHello
    EXPECT_EQ(pqtls_server_findings(bad), PQTLS_MALFORMED_SHARE_LENGTH);

    PqtlsServerObservation hrr;
    hrr.is_hrr = true;
    hrr.selected_group = 0x11ec;   // HRR: no key
    EXPECT_EQ(pqtls_server_findings(hrr), PQTLS_FINDING_NONE);
}

// Combined findings
TEST(PqtlsAnalysisTest, DuplicateAndSizeTogether) {
    PqtlsClientObservation client;
    client.duplicate_key_share = true;
    client.key_share_groups = {0x11ec};
    client.key_share_lens = {1000};
    EXPECT_EQ(pqtls_client_findings(client), PQTLS_MALFORMED_SHARE_LENGTH | PQTLS_DUPLICATE_EXTENSION);

    PqtlsServerObservation server;
    server.duplicate_key_share = true;
    EXPECT_EQ(pqtls_server_findings(server), PQTLS_DUPLICATE_EXTENSION);
    EXPECT_EQ(pqtls_server_check_text(server), "PQC_DUPLICATE_EXTENSION (key_share twice) ");
}

// ============================================================
// REGRESSION: LABEL / FINDING CONSISTENCY
// ============================================================

// Share mode and size check must agree across key lengths
TEST(PqtlsAnalysisTest, ShareModeNeverContradictsSizeCheck) {
    const uint16_t lengths[] = {0, 32, 1184, 1199, 1200, 1215, 1216, 1217, 1249, 1665, 4000};
    for (uint16_t len : lengths) {
        PqtlsClientObservation client;
        client.pq_group = 0x11ec;
        client.has_key_share = true;
        client.key_share_parsed = true;
        client.key_share_groups.push_back(0x11ec);
        client.key_share_lens.push_back(len);
        client.key_share_groups.push_back(0x001d);
        client.key_share_lens.push_back(32);

        bool says_valid = (pqtls_share_mode(client, false) == PqtlsShareMode::PROACTIVE_SHARE_VALID);
        bool size_ok = (pqtls_client_findings(client) == PQTLS_FINDING_NONE);
        EXPECT_EQ(says_valid, size_ok) << "length " << len;
    }
}

// Unreadable client key_share -> PQC_MALFORMED_KEY_SHARE
TEST(PqtlsAnalysisTest, UnreadableClientKeyShareIsReported) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;
    client.has_key_share = true;
    client.key_share_parsed = false;

    EXPECT_EQ(pqtls_client_findings(client), PQTLS_MALFORMED_KEY_SHARE);
    EXPECT_EQ(pqtls_client_check_text(client), "PQC_MALFORMED_KEY_SHARE (key_share could not be read) ");
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::UNKNOWN_SHARE);
}

// Absent key_share is not a parse failure
TEST(PqtlsAnalysisTest, MissingClientKeyShareIsNotMalformed) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;   // has_key_share = false

    EXPECT_EQ(pqtls_client_findings(client), PQTLS_FINDING_NONE);
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::SUPPORTED_ONLY);
}

// Unreadable server key_share -> finding + UNKNOWN_SERVER_SELECTION
TEST(PqtlsAnalysisTest, UnreadableServerKeyShareIsUnknown) {
    PqtlsOffer offer;
    offer.seen = true;
    offer.pq_group = 0x11ec;

    PqtlsServerObservation server;
    server.has_key_share = true;
    server.key_share_parsed = false;   // e.g. 1120 B declared, 0 present
    server.selected_group = 0x11ec;
    server.server_share_len = 1120;

    EXPECT_EQ(pqtls_server_findings(server), PQTLS_MALFORMED_KEY_SHARE);
    EXPECT_NE(pqtls_server_check_text(server), "ok");
    EXPECT_EQ(pqtls_posture(offer, server, 0x0304), PqtlsPosture::UNKNOWN_SERVER_SELECTION);
    EXPECT_EQ(pqtls_server_text(server), "present, but could not be read (bad lengths)");
}

// Hybrid group with wrong key size -> UNKNOWN_SERVER_SELECTION
TEST(PqtlsAnalysisTest, WrongSizeHybridIsNotConfirmed) {
    PqtlsOffer offer;
    offer.seen = true;
    offer.pq_group = 0x11ec;

    PqtlsServerObservation server;
    server.has_key_share = true;
    server.key_share_parsed = true;
    server.selected_group = 0x11ec;
    server.server_share_len = 1000;

    EXPECT_EQ(pqtls_server_findings(server), PQTLS_MALFORMED_SHARE_LENGTH);
    EXPECT_EQ(pqtls_posture(offer, server, 0x0304), PqtlsPosture::UNKNOWN_SERVER_SELECTION);
}

// Missing / unrecognized server group -> UNKNOWN, classical only with evidence
TEST(PqtlsAnalysisTest, MissingOrUnknownServerGroupIsUnknown) {
    PqtlsOffer offer;
    offer.seen = true;
    offer.pq_group = 0x11ec;

    // TLS 1.3, no key_share (e.g. PSK-only)
    PqtlsServerObservation no_share;
    EXPECT_EQ(pqtls_posture(offer, no_share, 0x0304), PqtlsPosture::UNKNOWN_SERVER_SELECTION);

    // Unrecognized group
    PqtlsServerObservation unknown_group;
    unknown_group.has_key_share = true;
    unknown_group.key_share_parsed = true;
    unknown_group.selected_group = 0x1234;
    unknown_group.server_share_len = 32;
    EXPECT_EQ(pqtls_posture(offer, unknown_group, 0x0304), PqtlsPosture::UNKNOWN_SERVER_SELECTION);

    // TLS 1.2 and known classical groups remain classical
    EXPECT_EQ(pqtls_posture(offer, no_share, 0x0303), PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER);
    PqtlsServerObservation ffdhe;
    ffdhe.has_key_share = true;
    ffdhe.key_share_parsed = true;
    ffdhe.selected_group = 0x0100;   // ffdhe2048
    ffdhe.server_share_len = 256;
    EXPECT_EQ(pqtls_posture(offer, ffdhe, 0x0304), PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER);
}

TEST(PqtlsAnalysisTest, KnownClassicalGroups) {
    EXPECT_TRUE(is_known_classical_group(0x001d));   // x25519
    EXPECT_TRUE(is_known_classical_group(0x0017));   // secp256r1
    EXPECT_TRUE(is_known_classical_group(0x0018));   // secp384r1
    EXPECT_TRUE(is_known_classical_group(0x0104));   // ffdhe8192
    EXPECT_FALSE(is_known_classical_group(0x11ec));  // PQ hybrid
    EXPECT_FALSE(is_known_classical_group(0x1234));  // unknown
}

// ============================================================
// OFFER TABLE (per worker, bounded)
// ============================================================

namespace {

// Client -> server key, client port varies per flow
FlowKey client_key(uint16_t client_port) {
    FlowKey k;
    k.ip_version = 4;
    k.src_ip.v4.s_addr = htonl(0x0a000001);  // 10.0.0.1
    k.dst_ip.v4.s_addr = htonl(0x01010101);  // 1.1.1.1
    k.src_port = htons(client_port);
    k.dst_port = htons(443);
    return k;
}

// Same flow, server -> client
FlowKey server_key(uint16_t client_port) {
    FlowKey k = client_key(client_port);
    std::swap(k.src_ip, k.dst_ip);
    std::swap(k.src_port, k.dst_port);
    return k;
}

PqtlsOffer pq_offer() {
    PqtlsOffer offer;
    offer.seen = true;
    offer.pq_group = 0x11ec;
    offer.pq_key_sent = true;
    return offer;
}

} // anonymous namespace

// ServerHello finds the offer by the reversed key, then it is removed
TEST(PqtlsOfferTableTest, FinalServerHelloTakesAndRemoves) {
    PqtlsOfferTable table;
    table.store(client_key(50000), pq_offer());
    EXPECT_EQ(table.size(), 1u);

    PqtlsOffer offer = table.take(server_key(50000), false);
    EXPECT_TRUE(offer.seen);
    EXPECT_EQ(offer.pq_group, 0x11ec);
    EXPECT_EQ(table.size(), 0u);
}

// ServerHello with no ClientHello on the flow
TEST(PqtlsOfferTableTest, MissingOfferIsNotSeen) {
    PqtlsOfferTable table;
    PqtlsOffer offer = table.take(server_key(50000), false);
    EXPECT_FALSE(offer.seen);
}

// HRR keeps the offer for the retry; second ClientHello sees after_hrr
TEST(PqtlsOfferTableTest, HrrKeepsOfferForRetry) {
    PqtlsOfferTable table;
    table.store(client_key(50000), pq_offer());
    EXPECT_FALSE(table.after_hrr(client_key(50000)));

    table.take(server_key(50000), true);  // HRR
    EXPECT_EQ(table.size(), 1u);
    EXPECT_TRUE(table.after_hrr(client_key(50000)));

    table.store(client_key(50000), pq_offer());  // post-HRR ClientHello overwrites
    EXPECT_FALSE(table.after_hrr(client_key(50000)));

    EXPECT_TRUE(table.take(server_key(50000), false).seen);
    EXPECT_EQ(table.size(), 0u);
}

// Review issue: flows without a ServerHello must not grow the table forever
TEST(PqtlsOfferTableTest, SizeNeverExceedsMax) {
    PqtlsOfferTable table(8);
    for (uint16_t port = 1000; port < 1100; ++port) {
        table.store(client_key(port), pq_offer());
        EXPECT_LE(table.size(), 8u);
    }
}

// When full, the oldest offers go and the newest stay
TEST(PqtlsOfferTableTest, FullTableDropsOldestKeepsNewest) {
    PqtlsOfferTable table(4);
    table.store(client_key(1), pq_offer());
    table.store(client_key(2), pq_offer());
    table.store(client_key(3), pq_offer());
    table.store(client_key(4), pq_offer());
    table.store(client_key(5), pq_offer());  // full: older half (1, 2) dropped

    EXPECT_EQ(table.size(), 3u);
    EXPECT_FALSE(table.take(server_key(1), false).seen);
    EXPECT_FALSE(table.take(server_key(2), false).seen);
    EXPECT_TRUE(table.take(server_key(3), false).seen);
    EXPECT_TRUE(table.take(server_key(5), false).seen);
}

// Updating an existing flow does not evict anything
TEST(PqtlsOfferTableTest, OverwriteSameFlowDoesNotEvict) {
    PqtlsOfferTable table(2);
    table.store(client_key(1), pq_offer());
    table.store(client_key(2), pq_offer());
    table.store(client_key(2), pq_offer());  // same flow again

    EXPECT_EQ(table.size(), 2u);
    EXPECT_TRUE(table.take(server_key(1), false).seen);
}
