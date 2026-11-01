// Tests for pqtls_analysis.cpp (the INTERPRET part of PQ-TLS):
//   make_pqtls_offer(), pqtls_posture() (doc 5.2), pqtls_share_mode() (doc 5.3),
//   and the output text.
//
// How it works: we fill the observation structs by hand (no bytes, no pcap),
// because the parser itself is already tested in test_pqtls_parser.cpp.

#include <gtest/gtest.h>

#include "tlsfp/pqtls_analysis.hpp"

using namespace tlsfp;

// ---------- make_pqtls_offer() ----------

// The offer copies the PQ-TLS facts out of the ClientHello observation.
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

// PQ group listed, but only a classical key sent.
TEST(PqtlsAnalysisTest, MakeOfferWithoutPQKey) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;
    client.key_share_groups = {0x001d};
    client.key_share_lens = {32};

    PqtlsOffer offer = make_pqtls_offer(client);

    EXPECT_EQ(offer.pq_group, 0x11ec);
    EXPECT_FALSE(offer.pq_key_sent);
}

// ---------- pqtls_posture(): one rule at a time ----------

TEST(PqtlsAnalysisTest, PostureRules) {
    PqtlsOffer pq_offer;
    pq_offer.seen = true;
    pq_offer.pq_group = 0x11ec;
    pq_offer.pq_key_sent = true;

    PqtlsOffer classical_offer;
    classical_offer.seen = true;

    PqtlsOffer not_seen;   // seen = false

    PqtlsServerObservation hybrid;
    hybrid.selected_group = 0x11ec;

    PqtlsServerObservation classical;
    classical.selected_group = 0x001d;

    PqtlsServerObservation hrr;
    hrr.is_hrr = true;
    hrr.selected_group = 0x0017;

    PqtlsServerObservation tls12;   // no key_share at all, selected_group stays 0

    EXPECT_EQ(pqtls_posture(not_seen, hybrid), PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO);
    EXPECT_EQ(pqtls_posture(pq_offer, hrr), PqtlsPosture::HRR_REQUESTED_RETRY);
    EXPECT_EQ(pqtls_posture(pq_offer, hybrid), PqtlsPosture::HYBRID_SELECTED_OBSERVED);
    EXPECT_EQ(pqtls_posture(pq_offer, classical), PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER);
    EXPECT_EQ(pqtls_posture(pq_offer, tls12), PqtlsPosture::CLASSICAL_SELECTED_AFTER_HYBRID_OFFER);
    EXPECT_EQ(pqtls_posture(classical_offer, classical), PqtlsPosture::CLASSICAL_NO_PQ_OFFERED);
}

// ---------- Text for the output lines ----------

// The text functions give exactly what the engine prints.
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
    server.selected_group = 0x11ec;
    server.server_share_len = 1120;
    EXPECT_EQ(pqtls_server_text(server), "0x11ec (X25519MLKEM768), post-quantum hybrid, key 1120B");

    PqtlsServerObservation hrr;
    hrr.is_hrr = true;
    hrr.selected_group = 0x0017;
    EXPECT_EQ(pqtls_server_text(hrr), "HelloRetryRequest: asks for 0x0017 (secp256r1)");

    PqtlsClientObservation plain;
    EXPECT_EQ(pqtls_offer_text(plain), "no PQ group offered");
    EXPECT_EQ(pqtls_keys_text(plain), "<none>");
}

// Every label has a printable name.
TEST(PqtlsAnalysisTest, PostureNames) {
    EXPECT_STREQ(pqtls_posture_name(PqtlsPosture::HYBRID_SELECTED_OBSERVED), "HYBRID_SELECTED_OBSERVED");
    EXPECT_STREQ(pqtls_posture_name(PqtlsPosture::HRR_REQUESTED_RETRY), "HRR_REQUESTED_RETRY");
    EXPECT_STREQ(pqtls_posture_name(PqtlsPosture::UNKNOWN_NO_CLIENT_HELLO), "UNKNOWN (ClientHello not seen)");
}

// ---------- pqtls_share_mode(): proactive vs reactive (doc section 5.3) ----------

// One hand-filled ClientHello observation per rule.
TEST(PqtlsAnalysisTest, ShareModeRules) {
    // Like Chrome: PQ listed, 1216 byte PQ key sent right away.
    PqtlsClientObservation proactive;
    proactive.pq_group = 0x11ec;
    proactive.has_key_share = true;
    proactive.key_share_parsed = true;
    proactive.key_share_groups = {0x11ec, 0x001d};
    proactive.key_share_lens = {1216, 32};
    EXPECT_EQ(pqtls_share_mode(proactive, false), PqtlsShareMode::PROACTIVE_SHARE_VALID);

    // PQ listed, but only the 32 byte classical key sent.
    PqtlsClientObservation supported_only;
    supported_only.pq_group = 0x11ec;
    supported_only.has_key_share = true;
    supported_only.key_share_parsed = true;
    supported_only.key_share_groups = {0x001d};
    supported_only.key_share_lens = {32};
    EXPECT_EQ(pqtls_share_mode(supported_only, false), PqtlsShareMode::SUPPORTED_ONLY);

    // Same hello, but it is the second hello after an HRR.
    EXPECT_EQ(pqtls_share_mode(supported_only, true), PqtlsShareMode::RETRY_AFTER_HRR);

    // Like curl: no PQ group at all (even after an HRR).
    PqtlsClientObservation classical;
    classical.has_key_share = true;
    classical.key_share_parsed = true;
    classical.key_share_groups = {0x001d};
    classical.key_share_lens = {32};
    EXPECT_EQ(pqtls_share_mode(classical, false), PqtlsShareMode::NO_PQ_OFFERED);
    EXPECT_EQ(pqtls_share_mode(classical, true), PqtlsShareMode::NO_PQ_OFFERED);

    // PQ key present but only 100 bytes: too small to be real.
    PqtlsClientObservation too_small;
    too_small.pq_group = 0x11ec;
    too_small.has_key_share = true;
    too_small.key_share_parsed = true;
    too_small.key_share_groups = {0x11ec};
    too_small.key_share_lens = {100};
    EXPECT_EQ(pqtls_share_mode(too_small, false), PqtlsShareMode::UNKNOWN_SHARE);

    // key_share could not be read.
    PqtlsClientObservation unreadable;
    unreadable.pq_group = 0x11ec;
    unreadable.has_key_share = true;
    unreadable.key_share_parsed = false;
    EXPECT_EQ(pqtls_share_mode(unreadable, false), PqtlsShareMode::UNKNOWN_SHARE);
}

// The 1200 byte threshold: exactly 1200 counts, 1199 does not.
TEST(PqtlsAnalysisTest, ShareModeThreshold) {
    PqtlsClientObservation client;
    client.pq_group = 0x11ec;
    client.has_key_share = true;
    client.key_share_parsed = true;
    client.key_share_groups = {0x11ec};

    client.key_share_lens = {1200};
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::PROACTIVE_SHARE_VALID);

    client.key_share_lens = {1199};
    EXPECT_EQ(pqtls_share_mode(client, false), PqtlsShareMode::UNKNOWN_SHARE);
}

// Every share mode has a printable name.
TEST(PqtlsAnalysisTest, ShareModeNames) {
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::PROACTIVE_SHARE_VALID), "PROACTIVE_SHARE_VALID");
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::SUPPORTED_ONLY), "SUPPORTED_ONLY");
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::RETRY_AFTER_HRR), "RETRY_AFTER_HRR");
    EXPECT_STREQ(pqtls_share_mode_name(PqtlsShareMode::NO_PQ_OFFERED), "NO_PQ_OFFERED");
}
