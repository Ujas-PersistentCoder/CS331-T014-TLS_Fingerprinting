// PQ-TLS observation tests (pqtls_parser.cpp), using hand-built records
// from fixtures/pqtls_fixtures.hpp through parse_client_hello / parse_server_hello

#include <gtest/gtest.h>

#include "tlsfp/parser.hpp"
#include "tlsfp/pqtls_parser.hpp"
#include "tlsfp/pqtls_analysis.hpp"
#include "fixtures/pqtls_fixtures.hpp"

using namespace tlsfp;
using namespace pqtls_fixture;

// ============================================================
// CLIENTHELLO: SUPPORTED_GROUPS & KEY_SHARE
// ============================================================

// Chrome-style: GREASE, X25519MLKEM768, x25519
TEST(PqtlsParserTest, ChromeLikeHybridHello) {
    Bytes groups = make_extension(0x000a, make_groups_body({0x2a2a, 0x11ec, 0x001d, 0x0017}));
    Bytes shares = make_extension(0x0033, make_key_share_body({{0x2a2a, 1}, {0x11ec, 1216}, {0x001d, 32}}));
    Bytes record = make_client_hello(join(groups, shares));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_EQ(ch.pqtls.pq_group, 0x11ec);
    EXPECT_TRUE(ch.pqtls.pq_first_choice);   // GREASE ignored for preference

    EXPECT_TRUE(ch.pqtls.has_key_share);
    EXPECT_TRUE(ch.pqtls.key_share_parsed);
    ASSERT_EQ(ch.pqtls.key_share_groups.size(), 2u);   // GREASE entry pruned
    EXPECT_EQ(ch.pqtls.key_share_groups[0], 0x11ec);
    EXPECT_EQ(ch.pqtls.key_share_lens[0], 1216);
    EXPECT_EQ(ch.pqtls.key_share_groups[1], 0x001d);
    EXPECT_EQ(ch.pqtls.key_share_lens[1], 32);
}

// curl-style: classical groups only
TEST(PqtlsParserTest, ClassicalHelloHasNoPQGroup) {
    Bytes groups = make_extension(0x000a, make_groups_body({0x001d, 0x0017, 0x0018}));
    Bytes shares = make_extension(0x0033, make_key_share_body({{0x001d, 32}}));
    Bytes record = make_client_hello(join(groups, shares));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_EQ(ch.pqtls.pq_group, 0);
    EXPECT_FALSE(ch.pqtls.pq_first_choice);
    ASSERT_EQ(ch.pqtls.key_share_groups.size(), 1u);
    EXPECT_EQ(ch.pqtls.key_share_groups[0], 0x001d);
}

// PQ listed second, classical key only
TEST(PqtlsParserTest, PQListedButNotFirstAndNoPQKey) {
    Bytes groups = make_extension(0x000a, make_groups_body({0x001d, 0x11ec}));
    Bytes shares = make_extension(0x0033, make_key_share_body({{0x001d, 32}}));
    Bytes record = make_client_hello(join(groups, shares));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_EQ(ch.pqtls.pq_group, 0x11ec);
    EXPECT_FALSE(ch.pqtls.pq_first_choice);
    ASSERT_EQ(ch.pqtls.key_share_groups.size(), 1u);
    EXPECT_EQ(ch.pqtls.key_share_groups[0], 0x001d);   // Classical key only
}

// Declared key_len 1216, only 10 bytes present
TEST(PqtlsParserTest, KeyShareWithWrongLengthIsNotTrusted) {
    Bytes body;
    add16(body, 4 + 10);        // list_len
    add16(body, 0x11ec);        // group
    add16(body, 1216);          // key_len (overstated)
    body.insert(body.end(), 10, 0xAA);
    Bytes record = make_client_hello(make_extension(0x0033, body));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_TRUE(ch.pqtls.has_key_share);
    EXPECT_FALSE(ch.pqtls.key_share_parsed);
}

// clear() resets PQ state between hellos
TEST(PqtlsParserTest, NothingLeftOverBetweenHellos) {
    Bytes pq_hello = make_client_hello(join(
        make_extension(0x000a, make_groups_body({0x11ec, 0x001d})),
        make_extension(0x0033, make_key_share_body({{0x11ec, 1216}}))));
    Bytes plain_hello = make_client_hello(make_extension(0x0017, Bytes{}));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(pq_hello.data(), pq_hello.size(), ch));
    EXPECT_EQ(ch.pqtls.pq_group, 0x11ec);

    ASSERT_TRUE(parse_client_hello(plain_hello.data(), plain_hello.size(), ch));
    EXPECT_EQ(ch.pqtls.pq_group, 0);
    EXPECT_FALSE(ch.pqtls.pq_first_choice);
    EXPECT_FALSE(ch.pqtls.has_key_share);
    EXPECT_FALSE(ch.pqtls.key_share_parsed);
    EXPECT_TRUE(ch.pqtls.key_share_groups.empty());
    EXPECT_TRUE(ch.pqtls.key_share_lens.empty());
}

// find_pqtls_group() unit check
TEST(PqtlsParserTest, FindGroupDirectly) {
    PqtlsClientObservation obs;
    find_pqtls_group({0x000a}, {0x001d, 0x0017, 0x6399}, obs);
    EXPECT_EQ(obs.pq_group, 0x6399);        // Kyber draft group recognized
    EXPECT_FALSE(obs.pq_first_choice);
    EXPECT_FALSE(obs.duplicate_supported_groups);

    PqtlsClientObservation none;
    find_pqtls_group({0x000a}, {0x001d, 0x0017}, none);
    EXPECT_EQ(none.pq_group, 0);
}

// ============================================================
// SERVERHELLO: KEY_SHARE
// ============================================================

// Server selects X25519MLKEM768 (1120 B share)
TEST(PqtlsParserTest, ServerPicksHybridGroup) {
    Bytes body;
    add16(body, 0x11ec);
    add16(body, 1120);
    body.insert(body.end(), 1120, 0xBB);
    Bytes record = make_server_hello(make_extension(0x0033, body));

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));

    EXPECT_EQ(sh.pqtls.selected_group, 0x11ec);
    EXPECT_EQ(sh.pqtls.server_share_len, 1120);
    EXPECT_FALSE(sh.pqtls.is_hrr);
    EXPECT_TRUE(sh.pqtls.key_share_parsed);
}

// TLS 1.2-style ServerHello: no key_share
TEST(PqtlsParserTest, ServerWithoutKeyShare) {
    Bytes record = make_server_hello(make_extension(0xff01, Bytes{0}));  // renegotiation_info

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));

    EXPECT_EQ(sh.pqtls.selected_group, 0);
    EXPECT_EQ(sh.pqtls.server_share_len, 0);
}

// ============================================================
// HELLORETRYREQUEST
// ============================================================

// HRR: fixed random, key_share carries selected group only
TEST(PqtlsParserTest, HelloRetryRequestIsRecognised) {
    Bytes body;
    add16(body, 0x0017);   // Requested group: secp256r1
    Bytes record = make_server_hello(make_extension(0x0033, body), true);

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));

    EXPECT_TRUE(sh.pqtls.is_hrr);
    EXPECT_EQ(sh.pqtls.selected_group, 0x0017);
    EXPECT_EQ(sh.pqtls.server_share_len, 0);
    EXPECT_TRUE(sh.pqtls.key_share_parsed);   // Group-only layout is valid for HRR
}

// is_hrr_random(): exact match vs one-byte difference
TEST(PqtlsParserTest, HrrRandomCheck) {
    EXPECT_TRUE(is_hrr_random(HRR_RANDOM.data()));

    Bytes almost = HRR_RANDOM;
    almost[31] = 0x00;   // Flip last byte
    EXPECT_FALSE(is_hrr_random(almost.data()));
}

// ============================================================
// DUPLICATE EXTENSIONS (RFC 8446 Sec. 4.2)
// ============================================================

// Duplicate client key_share: first kept, flag set
TEST(PqtlsParserTest, DuplicateClientKeyShareKeepsFirst) {
    Bytes first = make_extension(0x0033, make_key_share_body({{0x11ec, 1216}}));
    Bytes second = make_extension(0x0033, make_key_share_body({{0x001d, 32}}));
    Bytes record = make_client_hello(join(first, second));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_TRUE(ch.pqtls.duplicate_key_share);
    ASSERT_EQ(ch.pqtls.key_share_groups.size(), 1u);   // First occurrence only
    EXPECT_EQ(ch.pqtls.key_share_groups[0], 0x11ec);
}

// Duplicate supported_groups: flag set
TEST(PqtlsParserTest, DuplicateSupportedGroupsIsFlagged) {
    Bytes first = make_extension(0x000a, make_groups_body({0x11ec, 0x001d}));
    Bytes second = make_extension(0x000a, make_groups_body({0x001d}));
    Bytes record = make_client_hello(join(first, second));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_TRUE(ch.pqtls.duplicate_supported_groups);
    EXPECT_FALSE(ch.pqtls.duplicate_key_share);
}

// Duplicate server key_share: first kept, flag set
TEST(PqtlsParserTest, DuplicateServerKeyShareKeepsFirst) {
    Bytes body1;
    add16(body1, 0x11ec);
    add16(body1, 1120);
    body1.insert(body1.end(), 1120, 0xBB);
    Bytes body2;
    add16(body2, 0x001d);
    add16(body2, 32);
    body2.insert(body2.end(), 32, 0xBB);
    Bytes record = make_server_hello(join(make_extension(0x0033, body1), make_extension(0x0033, body2)));

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));

    EXPECT_TRUE(sh.pqtls.duplicate_key_share);
    EXPECT_EQ(sh.pqtls.selected_group, 0x11ec);
    EXPECT_EQ(sh.pqtls.server_share_len, 1120);
}

// No duplicate flags on a well-formed hello
TEST(PqtlsParserTest, NormalHelloHasNoDuplicateFlags) {
    Bytes record = make_client_hello(join(
        make_extension(0x000a, make_groups_body({0x11ec, 0x001d})),
        make_extension(0x0033, make_key_share_body({{0x11ec, 1216}, {0x001d, 32}}))));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_FALSE(ch.pqtls.duplicate_key_share);
    EXPECT_FALSE(ch.pqtls.duplicate_supported_groups);
}

// ============================================================
// REGRESSION: KEY_SHARE FRAMING & LABEL CONSISTENCY
// ============================================================

// ServerHello declares 1120 B key, carries none
TEST(PqtlsParserTest, ServerKeyShareDeclaredButMissingBytes) {
    Bytes body;
    add16(body, 0x11ec);
    add16(body, 1120);          // Declared, no key bytes
    Bytes record = make_server_hello(make_extension(0x0033, body));

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));

    EXPECT_TRUE(sh.pqtls.has_key_share);
    EXPECT_FALSE(sh.pqtls.key_share_parsed);
    EXPECT_NE(pqtls_server_check_text(sh.pqtls), "ok");

    PqtlsOffer offer;
    offer.seen = true;
    offer.pq_group = 0x11ec;
    EXPECT_NE(pqtls_posture(offer, sh.pqtls, 0x0304), PqtlsPosture::HYBRID_SELECTED_OBSERVED);
}

// ServerHello key_share with trailing byte
TEST(PqtlsParserTest, ServerKeyShareWithTrailingBytes) {
    Bytes body;
    add16(body, 0x11ec);
    add16(body, 1120);
    body.insert(body.end(), 1120, 0xBB);
    body.push_back(0x00);       // Trailing byte
    Bytes record = make_server_hello(make_extension(0x0033, body));

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));
    EXPECT_FALSE(sh.pqtls.key_share_parsed);
}

// HRR carrying a full key share is malformed
TEST(PqtlsParserTest, HrrWithKeyBytesIsNotParsed) {
    Bytes body;
    add16(body, 0x11ec);
    add16(body, 1120);
    body.insert(body.end(), 1120, 0xBB);
    Bytes record = make_server_hello(make_extension(0x0033, body), true);

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));
    EXPECT_TRUE(sh.pqtls.is_hrr);
    EXPECT_FALSE(sh.pqtls.key_share_parsed);
    EXPECT_NE(pqtls_server_check_text(sh.pqtls), "ok");
}

// Truncated client key_share must not report "ok"
TEST(PqtlsParserTest, TruncatedClientKeyShareIsReported) {
    Bytes body;
    add16(body, 4 + 10);        // list_len
    add16(body, 0x11ec);        // group
    add16(body, 1216);          // key_len (overstated)
    body.insert(body.end(), 10, 0xAA);
    Bytes record = make_client_hello(join(
        make_extension(0x000a, make_groups_body({0x11ec, 0x001d})),
        make_extension(0x0033, body)));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_FALSE(ch.pqtls.key_share_parsed);
    EXPECT_EQ(pqtls_client_findings(ch.pqtls), PQTLS_MALFORMED_KEY_SHARE);
    EXPECT_NE(pqtls_client_check_text(ch.pqtls), "ok");
    EXPECT_EQ(pqtls_share_mode(ch.pqtls, false), PqtlsShareMode::UNKNOWN_SHARE);
}

// 1200 B X25519MLKEM768 key: not PROACTIVE_SHARE_VALID
TEST(PqtlsParserTest, Client1200ByteKeyIsNotValid) {
    Bytes record = make_client_hello(join(
        make_extension(0x000a, make_groups_body({0x11ec, 0x001d})),
        make_extension(0x0033, make_key_share_body({{0x11ec, 1200}, {0x001d, 32}}))));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_TRUE(ch.pqtls.key_share_parsed);
    EXPECT_EQ(pqtls_client_findings(ch.pqtls), PQTLS_MALFORMED_SHARE_LENGTH);
    EXPECT_EQ(pqtls_share_mode(ch.pqtls, false), PqtlsShareMode::UNKNOWN_SHARE);
}
