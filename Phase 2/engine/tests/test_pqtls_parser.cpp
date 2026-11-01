// Tests for pqtls_parser.cpp (the OBSERVE part of PQ-TLS).
//
// How it works: we build small fake hellos byte by byte (helpers in
// fixtures/pqtls_fixtures.hpp), give them to the real parser
// (parse_client_hello / parse_server_hello), and check what it found.
// No pcap file is needed.

#include <gtest/gtest.h>

#include "tlsfp/parser.hpp"
#include "tlsfp/pqtls_parser.hpp"
#include "fixtures/pqtls_fixtures.hpp"

using namespace tlsfp;
using namespace pqtls_fixture;

// ---------- ClientHello: supported_groups and key_share ----------

// Like modern Chrome: GREASE first, then X25519MLKEM768, then x25519.
TEST(PqtlsParserTest, ChromeLikeHybridHello) {
    Bytes groups = make_extension(0x000a, make_groups_body({0x2a2a, 0x11ec, 0x001d, 0x0017}));
    Bytes shares = make_extension(0x0033, make_key_share_body({{0x2a2a, 1}, {0x11ec, 1216}, {0x001d, 32}}));
    Bytes record = make_client_hello(join(groups, shares));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_EQ(ch.pqtls.pq_group, 0x11ec);
    EXPECT_TRUE(ch.pqtls.pq_first_choice);   // GREASE does not count as first

    EXPECT_TRUE(ch.pqtls.has_key_share);
    EXPECT_TRUE(ch.pqtls.key_share_parsed);
    ASSERT_EQ(ch.pqtls.key_share_groups.size(), 2u);   // GREASE entry left out
    EXPECT_EQ(ch.pqtls.key_share_groups[0], 0x11ec);
    EXPECT_EQ(ch.pqtls.key_share_lens[0], 1216);
    EXPECT_EQ(ch.pqtls.key_share_groups[1], 0x001d);
    EXPECT_EQ(ch.pqtls.key_share_lens[1], 32);
}

// Like curl or Python: only classical groups.
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

// PQ group is in the list, but not first, and no PQ key was sent.
TEST(PqtlsParserTest, PQListedButNotFirstAndNoPQKey) {
    Bytes groups = make_extension(0x000a, make_groups_body({0x001d, 0x11ec}));
    Bytes shares = make_extension(0x0033, make_key_share_body({{0x001d, 32}}));
    Bytes record = make_client_hello(join(groups, shares));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_EQ(ch.pqtls.pq_group, 0x11ec);
    EXPECT_FALSE(ch.pqtls.pq_first_choice);
    ASSERT_EQ(ch.pqtls.key_share_groups.size(), 1u);
    EXPECT_EQ(ch.pqtls.key_share_groups[0], 0x001d);   // only the classical key was sent
}

// The key length says 1216 but only 10 key bytes are really there.
TEST(PqtlsParserTest, KeyShareWithWrongLengthIsNotTrusted) {
    Bytes body;
    add16(body, 4 + 10);        // list length
    add16(body, 0x11ec);        // group
    add16(body, 1216);          // key length (a lie)
    body.insert(body.end(), 10, 0xAA);
    Bytes record = make_client_hello(make_extension(0x0033, body));

    ClientHelloData ch;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), ch));

    EXPECT_TRUE(ch.pqtls.has_key_share);
    EXPECT_FALSE(ch.pqtls.key_share_parsed);
}

// Values from one hello must not stay behind for the next hello.
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

// find_pqtls_group() on its own, without a whole hello.
TEST(PqtlsParserTest, FindGroupDirectly) {
    PqtlsClientObservation obs;
    find_pqtls_group({0x001d, 0x0017, 0x6399}, obs);
    EXPECT_EQ(obs.pq_group, 0x6399);        // older Kyber draft group still counts
    EXPECT_FALSE(obs.pq_first_choice);

    PqtlsClientObservation none;
    find_pqtls_group({0x001d, 0x0017}, none);
    EXPECT_EQ(none.pq_group, 0);
}

// ---------- ServerHello: key_share ----------

// The server picks X25519MLKEM768 and sends its 1120 byte share.
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
}

// A TLS 1.2 style ServerHello has no key_share at all.
TEST(PqtlsParserTest, ServerWithoutKeyShare) {
    Bytes record = make_server_hello(make_extension(0xff01, Bytes{0}));  // renegotiation_info

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));

    EXPECT_EQ(sh.pqtls.selected_group, 0);
    EXPECT_EQ(sh.pqtls.server_share_len, 0);
}

// ---------- HelloRetryRequest ----------

// An HRR: special random, and key_share holds only the group the server wants (no key).
TEST(PqtlsParserTest, HelloRetryRequestIsRecognised) {
    Bytes body;
    add16(body, 0x0017);   // server asks for secp256r1
    Bytes record = make_server_hello(make_extension(0x0033, body), true);

    ServerHelloData sh;
    ASSERT_TRUE(parse_server_hello(record.data(), record.size(), sh));

    EXPECT_TRUE(sh.pqtls.is_hrr);
    EXPECT_EQ(sh.pqtls.selected_group, 0x0017);
    EXPECT_EQ(sh.pqtls.server_share_len, 0);
}

// is_hrr_random() on its own: the right value and a nearly-right value.
TEST(PqtlsParserTest, HrrRandomCheck) {
    EXPECT_TRUE(is_hrr_random(HRR_RANDOM.data()));

    Bytes almost = HRR_RANDOM;
    almost[31] = 0x00;   // change only the last byte
    EXPECT_FALSE(is_hrr_random(almost.data()));
}
