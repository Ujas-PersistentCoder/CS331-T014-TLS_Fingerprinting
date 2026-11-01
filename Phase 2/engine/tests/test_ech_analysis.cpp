#include <gtest/gtest.h>
#include "tlsfp/parser.hpp"
#include "tlsfp/ech_analysis.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/ja4.hpp"
#include "fixtures/ech_fixtures.hpp"

using namespace tlsfp;
using namespace ech_fixture;

TEST(EchAnalysisTest, FindingsCoexistAndDoNotOverwriteDecodedBodies) {
    Bytes extensions;
    extension(extensions, ECH_EXTENSION, outer(32, 1, 1, 0xffff));
    extension(extensions, ECH_EXTENSION, {1});
    extension(extensions, ECH_OUTER_EXTENSIONS, {0});
    auto record = hello(extensions);
    ClientHelloData out;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), out));
    EXPECT_EQ(out.ech.findings, DuplicateEch | ForbiddenOuterExtensions | ExternalInnerMarker | ExportOnlyAead);
    ASSERT_EQ(out.ech.occurrences.size(), 2u);
    EXPECT_EQ(out.ech.occurrences[0].status, ParseStatus::Complete);
    EXPECT_EQ(out.ech.occurrences[1].status, ParseStatus::Complete);
}

TEST(EchAnalysisTest, DuplicateValuesRemainSeparate) {
    Bytes extensions;
    extension(extensions, ECH_EXTENSION, outer(32, 1, 1, 1, 139));
    extension(extensions, ECH_EXTENSION, outer(32, 1, 1, 1, 7));
    const auto record = hello(extensions);
    ClientHelloData out;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), out));
    ASSERT_EQ(out.ech.occurrences.size(), 2u);
    EXPECT_EQ(out.ech.occurrences[0].config_id, 139);
    EXPECT_EQ(out.ech.occurrences[1].config_id, 7);
    EXPECT_TRUE(out.ech.findings & DuplicateEch);
}

TEST(EchAnalysisTest, ExtensionOrderChangesJa3ButNotFindingsOrSortedJa4) {
    Bytes a, b;
    extension(a, ECH_EXTENSION, {1});
    extension(a, ECH_OUTER_EXTENSIONS, {0});
    extension(b, ECH_OUTER_EXTENSIONS, {0});
    extension(b, ECH_EXTENSION, {1});
    ClientHelloData first, second;
    const auto ra = hello(a), rb = hello(b);
    ASSERT_TRUE(parse_client_hello(ra.data(), ra.size(), first));
    ASSERT_TRUE(parse_client_hello(rb.data(), rb.size(), second));
    EXPECT_EQ(first.ech.findings, second.ech.findings);
    EXPECT_NE(compute_ja3(first).md5_hash, compute_ja3(second).md5_hash);
    EXPECT_EQ(compute_ja4(first).full_fp, compute_ja4(second).full_fp);
}

TEST(EchAnalysisTest, EmptyEncDependsOnKnownRole) {
    EchObservation observation;
    const auto body = outer(0, 1);
    observation.occurrences.push_back(parse_ech_extension(ByteReader{body.data(), body.size()}));
    analyze_ech(observation);
    EXPECT_EQ(observation.findings, EmptyEncContextUnknown);
    analyze_ech(observation, HelloRole::Initial);
    EXPECT_EQ(observation.findings, EmptyEncInInitialHello);
    analyze_ech(observation, HelloRole::AfterHrr);
    EXPECT_EQ(observation.findings, 0u); // No acceptance inference from one hello.
}

TEST(EchAnalysisTest, FramingFailureDoesNotDiscardEarlierFindings) {
    Bytes extensions;
    extension(extensions, ECH_OUTER_EXTENSIONS, {0});
    extension(extensions, ECH_EXTENSION, {1});
    extensions.push_back(0xff); // Incomplete next extension header in a complete hello.
    const auto record = hello(extensions);
    ClientHelloData out;
    EXPECT_FALSE(parse_client_hello(record.data(), record.size(), out));
    EXPECT_EQ(out.ech.present, true);
    EXPECT_EQ(out.ech.findings, ForbiddenOuterExtensions | ExternalInnerMarker);
    EXPECT_EQ(out.ech.occurrences[0].status, ParseStatus::Complete);
}

TEST(EchAnalysisTest, ScratchpadResetClearsAllFindings) {
    const auto record = with_ech({1});
    ClientHelloData out;
    ASSERT_TRUE(parse_client_hello(record.data(), record.size(), out));
    EXPECT_EQ(out.ech.findings, ExternalInnerMarker);
    out.clear();
    EXPECT_EQ(out.ech.findings, 0u);
    EXPECT_FALSE(out.ech.present.has_value());
    EXPECT_EQ(out.parse_status, ParseStatus::NotExamined);
}
