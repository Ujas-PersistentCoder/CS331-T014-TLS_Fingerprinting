#include <gtest/gtest.h>
#include "tlsfp/parser.hpp"
#include "tlsfp/accumulator.hpp"
#include "tlsfp/capture.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/ja4.hpp"
#include "fixtures/ech_fixtures.hpp"
#include <algorithm>

using namespace tlsfp;
using namespace ech_fixture;

namespace {
EchExtension decode(const Bytes &body) {
    return parse_ech_extension(ByteReader{body.data(), body.size()});
}
bool parse(const Bytes &record, ClientHelloData &out) {
    return parse_client_hello(record.data(), record.size(), out);
}
}

TEST(EchParserTest, OuterWireFields) {
    auto body = outer();
    ASSERT_EQ(body.size(), 250u);
    const auto result = decode(body);
    EXPECT_EQ(result.status, ParseStatus::Complete);
    EXPECT_EQ(result.variant, 0);
    EXPECT_EQ(result.kdf_id, 1);
    EXPECT_EQ(result.aead_id, 1);
    EXPECT_EQ(result.config_id, 139);
    EXPECT_EQ(result.enc_length, 32);
    EXPECT_EQ(result.payload_length, 208);
}

TEST(EchParserTest, UnknownAlgorithmIdsRemainNumeric) {
    const auto result = decode(outer(1, 1, 0x9234, 0x8123, 0));
    EXPECT_EQ(result.status, ParseStatus::Complete);
    EXPECT_EQ(result.kdf_id, 0x9234);
    EXPECT_EQ(result.aead_id, 0x8123);
    EXPECT_EQ(result.config_id, 0); // A real zero, distinct from an unavailable value.
}

TEST(EchParserTest, InnerMarkerHasNoOuterFields) {
    const auto result = decode({1});
    EXPECT_EQ(result.status, ParseStatus::Complete);
    EXPECT_EQ(result.variant, 1);
    EXPECT_FALSE(result.enc_length.has_value());
    EXPECT_FALSE(result.kdf_id.has_value());
}

TEST(EchParserTest, InnerMarkerRejectsTrailingData) {
    EXPECT_EQ(decode({1, 0}).status, ParseStatus::Malformed);
}

TEST(EchParserTest, EmptyAndInvalidVariant) {
    EXPECT_FALSE(decode({}).variant.has_value());
    EXPECT_EQ(decode({}).status, ParseStatus::Malformed);
    EXPECT_EQ(decode({2}).status, ParseStatus::Malformed);
}

TEST(EchParserTest, EmptyEncIsStructurallyValid) {
    const auto result = decode(outer(0, 1));
    EXPECT_EQ(result.status, ParseStatus::Complete);
    EXPECT_EQ(result.enc_length, 0);
}

TEST(EchParserTest, EmptyCiphertextIsMalformed) {
    EXPECT_EQ(decode(outer(32, 0)).status, ParseStatus::Malformed);
}

TEST(EchParserTest, EveryIncompleteBodyPrefixIsMalformedWhenFramingIsComplete) {
    const auto body = outer();
    for (size_t length = 0; length < body.size(); ++length) {
        SCOPED_TRACE(length);
        EXPECT_EQ(decode(Bytes(body.begin(), body.begin() + length)).status, ParseStatus::Malformed);
    }
}

TEST(EchParserTest, ContradictoryEncLength) {
    auto body = outer();
    body[6] = body[7] = 0xff;
    EXPECT_EQ(decode(body).status, ParseStatus::Malformed);
}

TEST(EchParserTest, TrailingCiphertextBytesAreRejected) {
    auto body = outer();
    body.push_back(0);
    EXPECT_EQ(decode(body).status, ParseStatus::Malformed);
}

TEST(EchHelloTest, CompleteEnvelopeAndOwnedRandom) {
    auto record = with_ech();
    ClientHelloData out;
    ASSERT_TRUE(parse(record, out));
    EXPECT_EQ(out.parse_status, ParseStatus::Complete);
    EXPECT_EQ(out.ech.present, true);
    ASSERT_TRUE(out.outer_random.has_value());
    std::fill(record.begin(), record.end(), 0xff);
    EXPECT_EQ((*out.outer_random)[0], 0);
    EXPECT_EQ((*out.outer_random)[31], 31);
    ASSERT_EQ(out.ech.occurrences.size(), 1u);
    EXPECT_EQ(out.ech.occurrences[0].payload_length, 208);
}

TEST(EchHelloTest, CertificateCompressionAloneIsNotEch) {
    Bytes extensions;
    extension(extensions, 0x001b, {2, 0, 2});
    ClientHelloData out;
    ASSERT_TRUE(parse(hello(extensions), out));
    EXPECT_EQ(out.ech.present, false);
    EXPECT_TRUE(out.ech.occurrences.empty());
}

TEST(EchHelloTest, LegacyHelloWithoutExtensionsEstablishesAbsence) {
    auto record = hello();
    record.resize(record.size() - 2);
    handshake_length(record);
    ClientHelloData out;
    ASSERT_TRUE(parse(record, out));
    EXPECT_EQ(out.ech.present, false);
}

TEST(EchHelloTest, CaptureTruncationIsIncompleteNotAbsent) {
    auto record = with_ech();
    record.pop_back();
    ClientHelloData out;
    EXPECT_FALSE(parse(record, out));
    EXPECT_EQ(out.parse_status, ParseStatus::Incomplete);
    EXPECT_FALSE(out.ech.present.has_value());
}

TEST(EchHelloTest, MissingHeaderIsIncomplete) {
    ClientHelloData out;
    EXPECT_FALSE(parse_client_hello(nullptr, 0, out));
    EXPECT_EQ(out.parse_status, ParseStatus::Incomplete);
}

TEST(EchHelloTest, CompleteRecordWithShortHelloBodyIsMalformed) {
    Bytes record{22, 3, 1, 0, 4, 1, 0, 0, 0};
    ClientHelloData out;
    EXPECT_FALSE(parse(record, out));
    EXPECT_EQ(out.parse_status, ParseStatus::Malformed);
}

TEST(EchHelloTest, PartialExtensionHeaderCannotEstablishAbsence) {
    ClientHelloData out;
    EXPECT_FALSE(parse(hello({0xfe, 0x0d, 0}), out));
    EXPECT_EQ(out.parse_status, ParseStatus::Malformed);
    EXPECT_FALSE(out.ech.present.has_value());
}

TEST(EchHelloTest, CompleteContradictoryExtensionLengthRetainsPresence) {
    ClientHelloData out;
    EXPECT_FALSE(parse(hello({0xfe, 0x0d, 0, 2, 1}), out));
    EXPECT_EQ(out.parse_status, ParseStatus::Malformed);
    EXPECT_EQ(out.ech.present, true);
    ASSERT_EQ(out.ech.occurrences.size(), 1u);
    EXPECT_EQ(out.ech.occurrences[0].status, ParseStatus::Malformed);
}

TEST(EchHelloTest, ExtensionVectorMustConsumeCompleteHello) {
    auto record = hello();
    record.push_back(0);
    handshake_length(record);
    ClientHelloData out;
    EXPECT_FALSE(parse(record, out));
    EXPECT_EQ(out.parse_status, ParseStatus::Malformed);
    EXPECT_FALSE(out.ech.present.has_value());
}

TEST(EchHelloTest, MalformedEchBodyDoesNotEraseCompleteOuterFields) {
    ClientHelloData out;
    ASSERT_TRUE(parse(with_ech(outer(32, 0)), out));
    EXPECT_EQ(out.parse_status, ParseStatus::Complete);
    ASSERT_EQ(out.ech.occurrences.size(), 1u);
    EXPECT_EQ(out.ech.occurrences[0].status, ParseStatus::Malformed);
    EXPECT_EQ(out.extensions, std::vector<uint16_t>{0xfe0d});
}

TEST(EchHelloTest, RecordSpanningHelloIsUnsupported) {
    auto record = with_ech();
    record.resize(record.size() - 10);
    record_length(record); // Keep original handshake length, split across records.
    ClientHelloData out;
    EXPECT_FALSE(parse(record, out));
    EXPECT_EQ(out.parse_status, ParseStatus::Unsupported);
    EXPECT_FALSE(out.ech.present.has_value());
}

TEST(EchHelloTest, PartialHandshakeHeaderIsUnsupported) {
    ClientHelloData out;
    EXPECT_FALSE(parse({22, 3, 1, 0, 1, 1}, out));
    EXPECT_EQ(out.parse_status, ParseStatus::Unsupported);
}

TEST(EchHelloTest, EightKiBBoundaryAndOversizeAreConsistent) {
    ClientHelloData out;
    ASSERT_TRUE(parse(hello(padding(8192 - hello().size())), out));
    EXPECT_FALSE(parse(hello(padding(8193 - hello().size())), out));
    EXPECT_EQ(out.parse_status, ParseStatus::Unsupported);
    EXPECT_FALSE(out.ech.present.has_value());
}

TEST(EchHelloTest, CallerMayHaveFollowingRecordsBeyondEightKiB) {
    auto record = with_ech();
    record.resize(9000, 0x17);
    ClientHelloData out;
    ASSERT_TRUE(parse(record, out));
    EXPECT_EQ(out.ech.present, true);
}

TEST(EchHelloTest, AccumulatorReportsSameLimitForFastSegmentedAndSplitHeaderPaths) {
    const auto record = hello(padding(8193 - hello().size()));
    for (size_t prefix : {record.size(), size_t{5}, size_t{2}}) {
        SCOPED_TRACE(prefix);
        int ready = 0, limited = 0;
        TwoTierAccumulator accumulator(
            [&](const FlowKey &, const uint8_t *, size_t) { ++ready; },
            [&](const FlowKey &) { ++limited; });
        FlowKey key;
        accumulator.process_segment(key, 100, record.data(), prefix, 1);
        if (prefix < record.size()) {
            accumulator.process_segment(key, static_cast<uint32_t>(100 + prefix),
                                        record.data() + prefix, record.size() - prefix, 1);
        }
        EXPECT_EQ(ready, 0);
        EXPECT_EQ(limited, 1);
        EXPECT_EQ(accumulator.active_flow_count(), 0u);
    }
}

TEST(EchHelloTest, AccumulatorDeliversSplitHandshakeHeaderForUnsupportedDiagnostic) {
    const Bytes record{22, 3, 1, 0, 1, 1};
    int callbacks = 0;
    TwoTierAccumulator accumulator([&](const FlowKey &, const uint8_t *bytes, size_t length) {
        ++callbacks;
        ClientHelloData out;
        EXPECT_FALSE(parse_client_hello(bytes, length, out));
        EXPECT_EQ(out.parse_status, ParseStatus::Unsupported);
    });
    FlowKey key;
    accumulator.process_segment(key, 100, record.data(), record.size(), 1);
    EXPECT_EQ(callbacks, 1);
}

TEST(EchHelloTest, SegmentationAndOverlappingRetransmissionPreserveObservation) {
    const auto record = with_ech();
    int callbacks = 0;
    ClientHelloData out;
    TwoTierAccumulator accumulator([&](const FlowKey &, const uint8_t *bytes, size_t length) {
        ++callbacks;
        EXPECT_TRUE(parse_client_hello(bytes, length, out));
    });
    FlowKey key;
    accumulator.process_segment(key, 100, record.data(), 100, 1);
    accumulator.process_segment(key, 150, record.data() + 50, 100, 1);
    accumulator.process_segment(key, 250, record.data() + 150, record.size() - 150, 1);
    ASSERT_EQ(callbacks, 1);
    ASSERT_EQ(out.ech.occurrences.size(), 1u);
    EXPECT_EQ(out.ech.occurrences[0].payload_length, 208);
}

TEST(EchHelloTest, ScratchpadReuseClearsObservationsAndRandom) {
    ClientHelloData out;
    ASSERT_TRUE(parse(with_ech(), out));
    EXPECT_FALSE(parse({}, out));
    EXPECT_FALSE(out.outer_random.has_value());
    EXPECT_FALSE(out.ech.present.has_value());
    EXPECT_TRUE(out.ech.occurrences.empty());
    EXPECT_EQ(out.ech.findings, 0u);
    ASSERT_TRUE(parse(hello(), out));
    EXPECT_EQ(out.ech.present, false);
}

TEST(EchHelloTest, EveryCapturePrefixIsIncompleteAndNeverAbsent) {
    const auto record = with_ech();
    ClientHelloData out;
    for (size_t length = 0; length < record.size(); ++length) {
        SCOPED_TRACE(length);
        EXPECT_FALSE(parse_client_hello(record.data(), length, out));
        EXPECT_EQ(out.parse_status, ParseStatus::Incomplete);
        EXPECT_FALSE(out.ech.present.has_value());
    }
}

TEST(EchReplayTest, SyntheticPcapHasFieldsFindingsAndFramingDiagnostics) {
    CaptureOptions options;
    options.read_filename = std::string(TLSFP_FIXTURES_DIR) + "/ech_checkpoint1.pcap";
    options.verbose = true;
    CaptureEngine engine(options);
    testing::internal::CaptureStdout();
    const bool success = engine.run();
    const auto output = testing::internal::GetCapturedStdout();
    ASSERT_TRUE(success);
    EXPECT_EQ(engine.stats().client_hellos, 6u);
    EXPECT_NE(output.find("config_id=139 enc_length=32 ciphertext_length=208"), std::string::npos);
    EXPECT_NE(output.find("presence=absent"), std::string::npos);
    EXPECT_NE(output.find("duplicate_ech"), std::string::npos);
    EXPECT_NE(output.find("export_only_aead"), std::string::npos);
    EXPECT_NE(output.find("external_inner_marker"), std::string::npos);
    EXPECT_NE(output.find("forbidden_outer_extensions"), std::string::npos);
    EXPECT_NE(output.find("empty_enc_context_unknown"), std::string::npos);
    EXPECT_NE(output.find("ciphertext must not be empty"), std::string::npos);
    EXPECT_NE(output.find("status=unsupported"), std::string::npos);
    EXPECT_NE(output.find("status=malformed"), std::string::npos);
    EXPECT_NE(output.find("fingerprints suppressed"), std::string::npos);
    EXPECT_EQ(output.find("accepted"), std::string::npos);
    // None of the three shared-framing failures may emit a partial fingerprint.
    const auto framing_error = output.find("[ClientHello diagnostic] 192.0.2.10:41004");
    ASSERT_NE(framing_error, std::string::npos);
    const auto next_client = output.find("CLIENT", framing_error);
    ASSERT_NE(next_client, std::string::npos);
    EXPECT_EQ(output.substr(framing_error, next_client - framing_error).find("JA3:"), std::string::npos);
}

TEST(EchReplayTest, QuietModeSuppressesVerboseEchAndDiagnostics) {
    CaptureOptions options;
    options.read_filename = std::string(TLSFP_FIXTURES_DIR) + "/ech_checkpoint1.pcap";
    options.verbose = true;
    options.quiet = true;
    CaptureEngine engine(options);
    testing::internal::CaptureStdout();
    const bool success = engine.run();
    const auto output = testing::internal::GetCapturedStdout();
    ASSERT_TRUE(success);
    EXPECT_EQ(engine.stats().client_hellos, 6u);
    EXPECT_EQ(output.find("[V-ECH"), std::string::npos);
    EXPECT_EQ(output.find("diagnostic"), std::string::npos);
}
