#include <gtest/gtest.h>
#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include "fixtures/ech_fixtures.hpp"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/resource.h>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iterator>

using namespace tlsfp;
using namespace ech_fixture;
namespace {
FlowKey flow(uint16_t port = 41000) {
    FlowKey key;
    inet_pton(AF_INET, "192.0.2.10", &key.src_ip.v4);
    inet_pton(AF_INET, "198.51.100.20", &key.dst_ip.v4);
    key.src_port = htons(port); key.dst_port = htons(443);
    return key;
}
FlowKey reverse(FlowKey key) {
    std::swap(key.src_ip, key.dst_ip); std::swap(key.src_port, key.dst_port); return key;
}
std::string unused_path() {
    std::string path = (std::filesystem::temp_directory_path() / "tlsfp-cp2-XXXXXX").string();
    int fd = mkstemp(path.data());
    if (fd < 0) throw std::runtime_error("cannot reserve temporary filename");
    close(fd); unlink(path.c_str()); return path;
}
std::vector<std::string> read_rows(const std::string &path) {
    std::ifstream input(path); std::vector<std::string> rows; std::string line;
    while (std::getline(input, line)) rows.push_back(line);
    return rows;
}
class ConnectionTest : public ::testing::Test {
protected:
    std::string path;
    double now{0};
    std::unique_ptr<CaptureEngine> engine;
    void SetUp() override { path = unused_path(); create(); }
    void TearDown() override { engine.reset(); unlink(path.c_str()); }
    void create(size_t capacity = 1024) {
        engine.reset(); unlink(path.c_str());
        CaptureOptions options; options.json_filename = path; options.quiet = true;
        options.max_connections = capacity; options.monotonic_clock = [this] { return now; };
        engine = std::make_unique<CaptureEngine>(options);
    }
    void send(const Bytes &bytes, bool server_direction = false, uint32_t seq = 100,
              uint8_t flags = TH_ACK, FlowKey key = flow(), bool truncated = false) {
        if (server_direction) key = reverse(key);
        engine->ingest_tcp_segment(key, seq, flags, bytes.data(), bytes.size(),
                                   static_cast<uint64_t>((now + 1) * 1000000), truncated);
    }
    void start(FlowKey key = flow()) {
        send({}, false, 99, TH_SYN, key); send({}, true, 999, TH_SYN | TH_ACK, key);
    }
    std::vector<std::string> rows() { return read_rows(path); }
};
}

TEST_F(ConnectionTest, Tls13PairsBothDirectionsAndFlushesImmediately) {
    start(); send(client()); send(server(), true, 1000);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"negotiated_version\":772"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"acceptance\":\"unverified\""), std::string::npos);
    EXPECT_NE(rows()[0].find("\"client_endpoint\":\"a\""), std::string::npos);
    EXPECT_TRUE(engine->finish_capture()); EXPECT_EQ(rows().size(), 1u);
}
TEST_F(ConnectionTest, Tls12NonAcceptanceHasI3EvidenceAndUnknownOfferType) {
    start(); send(client()); send(server(0x0303), true, 1000);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("I3_negotiated_below_tls13"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"acceptance\":\"non_acceptance_observed\""), std::string::npos);
    EXPECT_NE(rows()[0].find("\"offer_type\":\"unknown\""), std::string::npos);
}
TEST_F(ConnectionTest, CompleteAbsenceIsFalseRatherThanNull) {
    send(client(false)); send(server(), true, 1000);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"presence\":false"), std::string::npos);
}
TEST_F(ConnectionTest, ServerOnlyHasUnknownClientAndNoI3) {
    send(server(0x0303), true, 1000);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"presence\":null"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"complete_hello_pair\":false"), std::string::npos);
    EXPECT_EQ(rows()[0].find("I3_"), std::string::npos);
}
TEST_F(ConnectionTest, RetransmittedHellosAndSynDoNotDuplicateOrReset) {
    start(); const auto ch = client(); send(ch); send({}, false, 99, TH_SYN); send(ch);
    send(server(), true, 1000); send(ch); send(server(), true, 1000);
    EXPECT_TRUE(engine->finish_capture()); EXPECT_EQ(rows().size(), 1u);
    EXPECT_EQ(engine->stats().client_hellos, 1u); EXPECT_EQ(engine->stats().server_hellos, 1u);
}
TEST_F(ConnectionTest, SynWithPayloadConsumesOneSequenceNumber) {
    send(client(), false, 99, TH_SYN); send(server(), true, 1000);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
}
TEST_F(ConnectionTest, NewSynSeparatesConnectionGenerations) {
    start(); send(client()); send({}, false, 499, TH_SYN);
    send(client(), false, 500); send(server(), true, 2000);
    ASSERT_EQ(rows().size(), 2u);
    EXPECT_NE(rows()[0].find("connection_replaced"), std::string::npos);
    EXPECT_NE(rows()[1].find("\"complete_hello_pair\":true"), std::string::npos);
}
TEST_F(ConnectionTest, SynAfterClosureStartsFreshEvenWithSameInitialSequence) {
    start(); send(client()); send({}, false, 400, TH_RST);
    start(); send(client()); send(server(), true, 1000);
    EXPECT_EQ(rows().size(), 2u);
}
TEST_F(ConnectionTest, FinWithPayloadIsProcessedBeforeFinalization) {
    start(); send(client(), false, 100, TH_FIN | TH_ACK);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"completion_reason\":\"fin\""), std::string::npos);
    EXPECT_NE(rows()[0].find("\"presence\":true"), std::string::npos);
}
TEST_F(ConnectionTest, ResetWithServerPayloadStillEmitsFinalHelloOnce) {
    send(client()); send(server(), true, 1000, TH_RST | TH_ACK);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("final_server_hello"), std::string::npos);
    engine->finish_capture(); EXPECT_EQ(rows().size(), 1u);
}
TEST_F(ConnectionTest, PureTcpSynAndFinDoNotProduceTlsSummary) {
    start(); send({}, false, 100, TH_FIN); engine->finish_capture(); EXPECT_TRUE(rows().empty());
}
TEST_F(ConnectionTest, CapacityIncludesSynHintsAndEmittedMarkers) {
    create(1); send(client()); send({}, false, 100, TH_SYN, flow(41001));
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("capacity_limit"), std::string::npos);
    EXPECT_EQ(engine->retained_connection_count(), 1u);
    send(client(), false, 101, TH_ACK, flow(41001)); send(server(), true, 1000, TH_ACK, flow(41001));
    EXPECT_EQ(engine->retained_connection_count(), 1u);
    send({}, false, 100, TH_SYN, flow(41002));
    EXPECT_EQ(rows().size(), 2u); EXPECT_EQ(engine->retained_connection_count(), 1u);
}
TEST_F(ConnectionTest, IdleTimeoutRunsWithoutAnotherPacket) {
    send(client()); now = 31; engine->maintenance();
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"completion_reason\":\"timeout\""), std::string::npos);
    EXPECT_EQ(engine->retained_connection_count(), 0u);
}
TEST_F(ConnectionTest, PartialRecordTimeoutKeepsUnknownPresence) {
    auto ch = client(); ch.resize(40); send(ch); now = 4; engine->maintenance();
    EXPECT_TRUE(rows().empty()); EXPECT_TRUE(engine->finish_capture());
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("record_timeout"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"presence\":null"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"ja3\":null"), std::string::npos);
}
TEST_F(ConnectionTest, ActiveGapStopsParsingWithoutGuessingAnotherBoundary) {
    auto ch = client(); send(Bytes(ch.begin(), ch.begin()+30));
    send(ch, false, 200); send(ch, false, 130); engine->finish_capture();
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("tcp_gap"), std::string::npos);
    EXPECT_EQ(engine->stats().client_hellos, 0u);
}
TEST_F(ConnectionTest, SynAlignedHelloCanArriveAfterDetachedServerSegment) {
    start(); send(client()); send({0xa4,0xb5,0xc6}, true, 4000); send(server(), true, 1000);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("pre_tls_sequence_gap"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
}
TEST_F(ConnectionTest, CaptureTruncationStopsDirectionEvenIfPrefixLooksLikeHello) {
    send(client(), false, 100, TH_ACK, flow(), true); send(client(), false, 100);
    engine->finish_capture(); ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("capture_truncated"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"presence\":null"), std::string::npos);
    EXPECT_EQ(engine->stats().client_hellos, 0u);
}
TEST_F(ConnectionTest, HrrWaitsForFinalServerAndKeepsOriginalClient) {
    start(); auto ch = client(); send(ch); const auto retry = server(0x0304, true); send(retry, true, 1000);
    EXPECT_TRUE(rows().empty());
    auto second = client(false); send(second, false, 100 + static_cast<uint32_t>(ch.size()));
    send(server(), true, 1000 + static_cast<uint32_t>(retry.size()));
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"hrr_seen\":true"), std::string::npos);
    EXPECT_NE(rows()[0].find("hrr_sequence_not_analyzed"), std::string::npos);
    EXPECT_NE(rows()[0].find("\"presence\":true"), std::string::npos);
    EXPECT_EQ(engine->stats().server_hellos, 1u);
}
TEST_F(ConnectionTest, CompatibilityCcsAndCoalescedServerRecordsAreWalked) {
    start(); send(client()); Bytes bytes{20,3,3,0,1,1}; const auto sh = server();
    bytes.insert(bytes.end(), sh.begin(), sh.end()); send(bytes, true, 1000);
    ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("\"complete_hello_pair\":true"), std::string::npos);
}
TEST_F(ConnectionTest, MultipleHandshakeMessagesWithinRecordAreWalked) {
    send(client()); auto sh = server();
    sh.insert(sh.begin()+5, {0,0,0,0}); record_length(sh); send(sh, true, 1000);
    ASSERT_EQ(rows().size(), 1u); EXPECT_EQ(engine->stats().server_hellos, 1u);
}
TEST_F(ConnectionTest, EncryptedRecordPayloadIsNotParsedAsHello) {
    send(client()); auto sh = server(); sh[0] = 23; send(sh, true, 1000);
    engine->finish_capture(); ASSERT_EQ(rows().size(), 1u);
    EXPECT_NE(rows()[0].find("encrypted_record_before_final_hello"), std::string::npos);
    EXPECT_EQ(engine->stats().server_hellos, 0u);
}
TEST_F(ConnectionTest, UnknownCcsContextDoesNotExposeEncryptedHandshakeAsHello) {
    send(with_ech()); Bytes bytes{20,3,3,0,1,1}; const auto sh = server(0x0303);
    bytes.insert(bytes.end(),sh.begin(),sh.end()); send(bytes,true,1000); engine->finish_capture();
    ASSERT_EQ(rows().size(),1u); EXPECT_EQ(engine->stats().server_hellos,0u);
    EXPECT_NE(rows()[0].find("ccs_plaintext_context_unknown"),std::string::npos);
}
TEST_F(ConnectionTest, JsonEscapesPacketStringsAndOwnsTheirBytes) {
    const Bytes name{'a','"','\\','\n',0xff}; Bytes sni; u16(sni,name.size()+3); sni.push_back(0); u16(sni,name.size());
    sni.insert(sni.end(),name.begin(),name.end()); Bytes extra; extension(extra,0,sni);
    auto ch=client(true,extra); send(ch); std::fill(ch.begin(),ch.end(),0); send(server(),true,1000);
    ASSERT_EQ(rows().size(),1u);
    EXPECT_NE(rows()[0].find("a\\\"\\\\\\u000a\\u00ff"),std::string::npos);
}
TEST_F(ConnectionTest, IncompleteCaptureFlushesExactlyOnceOnInterruption) {
    auto ch=client(); ch.resize(30); send(ch); EXPECT_TRUE(engine->finish_capture("interrupted"));
    EXPECT_TRUE(engine->finish_capture("interrupted")); ASSERT_EQ(rows().size(),1u);
    EXPECT_NE(rows()[0].find("\"completion_reason\":\"interrupted\""),std::string::npos);
    EXPECT_NE(rows()[0].find("\"presence\":null"),std::string::npos);
}
TEST_F(ConnectionTest, EndpointOrientationDoesNotDependOnPortOrAddressOrder) {
    auto key=flow(); std::swap(key.src_ip,key.dst_ip); key.src_port=htons(443); key.dst_port=htons(32000);
    send(client(),false,100,TH_ACK,key); send(server(),true,1000,TH_ACK,key);
    ASSERT_EQ(rows().size(),1u);
    EXPECT_NE(rows()[0].find("\"client_endpoint\":\"b\""),std::string::npos);
}
TEST_F(ConnectionTest, Ipv6CorrelatesReversedEndpoints) {
    auto key=flow(); key.ip_version=6;
    inet_pton(AF_INET6,"2001:db8::1",&key.src_ip.v6); inet_pton(AF_INET6,"2001:db8::2",&key.dst_ip.v6);
    send(client(),false,100,TH_ACK,key); send(server(),true,1000,TH_ACK,key);
    ASSERT_EQ(rows().size(),1u); EXPECT_NE(rows()[0].find("\"ip_version\":6"),std::string::npos);
}
TEST_F(ConnectionTest, ExistingOutputFileIsNotOverwritten) {
    { std::ofstream out(path); out << "preserve\n"; }
    CaptureOptions options; options.quiet=true; options.json_filename=path;
    CaptureEngine other(options); EXPECT_FALSE(other.run());
    ASSERT_EQ(rows().size(),1u); EXPECT_EQ(rows()[0],"preserve");
}
TEST_F(ConnectionTest, OutputWriteFailureMakesCaptureFail) {
    // RLIMIT_FSIZE also limits GoogleTest's stderr capture file. The child exit
    // status verifies the failed write without depending on truncated diagnostics.
    ASSERT_EXIT({
        std::signal(SIGXFSZ,SIG_IGN); struct rlimit limit{}; getrlimit(RLIMIT_FSIZE,&limit);
        limit.rlim_cur=1; if (setrlimit(RLIMIT_FSIZE,&limit)) _exit(2);
        send(client()); send(server(),true,1000); _exit(engine->finish_capture()?1:0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(ServerObservationTest, SupportedVersionsMustHaveExactLengthAndNoDuplicate) {
    Bytes bad; extension(bad,43,{3}); auto record=server(0x0303,false,bad); ServerHelloData out;
    EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out)); EXPECT_EQ(out.parse_status,ParseStatus::Malformed);
    bad.clear(); extension(bad,43,{3,4}); record=server(0x0304,false,bad);
    EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out)); EXPECT_EQ(out.parse_status,ParseStatus::Malformed);
}
TEST(ServerObservationTest, TruncationCrossRecordAndContradictoryCompleteFramingDiffer) {
    auto record=server(); ServerHelloData out; record.pop_back();
    EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out)); EXPECT_EQ(out.parse_status,ParseStatus::Incomplete);
    record_length(record); EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out));
    EXPECT_EQ(out.parse_status,ParseStatus::Unsupported);
    handshake_length(record); EXPECT_FALSE(parse_server_hello(record.data(),record.size(),out));
    EXPECT_EQ(out.parse_status,ParseStatus::Malformed);
}
TEST(ServerObservationTest, UnknownVersionRemainsNumericAndHrrResetsWithScratchpad) {
    auto record=server(0x9999,true); ServerHelloData out;
    ASSERT_TRUE(parse_server_hello(record.data(),record.size(),out)); EXPECT_TRUE(out.is_hrr); EXPECT_EQ(out.selected_version,0x9999);
    record=server(0x0303); ASSERT_TRUE(parse_server_hello(record.data(),record.size(),out));
    EXPECT_FALSE(out.is_hrr); EXPECT_EQ(out.selected_version,0x0303);
}

TEST(RecordStreamTest, CoalescedRecordsAndPartialTailSurviveAllHeaderSplits) {
    auto first=client(), second=server(); Bytes combined=first; combined.insert(combined.end(),second.begin(),second.end());
    for (size_t split=1;split<first.size()+5;++split) {
        SCOPED_TRACE(split); std::vector<Bytes> records;
        TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t *p,size_t n){ records.emplace_back(p,p+n); });
        auto key=flow(); accumulator.process_segment(key,100,combined.data(),split,0);
        accumulator.process_segment(key,100+static_cast<uint32_t>(split),combined.data()+split,combined.size()-split,0);
        ASSERT_EQ(records.size(),2u); EXPECT_EQ(records[0],first); EXPECT_EQ(records[1],second);
        EXPECT_EQ(accumulator.active_flow_count(),0u);
    }
}
TEST(RecordStreamTest, SequenceWraparoundAndCompletedRetransmissions) {
    const auto record=client(); int count=0;
    TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t*,size_t){++count;}); auto key=flow();
    accumulator.process_segment(key,0xfffffff0,record.data(),30,0);
    accumulator.process_segment(key,14,record.data()+30,record.size()-30,0);
    accumulator.process_segment(key,0xfffffff0,record.data(),record.size(),0); EXPECT_EQ(count,1);
}
TEST(RecordStreamTest, InvalidHeaderAndStreamCapacityHaveExplicitOutcomes) {
    std::vector<ParseStatus> issues;
    TwoTierAccumulator accumulator([](const FlowKey&,const uint8_t*,size_t){}, {},
        [&](const FlowKey&,ParseStatus status,const char*,const uint8_t*,size_t){issues.push_back(status);},1);
    const Bytes invalid{22,4,0,0,0}; accumulator.process_segment(flow(),1,invalid.data(),invalid.size(),0);
    const auto record=client(); accumulator.process_segment(flow(41001),1,record.data(),record.size(),0);
    ASSERT_EQ(issues.size(),2u); EXPECT_EQ(issues[0],ParseStatus::Malformed); EXPECT_EQ(issues[1],ParseStatus::Unsupported);
}

TEST_F(ConnectionTest, InvalidCompatibilityCcsDoesNotHideItsFramingError) {
    send(client()); send({20,3,3,0,1,2},true,1000); engine->finish_capture();
    ASSERT_EQ(rows().size(),1u); EXPECT_NE(rows()[0].find("invalid_change_cipher_spec"),std::string::npos);
}
TEST_F(ConnectionTest, MalformedServerVersionNeverSuppliesI3Evidence) {
    send(client()); Bytes extra; extension(extra,43,{3}); send(server(0x0303,false,extra),true,1000);
    engine->finish_capture(); ASSERT_EQ(rows().size(),1u);
    EXPECT_NE(rows()[0].find("\"negotiated_version\":null"),std::string::npos);
    EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
}
TEST_F(ConnectionTest, UnknownNegotiatedVersionAbstains) {
    send(client()); send(server(0x9999),true,1000);
    ASSERT_EQ(rows().size(),1u); EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
    EXPECT_NE(rows()[0].find("\"negotiated_version\":39321"),std::string::npos);
}
TEST_F(ConnectionTest, MissingOutputDirectoryFailsBeforeCapture) {
    CaptureOptions options; options.quiet=true; options.json_filename=path+"/missing/result.jsonl";
    CaptureEngine other(options); EXPECT_FALSE(other.run());
}
TEST(RecordStreamTest, CompletedPrefixOverlapCanDeliverNextRecordWithoutRepeatingFirst) {
    const auto first=client(), second=server(); int count=0;
    TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t*,size_t){++count;});
    accumulator.process_segment(flow(),100,first.data(),first.size(),0);
    Bytes overlap(first.end()-10,first.end()); overlap.insert(overlap.end(),second.begin(),second.end());
    accumulator.process_segment(flow(),static_cast<uint32_t>(100+first.size()-10),overlap.data(),overlap.size(),0);
    EXPECT_EQ(count,2);
}
TEST(RecordStreamTest, MissingSynAlignedStartTimesOutWithoutResynchronizing) {
    int records=0; std::vector<std::string> issues;
    TwoTierAccumulator accumulator([&](const FlowKey&,const uint8_t*,size_t){++records;},{},
        [&](const FlowKey&,ParseStatus,const char *reason,const uint8_t*,size_t){issues.emplace_back(reason);});
    accumulator.start_flow(flow(),100,0); const auto record=client();
    accumulator.process_segment(flow(),200,record.data(),record.size(),0);
    accumulator.cleanup_stale_flows(4); accumulator.process_segment(flow(),100,record.data(),record.size(),4);
    EXPECT_EQ(records,0); ASSERT_EQ(issues.size(),2u); EXPECT_EQ(issues.back(),"initial_data_timeout");
}
TEST(ConnectionReplayTest, SyntheticPcapProducesElevenIndependentSummaries) {
    const auto path=unused_path(); CaptureOptions options; options.quiet=true; options.json_filename=path;
    options.read_filename=std::string(TLSFP_FIXTURES_DIR)+"/ech_checkpoint2.pcap";
    CaptureEngine engine(options); EXPECT_TRUE(engine.run()); const auto rows=read_rows(path); unlink(path.c_str());
    ASSERT_EQ(rows.size(),11u);
    EXPECT_EQ(std::count_if(rows.begin(),rows.end(),[](const auto &row){return row.find("I3_negotiated_below_tls13")!=std::string::npos;}),1);
    EXPECT_EQ(std::count_if(rows.begin(),rows.end(),[](const auto &row){return row.find("\"complete_hello_pair\":true")!=std::string::npos;}),7);
}
TEST(ConnectionReplayTest, PcapReadErrorFlushesPendingObservationsAndFails) {
    const auto input_path=unused_path(), output_path=unused_path();
    {
        std::ifstream input(std::string(TLSFP_FIXTURES_DIR)+"/ech_checkpoint1.pcap",std::ios::binary);
        std::ofstream output(input_path,std::ios::binary); output << input.rdbuf();
        const uint32_t header[4]{1700000001,0,100,100};
        output.write(reinterpret_cast<const char*>(header),sizeof(header)); output.put('x');
    }
    CaptureOptions options; options.quiet=true; options.read_filename=input_path; options.json_filename=output_path;
    CaptureEngine engine(options); EXPECT_FALSE(engine.run()); const auto rows=read_rows(output_path);
    unlink(input_path.c_str()); unlink(output_path.c_str()); ASSERT_FALSE(rows.empty());
    for (const auto &row:rows) EXPECT_NE(row.find("\"completion_reason\":\"capture_error\""),std::string::npos);
}
TEST_F(ConnectionTest, ConflictingRolesRemainUnknownAndSuppressI3) {
    start(); send(client(),true,1000); send(server(0x0303),false,100);
    ASSERT_EQ(rows().size(),1u); EXPECT_NE(rows()[0].find("\"client_endpoint\":null"),std::string::npos);
    EXPECT_NE(rows()[0].find("conflicting_endpoint_roles"),std::string::npos);
    EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
}
TEST_F(ConnectionTest, UnexpectedSecondClientWithoutHrrSuppressesI3) {
    const auto first=client(); send(first); send(client(false),false,100+static_cast<uint32_t>(first.size()));
    send(server(0x0303),true,1000); ASSERT_EQ(rows().size(),1u);
    EXPECT_NE(rows()[0].find("unexpected_additional_client_hello"),std::string::npos);
    EXPECT_EQ(rows()[0].find("I3_"),std::string::npos);
}
TEST_F(ConnectionTest, ValidUtf8SurvivesJsonSerialization) {
    const Bytes name{'t',0xc3,0xa9,'s','t'}; Bytes sni; u16(sni,name.size()+3); sni.push_back(0); u16(sni,name.size());
    sni.insert(sni.end(),name.begin(),name.end()); Bytes extra; extension(extra,0,sni);
    send(client(true,extra)); send(server(),true,1000); ASSERT_EQ(rows().size(),1u);
    EXPECT_NE(rows()[0].find(std::string(name.begin(),name.end())),std::string::npos);
}
TEST_F(ConnectionTest, Tls13OfferAloneDoesNotMakeUnknownCcsPlaintext) {
    send(client()); Bytes bytes{20,3,3,0,1,1}; const auto encoded=server(0x0303);
    bytes.insert(bytes.end(),encoded.begin(),encoded.end()); send(bytes,true,1000); engine->finish_capture();
    ASSERT_EQ(rows().size(),1u); EXPECT_EQ(engine->stats().server_hellos,0u);
    EXPECT_NE(rows()[0].find("ccs_plaintext_context_unknown"),std::string::npos);
}
