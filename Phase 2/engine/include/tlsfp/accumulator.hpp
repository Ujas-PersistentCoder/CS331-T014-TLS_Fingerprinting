#ifndef TLSFP_ACCUMULATOR_HPP
#define TLSFP_ACCUMULATOR_HPP

#include "tlsfp/types.hpp"
#include "tlsfp/ech_parser.hpp"
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>
#include <ctime>

namespace tlsfp {

// Only unfinished records allocate storage. Completed streams retain a sequence
// watermark so retransmission after record delivery cannot produce another hello.
struct FragmentedHandshake {
    std::vector<uint8_t> bytes;
    size_t expected{0};
    time_t last_seen{0};
};

class TwoTierAccumulator {
public:
    // Callback bytes are borrowed only for the call (packet storage on the fast
    // path, accumulation storage otherwise). Connection summaries must copy them.
    using HandshakeCallback = std::function<void(const FlowKey &, const uint8_t *, size_t)>;
    using RecordLimitCallback = std::function<void(const FlowKey &)>;
    using IssueCallback = std::function<void(const FlowKey &, ParseStatus, const char *,
                                             const uint8_t *, size_t)>;

    explicit TwoTierAccumulator(HandshakeCallback ready, RecordLimitCallback limit = {},
                                IssueCallback issue = {}, size_t max_streams = 2048,
                                bool enable_ech = true)
        : ready_(std::move(ready)), limit_(std::move(limit)), issue_(std::move(issue)),
          max_streams_(max_streams), enable_ech_(enable_ech) {}

    void set_ech_mode(bool enable) noexcept { enable_ech_ = enable; }
    [[nodiscard]] bool ech_mode() const noexcept { return enable_ech_; }

    void process_segment(const FlowKey &, uint32_t seq, const uint8_t *, size_t, time_t);
    void start_flow(const FlowKey &, uint32_t first_data_seq, time_t);
    void stop_flow(const FlowKey &); // Call outside a record callback; frees any partial buffer.
    void forget_flow(const FlowKey &);
    void invalidate_flow(const FlowKey &, const char *reason, bool only_pending = false);
    void cleanup_stale_flows(time_t);
    void flush_pending(const char *reason);
    [[nodiscard]] size_t active_flow_count() const noexcept;

private:
    struct Stream {
        uint32_t next_seq{0};
        bool stopped{false};
        bool tls_started{false};
        bool syn_anchored{false};
        std::optional<time_t> waiting_since;
        time_t last_seen{0};
        std::unique_ptr<FragmentedHandshake> partial;
    };
    void report(const FlowKey &, Stream &, ParseStatus, const char *);
    HandshakeCallback ready_;
    RecordLimitCallback limit_;
    IssueCallback issue_;
    size_t max_streams_;
    bool enable_ech_{true};
    std::unordered_map<FlowKey, Stream, FlowHash> streams_;
};
} // namespace tlsfp
#endif
