#ifndef TLSFP_ACCUMULATOR_HPP
#define TLSFP_ACCUMULATOR_HPP

#include "tlsfp/types.hpp"
#include <array>
#include <unordered_map>
#include <functional>
#include <cstdint>
#include <cstddef>
#include <ctime>

namespace tlsfp {

/**
 * @brief Represents an in-flight fragmented TLS handshake segment accumulation.
 */
struct FragmentedHandshake {
    std::array<uint8_t, ACCUMULATOR_BUFFER_SIZE> buffer;
    size_t total_expected{0};
    size_t high_water_mark{0};
    uint32_t base_seq{0};
    time_t last_seen{0};
};

/**
 * @brief Two-Tier Stream Accumulator.
 * 
 * - Tier 1 (Fast Path): If packet contains the entire TLS record (>= 5 + record_len),
 *   it immediately invokes the completion callback zero-copy.
 * - Tier 2 (Slow Path): If packet is fragmented across MTUs (< 5 + record_len),
 *   it buffers contiguous or sequence-offset slices into an 8 KB scratchpad
 *   until complete, then invokes callback and evicts immediately.
 */
class TwoTierAccumulator {
public:
    using HandshakeCallback = std::function<void(const FlowKey &key, 
                                                 const uint8_t *record_data, 
                                                 size_t record_len)>;

    explicit TwoTierAccumulator(HandshakeCallback callback) 
        : on_handshake_ready_(std::move(callback)) {}

    /**
     * @brief Ingest a raw TCP segment for a given 4-tuple flow.
     * @param key 4-tuple identifying the flow
     * @param seq TCP sequence number of segment
     * @param payload Pointer to TCP payload bytes
     * @param payload_len Length of TCP payload in bytes
     * @param current_time Packet timestamp in seconds
     */
    void process_segment(const FlowKey &key,
                         uint32_t seq,
                         const uint8_t *payload,
                         size_t payload_len,
                         time_t current_time);

    /**
     * @brief Periodic garbage collection for incomplete or abandoned handshakes.
     */
    void cleanup_stale_flows(time_t current_time);

    [[nodiscard]] size_t active_flow_count() const noexcept {
        return active_flows_.size();
    }

private:
    HandshakeCallback on_handshake_ready_;
    std::unordered_map<FlowKey, FragmentedHandshake, FlowHash> active_flows_;
    uint64_t packet_counter_{0};
};

} // namespace tlsfp

#endif // TLSFP_ACCUMULATOR_HPP
