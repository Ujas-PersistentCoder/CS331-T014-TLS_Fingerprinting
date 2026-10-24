#include "tlsfp/accumulator.hpp"
#include <algorithm>
#include <cstring>

namespace tlsfp {

void TwoTierAccumulator::process_segment(const FlowKey &key,
                                        uint32_t seq,
                                        const uint8_t *payload,
                                        size_t payload_len,
                                        time_t current_time) {
    if (payload == nullptr || payload_len == 0) {
        return;
    }

    // Periodic sweep for stale/abandoned flows
    if ((++packet_counter_ & 0x03FF) == 0) { // Every 1024 packets
        cleanup_stale_flows(current_time);
    }

    // Fast Path optimization: If no active fragmented flows, skip map lookup completely
    if (!active_flows_.empty()) {
        auto it = active_flows_.find(key);
        if (it != active_flows_.end()) {
            // --- TIER 2: Existing Fragmented Flow ---
            FragmentedHandshake &flow = it->second;
            flow.last_seen = current_time;

            // RFC 1982 sequence distance from base_seq
            int32_t seq_diff = static_cast<int32_t>(seq - flow.base_seq);

            // If segment is before our current accumulation point, it's a duplicate/retransmit; ignore safely
            if (seq_diff < 0 || static_cast<size_t>(seq_diff) < flow.bytes_accumulated) {
                return;
            }

            // If segment is beyond our current accumulation point, a gap occurred; drop flow
            if (static_cast<size_t>(seq_diff) > flow.bytes_accumulated) {
                active_flows_.erase(it);
                return;
            }

            size_t bytes_needed = flow.total_expected - flow.bytes_accumulated;
            size_t bytes_to_copy = std::min(payload_len, bytes_needed);

            std::memcpy(flow.buffer.data() + flow.bytes_accumulated, payload, bytes_to_copy);
            flow.bytes_accumulated += bytes_to_copy;

            // Check if full TLS record has been assembled
            if (flow.bytes_accumulated >= flow.total_expected) {
                if (on_handshake_ready_) {
                    on_handshake_ready_(key, flow.buffer.data(), flow.total_expected);
                }
                active_flows_.erase(it);
            }
            return;
        }
    }

    // --- NEW FLOW: Inspect Initial TLS Record Layer ---
    if (payload_len < 5) {
        return; // Incomplete record header; cannot determine boundary
    }

    uint8_t record_type = payload[0];
    uint8_t major_ver   = payload[1];
    uint8_t minor_ver   = payload[2];

    // Must be a TLS Handshake record (0x16) with valid version framing
    if (record_type != TLS_RECORD_HANDSHAKE || major_ver != 0x03 || minor_ver > 0x04) {
        return; // Ignore non-handshake records (ApplicationData, Alerts, etc.)
    }

    uint16_t tls_rec_len = (static_cast<uint16_t>(payload[3]) << 8) | payload[4];
    size_t total_record_len = 5 + tls_rec_len;

    // Minimum handshake header is 4 bytes; max RFC record length is 16384 bytes
    if (tls_rec_len < 4 || total_record_len > MAX_TLS_RECORD_LENGTH) {
        return;
    }

    // ─────────────────────────────────────────────────────────────────────
    // TIER 1: FAST PATH (Single-packet frame, GRO-on, or standard MTU)
    // ─────────────────────────────────────────────────────────────────────
    if (payload_len >= total_record_len) {
        if (on_handshake_ready_) {
            on_handshake_ready_(key, payload, total_record_len);
        }
        return;
    }

    // ─────────────────────────────────────────────────────────────────────
    // TIER 2: SLOW PATH (Multi-packet handshake, GRO-off, or PQ-TLS)
    // ─────────────────────────────────────────────────────────────────────
    if (total_record_len > ACCUMULATOR_BUFFER_SIZE) {
        // Guard against pathologically oversized records (> 8 KB)
        return;
    }

    FragmentedHandshake &flow = active_flows_[key];
    flow.total_expected   = total_record_len;
    flow.base_seq         = seq;
    flow.last_seen         = current_time;
    flow.bytes_accumulated = payload_len;

    std::memcpy(flow.buffer.data(), payload, payload_len);
}

void TwoTierAccumulator::cleanup_stale_flows(time_t current_time) {
    if (active_flows_.empty()) return;

    for (auto it = active_flows_.begin(); it != active_flows_.end(); ) {
        if (current_time > it->second.last_seen &&
            (current_time - it->second.last_seen) > FLOW_TIMEOUT_SECONDS) {
            it = active_flows_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace tlsfp
