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

            // Forward gap detected: segment arrives after a missing hole
            if (seq_diff > static_cast<int32_t>(flow.bytes_accumulated)) {
                active_flows_.erase(it);
                return;
            }

            const uint8_t *new_payload = payload;
            size_t new_payload_len = payload_len;

            // Handle overlap / retransmission: segment starts before or at current accumulation point
            if (seq_diff < static_cast<int32_t>(flow.bytes_accumulated)) {
                int32_t seg_end = seq_diff + static_cast<int32_t>(payload_len);
                if (seg_end <= static_cast<int32_t>(flow.bytes_accumulated)) {
                    // Fully duplicate segment; ignore safely
                    return;
                }
                // Partial overlap: slice off already-accumulated prefix bytes
                size_t overlap = flow.bytes_accumulated - seq_diff;
                new_payload += overlap;
                new_payload_len -= overlap;
            }

            // If total_expected is 0, we are waiting for at least 5 bytes to decode the TLS record header
            if (flow.total_expected == 0) {
                size_t bytes_to_copy = std::min(new_payload_len, static_cast<size_t>(ACCUMULATOR_BUFFER_SIZE - flow.bytes_accumulated));
                std::memcpy(flow.buffer.data() + flow.bytes_accumulated, new_payload, bytes_to_copy);
                flow.bytes_accumulated += bytes_to_copy;

                if (flow.bytes_accumulated >= 5) {
                    uint8_t rec_type = flow.buffer[0];
                    uint8_t maj_ver  = flow.buffer[1];
                    uint8_t min_ver  = flow.buffer[2];
                    if (rec_type != TLS_RECORD_HANDSHAKE || maj_ver != 0x03 || min_ver > 0x04) {
                        active_flows_.erase(it);
                        return;
                    }
                    uint16_t tls_rec_len = (static_cast<uint16_t>(flow.buffer[3]) << 8) | flow.buffer[4];
                    size_t total_record_len = 5 + tls_rec_len;
                    if (tls_rec_len < 4 || total_record_len > ACCUMULATOR_BUFFER_SIZE) {
                        active_flows_.erase(it);
                        return;
                    }
                    flow.total_expected = total_record_len;
                } else {
                    return; // Still less than 5 bytes
                }
            } else {
                size_t bytes_needed = flow.total_expected - flow.bytes_accumulated;
                size_t bytes_to_copy = std::min(new_payload_len, bytes_needed);

                std::memcpy(flow.buffer.data() + flow.bytes_accumulated, new_payload, bytes_to_copy);
                flow.bytes_accumulated += bytes_to_copy;
            }

            // Check if full TLS record has been assembled
            if (flow.total_expected > 0 && flow.bytes_accumulated >= flow.total_expected) {
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
        // Buffer partial record header if initial byte indicates a TLS Handshake record (0x16)
        if (payload[0] == TLS_RECORD_HANDSHAKE && (payload_len == 1 || payload[1] == 0x03)) {
            FragmentedHandshake &flow = active_flows_[key];
            flow.total_expected    = 0;
            flow.base_seq          = seq;
            flow.last_seen         = current_time;
            flow.bytes_accumulated = payload_len;
            std::memcpy(flow.buffer.data(), payload, payload_len);
        }
        return;
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
