#include "tlsfp/accumulator.hpp"
#include <algorithm>

namespace tlsfp {
namespace {
bool tls_type(uint8_t value) { return value >= 20 && value <= 24; }
}

void TwoTierAccumulator::report(const FlowKey &key, Stream &stream, ParseStatus status,
                                 const char *reason) {
    stream.stopped = true;
    const auto *partial = stream.partial.get();
    if (issue_) issue_(key, status, reason, partial ? partial->bytes.data() : nullptr,
                      partial ? partial->bytes.size() : 0);
    if (status == ParseStatus::Unsupported && limit_) limit_(key);
    stream.partial.reset();
}

void TwoTierAccumulator::start_flow(const FlowKey &key, uint32_t seq, time_t) {
    forget_flow(key);
    if (streams_.size() < max_streams_) {
        auto &stream = streams_[key];
        stream.next_seq = seq;
        stream.syn_anchored = true;
    }
}

void TwoTierAccumulator::forget_flow(const FlowKey &key) { streams_.erase(key); }
void TwoTierAccumulator::stop_flow(const FlowKey &key) {
    auto it = streams_.find(key);
    if (it != streams_.end()) {
        it->second.stopped = true;
        it->second.partial.reset();
    }
}

void TwoTierAccumulator::invalidate_flow(const FlowKey &key, const char *reason, bool only_pending) {
    auto it = streams_.find(key);
    if (it == streams_.end() && streams_.size() < max_streams_)
        it = streams_.try_emplace(key).first;
    if (it != streams_.end() && !it->second.stopped) {
        if (!only_pending || it->second.partial || it->second.waiting_since)
            report(key, it->second, ParseStatus::Incomplete, reason);
        else it->second.stopped = true;
    }
}

void TwoTierAccumulator::process_segment(const FlowKey &key, uint32_t seq,
                                         const uint8_t *payload, size_t length, time_t now) {
    if (!payload || length == 0) return;
    if (!enable_ech_ && (streams_.empty() || streams_.find(key) == streams_.end())) {
        while (length >= 5 && tls_type(payload[0]) && payload[1] == 3 && payload[2] <= 4) {
            const size_t total = 5 + (size_t{payload[3]} << 8) + payload[4];
            if (total > ACCUMULATOR_BUFFER_SIZE) break;
            if (length < total) break; // Partial record tail; fall through to stream assembly
            if (ready_) ready_(key, payload, total);
            payload += total;
            seq += static_cast<uint32_t>(total);
            length -= total;
        }
        if (length == 0) return;
    }
    auto it = streams_.find(key);
    if (it == streams_.end()) {
        if (!tls_type(payload[0])) return;
        if (streams_.size() >= max_streams_) {
            if (issue_) issue_(key, ParseStatus::Unsupported, "stream_capacity", nullptr, 0);
            return;
        }
        it = streams_.try_emplace(key).first;
        it->second.next_seq = seq;
    }
    Stream &stream = it->second;
    if (stream.stopped) return;
    // TCP sequence numbers wrap modulo 2^32. The signed distance gives local
    // ordering for separations below half the sequence space, as assumed here.
    const int32_t distance = static_cast<int32_t>(seq - stream.next_seq);
    if (distance > 0) {
        if (stream.syn_anchored && !stream.tls_started) {
            // No TLS boundary has been chosen yet. Discard this detached segment
            // and wait for the EXACT SYN-derived prefix, not a guessed resync.
            // No reorder queue is kept; a hello needing discarded bytes remains incomplete.
            if (!stream.waiting_since) {
                stream.waiting_since = now;
                if (issue_) issue_(key, ParseStatus::Incomplete, "pre_tls_sequence_gap", nullptr, 0);
            }
            return;
        }
        // Once framing starts, missing bytes destroy record alignment. Stop this
        // direction rather than scanning later ciphertext for a plausible header.
        report(key, stream, ParseStatus::Incomplete, "tcp_gap");
        return;
    }
    if (distance < 0) {
        // Ignore already delivered bytes but keep a partial overlap's new suffix.
        // Keeping next_seq after delivery prevents retransmitted hello emission.
        const auto overlap = static_cast<uint32_t>(stream.next_seq - seq);
        if (overlap >= length) return;
        payload += overlap;
        length -= overlap;
    }
    stream.next_seq += static_cast<uint32_t>(length);
    stream.waiting_since.reset();

    // TCP segment boundaries are unrelated to TLS records: consume coalesced
    // records and retain a partial tail, including headers split across segments.
    while (length != 0 && !stream.stopped) {
        if (!stream.partial) {
            if (!stream.tls_started && !tls_type(payload[0])) {
                stream.stopped = true; // A SYN hint was for non-TLS traffic.
                return;
            }
            stream.tls_started = true;
            // Fast path: deliver one bounded complete record without copying.
            if (length >= 5 && tls_type(payload[0]) && payload[1] == 3 && payload[2] <= 4) {
                const size_t total = 5 + (size_t{payload[3]} << 8) + payload[4];
                if (total > ACCUMULATOR_BUFFER_SIZE) {
                    report(key, stream, ParseStatus::Unsupported, "record_size_limit");
                    return;
                }
                if (length >= total) {
                    if (ready_) ready_(key, payload, total);
                    payload += total;
                    length -= total;
                    continue;
                }
            }
            stream.partial = std::make_unique<FragmentedHandshake>();
        }
        auto &partial = *stream.partial;
        const size_t target = partial.expected ? partial.expected : 5;
        const size_t count = std::min(length, target - partial.bytes.size());
        partial.bytes.insert(partial.bytes.end(), payload, payload + count);
        partial.last_seen = now;
        payload += count;
        length -= count;
        if (!partial.expected && partial.bytes.size() == 5) {
            const auto &header = partial.bytes;
            if (!tls_type(header[0]) || header[1] != 3 || header[2] > 4) {
                report(key, stream, ParseStatus::Malformed, "invalid_tls_record_header");
                return;
            }
            partial.expected = 5 + (size_t{header[3]} << 8) + header[4];
            if (partial.expected > ACCUMULATOR_BUFFER_SIZE) {
                report(key, stream, ParseStatus::Unsupported, "record_size_limit");
                return;
            }
            partial.bytes.reserve(partial.expected); // Avoid growth beyond the bounded record size.
        }
        if (partial.expected && partial.bytes.size() == partial.expected) {
            // Deliver a record, not a reassembled handshake message. A hello
            // spanning multiple records remains the parser's unsupported case.
            if (ready_) ready_(key, partial.bytes.data(), partial.bytes.size());
            stream.partial.reset();
        }
    }
}

void TwoTierAccumulator::cleanup_stale_flows(time_t now) {
    for (auto &[key, stream] : streams_) {
        if (!stream.stopped && stream.waiting_since && now > *stream.waiting_since &&
            now - *stream.waiting_since > FLOW_TIMEOUT_SECONDS) {
            report(key, stream, ParseStatus::Incomplete, "initial_data_timeout");
            stream.waiting_since.reset();
        }
        if (stream.partial && now > stream.partial->last_seen &&
            now - stream.partial->last_seen > FLOW_TIMEOUT_SECONDS)
            report(key, stream, ParseStatus::Incomplete, "record_timeout");
    }
}

void TwoTierAccumulator::flush_pending(const char *reason) {
    for (auto &[key, stream] : streams_)
        if (stream.partial) report(key, stream, ParseStatus::Incomplete, reason);
}

size_t TwoTierAccumulator::active_flow_count() const noexcept {
    size_t count = 0;
    for (const auto &[key, stream] : streams_) if (stream.partial) ++count;
    return count;
}
} // namespace tlsfp
