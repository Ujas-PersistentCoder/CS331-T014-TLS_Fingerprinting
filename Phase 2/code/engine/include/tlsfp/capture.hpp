#ifndef TLSFP_CAPTURE_HPP
#define TLSFP_CAPTURE_HPP

#include "tlsfp/types.hpp"
#include "tlsfp/accumulator.hpp"
#include "tlsfp/ech_analysis.hpp"
#include <pcap.h>
#include <string>
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>
#include <cstddef>

namespace tlsfp {

struct WorkerContext;
struct HandshakeJob;

struct CaptureOptions {
    std::string json_filename;
    size_t max_connections{65536};
    double connection_timeout_seconds{30};
    // Empty selects steady_clock. Injection permits deterministic idle tests.
    std::function<double()> monotonic_clock;
    std::string read_filename;    // Offline PCAP path
    std::string interface_name;   // Live capture interface (e.g., eth0)
    std::string bpf_filter{"tcp"};
    bool verbose{false};
    bool quiet{false};
    bool enable_ja4t{false};
    bool enable_ech{false};
    bool enable_pqtls{false};
    bool prompt_unknown{false};
    std::string seed_filename{"Phase 1/code/db/seed_fingerprints.json"};
    std::string manifest_filename{"Phase 1/code/db/capture_manifest.json"};
    std::string legacy_filename{"Phase 1/code/python/fingerprints.json"};
    std::string extra_catalog_filename; // Optional lab catalog (same schema as seed), loaded last
    std::string redis_host{"127.0.0.1"};
    uint16_t redis_port{6379};
    size_t num_threads{0};
};

struct CaptureStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> client_hellos{0};
    std::atomic<uint64_t> server_hellos{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_syns{0};            // Client SYNs fingerprinted (JA4T)
    std::atomic<uint64_t> tcp_synacks{0};         // Server SYN-ACKs fingerprinted (JA4TS)
    std::atomic<uint64_t> cross_layer_alerts{0};  // Impersonation / TTL / stack anomaly alerts raised
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;

    [[nodiscard]] double elapsed_seconds() const noexcept {
        auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        return dur.count() / 1000000.0;
    }

    [[nodiscard]] double packets_per_second() const noexcept {
        double sec = elapsed_seconds();
        return (sec > 0.0) ? (total_packets.load(std::memory_order_relaxed) / sec) : 0.0;
    }
};

class CaptureEngine {
public:
    explicit CaptureEngine(CaptureOptions options);
    ~CaptureEngine();

    // Disable copy
    CaptureEngine(const CaptureEngine&) = delete;
    CaptureEngine& operator=(const CaptureEngine&) = delete;

    /**
     * @brief Run the capture engine (offline or live) until complete or interrupted.
     * @return true if capture succeeded, false on error
     */
    bool run();

    // The same TCP ingestion path used by packet capture, also usable by embedders.
    // Ingestion, maintenance, and finalization belong to one capture thread.
    // Only stop() may be invoked from another thread.
    void ingest_tcp_segment(const FlowKey &, uint32_t seq, uint8_t flags,
                            const uint8_t *payload, size_t length, uint64_t timestamp_us,
                            bool truncated = false);
    void maintenance();
    bool finish_capture(const char *reason = "end_of_capture");
    [[nodiscard]] size_t retained_connection_count() const noexcept;

    /**
     * @brief Handle raw packet delivered by libpcap callback.
     */
    void handle_packet(const struct pcap_pkthdr *pkthdr, const uint8_t *packet);

    [[nodiscard]] const CaptureStats& stats() const noexcept {
        return stats_;
    }

    void stop() noexcept;

private:
    bool setup_pcap();
    void process_assembled_handshake(const FlowKey &key,
                                     const uint8_t *record_data,
                                     size_t record_len);
    void process_hello(const FlowKey &, const uint8_t *, size_t);
    void record_issue(const FlowKey &, ParseStatus, const char *, const uint8_t *, size_t);
    void dispatch_handshake(const FlowKey &key, const uint8_t *record, size_t len, HelloRole role = HelloRole::Unknown);
    void process_worker_hello(WorkerContext &ctx, const HandshakeJob &job);

    CaptureOptions options_;
    CaptureStats stats_;
    pcap_t *pcap_handle_{nullptr};
    int datalink_type_{0};
    std::atomic<bool> stop_requested_{false};
    std::unique_ptr<TwoTierAccumulator> accumulator_;

    // Forward declarations for DB & parser scratchpads are hooked in implementation
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tlsfp

#endif // TLSFP_CAPTURE_HPP
