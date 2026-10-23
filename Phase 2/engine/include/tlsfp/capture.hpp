#ifndef TLSFP_CAPTURE_HPP
#define TLSFP_CAPTURE_HPP

#include "tlsfp/types.hpp"
#include "tlsfp/accumulator.hpp"
#include <pcap.h>
#include <string>
#include <memory>
#include <chrono>

namespace tlsfp {

struct CaptureOptions {
    std::string read_filename;    // Offline PCAP path
    std::string interface_name;   // Live capture interface (e.g., eth0)
    std::string bpf_filter{"tcp"};
    bool verbose{false};
    bool quiet{false};
    bool prompt_unknown{false};
    std::string seed_filename{"code/db/seed_fingerprints.json"};
    std::string manifest_filename{"code/db/capture_manifest.json"};
    std::string legacy_filename{"code/python/fingerprints.json"};
    std::string redis_host{"127.0.0.1"};
    uint16_t redis_port{6379};
};

struct CaptureStats {
    uint64_t total_packets{0};
    uint64_t client_hellos{0};
    uint64_t server_hellos{0};
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;

    [[nodiscard]] double elapsed_seconds() const noexcept {
        auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        return dur.count() / 1000000.0;
    }

    [[nodiscard]] double packets_per_second() const noexcept {
        double sec = elapsed_seconds();
        return (sec > 0.0) ? (total_packets / sec) : 0.0;
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

    /**
     * @brief Handle raw packet delivered by libpcap callback.
     */
    void handle_packet(const struct pcap_pkthdr *pkthdr, const uint8_t *packet);

    [[nodiscard]] const CaptureStats& stats() const noexcept {
        return stats_;
    }

    void stop() noexcept {
        stop_requested_ = true;
        if (pcap_handle_) {
            pcap_breakloop(pcap_handle_);
        }
    }

private:
    bool setup_pcap();
    void process_assembled_handshake(const FlowKey &key, 
                                     const uint8_t *record_data, 
                                     size_t record_len);

    CaptureOptions options_;
    CaptureStats stats_;
    pcap_t *pcap_handle_{nullptr};
    int datalink_type_{0};
    bool stop_requested_{false};
    std::unique_ptr<TwoTierAccumulator> accumulator_;

    // Forward declarations for DB & parser scratchpads are hooked in implementation
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace tlsfp

#endif // TLSFP_CAPTURE_HPP
