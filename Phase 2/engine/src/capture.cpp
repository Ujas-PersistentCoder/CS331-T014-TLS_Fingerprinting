#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/ja4.hpp"
#include "tlsfp/ja4t.hpp"
#include "tlsfp/db.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <optional>
#include <unordered_map>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <filesystem>
#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace tlsfp {

namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string DIM     = "\033[2m";
    const std::string CYAN    = "\033[36m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string RED     = "\033[31m";
    const std::string GRAY    = "\033[90m";

    const std::string CLIENT_BADGE = "\033[1;37;44m CLIENT \033[0m"; // White text on Blue
    const std::string SERVER_BADGE = "\033[1;37;42m SERVER \033[0m"; // White text on Green
    const std::string MATCH_BADGE  = "\033[1;30;42m MATCH \033[0m";  // Black text on Green
}

namespace {

std::string resolve_data_file(const std::string &requested,
                              std::initializer_list<const char *> fallbacks) {
    if (std::filesystem::exists(requested)) return requested;
    for (const char *fallback : fallbacks) {
        if (std::filesystem::exists(fallback)) return fallback;
    }
    return requested;
}

inline std::string to_hex(uint16_t val) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04x", val);
    return std::string(buf);
}

void print_verbose_client(const ClientHelloData &ch, const JA3Fingerprint &ja3, const JA4Fingerprint &ja4) {
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Version]     " << Color::RESET
              << Color::YELLOW << to_hex(ch.client_version) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-SNI]         " << Color::RESET
              << (ch.has_sni ? Color::GREEN : Color::GRAY)
              << (ch.has_sni ? ch.sni : std::string_view("<none>"))
              << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-ALPN]        " << Color::RESET
              << (ch.first_alpn.empty() ? Color::GRAY : Color::MAGENTA)
              << (ch.first_alpn.empty() ? std::string_view("<none>") : ch.first_alpn)
              << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Ciphers]     " << Color::RESET
              << Color::DIM << "Count: " << Color::RESET
              << Color::BOLD << ch.cipher_suites.size() << Color::RESET << " [";
    for (size_t i = 0; i < ch.cipher_suites.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(ch.cipher_suites[i]) << Color::RESET;
    }
    std::cout << "]\n" << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Extensions]  " << Color::RESET
              << Color::DIM << "Count: " << Color::RESET
              << Color::BOLD << ch.extensions.size() << Color::RESET << " [";
    for (size_t i = 0; i < ch.extensions.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(ch.extensions[i]) << Color::RESET;
    }
    std::cout << "]\n" << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Curves]      " << Color::RESET
              << Color::DIM << "Count: " << Color::RESET
              << Color::BOLD << ch.supported_groups.size() << Color::RESET << " [";
    for (size_t i = 0; i < ch.supported_groups.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(ch.supported_groups[i]) << Color::RESET;
    }
    std::cout << "]\n" << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-SigAlgs]     " << Color::RESET
              << Color::DIM << "Count: " << Color::RESET
              << Color::BOLD << ch.signature_algorithms.size() << Color::RESET << " [";
    for (size_t i = 0; i < ch.signature_algorithms.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(ch.signature_algorithms[i]) << Color::RESET;
    }
    std::cout << "]\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-JA3-Raw]     " << Color::RESET
              << Color::DIM << ja3.raw_string << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-JA4-Raw]     " << Color::RESET
              << Color::DIM << "b: [" << ja4.raw_ja4_b << "] c: [" << ja4.raw_ja4_c << "]" << Color::RESET << "\n";
}

void print_verbose_server(const ServerHelloData &sh, const JA3Fingerprint &ja3s, const JA4Fingerprint &ja4s) {
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Version]     " << Color::RESET
              << Color::YELLOW << to_hex(sh.server_version) << Color::RESET
              << Color::DIM << " (Negotiated: " << Color::RESET
              << Color::YELLOW << to_hex(sh.selected_version) << Color::DIM << ")" << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Cipher]      " << Color::RESET
              << Color::YELLOW << to_hex(sh.selected_cipher) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-ALPN]        " << Color::RESET
              << (sh.first_alpn.empty() ? Color::GRAY : Color::MAGENTA)
              << (sh.first_alpn.empty() ? std::string_view("<none>") : sh.first_alpn)
              << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Extensions]  " << Color::RESET
              << Color::DIM << "Count: " << Color::RESET
              << Color::BOLD << sh.extensions.size() << Color::RESET << " [";
    for (size_t i = 0; i < sh.extensions.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(sh.extensions[i]) << Color::RESET;
    }
    std::cout << "]\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-JA3S-Raw]    " << Color::RESET
              << Color::DIM << ja3s.raw_string << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-JA4S-Raw]    " << Color::RESET
              << Color::DIM << "c: [" << ja4s.raw_ja4_c << "]" << Color::RESET << "\n";
}

void print_verbose_tcp(const TcpSynData &syn, const OsInference &inf, bool server_side) {
    const std::string ja4t_str = compute_ja4t(syn);

    // Option flags inspection
    bool has_sack = false;
    bool has_ts = false;
    size_t eol_count = 0;
    for (size_t i = 0; i < syn.option_count; ++i) {
        if (syn.option_kinds[i] == TCP_OPT_SACK_PERM) has_sack = true;
        else if (syn.option_kinds[i] == TCP_OPT_TIMESTAMP) has_ts = true;
        else if (syn.option_kinds[i] == TCP_OPT_EOL) ++eol_count;
    }

    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-JA4T-Raw]    " << Color::RESET
              << Color::BOLD << ja4t_str << Color::RESET << "\n";

    // 1. TCP Options List with friendly names
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-TCP-Opts]    " << Color::RESET << "[";
    for (size_t i = 0; i < syn.option_count; ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        const char *name = tcp_option_name(syn.option_kinds[i]);
        std::cout << Color::YELLOW;
        if (name) std::cout << name;
        else std::cout << static_cast<unsigned>(syn.option_kinds[i]);
        std::cout << Color::RESET;
    }
    std::cout << "]  " << Color::DIM << "(SACK: " << (has_sack ? "supported" : "off")
              << ", Timestamps: " << (has_ts ? "enabled" : "disabled")
              << (eol_count > 0 ? (", EOL padding: " + std::to_string(eol_count) + "B") : "")
              << ")" << Color::RESET << "\n";

    // 2. Window & Buffering Profile
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-TCP-Window]  " << Color::RESET
              << Color::DIM << "raw: " << Color::RESET << syn.window_size;
    // The SYN's own window is never scaled (RFC 7323 §2.2); the shift applies to later segments,
    // so the largest window this stack can ever advertise is 65535 << shift.
    if (syn.has_window_scale && syn.window_scale > 14) {
        std::cout << Color::DIM << "  scale: " << Color::RESET << Color::RED
                  << static_cast<unsigned>(syn.window_scale) << " (invalid: RFC 7323 caps the shift at 14)"
                  << Color::RESET;
    } else if (syn.has_window_scale && syn.window_scale > 0) {
        const uint32_t mult = 1U << syn.window_scale;
        const uint64_t max_window = static_cast<uint64_t>(65535) * mult;
        std::cout << Color::DIM << "  scale: " << Color::RESET << static_cast<unsigned>(syn.window_scale)
                  << Color::DIM << " (×" << mult << " → max receive window " << (max_window / 1024)
                  << " KB)" << Color::RESET;
    } else if (syn.has_window_scale) {
        std::cout << Color::DIM << "  scale: 0 (×1, scaling enabled but unused)" << Color::RESET;
    } else {
        std::cout << Color::DIM << "  (no window scale option: max window 64 KB)" << Color::RESET;
    }
    std::cout << "\n";

    // 3. Path MTU & Encapsulation
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-TCP-MTU]     " << Color::RESET
              << describe_path_mtu(syn, server_side) << "\n";

    // 4. Network Distance & Proximity
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-TCP-Network] " << Color::RESET;
    if (inf.initial_ttl == 0) {
        std::cout << Color::DIM << "TTL unknown (0): distance undetermined" << Color::RESET << "\n";
    } else {
        std::cout << Color::DIM << "Observed TTL: " << Color::RESET << static_cast<unsigned>(syn.ip_ttl)
                  << Color::DIM << " | Estimated Initial TTL: " << Color::RESET << static_cast<unsigned>(inf.initial_ttl)
                  << Color::DIM << " → " << Color::RESET << Color::BOLD << static_cast<unsigned>(inf.hops) << " hops " << Color::RESET
                  << Color::DIM << "(" << describe_network_proximity(inf.hops) << ")" << Color::RESET << "\n";
    }

    // 5. OS Stack Deduction & Integrity
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-TCP-Stack]   " << Color::RESET
              << Color::DIM << "layout: " << Color::RESET << os_family_name(inf.layout_family)
              << Color::DIM << " | TTL family: " << Color::RESET << os_family_name(inf.ttl_family)
              << Color::DIM << " → " << Color::RESET;
    // Malformed first: infer_os() also sets stack_anomaly for it, which would hide this branch
    if (syn.malformed_options) {
        std::cout << Color::RED << Color::BOLD << "MALFORMED: invalid option framing or window scale > 14 (hand-crafted packet)"
                  << Color::RESET;
    } else if (inf.stack_anomaly && server_side) {
        // Mirrors report_tcp_fingerprint: no STACK_ANOMALY for SYN-ACKs
        std::cout << Color::DIM << "layout and TTL disagree: normal for CDN / load-balancer SYN-ACKs (not alerted)"
                  << Color::RESET;
    } else if (inf.stack_anomaly) {
        std::cout << Color::YELLOW << Color::BOLD << "ANOMALY: Incompatible layout & TTL (possible spoofing/rewrite)" << Color::RESET;
    } else if (inf.layout_family == OsFamily::Unknown) {
        std::cout << os_family_name(inf.family) << Color::DIM << " (TTL only: option layout not recognised)" << Color::RESET;
    } else if (inf.ttl_family == OsFamily::Unknown) {
        std::cout << os_family_name(inf.family) << Color::DIM << " (option layout only: TTL unknown)" << Color::RESET;
    } else {
        std::cout << Color::GREEN << os_family_name(inf.family) << " (Corroborated: layout and TTL agree)" << Color::RESET;
    }
    std::cout << "\n";
}

void print_alert(const std::string &color, const char *tag, const std::string &message) {
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << color << Color::BOLD << tag << Color::RESET << "  "
              << color << message << Color::RESET << "\n";
}

// A SYN or SYN-ACK held until the TLS Hello on the same directional 4-tuple arrives
struct SynObservation {
    TcpSynData syn;
    uint32_t sequence_number{0};
    std::time_t seen{0};
};

} // anonymous namespace

template <typename T, size_t Capacity>
class SPSCQueue {
public:
    template <typename F>
    bool emplace(F &&init) noexcept {
        const size_t head = head_.load(std::memory_order_relaxed);
        const size_t next = (head + 1) % Capacity;
        if (next == tail_.load(std::memory_order_acquire)) return false;
        init(slots_[head]);
        head_.store(next, std::memory_order_release);
        return true;
    }

    template <typename F>
    bool pop_into(F &&consumer) noexcept {
        const size_t tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) return false;
        consumer(slots_[tail]);
        tail_.store((tail + 1) % Capacity, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool empty() const noexcept {
        return tail_.load(std::memory_order_acquire) ==
               head_.load(std::memory_order_acquire);
    }

private:
    std::array<T, Capacity> slots_{};
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
};

struct HandshakeJob {
    FlowKey key;
    uint16_t record_len{0};
    uint8_t ip_ttl{0};
    bool has_syn{false};
    TcpSynData syn_data{};
    uint8_t record_data[ACCUMULATOR_BUFFER_SIZE]{};
};

inline uint32_t compute_symmetric_flow_hash(const FlowKey &key) noexcept {
    uint32_t hash = static_cast<uint32_t>(key.src_port ^ key.dst_port);
    if (key.ip_version == 4) {
        hash ^= key.src_ip.v4.s_addr ^ key.dst_ip.v4.s_addr;
    } else {
        uint32_t src[4]{};
        uint32_t dst[4]{};
        std::memcpy(src, &key.src_ip.v6, sizeof(src));
        std::memcpy(dst, &key.dst_ip.v6, sizeof(dst));
        for (size_t i = 0; i < 4; ++i) hash ^= src[i] ^ dst[i];
    }
    return hash;
}

struct WorkerContext {
    SPSCQueue<HandshakeJob, 2048> queue;
    ClientHelloData client_scratchpad;
    ServerHelloData server_scratchpad;
    std::thread thread;
};

struct CaptureEngine::Impl {
    std::vector<std::unique_ptr<WorkerContext>> workers;
    std::atomic<bool> running{false};
    std::mutex stdout_mutex;
    std::mutex enroll_mutex;
    std::unique_ptr<FingerprintDatabase> db;

    // JA4T state: ONLY accessed by the producer thread in handle_packet / dispatch_handshake
    // SYNs keyed client->server and SYN-ACKs keyed server->client
    std::unordered_map<FlowKey, SynObservation, FlowHash> syn_table;
    std::time_t last_syn_cleanup{0};
    bool has_syn_cleanup_time{false};
    uint8_t current_ttl{0};
    std::time_t current_packet_time{0};

    // Age in either direction: merged or concatenated pcaps can step the clock backwards,
    // and entries stamped in the "future" must still expire.
    static bool syn_expired(std::time_t seen, std::time_t now) noexcept {
        const std::time_t age = now >= seen ? now - seen : seen - now;
        return age >= static_cast<std::time_t>(SYN_TIMEOUT_SECONDS);
    }

    /**
     * @brief Records a SYN / SYN-ACK. Retransmissions with the same ISN keep the first
     * fingerprint: BSD-derived stacks can strip options on later retransmits. A changed
     * ISN identifies a new connection reusing the 4-tuple.
     * @return true if the packet was a valid SYN that is (or already was) tracked
     */
    bool observe_syn(const FlowKey &key, const uint8_t *tcp_hdr, size_t tcp_hdr_len,
                     uint32_t sequence_number, uint8_t ip_ttl, std::time_t now) {
        TcpSynData syn;
        if (!parse_tcp_syn(tcp_hdr, tcp_hdr_len, ip_ttl, syn)) return false;
        syn.ipv6 = key.ip_version == 6;
        if (syn_table.size() >= SYN_TABLE_MAX_ENTRIES && syn_table.find(key) == syn_table.end()) {
            return false; // Flooded with fresh SYNs: fail open, this flow just gets no JA4T
        }
        auto [it, inserted] = syn_table.try_emplace(key);
        if (inserted || syn_expired(it->second.seen, now) ||
            it->second.sequence_number != sequence_number) {
            // A changed initial sequence number identifies a new connection reusing this 4-tuple.
            it->second.syn = syn;
            it->second.sequence_number = sequence_number;
            it->second.seen = now;
        }
        return true;
    }

    std::optional<SynObservation> take_syn(const FlowKey &key, std::time_t now) {
        auto it = syn_table.find(key);
        if (it == syn_table.end()) return std::nullopt;
        std::optional<SynObservation> obs;
        if (!syn_expired(it->second.seen, now)) obs = it->second;
        syn_table.erase(it);
        return obs;
    }

    void evict_stale_syns(std::time_t now) {
        for (auto it = syn_table.begin(); it != syn_table.end(); ) {
            if (syn_expired(it->second.seen, now)) {
                it = syn_table.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Full sweep at most once per capture-second; a backwards jump larger than the timeout
    // (concatenated pcaps) also triggers one, otherwise the table would never drain.
    void cleanup_stale_syns_if_due(std::time_t now) {
        if (has_syn_cleanup_time && now - last_syn_cleanup < 1 &&
            last_syn_cleanup - now < static_cast<std::time_t>(SYN_TIMEOUT_SECONDS)) {
            return;
        }
        evict_stale_syns(now);
        last_syn_cleanup = now;
        has_syn_cleanup_time = true;
    }

    bool lookup(FingerprintKind kind, const std::string &hash, FingerprintRecord &record) {
        return db && db->lookup(kind, hash, record);
    }

    unsigned report_tcp_fingerprint(FingerprintKind kind, const char *tag,
                                    const std::optional<TcpSynData> &obs_syn,
                                    uint8_t current_ttl,
                                    const char *hello_name, const CaptureOptions &opts) {
        std::cout << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << tag << Color::RESET;
        if (!obs_syn) {
            std::cout << Color::GRAY << "<" << (kind == FingerprintKind::JA4T ? "SYN" : "SYN-ACK")
                      << " not captured or correlation expired>" << Color::RESET << "\n";
            return 0;
        }

        const TcpSynData &syn = *obs_syn;
        const OsInference inf = infer_os(syn);
        const std::string fp = compute_ja4t(syn);
        std::string label = resolve_label(kind, fp, opts.prompt_unknown);
        const bool catalogued = label != "<unknown>";
        if (!catalogued && syn.malformed_options) {
            label = "inferred: malformed options";
        } else if (!catalogued && inf.stack_anomaly) {
            label = std::string("inferred: ") + os_family_name(inf.layout_family) + " options, TTL " +
                    std::to_string(inf.initial_ttl);
        } else if (!catalogued) {
            label = std::string("inferred: ") + os_family_name(inf.family);
        }

        std::cout << Color::BOLD << fp << Color::RESET << "  "
                  << (catalogued ? Color::GREEN : Color::BLUE) << "[" << label << "]" << Color::RESET
                  << Color::DIM << "  TTL " << static_cast<unsigned>(syn.ip_ttl)
                  << ", " << static_cast<unsigned>(inf.hops) << " hops" << Color::RESET << "\n";

        if (opts.verbose) print_verbose_tcp(syn, inf, kind == FingerprintKind::JA4TS);

        unsigned alerts = 0;
        // Client SYNs only: CDNs and load balancers routinely run Linux with TTL 128/255
        if (inf.stack_anomaly && kind == FingerprintKind::JA4T) {
            print_alert(Color::YELLOW, "⚠ STACK_ANOMALY",
                        syn.malformed_options
                            ? std::string("malformed TCP options, which no stock kernel emits (hand-crafted SYN)")
                            : std::string("TCP options look like ") + os_family_name(inf.layout_family) +
                                  " but initial TTL " + std::to_string(inf.initial_ttl) + " says " +
                                  os_family_name(inf.ttl_family) + " (hand-crafted SYN or TTL rewrite)");
            ++alerts;
        }
        const unsigned ttl_delta = current_ttl > syn.ip_ttl ? current_ttl - syn.ip_ttl
                                                            : syn.ip_ttl - current_ttl;
        if (ttl_delta > TTL_MISMATCH_TOLERANCE) {
            print_alert(Color::YELLOW, "⚠ TTL_MISMATCH",
                        std::string(kind == FingerprintKind::JA4T ? "SYN" : "SYN-ACK") + " arrived with TTL " +
                        std::to_string(syn.ip_ttl) + " but " + hello_name + " with TTL " +
                        std::to_string(current_ttl) + " (packets from different hosts or paths: possible injection)");
            ++alerts;
        }
        return alerts;
    }

    /**
     * @brief L7 vs L4 check: does the client's kernel match the OS its TLS stack implies?
     * Only fires for catalog records carrying expected_os (OS-bound TLS stacks such as
     * SChannel or Apple's Network.framework); cross-platform stacks like Chrome make no claim.
     * @return Number of alerts raised
     */
    unsigned report_impersonation(const std::optional<TcpSynData> &syn,
                                  const std::string &ja3_hash, const std::string &ja4_fp,
                                  const CaptureOptions &opts) {
        if (!syn) return 0;

        FingerprintRecord tls_record;
        OsFamily claimed = OsFamily::Unknown;
        if ((lookup(FingerprintKind::JA4, ja4_fp, tls_record) && !tls_record.expected_os.empty()) ||
            (lookup(FingerprintKind::JA3, ja3_hash, tls_record) && !tls_record.expected_os.empty())) {
            claimed = os_family_from_label(tls_record.expected_os);
        }

        const OsInference inf = infer_os(*syn);
        const std::string ja4t_fp = compute_ja4t(*syn);

        // A catalogued JA4T with an OS label beats the heuristic
        OsFamily actual = inf.family;
        FingerprintRecord tcp_record;
        if (lookup(FingerprintKind::JA4T, ja4t_fp, tcp_record)) {
            const OsFamily labelled = os_family_from_label(tcp_record.os);
            if (labelled != OsFamily::Unknown) actual = labelled;
        }

        if (claimed == OsFamily::Unknown || actual == OsFamily::Unknown) {
            if (opts.verbose) {
                std::cout << Color::GRAY << "   │  " << Color::RESET << Color::DIM << "cross-layer: "
                          << (claimed == OsFamily::Unknown
                                  ? "no OS claim (TLS fingerprint has no expected_os in catalog)"
                                  : "TCP/IP stack OS undetermined")
                          << Color::RESET << "\n";
            }
            return 0;
        }

        const std::string who = tls_record.name.empty() ? std::string("this TLS client") : tls_record.name;
        if (!os_families_compatible(claimed, actual)) {
            print_alert(Color::RED, "✖ IMPERSONATION_MISMATCH",
                        "TLS says " + who + " (ships only on " + os_family_name(claimed) +
                        ") but the TCP/IP stack is " + os_family_name(actual));
            return 1;
        }
        print_alert(Color::GREEN, "✓ CROSS-LAYER OK", who + " on " + os_family_name(actual));
        return 0;
    }

    std::string resolve_label(FingerprintKind kind, const std::string &hash, bool prompt_unknown) {
        if (!db) return "<unknown>";

        FingerprintRecord record;
        if (db->lookup(kind, hash, record)) {
            if (record.name.empty()) return "<unnamed>";
            if (record.category.empty()) return record.name;
            return record.name + " (" + record.category + ")";
        }

        if (prompt_unknown) {
            std::lock_guard<std::mutex> enroll_lock(enroll_mutex);
            if (db->lookup(kind, hash, record)) {
                if (record.name.empty()) return "<unnamed>";
                if (record.category.empty()) return record.name;
                return record.name + " (" + record.category + ")";
            }
            std::cout << Color::YELLOW << Color::BOLD << "[?]" << Color::RESET << " Unknown "
                      << Color::CYAN << FingerprintDatabase::kind_name(kind) << Color::RESET
                      << " fingerprint " << Color::BOLD << hash << Color::RESET
                      << ". Enter verified client/server name (empty to skip): " << std::flush;
            std::string name;
            if (std::getline(std::cin, name) && !name.empty()) {
                if (db->enroll(kind, hash, name)) {
                    return name + " (enrolled)";
                }
            }
        }
        return "<unknown>";
    }
};

CaptureEngine::CaptureEngine(CaptureOptions options)
    : options_(std::move(options)), impl_(std::make_unique<Impl>()) {
    accumulator_ = std::make_unique<TwoTierAccumulator>(
        [this](const FlowKey &key, const uint8_t *record, size_t len) {
            dispatch_handshake(key, record, len);
        });
}

CaptureEngine::~CaptureEngine() {
    stop();
    if (impl_) {
        for (auto &worker : impl_->workers) {
            if (worker->thread.joinable()) worker->thread.join();
        }
    }
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

void CaptureEngine::dispatch_handshake(const FlowKey &key, const uint8_t *record, size_t len) {
    if (!impl_ || impl_->workers.empty()) return;

    std::optional<SynObservation> syn_obs;
    if (options_.enable_ja4t) {
        syn_obs = impl_->take_syn(key, impl_->current_packet_time);
    }

    const uint8_t current_ttl = impl_->current_ttl;

    const uint32_t worker_idx = compute_symmetric_flow_hash(key) % impl_->workers.size();
    auto &worker = *impl_->workers[worker_idx];

    auto init_job = [&](HandshakeJob &job) {
        job.key = key;
        job.record_len = static_cast<uint16_t>(len);
        job.ip_ttl = current_ttl;
        if (syn_obs) {
            job.has_syn = true;
            job.syn_data = syn_obs->syn;
        } else {
            job.has_syn = false;
        }
        std::memcpy(job.record_data, record, len);
    };

    bool pushed = worker.queue.emplace(init_job);

    if (!pushed) {
        if (!options_.read_filename.empty()) {
            while (!stop_requested_.load(std::memory_order_relaxed)) {
                #if defined(__x86_64__) || defined(_M_X64)
                _mm_pause();
                #else
                std::this_thread::yield();
                #endif
                if (worker.queue.emplace(init_job)) {
                    pushed = true;
                    break;
                }
            }
        }
        if (!pushed) {
            stats_.dropped_packets.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

bool CaptureEngine::setup_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    if (!options_.read_filename.empty()) {
        pcap_handle_ = pcap_open_offline(options_.read_filename.c_str(), errbuf);
        if (!pcap_handle_) {
            std::cerr << Color::RED << "[!] Error opening PCAP: " << errbuf << Color::RESET << "\n";
            return false;
        }
    } else if (!options_.interface_name.empty()) {
        pcap_handle_ = pcap_open_live(options_.interface_name.c_str(), 65535, 1, 100, errbuf);
        if (!pcap_handle_) {
            std::cerr << Color::RED << "[!] Error opening live interface: " << errbuf << Color::RESET << "\n";
            return false;
        }
    } else {
        std::cerr << Color::RED << "[!] Neither PCAP file nor live interface specified." << Color::RESET << "\n";
        return false;
    }

    datalink_type_ = pcap_datalink(pcap_handle_);

    if (options_.enable_ja4t) {
        // Allocate buckets once: a rehash of a near-full table mid SYN flood is a latency spike
        impl_->syn_table.reserve(SYN_TABLE_MAX_ENTRIES);
    }

    // Compile and set BPF filter
    if (!options_.bpf_filter.empty()) {
        struct bpf_program bpf;
        if (pcap_compile(pcap_handle_, &bpf, options_.bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
            std::cerr << Color::YELLOW << "[!] BPF filter compilation error: " 
                      << pcap_geterr(pcap_handle_) << Color::RESET << "\n";
        } else {
            pcap_setfilter(pcap_handle_, &bpf);
            pcap_freecode(&bpf);
        }
    }

    const size_t worker_count = options_.num_threads != 0
        ? options_.num_threads
        : std::max<size_t>(1, std::thread::hardware_concurrency());
    impl_->workers.reserve(worker_count);
    const std::string seed_path = resolve_data_file(
        options_.seed_filename, {"code/db/seed_fingerprints.json", "../db/seed_fingerprints.json", "../../code/db/seed_fingerprints.json"});
    const std::string manifest_path = resolve_data_file(
        options_.manifest_filename, {"code/db/capture_manifest.json", "../db/capture_manifest.json", "../../code/db/capture_manifest.json"});
    const std::string legacy_path = resolve_data_file(
        options_.legacy_filename, {"code/python/fingerprints.json", "../python/fingerprints.json", "../../code/python/fingerprints.json"});

    if (!options_.quiet) {
        RedisConfig rconf;
        rconf.host = options_.redis_host;
        rconf.port = options_.redis_port;
        impl_->db = std::make_unique<FingerprintDatabase>(rconf);

        if (impl_->db->connect()) {
            std::cout << Color::GREEN << "[+] Connected to Redis on " 
                      << options_.redis_host << ":" << options_.redis_port << Color::RESET << "\n";
        } else {
            std::cout << Color::DIM << "[*] Redis offline, using in-memory catalog from " 
                      << seed_path << Color::RESET << "\n";
        }
        std::size_t loaded = impl_->db->load_seed_files(seed_path, manifest_path) +
                             impl_->db->load_legacy_ja3_file(legacy_path);
        if (!options_.extra_catalog_filename.empty()) {
            std::size_t lab = impl_->db->load_seed_files(options_.extra_catalog_filename);
            if (lab == 0) {
                std::cout << Color::YELLOW << "[!] No records loaded from lab catalog "
                          << options_.extra_catalog_filename << Color::RESET << "\n";
            } else {
                std::cout << Color::DIM << "[*] Loaded " << lab << " lab catalog records from "
                          << options_.extra_catalog_filename << Color::RESET << "\n";
            }
        }
        std::cout << Color::DIM << "[*] Loaded " << loaded << " fingerprint catalog records." << Color::RESET << "\n";
    }

    impl_->running.store(true, std::memory_order_release);
    for (size_t i = 0; i < worker_count; ++i) {
        auto ctx = std::make_unique<WorkerContext>();
        impl_->workers.push_back(std::move(ctx));
    }
    for (auto &ctx : impl_->workers) {
        WorkerContext *ctx_ptr = ctx.get();
        ctx->thread = std::thread([this, ctx_ptr] {
            while (impl_->running.load(std::memory_order_acquire) || !ctx_ptr->queue.empty()) {
                bool processed = ctx_ptr->queue.pop_into([this, ctx_ptr](const HandshakeJob &job) {
                    process_assembled_handshake(*ctx_ptr, job);
                });
                if (!processed) {
                    for (int spin = 0; spin < 32; ++spin) {
                        #if defined(__x86_64__) || defined(_M_X64)
                        _mm_pause();
                        #endif
                    }
                    if (!ctx_ptr->queue.empty()) continue;
                    std::this_thread::yield();
                }
            }
        });
    }

    return true;
}

static void global_pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *engine = reinterpret_cast<CaptureEngine*>(user);
    engine->handle_packet(h, bytes);
}

void CaptureEngine::stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    if (impl_) impl_->running.store(false, std::memory_order_release);
    if (pcap_handle_) pcap_breakloop(pcap_handle_);
}

bool CaptureEngine::run() {
    if (!setup_pcap()) return false;
    stats_.start_time = std::chrono::steady_clock::now();

    int ret = pcap_loop(pcap_handle_, 0, global_pcap_callback, reinterpret_cast<u_char*>(this));

    impl_->running.store(false, std::memory_order_release);
    for (auto &worker : impl_->workers) {
        if (worker->thread.joinable()) worker->thread.join();
    }
    stats_.end_time = std::chrono::steady_clock::now();

    if (ret < 0 && ret != -2) { // -2 is expected break from pcap_breakloop
        std::cerr << Color::RED << "[!] pcap_loop error: " << pcap_geterr(pcap_handle_) << Color::RESET << "\n";
        return false;
    }
    return true;
}

void CaptureEngine::handle_packet(const struct pcap_pkthdr *pkthdr, const uint8_t *packet) {
    stats_.total_packets.fetch_add(1, std::memory_order_relaxed);
    if (options_.enable_ja4t) {
        impl_->cleanup_stale_syns_if_due(pkthdr->ts.tv_sec);
    }

    size_t link_hdr_len = 0;
    uint16_t ethertype = 0;

    switch (datalink_type_) {
        case DLT_EN10MB: {
            if (pkthdr->caplen < 14) return;
            link_hdr_len = 14;
            ethertype = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];
            if (ethertype == 0x8100 || ethertype == 0x88A8) { // 802.1Q or 802.1ad QinQ outer tag
                if (pkthdr->caplen < 18) return;
                link_hdr_len = 18;
                ethertype = (static_cast<uint16_t>(packet[16]) << 8) | packet[17];
                // Loop over stacked inner VLAN tags (0x8100 = 802.1Q, 0x88A8 = 802.1ad QinQ)
                while ((ethertype == 0x8100 || ethertype == 0x88A8) && 
                       pkthdr->caplen >= link_hdr_len + 4) {
                    ethertype = (static_cast<uint16_t>(packet[link_hdr_len + 2]) << 8) | 
                                packet[link_hdr_len + 3];
                    link_hdr_len += 4;
                }
            }
            break;
        }
        case DLT_LINUX_SLL2: {
            if (pkthdr->caplen < 20) return;
            link_hdr_len = 20;
            ethertype = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
            break;
        }
        case DLT_LINUX_SLL: {
            if (pkthdr->caplen < 16) return;
            link_hdr_len = 16;
            ethertype = (static_cast<uint16_t>(packet[14]) << 8) | packet[15];
            break;
        }
        case DLT_NULL: {
            if (pkthdr->caplen < 4) return;
            link_hdr_len = 4;
            uint32_t family = 0;
            std::memcpy(&family, packet, 4);
            ethertype = (family == 2) ? 0x0800 : 0x86DD;
            break;
        }
        case DLT_RAW: {
            link_hdr_len = 0;
            if (pkthdr->caplen < 1) return;
            ethertype = ((packet[0] >> 4) == 4) ? 0x0800 : 0x86DD;
            break;
        }
        default:
            return;
    }

    FlowKey key{};
    size_t ip_hdr_len = 0;
    size_t ip_total_len = 0;
    uint8_t ip_ttl = 0; // IPv4 TTL / IPv6 Hop Limit

    if (ethertype == 0x0800) { // IPv4
        if (pkthdr->caplen < link_hdr_len + 20) return;
        const uint8_t *ip_ptr = packet + link_hdr_len;
        if ((ip_ptr[0] >> 4) != 4) return;

        ip_hdr_len = static_cast<size_t>(ip_ptr[0] & 0x0F) * 4;
        if (ip_hdr_len < 20 || pkthdr->caplen < link_hdr_len + ip_hdr_len) return;
        if (ip_ptr[9] != IPPROTO_TCP) return;

        ip_total_len = (static_cast<size_t>(ip_ptr[2]) << 8) | ip_ptr[3];
        if (ip_total_len == 0) {
            // TCP Segmentation Offload (TSO/GSO): kernel leaves 0 for outbound superpackets
            ip_total_len = pkthdr->caplen - link_hdr_len;
        } else if (ip_total_len < ip_hdr_len) {
            return;
        }

        ip_ttl = ip_ptr[8];
        key.ip_version = 4;
        std::memcpy(&key.src_ip.v4.s_addr, ip_ptr + 12, 4);
        std::memcpy(&key.dst_ip.v4.s_addr, ip_ptr + 16, 4);
    } else if (ethertype == 0x86DD) { // IPv6
        if (pkthdr->caplen < link_hdr_len + 40) return;
        const uint8_t *ip6_ptr = packet + link_hdr_len;
        if ((ip6_ptr[0] >> 4) != 6) return;

        uint16_t v6_payload_len = (static_cast<uint16_t>(ip6_ptr[4]) << 8) | ip6_ptr[5];
        ip_total_len = 40 + v6_payload_len;

        uint8_t next_proto = ip6_ptr[6];
        size_t ext_offset = link_hdr_len + 40;
        while ((next_proto == 0 || next_proto == 43 || next_proto == 60) && pkthdr->caplen >= ext_offset + 8) {
            next_proto = packet[ext_offset];
            ext_offset += static_cast<size_t>(packet[ext_offset + 1] + 1) * 8;
        }
        if (next_proto != IPPROTO_TCP) return;

        ip_hdr_len = ext_offset - link_hdr_len;
        if (pkthdr->caplen < link_hdr_len + ip_hdr_len || ip_total_len < ip_hdr_len) return;

        ip_ttl = ip6_ptr[7];
        key.ip_version = 6;
        std::memcpy(&key.src_ip.v6, ip6_ptr + 8, 16);
        std::memcpy(&key.dst_ip.v6, ip6_ptr + 24, 16);
    } else {
        return;
    }

    // TCP Header
    if (pkthdr->caplen < link_hdr_len + ip_hdr_len + 20) return;
    const uint8_t *tcp_ptr = packet + link_hdr_len + ip_hdr_len;

    std::memcpy(&key.src_port, tcp_ptr + 0, 2);
    std::memcpy(&key.dst_port, tcp_ptr + 2, 2);

    uint32_t raw_seq = 0;
    std::memcpy(&raw_seq, tcp_ptr + 4, 4);
    uint32_t seq = ntohl(raw_seq);

    size_t tcp_hdr_len = static_cast<size_t>(tcp_ptr[12] >> 4) * 4;
    if (tcp_hdr_len < 20 ||
        ip_total_len < ip_hdr_len + tcp_hdr_len ||
        pkthdr->caplen < link_hdr_len + ip_hdr_len + tcp_hdr_len) {
        return;
    }

    // JA4T / JA4TS: record the kernel-built SYN and SYN-ACK before the payload-less early exit
    // Only a genuine SYN or SYN-ACK: SYN+FIN / SYN+RST are scan probes, not connection opens.
    // ECE/CWR (ECN negotiation), PSH and URG are ignored, as in FoxIO's is_initial_syn.
    const uint8_t handshake_flags = tcp_ptr[13] & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK);
    if (options_.enable_ja4t &&
        (handshake_flags == TCP_FLAG_SYN || handshake_flags == (TCP_FLAG_SYN | TCP_FLAG_ACK)) &&
        impl_->observe_syn(key, tcp_ptr, tcp_hdr_len, seq, ip_ttl, pkthdr->ts.tv_sec)) {
        if (handshake_flags & TCP_FLAG_ACK) {
            stats_.tcp_synacks.fetch_add(1, std::memory_order_relaxed);
        } else {
            stats_.tcp_syns.fetch_add(1, std::memory_order_relaxed);
        }
    }

    size_t total_hdrs = link_hdr_len + ip_hdr_len + tcp_hdr_len;
    if (pkthdr->caplen <= total_hdrs) return; // Pure ACK, SYN, etc.

    // Determine available datagram length (clamping Ethernet trailer padding or respecting snaplen truncation)
    size_t ip_captured = pkthdr->caplen - link_hdr_len;
    size_t ip_available = std::min(ip_captured, ip_total_len);
    if (ip_available <= ip_hdr_len + tcp_hdr_len) return;

    size_t payload_len = ip_available - ip_hdr_len - tcp_hdr_len;
    const uint8_t *payload = packet + total_hdrs;

    // Middlebox Compatibility TLS 1.3 ChangeCipherSpec stripping (0x14 0x03 0x03 0x00 0x01 0x01)
    if (payload_len >= 6 &&
        payload[0] == 0x14 && payload[1] == 0x03 && payload[2] == 0x03 &&
        payload[3] == 0x00 && payload[4] == 0x01 && payload[5] == 0x01) {
        payload += 6;
        payload_len -= 6;
        seq += 6;
    }

    if (payload_len == 0) return;

    // Feed to Two-Tier Accumulator
    impl_->current_ttl = ip_ttl;
    impl_->current_packet_time = pkthdr->ts.tv_sec;
    if (accumulator_) {
        accumulator_->process_segment(key, seq, payload, payload_len, static_cast<uint64_t>(pkthdr->ts.tv_sec));
    }
}

void CaptureEngine::process_assembled_handshake(WorkerContext &ctx,
                                                const HandshakeJob &job) {
    const FlowKey &key = job.key;
    const uint8_t *record_data = job.record_data;
    const size_t record_len = job.record_len;

    if (record_len < 9 || record_data[0] != TLS_RECORD_HANDSHAKE) return;

    uint8_t hs_type = record_data[5]; // Byte 0..4 = Record Header, Byte 5 = Handshake Type

    std::optional<TcpSynData> syn_opt;
    if (job.has_syn) {
        syn_opt = job.syn_data;
    }

    if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
        if (parse_client_hello(record_data, record_len, ctx.client_scratchpad)) {
            stats_.client_hellos.fetch_add(1, std::memory_order_relaxed);
            JA3Fingerprint ja3 = compute_ja3(ctx.client_scratchpad);
            JA4Fingerprint ja4 = compute_ja4(ctx.client_scratchpad);

            if (options_.quiet) return;

            char src_ip_str[INET6_ADDRSTRLEN], dst_ip_str[INET6_ADDRSTRLEN];
            if (key.ip_version == 4) {
                inet_ntop(AF_INET, &key.src_ip.v4, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET, &key.dst_ip.v4, dst_ip_str, sizeof(dst_ip_str));
            } else {
                inet_ntop(AF_INET6, &key.src_ip.v6, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET6, &key.dst_ip.v6, dst_ip_str, sizeof(dst_ip_str));
            }
            uint16_t src_p = ntohs(key.src_port);
            uint16_t dst_p = ntohs(key.dst_port);

            std::lock_guard<std::mutex> lock(impl_->stdout_mutex);
            std::string label_ja3 = impl_->resolve_label(FingerprintKind::JA3, ja3.md5_hash, options_.prompt_unknown);
            std::string label_ja4 = impl_->resolve_label(FingerprintKind::JA4, ja4.full_fp, options_.prompt_unknown);

            std::cout << "\n" << Color::CLIENT_BADGE << " "
                      << Color::BOLD << src_ip_str << ":" << src_p
                      << Color::RESET << Color::GRAY << " ──▶ " << Color::RESET
                      << Color::BOLD << dst_ip_str << ":" << dst_p << Color::RESET << "\n"
                      << Color::GRAY << "   │  " << Color::RESET
                      << Color::CYAN << "JA3:  " << Color::RESET
                      << Color::BOLD << ja3.md5_hash << Color::RESET << "  "
                      << (label_ja3 != "<unknown>" ? Color::GREEN : Color::GRAY) << "[" << label_ja3 << "]" << Color::RESET << "\n"
                      << Color::GRAY << "   │  " << Color::RESET
                      << Color::CYAN << "JA4:  " << Color::RESET
                      << Color::BOLD << ja4.full_fp << Color::RESET << "  "
                      << (label_ja4 != "<unknown>" ? Color::GREEN : Color::GRAY) << "[" << label_ja4 << "]" << Color::RESET << "\n";

            if (options_.enable_ja4t) {
                stats_.cross_layer_alerts.fetch_add(
                    impl_->report_tcp_fingerprint(FingerprintKind::JA4T, "JA4T: ", syn_opt, job.ip_ttl, "ClientHello", options_) +
                    impl_->report_impersonation(syn_opt, ja3.md5_hash, ja4.full_fp, options_),
                    std::memory_order_relaxed
                );
            }

            if (options_.verbose) {
                print_verbose_client(ctx.client_scratchpad, ja3, ja4);
            }
            if (!options_.interface_name.empty()) {
                std::cout << std::flush;
            }
        }
    } else if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
        if (parse_server_hello(record_data, record_len, ctx.server_scratchpad)) {
            stats_.server_hellos.fetch_add(1, std::memory_order_relaxed);
            JA3Fingerprint ja3s = compute_ja3s(ctx.server_scratchpad);
            JA4Fingerprint ja4s = compute_ja4s(ctx.server_scratchpad);

            if (options_.quiet) return;

            char src_ip_str[INET6_ADDRSTRLEN], dst_ip_str[INET6_ADDRSTRLEN];
            if (key.ip_version == 4) {
                inet_ntop(AF_INET, &key.src_ip.v4, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET, &key.dst_ip.v4, dst_ip_str, sizeof(dst_ip_str));
            } else {
                inet_ntop(AF_INET6, &key.src_ip.v6, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET6, &key.dst_ip.v6, dst_ip_str, sizeof(dst_ip_str));
            }
            uint16_t src_p = ntohs(key.src_port);
            uint16_t dst_p = ntohs(key.dst_port);

            std::lock_guard<std::mutex> lock(impl_->stdout_mutex);
            std::string label_ja3s = impl_->resolve_label(FingerprintKind::JA3S, ja3s.md5_hash, options_.prompt_unknown);
            std::string label_ja4s = impl_->resolve_label(FingerprintKind::JA4S, ja4s.full_fp, options_.prompt_unknown);

            std::cout << "\n" << Color::SERVER_BADGE << " "
                      << Color::BOLD << src_ip_str << ":" << src_p
                      << Color::RESET << Color::GRAY << " ──▶ " << Color::RESET
                      << Color::BOLD << dst_ip_str << ":" << dst_p << Color::RESET << "\n"
                      << Color::GRAY << "   │  " << Color::RESET
                      << Color::CYAN << "JA3S: " << Color::RESET
                      << Color::BOLD << ja3s.md5_hash << Color::RESET << "  "
                      << (label_ja3s != "<unknown>" ? Color::GREEN : Color::GRAY) << "[" << label_ja3s << "]" << Color::RESET << "\n"
                      << Color::GRAY << "   │  " << Color::RESET
                      << Color::CYAN << "JA4S: " << Color::RESET
                      << Color::BOLD << ja4s.full_fp << Color::RESET << "  "
                      << (label_ja4s != "<unknown>" ? Color::GREEN : Color::GRAY) << "[" << label_ja4s << "]" << Color::RESET << "\n";

            if (options_.enable_ja4t) {
                stats_.cross_layer_alerts.fetch_add(
                    impl_->report_tcp_fingerprint(FingerprintKind::JA4TS, "JA4TS: ", syn_opt, job.ip_ttl, "ServerHello", options_),
                    std::memory_order_relaxed
                );
            }

            if (options_.verbose) {
                print_verbose_server(ctx.server_scratchpad, ja3s, ja4s);
            }
            if (!options_.interface_name.empty()) {
                std::cout << std::flush;
            }
        }
    }
}

} // namespace tlsfp
