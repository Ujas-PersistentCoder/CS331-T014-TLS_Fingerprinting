#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include "tlsfp/ech_analysis.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/ja4.hpp"
#include "tlsfp/db.hpp"
#include "tlsfp/ja4t.hpp"
#include "tlsfp/pqtls_analysis.hpp"
#include <mutex>
#include <array>
#include <vector>
#include <list>
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <thread>
#include <type_traits>
#include <algorithm>

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

template <typename T>
std::string observed_number(const std::optional<T> &value) {
    return value ? std::to_string(*value) : "<unknown>";
}

void print_parse_diagnostic(const FlowKey &key, const char *kind) {
    char src[INET6_ADDRSTRLEN]{}, dst[INET6_ADDRSTRLEN]{};
    const int family = key.ip_version == 4 ? AF_INET : AF_INET6;
    inet_ntop(family, &key.src_ip, src, sizeof(src));
    inet_ntop(family, &key.dst_ip, dst, sizeof(dst));
    std::cout << "\n[" << kind << " diagnostic] " << src << ":" << ntohs(key.src_port)
              << " -> " << dst << ":" << ntohs(key.dst_port)
              << " (fingerprints suppressed)\n";
}

void print_ech_observation(const ClientHelloData &ch) {
    std::cout << "   │  [V-ClientHello] status=" << parse_status_name(ch.parse_status)
              << " (" << ch.parse_detail << ")\n"
              << "   │  [V-OuterRandom] ";
    if (ch.outer_random) {
        for (uint8_t byte : *ch.outer_random) {
            char hex[3];
            std::snprintf(hex, sizeof(hex), "%02x", byte);
            std::cout << hex;
        }
    } else {
        std::cout << "<unknown>";
    }
    std::cout << "\n   │  [V-ECH] presence="
              << (!ch.ech.present ? "unknown" : (*ch.ech.present ? "present" : "absent"))
              << " occurrences=" << ch.ech.occurrences.size() << "\n";
    for (size_t i = 0; i < ch.ech.occurrences.size(); ++i) {
        const auto &extension = ch.ech.occurrences[i];
        std::cout << "   │  [V-ECH #" << i + 1 << "] status=" << parse_status_name(extension.status)
                  << " (" << extension.detail << ") variant=" << observed_number(extension.variant)
                  << " kdf_id=" << observed_number(extension.kdf_id)
                  << " aead_id=" << observed_number(extension.aead_id)
                  << " config_id=" << observed_number(extension.config_id)
                  << " enc_length=" << observed_number(extension.enc_length)
                  << " ciphertext_length=" << observed_number(extension.payload_length) << "\n";
    }
    std::cout << "   │  [V-ECH findings]";
    if (ch.ech.findings == 0) std::cout << " none";
    for (const auto &finding : {
             std::pair{DuplicateEch, "duplicate_ech"},
             std::pair{ForbiddenOuterExtensions, "forbidden_outer_extensions"},
             std::pair{ExternalInnerMarker, "external_inner_marker"},
             std::pair{ExportOnlyAead, "export_only_aead"},
             std::pair{EmptyEncContextUnknown, "empty_enc_context_unknown"},
             std::pair{EmptyEncInInitialHello, "empty_enc_in_initial_hello"}}) {
        if (ch.ech.findings & finding.first) std::cout << " " << finding.second;
    }
    std::cout << "\n";
    if (ch.ech.present == true) {
        std::cout << "   │  [V-ECH interpretation] offer_type=unknown acceptance=unverified\n";
    }
}

void print_verbose_client(const ClientHelloData &ch, const JA3Fingerprint &ja3, const JA4Fingerprint &ja4) {
    print_ech_observation(ch);
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Version]     " << Color::RESET
              << Color::YELLOW << to_hex(ch.client_version) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-Outer SNI]   " << Color::RESET
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

// --- PQ-TLS Verbose Output ---

void print_pqtls_client(const ClientHelloData &ch, PqtlsShareMode mode) {
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-PQTLS-Offer]  " << Color::RESET
              << (ch.pqtls.pq_group != 0 ? Color::MAGENTA : Color::GRAY)
              << pqtls_offer_text(ch.pqtls) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-PQTLS-Keys]   " << Color::RESET
              << pqtls_keys_text(ch.pqtls) << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-PQTLS-Share]  " << Color::RESET
              << (mode == PqtlsShareMode::PROACTIVE_SHARE_VALID ? Color::GREEN : Color::YELLOW)
              << pqtls_share_mode_name(mode) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-PQTLS-Check]  " << Color::RESET
              << (pqtls_client_findings(ch.pqtls) == PQTLS_FINDING_NONE ? Color::GRAY : Color::RED)
              << pqtls_client_check_text(ch.pqtls) << Color::RESET << "\n";
}

void print_pqtls_server(const ServerHelloData &sh, PqtlsPosture posture) {
    std::cout << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-PQTLS-Group]  " << Color::RESET
              << (is_pqtls_group(sh.pqtls.selected_group) ? Color::MAGENTA : Color::GRAY)
              << pqtls_server_text(sh.pqtls) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-PQTLS-Result] " << Color::RESET
              << (posture == PqtlsPosture::HYBRID_SELECTED_OBSERVED ? Color::GREEN : Color::YELLOW)
              << pqtls_posture_name(posture) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET
              << Color::CYAN << "[V-PQTLS-Check]  " << Color::RESET
              << (pqtls_server_findings(sh.pqtls) == PQTLS_FINDING_NONE ? Color::GRAY : Color::RED)
              << pqtls_server_check_text(sh.pqtls) << Color::RESET << "\n";
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


FlowKey reverse_flow(FlowKey key) {
    std::swap(key.src_ip, key.dst_ip);
    std::swap(key.src_port, key.dst_port);
    return key;
}

FlowKey canonical_flow(const FlowKey &key) {
    // Both directions share a map key. Endpoint sorting is only storage order;
    // SYN/hello evidence establishes client/server roles, never port-number guesses.
    const size_t length = key.ip_version == 4 ? 4 : 16;
    const int order = std::memcmp(&key.src_ip, &key.dst_ip, length);
    return order > 0 || (order == 0 && ntohs(key.src_port) > ntohs(key.dst_port))
        ? reverse_flow(key) : key;
}

std::string json_string(std::string_view value) {
    // SNI/ALPN originate in untrusted packet bytes. Preserve valid UTF-8 while
    // escaping controls and invalid bytes so one observation cannot break JSONL.
    std::string out{"\""};
    for (size_t i = 0; i < value.size(); ++i) {
        const auto byte = static_cast<unsigned char>(value[i]);
        if (byte >= 0xc2 && byte <= 0xf4) {
            const size_t count = byte < 0xe0 ? 2 : (byte < 0xf0 ? 3 : 4);
            bool valid = i + count <= value.size();
            for (size_t j = 1; valid && j < count; ++j) {
                const auto continuation = static_cast<unsigned char>(value[i+j]);
                valid = continuation >= 0x80 && continuation <= 0xbf;
            }
            if (valid) {
                const auto second = static_cast<unsigned char>(value[i+1]);
                valid = !(byte == 0xe0 && second < 0xa0) && !(byte == 0xed && second >= 0xa0) &&
                        !(byte == 0xf0 && second < 0x90) && !(byte == 0xf4 && second >= 0x90);
            }
            if (valid) { out.append(value.substr(i, count)); i += count - 1; continue; }
        }
        if (byte == '"' || byte == '\\') { out += '\\'; out += static_cast<char>(byte); }
        else if (byte < 32 || byte >= 127) {
            char escaped[7];
            std::snprintf(escaped, sizeof(escaped), "\\u%04x", byte);
            out += escaped;
        } else out += static_cast<char>(byte);
    }
    return out + '"';
}

template <typename T>
std::string json_number(const std::optional<T> &value) {
    if (!value) return "null";
    if constexpr (std::is_same_v<T, bool>) return *value ? "true" : "false";
    return std::to_string(*value);
}

std::string json_text(const std::string &value) {
    return value.empty() ? "null" : json_string(value);
}

std::string random_hex(const std::optional<std::array<uint8_t, 32>> &value) {
    if (!value) return {};
    std::string out;
    for (uint8_t byte : *value) {
        char hex[3]; std::snprintf(hex, sizeof(hex), "%02x", byte); out += hex;
    }
    return out;
}

std::string endpoint_json(const FlowKey &key, bool source) {
    char address[INET6_ADDRSTRLEN]{};
    inet_ntop(key.ip_version == 4 ? AF_INET : AF_INET6,
              source ? &key.src_ip : &key.dst_ip, address, sizeof(address));
    return "{\"ip\":" + json_string(address) + ",\"port\":" +
        std::to_string(ntohs(source ? key.src_port : key.dst_port)) + "}";
}

std::string ech_json(const EchObservation &ech) {
    std::string out = "{\"presence\":" + json_number(ech.present) + ",\"findings\":[";
    bool comma = false;
    for (const auto &finding : {
            std::pair{DuplicateEch, "duplicate_ech"},
            std::pair{ForbiddenOuterExtensions, "forbidden_outer_extensions"},
            std::pair{ExternalInnerMarker, "external_inner_marker"},
            std::pair{ExportOnlyAead, "export_only_aead"},
            std::pair{EmptyEncContextUnknown, "empty_enc_context_unknown"},
            std::pair{EmptyEncInInitialHello, "empty_enc_in_initial_hello"}}) {
        if (!(ech.findings & finding.first)) continue;
        if (comma) out += ',';
        comma = true; out += json_string(finding.second);
    }
    out += "],\"occurrences\":[";
    comma = false;
    for (const auto &body : ech.occurrences) {
        if (comma) out += ',';
        comma = true;
        out += "{\"status\":" + json_string(parse_status_name(body.status)) +
            ",\"detail\":" + json_string(body.detail) +
            ",\"variant\":" + json_number(body.variant) + ",\"kdf_id\":" + json_number(body.kdf_id) +
            ",\"aead_id\":" + json_number(body.aead_id) + ",\"config_id\":" + json_number(body.config_id) +
            ",\"enc_length\":" + json_number(body.enc_length) +
            ",\"ciphertext_length\":" + json_number(body.payload_length) + "}";
    }
    return out + "]}";
}

// Connection observations own their data: parser string_views borrow buffers
// that disappear after record delivery. Keep correlation/output here and ECH
// decoding/interpretation in their focused modules (strategy document, §3).
struct ClientObservation {
    ParseStatus status{ParseStatus::NotExamined};
    std::string detail, random, sni, alpn, ja3, ja4;
    EchObservation ech;
};
struct ServerObservation {
    ParseStatus status{ParseStatus::NotExamined};
    std::string detail, ja3s, ja4s;
    std::optional<uint16_t> version;
};
struct TransportIssue { ParseStatus status; std::string reason; };
struct Connection {
    // One bounded TCP generation, distinct from per-direction record buffers.
    // Transport issues coexist with complete hellos; neither erases the other.
    FlowKey key;
    uint64_t id{0}, first_us{0}, last_us{0}, recency{0};
    double idle_at{0};
    std::list<FlowKey>::iterator lru_it;
    std::optional<bool> client_at_a;
    std::optional<uint32_t> syn_seq[2];
    bool tls_candidate{false}, emitted{false}, closed{false}, hrr_seen{false}, role_conflict{false};
    bool protected_direction[2]{false, false};
    bool tls13_offered{false};
    bool unexpected_client_hello{false};
    std::optional<ClientObservation> client;
    std::optional<ServerObservation> server;
    ParseStatus direction_status[2]{ParseStatus::NotExamined, ParseStatus::NotExamined};
    std::vector<TransportIssue> issues[2];

    int direction(const FlowKey &flow) const { return flow == key ? 0 : 1; }
    void orient(bool client_a) {
        if (role_conflict) return;
        if (client_at_a && *client_at_a != client_a) {
            role_conflict = true;
            client_at_a.reset();
        }
        else client_at_a = client_a;
    }
};

std::string client_json(const Connection &connection) {
    const ClientObservation empty;
    const auto &client = connection.client ? *connection.client : empty;
    ParseStatus status = client.status;
    if (!connection.client && connection.client_at_a)
        status = connection.direction_status[*connection.client_at_a ? 0 : 1];
    return "{\"status\":" + json_string(parse_status_name(status)) + ",\"detail\":" + json_text(client.detail) +
        ",\"outer_random\":" + json_text(client.random) + ",\"outer_sni\":" + json_text(client.sni) +
        ",\"alpn\":" + json_text(client.alpn) + ",\"ech\":" + ech_json(client.ech) +
        ",\"ja3\":" + json_text(client.ja3) + ",\"ja4\":" + json_text(client.ja4) + "}";
}

std::string server_json(const Connection &connection) {
    const ServerObservation empty;
    const auto &server = connection.server ? *connection.server : empty;
    ParseStatus status = server.status;
    if (!connection.server && connection.client_at_a)
        status = connection.direction_status[*connection.client_at_a ? 1 : 0];
    return "{\"status\":" + json_string(parse_status_name(status)) + ",\"detail\":" + json_text(server.detail) +
        ",\"negotiated_version\":" + json_number(server.version) +
        ",\"hrr_seen\":" + (connection.hrr_seen ? "true" : "false") +
        ",\"ja3s\":" + json_text(server.ja3s) + ",\"ja4s\":" + json_text(server.ja4s) + "}";
}

bool non_acceptance_observed(const Connection &connection) {
    // I3 requires a consistent pair. Retries are deliberately excluded because
    // recognizing HRR does not implement the optional CH1/HRR/CH2 evidence rules.
    if (connection.role_conflict || connection.hrr_seen || connection.unexpected_client_hello || !connection.client || !connection.server ||
        connection.client->status != ParseStatus::Complete ||
        connection.server->status != ParseStatus::Complete || connection.client->ech.present != true)
        return false;
    return ech_non_acceptance_observed(connection.client->ech, connection.client->status,
                                       connection.server->status, connection.server->version);
}

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
    HelloRole hello_role{HelloRole::Unknown};
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
    PqtlsOfferTable pqtls_offers;  // PQ-TLS: per worker, no lock needed
    std::thread thread;
};

struct CaptureEngine::Impl {
    std::vector<std::unique_ptr<WorkerContext>> workers;
    std::atomic<bool> running{false};
    std::mutex stdout_mutex;
    std::mutex enroll_mutex;

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


    explicit Impl(const CaptureOptions &settings) : options(settings) {
        static std::atomic<uint64_t> serial{0};
        capture_id = std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) +
            "-" + std::to_string(getpid()) + "-" + std::to_string(++serial);
        if (!options.max_connections || options.connection_timeout_seconds <= 0) {
            failed = true;
            std::cerr << "Invalid connection capacity or timeout\n";
        }
        if (!options.json_filename.empty()) {
            // Capture artifacts may be used for independent label joins. Exclusive
            // creation prevents overwriting a prior run; restrict local file access.
            json_fd = open(options.json_filename.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (json_fd < 0) {
                failed = true;
                std::cerr << "Cannot create JSON output " << options.json_filename << ": " << std::strerror(errno) << "\n";
            }
        }
    }
    ~Impl() { if (json_fd >= 0) close(json_fd); }
    const CaptureOptions &options;
    std::unordered_map<FlowKey, Connection, FlowHash> connections;
    std::list<FlowKey> lru_order;
    std::string capture_id;
    uint64_t next_id{0}, recency{0}, watermark_us{0};
    double now{0}, next_sweep{-1};
    time_t last_accumulator_cleanup{0};
    int json_fd{-1};
    bool failed{false};

    double clock_now() const {
        if (options.monotonic_clock) return options.monotonic_clock();
        return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    void emit(Connection &connection, const char *reason) {
        if (connection.emitted || !connection.tls_candidate) return;
        connection.emitted = true;
        // A complete hello pair means framing/correlation succeeded, not that TLS
        // completed. Real-versus-GREASE stays unknown; ordinary ECH acceptance
        // confirmation needs inner-handshake information absent at this tap.
        const bool non_acceptance = non_acceptance_observed(connection);

        if (!failed && json_fd >= 0) {
            const bool complete = !connection.role_conflict && !connection.unexpected_client_hello && connection.client && connection.server &&
                connection.client->status == ParseStatus::Complete && connection.server->status == ParseStatus::Complete;
            std::string output = "{\"schema_version\":1,\"capture_id\":" + json_string(capture_id) +
                ",\"connection_id\":" + std::to_string(connection.id) + ",\"capture_source\":" +
                json_string(options.read_filename.empty() ? options.interface_name : options.read_filename) +
                ",\"ip_version\":" + std::to_string(connection.key.ip_version) +
                ",\"endpoint_a\":" + endpoint_json(connection.key, true) +
                ",\"endpoint_b\":" + endpoint_json(connection.key, false) + ",\"client_endpoint\":" +
                (!connection.client_at_a ? "null" : json_string(*connection.client_at_a ? "a" : "b")) +
                ",\"first_observation_us\":" + std::to_string(connection.first_us) +
                ",\"last_observation_us\":" + std::to_string(connection.last_us) +
                ",\"completion_reason\":" + json_string(reason) + ",\"complete_hello_pair\":" + (complete ? "true" : "false") +
                ",\"client\":" + client_json(connection) + ",\"server\":" + server_json(connection) +
                ",\"interpretation\":{\"offer_type\":\"unknown\",\"acceptance\":" +
                json_string(non_acceptance ? "non_acceptance_observed" : "unverified") +
                ",\"evidence\":" + (non_acceptance ? "[\"I3_negotiated_below_tls13\"]" : "[]") + "},\"limitations\":[";
            bool comma = false;
            const auto add_limit = [&](const std::string &limit) {
                if (comma) output += ',';
                comma = true; output += json_string(limit);
            };
            if (connection.hrr_seen) add_limit("hrr_sequence_not_analyzed");
            if (connection.role_conflict) add_limit("conflicting_endpoint_roles");
            if (connection.unexpected_client_hello) add_limit("unexpected_additional_client_hello");
            output += "],\"transport\":[";
            for (int direction = 0; direction < 2; ++direction) {
                if (direction) output += ',';
                output += "{\"endpoint\":" + json_string(direction ? "b" : "a") +
                    ",\"status\":" + json_string(parse_status_name(connection.direction_status[direction])) + ",\"issues\":[";
                for (size_t i = 0; i < connection.issues[direction].size(); ++i) {
                    if (i) output += ',';
                    const auto &issue = connection.issues[direction][i];
                    output += "{\"status\":" + json_string(parse_status_name(issue.status)) +
                        ",\"reason\":" + json_string(issue.reason) + "}";
                }
                output += "]}";
            }
            output += "]}\n";

            size_t offset = 0;
            while (offset < output.size()) {
                const auto count = write(json_fd, output.data() + offset, output.size() - offset);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) {
                    failed = true;
                    std::cerr << "JSON output write failed: " << std::strerror(errno) << "\n";
                    break;
                }
                offset += static_cast<size_t>(count);
            }
        }
        if (options.verbose && !options.quiet) {
            std::lock_guard<std::mutex> lock(stdout_mutex);
            std::cout << "[Connection summary] id=" << connection.id << " reason=" << reason
                      << " acceptance=" << (non_acceptance ? "non_acceptance_observed" : "unverified") << "\n";
        }
        // Release owned observations after the single summary. Retain lifecycle
        // markers so retransmissions cannot create another summary before expiry.
        connection.client.reset();
        connection.server.reset();
        for (auto &issues : connection.issues) std::vector<TransportIssue>().swap(issues);
    }
    ClientHelloData client_scratchpad;
    ServerHelloData server_scratchpad;
    std::unique_ptr<FingerprintDatabase> db;

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
    : options_(std::move(options)) {
    if (!options_.json_filename.empty()) {
        options_.enable_ech = true;
    }
    impl_ = std::make_unique<Impl>(options_);
    accumulator_ = std::make_unique<TwoTierAccumulator>(
        [this](const FlowKey &key, const uint8_t *record, size_t len) {
            this->process_assembled_handshake(key, record, len);
        },
        TwoTierAccumulator::RecordLimitCallback{},
        [this](const FlowKey &key, ParseStatus status, const char *reason, const uint8_t *prefix, size_t length) {
            record_issue(key, status, reason, prefix, length);
        }, options_.max_connections * 2,
        options_.enable_ech
    );
}

CaptureEngine::~CaptureEngine() {
    stop();
    impl_->running.store(false, std::memory_order_release);
    for (auto &worker : impl_->workers)
        if (worker->thread.joinable()) worker->thread.join();
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

void CaptureEngine::dispatch_handshake(const FlowKey &key, const uint8_t *record, size_t len, HelloRole role) {
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
        job.hello_role = role;
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
    if (options_.enable_ja4t) impl_->syn_table.reserve(SYN_TABLE_MAX_ENTRIES);

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

    // Connect database and seed catalog
    if (!options_.quiet) {
        RedisConfig rconf;
        rconf.host = options_.redis_host;
        rconf.port = options_.redis_port;
        impl_->db = std::make_unique<FingerprintDatabase>(rconf);

        const std::string seed_path = resolve_data_file(
            options_.seed_filename, {
                "Phase 1/code/db/seed_fingerprints.json",
                "../../../Phase 1/code/db/seed_fingerprints.json",
                "../../Phase 1/code/db/seed_fingerprints.json",
                "code/db/seed_fingerprints.json",
                "../db/seed_fingerprints.json",
                "../../code/db/seed_fingerprints.json"
            });
        const std::string manifest_path = resolve_data_file(
            options_.manifest_filename, {
                "Phase 1/code/db/capture_manifest.json",
                "../../../Phase 1/code/db/capture_manifest.json",
                "../../Phase 1/code/db/capture_manifest.json",
                "code/db/capture_manifest.json",
                "../db/capture_manifest.json",
                "../../code/db/capture_manifest.json"
            });
        const std::string legacy_path = resolve_data_file(
            options_.legacy_filename, {
                "Phase 1/code/python/fingerprints.json",
                "../../../Phase 1/code/python/fingerprints.json",
                "../../Phase 1/code/python/fingerprints.json",
                "code/python/fingerprints.json",
                "../python/fingerprints.json",
                "../../code/python/fingerprints.json"
            });

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

    const size_t worker_count = options_.num_threads ? options_.num_threads
        : std::max<size_t>(1, std::thread::hardware_concurrency());
    impl_->workers.reserve(worker_count);
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
                    process_worker_hello(*ctx_ptr, job);
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
    if (pcap_handle_) pcap_breakloop(pcap_handle_);
}

bool CaptureEngine::run() {
    if (impl_->failed) return false;
    if (!setup_pcap()) return false;

    stats_.start_time = std::chrono::steady_clock::now();

    const bool live = options_.read_filename.empty();
    if (live) {
        // Nonblocking dispatch permits idle maintenance even when no packets
        // arrive; otherwise unfinished observations might never time out.
        char error[PCAP_ERRBUF_SIZE]{};
        if (pcap_setnonblock(pcap_handle_, 1, error) < 0) {
            std::cerr << "Cannot enable nonblocking capture: " << error << "\n";
            return false;
        }
    }
    int ret = 0;
    while (!stop_requested_ && !impl_->failed) {
        ret = pcap_dispatch(pcap_handle_, 64, global_pcap_callback, reinterpret_cast<u_char*>(this));
        maintenance();
        if (ret < 0 || (!live && ret == 0)) break;
        if (live && ret == 0) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    impl_->running.store(false, std::memory_order_release);
    for (auto &worker : impl_->workers)
        if (worker->thread.joinable()) worker->thread.join();
    stats_.end_time = std::chrono::steady_clock::now();

    if (ret < 0 && ret != -2) { // -2 is expected break from pcap_breakloop
        std::cerr << Color::RED << "[!] Capture read error: " << pcap_geterr(pcap_handle_) << Color::RESET << "\n";
        finish_capture("capture_error");
        return false;
    }
    return finish_capture(impl_->failed ? "capture_error" :
                          (stop_requested_ || ret == -2 ? "interrupted" : "end_of_capture"));
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

    // Determine available datagram length (clamping Ethernet trailer padding or respecting snaplen truncation)
    size_t ip_captured = pkthdr->caplen - link_hdr_len;
    size_t ip_available = std::min(ip_captured, ip_total_len);
    if (ip_available < ip_hdr_len + tcp_hdr_len) return;

    size_t payload_len = ip_available - ip_hdr_len - tcp_hdr_len;
    const uint8_t *payload = packet + total_hdrs;

    impl_->current_ttl = ip_ttl;
    impl_->current_packet_time = pkthdr->ts.tv_sec;
    const uint64_t stamp = uint64_t{static_cast<uint64_t>(pkthdr->ts.tv_sec)} * 1000000 +
        static_cast<uint64_t>(pcap_handle_ && pcap_get_tstamp_precision(pcap_handle_) == PCAP_TSTAMP_PRECISION_NANO ?
                              pkthdr->ts.tv_usec / 1000 : pkthdr->ts.tv_usec);
    ingest_tcp_segment(key, seq, tcp_ptr[13], payload, payload_len, stamp, ip_captured < ip_total_len);
}

void CaptureEngine::maintenance() {
    // Offline expiry follows a nondecreasing capture-time watermark so replay
    // speed and timestamp regressions do not change timeout behavior. Live expiry
    // uses a monotonic clock to tolerate wall-clock adjustments and idle periods.
    impl_->now = options_.read_filename.empty() ? impl_->clock_now() : impl_->watermark_us / 1000000.0;
    if (impl_->now < impl_->next_sweep) return;
    impl_->next_sweep = impl_->now + 0.1;
    accumulator_->cleanup_stale_flows(static_cast<time_t>(impl_->now));
    for (auto it = impl_->connections.begin(); it != impl_->connections.end();) {
        if (impl_->now - it->second.idle_at > options_.connection_timeout_seconds) {
            impl_->emit(it->second, "timeout");
            accumulator_->forget_flow(it->first);
            accumulator_->forget_flow(reverse_flow(it->first));
            impl_->lru_order.erase(it->second.lru_it);
            it = impl_->connections.erase(it);
        } else ++it;
    }
}

size_t CaptureEngine::retained_connection_count() const noexcept { return impl_->connections.size(); }

bool CaptureEngine::finish_capture(const char *reason) {
    if (!options_.enable_ech) return !impl_->failed;
    accumulator_->flush_pending(reason);
    std::vector<Connection *> ordered;
    for (auto &[key, connection] : impl_->connections) ordered.push_back(&connection);
    std::sort(ordered.begin(), ordered.end(), [](const auto *a, const auto *b) { return a->id < b->id; });
    for (auto *connection : ordered) {
        impl_->emit(*connection, reason);
        accumulator_->forget_flow(connection->key);
        accumulator_->forget_flow(reverse_flow(connection->key));
    }
    impl_->connections.clear();
    impl_->lru_order.clear();
    return !impl_->failed;
}

void CaptureEngine::record_issue(const FlowKey &key, ParseStatus status, const char *reason,
                                  const uint8_t *prefix, size_t length) {
    auto it = impl_->connections.find(canonical_flow(key));
    if (it == impl_->connections.end() || it->second.emitted) return;
    auto &connection = it->second;
    const int direction = connection.direction(key);
    auto &issues = connection.issues[direction];
    if (std::any_of(issues.begin(), issues.end(), [reason](const auto &issue) { return issue.reason == reason; })) return;
    issues.push_back({status, reason});
    if (connection.direction_status[direction] == ParseStatus::NotExamined ||
        connection.direction_status[direction] == ParseStatus::Complete)
        connection.direction_status[direction] = status;
    if (prefix && length >= 6 && prefix[0] == TLS_RECORD_HANDSHAKE) {
        if (prefix[5] == TLS_HANDSHAKE_CLIENT_HELLO) {
            connection.orient(direction == 0);
            if (!connection.client) {
                ClientObservation observation;
                observation.status = status; observation.detail = reason;
                connection.client = std::move(observation);
            }
        } else if (prefix[5] == TLS_HANDSHAKE_SERVER_HELLO) {
            connection.orient(direction != 0);
        }
    }
    if (connection.tls_candidate && options_.verbose && !options_.quiet) {
        std::lock_guard<std::mutex> lock(impl_->stdout_mutex);
        print_parse_diagnostic(key, "TLS record");
        std::cout << "   │  status=" << parse_status_name(status) << " (" << reason << ")\n";
    }
}

void CaptureEngine::ingest_tcp_segment(const FlowKey &key, uint32_t seq, uint8_t flags,
                                        const uint8_t *payload, size_t length, uint64_t timestamp_us,
                                        bool truncated) {
    if (impl_->failed) return;
    if (!options_.enable_ech) {
        if (truncated) return;
        const time_t now = static_cast<time_t>(timestamp_us / 1000000);
        if (now > impl_->last_accumulator_cleanup) {
            impl_->last_accumulator_cleanup = now;
            accumulator_->cleanup_stale_flows(now);
        }
        if (flags & (TH_FIN | TH_RST)) {
            if (payload && length) {
                accumulator_->process_segment(key, seq, payload, length, now);
            }
            accumulator_->forget_flow(key);
            accumulator_->forget_flow(reverse_flow(key));
            return;
        }
        if ((flags & TH_SYN) && !(flags & TH_ACK)) {
            accumulator_->forget_flow(key);
            accumulator_->forget_flow(reverse_flow(key));
        }
        accumulator_->process_segment(key, seq + ((flags & TH_SYN) ? 1 : 0), payload, length, now);
        return;
    }
    impl_->watermark_us = std::max(impl_->watermark_us, timestamp_us);
    maintenance();
    const FlowKey canonical = canonical_flow(key);
    const int direction = key == canonical ? 0 : 1;
    const bool initial_syn = (flags & TH_SYN) && !(flags & TH_ACK);
    auto it = impl_->connections.find(canonical);
    // The same tuple can be reused. A new initial sequence number (or SYN after
    // closure) starts a new generation; a retransmitted opening SYN preserves it.
    if (it != impl_->connections.end() && initial_syn &&
        (it->second.closed || !it->second.syn_seq[direction] || *it->second.syn_seq[direction] != seq)) {
        accumulator_->invalidate_flow(canonical, "connection_replaced", true);
        accumulator_->invalidate_flow(reverse_flow(canonical), "connection_replaced", true);
        impl_->emit(it->second, "connection_replaced");
        accumulator_->forget_flow(canonical); accumulator_->forget_flow(reverse_flow(canonical));
        impl_->lru_order.erase(it->second.lru_it);
        impl_->connections.erase(it);
        it = impl_->connections.end();
    }
    const bool tls_start = payload && length && payload[0] >= 20 && payload[0] <= 24;
    if (it == impl_->connections.end()) {
        if (!(flags & TH_SYN) && !tls_start) return;
        if (impl_->connections.size() >= options_.max_connections) {
            // Bound all retained generations, including SYN hints and completion
            // markers. Evict by observation recency and summarize any TLS candidate.
            if (impl_->lru_order.empty()) return;
            FlowKey oldest_key = impl_->lru_order.back();
            auto oldest = impl_->connections.find(oldest_key);
            if (oldest == impl_->connections.end()) return;
            accumulator_->invalidate_flow(oldest->first, "capacity_limit", true);
            accumulator_->invalidate_flow(reverse_flow(oldest->first), "capacity_limit", true);
            impl_->emit(oldest->second, "capacity_limit");
            accumulator_->forget_flow(oldest->first); accumulator_->forget_flow(reverse_flow(oldest->first));
            impl_->lru_order.pop_back();
            impl_->connections.erase(oldest);
        }
        Connection connection;
        connection.key = canonical;
        connection.id = ++impl_->next_id;
        connection.first_us = timestamp_us;
        connection.lru_it = impl_->lru_order.insert(impl_->lru_order.begin(), canonical);
        it = impl_->connections.emplace(canonical, std::move(connection)).first;
    }
    auto &connection = it->second;
    connection.last_us = std::max(connection.last_us, timestamp_us);
    connection.idle_at = impl_->now;
    connection.recency = ++impl_->recency;
    impl_->lru_order.splice(impl_->lru_order.begin(), impl_->lru_order, connection.lru_it);
    if (initial_syn) connection.orient(direction == 0);
    if ((flags & TH_SYN) && !connection.syn_seq[direction]) {
        connection.syn_seq[direction] = seq;
        // SYN occupies one TCP sequence number before any payload, including
        // when data accompanies the SYN. Anchor framing to the first data byte.
        accumulator_->start_flow(key, seq + 1, static_cast<time_t>(impl_->now));
    }
    connection.tls_candidate |= tls_start;
    if (!connection.emitted && !connection.closed && (length || truncated)) {
        if (truncated) {
            record_issue(key, ParseStatus::Incomplete, "capture_truncated", payload, length);
            accumulator_->invalidate_flow(key, "capture_truncated");
        } else {
            accumulator_->process_segment(key, seq + ((flags & TH_SYN) ? 1 : 0), payload,
                                          length, static_cast<time_t>(impl_->now));
        }
    }
    if (flags & (TH_FIN | TH_RST)) {
        // A closing segment may carry the final hello bytes. Process its payload
        // first, then finalize pending observations without claiming ECH absence.
        accumulator_->invalidate_flow(key, "connection_closed", true);
        accumulator_->invalidate_flow(reverse_flow(key), "connection_closed", true);
        impl_->emit(connection, flags & TH_RST ? "rst" : "fin");
        connection.closed = true;
    }
    if (connection.emitted || connection.closed) {
        accumulator_->stop_flow(canonical);
        accumulator_->stop_flow(reverse_flow(canonical));
    }
}

void CaptureEngine::process_assembled_handshake(const FlowKey &key, const uint8_t *record, size_t length) {
    if (length < 5) return;
    if (!options_.enable_ech) {
        if (record[0] != TLS_RECORD_HANDSHAKE) return;
        if (!impl_->workers.empty()) {
            dispatch_handshake(key, record, length);
            return;
        }
        process_hello(key, record, length);
        return;
    }
    auto it = impl_->connections.find(canonical_flow(key));
    if (it == impl_->connections.end() || it->second.emitted || length < 5) return;
    auto &connection = it->second;
    const int direction = connection.direction(key);
    if (connection.protected_direction[direction]) return;
    if (connection.direction_status[direction] == ParseStatus::NotExamined)
        connection.direction_status[direction] = ParseStatus::Complete;
    if (record[0] == TLS_RECORD_CHANGE_CIPHER_SPEC) {
        if (length != 6 || record[5] != 1) {
            connection.protected_direction[direction] = true;
            record_issue(key, ParseStatus::Malformed, "invalid_change_cipher_spec", nullptr, 0);
            return;
        }
        // Offering TLS 1.3 alone does not establish the negotiated version:
        // TLS 1.2 encrypts Handshake-type records after CCS. Before the final
        // hello, accept a compatibility CCS only in a retry context or at the
        // exact SYN-anchored server start (no unseen earlier ServerHello).
        const bool server_start = connection.client_at_a &&
            direction == (*connection.client_at_a ? 1 : 0) && connection.syn_seq[direction] &&
            connection.tls13_offered;
        if (!server_start && !connection.hrr_seen) {
            connection.protected_direction[direction] = true;
            record_issue(key, ParseStatus::Unsupported, "ccs_plaintext_context_unknown", nullptr, 0);
        }
        return;
    }
    if (record[0] == 23) {
        // TLS 1.3 protected handshake messages use outer application_data type 23.
        // No decryption is attempted; encrypted bytes cannot be read as extensions.
        connection.protected_direction[direction] = true;
        record_issue(key, ParseStatus::Unsupported, "encrypted_record_before_final_hello", nullptr, 0);
        return;
    }
    if (record[0] != TLS_RECORD_HANDSHAKE) return;
    size_t offset = 5;
    while (offset < length && !connection.emitted) {
        const size_t available = length - offset;
        size_t message_length = available;
        bool complete = false;
        if (available >= 4) {
            message_length = 4 + (size_t{record[offset+1]} << 16) +
                (size_t{record[offset+2]} << 8) + record[offset+3];
            complete = message_length <= available;
        }
        const bool hello = record[offset] == 1 || record[offset] == 2;
        if (hello) {
            // Reuse the shared record parser for each message, bounded to this
            // message's bytes. Synthetic framing owns no data beyond the callback.
            const size_t count = complete ? message_length : available;
            std::vector<uint8_t> framed(record, record + 5);
            framed[3] = static_cast<uint8_t>(count >> 8); framed[4] = static_cast<uint8_t>(count);
            framed.insert(framed.end(), record + offset, record + offset + count);
            process_hello(key, framed.data(), framed.size());
        }
        if (!complete) {
            record_issue(key, ParseStatus::Unsupported, "handshake_spans_records", nullptr, 0);
            connection.protected_direction[direction] = true;
            return;
        }
        offset += message_length;
    }
}

void CaptureEngine::process_hello(const FlowKey &key,
                                                const uint8_t *record_data,
                                                size_t record_len) {
    if (record_len < 6 || record_data[0] != TLS_RECORD_HANDSHAKE) return;

    uint8_t hs_type = record_data[5]; // Byte 0..4 = Record Header, Byte 5 = Handshake Type
    if (!options_.enable_ech) {
        if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
            if (parse_client_hello(record_data, record_len, impl_->client_scratchpad)) {
                stats_.client_hellos++;
                JA3Fingerprint ja3 = compute_ja3(impl_->client_scratchpad);
                JA4Fingerprint ja4 = compute_ja4(impl_->client_scratchpad);
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
                if (options_.verbose) print_verbose_client(impl_->client_scratchpad, ja3, ja4);
            }
        } else if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
            if (parse_server_hello(record_data, record_len, impl_->server_scratchpad)) {
                if (impl_->server_scratchpad.is_hrr) return;
                stats_.server_hellos++;
                JA3Fingerprint ja3s = compute_ja3s(impl_->server_scratchpad);
                JA4Fingerprint ja4s = compute_ja4s(impl_->server_scratchpad);
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
                if (options_.verbose) print_verbose_server(impl_->server_scratchpad, ja3s, ja4s);
            }
        }
        return;
    }
    auto it = impl_->connections.find(canonical_flow(key));
    if (it == impl_->connections.end() || it->second.emitted) return;
    auto &connection = it->second;
    const int direction = connection.direction(key);

    if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
        connection.orient(direction == 0);
        if (parse_client_hello(record_data, record_len, impl_->client_scratchpad)) {
            const auto &client = impl_->client_scratchpad;
            analyze_ech(impl_->client_scratchpad.ech,
                        connection.hrr_seen ? HelloRole::AfterHrr :
                        (connection.syn_seq[direction] ? HelloRole::Initial : HelloRole::Unknown));
            stats_.client_hellos++;
            std::string ja3_str, ja4_str;
            if (impl_->json_fd >= 0) {
                ja3_str = compute_ja3(impl_->client_scratchpad).md5_hash;
                ja4_str = compute_ja4(impl_->client_scratchpad).full_fp;
            }
            if (connection.client && !connection.hrr_seen) connection.unexpected_client_hello = true;
            if (!connection.client) {
                // CH1 is the baseline across retries. Copy only visible outer
                // metadata; endpoint labels/secrets belong to the external harness.
                ClientObservation observation;
                observation.status = client.parse_status; observation.detail = client.parse_detail;
                observation.random = random_hex(client.outer_random);
                observation.sni = std::string(client.sni); observation.alpn = std::string(client.first_alpn);
                observation.ech = client.ech;
                observation.ja3 = std::move(ja3_str);
                observation.ja4 = std::move(ja4_str);
                connection.client = std::move(observation);
                connection.tls13_offered = std::find(client.supported_versions.begin(), client.supported_versions.end(), 0x0304)
                    != client.supported_versions.end();
            }

            if (!impl_->workers.empty()) {
                dispatch_handshake(key, record_data, record_len,
                    connection.hrr_seen ? HelloRole::AfterHrr :
                    (connection.syn_seq[direction] ? HelloRole::Initial : HelloRole::Unknown));
                return;
            }

            JA3Fingerprint ja3 = compute_ja3(impl_->client_scratchpad);
            JA4Fingerprint ja4 = compute_ja4(impl_->client_scratchpad);
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

            if (options_.verbose) {
                print_verbose_client(impl_->client_scratchpad, ja3, ja4);
            }
            if (!options_.interface_name.empty()) {
                std::cout << std::flush;
            }
        } else {
            const auto &client = impl_->client_scratchpad;
            if (!connection.client) {
                ClientObservation observation;
                observation.status = client.parse_status; observation.detail = client.parse_detail;
                observation.random = random_hex(client.outer_random); observation.ech = client.ech;
                connection.client = std::move(observation);
            }
            record_issue(key, client.parse_status, client.parse_detail, nullptr, 0);
            if (options_.verbose && !options_.quiet) {
                std::lock_guard<std::mutex> lock(impl_->stdout_mutex);
                print_parse_diagnostic(key, "ClientHello");
                print_ech_observation(client);
            }
        }
    } else if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
        connection.orient(direction != 0);
        if (parse_server_hello(record_data, record_len, impl_->server_scratchpad)) {
            const auto &server = impl_->server_scratchpad;
            if (server.is_hrr) {
                // HRR requests another ClientHello, so neither final-server
                // fingerprints nor a final summary are appropriate yet. Merely
                // recognizing HRR provides no real/GREASE or acceptance verdict.
                connection.hrr_seen = true;
                if (options_.verbose && !options_.quiet) {
                    std::lock_guard<std::mutex> lock(impl_->stdout_mutex);
                    std::cout << "[HRR] waiting for final ServerHello; sequence analysis unsupported\n";
                }
                if (!impl_->workers.empty()) {
                    dispatch_handshake(key, record_data, record_len);
                }
                return;
            }
            stats_.server_hellos++;
            std::string ja3s_str, ja4s_str;
            if (impl_->json_fd >= 0) {
                ja3s_str = compute_ja3s(impl_->server_scratchpad).md5_hash;
                ja4s_str = compute_ja4s(impl_->server_scratchpad).full_fp;
            }
            ServerObservation observation;
            observation.status = server.parse_status; observation.detail = server.parse_detail;
            observation.version = server.selected_version;
            observation.ja3s = std::move(ja3s_str); observation.ja4s = std::move(ja4s_str);
            connection.server = std::move(observation);
            // The initial-response study ends at the final ServerHello. Later
            // encrypted handshake/application traffic is outside this summary.
            impl_->emit(connection, "final_server_hello");

            if (!impl_->workers.empty()) {
                dispatch_handshake(key, record_data, record_len);
                return;
            }

            JA3Fingerprint ja3s = compute_ja3s(impl_->server_scratchpad);
            JA4Fingerprint ja4s = compute_ja4s(impl_->server_scratchpad);
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

            if (options_.verbose) {
                print_verbose_server(impl_->server_scratchpad, ja3s, ja4s);
            }
            if (!options_.interface_name.empty()) {
                std::cout << std::flush;
            }
        } else {
            const auto &server = impl_->server_scratchpad;
            ServerObservation observation;
            observation.status = server.parse_status; observation.detail = server.parse_detail;
            connection.server = std::move(observation);
            record_issue(key, server.parse_status, server.parse_detail, nullptr, 0);
        }
    }
}

void CaptureEngine::process_worker_hello(WorkerContext &ctx,
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
            if (options_.enable_ech) {
                analyze_ech(ctx.client_scratchpad.ech, job.hello_role);
            } else {
                stats_.client_hellos.fetch_add(1, std::memory_order_relaxed);
            }

            // PQ-TLS: evaluate share mode and store offer only when enabled
            PqtlsShareMode share_mode = PqtlsShareMode::NO_PQ_OFFERED;
            if (options_.enable_pqtls) {
                bool after_hrr = ctx.pqtls_offers.after_hrr(key);
                share_mode = pqtls_share_mode(ctx.client_scratchpad.pqtls, after_hrr);
                ctx.pqtls_offers.store(key, make_pqtls_offer(ctx.client_scratchpad.pqtls));
            }
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
                if (options_.enable_pqtls) {
                    print_pqtls_client(ctx.client_scratchpad, share_mode);
                }
            }
            if (!options_.interface_name.empty()) {
                std::cout << std::flush;
            }
        }
    } else if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
        if (parse_server_hello(record_data, record_len, ctx.server_scratchpad)) {
            // PQ-TLS: correlate with client offer only when enabled
            PqtlsPosture posture = PqtlsPosture::UNKNOWN_SERVER_SELECTION;
            if (options_.enable_pqtls) {
                PqtlsOffer offer = ctx.pqtls_offers.take(key, ctx.server_scratchpad.pqtls.is_hrr);
                posture = pqtls_posture(offer, ctx.server_scratchpad.pqtls,
                                        ctx.server_scratchpad.selected_version);
            }

            if (ctx.server_scratchpad.is_hrr) {
                if (options_.enable_pqtls && options_.verbose && !options_.quiet) {
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
                    std::cout << "\n" << Color::SERVER_BADGE << " "
                              << Color::BOLD << src_ip_str << ":" << src_p
                              << Color::RESET << Color::GRAY << " ──▶ " << Color::RESET
                              << Color::BOLD << dst_ip_str << ":" << dst_p << Color::RESET
                              << " " << Color::YELLOW << "[HelloRetryRequest]" << Color::RESET << "\n";
                    print_pqtls_server(ctx.server_scratchpad, posture);
                    if (!options_.interface_name.empty()) {
                        std::cout << std::flush;
                    }
                }
                return;
            }
            if (!options_.enable_ech) {
                stats_.server_hellos.fetch_add(1, std::memory_order_relaxed);
            }
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
                if (options_.enable_pqtls) {
                    print_pqtls_server(ctx.server_scratchpad, posture);
                }
            }
            if (!options_.interface_name.empty()) {
                std::cout << std::flush;
            }
        }
    }
}

} // namespace tlsfp
