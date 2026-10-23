#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/ja4.hpp"
#include "tlsfp/db.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <filesystem>

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

void print_verbose_client(const ClientHelloData &ch) {
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
    std::cout << "]\n";
}

void print_verbose_server(const ServerHelloData &sh) {
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
    std::cout << "]\n";
}

} // anonymous namespace

struct CaptureEngine::Impl {
    ClientHelloData client_scratchpad;
    ServerHelloData server_scratchpad;
    std::unique_ptr<FingerprintDatabase> db;

    std::string resolve_label(FingerprintKind kind, const std::string &hash, bool prompt_unknown) {
        if (!db) return "<unknown>";

        FingerprintRecord record;
        if (db->lookup(kind, hash, record)) {
            if (record.name.empty()) return "<unnamed>";
            if (record.category.empty()) return record.name;
            return record.name + " (" + record.category + ")";
        }

        if (prompt_unknown) {
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
    : options_(std::move(options)),
      impl_(std::make_unique<Impl>()) {
    accumulator_ = std::make_unique<TwoTierAccumulator>(
        [this](const FlowKey &key, const uint8_t *record, size_t len) {
            this->process_assembled_handshake(key, record, len);
        }
    );
}

CaptureEngine::~CaptureEngine() {
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
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
            options_.seed_filename, {"code/db/seed_fingerprints.json", "../db/seed_fingerprints.json", "../../code/db/seed_fingerprints.json"});
        const std::string manifest_path = resolve_data_file(
            options_.manifest_filename, {"code/db/capture_manifest.json", "../db/capture_manifest.json", "../../code/db/capture_manifest.json"});
        const std::string legacy_path = resolve_data_file(
            options_.legacy_filename, {"code/python/fingerprints.json", "../python/fingerprints.json", "../../code/python/fingerprints.json"});

        if (impl_->db->connect()) {
            std::cout << Color::GREEN << "[+] Connected to Redis on " 
                      << options_.redis_host << ":" << options_.redis_port << Color::RESET << "\n";
        } else {
            std::cout << Color::DIM << "[*] Redis offline, using in-memory catalog from " 
                      << seed_path << Color::RESET << "\n";
        }
        std::size_t loaded = impl_->db->load_seed_files(seed_path, manifest_path) +
                             impl_->db->load_legacy_ja3_file(legacy_path);
        std::cout << Color::DIM << "[*] Loaded " << loaded << " fingerprint catalog records." << Color::RESET << "\n";
    }

    return true;
}

static void global_pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    auto *engine = reinterpret_cast<CaptureEngine*>(user);
    engine->handle_packet(h, bytes);
}

bool CaptureEngine::run() {
    if (!setup_pcap()) return false;

    stats_.start_time = std::chrono::steady_clock::now();

    pcap_loop(pcap_handle_, 0, global_pcap_callback, reinterpret_cast<u_char*>(this));

    stats_.end_time = std::chrono::steady_clock::now();
    return true;
}

void CaptureEngine::handle_packet(const struct pcap_pkthdr *pkthdr, const uint8_t *packet) {
    stats_.total_packets++;

    size_t link_hdr_len = 0;
    uint16_t ethertype = 0;

    switch (datalink_type_) {
        case DLT_EN10MB: {
            if (pkthdr->caplen < 14) return;
            link_hdr_len = 14;
            ethertype = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];
            if (ethertype == 0x8100) { // 802.1Q VLAN
                if (pkthdr->caplen < 18) return;
                link_hdr_len = 18;
                ethertype = (static_cast<uint16_t>(packet[16]) << 8) | packet[17];
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

    if (ethertype == 0x0800) { // IPv4
        if (pkthdr->caplen < link_hdr_len + 20) return;
        const uint8_t *ip_ptr = packet + link_hdr_len;
        if ((ip_ptr[0] >> 4) != 4) return;

        ip_hdr_len = static_cast<size_t>(ip_ptr[0] & 0x0F) * 4;
        if (ip_hdr_len < 20 || pkthdr->caplen < link_hdr_len + ip_hdr_len) return;
        if (ip_ptr[9] != IPPROTO_TCP) return;

        key.ip_version = 4;
        std::memcpy(&key.src_ip.v4.s_addr, ip_ptr + 12, 4);
        std::memcpy(&key.dst_ip.v4.s_addr, ip_ptr + 16, 4);
    } else if (ethertype == 0x86DD) { // IPv6
        if (pkthdr->caplen < link_hdr_len + 40) return;
        const uint8_t *ip6_ptr = packet + link_hdr_len;
        if ((ip6_ptr[0] >> 4) != 6) return;

        uint8_t next_proto = ip6_ptr[6];
        size_t ext_offset = link_hdr_len + 40;
        while ((next_proto == 0 || next_proto == 43) && pkthdr->caplen >= ext_offset + 8) {
            next_proto = packet[ext_offset];
            ext_offset += static_cast<size_t>(packet[ext_offset + 1] + 1) * 8;
        }
        if (next_proto != IPPROTO_TCP) return;

        ip_hdr_len = ext_offset - link_hdr_len;
        if (pkthdr->caplen < link_hdr_len + ip_hdr_len) return;

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
    if (tcp_hdr_len < 20 || pkthdr->caplen < link_hdr_len + ip_hdr_len + tcp_hdr_len) return;

    size_t total_hdrs = link_hdr_len + ip_hdr_len + tcp_hdr_len;
    if (pkthdr->caplen <= total_hdrs) return; // Pure ACK, SYN, etc.

    size_t payload_len = pkthdr->caplen - total_hdrs;
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
    accumulator_->process_segment(key, seq, payload, payload_len, pkthdr->ts.tv_sec);
}

void CaptureEngine::process_assembled_handshake(const FlowKey &key, 
                                                const uint8_t *record_data, 
                                                size_t record_len) {
    if (record_len < 6) return;

    uint8_t hs_type = record_data[5]; // Byte 0..4 = Record Header, Byte 5 = Handshake Type

    if (hs_type == TLS_HANDSHAKE_CLIENT_HELLO) {
        stats_.client_hellos++;
        if (parse_client_hello(record_data, record_len, impl_->client_scratchpad)) {
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
                print_verbose_client(impl_->client_scratchpad);
            }
            std::cout << std::flush;
        }
    } else if (hs_type == TLS_HANDSHAKE_SERVER_HELLO) {
        stats_.server_hellos++;
        if (parse_server_hello(record_data, record_len, impl_->server_scratchpad)) {
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
                print_verbose_server(impl_->server_scratchpad);
            }
            std::cout << std::flush;
        }
    }
}

} // namespace tlsfp
