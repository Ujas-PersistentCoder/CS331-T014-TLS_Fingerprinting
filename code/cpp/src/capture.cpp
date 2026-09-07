#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include "tlsfp/ja3.hpp"
#include "tlsfp/ja4.hpp"
#include <iostream>
#include <atomic>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <filesystem>
#include <unistd.h>
#include <initializer_list>
#include <chrono>
#include <cstring>
#include <cstdio>

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
    
    // Status Badges
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

std::string lookup_label(CaptureContext &ctx, FingerprintKind kind,
                         const std::string &hash) {
    if (!ctx.database_ready || !ctx.database) return "<database unavailable>";

    FingerprintRecord record;
    if (!ctx.database->lookup(kind, hash, record)) {
        if (!ctx.prompt_unknown) return "<unknown>";

        std::cout << Color::YELLOW << Color::BOLD << "[?]" << Color::RESET << " Unknown " 
                  << Color::CYAN << FingerprintDatabase::kind_name(kind) << Color::RESET
                  << " fingerprint " << Color::BOLD << hash << Color::RESET 
                  << ". Enter verified client/server name (empty to skip): " << std::flush;
        std::string name;
        if (!std::getline(std::cin, name) || name.empty()) return "<unknown>";
        if (!ctx.database->enroll(kind, hash, name)) return "<unknown>";
        record.name = name;
        record.category = "enrolled";
    }
    if (record.name.empty()) return "<unnamed>";
    if (record.category.empty()) return record.name;
    return record.name + " (" + record.category + ")";
}

// Helper: Print 16-bit integer in hex
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
    std::cout << "]\n" << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-Extensions]  " << Color::RESET << Color::DIM << "Count: " << Color::RESET << Color::BOLD << ch.extensions.size() << Color::RESET << " [";
    for (size_t i = 0; i < ch.extensions.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(ch.extensions[i]) << Color::RESET;
    }
    std::cout << "]\n" << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-Curves]      " << Color::RESET << Color::DIM << "Count: " << Color::RESET << Color::BOLD << ch.supported_groups.size() << Color::RESET << " [";
    for (size_t i = 0; i < ch.supported_groups.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(ch.supported_groups[i]) << Color::RESET;
    }
    std::cout << "]\n" << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-SigAlgs]     " << Color::RESET << Color::DIM << "Count: " << Color::RESET << Color::BOLD << ch.signature_algorithms.size() << Color::RESET << " [";
    for (size_t i = 0; i < ch.signature_algorithms.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(ch.signature_algorithms[i]) << Color::RESET;
    }
    std::cout << "]\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-PreHash-JA3] " << Color::RESET << Color::DIM << ja3.raw_string << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-PreHash-JA4b]" << Color::RESET << Color::DIM << ja4.raw_ja4_b << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-PreHash-JA4c]" << Color::RESET << Color::DIM << ja4.raw_ja4_c << Color::RESET << "\n";
}

void print_verbose_server(const ServerHelloData &sh, const JA3Fingerprint &ja3s, const JA4Fingerprint &ja4s) {
    std::cout << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-WireVersion] " << Color::RESET << Color::YELLOW << to_hex(sh.server_version) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-Negotiated]  " << Color::RESET << Color::YELLOW << to_hex(sh.selected_version) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-Cipher]      " << Color::RESET << Color::YELLOW << to_hex(sh.selected_cipher) << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-ALPN]        " << Color::RESET << (sh.first_alpn.empty() ? Color::GRAY : Color::MAGENTA)
<< (sh.first_alpn.empty()
        ? std::string_view("<none>")
        : sh.first_alpn)
<< Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-Extensions]  " << Color::RESET << Color::DIM << "Count: " << Color::RESET << Color::BOLD << sh.extensions.size() << Color::RESET << " [";
    for (size_t i = 0; i < sh.extensions.size(); ++i) {
        if (i > 0) std::cout << Color::GRAY << ", " << Color::RESET;
        std::cout << Color::YELLOW << to_hex(sh.extensions[i]) << Color::RESET;
    }
    std::cout << "]\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-PreHash-JA3S]" << Color::RESET << Color::DIM << ja3s.raw_string << Color::RESET << "\n"
              << Color::GRAY << "   │  " << Color::RESET << Color::CYAN << "[V-PreHash-JA4S]" << Color::RESET << Color::DIM << ja4s.raw_ja4_c << Color::RESET << "\n";
}

} // namespace

// Atomic handle for async-signal-safe termination
static std::atomic<pcap_t*> g_pcap_handle{nullptr};

// Signal handler to gracefully terminate the packet capture loop
void signal_handler(int) {
    pcap_t *handle = g_pcap_handle.load(std::memory_order_relaxed);
    if (handle != nullptr) {
        const char msg[] = "\n[*] Stopping capture gracefully...\n";
        auto bytes_written = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        (void)bytes_written;
        pcap_breakloop(handle);
    }
}


// Cleanup function to remove stale flows that haven't seen packets for a defined timeout period
void CaptureContext::cleanup_stale_flows(time_t current_time) {
    constexpr time_t TIMEOUT_SECONDS = 30;
    for (auto it = active_flows.begin(); it != active_flows.end();) {
        if (current_time - it->second.last_seen > TIMEOUT_SECONDS) {
            it = active_flows.erase(it);
        } else {
            ++it;
        }
    }
}

// Packet callback function invoked by libpcap for each captured packet. It handles link-layer demuxing, IP and TCP parsing, stream reassembly, TLS validation, and JA3/JA4 fingerprint extraction.
void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    CaptureContext *ctx = reinterpret_cast<CaptureContext*>(user_data);
    if (!ctx) return;

    ctx->total_packets++;

    // Periodic garbage collection sweep every 2048 packets
    if ((++ctx->packet_counter & 0x7FF) == 0) {
        ctx->cleanup_stale_flows(pkthdr->ts.tv_sec);
    }

    // Resolve Link-Layer Offset & Dynamic VLAN Peeling
    size_t link_header_len = 0;
    uint16_t ethertype = 0;

    switch (ctx->link_type) {
        case DLT_EN10MB: {
            link_header_len = 14;
            if (pkthdr->caplen < 14) return;
            ethertype = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];

            // Loop to peel single (0x8100) or nested (0x88A8 / 0x8100) VLAN tags
            while ((ethertype == 0x8100 || ethertype == 0x88A8) && 
                   pkthdr->caplen >= link_header_len + 4) {
                ethertype = (static_cast<uint16_t>(packet[link_header_len + 2]) << 8) | 
                             packet[link_header_len + 3];
                link_header_len += 4;
            }
            break;
        }
        case DLT_LINUX_SLL2: {
            if (pkthdr->caplen < 20) return;
            link_header_len = 20;
            ethertype = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
            break;
        }
        case DLT_LINUX_SLL: {
            if (pkthdr->caplen < 16) return;
            link_header_len = 16;
            ethertype = (static_cast<uint16_t>(packet[14]) << 8) | packet[15];
            break;
        }
        case DLT_NULL: {
            if (pkthdr->caplen < 4) return;
            link_header_len = 4;
            uint32_t family = 0;
            std::memcpy(&family, packet, 4);
            ethertype = (family == 2 /* PF_INET */) ? 0x0800 : 0x86DD;
            break;
        }
        case DLT_RAW: {
            link_header_len = 0;
            if (pkthdr->caplen < 1) return;
            ethertype = ((packet[0] >> 4) == 4) ? 0x0800 : 0x86DD;
            break;
        }
        default:
            return;
    }

    // Alignment-Safe IP Demuxing
    if (pkthdr->caplen < link_header_len + 1) return;

    size_t ip_header_len = 0;
    FlowKey key{};

    if (ethertype == 0x0800) { // IPv4
        if (pkthdr->caplen < link_header_len + 20) return;
        const uint8_t *ip_ptr = packet + link_header_len;

        uint8_t ver_ihl = ip_ptr[0];
        if ((ver_ihl >> 4) != 4) return;

        ip_header_len = static_cast<size_t>(ver_ihl & 0x0F) * 4;
        if (ip_header_len < 20 || pkthdr->caplen < link_header_len + ip_header_len) return;

        uint8_t protocol = ip_ptr[9];
        if (protocol != IPPROTO_TCP) return;

        key.ip_version = 4;
        std::memcpy(&key.src_ip.v4.s_addr, ip_ptr + 12, 4);
        std::memcpy(&key.dst_ip.v4.s_addr, ip_ptr + 16, 4);

    } else if (ethertype == 0x86DD) { // IPv6
        if (pkthdr->caplen < link_header_len + 40) return;
        const uint8_t *ip6_ptr = packet + link_header_len;

        if ((ip6_ptr[0] >> 4) != 6) return;

        uint8_t next_proto = ip6_ptr[6];
        size_t ext_offset = link_header_len + 40;

        // Peel basic extension headers (Hop-by-Hop: 0, Routing: 43)
        while ((next_proto == 0 || next_proto == 43) && pkthdr->caplen >= ext_offset + 8) {
            next_proto = packet[ext_offset];
            ext_offset += static_cast<size_t>(packet[ext_offset + 1] + 1) * 8;
        }

        if (next_proto != IPPROTO_TCP) return;

        ip_header_len = ext_offset - link_header_len;
        if (pkthdr->caplen < link_header_len + ip_header_len) return;

        key.ip_version = 6;
        std::memcpy(&key.src_ip.v6, ip6_ptr + 8, 16);
        std::memcpy(&key.dst_ip.v6, ip6_ptr + 24, 16);

    } else {
        return; // Non-IP traffic (ARP, STP, etc.)
    }

    // TCP Inspection
    if (pkthdr->caplen < link_header_len + ip_header_len + 20) return;
    const uint8_t *tcp_ptr = packet + link_header_len + ip_header_len;

    // Safely extract 16-bit ports in network byte order via memcpy
    std::memcpy(&key.src_port, tcp_ptr + 0, 2);
    std::memcpy(&key.dst_port, tcp_ptr + 2, 2);

    // Safely extract 32-bit sequence number (Network Byte Order -> Host Order)
    uint32_t raw_seq = 0;
    std::memcpy(&raw_seq, tcp_ptr + 4, 4);
    uint32_t seq = ntohl(raw_seq);

    // Data Offset sits in the upper 4 bits of byte 12 (measured in 32-bit / 4-byte words)
    size_t tcp_header_len = static_cast<size_t>(tcp_ptr[12] >> 4) * 4;
    if (tcp_header_len < 20 || pkthdr->caplen < link_header_len + ip_header_len + tcp_header_len) {
        return;
    }

    // Payload Bounds Check
    size_t header_total_len = link_header_len + ip_header_len + tcp_header_len;
    if (pkthdr->caplen <= header_total_len) return; // Discard pure ACKs, SYNs, etc.

    size_t payload_len = pkthdr->caplen - header_total_len;
    const uint8_t *payload = packet + header_total_len;

    // Strip TLS 1.3 Middlebox Compatibility ChangeCipherSpec (0x14 0x03 0x03 0x00 0x01 0x01)
    // When a HelloRetryRequest occurs, clients prepend this 6-byte record before the 2nd ClientHello
    if (payload_len >= 6 && 
        payload[0] == 0x14 && 
        payload[1] == 0x03 && 
        payload[2] == 0x03 && 
        payload[3] == 0x00 && 
        payload[4] == 0x01) {
        payload += 6;
        payload_len -= 6;
        seq += 6; // Advance sequence anchor to match stripped payload
    }

    if (payload_len == 0) return;

    // Flow Lookup & Fast Non-TLS Filter
    auto it = ctx->active_flows.find(key);
    if (it == ctx->active_flows.end()) {
        // Untracked stream: First payload byte MUST be TLS Handshake (0x16)
        if (payload[0] != 0x16) return;
        it = ctx->active_flows.emplace(key, StreamBuffer{}).first;
    }

    StreamBuffer &buf = it->second;
    buf.last_seen = pkthdr->ts.tv_sec;

    if (!buf.seq_initialized) {
        buf.next_seq = seq;
        buf.seq_initialized = true;
    }

    // RFC 1982 Modular Sequence Arithmetic (Safe Unsigned Distance)
    uint32_t diff = seq - buf.next_seq;

    if (diff > 0x80000000U) {
        // Modular negative: packet is an overlapping retransmission (seq < buf.next_seq)
        uint32_t overlap = buf.next_seq - seq;
        if (overlap >= payload_len) return; // Entire segment already absorbed
        payload += overlap;
        payload_len -= overlap;
    } else if (diff > 0) {
        // Modular positive: packet has a gap (out-of-order segment arrived early)
        ctx->active_flows.erase(key);
        return;
    }

    // Guard against reassembly buffer overflow (4096 bytes max)
    if (buf.len + payload_len > StreamBuffer::MAX_BUF_SIZE) {
        ctx->active_flows.erase(key);
        return;
    }

    // Append newly arrived contiguous payload slice
    std::memcpy(buf.bytes + buf.len, payload, payload_len);
    buf.len += static_cast<uint16_t>(payload_len);
    buf.next_seq += static_cast<uint32_t>(payload_len);

    // TLS Record Layer Validation
    if (buf.len < 5) return; // Wait until at least the 5-byte TLS record header is assembled

    uint8_t record_type  = buf.bytes[0];
    uint8_t major_ver    = buf.bytes[1];
    uint8_t minor_ver    = buf.bytes[2];
    uint16_t tls_rec_len = (static_cast<uint16_t>(buf.bytes[3]) << 8) | buf.bytes[4];

    bool is_valid_tls = (record_type == 0x16) && 
                        (major_ver == 0x03) && 
                        (minor_ver <= 0x04) && 
                        (tls_rec_len <= 16384);

    if (!is_valid_tls) {
        ctx->active_flows.erase(key);
        return;
    }

    size_t total_record_len = 5 + tls_rec_len;
    if (buf.len < total_record_len) {
        return; // Segment incomplete, await remaining fragments
    }

    if (tls_rec_len < 4) {
        ctx->active_flows.erase(key);
        return;
    }

    // Handshake Processing
    uint8_t handshake_type = buf.bytes[5];
    char src_ip_str[INET6_ADDRSTRLEN], dst_ip_str[INET6_ADDRSTRLEN];
    if (key.ip_version == 4) {
        inet_ntop(AF_INET, &key.src_ip.v4, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET, &key.dst_ip.v4, dst_ip_str, sizeof(dst_ip_str));
    } else {
        inet_ntop(AF_INET6, &key.src_ip.v6, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET6, &key.dst_ip.v6, dst_ip_str, sizeof(dst_ip_str));
    }

    if (handshake_type == 0x01) {
        ctx->client_scratchpad.clear();
        if (parse_client_hello(buf.bytes, total_record_len, ctx->client_scratchpad)) {
            ctx->client_hellos++; // Always track count for benchmark metrics
            JA3Fingerprint ja3 = compute_ja3(ctx->client_scratchpad);
            JA4Fingerprint ja4 = compute_ja4(ctx->client_scratchpad);

            // In quiet mode (-q), completely bypass terminal prints & Redis network lookups
            if (!ctx->quiet) {
                const std::string ja3_match = lookup_label(*ctx, FingerprintKind::JA3, ja3.md5_hash);
                const std::string ja4_match = lookup_label(*ctx, FingerprintKind::JA4, ja4.full_fp);

                std::cout << "\n"
                << Color::CLIENT_BADGE << " "
                << Color::BOLD << "Captured ClientHello"
                << Color::RESET << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "Flow          "
                << Color::RESET
                << Color::CYAN << "[" << src_ip_str << "]:" << ntohs(key.src_port)
                << Color::GRAY << " → "
                << Color::CYAN << "[" << dst_ip_str << "]:" << ntohs(key.dst_port)
                << Color::RESET << "\n"
                << Color::GRAY << "  └─ " << Color::RESET
                << Color::BOLD << "Reassembled   "
                << Color::RESET
                << total_record_len << " bytes\n";

                if (ctx->verbose) {
                    print_verbose_client(ctx->client_scratchpad, ja3, ja4);
                }

                std::cout << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "SNI           "
                << Color::RESET
                << (ctx->client_scratchpad.has_sni
                        ? ctx->client_scratchpad.sni
                        : "<none>")
                << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA3 String     "
                << Color::RESET
                << Color::MAGENTA << ja3.raw_string
                << Color::RESET << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA3 Hash       "
                << Color::RESET
                << Color::MAGENTA << ja3.md5_hash
                << Color::RESET << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA3 Match      "
                << Color::RESET
                << Color::GREEN << ja3_match
                << Color::RESET << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA4            "
                << Color::RESET
                << Color::MAGENTA << ja4.full_fp
                << Color::RESET << "\n"
                << Color::GRAY << "  └─ " << Color::RESET
                << Color::BOLD << "JA4 Match      "
                << Color::RESET
                << Color::GREEN << ja4_match
                << Color::RESET << "\n";
            }

            if (ctx->dumper) {
                pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
            }
        }
    } else if (handshake_type == 0x02) {
        ctx->server_scratchpad.clear();
        if (parse_server_hello(buf.bytes, total_record_len, ctx->server_scratchpad)) {
            ctx->server_hellos++; // Always track count for benchmark metrics
            JA3Fingerprint ja3s = compute_ja3s(ctx->server_scratchpad);
            JA4Fingerprint ja4s = compute_ja4s(ctx->server_scratchpad);

            // In quiet mode (-q), completely bypass terminal prints & Redis network lookups
            if (!ctx->quiet) {
                const std::string ja3s_match = lookup_label(*ctx, FingerprintKind::JA3S, ja3s.md5_hash);
                const std::string ja4s_match = lookup_label(*ctx, FingerprintKind::JA4S, ja4s.full_fp);

                std::cout << "\n"
                        << Color::SERVER_BADGE << " "
                        << Color::BOLD << "Captured ServerHello"
                        << Color::RESET << "\n"
                        << Color::GRAY << "  ├─ " << Color::RESET
                        << Color::BOLD << "Flow          "
                        << Color::RESET
                        << Color::CYAN << "[" << src_ip_str << "]:" << ntohs(key.src_port)
                        << Color::GRAY << " → "
                        << Color::CYAN << "[" << dst_ip_str << "]:" << ntohs(key.dst_port)
                        << Color::RESET << "\n"
                        << Color::GRAY << "  └─ " << Color::RESET
                        << Color::BOLD << "Reassembled   "
                        << Color::RESET
                        << total_record_len << " bytes\n";

                if (ctx->verbose) {
                    print_verbose_server(ctx->server_scratchpad, ja3s, ja4s);
                }

                std::cout << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA3S String    "
                << Color::RESET
                << Color::MAGENTA << ja3s.raw_string
                << Color::RESET << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA3S Hash      "
                << Color::RESET
                << Color::MAGENTA << ja3s.md5_hash
                << Color::RESET << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA3S Match     "
                << Color::RESET
                << Color::GREEN << ja3s_match
                << Color::RESET << "\n"
                << Color::GRAY << "  ├─ " << Color::RESET
                << Color::BOLD << "JA4S           "
                << Color::RESET
                << Color::MAGENTA << ja4s.full_fp
                << Color::RESET << "\n"
                << Color::GRAY << "  └─ " << Color::RESET
                << Color::BOLD << "JA4S Match     "
                << Color::RESET
                << Color::GREEN << ja4s_match
                << Color::RESET << "\n";
            }

            if (ctx->dumper) {
                pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
            }
        }
    }
    ctx->active_flows.erase(it); // Remove flow after processing handshake 
}

bool start_capture(const CaptureOptions &opts) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = nullptr;

    if (!opts.read_filename.empty()) {
        handle = pcap_open_offline(opts.read_filename.c_str(), errbuf);
        if (!handle) {
            std::cerr << "[-] Error opening offline PCAP file '" 
                      << opts.read_filename << "': " << errbuf << "\n";
            return false;
        }
        std::cout << Color::CYAN << Color::BOLD
          << "[>] Offline capture"
          << Color::RESET
          << "  " << Color::GRAY
          << opts.read_filename
          << Color::RESET << "\n";
    } else {
        if (opts.interface_name.empty()) {
            std::cerr << "[-] Error: Interface name must be specified for live capture.\n";
            return false;
        }
        // Snaplen 65535 prevents truncation of TSO/GRO jumbo frames
        handle = pcap_open_live(opts.interface_name.c_str(), 65535, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "[-] Error opening live interface '" 
                      << opts.interface_name << "': " << errbuf << "\n";
            return false;
        }
        if (!opts.quiet) {
            std::cout << Color::GREEN << Color::BOLD
          << "[✓] Live capture started"
          << Color::RESET
          << "  Interface: "
          << Color::CYAN << opts.interface_name
          << Color::RESET << "\n";
        }
    }

    g_pcap_handle.store(handle, std::memory_order_relaxed);

    const std::string &filter_str = opts.bpf_filter.empty() ? "tcp" : opts.bpf_filter;
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
        if (pcap_setfilter(handle, &fp) != 0) {
            std::cerr << "[-] Warning: Failed to attach BPF filter: " << pcap_geterr(handle) << "\n";
        }
        pcap_freecode(&fp);
    } else {
        std::cerr << "[-] Warning: Failed to compile BPF filter '" << filter_str 
                  << "': " << pcap_geterr(handle) << "\n";
    }

    CaptureContext ctx;
    ctx.link_type = pcap_datalink(handle);
    ctx.prompt_unknown = opts.prompt_unknown;
    ctx.quiet = opts.quiet;
    ctx.verbose = opts.verbose;
    if (!opts.quiet) {
        std::cout << Color::GREEN << Color::BOLD
          << "[✓] Capture initialized"
          << Color::RESET
          << "  Datalink: "
          << Color::CYAN << ctx.link_type
          << Color::RESET << "\n";

        // Connect to Redis and load seeds ONLY in interactive/standard mode
        ctx.database = std::make_unique<FingerprintDatabase>(opts.redis_config);
        if (!ctx.database->connect()) {
            std::cerr << "[-] Warning: Redis database unavailable; fingerprints will be reported as unknown.\n";
        } else {
            const std::string seed_path = resolve_data_file(
                opts.seed_filename, {"../db/seed_fingerprints.json", "../../db/seed_fingerprints.json"});
            const std::string manifest_path = resolve_data_file(
                opts.manifest_filename, {"../db/capture_manifest.json", "../../db/capture_manifest.json"});
            const std::string legacy_path = resolve_data_file(
                "code/python/fingerprints.json", {"../python/fingerprints.json", "../../python/fingerprints.json"});
            const std::size_t loaded = ctx.database->load_seed_files(seed_path, manifest_path) +
                ctx.database->load_legacy_ja3_file(legacy_path);
            if (loaded == 0) {
                std::cerr << "[-] Warning: No fingerprint seed entries loaded from " << seed_path << ".\n";
            } else {
                ctx.database_ready = true;
                std::cout << "[*] Redis fingerprint database loaded: " << loaded << " entries\n";
            }
        }
    }

    if (!opts.write_filename.empty()) {
        ctx.dumper = pcap_dump_open(handle, opts.write_filename.c_str());
        if (!ctx.dumper) {
            std::cerr << "[-] Warning: Could not open output PCAP for writing: " 
                      << pcap_geterr(handle) << "\n";
        } else {
            std::cout << Color::CYAN << Color::BOLD
          << "[→] Mirroring handshakes"
          << Color::RESET
          << "  Output: "
          << Color::CYAN << opts.write_filename
          << Color::RESET << "\n";
        }
    }

    // Measure strictly the packet ingestion and dissection loop
    ctx.start_time = std::chrono::steady_clock::now();

    int loop_status = pcap_loop(handle, 0, packet_callback, reinterpret_cast<u_char*>(&ctx));
    // Diagnostics & Clean Teardown
    auto end_time = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end_time - ctx.start_time).count();
    double elapsed_sec = elapsed_ms / 1000.0;
    double pps = (elapsed_sec > 0.0) ? (static_cast<double>(ctx.total_packets) / elapsed_sec) : 0.0;
    bool success = (loop_status != -1);
    if (opts.quiet) {
        std::cout << "\n"
          << Color::CYAN << Color::BOLD
          << "╭──────────────────── TLSFP Benchmark ────────────────────╮"
          << Color::RESET << "\n"
          << Color::BOLD << "│ " << Color::RESET
          << "Total Packets Scanned : "
          << Color::CYAN << ctx.total_packets
          << Color::RESET << "\n"
          << Color::BOLD << "│ " << Color::RESET
          << "ClientHellos Found    : "
          << Color::CYAN << ctx.client_hellos
          << Color::RESET << "\n"
          << Color::BOLD << "│ " << Color::RESET
          << "ServerHellos Found    : "
          << Color::CYAN << ctx.server_hellos
          << Color::RESET << "\n"
          << Color::BOLD << "│ " << Color::RESET
          << "Execution Time        : "
          << Color::CYAN << elapsed_ms
          << Color::RESET << " ms\n"
          << Color::BOLD << "│ " << Color::RESET
          << "Packet Throughput     : "
          << Color::GREEN
          << static_cast<uint64_t>(pps)
          << Color::RESET << " pkts/sec\n"
          << Color::CYAN << Color::BOLD
          << "╰───────────────────────────────────────────────────────────╯"
          << Color::RESET << "\n";
    } else {
        if (loop_status == -1) {
            std::cerr << "[-] pcap_loop aborted due to error: " << pcap_geterr(handle) << "\n";
            success = false;
        } else if (loop_status == -2) {
            std::cout << Color::YELLOW << Color::BOLD
          << "[!] Capture terminated by signal."
          << Color::RESET << "\n";
        } else {
            std::cout << Color::GREEN << Color::BOLD
          << "[✓] Reached end of capture file."
          << Color::RESET << "\n";
        }
    }

    if (ctx.dumper) {
        pcap_dump_flush(ctx.dumper);
        pcap_dump_close(ctx.dumper);
    }

    pcap_close(handle);
    g_pcap_handle.store(nullptr, std::memory_order_relaxed);
    return success;
}

}