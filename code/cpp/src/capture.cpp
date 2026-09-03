#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include "tlsfp/ja3.hpp"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

namespace tlsfp {

static pcap_t *g_pcap_handle = nullptr;

void signal_handler(int signum) {
    if (g_pcap_handle != nullptr) {
        std::cout << "\n[*] Caught signal " << signum << ", stopping capture gracefully...\n";
        pcap_breakloop(g_pcap_handle);
    }
}

void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    CaptureContext *ctx = reinterpret_cast<CaptureContext*>(user_data);
    if (!ctx) return;

    // 1. Resolve Link-Layer Offset dynamically
    size_t link_header_len = 0;
    switch (ctx->link_type) {
        case DLT_EN10MB:      // Standard Ethernet / Wi-Fi (14 bytes)
            link_header_len = 14;
            break;
        case DLT_LINUX_SLL2:  // Linux Cooked v2 (WSL / tcpdump -i any) (20 bytes)
            link_header_len = 20;
            break;
        case DLT_LINUX_SLL:   // Linux Cooked v1 (16 bytes)
            link_header_len = 16;
            break;
        case DLT_NULL:        // BSD / macOS Loopback (4 bytes)
            link_header_len = 4;
            break;
        case DLT_RAW:         // Raw IP (VPN / tun interfaces) (0 bytes)
            link_header_len = 0;
            break;
        default:
            return; // Unsupported link-layer
    }

    // Ensure packet has at least 1 byte after link layer to check the IP version nibble
    if (pkthdr->caplen < link_header_len + 1) {
        return;
    }

    // 2. Determine IP Version (first 4 bits of the IP header)
    uint8_t ip_version = (packet[link_header_len] >> 4);
    size_t ip_header_len = 0;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    if (ip_version == 4) {
        // --- IPv4 Path ---
        if (pkthdr->caplen < link_header_len + sizeof(struct ip)) return;
        const struct ip *ip_hdr = reinterpret_cast<const struct ip *>(packet + link_header_len);

        if (ip_hdr->ip_p != IPPROTO_TCP) return; // Verify TCP protocol

        ip_header_len = ip_hdr->ip_hl * 4;
        if (ip_header_len < 20) return;

        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    } else if (ip_version == 6) {
        // --- IPv6 Path ---
        if (pkthdr->caplen < link_header_len + sizeof(struct ip6_hdr)) return;
        const struct ip6_hdr *ip6_hdr = reinterpret_cast<const struct ip6_hdr *>(packet + link_header_len);

        if (ip6_hdr->ip6_nxt != IPPROTO_TCP) return; // Verify TCP protocol

        ip_header_len = sizeof(struct ip6_hdr); // Fixed 40 bytes for standard IPv6

        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

    } else {
        return; // Non-IP packet
    }

    // 3. Inspect TCP Header
    if (pkthdr->caplen < link_header_len + ip_header_len + sizeof(struct tcphdr)) {
        return;
    }

    const struct tcphdr *tcp_hdr = reinterpret_cast<const struct tcphdr *>(packet + link_header_len + ip_header_len);
    size_t tcp_header_len = tcp_hdr->th_off * 4;
    if (tcp_header_len < 20) {
        return;
    }

    // 4. Calculate Payload Offset & Length
    size_t header_total_len = link_header_len + ip_header_len + tcp_header_len;
    if (pkthdr->caplen <= header_total_len) {
        return; // Pure TCP ACK/SYN/FIN without data
    }

    size_t payload_len = pkthdr->caplen - header_total_len;
    const uint8_t *payload = packet + header_total_len;

    // 5. Validate TLS Record (5 bytes Record Header + 4 bytes Handshake Header = 9 bytes)
    if (payload_len < 9 || payload[0] != 0x16) {
        return; // Not a TLS Handshake record
    }

    uint8_t handshake_type = payload[5];

    // 6. Process ClientHello (0x01) or ServerHello (0x02)
    if (handshake_type == 0x01 || handshake_type == 0x02) {
        // Save matched frame immediately to PCAP if -w was passed
        if (ctx->dumper != nullptr) {
            pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
            pcap_dump_flush(ctx->dumper);
        }

        uint16_t src_port = ntohs(tcp_hdr->th_sport);
        uint16_t dst_port = ntohs(tcp_hdr->th_dport);

        std::cout << "[+] Captured " << (handshake_type == 0x01 ? "ClientHello" : "ServerHello")
                  << " | Flow: [" << src_ip << "]:" << src_port
                  << " -> [" << dst_ip << "]:" << dst_port
                  << " | Payload Size: " << payload_len << " bytes\n";

        // Zero-copy handoff to parser (activate when parser.cpp is ready)
        // Zero-copy handoff using recycled scratchpads
        if (handshake_type == 0x01) {
            ctx->client_scratchpad.clear();
            if (parse_client_hello(payload, payload_len, ctx->client_scratchpad)) {
                JA3Fingerprint ja3 = compute_ja3(ctx->client_scratchpad);
                
                std::cout << "  ├─ [SNI] " << (ctx->client_scratchpad.has_sni ? ctx->client_scratchpad.sni : "<none>") << "\n"
                          << "  ├─ [JA3 String] " << ja3.raw_string << "\n"
                          << "  └─ [JA3 Hash]   " << ja3.md5_hash << "\n";
            }
        } else if (handshake_type == 0x02) {
            ctx->server_scratchpad.clear();
            if (parse_server_hello(payload, payload_len, ctx->server_scratchpad)) {
                JA3Fingerprint ja3s = compute_ja3s(ctx->server_scratchpad);

                std::cout << "  ├─ [JA3S String] " << ja3s.raw_string << "\n"
                          << "  └─ [JA3S Hash]   " << ja3s.md5_hash << "\n";
            }
        }
    }
}

bool start_capture(const CaptureOptions &opts) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = nullptr;

    if (!opts.read_filename.empty()) {
        handle = pcap_open_offline(opts.read_filename.c_str(), errbuf);
    } else {
        handle = pcap_open_live(opts.interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    }

    if (!handle) {
        std::cerr << "[-] Error opening pcap target: " << errbuf << "\n";
        return false;
    }

    g_pcap_handle = handle;

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 443", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    } else {
        std::cerr << "[-] Warning: Failed to set BPF filter 'tcp port 443'\n";
    }

    CaptureContext ctx;
    ctx.link_type = pcap_datalink(handle);
    std::cout << "[*] Capture initialized. Datalink type: " << ctx.link_type << "\n";

    if (!opts.write_filename.empty()) {
        ctx.dumper = pcap_dump_open(handle, opts.write_filename.c_str());
        if (!ctx.dumper) {
            std::cerr << "[-] Warning: Could not open output PCAP for writing: " << opts.write_filename << "\n";
        }
    }

    pcap_loop(handle, 0, packet_callback, reinterpret_cast<u_char*>(&ctx));

    if (ctx.dumper) {
        pcap_dump_flush(ctx.dumper);
        pcap_dump_close(ctx.dumper);
    }

    pcap_close(handle);
    g_pcap_handle = nullptr;
    std::cout << "[*] Capture completed.\n";
    return true;
}

} // namespace tlsfp