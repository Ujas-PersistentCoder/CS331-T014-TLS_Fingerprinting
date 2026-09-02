#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
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

    FlowKey key{};

    if (ip_version == 4) {
        // --- IPv4 Path ---
        if (pkthdr->caplen < link_header_len + sizeof(struct ip)) return;
        const struct ip *ip_hdr = reinterpret_cast<const struct ip *>(packet + link_header_len);

        if (ip_hdr->ip_p != IPPROTO_TCP) return; // Verify TCP protocol

        ip_header_len = ip_hdr->ip_hl * 4;
        if (ip_header_len < 20) return;

        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

        // Store binary IP addresses directly (Zero Heap Allocation)
        key.ip_version = 4;
        key.src_ip.v4 = ip_hdr->ip_src;
        key.dst_ip.v4 = ip_hdr->ip_dst;

    } else if (ip_version == 6) {
        // --- IPv6 Path ---
        if (pkthdr->caplen < link_header_len + sizeof(struct ip6_hdr)) return;
        const struct ip6_hdr *ip6_hdr = reinterpret_cast<const struct ip6_hdr *>(packet + link_header_len);

        if (ip6_hdr->ip6_nxt != IPPROTO_TCP) return; // Verify TCP protocol

        ip_header_len = sizeof(struct ip6_hdr); // Fixed 40 bytes for standard IPv6

        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        // Store binary IP addresses directly (Zero Heap Allocation)
        key.ip_version = 6;
        key.src_ip.v6 = ip6_hdr->ip6_src;
        key.dst_ip.v6 = ip6_hdr->ip6_dst;

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

    // Set 5-tuple ports
    key.src_port = tcp_hdr->th_sport;
    key.dst_port = tcp_hdr->th_dport;

    // 4. Calculate Payload Offset & Length
    size_t header_total_len = link_header_len + ip_header_len + tcp_header_len;
    if (pkthdr->caplen <= header_total_len) {
        return; // Pure TCP ACK/SYN/FIN or header-only frame
    }

    size_t payload_len = pkthdr->caplen - header_total_len;
    const uint8_t *payload = packet + header_total_len;

    // 5. TCP Sequence Alignment and Deduplication
    StreamBuffer &buf = ctx->active_flows[key];
    buf.last_seen = pkthdr->ts.tv_sec;

    uint32_t seq = ntohl(tcp_hdr->th_seq);

    if (!buf.seq_initialized) {
        buf.next_seq = seq;
        buf.seq_initialized = true;
    }

    if (seq < buf.next_seq) {
        // Handle duplicate bytes / retransmissions
        uint32_t diff = buf.next_seq - seq;
        if (diff >= payload_len) return; // Entirely duplicate, discard
        payload += diff;
        payload_len -= diff;
    } else if (seq > buf.next_seq) {
        // Gap detected due to out-of-order packet: clear flow state
        ctx->active_flows.erase(key);
        return;
    }

    if (buf.len + payload_len > StreamBuffer::MAX_BUF_SIZE) {
        ctx->active_flows.erase(key);
        return;
    }

    std::memcpy(buf.bytes + buf.len, payload, payload_len);
    buf.len += static_cast<uint16_t>(payload_len);
    buf.next_seq += payload_len; // Advance expected sequence number

    // 6. Inspect TLS Record Header
    if (buf.len < 5) {
        return; // Wait for full 5-byte TLS record header
    }

    uint8_t record_type  = buf.bytes[0];
    uint8_t major_ver    = buf.bytes[1];
    uint8_t minor_ver    = buf.bytes[2];
    
    // Declared here so it remains in scope for validation below
    uint16_t tls_rec_len = (static_cast<uint16_t>(buf.bytes[3]) << 8) | buf.bytes[4];

    bool is_valid_tls = (record_type == 0x16) && 
                        (major_ver == 0x03) && 
                        (minor_ver <= 0x04) && 
                        (tls_rec_len <= 16384);

    if (!is_valid_tls) {
        ctx->active_flows.erase(key);
        return;
    }

    size_t total_expected_len = 5 + tls_rec_len;
    if (buf.len < total_expected_len) {
        return; // Wait for full TLS record payload
    }

    if (tls_rec_len < 4 || buf.len < 9) {
        ctx->active_flows.erase(key);
        return;
    }

    // Process Complete Reassembled ClientHello (0x01) or ServerHello (0x02)
    uint8_t handshake_type = buf.bytes[5];

    if (handshake_type == 0x01 || handshake_type == 0x02) {
        uint32_t hs_len = (static_cast<uint32_t>(buf.bytes[6]) << 16) |
                          (static_cast<uint32_t>(buf.bytes[7]) << 8)  |
                           static_cast<uint32_t>(buf.bytes[8]);

        // Validate handshake length against tls_rec_len
        if (4 + hs_len > tls_rec_len) {
            ctx->active_flows.erase(key);
            return;
        }

        if (ctx->dumper != nullptr) {
            pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
            pcap_dump_flush(ctx->dumper);
        }

        uint16_t src_port = ntohs(tcp_hdr->th_sport);
        uint16_t dst_port = ntohs(tcp_hdr->th_dport);

        std::cout << "[+] Captured " << (handshake_type == 0x01 ? "ClientHello" : "ServerHello")
                  << " | Flow: [" << src_ip << "]:" << src_port
                  << " -> [" << dst_ip << "]:" << dst_port
                  << " | Reassembled Size: " << buf.len << " bytes"
                  << " | Handshake Payload: " << hs_len << " bytes\n";

        ctx->active_flows.erase(key);
    } else {
        ctx->active_flows.erase(key);
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