#include "tlsfp/capture.hpp"
#include "tlsfp/parser.hpp"
#include "tlsfp/ja3.hpp"
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

void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    CaptureContext *ctx = reinterpret_cast<CaptureContext*>(user_data);
    if (!ctx) return;

    // Periodic garbage collection sweep every 2048 packets
    if ((++ctx->packet_counter & 0x7FF) == 0) {
        ctx->cleanup_stale_flows(pkthdr->ts.tv_sec);
    }

    // 1. Resolve Link-Layer Offset
    size_t link_header_len = 0;
    switch (ctx->link_type) {
        case DLT_EN10MB:      link_header_len = 14; break;
        case DLT_LINUX_SLL2:  link_header_len = 20; break;
        case DLT_LINUX_SLL:   link_header_len = 16; break;
        case DLT_NULL:        link_header_len = 4;  break;
        case DLT_RAW:         link_header_len = 0;  break;
        default:              return;
    }

    if (pkthdr->caplen < link_header_len + 1) return;

    // 2. IP Demuxing
    uint8_t ip_version = (packet[link_header_len] >> 4);
    size_t ip_header_len = 0;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    FlowKey key{};

    if (ip_version == 4) {
        if (pkthdr->caplen < link_header_len + sizeof(struct ip)) return;
        const struct ip *ip_hdr = reinterpret_cast<const struct ip *>(packet + link_header_len);
        if (ip_hdr->ip_p != IPPROTO_TCP) return;

        ip_header_len = ip_hdr->ip_hl * 4;
        if (ip_header_len < 20 || pkthdr->caplen < link_header_len + ip_header_len) return;

        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

        key.ip_version = 4;
        key.src_ip.v4 = ip_hdr->ip_src;
        key.dst_ip.v4 = ip_hdr->ip_dst;
    } else if (ip_version == 6) {
        if (pkthdr->caplen < link_header_len + sizeof(struct ip6_hdr)) return;
        const struct ip6_hdr *ip6_hdr = reinterpret_cast<const struct ip6_hdr *>(packet + link_header_len);
        if (ip6_hdr->ip6_nxt != IPPROTO_TCP) return;

        ip_header_len = sizeof(struct ip6_hdr);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        key.ip_version = 6;
        key.src_ip.v6 = ip6_hdr->ip6_src;
        key.dst_ip.v6 = ip6_hdr->ip6_dst;
    } else {
        return;
    }

    // 3. TCP Inspection
    if (pkthdr->caplen < link_header_len + ip_header_len + sizeof(struct tcphdr)) return;
    const struct tcphdr *tcp_hdr = reinterpret_cast<const struct tcphdr *>(packet + link_header_len + ip_header_len);
    size_t tcp_header_len = tcp_hdr->th_off * 4;
    if (tcp_header_len < 20) return;

    key.src_port = tcp_hdr->th_sport;
    key.dst_port = tcp_hdr->th_dport;

    // 4. Payload Bounds Check
    size_t header_total_len = link_header_len + ip_header_len + tcp_header_len;
    if (pkthdr->caplen <= header_total_len) return;

    size_t payload_len = pkthdr->caplen - header_total_len;
    const uint8_t *payload = packet + header_total_len;

    // 5. Sequence Reassembly
    StreamBuffer &buf = ctx->active_flows[key];
    buf.last_seen = pkthdr->ts.tv_sec;
    uint32_t seq = ntohl(tcp_hdr->th_seq);

    if (!buf.seq_initialized) {
        buf.next_seq = seq;
        buf.seq_initialized = true;
    }

    // RFC 1982 Sequence Arithmetic (Handles 32-bit Wraparound)
    int32_t seq_diff = static_cast<int32_t>(seq - buf.next_seq);

    if (seq_diff < 0) {
        // Retransmission / Overlap
        uint32_t overlap = static_cast<uint32_t>(-seq_diff);
        if (overlap >= payload_len) return; // Full duplicate
        payload += overlap;
        payload_len -= overlap;
    } else if (seq_diff > 0) {
        // Out-of-order segment gap: drop state and reset to avoid corrupting stream
        ctx->active_flows.erase(key);
        return;
    }

    if (buf.len + payload_len > StreamBuffer::MAX_BUF_SIZE) {
        ctx->active_flows.erase(key);
        return;
    }

    std::memcpy(buf.bytes + buf.len, payload, payload_len);
    buf.len += static_cast<uint16_t>(payload_len);
    buf.next_seq += static_cast<uint32_t>(payload_len);

    // 6. TLS Validation
    if (buf.len < 5) return; // Need at least the 5-byte TLS record header

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

    // Wait until full TLS record has assembled
    if (buf.len < 5 + tls_rec_len) return;
    if (tls_rec_len < 4 || buf.len < 9) {
        ctx->active_flows.erase(key);
        return;
    }

    // 7. Parse Reassembled Handshake
    uint8_t handshake_type = buf.bytes[5];
    uint16_t src_port = ntohs(tcp_hdr->th_sport);
    uint16_t dst_port = ntohs(tcp_hdr->th_dport);

    if (handshake_type == 0x01) {
        ctx->client_scratchpad.clear();
        // Fixed: Passing reassembled buffer (buf.bytes, buf.len)
        if (parse_client_hello(buf.bytes, buf.len, ctx->client_scratchpad)) {
            JA3Fingerprint ja3 = compute_ja3(ctx->client_scratchpad);

            std::cout << "[+] Captured ClientHello | Flow: [" << src_ip << "]:" << src_port
                      << " -> [" << dst_ip << "]:" << dst_port
                      << " | Reassembled Size: " << buf.len << " bytes\n"
                      << "  ├─ [SNI] " << (ctx->client_scratchpad.has_sni ? ctx->client_scratchpad.sni : "<none>") << "\n"
                      << "  ├─ [JA3 String] " << ja3.raw_string << "\n"
                      << "  └─ [JA3 Hash]   " << ja3.md5_hash << "\n";

            if (ctx->dumper) {
                pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
                pcap_dump_flush(ctx->dumper);
            }
        }
    } else if (handshake_type == 0x02) {
        ctx->server_scratchpad.clear();
        // Fixed: Passing reassembled buffer (buf.bytes, buf.len)
        if (parse_server_hello(buf.bytes, buf.len, ctx->server_scratchpad)) {
            JA3Fingerprint ja3s = compute_ja3s(ctx->server_scratchpad);

            std::cout << "[+] Captured ServerHello | Flow: [" << src_ip << "]:" << src_port
                      << " -> [" << dst_ip << "]:" << dst_port
                      << " | Reassembled Size: " << buf.len << " bytes\n"
                      << "  ├─ [JA3S String] " << ja3s.raw_string << "\n"
                      << "  └─ [JA3S Hash]   " << ja3s.md5_hash << "\n";

            if (ctx->dumper) {
                pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
                pcap_dump_flush(ctx->dumper);
            }
        }
    }

    // Clean up flow state now that handshake has been processed
    ctx->active_flows.erase(key);
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