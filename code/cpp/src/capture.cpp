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
#include <unistd.h>

namespace tlsfp {

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
    if (pkthdr->caplen <= header_total_len) return; // No payload present

    size_t payload_len = pkthdr->caplen - header_total_len;
    const uint8_t *payload = packet + header_total_len;

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
            JA3Fingerprint ja3 = compute_ja3(ctx->client_scratchpad);
            JA4Fingerprint ja4 = compute_ja4(ctx->client_scratchpad);

            std::cout << "[+] Captured ClientHello | Flow: [" << src_ip_str << "]:" << ntohs(key.src_port)
                      << " -> [" << dst_ip_str << "]:" << ntohs(key.dst_port)
                      << " | Reassembled Size: " << total_record_len << " bytes\n"
                      << "  ├─ [SNI]        " << (ctx->client_scratchpad.has_sni ? ctx->client_scratchpad.sni : "<none>") << "\n"
                      << "  ├─ [JA3 String] " << ja3.raw_string << "\n"
                      << "  ├─ [JA3 Hash]   " << ja3.md5_hash << "\n"
                      << "  └─ [JA4]        " << ja4.full_fp << "\n";

            if (ctx->dumper) {
                pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
            }
        }
    } else if (handshake_type == 0x02) {
        ctx->server_scratchpad.clear();
        if (parse_server_hello(buf.bytes, total_record_len, ctx->server_scratchpad)) {
            JA3Fingerprint ja3s = compute_ja3s(ctx->server_scratchpad);
            JA4Fingerprint ja4s = compute_ja4s(ctx->server_scratchpad);

            std::cout << "[+] Captured ServerHello | Flow: [" << src_ip_str << "]:" << ntohs(key.src_port)
                      << " -> [" << dst_ip_str << "]:" << ntohs(key.dst_port)
                      << " | Reassembled Size: " << total_record_len << " bytes\n"
                      << "  ├─ [JA3S String] " << ja3s.raw_string << "\n"
                      << "  ├─ [JA3S Hash]   " << ja3s.md5_hash << "\n"
                      << "  └─ [JA4S]        " << ja4s.full_fp << "\n";

            if (ctx->dumper) {
                pcap_dump(reinterpret_cast<u_char*>(ctx->dumper), pkthdr, packet);
            }
        }
    }
    ctx->active_flows.erase(key); // Remove flow after processing handshake 
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
        std::cout << "[*] Reading from offline capture: " << opts.read_filename << "\n";
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
        std::cout << "[*] Listening on interface: " << opts.interface_name << "\n";
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
    std::cout << "[*] Capture initialized. Datalink type: " << ctx.link_type << "\n";

    if (!opts.write_filename.empty()) {
        ctx.dumper = pcap_dump_open(handle, opts.write_filename.c_str());
        if (!ctx.dumper) {
            std::cerr << "[-] Warning: Could not open output PCAP for writing: " 
                      << pcap_geterr(handle) << "\n";
        } else {
            std::cout << "[*] Mirroring handshakes to: " << opts.write_filename << "\n";
        }
    }

    int loop_status = pcap_loop(handle, 0, packet_callback, reinterpret_cast<u_char*>(&ctx));

    // Diagnostics & Clean Teardown
    bool success = true;
    if (loop_status == -1) {
        std::cerr << "[-] pcap_loop aborted due to error: " << pcap_geterr(handle) << "\n";
        success = false;
    } else if (loop_status == -2) {
        std::cout << "[*] Capture terminated by signal.\n";
    } else {
        std::cout << "[*] Reached end of capture file.\n";
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