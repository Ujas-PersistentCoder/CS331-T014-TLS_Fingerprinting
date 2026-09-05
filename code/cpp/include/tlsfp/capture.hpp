#ifndef TLSFP_CAPTURE_HPP
#define TLSFP_CAPTURE_HPP

#include "tlsfp/parser.hpp"
#include <string>
#include <pcap.h>
#include <cstring>
#include <unordered_map>
#include <cstdint>
#include <netinet/in.h>

namespace tlsfp {

struct CaptureOptions {
    std::string interface_name; //stores eth0, wlan0, etc. for live capture
    std::string read_filename; //stores path to pcap file for offline analysis
    std::string write_filename; //stores path to pcap file for writing captured packets
    std::string bpf_filter{"tcp"};
};

//A connection is uniquely identified by the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
// Protocol is always TCP(IPPROTO_TCP) for this application, so we only need to store the other four fields and the ip_version (4 or 6) to distinguish between IPv4 and IPv6 flows.
struct FlowKey {
    uint8_t ip_version;
    union { // Anonymous union for source and destination IP addresses
        struct in_addr v4;
        struct in6_addr v6;
    } src_ip, dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const FlowKey &o) const {
        if (ip_version != o.ip_version || src_port != o.src_port || dst_port != o.dst_port) 
            return false;
        if (ip_version == 4) {
            return src_ip.v4.s_addr == o.src_ip.v4.s_addr && 
                   dst_ip.v4.s_addr == o.dst_ip.v4.s_addr;
        }
        return std::memcmp(&src_ip.v6, &o.src_ip.v6, sizeof(struct in6_addr)) == 0 &&
               std::memcmp(&dst_ip.v6, &o.dst_ip.v6, sizeof(struct in6_addr)) == 0;
    }
};

// Custom hash function for FlowKey to be used in unordered_map
struct FlowHash {
    std::size_t operator()(const FlowKey &k) const {
        std::size_t h = k.ip_version ^ (static_cast<std::size_t>(k.src_port) << 16) ^ k.dst_port;
        if (k.ip_version == 4) {
            h ^= k.src_ip.v4.s_addr ^ (k.dst_ip.v4.s_addr * 0x9e3779b9); //Fibonacci hashing for better distribution
        } else {
            uint32_t p1[4], p2[4];
            std::memcpy(p1, &k.src_ip.v6, sizeof(p1));
            std::memcpy(p2, &k.dst_ip.v6, sizeof(p2));
            h ^= p1[0] ^ p1[1] ^ p1[2] ^ p1[3] ^ p2[0] ^ p2[1] ^ p2[2] ^ p2[3];
        }
        return h;
    }
};

// StreamBuffer is used to reassemble TCP streams for each active flow. It maintains a buffer of bytes, the next expected sequence number, and a timestamp of the last seen packet for cleanup purposes.
struct StreamBuffer {
    // 4096 bytes comfortably fits Post-Quantum Cyber handshakes while sparing CPU cache
    static constexpr size_t MAX_BUF_SIZE = 4096; 
    uint8_t bytes[MAX_BUF_SIZE];
    uint16_t len{0};
    
    uint32_t next_seq{0};
    bool seq_initialized{false};
    time_t last_seen{0};
};

// CaptureContext holds the state of the packet capture session, including the pcap dumper for writing packets, the link type, and a map of active flows to their corresponding StreamBuffers. It also includes scratchpad structures for parsing ClientHello and ServerHello messages, as well as a packet counter for periodic cleanup of stale flows.
struct CaptureContext {
    pcap_dumper_t *dumper{nullptr};
    int link_type{0};
    std::unordered_map<FlowKey, StreamBuffer, FlowHash> active_flows;

    ClientHelloData client_scratchpad;
    ServerHelloData server_scratchpad;
    
    // Periodic sweep counter to prevent memory growth from abandoned flows
    uint64_t packet_counter{0};
    void cleanup_stale_flows(time_t current_time);
};

bool start_capture(const CaptureOptions &opts);
void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void signal_handler(int signum);

}

#endif