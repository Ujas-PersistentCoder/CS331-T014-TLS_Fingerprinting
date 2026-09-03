#ifndef TLSFP_CAPTURE_HPP
#define TLSFP_CAPTURE_HPP

#include "tlsfp/parser.hpp"
#include <string>
#include <pcap.h>
#include <cstring>
#include <unordered_map>
#include <cstdint>

namespace tlsfp{

    struct CaptureOptions {
        std::string interface_name;
        std::string read_filename;
        std::string write_filename;
    };

    struct FlowKey {
        uint8_t ip_version;
        union {
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

    struct FlowHash {
        std::size_t operator()(const FlowKey &k) const {
            std::size_t h = k.ip_version ^ (static_cast<std::size_t>(k.src_port) << 16) ^ k.dst_port;
            if (k.ip_version == 4) {
                h ^= k.src_ip.v4.s_addr ^ (k.dst_ip.v4.s_addr * 0x9e3779b9);
            } else {
                const uint64_t *p1 = reinterpret_cast<const uint64_t*>(&k.src_ip.v6);
                const uint64_t *p2 = reinterpret_cast<const uint64_t*>(&k.dst_ip.v6);
                h ^= p1[0] ^ p1[1] ^ p2[0] ^ p2[1];
            }
            return h;
        }
    };

    struct StreamBuffer {
        static constexpr size_t MAX_BUF_SIZE = 16389; // 5-byte TLS Header + 16384 Max Payload
        uint8_t bytes[MAX_BUF_SIZE];
        uint16_t len = 0;
        
        // TCP State Tracking
        uint32_t next_seq = 0;
        bool seq_initialized = false;
        time_t last_seen = 0;
    };

    struct CaptureContext {
        pcap_dumper_t *dumper{nullptr};
        int link_type{0};
        std::unordered_map<FlowKey, StreamBuffer, FlowHash> active_flows;

        ClientHelloData client_scratchpad;
        ServerHelloData server_scratchpad;
    };

    bool start_capture(const CaptureOptions &opts);
    void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    void signal_handler(int signum);
}

#endif