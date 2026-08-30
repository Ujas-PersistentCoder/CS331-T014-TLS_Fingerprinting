#ifndef TLSFP_CAPTURE_HPP
#define TLSFP_CAPTURE_HPP

#include <string>
#include <pcap.h>

namespace TLSFP {
    struct HandshakePacket {
        uint32_t timestamp;
        std::string src_ip;
        uint16_t src_port;
        std::string dst_ip;
        uint16_t dst_port;
        uint8_t handshake_type;
        std::string payload_hex;
    };

    struct CaptureOptions {
        std::string interface_name;
        std::string read_filename;
        std::string write_filename;
    };

    void start_capture(const CaptureOptions &opts);
    void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    std::string bytes_to_hex(const u_char *data, size_t len);
}

#endif