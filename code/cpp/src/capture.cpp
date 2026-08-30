#include "../include/tlsfp/capture.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

namespace TLSFP {

std::string bytes_to_hex(const u_char *data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pcap_dumper_t *dumper = reinterpret_cast<pcap_dumper_t*>(user_data);

    const struct ip *ip_hdr = reinterpret_cast<const struct ip *>(packet + 14);
    int ip_header_len = ip_hdr->ip_hl * 4;

    const struct tcphdr *tcp_hdr = reinterpret_cast<const struct tcphdr *>(packet + 14 + ip_header_len);
    int tcp_header_len = tcp_hdr->th_off * 4;

    int header_total_len = 14 + ip_header_len + tcp_header_len;
    int payload_len = pkthdr->caplen - header_total_len;

    if (payload_len <= 5) return;

    const u_char *payload = packet + header_total_len;

    if (payload[0] == 0x16) {
        uint8_t handshake_type = payload[5];

        if (handshake_type == 0x01 || handshake_type == 0x02) {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            if (dumper != nullptr) {
                pcap_dump(reinterpret_cast<u_char*>(dumper), pkthdr, packet);
            }

            std::cout << "{"
                      << "\"timestamp\":" << pkthdr->ts.tv_sec << ","
                      << "\"src_ip\":\"" << src_ip << "\","
                      << "\"src_port\":" << ntohs(tcp_hdr->th_sport) << ","
                      << "\"dst_ip\":\"" << dst_ip << "\","
                      << "\"dst_port\":" << ntohs(tcp_hdr->th_dport) << ","
                      << "\"handshake_type\":" << static_cast<int>(handshake_type) << ","
                      << "\"payload_hex\":\"" << bytes_to_hex(payload, payload_len) << "\""
                      << "}" << std::endl;
        }
    }

}

void start_capture(const CaptureOptions &opts) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = nullptr;

    if (!opts.read_filename.empty()) {
        handle = pcap_open_offline(opts.read_filename.c_str(), errbuf);
    } else {
        handle = pcap_open_live(opts.interface_name.c_str(), BUFSIZ, 1, 1, errbuf);
    }

    if (!handle) {
        std::cerr << "Error opening pcap target: " << errbuf << std::endl;
        return;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp port 443", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
    }

    pcap_dumper_t *dumper = nullptr;
    if (!opts.write_filename.empty()) {
        dumper = pcap_dump_open(handle, opts.write_filename.c_str());
    }

    pcap_loop(handle, 0, packet_callback, reinterpret_cast<u_char*>(dumper));

    if (dumper) pcap_dump_close(dumper);
    pcap_close(handle);
}

}
