#ifndef TLSFP_CAPTURE_HPP
#define TLSFP_CAPTURE_HPP

#include "tlsfp/parser.hpp"
#include <string>
#include <pcap.h>
#include <cstdint>

namespace tlsfp{

    struct CaptureOptions {
        std::string interface_name;
        std::string read_filename;
        std::string write_filename;
    };

    struct CaptureContext {
        pcap_dumper_t *dumper{nullptr};
        int link_type{0};

        ClientHelloData client_scratchpad;
        ServerHelloData server_scratchpad;
    };

    bool start_capture(const CaptureOptions &opts);
    void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    void signal_handler(int signum);
}

#endif