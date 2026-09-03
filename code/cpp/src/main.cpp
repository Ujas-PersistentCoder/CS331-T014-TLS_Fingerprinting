#include "tlsfp/capture.hpp"
#include <iostream>
#include <unistd.h>
#include <csignal>
#include <filesystem>

namespace fs = std::filesystem;

static void print_usage(const char *prog_name) {
    std::cerr << "Usage: " << prog_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  -i <interface>   Live network interface (eg, eth0, any)\n"
              << "  -r <pcap_file>   Read packets from offline PCAP file\n"
              << "  -w <pcap_file>   Save matched TLS handshakes to output PCAP\n"
              << "  -h               Show this help message\n";
}

int main(int argc, char *argv[]) {
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    tlsfp::CaptureOptions opts;
    int opt;

    while ((opt = getopt(argc, argv, "i:r:w:h")) != -1) {
        switch (opt) {
            case 'i': opts.interface_name = optarg; break;
            case 'r': opts.read_filename = optarg; break;
            case 'w': opts.write_filename = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (!opts.write_filename.empty()) {
        fs::path p(opts.write_filename);
        if (!p.has_parent_path()) {
            // Locate ../../../pcaps relative to build directory
            fs::path target_dir = "../../pcaps";
            if (!fs::exists(target_dir)) {
                fs::create_directories(target_dir);
            }
            opts.write_filename = (target_dir / p).string();
        }
    }

    if (opts.interface_name.empty() && opts.read_filename.empty()) {
        std::cerr << "[-] Error: Must specify an interface (-i) or PCAP file (-r).\n";
        print_usage(argv[0]);
        return 1;
    }

    if (!opts.interface_name.empty() && !opts.read_filename.empty()) {
        std::cerr << "[-] Error: Cannot specify both -i (live) and -r (file) at the same time.\n";
        return 1;
    }

    std::signal(SIGINT, tlsfp::signal_handler);
    std::signal(SIGTERM, tlsfp::signal_handler);

    if (!tlsfp::start_capture(opts)) {
        std::cerr << "[-] Capture engine encountered a fatal error.\n";
        return 1;
    }

    return 0;
}