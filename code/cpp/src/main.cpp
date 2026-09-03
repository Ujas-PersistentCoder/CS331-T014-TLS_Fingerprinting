#include "tlsfp/capture.hpp"
#include <iostream>
#include <unistd.h>
#include <csignal>
#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

static void print_usage(const char *prog_name) {
    std::cerr << "Usage: " << prog_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  -i <interface>   Live network interface (e.g., eth0, any)\n"
              << "  -r <pcap_file>   Read packets from offline PCAP file\n"
              << "  -w <pcap_file>   Save matched TLS handshakes to output PCAP\n"
              << "  -h               Show this help message\n";
}

int main(int argc, char *argv[]) {
    // Decouple C++ streams from C stdio to eliminate I/O lock contention
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::cout << std::unitbuf;

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
            default:  print_usage(argv[0]); return 1;
        }
    }

    // Catch rogue unparsed positional arguments
    if (optind < argc) {
        std::cerr << "[-] Error: Unrecognized extra argument: " << argv[optind] << "\n";
        print_usage(argv[0]);
        return 1;
    }

    // Validate mutual exclusivity
    if (opts.interface_name.empty() && opts.read_filename.empty()) {
        std::cerr << "[-] Error: Must specify an interface (-i) or PCAP file (-r).\n";
        print_usage(argv[0]);
        return 1;
    }

    if (!opts.interface_name.empty() && !opts.read_filename.empty()) {
        std::cerr << "[-] Error: Cannot specify both -i (live) and -r (file) at the same time.\n";
        return 1;
    }

    // Prevent self-destructive read/write overlap
    if (!opts.read_filename.empty() && opts.read_filename == opts.write_filename) {
        std::cerr << "[-] Error: Input and output PCAP file paths cannot be identical.\n";
        return 1;
    }

    // Exception-safe output path resolution
    if (!opts.write_filename.empty()) {
        fs::path p(opts.write_filename);
        if (!p.has_parent_path()) {
            std::error_code ec;
            fs::path target_dir = "../../pcaps";
            
            // Only redirect to ../../pcaps if that directory structure actually exists
            if (fs::exists(target_dir, ec)) {
                opts.write_filename = (target_dir / p).string();
            }
        }
    }

    // POSIX sigaction for deterministic interrupt safety
    struct sigaction sa{};
    sa.sa_handler = tlsfp::signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Avoid SA_RESTART so pcap_loop/blocking calls unblock
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    if (!tlsfp::start_capture(opts)) {
        std::cerr << "[-] Capture engine encountered a fatal error.\n";
        return 1;
    }

    return 0;
}