#include "tlsfp/capture.hpp"
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <iomanip>

namespace {
tlsfp::CaptureEngine *g_engine = nullptr;

void signal_handler(int) {
    if (g_engine) {
        g_engine->stop();
    }
}

void print_usage(const char *prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -r <file>        Read and analyze offline PCAP/PCAPNG file\n"
              << "  -i <interface>   Capture live packets from network interface (requires root)\n"
              << "  -f <filter>      BPF packet filter string (default: \"tcp port 443\")\n"
              << "  -v               Enable verbose dissection of TLS handshake fields\n"
              << "  -q               Quiet / benchmark mode (suppress output, measure pps)\n"
              << "  -a               Interactively prompt to label unknown fingerprints\n"
              << "  -h               Show this help message and exit\n";
}

} // anonymous namespace

int main(int argc, char *argv[]) {
    tlsfp::CaptureOptions options;
    options.bpf_filter = "tcp port 443";

    int opt = 0;
    while ((opt = getopt(argc, argv, "r:i:f:vqah")) != -1) {
        switch (opt) {
            case 'r':
                options.read_filename = optarg;
                break;
            case 'i':
                options.interface_name = optarg;
                break;
            case 'f':
                options.bpf_filter = optarg;
                break;
            case 'v':
                options.verbose = true;
                break;
            case 'q':
                options.quiet = true;
                break;
            case 'a':
                options.prompt_unknown = true;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (options.read_filename.empty() && options.interface_name.empty()) {
        std::cerr << "Error: Must specify either -r <pcap_file> or -i <interface>.\n\n";
        print_usage(argv[0]);
        return 1;
    }

    tlsfp::CaptureEngine engine(options);
    g_engine = &engine;

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    if (!options.quiet) {
        std::cout << "\033[1;36m====================================================\033[0m\n"
                  << "\033[1;37m   TLS Fingerprinting Engine (Phase 2 - High-Speed)  \033[0m\n"
                  << "\033[1;36m====================================================\033[0m\n";
        if (!options.read_filename.empty()) {
            std::cout << "Target: " << options.read_filename << "\n";
        } else {
            std::cout << "Interface: " << options.interface_name << " (Filter: " << options.bpf_filter << ")\n";
        }
    }

    bool success = engine.run();
    g_engine = nullptr;

    const auto &stats = engine.stats();
    if (!options.quiet) {
        std::cout << "\n\033[1;32m=== Processing Summary ===\033[0m\n"
                  << "Total Packets:   " << stats.total_packets << "\n"
                  << "ClientHellos:    " << stats.client_hellos << "\n"
                  << "ServerHellos:    " << stats.server_hellos << "\n"
                  << "Elapsed Time:    " << std::fixed << std::setprecision(4) 
                  << stats.elapsed_seconds() << "s\n"
                  << "Throughput:      " << std::fixed << std::setprecision(1) 
                  << stats.packets_per_second() << " packets/s\n";
    } else {
        // Benchmark quiet output
        std::cout << stats.client_hellos << " "
                  << stats.server_hellos << " "
                  << std::fixed << std::setprecision(3) << (stats.elapsed_seconds() * 1000.0) << " ms "
                  << std::fixed << std::setprecision(1) << (stats.packets_per_second() / 1000.0) << " k/s\n";
    }

    return success ? 0 : 1;
}
