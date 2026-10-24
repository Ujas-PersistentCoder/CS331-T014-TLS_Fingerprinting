#include "tlsfp/capture.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <unistd.h>
#include <iomanip>

namespace {

std::atomic<tlsfp::CaptureEngine*> g_engine{nullptr};

void signal_handler(int sig) {
    auto *engine = g_engine.load(std::memory_order_relaxed);
    if (engine) {
        engine->stop();
    }
    // Restore default handler so a second interrupt immediately terminates
    std::signal(sig, SIG_DFL);
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
    g_engine.store(&engine, std::memory_order_relaxed);

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
    g_engine.store(nullptr, std::memory_order_relaxed);

    if (!success) {
        return 1; // Exit cleanly if pcap initialization failed
    }

    const auto &stats = engine.stats();
    if (!options.quiet) {
        bool is_live = !options.interface_name.empty();
        std::cout << "\n\033[1;32m=== " << (is_live ? "Live Capture Summary" : "Processing Summary") << " ===\033[0m\n"
                  << "Total Packets:    " << stats.total_packets << "\n"
                  << "ClientHellos:     " << stats.client_hellos << "\n"
                  << "ServerHellos:     " << stats.server_hellos << "\n"
                  << (is_live ? "Capture Duration: " : "Elapsed Time:     ") 
                  << std::fixed << std::setprecision(is_live ? 2 : 4) 
                  << stats.elapsed_seconds() << "s\n";

        if (!is_live) {
            std::cout << "Throughput:       " << std::fixed << std::setprecision(1) 
                      << stats.packets_per_second() << " packets/s\n";
        } else if (stats.elapsed_seconds() > 0.05) {
            std::cout << "TLS Traffic Rate:     " << std::fixed << std::setprecision(1) 
                      << stats.packets_per_second() << " packets/s\n";
        }
    } else {
        // Output for automated benchmarking: <client_hellos> <server_hellos> <elapsed_ms> <kpps>
        std::cout << stats.client_hellos << " "
                  << stats.server_hellos << " "
                  << std::fixed << std::setprecision(3) << (stats.elapsed_seconds() * 1000.0) << " ms "
                  << std::fixed << std::setprecision(1) << (stats.packets_per_second() / 1000.0) << " k/s\n";
    }

    return 0;
}