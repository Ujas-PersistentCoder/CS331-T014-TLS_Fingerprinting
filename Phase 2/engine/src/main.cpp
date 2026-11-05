#include "tlsfp/capture.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <unistd.h>
#include <getopt.h>
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
              << "  -f <filter>      BPF packet filter string (default: \"tcp\")\n"
              << "  -t               Enable JA4T/JA4TS TCP fingerprinting and cross-layer alerts\n"
              << "  -v               Enable verbose dissection of TLS handshake fields\n"
              << "  -q               Quiet / benchmark mode (suppress output, measure pps)\n"
              << "  -j <threads>     Number of worker threads (default: auto-detect CPU cores)\n"
              << "  -u               Interactively prompt to label unknown fingerprints\n"
              << "  --json <file>    Create a new JSON Lines file of connection summaries\n"
              << "  -e, --ech        Enable stateful ECH analysis and connection tracking\n"
              << "  --no-ech         Disable ECH analysis (high-throughput line-rate mode, default)\n"
              << "  -p, --pq         Enable Post-Quantum TLS (PQ-TLS) posture analysis and wire checks\n"
              << "  --no-pq          Disable Post-Quantum TLS analysis (default)\n"
              << "  -c <catalog>     Load an extra catalog JSON (seed schema, e.g. ja4t / expected_os lab records)\n"
              << "  -h               Show this help message and exit\n";
}

} // anonymous namespace

int main(int argc, char *argv[]) {
    tlsfp::CaptureOptions options;
    options.bpf_filter = "tcp";
    bool ech_flag_seen = false;

    int opt = 0;
    const option long_options[] = {
        {"json", required_argument, nullptr, 1000},
        {"ech", no_argument, nullptr, 1001},
        {"no-ech", no_argument, nullptr, 1002},
        {"enable-ech", no_argument, nullptr, 1001},
        {"disable-ech", no_argument, nullptr, 1002},
        {"pq", no_argument, nullptr, 'p'},
        {"pqtls", no_argument, nullptr, 'p'},
        {"no-pq", no_argument, nullptr, 1003},
        {"no-pqtls", no_argument, nullptr, 1003},
        {nullptr, 0, nullptr, 0}
    };
    while ((opt = getopt_long(argc, argv, "r:i:f:c:etvquj:hp", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'p':
                options.enable_pqtls = true;
                break;
            case 1003:
                options.enable_pqtls = false;
                break;
            case 1000:
                if (!*optarg) {
                    std::cerr << "Error: --json requires a nonempty output filename.\n";
                    return 1;
                }
                options.json_filename = optarg;
                if (!ech_flag_seen) options.enable_ech = true;
                break;
            case 'e':
            case 1001:
                options.enable_ech = true;
                ech_flag_seen = true;
                break;
            case 1002:
                options.enable_ech = false;
                ech_flag_seen = true;
                break;
            case 'r':
                options.read_filename = optarg;
                break;
            case 'i':
                options.interface_name = optarg;
                break;
            case 'f':
                options.bpf_filter = optarg;
                break;
            case 'c':
                options.extra_catalog_filename = optarg;
                break;
            case 't':
                options.enable_ja4t = true;
                break;
            case 'v':
                options.verbose = true;
                break;
            case 'q':
                options.quiet = true;
                break;
            case 'u':
                options.prompt_unknown = true;
                break;
            case 'j':
                options.num_threads = std::stoul(optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (!ech_flag_seen && options.json_filename.empty()) {
        options.enable_ech = false;
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
                  << "Total Packets:    " << stats.total_packets.load() << "\n"
                  << "ClientHellos:     " << stats.client_hellos.load() << "\n"
                  << "ServerHellos:     " << stats.server_hellos.load() << "\n";
        if (options.enable_ja4t) {
            std::cout << "TCP SYN/SYN-ACK:  " << stats.tcp_syns.load() << " / " << stats.tcp_synacks.load() << "\n"
                      << "Cross-layer Alerts: " << stats.cross_layer_alerts.load() << "\n";
        }
        std::cout << (is_live ? "Capture Duration: " : "Elapsed Time:     ")
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
        std::cout << "\n\033[1;36m====================================================\033[0m\n"
                  << "\033[1;37m            Benchmark Execution Summary             \033[0m\n"
                  << "\033[1;36m====================================================\033[0m\n"
                  << "Total Packets Scanned : " << stats.total_packets.load() << "\n"
                  << "ClientHellos Found    : " << stats.client_hellos.load() << "\n"
                  << "ServerHellos Found    : " << stats.server_hellos.load() << "\n"
                  << "Execution Time        : " << std::fixed << std::setprecision(3) 
                  << (stats.elapsed_seconds() * 1000.0) << " ms (" 
                  << std::setprecision(4) << stats.elapsed_seconds() << " s)\n"
                  << "Processing Throughput : " << std::fixed << std::setprecision(1) 
                  << stats.packets_per_second() << " packets/s ("
                  << std::setprecision(1) << (stats.packets_per_second() / 1000.0) << " kpps)\n"
                  << "\033[1;36m====================================================\033[0m\n";
    }

    return 0;
}
