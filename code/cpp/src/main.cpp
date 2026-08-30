#include "../include/tlsfp/capture.hpp"
#include <iostream>
#include <unistd.h>

int main(int argc, char *argv[]) {
    TLSFP::CaptureOptions opts;
    int opt;

    while ((opt = getopt(argc, argv, "i:r:w:")) != -1) {
        switch (opt) {
            case 'i': opts.interface_name = optarg; break;
            case 'r': opts.read_filename = optarg; break;
            case 'w': opts.write_filename = optarg; break;
            default: break;
        }
    }

    if (opts.interface_name.empty() && opts.read_filename.empty()) {
        std::cerr << "Usage: " << argv[0] << " [-i interface | -r input.pcap] [-w output.pcap]\n";
        return 1;
    }

    TLSFP::start_capture(opts);
    return 0;
}