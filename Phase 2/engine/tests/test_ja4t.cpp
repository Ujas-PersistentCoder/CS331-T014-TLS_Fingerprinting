// JA4T unit tests: FoxIO reference vectors + OS inference. Run via `ctest` or directly.
#include "tlsfp/ja4t.hpp"

#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

using namespace tlsfp;

namespace {

int g_failures = 0;

void check(bool ok, const std::string &what) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_failures;
}

void check_eq(const std::string &got, const std::string &want, const std::string &what) {
    check(got == want, what + "  (got " + got + ", want " + want + ")");
}

// Builds a raw TCP header: 20 fixed bytes (only window set) + options padded to 4 bytes.
std::vector<uint8_t> tcp_header(uint16_t window, std::initializer_list<uint8_t> options) {
    std::vector<uint8_t> hdr(20, 0);
    hdr[14] = static_cast<uint8_t>(window >> 8);
    hdr[15] = static_cast<uint8_t>(window & 0xFF);
    hdr.insert(hdr.end(), options);
    while (hdr.size() % 4 != 0) hdr.push_back(0);
    hdr[12] = static_cast<uint8_t>((hdr.size() / 4) << 4);
    hdr[13] = TCP_FLAG_SYN;
    return hdr;
}

TcpSynData parse(const std::vector<uint8_t> &hdr, uint8_t ttl) {
    TcpSynData syn;
    parse_tcp_syn(hdr.data(), hdr.size(), ttl, syn);
    return syn;
}

// Option byte sequences as each stack emits them
const std::initializer_list<uint8_t> WINDOWS_OPTS = {2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2};
const std::initializer_list<uint8_t> LINUX_OPTS   = {2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
                                                     1, 3, 3, 7};
const std::initializer_list<uint8_t> MACOS_OPTS   = {2, 4, 0x05, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1,
                                                     0, 0, 0, 0, 4, 2, 0, 0};

} // anonymous namespace

int main() {
    // --- FoxIO reference vectors ---
    check_eq(compute_ja4t(parse(tcp_header(64240, WINDOWS_OPTS), 128)),
             "64240_2-1-3-1-1-4_1460_8", "Windows 11 (FoxIO README)");
    check_eq(compute_ja4t(parse(tcp_header(65535, MACOS_OPTS), 64)),
             "65535_2-1-3-1-1-8-4-0-0_1460_6", "macOS keeps EOL padding (FoxIO Rust snapshot)");
    check_eq(compute_ja4t(parse(tcp_header(8192, {}), 64)),
             "8192_00_00_00", "No options -> 00 fields (FoxIO test_ja4t_format_defaults)");
    check_eq(compute_ja4t(parse(tcp_header(5744, {2, 4, 0x05, 0x9c, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 0}), 64)),
             "5744_2-4-8-1-3_1436_00", "Zero window scale -> 00 (FoxIO test_ja4t_format_zero_window_scale)");
    check_eq(compute_ja4t(parse(tcp_header(8192, {2, 4, 0x00, 0x09}), 64)),
             "8192_2_09_00", "Single-digit MSS zero-padded (FoxIO test_ja4t_format_present_single_digit_mss)");
    check_eq(compute_ja4t(parse(tcp_header(64240, LINUX_OPTS), 64)),
             "64240_2-4-8-1-3_1460_7", "Linux default SYN");

    // --- Robustness ---
    TcpSynData malformed = parse(tcp_header(64240, WINDOWS_OPTS), 128);
    auto malformed_header = tcp_header(1024, {2, 4, 0x05, 0xb4, 3, 0});
    check(parse_tcp_syn(malformed_header.data(), malformed_header.size(), 64, malformed) &&
          malformed.malformed_options, "Malformed zero-length option is flagged, not dropped");
    check_eq(compute_ja4t(malformed), "1024_2-3_1460_00", "Malformed option keeps kinds read so far");
    OsInference crafted = infer_os(malformed);
    check(crafted.stack_anomaly && crafted.family == OsFamily::Unknown,
          "Malformed options -> STACK_ANOMALY, no TTL-only OS guess");

    TcpSynData eol_garbage = parse(tcp_header(1024, {2, 4, 0x05, 0xb4, 0, 0, 7, 0}), 64);
    check(eol_garbage.malformed_options, "Non-zero byte after EOL is flagged");
    check_eq(compute_ja4t(eol_garbage), "1024_2-0-0_1460_00", "EOL padding before the garbage byte is kept");

    TcpSynData bad_mss = parse(tcp_header(1024, {2, 6, 0x05, 0xb4, 0, 0, 1, 3, 3, 7}), 64);
    check(bad_mss.malformed_options && !bad_mss.has_mss && bad_mss.has_window_scale,
          "Wrong MSS length: flagged, value ignored, walk continues");

    TcpSynData ws15 = parse(tcp_header(64240, {2, 4, 0x05, 0xb4, 1, 3, 3, 15, 1, 1, 4, 2}), 128);
    check(ws15.malformed_options && infer_os(ws15).stack_anomaly, "Window scale > 14 is malformed -> STACK_ANOMALY");
    check_eq(compute_ja4t(ws15), "64240_2-1-3-1-1-4_1460_15", "Window scale > 14 still fingerprinted as sent");

    check(infer_os(parse(tcp_header(64240, {2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
                                            1, 1, 4, 2}), 128)).family == OsFamily::Windows,
          "Windows layout with timestamps -> Windows");
    check(infer_os(parse(tcp_header(65535, {2, 4, 0x05, 0xb4, 1, 3, 3, 6, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}),
                         64)).layout_family == OsFamily::UnixLike,
          "FreeBSD layout -> Unix-like");

    // Path MTU text: IPv6 adds 20 header bytes, loopback is not a jumbo-frame fabric
    TcpSynData mtu = parse(tcp_header(64240, {2, 4, 0x05, 0xa0}), 64); // MSS 1440
    check(describe_path_mtu(mtu, false).find("Link MTU 1480") != std::string::npos, "IPv4 MSS 1440 -> MTU 1480");
    mtu.ipv6 = true;
    check(describe_path_mtu(mtu, false).find("Link MTU 1500 over IPv6 (Standard Ethernet") != std::string::npos,
          "IPv6 MSS 1440 -> standard 1500 MTU, not a tunnel");
    mtu = parse(tcp_header(65495, {2, 4, 0xff, 0xd7}), 64); // MSS 65495
    check(describe_path_mtu(mtu, false).find("Loopback") != std::string::npos, "IPv4 MSS 65495 -> loopback");
    mtu = parse(tcp_header(1400, {2, 4, 0x05, 0x78}), 52); // MSS 1400 from a CDN
    check(describe_path_mtu(mtu, true).find("server-side MSS clamping") != std::string::npos,
          "Reduced server MSS is described as clamping, not as a VPN");

    check(!parse(tcp_header(64240, WINDOWS_OPTS), 128).malformed_options, "Stock Windows SYN is not malformed");
    check(!parse(tcp_header(65535, MACOS_OPTS), 64).malformed_options, "Stock macOS SYN (EOL padded) is not malformed");

    auto truncated = tcp_header(1024, {});
    check(!parse_tcp_syn(truncated.data(), 10, 64, malformed) && compute_ja4t(malformed) == "0_00_00_00",
          "Invalid header clears a previous parse result");

    auto non_syn = tcp_header(1024, {2, 4, 0x05, 0xb4});
    non_syn[13] = 0;
    check(!parse_tcp_syn(non_syn.data(), non_syn.size(), 64, malformed), "Rejects a non-SYN TCP header");

    auto invalid_offset = tcp_header(1024, {});
    invalid_offset[12] = 0x40;
    check(!parse_tcp_syn(invalid_offset.data(), invalid_offset.size(), 64, malformed),
          "Rejects a TCP data offset that does not match the header length");

    auto syn_ack = tcp_header(1024, {});
    syn_ack[13] |= TCP_FLAG_ACK;
    check(parse_tcp_syn(syn_ack.data(), syn_ack.size(), 64, malformed), "Accepts a SYN-ACK header");

    TcpSynData short_hdr;
    check(!parse_tcp_syn(std::vector<uint8_t>(10, 0).data(), 10, 64, short_hdr), "Rejects header < 20 bytes");

    // --- TTL estimation ---
    check(estimate_initial_ttl(64) == 64 && estimate_initial_ttl(51) == 64, "TTL <= 64 -> 64");
    check(estimate_initial_ttl(117) == 128 && estimate_initial_ttl(128) == 128, "TTL 65..128 -> 128");
    check(estimate_initial_ttl(240) == 255, "TTL > 128 -> 255");
    check(estimate_initial_ttl(0) == 0, "TTL 0 remains unknown");

    // --- OS inference ---
    OsInference win = infer_os(parse(tcp_header(64240, WINDOWS_OPTS), 117));
    check(win.family == OsFamily::Windows && win.hops == 11 && !win.stack_anomaly, "Windows layout + TTL 117 -> Windows, 11 hops");
    check(infer_os(parse(tcp_header(64240, LINUX_OPTS), 64)).family == OsFamily::Linux, "Linux layout + TTL 64 -> Linux");
    check(infer_os(parse(tcp_header(65535, MACOS_OPTS), 64)).family == OsFamily::Apple, "macOS layout + TTL 64 -> macOS/iOS");
    check(infer_os(parse(tcp_header(64240, {2, 4, 0x05, 0xb4}), 128)).family == OsFamily::Windows,
          "Unknown layout falls back to TTL");

    OsInference forged = infer_os(parse(tcp_header(64240, WINDOWS_OPTS), 64));
    check(forged.stack_anomaly && forged.family == OsFamily::Unknown, "Windows layout + TTL 64 -> STACK_ANOMALY");
    OsInference missing_ttl = infer_os(parse(tcp_header(64240, WINDOWS_OPTS), 0));
    check(missing_ttl.family == OsFamily::Windows && !missing_ttl.stack_anomaly,
          "Known TCP layout remains usable when TTL is unknown");

    // --- Catalog labels & compatibility ---
    check(os_family_from_label("Windows 11") == OsFamily::Windows, "label 'Windows 11'");
    check(os_family_from_label("darwin") == OsFamily::Apple, "label 'darwin' is not Windows");
    check(os_family_from_label("linux") == OsFamily::Linux, "label 'linux'");
    check(os_family_from_label("") == OsFamily::Unknown, "empty label");
    check(os_families_compatible(OsFamily::UnixLike, OsFamily::Apple), "Unix-like ~ macOS");
    check(!os_families_compatible(OsFamily::Windows, OsFamily::Linux), "Windows !~ Linux");
    check(!os_families_compatible(OsFamily::Unknown, OsFamily::Unknown), "Unknown is never comparable");

    std::printf("\n%d failure(s)\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
