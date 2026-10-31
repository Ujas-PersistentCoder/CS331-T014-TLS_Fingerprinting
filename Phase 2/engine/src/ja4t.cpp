#include "tlsfp/ja4t.hpp"
#include <algorithm>
#include <cctype>

namespace tlsfp {

namespace {

// %02d semantics used by the FoxIO reference implementation (9 -> "09", 1460 -> "1460")
inline void append_padded2(std::string &out, unsigned val) {
    if (val < 10) out.push_back('0');
    out.append(std::to_string(val));
}

/**
 * Default SYN option layouts of mainstream kernels (trailing EOL padding stripped).
 * The first, third and fourth are confirmed by SYNs in code/pcaps; Linux without
 * timestamps follows tcp_options_write() (MSS, NOP-NOP-SACK_PERM, NOP-WS).
 */
struct LayoutSignature {
    std::array<uint8_t, 8> kinds;
    uint8_t count;
    OsFamily family;
};

constexpr LayoutSignature KNOWN_LAYOUTS[] = {
    {{2, 4, 8, 1, 3},       5, OsFamily::Linux},   // Linux / Android (timestamps on, default)
    {{2, 1, 1, 4, 1, 3},    6, OsFamily::Linux},   // Linux with net.ipv4.tcp_timestamps=0
    {{2, 1, 3, 1, 1, 8, 4}, 7, OsFamily::Apple},   // macOS / iOS (followed by 2x EOL)
    {{2, 1, 3, 1, 1, 4},    6, OsFamily::Windows}, // Windows 10 / 11 (timestamps off)
};

OsFamily classify_layout(const TcpSynData &syn) noexcept {
    size_t count = syn.option_count;
    while (count > 0 && syn.option_kinds[count - 1] == TCP_OPT_EOL) --count;

    for (const LayoutSignature &sig : KNOWN_LAYOUTS) {
        if (sig.count == count &&
            std::equal(sig.kinds.begin(), sig.kinds.begin() + count, syn.option_kinds.begin())) {
            return sig.family;
        }
    }
    return OsFamily::Unknown;
}

OsFamily family_from_initial_ttl(uint8_t initial_ttl) noexcept {
    switch (initial_ttl) {
        case 64:  return OsFamily::UnixLike;      // Linux, Android, macOS, iOS, BSD
        case 128: return OsFamily::Windows;
        case 255: return OsFamily::NetworkDevice; // Routers, Solaris, some appliances
        default:  return OsFamily::Unknown;
    }
}

inline bool is_unix_family(OsFamily f) noexcept {
    return f == OsFamily::Linux || f == OsFamily::Apple || f == OsFamily::UnixLike;
}

} // anonymous namespace

bool parse_tcp_syn(const uint8_t *tcp_hdr, size_t tcp_hdr_len, uint8_t ip_ttl, TcpSynData &out) {
    out.clear();
    if (tcp_hdr == nullptr || tcp_hdr_len < 20) return false;

    out.window_size = static_cast<uint16_t>((tcp_hdr[14] << 8) | tcp_hdr[15]);
    out.ip_ttl = ip_ttl;

    const uint8_t *opts = tcp_hdr + 20;
    const size_t opts_len = std::min(tcp_hdr_len - 20, TCP_MAX_OPTIONS_LEN);

    size_t i = 0;
    while (i < opts_len && out.option_count < TCP_MAX_OPTIONS_LEN) {
        const uint8_t kind = opts[i];
        out.option_kinds[out.option_count++] = kind;

        // EOL and NOP are single bytes. EOL padding is kept byte-for-byte to match
        // FoxIO's reference output (macOS SYN: 65535_2-1-3-1-1-8-4-0-0_1460_6).
        if (kind == TCP_OPT_EOL || kind == TCP_OPT_NOP) {
            ++i;
            continue;
        }

        if (i + 1 >= opts_len) break;           // Truncated TLV: kind recorded, no length byte
        const uint8_t len = opts[i + 1];
        if (len < 2 || i + len > opts_len) break; // Malformed length: stop walking

        if (kind == TCP_OPT_MSS && len == 4) {
            out.has_mss = true;
            out.mss = static_cast<uint16_t>((opts[i + 2] << 8) | opts[i + 3]);
        } else if (kind == TCP_OPT_WINDOW_SCALE && len == 3) {
            out.has_window_scale = true;
            out.window_scale = opts[i + 2];
        }
        i += len;
    }
    return true;
}

std::string compute_ja4t(const TcpSynData &syn) {
    std::string fp;
    fp.reserve(48);

    // a: Raw (unscaled) TCP window size
    fp.append(std::to_string(syn.window_size)).push_back('_');

    // b: Option kinds in wire order, decimal, '-' delimited
    if (syn.option_count == 0) {
        fp.append("00");
    }
    for (size_t i = 0; i < syn.option_count; ++i) {
        if (i > 0) fp.push_back('-');
        fp.append(std::to_string(syn.option_kinds[i]));
    }
    fp.push_back('_');

    // c: Maximum Segment Size
    append_padded2(fp, syn.has_mss ? syn.mss : 0);
    fp.push_back('_');

    // d: Window scale shift ("00" when absent or zero, otherwise unpadded)
    if (!syn.has_window_scale || syn.window_scale == 0) {
        fp.append("00");
    } else {
        fp.append(std::to_string(syn.window_scale));
    }
    return fp;
}

uint8_t estimate_initial_ttl(uint8_t observed_ttl) noexcept {
    if (observed_ttl <= 64) return 64;
    if (observed_ttl <= 128) return 128;
    return 255;
}

OsInference infer_os(const TcpSynData &syn) noexcept {
    OsInference inf;
    inf.initial_ttl   = estimate_initial_ttl(syn.ip_ttl);
    inf.hops          = static_cast<uint8_t>(inf.initial_ttl - syn.ip_ttl);
    inf.ttl_family    = family_from_initial_ttl(inf.initial_ttl);
    inf.layout_family = classify_layout(syn);

    if (inf.layout_family == OsFamily::Unknown) {
        inf.family = inf.ttl_family;
    } else if (os_families_compatible(inf.layout_family, inf.ttl_family)) {
        inf.family = inf.layout_family;
    } else {
        // e.g. a Windows option layout arriving with TTL 64: hand-crafted SYN or TTL rewrite
        inf.stack_anomaly = true;
        inf.family = OsFamily::Unknown;
    }
    return inf;
}

OsFamily os_family_from_label(std::string_view label) noexcept {
    std::string lower(label);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    auto has = [&lower](std::string_view needle) {
        return lower.find(needle) != std::string::npos;
    };

    // "win" only as a prefix: "darwin" also contains it
    if (lower.rfind("win", 0) == 0 || has("windows")) return OsFamily::Windows;
    if (has("linux") || has("android") || has("ubuntu") || has("debian")) return OsFamily::Linux;
    if (has("mac") || has("darwin") || has("ios") || has("apple")) return OsFamily::Apple;
    if (has("unix") || has("bsd")) return OsFamily::UnixLike;
    return OsFamily::Unknown;
}

bool os_families_compatible(OsFamily a, OsFamily b) noexcept {
    if (a == OsFamily::Unknown || b == OsFamily::Unknown) return false;
    if (a == b) return true;
    return (a == OsFamily::UnixLike && is_unix_family(b)) ||
           (b == OsFamily::UnixLike && is_unix_family(a));
}

const char *os_family_name(OsFamily family) noexcept {
    switch (family) {
        case OsFamily::Windows:       return "Windows";
        case OsFamily::Linux:         return "Linux";
        case OsFamily::Apple:         return "macOS/iOS";
        case OsFamily::UnixLike:      return "Unix-like";
        case OsFamily::NetworkDevice: return "network device";
        case OsFamily::Unknown:       break;
    }
    return "unknown";
}

const char *tcp_option_name(uint8_t kind) noexcept {
    switch (kind) {
        case 0:  return "EOL";
        case 1:  return "NOP";
        case 2:  return "MSS";
        case 3:  return "WS";
        case 4:  return "SACK";
        case 8:  return "TS";
        case 19: return "MD5";
        case 28: return "UTO";
        case 29: return "AO";
        case 30: return "MPTCP";
        case 34: return "TFO";
        default: return nullptr;
    }
}

} // namespace tlsfp
