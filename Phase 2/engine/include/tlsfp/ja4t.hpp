#ifndef TLSFP_JA4T_HPP
#define TLSFP_JA4T_HPP

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace tlsfp {

// --- TCP Header Constants ---
constexpr uint8_t TCP_FLAG_SYN = 0x02;
constexpr uint8_t TCP_FLAG_ACK = 0x10;

constexpr uint8_t TCP_OPT_EOL          = 0;
constexpr uint8_t TCP_OPT_NOP          = 1;
constexpr uint8_t TCP_OPT_MSS          = 2;
constexpr uint8_t TCP_OPT_WINDOW_SCALE = 3;

constexpr size_t TCP_MAX_OPTIONS_LEN = 40; // 60-byte max header - 20-byte fixed header

/**
 * @brief Kernel-controlled L3/L4 fields of a TCP SYN (or SYN-ACK).
 *
 * The application chooses its TLS ClientHello, but the OS kernel builds the SYN:
 * window size, option layout, MSS, window scale and the IP TTL are all stack
 * defaults. Fixed-capacity so recording a SYN never touches the heap.
 */
struct TcpSynData {
    uint16_t window_size{0};
    uint8_t  ip_ttl{0};             // IPv4 TTL / IPv6 Hop Limit as observed at the sensor
    bool     has_mss{false};
    uint16_t mss{0};
    bool     has_window_scale{false};
    uint8_t  window_scale{0};
    std::array<uint8_t, TCP_MAX_OPTIONS_LEN> option_kinds{}; // Wire order, incl. NOP/EOL
    uint8_t  option_count{0};

    void clear() noexcept { *this = TcpSynData{}; }
};

/**
 * @brief Parses window size and TCP options from a SYN or SYN-ACK header.
 * @param tcp_hdr Pointer to start of TCP header
 * @param tcp_hdr_len Full TCP header length (data offset * 4), already bounds-checked
 * @param ip_ttl TTL / Hop Limit from the enclosing IP header
 * @return false if the header is shorter than 20 bytes
 */
bool parse_tcp_syn(const uint8_t *tcp_hdr, size_t tcp_hdr_len, uint8_t ip_ttl, TcpSynData &out);

/**
 * @brief Computes FoxIO JA4T (from a SYN) or JA4TS (from a SYN-ACK).
 * Format: <window>_<option kinds joined by '-'>_<mss>_<window scale>,
 * e.g. Windows 11: 64240_2-1-3-1-1-4_1460_8. Absent fields render as "00".
 */
std::string compute_ja4t(const TcpSynData &syn);

/**
 * @brief Coarse OS families distinguishable from a SYN.
 * UnixLike = TTL says Linux/macOS/BSD/Android/iOS but the option layout did not narrow it down.
 */
enum class OsFamily : uint8_t {
    Unknown,
    Windows,
    Linux,
    Apple,
    UnixLike,
    NetworkDevice
};

struct OsInference {
    OsFamily family{OsFamily::Unknown};        // Final verdict
    OsFamily layout_family{OsFamily::Unknown}; // From the TCP option layout alone
    OsFamily ttl_family{OsFamily::Unknown};    // From the initial TTL estimate alone
    uint8_t initial_ttl{0};
    uint8_t hops{0};
    bool stack_anomaly{false};                 // Layout and TTL point at incompatible stacks
};

/**
 * @brief Rounds an observed TTL up to the nearest common initial value (64, 128, 255).
 */
[[nodiscard]] uint8_t estimate_initial_ttl(uint8_t observed_ttl) noexcept;

/**
 * @brief Infers the sender's OS family from option layout and TTL (p0f-style heuristic).
 */
[[nodiscard]] OsInference infer_os(const TcpSynData &syn) noexcept;

/**
 * @brief Maps a free-text catalog OS label ("linux", "Windows 11", "macOS") to a family.
 */
[[nodiscard]] OsFamily os_family_from_label(std::string_view label) noexcept;

/**
 * @brief True if both families are known and could describe the same host.
 */
[[nodiscard]] bool os_families_compatible(OsFamily a, OsFamily b) noexcept;

[[nodiscard]] const char *os_family_name(OsFamily family) noexcept;

/**
 * @brief Short mnemonic for a TCP option kind ("MSS", "SACK", "TS", ...), or nullptr if unnamed.
 */
[[nodiscard]] const char *tcp_option_name(uint8_t kind) noexcept;

} // namespace tlsfp

#endif // TLSFP_JA4T_HPP
