#ifndef TLSFP_TYPES_HPP
#define TLSFP_TYPES_HPP

#include <cstdint>
#include <cstring>
#include <string>
#include <netinet/in.h>

namespace tlsfp {

// --- Datalink & TLS Constants ---
constexpr uint8_t TLS_RECORD_HANDSHAKE          = 0x16;
constexpr uint8_t TLS_RECORD_CHANGE_CIPHER_SPEC = 0x14;
constexpr uint8_t TLS_HANDSHAKE_CLIENT_HELLO    = 0x01;
constexpr uint8_t TLS_HANDSHAKE_SERVER_HELLO    = 0x02;

// Standard wire limits
constexpr size_t MAX_TLS_RECORD_LENGTH = 16384;      // RFC 8446 max record payload (16 KB)
constexpr size_t ACCUMULATOR_BUFFER_SIZE = 8192;     // 8 KB buffer: covers Kyber/ML-KEM PQ-TLS (2.5-3.5 KB)
constexpr uint32_t FLOW_TIMEOUT_SECONDS = 3;         // Incomplete handshake expiration window
constexpr uint32_t SYN_TIMEOUT_SECONDS = 30;         // SYN -> ClientHello correlation window (JA4T)
constexpr size_t   SYN_TABLE_MAX_ENTRIES = 65536;    // Bound on tracked SYNs (SYN flood guard)

// --- Flow Identification (4-tuple) ---
struct FlowKey {
    uint8_t ip_version{4}; // 4 or 6
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } src_ip, dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};

    FlowKey() noexcept {
        std::memset(this, 0, sizeof(FlowKey));
        ip_version = 4;
    }

    bool operator==(const FlowKey &o) const noexcept {
        if (ip_version != o.ip_version || src_port != o.src_port || dst_port != o.dst_port) {
            return false;
        }
        if (ip_version == 4) {
            return src_ip.v4.s_addr == o.src_ip.v4.s_addr &&
                   dst_ip.v4.s_addr == o.dst_ip.v4.s_addr;
        }
        return std::memcmp(&src_ip.v6, &o.src_ip.v6, sizeof(struct in6_addr)) == 0 &&
               std::memcmp(&dst_ip.v6, &o.dst_ip.v6, sizeof(struct in6_addr)) == 0;
    }
};

// High-distribution hash functor for FlowKey (Fibonacci multiplicative hashing for IPv4)
struct FlowHash {
    std::size_t operator()(const FlowKey &k) const noexcept {
        constexpr uint64_t PRIME = 0x9e3779b97f4a7c15ULL;
        std::size_t h = k.ip_version ^ (static_cast<std::size_t>(k.src_port) << 16) ^ k.dst_port;
        if (k.ip_version == 4) {
            h ^= static_cast<std::size_t>(k.src_ip.v4.s_addr) ^ 
                 (static_cast<std::size_t>(k.dst_ip.v4.s_addr) * PRIME);
        } else {
            uint64_t words[4];
            std::memcpy(words, &k.src_ip.v6, 16);
            std::memcpy(words + 2, &k.dst_ip.v6, 16);
            for (int i = 0; i < 4; ++i) {
                h ^= static_cast<std::size_t>(words[i] * PRIME);
                h = (h << 13) | (h >> (sizeof(std::size_t) * 8 - 13));
            }
        }
        return h;
    }
};

// --- Fingerprint Types & Kinds ---
enum class FingerprintKind : uint8_t {
    JA3,
    JA3S,
    JA4,
    JA4S,
    JA4T,  // TCP SYN (client kernel stack)
    JA4TS  // TCP SYN-ACK (server kernel stack)
};

struct JA3Fingerprint {
    std::string raw_string; // Canonical comma-separated representation
    std::string md5_hash;   // 32-character hex MD5
};

struct JA4Fingerprint {
    std::string ja4_a;
    std::string ja4_b;
    std::string ja4_c;
    std::string raw_ja4_b;
    std::string raw_ja4_c;
    std::string full_fp;   // 36-char canonical JA4 or 26-char JA4S
};

} // namespace tlsfp

#endif // TLSFP_TYPES_HPP
