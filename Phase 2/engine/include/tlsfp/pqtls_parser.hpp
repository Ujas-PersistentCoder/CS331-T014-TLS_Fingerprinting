#ifndef TLSFP_PQTLS_PARSER_HPP
#define TLSFP_PQTLS_PARSER_HPP

// PQ-TLS observation layer: wire facts only, no classification.
// Interpretation lives in pqtls_analysis.hpp.

#include "tlsfp/byte_reader.hpp"
#include <cstdint>
#include <vector>

namespace tlsfp {

// Hybrid PQ key exchange groups (RFC 10024 + Kyber drafts)
//   0x11ec  X25519MLKEM768
//   0x11eb  SecP256r1MLKEM768
//   0x11ed  SecP384r1MLKEM1024
//   0x6399  X25519Kyber768Draft00     (pre-standard, Chrome 124-130)
//   0x639a  SecP256r1Kyber768Draft00  (pre-standard)
[[nodiscard]] inline constexpr bool is_pqtls_group(uint16_t group) noexcept {
    if (group == 0x11ec) return true;
    if (group == 0x11eb) return true;
    if (group == 0x11ed) return true;
    if (group == 0x6399) return true;
    if (group == 0x639a) return true;
    return false;
}

/**
 * @brief PQ-TLS fields observed in a ClientHello (ClientHelloData::pqtls).
 */
struct PqtlsClientObservation {
    // supported_groups (0x000a)
    uint16_t pq_group{0};            // First PQ group offered (0 = none)
    bool     pq_first_choice{false}; // PQ group is first non-GREASE entry

    // key_share (0x0033)
    bool has_key_share{false};       // Extension present
    bool key_share_parsed{false};    // All entries fit, no trailing bytes
    std::vector<uint16_t> key_share_groups; // Non-GREASE groups with a key
    std::vector<uint16_t> key_share_lens;   // Key length per group (bytes)

    // Duplicate extension guard (RFC 8446 Sec. 4.2): first occurrence is kept
    bool duplicate_key_share{false};
    bool duplicate_supported_groups{false};

    void clear() noexcept {
        pq_group = 0;
        pq_first_choice = false;
        has_key_share = false;
        key_share_parsed = false;
        key_share_groups.clear();
        key_share_lens.clear();
        duplicate_key_share = false;
        duplicate_supported_groups = false;
    }
};

/**
 * @brief PQ-TLS fields observed in a ServerHello / HRR (ServerHelloData::pqtls).
 */
struct PqtlsServerObservation {
    uint16_t selected_group{0};   // 0 if no key_share (e.g. TLS 1.2)
    uint16_t server_share_len{0}; // Declared key length (0 for HRR)
    bool     is_hrr{false};       // HelloRetryRequest random detected
    bool     has_key_share{false};
    bool     key_share_parsed{false};    // Exact framing: group|len|key (SH) or group only (HRR)
    bool     duplicate_key_share{false}; // First occurrence is kept

    void clear() noexcept {
        selected_group = 0;
        server_share_len = 0;
        is_hrr = false;
        has_key_share = false;
        key_share_parsed = false;
        duplicate_key_share = false;
    }
};

/**
 * @brief Parses ClientHello key_share (0x0033).
 * @param reader Bounded to the extension body
 */
void parse_pqtls_client_key_share(ByteReader &reader, PqtlsClientObservation &out);

/**
 * @brief Parses ServerHello / HRR key_share (0x0033).
 * Requires out.is_hrr to be set first (random is parsed before extensions).
 */
void parse_pqtls_server_key_share(ByteReader &reader, PqtlsServerObservation &out);

/**
 * @brief Post-extension pass: first PQ group in supported_groups + duplicate 0x000a check.
 * Both input vectors are GREASE-filtered by the main parser.
 */
void find_pqtls_group(const std::vector<uint16_t> &extensions,
                      const std::vector<uint16_t> &supported_groups,
                      PqtlsClientObservation &out);

// HRR detection via fixed ServerHello.random (RFC 8446 Sec. 4.1.3)
bool is_hrr_random(const uint8_t *random);

} // namespace tlsfp

#endif // TLSFP_PQTLS_PARSER_HPP
