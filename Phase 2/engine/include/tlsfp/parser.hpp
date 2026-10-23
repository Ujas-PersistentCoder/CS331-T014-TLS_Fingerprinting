#ifndef TLSFP_PARSER_HPP
#define TLSFP_PARSER_HPP

#include "tlsfp/types.hpp"
#include "tlsfp/byte_reader.hpp"
#include <cstdint>
#include <vector>
#include <string_view>

namespace tlsfp {

// Bitwise check for RFC 8701 GREASE values (0x0A0A, 0x1A1A, ..., 0xFAFA)
[[nodiscard]] inline constexpr bool is_grease(uint16_t val) noexcept {
    return ((val & 0x0F0F) == 0x0A0A) && ((val >> 8) == (val & 0x00FF));
}

// Bitwise check for 2-byte ALPN GREASE values
[[nodiscard]] inline constexpr bool is_alpn_grease(std::string_view alpn) noexcept {
    if (alpn.size() != 2) return false;
    auto b1 = static_cast<uint8_t>(alpn[0]);
    auto b2 = static_cast<uint8_t>(alpn[1]);
    return (b1 == b2) && ((b1 & 0x0F) == 0x0A);
}

/**
 * @brief Extracted and filtered fields from a TLS ClientHello.
 * Reused across handshakes to eliminate per-packet heap allocations.
 */
struct ClientHelloData {
    uint16_t client_version{0};
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t>  ec_point_formats;
    std::vector<uint16_t> supported_versions;
    std::vector<uint16_t> signature_algorithms;

    bool has_sni{false};
    std::string_view sni;        // Zero-copy view into packet buffer
    std::string_view first_alpn; // First non-GREASE ALPN protocol

    void clear() noexcept {
        client_version = 0;
        cipher_suites.clear();
        extensions.clear();
        supported_groups.clear();
        ec_point_formats.clear();
        supported_versions.clear();
        signature_algorithms.clear();
        has_sni = false;
        sni = {};
        first_alpn = {};
    }
};

/**
 * @brief Extracted and filtered fields from a TLS ServerHello.
 */
struct ServerHelloData {
    uint16_t server_version{0};
    uint16_t selected_version{0};
    uint16_t selected_cipher{0};
    std::vector<uint16_t> extensions;
    std::string_view first_alpn;

    void clear() noexcept {
        server_version = 0;
        selected_version = 0;
        selected_cipher = 0;
        extensions.clear();
        first_alpn = {};
    }
};

/**
 * @brief Parses a complete TLS Handshake record containing a ClientHello.
 * @param record Pointer to start of TLS Record (starts with 0x16)
 * @param record_len Full length of record in bytes
 * @param out Output structure to populate
 * @return true if successfully parsed, false if malformed or truncated
 */
bool parse_client_hello(const uint8_t *record, size_t record_len, ClientHelloData &out);

/**
 * @brief Parses a complete TLS Handshake record containing a ServerHello.
 */
bool parse_server_hello(const uint8_t *record, size_t record_len, ServerHelloData &out);

} // namespace tlsfp

#endif // TLSFP_PARSER_HPP
